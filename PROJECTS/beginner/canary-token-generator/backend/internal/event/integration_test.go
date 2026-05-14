// ©AngelaMos | 2026
// integration_test.go

//go:build integration

package event_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/middleware"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/notify"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/testutil"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/registry"
)

const (
	intgManageURL = "https://canary.example.com"
	intgBaseURL   = "https://canary.example.com"
	intgTokenMemo = "integration-test-memo"
)

type capturingSender struct {
	mu    sync.Mutex
	calls []captureCall
}

type captureCall struct {
	info event.NotifyInfo
	evt  *event.Event
}

func (c *capturingSender) Channel() string { return "telegram" }

func (c *capturingSender) Send(
	_ context.Context,
	info event.NotifyInfo,
	evt *event.Event,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, captureCall{info, evt})
	return nil
}

func (c *capturingSender) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

type intgStack struct {
	router    chi.Router
	notifySvc *notify.Service
	sender    *capturingSender
	eventRepo *event.Repository
	tokenRepo *token.Repository
	mr        *miniredis.Miniredis
}

func setupIntgStack(t *testing.T) *intgStack {
	t.Helper()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() {
		if cErr := rdb.Close(); cErr != nil {
			t.Logf("redis close: %v", cErr)
		}
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)
	sender := &capturingSender{}

	notifySvc := notify.NewService(eventRepo,
		notify.WithLogger(logger),
		notify.WithSendTimeout(2*time.Second),
	)
	notifySvc.Register(sender)

	eventSvc := event.NewService(eventRepo, tokenRepo, rdb, notifySvc, event.ServiceConfig{
		DedupTTL: 15 * time.Minute,
		Logger:   logger,
	})

	genRegistry := registry.Build(registry.Config{
		BaseURL:         intgBaseURL,
		MySQLPublicHost: "localhost",
		MySQLPublicPort: 3306,
	})
	tokenSvc := token.NewService(
		tokenRepo,
		intgRegistryAdapter{r: genRegistry},
		token.ServiceConfig{
			BaseURL:   intgBaseURL,
			ManageURL: intgManageURL,
		},
	)

	tokenH := token.NewHandler(
		tokenSvc,
		intgRecorderAdapter{svc: eventSvc},
		nil,
		logger,
	)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recovery(logger))
	tokenH.RegisterTriggerRoutes(r)
	r.Route("/api", func(api chi.Router) {
		api.Get("/tokens/types", tokenH.GetTypes)
		api.Post("/tokens", tokenH.CreateToken)
	})

	return &intgStack{
		router:    r,
		notifySvc: notifySvc,
		sender:    sender,
		eventRepo: eventRepo,
		tokenRepo: tokenRepo,
		mr:        mr,
	}
}

type intgRegistryAdapter struct{ r registry.Registry }

func (a intgRegistryAdapter) Get(t token.Type) (token.Generator, bool) {
	g, ok := a.r[t]
	return g, ok
}

type intgRecorderAdapter struct{ svc *event.Service }

func (a intgRecorderAdapter) Record(
	ctx context.Context,
	t *token.Token,
	evt *event.Event,
) error {
	return a.svc.Record(ctx, t.NotifyInfo(), evt)
}

func TestIntegration_FullCreateAndTriggerFlow(t *testing.T) {
	t.Parallel()
	st := setupIntgStack(t)

	createBody := `{
		"type": "webbug",
		"memo": "` + intgTokenMemo + `",
		"alert_channel": "telegram",
		"telegram_bot": "111:AAA",
		"telegram_chat": "12345"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens",
		strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	st.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "body=%s", w.Body.String())

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Token struct {
				ID         string `json:"id"`
				ManageID   string `json:"manage_id"`
				TriggerURL string `json:"trigger_url"`
				ManageURL  string `json:"manage_url"`
			} `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.True(t, resp.Success)
	require.NotEmpty(t, resp.Data.Token.ID)
	require.Contains(t, resp.Data.Token.TriggerURL, "/c/"+resp.Data.Token.ID)
	require.Contains(t, resp.Data.Token.ManageURL, "/m/"+resp.Data.Token.ManageID)

	tokenID := resp.Data.Token.ID

	for range 2 {
		trigReq := httptest.NewRequest(http.MethodGet, "/c/"+tokenID, nil)
		trigReq.Header.Set("CF-Connecting-IP", "203.0.113.99")
		trigReq.Header.Set("User-Agent", "IntegrationTest/1.0")
		tw := httptest.NewRecorder()
		st.router.ServeHTTP(tw, trigReq)
		require.Equal(t, http.StatusOK, tw.Code)
		require.Equal(t, "image/gif", tw.Header().Get("Content-Type"))
	}

	require.Eventually(t, func() bool {
		return st.sender.callCount() == 1
	}, 2*time.Second, 10*time.Millisecond,
		"only first trigger should fire a notification")

	st.notifySvc.Wait()

	count, err := st.eventRepo.CountByToken(context.Background(), tokenID)
	require.NoError(t, err)
	require.Equal(t, int64(2), count, "both events recorded")

	list, err := st.eventRepo.ListByToken(context.Background(), tokenID, event.ListOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, list.Events, 2)

	statuses := []event.NotifyStatus{list.Events[0].NotifyStatus, list.Events[1].NotifyStatus}
	var sent, deduped int
	for _, s := range statuses {
		switch s {
		case event.NotifySent:
			sent++
		case event.NotifyDeduped:
			deduped++
		}
	}
	require.Equal(t, 1, sent, "first event eventually marked sent")
	require.Equal(t, 1, deduped, "duplicate event marked deduped")

	dedupKey := event.DedupKey(tokenID, "203.0.113.99")
	val, err := st.mr.Get(dedupKey)
	require.NoError(t, err)
	require.Equal(t, "2", val, "dedup INCR ran on duplicate")

	tok, err := st.tokenRepo.GetByID(context.Background(), tokenID)
	require.NoError(t, err)
	require.Equal(t, int64(2), tok.TriggerCount, "trigger count incremented twice")
	require.NotNil(t, tok.LastTriggered)
}

func TestIntegration_DifferentIPsBothNotify(t *testing.T) {
	t.Parallel()
	st := setupIntgStack(t)

	createBody := `{
		"type": "webbug",
		"memo": "` + intgTokenMemo + `",
		"alert_channel": "telegram",
		"telegram_bot": "111:AAA",
		"telegram_chat": "12345"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/tokens",
		strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	st.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Data struct {
			Token struct {
				ID string `json:"id"`
			} `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	tokenID := resp.Data.Token.ID

	ips := []string{"203.0.113.10", "203.0.113.11", "203.0.113.12"}
	for _, ip := range ips {
		trigReq := httptest.NewRequest(http.MethodGet, "/c/"+tokenID, nil)
		trigReq.Header.Set("CF-Connecting-IP", ip)
		tw := httptest.NewRecorder()
		st.router.ServeHTTP(tw, trigReq)
		require.Equal(t, http.StatusOK, tw.Code)
	}

	require.Eventually(t, func() bool {
		return st.sender.callCount() == len(ips)
	}, 2*time.Second, 10*time.Millisecond)

	st.notifySvc.Wait()
}

func TestIntegration_DedupTTLExpiry(t *testing.T) {
	t.Parallel()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)
	sender := &capturingSender{}

	notifySvc := notify.NewService(eventRepo,
		notify.WithLogger(logger),
		notify.WithSendTimeout(2*time.Second),
	)
	notifySvc.Register(sender)

	eventSvc := event.NewService(eventRepo, tokenRepo, rdb, notifySvc, event.ServiceConfig{
		DedupTTL: 50 * time.Millisecond,
		Logger:   logger,
	})

	tok := &token.Token{
		ID:           "intgttl00001",
		ManageID:     "11111111-1111-1111-1111-111111111111",
		Type:         token.TypeWebbug,
		Memo:         "ttl-test",
		AlertChannel: token.ChannelTelegram,
		TelegramBot:  testutil.Ptr("111:AAA"),
		TelegramChat: testutil.Ptr("12345"),
		CreatedIP:    "203.0.113.1",
		CreatedFP:    "fp",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
	}
	require.NoError(t, tokenRepo.Insert(context.Background(), tok))

	rec := func(ip string) {
		evt := &event.Event{TokenID: tok.ID, SourceIP: ip}
		require.NoError(t, eventSvc.Record(context.Background(), tok.NotifyInfo(), evt))
	}

	rec("203.0.113.1")
	rec("203.0.113.1")
	notifySvc.Wait()
	require.Equal(t, 1, sender.callCount(), "second within TTL is deduped")

	mr.FastForward(100 * time.Millisecond)

	rec("203.0.113.1")
	notifySvc.Wait()
	require.Equal(t, 2, sender.callCount(), "after TTL expiry next trigger notifies again")
}

func TestIntegration_RetentionLoopPrunes(t *testing.T) {
	t.Parallel()
	db := sqlx.NewDb(testutil.NewTestDB(t), "pgx")
	tokenRepo := token.NewRepository(db)
	eventRepo := event.NewRepository(db)

	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	eventSvc := event.NewService(eventRepo, tokenRepo, rdb, nil, event.ServiceConfig{
		DedupTTL: 15 * time.Minute,
		Logger:   logger,
	})

	tok := &token.Token{
		ID:           "intgret00001",
		ManageID:     "22222222-2222-2222-2222-222222222222",
		Type:         token.TypeWebbug,
		Memo:         "ret",
		AlertChannel: token.ChannelTelegram,
		TelegramBot:  testutil.Ptr("111:AAA"),
		TelegramChat: testutil.Ptr("12345"),
		CreatedIP:    "203.0.113.1",
		CreatedFP:    "fp",
		Metadata:     json.RawMessage(`{}`),
		Enabled:      true,
	}
	require.NoError(t, tokenRepo.Insert(context.Background(), tok))

	for range 7 {
		require.NoError(t, eventRepo.Insert(context.Background(), &event.Event{
			TokenID: tok.ID, SourceIP: "203.0.113.99",
		}))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		eventSvc.RunRetentionLoop(ctx, 25*time.Millisecond, 3)
		close(done)
	}()

	require.Eventually(t, func() bool {
		n, err := eventRepo.CountByToken(context.Background(), tok.ID)
		return err == nil && n == 3
	}, 2*time.Second, 25*time.Millisecond, "retention should prune to 3")

	cancel()
	<-done
}
