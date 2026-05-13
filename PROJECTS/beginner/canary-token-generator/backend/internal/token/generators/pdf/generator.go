// ©AngelaMos | 2026
// generator.go

package pdf

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	headerCFConnectingIP = "CF-Connecting-IP"
	headerXForwardedFor  = "X-Forwarded-For"
	headerXRealIP        = "X-Real-IP"
	headerReferer        = "Referer"
	headerCacheControl   = "Cache-Control"
	headerPragma         = "Pragma"

	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"

	triggerPathPrefix = "/c/"

	placeholderRoot = "HONEY_TRACK_URL_PADDED_TO_FIXED_WIDTH"

	PlaceholderLength = 76

	padChar = "_"

	contentType     = "application/pdf"
	defaultFilename = "Document.pdf"
)

var ErrTriggerURLTooLong = errors.New(
	"pdf: trigger URL exceeds placeholder length",
)

//go:embed template/template.pdf
var pdfTemplate []byte

var placeholder = placeholderRoot +
	strings.Repeat(padChar, PlaceholderLength-len(placeholderRoot))

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypePDF }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	baseURL string,
) (generators.Artifact, error) {
	triggerURL := strings.TrimRight(baseURL, "/") + triggerPathPrefix + t.ID

	if len(triggerURL) > PlaceholderLength {
		return generators.Artifact{}, fmt.Errorf(
			"%w: url=%d max=%d",
			ErrTriggerURLTooLong,
			len(triggerURL),
			PlaceholderLength,
		)
	}

	padded := triggerURL +
		strings.Repeat(padChar, PlaceholderLength-len(triggerURL))

	out := bytes.Replace(
		pdfTemplate,
		[]byte(placeholder),
		[]byte(padded),
		1,
	)

	if len(out) != len(pdfTemplate) {
		return generators.Artifact{}, fmt.Errorf(
			"pdf: substitution changed byte length (was %d, now %d)",
			len(pdfTemplate),
			len(out),
		)
	}
	if !bytes.Contains(out, []byte(triggerURL)) {
		return generators.Artifact{}, fmt.Errorf(
			"pdf: substitution did not embed trigger URL",
		)
	}

	return generators.Artifact{
		Kind:        generators.KindFile,
		Filename:    resolveFilename(t.Filename),
		Content:     out,
		ContentType: contentType,
	}, nil
}

func (g *Generator) Trigger(
	_ context.Context,
	t *token.Token,
	r *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	resp := &generators.TriggerResponse{
		StatusCode:  http.StatusOK,
		ContentType: pixel.ContentType,
		Body:        pixel.Clone(),
		ExtraHeaders: map[string]string{
			headerCacheControl: cacheControlNoStore,
			headerPragma:       pragmaNoCache,
		},
	}

	if t == nil {
		return nil, resp, nil
	}

	evt := &event.Event{
		TokenID:   t.ID,
		SourceIP:  realIP(r),
		UserAgent: optionalHeader(r.UserAgent()),
		Referer:   optionalHeader(r.Header.Get(headerReferer)),
	}
	return evt, resp, nil
}

func resolveFilename(name *string) string {
	if name == nil {
		return defaultFilename
	}
	trimmed := strings.TrimSpace(*name)
	if trimmed == "" {
		return defaultFilename
	}
	return trimmed
}

func optionalHeader(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

func realIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(headerCFConnectingIP)); v != "" {
		return v
	}
	if v := lastNonEmptyXFF(r.Header.Get(headerXForwardedFor)); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get(headerXRealIP)); v != "" {
		return v
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func lastNonEmptyXFF(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		if v := strings.TrimSpace(parts[i]); v != "" {
			return v
		}
	}
	return ""
}
