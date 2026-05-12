// ©AngelaMos | 2026
// generator.go

package slowredirect

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
)

const (
	headerCFConnectingIP = "CF-Connecting-IP"
	headerXForwardedFor  = "X-Forwarded-For"
	headerXRealIP        = "X-Real-IP"
	headerReferer        = "Referer"
	headerCSP            = "Content-Security-Policy"
	headerCacheControl   = "Cache-Control"
	headerPragma         = "Pragma"

	cspOverride         = "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'"
	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"
	contentTypeHTML     = "text/html; charset=utf-8"

	triggerPathPrefix     = "/c/"
	fingerprintPathSuffix = "/fingerprint"
	metadataDestKey       = "destination_url"

	schemeHTTP  = "http://"
	schemeHTTPS = "https://"

	enumerationDecoyDestination = "/"
)

var (
	ErrMissingDestination = errors.New(
		"slowredirect: destination_url missing from token metadata",
	)
	ErrInvalidDestinationScheme = errors.New(
		"slowredirect: destination_url must use http:// or https:// scheme",
	)
)

//go:embed template.html
var templateHTML string

var pageTemplate = template.Must(
	template.New("slowredirect").Parse(templateHTML),
)

type pageData struct {
	Destination    string
	FingerprintURL string
}

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypeSlowRedirect }

func (g *Generator) Generate(
	_ context.Context,
	t *token.Token,
	baseURL string,
) (generators.Artifact, error) {
	dest, err := extractDestination(t.Metadata)
	if err != nil {
		return generators.Artifact{}, err
	}
	url := strings.TrimRight(baseURL, "/") + triggerPathPrefix + t.ID
	return generators.Artifact{
		Kind:           generators.KindURL,
		URL:            url,
		DestinationURL: dest,
	}, nil
}

func (g *Generator) Trigger(
	_ context.Context,
	t *token.Token,
	r *http.Request,
) (*event.Event, *generators.TriggerResponse, error) {
	if t == nil {
		resp, err := renderDecoyResponse()
		if err != nil {
			return nil, nil, err
		}
		return nil, resp, nil
	}

	dest, err := extractDestination(t.Metadata)
	if err != nil {
		return nil, nil, err
	}

	resp, err := renderResponse(dest, t.ID)
	if err != nil {
		return nil, nil, err
	}

	evt := &event.Event{
		TokenID:   t.ID,
		SourceIP:  realIP(r),
		UserAgent: optionalHeader(r.UserAgent()),
		Referer:   optionalHeader(r.Header.Get(headerReferer)),
	}
	return evt, resp, nil
}

func renderResponse(
	destination, tokenID string,
) (*generators.TriggerResponse, error) {
	return renderWith(pageData{
		Destination:    destination,
		FingerprintURL: triggerPathPrefix + tokenID + fingerprintPathSuffix,
	})
}

func renderDecoyResponse() (*generators.TriggerResponse, error) {
	return renderWith(pageData{
		Destination:    enumerationDecoyDestination,
		FingerprintURL: enumerationDecoyDestination,
	})
}

func renderWith(
	data pageData,
) (*generators.TriggerResponse, error) {
	var body bytes.Buffer
	if err := pageTemplate.Execute(&body, data); err != nil {
		return nil, fmt.Errorf("render slowredirect template: %w", err)
	}
	return &generators.TriggerResponse{
		StatusCode:  http.StatusOK,
		ContentType: contentTypeHTML,
		Body:        body.Bytes(),
		ExtraHeaders: map[string]string{
			headerCSP:          cspOverride,
			headerCacheControl: cacheControlNoStore,
			headerPragma:       pragmaNoCache,
		},
	}, nil
}

func extractDestination(metadata json.RawMessage) (string, error) {
	if len(metadata) == 0 {
		return "", ErrMissingDestination
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(metadata, &m); err != nil {
		return "", fmt.Errorf("parse token metadata: %w", err)
	}
	raw, ok := m[metadataDestKey]
	if !ok {
		return "", ErrMissingDestination
	}
	var dest string
	if err := json.Unmarshal(raw, &dest); err != nil {
		return "", fmt.Errorf("parse destination_url: %w", err)
	}
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", ErrMissingDestination
	}
	lower := strings.ToLower(dest)
	if !strings.HasPrefix(lower, schemeHTTP) &&
		!strings.HasPrefix(lower, schemeHTTPS) {
		return "", ErrInvalidDestinationScheme
	}
	return dest, nil
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
