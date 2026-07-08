// Package auditsink streams audit ledger events to external sinks (webhook,
// SIEM, or file) in real time. It is designed to sit on the ledger append
// path: Emit never blocks the caller and never returns an error. Network
// sinks buffer events in a bounded queue drained by a background worker;
// when the queue overflows the oldest event is dropped and counted rather
// than blocking the producer.
package auditsink

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Runewardd/runeward/internal/ledger"
)

// Sink receives audit events. Emit must be non-blocking and must never fail
// or stall the caller. Close flushes best-effort and stops any workers.
type Sink interface {
	Emit(ev ledger.Event)
	Close() error
}

// Multi fans a single event out to several sinks.
type Multi struct {
	sinks []Sink
}

// NewMulti returns a Sink that fans out to each of sinks. If no sinks are
// given it returns a no-op sink so callers never have to nil-check.
func NewMulti(sinks ...Sink) Sink {
	if len(sinks) == 0 {
		return nopSink{}
	}
	return &Multi{sinks: sinks}
}

// Emit forwards the event to every underlying sink. It never blocks because
// each sink's Emit is itself non-blocking.
func (m *Multi) Emit(ev ledger.Event) {
	for _, s := range m.sinks {
		s.Emit(ev)
	}
}

// Close closes every underlying sink, returning the first error encountered
// while still attempting to close the rest.
func (m *Multi) Close() error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// nopSink discards events and is returned when nothing is configured.
type nopSink struct{}

func (nopSink) Emit(ledger.Event) {}
func (nopSink) Close() error      { return nil }

// Environment variables recognised by FromEnv.
const (
	// EnvWebhookURL, when set, POSTs each event as JSON to the given URL.
	EnvWebhookURL = "RUNEWARD_AUDIT_WEBHOOK_URL"
	// EnvWebhookHeader optionally adds one "Key: Value" header to every
	// webhook request, e.g. "Authorization: Bearer <token>".
	EnvWebhookHeader = "RUNEWARD_AUDIT_WEBHOOK_HEADER"
	// EnvFile, when set, appends each event as one JSON line to the file.
	EnvFile = "RUNEWARD_AUDIT_FILE"
	// EnvOTLPEndpoint, when set, exports each event as an OTLP log record.
	EnvOTLPEndpoint = "RUNEWARD_AUDIT_OTLP_ENDPOINT"
	// EnvOTLPHeaders optionally sets OTLP headers as "k=v,k2=v2".
	EnvOTLPHeaders = "RUNEWARD_AUDIT_OTLP_HEADERS"
	// EnvOTLPInsecure toggles insecure OTLP transport when true.
	EnvOTLPInsecure = "RUNEWARD_AUDIT_OTLP_INSECURE"
	// EnvOTLPServiceName sets resource attribute "service.name".
	EnvOTLPServiceName = "RUNEWARD_AUDIT_OTLP_SERVICE_NAME"
	// EnvOTLPResourceAttrs sets resource attrs as "k=v,k2=v2".
	EnvOTLPResourceAttrs = "RUNEWARD_AUDIT_OTLP_RESOURCE_ATTRS"
)

// FromEnv builds a Sink from environment variables. With no relevant
// variables set it returns a no-op sink. It returns an error only on
// obviously bad configuration (malformed URL, unopenable file, malformed
// header). logger may be nil, in which case slog.Default is used.
func FromEnv(logger *slog.Logger) (Sink, error) {
	if logger == nil {
		logger = slog.Default()
	}

	var sinks []Sink

	if raw := strings.TrimSpace(os.Getenv(EnvWebhookURL)); raw != "" {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("auditsink: invalid %s: %w", EnvWebhookURL, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("auditsink: %s must be an http(s) URL, got %q", EnvWebhookURL, raw)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("auditsink: %s has no host: %q", EnvWebhookURL, raw)
		}

		var headerKey, headerVal string
		if h := strings.TrimSpace(os.Getenv(EnvWebhookHeader)); h != "" {
			k, v, ok := strings.Cut(h, ":")
			if !ok {
				return nil, fmt.Errorf("auditsink: %s must be %q form, got %q", EnvWebhookHeader, "Key: Value", h)
			}
			headerKey = strings.TrimSpace(k)
			headerVal = strings.TrimSpace(v)
			if headerKey == "" {
				return nil, fmt.Errorf("auditsink: %s has empty header name: %q", EnvWebhookHeader, h)
			}
		}

		sinks = append(sinks, NewWebhookSink(WebhookConfig{
			URL:         u.String(),
			HeaderKey:   headerKey,
			HeaderValue: headerVal,
			Logger:      logger,
		}))
	}

	if path := strings.TrimSpace(os.Getenv(EnvFile)); path != "" {
		fs, err := NewFileSink(path, logger)
		if err != nil {
			return nil, fmt.Errorf("auditsink: %s: %w", EnvFile, err)
		}
		sinks = append(sinks, fs)
	}

	if endpoint := strings.TrimSpace(os.Getenv(EnvOTLPEndpoint)); endpoint != "" {
		var headers map[string]string
		if raw := strings.TrimSpace(os.Getenv(EnvOTLPHeaders)); raw != "" {
			parsed, err := parseKVList(raw)
			if err != nil {
				return nil, fmt.Errorf("auditsink: invalid %s: %w", EnvOTLPHeaders, err)
			}
			headers = parsed
		}

		insecure := false
		if raw := strings.TrimSpace(os.Getenv(EnvOTLPInsecure)); raw != "" {
			parsed, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("auditsink: invalid %s: %w", EnvOTLPInsecure, err)
			}
			insecure = parsed
		}

		var resourceAttrs map[string]string
		if raw := strings.TrimSpace(os.Getenv(EnvOTLPResourceAttrs)); raw != "" {
			parsed, err := parseKVList(raw)
			if err != nil {
				return nil, fmt.Errorf("auditsink: invalid %s: %w", EnvOTLPResourceAttrs, err)
			}
			resourceAttrs = parsed
		}

		osink, err := NewOTLPSink(OTLPSinkConfig{
			Endpoint:           endpoint,
			Headers:            headers,
			Insecure:           insecure,
			ServiceName:        strings.TrimSpace(os.Getenv(EnvOTLPServiceName)),
			ResourceAttributes: resourceAttrs,
			Logger:             logger,
		})
		if err != nil {
			return nil, fmt.Errorf("auditsink: %s: %w", EnvOTLPEndpoint, err)
		}
		sinks = append(sinks, osink)
	}

	return NewMulti(sinks...), nil
}
