package auditsink

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

func TestEventRecordMapsFieldsAndContextTrace(t *testing.T) {
	ev := sampleEvent()
	ev.ExitCode = 13
	ev.DurationMS = 2250
	ev.Meta = map[string]string{
		"reason":      "blocked by policy",
		"traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}

	rec := eventRecord(ev)
	if rec.EventName() != "runeward.audit" {
		t.Fatalf("event name = %q, want runeward.audit", rec.EventName())
	}

	attrs := map[string]log.Value{}
	rec.WalkAttributes(func(kv log.KeyValue) bool {
		attrs[kv.Key] = kv.Value
		return true
	})

	if got := attrs["runeward.session_id"].AsString(); got != ev.SessionID {
		t.Fatalf("runeward.session_id = %q, want %q", got, ev.SessionID)
	}
	if got := attrs["runeward.reason"].AsString(); got != "blocked by policy" {
		t.Fatalf("runeward.reason = %q, want blocked by policy", got)
	}
	if got := attrs["runeward.duration_ms"].AsInt64(); got != ev.DurationMS {
		t.Fatalf("runeward.duration_ms = %d, want %d", got, ev.DurationMS)
	}

	sc := trace.SpanContextFromContext(contextWithTrace(ev.Meta))
	if got := sc.TraceID().String(); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace id = %s, want 4bf92f3577b34da6a3ce929d0e0e4736", got)
	}
	if got := sc.SpanID().String(); got != "00f067aa0ba902b7" {
		t.Fatalf("span id = %s, want 00f067aa0ba902b7", got)
	}
	if sc.TraceFlags() != trace.TraceFlags(0x01) {
		t.Fatalf("trace flags = %v, want 0x01", sc.TraceFlags())
	}
}

func TestNewOTLPSinkDeliversToHTTPCollector(t *testing.T) {
	reqs := make(chan *http.Request, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs <- r
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink, err := NewOTLPSink(OTLPSinkConfig{
		Endpoint: srv.URL + "/v1/logs",
		Headers: map[string]string{
			"Authorization": "Bearer token",
		},
		Insecure:    true,
		ServiceName: "runeward-test",
	})
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}

	sink.Emit(sampleEvent())
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case r := <-reqs:
		if !strings.HasSuffix(r.URL.Path, "/v1/logs") {
			t.Fatalf("request path = %q, want suffix /v1/logs", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Fatalf("Authorization = %q, want Bearer token", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("collector did not receive otlp request")
	}
}

func TestOTLPSinkEmitDoesNotBlockWhenCollectorHangs(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(block)

	sink, err := NewOTLPSink(OTLPSinkConfig{
		Endpoint:  srv.URL + "/v1/logs",
		Insecure:  true,
		QueueSize: 8,
	})
	if err != nil {
		t.Fatalf("NewOTLPSink: %v", err)
	}
	defer sink.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100000; i++ {
			ev := sampleEvent()
			ev.Seq = i
			sink.Emit(ev)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked with saturated queue")
	}
}

func TestFromEnvBuildsOTLPSink(t *testing.T) {
	t.Setenv(EnvWebhookURL, "")
	t.Setenv(EnvFile, "")
	t.Setenv(EnvOTLPEndpoint, "http://localhost:4318/v1/logs")
	t.Setenv(EnvOTLPHeaders, "authorization=Bearer x")
	t.Setenv(EnvOTLPInsecure, "true")
	t.Setenv(EnvOTLPServiceName, "runeward")
	t.Setenv(EnvOTLPResourceAttrs, "deployment.environment=test")

	s, err := FromEnv(nil)
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	defer s.Close()

	m, ok := s.(*Multi)
	if !ok {
		t.Fatalf("FromEnv returned %T, want *Multi", s)
	}
	if len(m.sinks) != 1 {
		t.Fatalf("sinks = %d, want 1", len(m.sinks))
	}
	if _, ok := m.sinks[0].(*otlpSink); !ok {
		t.Fatalf("sink type = %T, want *otlpSink", m.sinks[0])
	}
}

func TestFromEnvRejectsInvalidOTLPVars(t *testing.T) {
	t.Setenv(EnvOTLPEndpoint, "http://localhost:4318/v1/logs")
	t.Setenv(EnvOTLPHeaders, "not-valid")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("expected invalid headers error")
	}

	t.Setenv(EnvOTLPHeaders, "")
	t.Setenv(EnvOTLPInsecure, "not-bool")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("expected invalid insecure bool error")
	}

	t.Setenv(EnvOTLPInsecure, "")
	t.Setenv(EnvOTLPResourceAttrs, "bad-attrs")
	if _, err := FromEnv(nil); err == nil {
		t.Fatal("expected invalid resource attrs error")
	}
}

func TestFromEnvBuildsOTLPAndFileSinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvWebhookURL, "")
	t.Setenv(EnvOTLPEndpoint, "http://localhost:4318/v1/logs")
	t.Setenv(EnvOTLPInsecure, "true")
	t.Setenv(EnvFile, filepath.Join(dir, "audit.jsonl"))

	s, err := FromEnv(nil)
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	defer s.Close()

	m, ok := s.(*Multi)
	if !ok {
		t.Fatalf("FromEnv returned %T, want *Multi", s)
	}
	if len(m.sinks) != 2 {
		t.Fatalf("sinks = %d, want 2", len(m.sinks))
	}
}
