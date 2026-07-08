package auditsink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Runewardd/runeward/internal/ledger"
	"go.opentelemetry.io/otel/attribute"
	otlplog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
)

const (
	otlpQueueSize    = 1024
	otlpCloseTimeout = 5 * time.Second
)

// OTLPSinkConfig configures OTLP audit export.
type OTLPSinkConfig struct {
	Endpoint           string
	Headers            map[string]string
	Insecure           bool
	ServiceName        string
	ResourceAttributes map[string]string
	Logger             *slog.Logger
	QueueSize          int
}

type otlpSink struct {
	logger   *slog.Logger
	otlp     otlplog.Logger
	provider *sdklog.LoggerProvider

	queue chan ledger.Event
	done  chan struct{}
	wg    sync.WaitGroup

	dropped     atomic.Int64
	lastDropLog atomic.Int64

	closeOnce sync.Once
}

// NewOTLPSink builds an OTLP audit sink with a bounded queue and worker.
func NewOTLPSink(cfg OTLPSinkConfig) (Sink, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, errors.New("endpoint is required")
	}
	if _, err := parseOTLPEndpoint(endpoint); err != nil {
		return nil, err
	}

	expOpts := []otlploghttp.Option{otlploghttp.WithEndpointURL(endpoint)}
	if cfg.Insecure {
		expOpts = append(expOpts, otlploghttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		expOpts = append(expOpts, otlploghttp.WithHeaders(copyStringMap(cfg.Headers)))
	}

	exp, err := otlploghttp.New(context.Background(), expOpts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	resAttrs := make([]attribute.KeyValue, 0, len(cfg.ResourceAttributes)+1)
	if svc := strings.TrimSpace(cfg.ServiceName); svc != "" {
		resAttrs = append(resAttrs, attribute.String("service.name", svc))
	}
	for _, k := range sortedKeys(cfg.ResourceAttributes) {
		resAttrs = append(resAttrs, attribute.String(k, cfg.ResourceAttributes[k]))
	}

	res := resource.Default()
	if len(resAttrs) > 0 {
		custom := resource.NewWithAttributes("", resAttrs...)
		res, err = resource.Merge(res, custom)
		if err != nil {
			return nil, fmt.Errorf("merge resource attributes: %w", err)
		}
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)

	size := cfg.QueueSize
	if size <= 0 {
		size = otlpQueueSize
	}

	s := &otlpSink{
		logger:   logger,
		otlp:     provider.Logger("runeward.audit"),
		provider: provider,
		queue:    make(chan ledger.Event, size),
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker()
	return s, nil
}

func (s *otlpSink) Emit(ev ledger.Event) {
	for {
		select {
		case s.queue <- ev:
			return
		default:
			select {
			case <-s.queue:
				s.recordDrop()
			default:
			}
		}
	}
}

func (s *otlpSink) recordDrop() {
	n := s.dropped.Add(1)
	now := time.Now().UnixNano()
	last := s.lastDropLog.Load()
	if now-last >= int64(dropLogInterval) && s.lastDropLog.CompareAndSwap(last, now) {
		s.logger.Warn("auditsink: otlp queue full, dropping events", "dropped_total", n)
	}
}

func (s *otlpSink) worker() {
	defer s.wg.Done()
	for {
		select {
		case ev := <-s.queue:
			s.deliver(ev)
		case <-s.done:
			for {
				select {
				case ev := <-s.queue:
					s.deliver(ev)
				default:
					return
				}
			}
		}
	}
}

func (s *otlpSink) deliver(ev ledger.Event) {
	ctx := contextWithTrace(ev.Meta)
	rec := eventRecord(ev)
	s.otlp.Emit(ctx, rec)
}

func (s *otlpSink) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
	})

	stopped := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(otlpCloseTimeout):
		s.logger.Warn("auditsink: otlp close timed out flushing queue")
	}

	ctx, cancel := context.WithTimeout(context.Background(), otlpCloseTimeout)
	defer cancel()

	var firstErr error
	if err := s.provider.ForceFlush(ctx); err != nil {
		firstErr = err
	}
	if err := s.provider.Shutdown(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func eventRecord(ev ledger.Event) otlplog.Record {
	var rec otlplog.Record
	if ev.Time.IsZero() {
		rec.SetTimestamp(time.Now().UTC())
	} else {
		rec.SetTimestamp(ev.Time.UTC())
	}
	rec.SetObservedTimestamp(time.Now().UTC())
	rec.SetEventName("runeward.audit")
	rec.SetBody(otlplog.StringValue(ev.Action))

	sev, sevText := severityForVerdict(ev.Verdict)
	rec.SetSeverity(sev)
	rec.SetSeverityText(sevText)

	attrs := make([]otlplog.KeyValue, 0, 12+len(ev.Meta)+len(ev.Args))
	attrs = append(attrs,
		otlplog.Int("runeward.audit.seq", ev.Seq),
		otlplog.String("runeward.session_id", ev.SessionID),
		otlplog.String("runeward.sandbox", ev.Sandbox),
		otlplog.String("runeward.profile", ev.Profile),
		otlplog.String("runeward.tool", ev.Tool),
		otlplog.String("runeward.action", ev.Action),
		otlplog.String("runeward.verdict", ev.Verdict),
		otlplog.Int("runeward.exit_code", ev.ExitCode),
		otlplog.Int64("runeward.duration_ms", ev.DurationMS),
		otlplog.String("runeward.hash", ev.Hash),
		otlplog.String("runeward.prev_hash", ev.PrevHash),
	)
	if reason := strings.TrimSpace(ev.Meta["reason"]); reason != "" {
		attrs = append(attrs, otlplog.String("runeward.reason", reason))
	}
	if len(ev.Args) > 0 {
		vals := make([]otlplog.Value, 0, len(ev.Args))
		for _, arg := range ev.Args {
			vals = append(vals, otlplog.StringValue(arg))
		}
		attrs = append(attrs, otlplog.Slice("runeward.args", vals...))
	}
	for _, k := range sortedKeys(ev.Meta) {
		attrs = append(attrs, otlplog.String("runeward.meta."+k, ev.Meta[k]))
	}
	rec.AddAttributes(attrs...)

	return rec
}

func severityForVerdict(verdict string) (otlplog.Severity, string) {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "allow":
		return otlplog.SeverityInfo, "allow"
	case "deny":
		return otlplog.SeverityWarn, "deny"
	default:
		return otlplog.SeverityInfo, verdict
	}
}

func contextWithTrace(meta map[string]string) context.Context {
	if len(meta) == 0 {
		return context.Background()
	}
	var (
		tid   trace.TraceID
		sid   trace.SpanID
		flags trace.TraceFlags
		okT   bool
		okS   bool
	)
	if tp := strings.TrimSpace(meta["traceparent"]); tp != "" {
		var ok bool
		tid, sid, flags, ok = parseTraceparent(tp)
		if ok {
			sc := trace.NewSpanContext(trace.SpanContextConfig{
				TraceID:    tid,
				SpanID:     sid,
				TraceFlags: flags,
				Remote:     true,
			})
			return trace.ContextWithSpanContext(context.Background(), sc)
		}
	}

	tid, okT = parseTraceID(meta["trace_id"])
	sid, okS = parseSpanID(meta["span_id"])
	if !okT || !okS {
		return context.Background()
	}
	if flags, ok := parseTraceFlags(meta["trace_flags"]); ok {
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    tid,
			SpanID:     sid,
			TraceFlags: flags,
			Remote:     true,
		})
		return trace.ContextWithSpanContext(context.Background(), sc)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: tid,
		SpanID:  sid,
		Remote:  true,
	})
	return trace.ContextWithSpanContext(context.Background(), sc)
}

func parseTraceparent(s string) (trace.TraceID, trace.SpanID, trace.TraceFlags, bool) {
	parts := strings.Split(strings.TrimSpace(s), "-")
	if len(parts) != 4 {
		return trace.TraceID{}, trace.SpanID{}, 0, false
	}
	tid, ok := parseTraceID(parts[1])
	if !ok {
		return trace.TraceID{}, trace.SpanID{}, 0, false
	}
	sid, ok := parseSpanID(parts[2])
	if !ok {
		return trace.TraceID{}, trace.SpanID{}, 0, false
	}
	ff, err := strconv.ParseUint(parts[3], 16, 8)
	if err != nil {
		return trace.TraceID{}, trace.SpanID{}, 0, false
	}
	return tid, sid, trace.TraceFlags(byte(ff)), true
}

func parseTraceID(s string) (trace.TraceID, bool) {
	id, err := trace.TraceIDFromHex(strings.TrimSpace(s))
	if err != nil || !id.IsValid() {
		return trace.TraceID{}, false
	}
	return id, true
}

func parseSpanID(s string) (trace.SpanID, bool) {
	id, err := trace.SpanIDFromHex(strings.TrimSpace(s))
	if err != nil || !id.IsValid() {
		return trace.SpanID{}, false
	}
	return id, true
}

func parseTraceFlags(s string) (trace.TraceFlags, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(trimmed, 0, 8)
	if err != nil {
		return 0, false
	}
	return trace.TraceFlags(byte(v)), true
}

func parseOTLPEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("endpoint must use http(s), got %q", raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("endpoint has no host: %q", raw)
	}
	return u, nil
}

func parseKVList(raw string) (map[string]string, error) {
	out := make(map[string]string)
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		k, v, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("invalid item %q (want key=value)", item)
		}
		key := strings.TrimSpace(k)
		if key == "" {
			return nil, fmt.Errorf("empty key in %q", item)
		}
		out[key] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil, errors.New("no key=value pairs found")
	}
	return out, nil
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
