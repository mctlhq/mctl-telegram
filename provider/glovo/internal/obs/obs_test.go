package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactionOfSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	for _, k := range []string{"receipt", "approval_ref", "basket", "item", "item_name", "address", "token", "session", "Session_Token"} {
		log.Info("x", k, "canary-value")
	}
	log.With("address", "canary-value").Info("y", slog.Group("g", "token", "canary-value"))
	log.Info("z", "order_ref", "ord-1", "code", "ok")
	out := buf.String()
	if strings.Contains(out, "canary-value") {
		t.Fatalf("sensitive value leaked: %s", out)
	}
	if !strings.Contains(out, "ord-1") {
		t.Fatalf("opaque value must survive: %s", out)
	}
}

func TestAuditCarriesOpaqueFieldsOnly(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	Audit(log, EventScopeRefused, "we_1", "ord-1", "not_authorized")
	out := buf.String()
	for _, want := range []string{"scope_refused", "we_1", "ord-1", "not_authorized"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	Audit(nil, EventPurged, "", "", "")
}

func TestMetricNamesPrefixed(t *testing.T) {
	m := NewMetrics()
	m.Refusals.WithLabelValues("x").Inc()
	m.Activities.WithLabelValues("a", "ok").Inc()
	m.Duration.WithLabelValues("a").Observe(1)
	m.Mutations.WithLabelValues("applied").Inc()
	fams, err := m.Registry.Gather()
	if err != nil || len(fams) == 0 {
		t.Fatal(err)
	}
	for _, f := range fams {
		if !strings.HasPrefix(f.GetName(), "mctl_glovo_provider_") {
			t.Fatalf("bad metric name %s", f.GetName())
		}
	}
}
