package edgectx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Slice 1 measured that Cf-Ray arrives on BOTH routes, so presence of a ray
// says nothing about where the call came from. Cf-Worker is what separates
// them, and that is what this has to key on.
func TestFromRequest_RouteIsDecidedByCfWorkerNotCfRay(t *testing.T) {
	portal := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	portal.Header.Set("Cf-Ray", "a39ad476896f4649-IAD")
	portal.Header.Set("Cf-Worker", "gateway.agents.cloudflare.com")
	portal.Header.Set("Mcp-Method", "tools/call")
	portal.Header.Set("Mcp-Name", "get_my_identity")
	portal.Header.Set("MCP-Protocol-Version", "2026-07-28")

	got := FromRequest(portal)
	if got.Route != RoutePortal {
		t.Errorf("Cf-Worker present must read as portal, got %q", got.Route)
	}
	if got.RequestID != "a39ad476896f4649-IAD" || got.MCPMethod != "tools/call" ||
		got.MCPName != "get_my_identity" || got.ProtocolVersion != "2026-07-28" {
		t.Errorf("fields not captured: %+v", got)
	}

	// The consumer path also carries a Cf-Ray, because the zone is proxied.
	direct := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	direct.Header.Set("Cf-Ray", "a39ac745292fb018-BEG")
	if got := FromRequest(direct); got.Route != RouteDirect {
		t.Errorf("a ray without Cf-Worker must read as direct, got %q", got.Route)
	}
	if got := FromRequest(direct); got.RequestID == "" {
		t.Error("the direct route's ray must still be recorded")
	}
}

// These values are attacker-controlled on the direct route and land in a
// database column, a JSON response and a log line.
func TestFromRequest_SanitizesHostileValues(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Cf-Ray", strings.Repeat("A", maxValue+1))
	r.Header.Set("Mcp-Method", "tools/call\nX-Injected: 1")
	r.Header.Set("Mcp-Name", "ok_name")

	got := FromRequest(r)
	if got.RequestID != "" {
		t.Errorf("an oversized value must be dropped, got %d bytes", len(got.RequestID))
	}
	if got.MCPMethod != "" {
		t.Errorf("a value with a control character must be dropped, got %q", got.MCPMethod)
	}
	if got.MCPName != "ok_name" {
		t.Errorf("a clean sibling value must survive, got %q", got.MCPName)
	}
}

// What is stored has to be what comes back out: the audit write reads this
// value and nothing else.
func TestWithAndFrom_RoundTrip(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Cf-Ray", "ray-1")
	r.Header.Set("Cf-Worker", "gateway.agents.cloudflare.com")

	got := From(With(r.Context(), FromRequest(r)))
	if got.RequestID != "ray-1" || got.Route != RoutePortal {
		t.Fatalf("round trip lost the facts: %+v", got)
	}
	if got.Empty() {
		t.Error("a captured context must not read as empty")
	}
}

// A caller with no HTTP request behind it (an internal path, a test) must
// produce the zero value rather than a fabricated route.
func TestFrom_WithoutMiddlewareIsEmpty(t *testing.T) {
	if got := From(httptest.NewRequest(http.MethodGet, "/", nil).Context()); !got.Empty() {
		t.Errorf("want empty, got %+v", got)
	}
}
