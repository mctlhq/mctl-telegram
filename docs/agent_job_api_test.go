package docs

import (
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentapi"
)

// recordingRouter is the router Register binds to; it keeps the routes.
type recordingRouter struct{ routes []string }

func (r *recordingRouter) Get(pattern string, _ http.HandlerFunc) {
	r.routes = append(r.routes, "GET "+pattern)
}

func (r *recordingRouter) Post(pattern string, _ http.HandlerFunc) {
	r.routes = append(r.routes, "POST "+pattern)
}

// registeredRoutes is what agentapi.Server.Register binds, sorted.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	rec := &recordingRouter{}
	(&agentapi.Server{}).Register(rec)
	slices.Sort(rec.routes)
	return rec.routes
}

const (
	contractPath    = "contracts/agent-job-api.md"
	threatModelPath = "agent-runtime/threat-model.md"
	routeTableHead  = "| Method | Path |"
)

// contractRoutes reads the route table of the contract: the rows under a
// header that starts with routeTableHead, as "METHOD path".
func contractRoutes(t *testing.T, doc string) []string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), routeTableHead) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s has no route table (header starting %q)", contractPath, routeTableHead)
	}
	var routes []string
	for _, l := range lines[start+2:] {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "|") {
			break
		}
		cells := strings.Split(strings.Trim(l, "|"), "|")
		if len(cells) < 2 {
			t.Fatalf("route row has %d cells: %s", len(cells), l)
		}
		method := strings.Trim(strings.TrimSpace(cells[0]), "`")
		path := strings.Trim(strings.TrimSpace(cells[1]), "`")
		routes = append(routes, method+" "+path)
	}
	slices.Sort(routes)
	return routes
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// Register still binds exactly these routes. A change to the list is a change
// to the agent job API: update the contract and the threat model with it.
func TestRegister_RoutesUnchanged(t *testing.T) {
	want := []string{
		"GET /conversations/{id}/context",
		"GET /conversations/{id}/leads",
		"GET /event/{eventID}",
		"GET /events",
		"GET /jobs/{id}",
		"GET /leads/{id}",
		"GET /policy",
		"GET /recruiters/{peer}",
		"POST /actions/propose_reply",
		"POST /actions/request_owner_approval",
		"POST /autopilot/pause",
		"POST /jobs/claim",
		"POST /jobs/{id}/complete",
		"POST /jobs/{id}/cost",
		"POST /jobs/{id}/retry",
		"POST /leads",
		"POST /notify/summary",
	}
	if got := registeredRoutes(t); !slices.Equal(got, want) {
		t.Fatalf("Register binds\n%q\nwant\n%q", got, want)
	}
}

// The contract lists every registered route and no other.
func TestAgentJobAPIContract_RouteTableMatchesRegister(t *testing.T) {
	got := contractRoutes(t, readDoc(t, contractPath))
	want := registeredRoutes(t)
	if !slices.Equal(got, want) {
		t.Fatalf("%s route table\n%q\ndiffers from Register\n%q", contractPath, got, want)
	}
}

// The threat model names every registered route, as `METHOD path`, in its
// read-exposure table or its threat list.
func TestThreatModel_NamesEveryRoute(t *testing.T) {
	doc := readDoc(t, threatModelPath)
	for _, route := range registeredRoutes(t) {
		if !strings.Contains(doc, "`"+route+"`") {
			t.Errorf("%s does not name `%s`", threatModelPath, route)
		}
	}
}

// The four documents state the same credential boundary and describe the
// managed runtime as implemented, not planned.
func TestCredentialBoundary_DocumentsAgree(t *testing.T) {
	stale := regexp.MustCompile(`(?is)agent-pool[^.]*(planned|not implemented)`)
	for _, path := range []string{contractPath, threatModelPath, "assistants/spec.md", "agent-worker.md"} {
		doc := readDoc(t, path)
		for _, want := range []string{"aud=agent", "agent-pool", "aud=agent-job"} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s does not mention %q", path, want)
			}
		}
		if strings.Contains(strings.ToLower(doc), "planned, not implemented") {
			t.Errorf("%s still says the managed runtime is planned, not implemented", path)
		}
		if loc := stale.FindString(doc); loc != "" {
			t.Errorf("%s still marks agent-pool as planned or not implemented: %q", path, loc)
		}
	}
}
