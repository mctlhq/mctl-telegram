package mcpui

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// TestWorkspaceHandshakeInChrome drives the embedded document in headless
// Chrome. CI runners do not install a browser; TestWorkspaceNegotiatesProtocolVersions
// is the source contract that still runs there. This test is the execution
// of that contract: a 2025-11-21 host (including one whose origin is the
// sandbox string "null"), a 2026-01-26 host, an unknown version, and a
// sibling frame.
func TestWorkspaceHandshakeInChrome(t *testing.T) {
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		chrome, err = exec.LookPath("chromium")
	}
	if err != nil {
		chrome, err = exec.LookPath("chromium-browser")
	}
	if err != nil {
		t.Skip("chrome not installed")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/workspace.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, workspaceHTML)
	})
	mux.HandleFunc("/host.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, workspaceHostHTML)
	})
	mux.HandleFunc("/sibling.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, workspaceSiblingHTML)
	})
	mux.HandleFunc("/proxy.html", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, workspaceProxyHTML)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	raw, err := chromeReport(ctx, chrome, srv.URL+"/host.html")
	if err != nil {
		t.Fatalf("chrome handshake: %v", err)
	}
	var report handshakeReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		t.Fatalf("decode report: %v\n%s", err, raw)
	}
	assertHandshake(t, report)
}

// chromeReport loads the host page in headless Chrome and returns the text
// the page writes once every frame has finished the handshake. dump-dom
// snapshots before those frames load, so this waits on the page through the
// DevTools protocol instead.
func chromeReport(ctx context.Context, chrome, pageURL string) (string, error) {
	dir, err := os.MkdirTemp("", "workspace-chrome-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, chrome,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--no-first-run",
		"--no-default-browser-check",
		"--window-size=800,600",
		"--remote-debugging-port=0",
		"--user-data-dir="+filepath.Join(dir, "profile"),
		pageURL,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	defer func() {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = cmd.Wait()
	}()

	port, err := chromeDebugPort(ctx, stderr)
	if err != nil {
		return "", err
	}
	wsURL, err := chromePageSocket(ctx, port, pageURL)
	if err != nil {
		return "", err
	}
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return "", err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)
	const expr = `new Promise((resolve) => {
	  const start = Date.now();
	  const tick = () => {
	    const el = document.getElementById("out");
	    const text = el ? el.textContent : "";
	    if (text && text !== "PENDING") { resolve(text); return; }
	    if (Date.now() - start > 8000) { resolve(text || "TIMEOUT"); return; }
	    setTimeout(tick, 50);
	  };
	  tick();
	})`
	var lastErr string
	for attempt := 1; attempt <= 8; attempt++ {
		body, err := json.Marshal(map[string]any{
			"id": attempt, "method": "Runtime.evaluate",
			"params": map[string]any{"expression": expr, "awaitPromise": true, "returnByValue": true},
		})
		if err != nil {
			return "", err
		}
		if err := conn.Write(ctx, websocket.MessageText, body); err != nil {
			return "", err
		}
		value, again, err := readEval(ctx, conn, attempt)
		if err != nil {
			return "", err
		}
		if again {
			lastErr = value
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if value == "" || value == "PENDING" || value == "TIMEOUT" {
			return "", errChrome("host report " + value)
		}
		return value, nil
	}
	return "", errChrome(lastErr)
}

func readEval(ctx context.Context, conn *websocket.Conn, id int) (string, bool, error) {
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return "", false, err
		}
		var envelope struct {
			ID     int `json:"id"`
			Result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
				Exception json.RawMessage `json:"exceptionDetails"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(msg, &envelope); err != nil || envelope.ID != id {
			continue
		}
		detail := string(envelope.Error) + string(envelope.Result.Exception)
		if strings.Contains(detail, "destroyed") || strings.Contains(detail, "Cannot find context") {
			return detail, true, nil
		}
		if detail != "" {
			return "", false, errChrome(detail)
		}
		return envelope.Result.Result.Value, false, nil
	}
}

type chromeError string

func (e chromeError) Error() string { return string(e) }

func errChrome(text string) error { return chromeError(text) }

func chromeDebugPort(ctx context.Context, stderr io.Reader) (string, error) {
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	port := regexp.MustCompile(`127\.0\.0\.1:(\d+)/`)
	found := make(chan string, 1)
	go func() {
		sent := false
		for scanner.Scan() {
			if sent {
				continue
			}
			if match := port.FindStringSubmatch(scanner.Text()); match != nil {
				found <- match[1]
				sent = true
			}
		}
		if !sent {
			found <- ""
		}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value := <-found:
		if value == "" {
			return "", errChrome("chrome did not publish a debugging port")
		}
		return value, nil
	}
}

func chromePageSocket(ctx context.Context, port, pageURL string) (string, error) {
	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+"/json/list", nil)
		if err != nil {
			return "", err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", err
		}
		last = string(body)
		var pages []struct {
			URL  string `json:"url"`
			WS   string `json:"webSocketDebuggerUrl"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &pages); err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		for _, page := range pages {
			if page.Type == "page" && strings.Contains(page.URL, pageURL) && page.WS != "" {
				return page.WS, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", errChrome("no debuggable page: " + last)
}

func assertHandshake(t *testing.T, report handshakeReport) {
	t.Helper()
	draft := report.Cases["draft"]
	if draft.Proposed != "2026-01-26" {
		t.Errorf("draft host: guest proposed %q, want 2026-01-26", draft.Proposed)
	}
	if !containsMethod(draft.Methods, "ui/notifications/initialized") {
		t.Errorf("draft host: missing initialized, methods %v", draft.Methods)
	}
	if !positiveHeight(draft.Heights) {
		t.Errorf("draft host: size-changed heights %v", draft.Heights)
	}
	if draft.MaxHeight != "480px" || draft.Height == "100%" {
		t.Errorf("draft host: viewport maxHeight=%q height=%q, want 480px and not a fixed container", draft.MaxHeight, draft.Height)
	}
	if draft.MinHeight != "240px" {
		t.Errorf("draft host: min-height %q, want the 2025-11-21 host size 240px", draft.MinHeight)
	}
	if draft.RefreshDisabled {
		t.Error("draft host: serverTools did not enable Refresh")
	}
	if !strings.Contains(draft.Text, "Alice") || strings.Contains(draft.Text, "Unsupported MCP Apps protocol") {
		t.Errorf("draft host: status %q text %q", draft.Status, draft.Text)
	}

	stable := report.Cases["stable"]
	if stable.Proposed != "2026-01-26" || !containsMethod(stable.Methods, "ui/notifications/initialized") || !positiveHeight(stable.Heights) {
		t.Errorf("stable host: proposed %q methods %v heights %v", stable.Proposed, stable.Methods, stable.Heights)
	}
	if stable.Height != "100%" || stable.Width != "100%" {
		t.Errorf("stable host: fixed container height=%q width=%q, want 100%%", stable.Height, stable.Width)
	}
	if stable.MinHeight == "240px" {
		t.Error("stable host applied a host-to-view size-changed, which 2026-01-26 does not define")
	}
	if strings.Contains(stable.Text, "Unsupported MCP Apps protocol") {
		t.Errorf("stable host: status %q", stable.Status)
	}

	unknown := report.Cases["unknown"]
	if unknown.Proposed != "2026-01-26" {
		t.Errorf("unknown host: guest proposed %q", unknown.Proposed)
	}
	if containsMethod(unknown.Methods, "ui/notifications/initialized") {
		t.Errorf("unknown host: sent initialized, methods %v", unknown.Methods)
	}
	if !containsMethod(unknown.Methods, "ui/notifications/size-changed") || !positiveHeight(unknown.Heights) {
		t.Errorf("unknown host: size-changed methods %v heights %v", unknown.Methods, unknown.Heights)
	}
	if !strings.Contains(unknown.Status, "Unsupported MCP Apps protocol: 1999-01-01") {
		t.Errorf("unknown host status %q", unknown.Status)
	}
	if unknown.MinHeight != "12rem" {
		t.Errorf("unknown host min-height %q, want 12rem", unknown.MinHeight)
	}
	if !unknown.RefreshDisabled {
		t.Error("unknown host enabled Refresh")
	}

	victim := report.Cases["victim"]
	if !strings.Contains(victim.Text, "Alice") || strings.Contains(victim.Text, "Bob") {
		t.Errorf("sibling frame changed the snapshot: %q", victim.Text)
	}

	if report.Opaque.Proposed != "2026-01-26" || !containsMethod(report.Opaque.Methods, "ui/notifications/initialized") || !positiveHeight(report.Opaque.Heights) {
		t.Errorf("opaque proxy: proposed %q methods %v heights %v", report.Opaque.Proposed, report.Opaque.Methods, report.Opaque.Heights)
	}
}

func containsMethod(methods []string, want string) bool {
	for _, method := range methods {
		if method == want {
			return true
		}
	}
	return false
}

func positiveHeight(heights []float64) bool {
	for _, height := range heights {
		if height > 0 {
			return true
		}
	}
	return false
}

type handshakeReport struct {
	Cases  map[string]handshakeCase `json:"cases"`
	Opaque handshakeCase            `json:"opaque"`
}

type handshakeCase struct {
	Proposed        string    `json:"proposed"`
	Methods         []string  `json:"methods"`
	Heights         []float64 `json:"heights"`
	Status          string    `json:"status"`
	MaxHeight       string    `json:"maxHeight"`
	Height          string    `json:"height"`
	Width           string    `json:"width"`
	MinHeight       string    `json:"minHeight"`
	RefreshDisabled bool      `json:"refreshDisabled"`
	Text            string    `json:"text"`
}

const workspaceHostHTML = `<!doctype html>
<meta charset="utf-8">
<iframe id="draft" src="/workspace.html"></iframe>
<iframe id="stable" src="/workspace.html"></iframe>
<iframe id="unknown" src="/workspace.html"></iframe>
<iframe id="victim" src="/workspace.html"></iframe>
<iframe id="sibling" src="/sibling.html"></iframe>
<iframe id="proxy" sandbox="allow-scripts" src="/proxy.html"></iframe>
<pre id="out">PENDING</pre>
<script>
"use strict";
const names = ["draft", "stable", "unknown", "victim"];
const frames = {};
for (const name of names) frames[name] = document.getElementById(name).contentWindow;
const proposed = {};
const methods = {};
const heights = {};
const seen = {};
let opaque = null;
for (const name of names) { methods[name] = []; heights[name] = []; }

function hostContext(name) {
  if (name === "draft") {
    return { theme: "light", displayMode: "inline", availableDisplayModes: ["inline", "fullscreen"], viewport: { width: 800, height: 600, maxHeight: 480 } };
  }
  if (name === "stable") {
    return { theme: "dark", displayMode: "inline", availableDisplayModes: ["inline", "fullscreen"], containerDimensions: { height: 420, width: 360 } };
  }
  return { theme: "light", availableDisplayModes: ["inline"] };
}
function versionOf(name) {
  if (name === "draft") return "2025-11-21";
  if (name === "unknown") return "1999-01-01";
  return "2026-01-26";
}
function alice() {
  return {
    jsonrpc: "2.0", method: "ui/notifications/tool-result",
    params: { structuredContent: {
      schema: "telegram-workspace/v1", updated_at: "2026-11-26T00:00:00.000Z",
      dialogs: { dialogs: [{ id: "user:8511", title: "Alice", type: "user", unread_count: 1, last_message_date: "2026-11-25T09:10:00Z" }] }
    } }
  };
}
function snapshot(name) {
  const doc = document.getElementById(name).contentDocument;
  const root = doc.documentElement;
  return {
    proposed: proposed[name] || "",
    methods: methods[name],
    heights: heights[name],
    status: doc.getElementById("status").textContent,
    maxHeight: root.style.maxHeight,
    height: root.style.height,
    width: root.style.width,
    minHeight: root.style.minHeight,
    refreshDisabled: doc.getElementById("refresh").disabled,
    text: doc.body.innerText
  };
}
function finish() {
  const cases = {};
  for (const name of names) cases[name] = snapshot(name);
  document.getElementById("out").textContent = JSON.stringify({ cases: cases, opaque: opaque || {} });
}
let finishTimer = 0;
function schedule() {
  if (!opaque) return;
  for (const name of names) if (!seen[name]) return;
  clearTimeout(finishTimer);
  finishTimer = setTimeout(finish, 300);
}
window.addEventListener("message", (event) => {
  const data = event.data;
  if (!data || typeof data !== "object") return;
  if (data.report) { opaque = data.report; schedule(); return; }
  let name = "";
  for (const candidate of names) if (event.source === frames[candidate]) name = candidate;
  if (!name || data.jsonrpc !== "2.0") return;
  if (data.method) {
    methods[name].push(data.method);
    if (data.method === "ui/notifications/size-changed" && data.params && typeof data.params.height === "number") {
      heights[name].push(data.params.height);
      seen[name] = true;
      schedule();
    }
  }
  if (data.method !== "ui/initialize") {
    if (data.method === "ui/notifications/initialized" && (name === "draft" || name === "victim")) {
      event.source.postMessage(alice(), "*");
    }
    if (data.method === "ui/notifications/initialized" && name === "draft") {
      event.source.postMessage({ jsonrpc: "2.0", method: "ui/notifications/size-changed", params: { height: 240 } }, "*");
    }
    if (data.method === "ui/notifications/initialized" && name === "stable") {
      event.source.postMessage({ jsonrpc: "2.0", method: "ui/notifications/size-changed", params: { height: 240 } }, "*");
    }
    return;
  }
  proposed[name] = data.params && data.params.protocolVersion;
  event.source.postMessage({
    jsonrpc: "2.0", id: data.id,
    result: {
      protocolVersion: versionOf(name),
      hostInfo: { name: "mctl-fixture-host", version: "1" },
      hostCapabilities: name === "unknown" ? {} : { serverTools: {} },
      hostContext: hostContext(name)
    }
  }, "*");
});
</script>
`

const workspaceSiblingHTML = `<!doctype html>
<meta charset="utf-8">
<script>
"use strict";
const victim = parent.document.getElementById("victim").contentWindow;
const forged = {
  jsonrpc: "2.0", method: "ui/notifications/tool-result",
  params: { structuredContent: {
    schema: "telegram-workspace/v1", updated_at: "2026-11-27T00:00:00.000Z",
    dialogs: { dialogs: [{ id: "user:4302", title: "Bob", type: "user", unread_count: 4, last_message_date: "2026-11-25T08:02:00Z" }] }
  } }
};
setInterval(() => victim.postMessage(forged, "*"), 40);
</script>
`

const workspaceProxyHTML = `<!doctype html>
<meta charset="utf-8">
<iframe id="app" src="/workspace.html"></iframe>
<script>
"use strict";
const frame = document.getElementById("app");
const methods = [];
const heights = [];
let proposed = "";
window.addEventListener("message", (event) => {
  if (event.source !== frame.contentWindow) return;
  const data = event.data;
  if (!data || data.jsonrpc !== "2.0") return;
  if (data.method) methods.push(data.method);
  if (data.method === "ui/notifications/size-changed" && data.params && typeof data.params.height === "number") {
    heights.push(data.params.height);
  }
  if (data.method !== "ui/initialize") return;
  proposed = data.params && data.params.protocolVersion;
  frame.contentWindow.postMessage({
    jsonrpc: "2.0", id: data.id,
    result: {
      protocolVersion: "2025-11-21",
      hostInfo: { name: "sandbox-proxy", version: "1" },
      hostCapabilities: { serverTools: {} },
      hostContext: { theme: "light", viewport: { width: 320, height: 240, maxHeight: 360 } }
    }
  }, "*");
});
let published = false;
function publish() {
  if (published) return;
  published = true;
  parent.postMessage({ report: { proposed: proposed, methods: methods, heights: heights } }, "*");
}
function ready() {
  return methods.indexOf("ui/notifications/initialized") >= 0 && heights.length > 0;
}
setTimeout(function wait() {
  if (ready()) { publish(); return; }
  setTimeout(wait, 50);
}, 50);
setTimeout(publish, 4000);
</script>
`
