package oauth

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// lockedBuffer is a bytes.Buffer safe to write from a login goroutine while
// the test reads it (CI runs with -race).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// pendingLogs maps a test to the buffer its servers log into. Tests call
// captureServerLog before they build the Server, and the test constructors
// hand the server the matching logger (adoptTestLogger). The process-wide
// slog default is never swapped: a goroutine that outlives its test could
// otherwise write into a later test's buffer and race with its reads.
var pendingLogs sync.Map // *testing.T -> *lockedBuffer

// captureServerLog returns a buffer that receives the log output of every
// Server the calling test constructs afterwards through the test constructors.
func captureServerLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	pendingLogs.Store(t, buf)
	t.Cleanup(func() { pendingLogs.Delete(t) })
	return buf
}

// captureServerLogFor is captureServerLog for a server that already exists,
// for tests that must not capture the lines logged while it was set up.
func captureServerLogFor(t *testing.T, srv *Server) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	srv.log = slog.New(slog.NewTextHandler(buf, nil))
	return buf
}

// adoptTestLogger points srv at the test's captured buffer, if it has one, and
// joins srv's login-flow goroutines when the test ends.
func adoptTestLogger(t *testing.T, srv *Server) {
	t.Helper()
	if v, ok := pendingLogs.Load(t); ok {
		srv.log = slog.New(slog.NewTextHandler(v.(*lockedBuffer), nil))
	}
	t.Cleanup(func() { stopLoginFlows(t, srv) })
}

// stopLoginFlows cancels every flow still registered and waits for all
// startLoginFlow goroutines to return, so none outlives its test.
func stopLoginFlows(t *testing.T, srv *Server) {
	t.Helper()
	srv.loginFlows.Range(func(_, v any) bool {
		if lf, ok := v.(*loginFlow); ok && lf != nil && lf.cancel != nil {
			lf.cancel()
		}
		return true
	})
	done := make(chan struct{})
	go func() { srv.flowWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Error("login flow goroutines still running 10s after the test ended")
	}
}

// TestServerLogger_LeakedFlowDoesNotTouchDefaultLogger is the regression test
// for #1080. A flow that outlives the code that started it keeps logging for
// as long as its CodeTTL; those lines must go to the server's own logger and
// never to whatever slog.Default is at that moment, which another test may be
// reading through an unsynchronised buffer.
func TestServerLogger_LeakedFlowDoesNotTouchDefaultLogger(t *testing.T) {
	own := captureServerLog(t)
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 300 * time.Millisecond })
	srv.loginFn = stubLoginParksAtCode()

	// An unsynchronised sink as the process default, the shape the other
	// tests used to install. The race detector flags any write to it.
	var sentinel bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&sentinel, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	lf := srv.startLoginFlow(1, 500100101, srv.phoneLogin("+14155551234"), false, time.Now())
	waitForFlowDone(t, lf, 3*time.Second)
	srv.flowWG.Wait()

	if got := own.String(); !bytes.Contains([]byte(got), []byte("enable: onboarding abandoned")) {
		t.Errorf("the server logger did not receive the flow's log line; got:\n%s", got)
	}
	if sentinel.Len() != 0 {
		t.Errorf("the flow wrote to slog.Default:\n%s", sentinel.String())
	}
}
