package main

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakePoller struct {
	mu          sync.Mutex
	started     bool
	stopped     bool
	inflight    chan struct{} // closed when the simulated in-flight activity finishes
	stopWaited  bool
	startErr    error
	stopCalls   int
	closedCalls int
}

func (f *fakePoller) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = true
	return f.startErr
}

// Stop blocks until the in-flight activity completed, like worker.Stop.
func (f *fakePoller) Stop() {
	if f.inflight != nil {
		<-f.inflight
		f.mu.Lock()
		f.stopWaited = true
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.stopped = true
	f.stopCalls++
	f.mu.Unlock()
}

func fakeDial(f *fakePoller, got *Config) dialer {
	return func(cfg Config, _ workerParts) (poller, func(), error) {
		if got != nil {
			*got = cfg
		}
		return f, func() { f.mu.Lock(); f.closedCalls++; f.mu.Unlock() }, nil
	}
}

func failDial(t *testing.T) dialer {
	return func(Config, workerParts) (poller, func(), error) {
		t.Error("dial must not be reached")
		return nil, nil, errors.New("unreachable")
	}
}

func baseEnv(extra ...string) []string {
	return append([]string{"FAKE_ONLY=true", "HEALTH_ADDR=127.0.0.1:0"}, extra...)
}

// T12: runtime fake-only gate.
func TestRunRefusesWithoutFakeOnly(t *testing.T) {
	for _, env := range [][]string{
		{}, {"FAKE_ONLY=false"},
		baseEnv("GLOVO_SESSION_TOKEN=x"), baseEnv("GLOVO_BASE_URL=http://127.0.0.1"),
	} {
		if err := run(context.Background(), env, failDial(t)); err == nil {
			t.Fatalf("env %v must be refused", env)
		}
	}
}

// T13: Temporal identity confinement.
func TestRunRefusesForeignNamespaceAndQueue(t *testing.T) {
	for _, ns := range []string{"mctl-assistants", "mctl-agents", "kuptsi", "default"} {
		err := run(context.Background(), baseEnv("TEMPORAL_NAMESPACE="+ns), failDial(t))
		if err == nil || !strings.Contains(err.Error(), "TEMPORAL_NAMESPACE") {
			t.Fatalf("namespace %s: err=%v", ns, err)
		}
	}
	for _, q := range []string{"assistants-control", "mctl-agents", "assistants"} {
		err := run(context.Background(), baseEnv("TEMPORAL_TASK_QUEUE="+q), failDial(t))
		if err == nil || !strings.Contains(err.Error(), "TEMPORAL_TASK_QUEUE") {
			t.Fatalf("queue %s: err=%v", q, err)
		}
	}
}

func TestLoadConfigDefaultsAndValidation(t *testing.T) {
	c, err := LoadConfig(nil)
	if err != nil || c.Namespace != "mctl-assistants-provider-glovo" || c.TaskQueue != "assistants-provider-glovo" ||
		c.HealthAddr != ":8081" || c.StopTimeout != 25*time.Second || c.Disabled {
		t.Fatalf("cfg=%+v err=%v", c, err)
	}
	for _, env := range [][]string{
		{"GLOVO_PROVIDER_DISABLED=maybe"}, {"WORKER_STOP_TIMEOUT=1h"}, {"WORKER_STOP_TIMEOUT=x"},
		{"TEMPORAL_TLS_CERT_FILE=/a"},
	} {
		if _, err := LoadConfig(env); err == nil {
			t.Fatalf("%v must fail", env)
		}
	}
	if c, err := LoadConfig([]string{"GLOVO_PROVIDER_DISABLED=true"}); err != nil || !c.Disabled {
		t.Fatalf("kill switch: %+v %v", c, err)
	}
	if tc, err := (Config{}).TLSConfig(); tc != nil || err != nil {
		t.Fatal("no TLS expected without files")
	}
}

func get(t *testing.T, url string) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// T14: SIGTERM-equivalent shutdown waits for the in-flight activity and
// returns nil (exit 0).
func TestGracefulShutdownWaitsForInflight(t *testing.T) {
	f := &fakePoller{inflight: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, baseEnv(), fakeDial(f, nil)) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		t.Fatalf("returned before in-flight finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(f.inflight)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.started || !f.stopped || !f.stopWaited || f.closedCalls != 1 || f.stopCalls != 1 {
		t.Fatalf("poller state: %+v", f)
	}
}

func TestStartFailureAndDialFailure(t *testing.T) {
	f := &fakePoller{startErr: errors.New("boom")}
	if err := run(context.Background(), baseEnv(), fakeDial(f, nil)); err == nil {
		t.Fatal("start failure must be reported")
	}
	err := run(context.Background(), baseEnv(), func(Config, workerParts) (poller, func(), error) {
		return nil, nil, errors.New("dial")
	})
	if err == nil {
		t.Fatal("dial failure must be reported")
	}
}

// T15 helper: the worker's only Temporal handle is the poller. No non-test
// source file may call a client control method.
func TestNoTemporalClientControlCalls(t *testing.T) {
	forbidden := map[string]bool{
		"SignalWorkflow": true, "ListWorkflow": true, "TerminateWorkflow": true, "CancelWorkflow": true,
		"QueryWorkflow": true, "ExecuteWorkflow": true, "SignalWithStartWorkflow": true,
		"ListOpenWorkflow": true, "ListClosedWorkflow": true, "ListWorkflowExecutions": true,
	}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		n++
		ast.Inspect(f, func(node ast.Node) bool {
			if sel, ok := node.(*ast.SelectorExpr); ok && forbidden[sel.Sel.Name] {
				t.Errorf("%s: forbidden call %s", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("scanned only %d files; wrong root?", n)
	}
}

// The Temporal client must only be created in dialTemporal.
func TestClientDialedOnlyInDialTemporal(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, _ := parser.ParseFile(fset, path, nil, 0)
		ast.Inspect(f, func(node ast.Node) bool {
			if sel, ok := node.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Dial" || sel.Sel.Name == "NewLazyClient") {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "client" && filepath.Base(path) != "main.go" {
					t.Errorf("%s: client constructed outside main.go", fset.Position(sel.Pos()))
				}
			}
			return true
		})
		return nil
	})
}

func TestVersionDefault(t *testing.T) {
	if version == "" {
		t.Fatal("version empty")
	}
	_ = os.Args
}
