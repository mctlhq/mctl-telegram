//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// A real SIGTERM delivered through signal.NotifyContext ends run with nil.
func TestSIGTERMExitsCleanly(t *testing.T) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	f := &fakePoller{}
	done := make(chan error, 1)
	go func() { done <- run(ctx, baseEnv(), fakeDial(f, nil)) }()
	time.Sleep(200 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no clean exit after SIGTERM")
	}
}
