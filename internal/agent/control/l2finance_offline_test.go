//go:build l2finance

package control

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestL2Finance_OfflineGuard shows that the DEFAULT transport and resolver
// refuse non-loopback traffic. It is not a whole-process egress firewall.
func TestL2Finance_OfflineGuard(t *testing.T) {
	tr := http.DefaultTransport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "192.0.2.1:443"); !errors.Is(err, errL2ExternalDial) {
		t.Fatalf("TEST-NET-1 dial err = %v, want errL2ExternalDial", err)
	}
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "example.invalid"); err == nil ||
		!strings.Contains(err.Error(), errL2ExternalDial.Error()) {
		t.Fatalf("DNS lookup err = %v, want refusal", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, err := tr.DialContext(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial: %v", err)
	}
	_ = c.Close()
	l2Record(t, "OFFLINE.default_paths", l2Pass, "TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed")
}
