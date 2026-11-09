// Package facade is the HTTP surface of the Glovo MCP facade: router,
// middleware, limits, audit, metrics and lifecycle. It serves only the frozen
// routes; every unknown path is 404.
package facade

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"

	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/config"
	"github.com/mctlhq/mctl-telegram/internal/glovo/contract"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
	"github.com/mctlhq/mctl-telegram/internal/glovo/tools"
)

const (
	// MaxRequestBytes caps request bodies.
	MaxRequestBytes = 64 << 10
	requestTimeout  = 30 * time.Second
)

// SupportedProtocolVersions is the pinned MCP protocol list. mcp-go may know
// more; a library bump must not silently widen what the facade speaks.
var SupportedProtocolVersions = []string{"2025-06-18", "2025-03-26"}

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Options builds a Facade. Verifier and API may be nil only when
// Config.Enabled is false.
type Options struct {
	Config   config.Config
	Contract *contract.Contract
	Verifier *authn.Verifier
	API      mctlapi.Client
	Logger   *slog.Logger
	Version  string
}

// Facade is the assembled HTTP handler and its lifecycle state.
type Facade struct {
	opt      Options
	m        *metrics
	mcp      http.Handler
	meta     http.Handler
	draining atomic.Bool
	inflight chan struct{}
	salt     []byte
	allow    *net.IPNet
	limiter  *principalLimiter
}

// New assembles the facade.
func New(opt Options) (*Facade, error) {
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	f := &Facade{opt: opt, m: newMetrics(), inflight: make(chan struct{}, opt.Config.MaxInflight), salt: make([]byte, 16)}
	_, _ = rand.Read(f.salt)
	_, f.allow, _ = net.ParseCIDR(opt.Config.MetricsAllowCIDR)
	f.limiter = newPrincipalLimiter(opt.Config.RatePerMin, opt.Config.Burst)
	f.meta = authn.MetadataHandler(opt.Config.Resource, opt.Config.AuthorizationServer, opt.Contract.Scopes)

	if opt.Config.Enabled {
		if opt.Verifier == nil || opt.API == nil {
			return nil, errors.New("facade: verifier and API are required when enabled")
		}
		srv, err := tools.NewMCPServer(tools.Deps{
			Contract: opt.Contract, API: opt.API, Version: opt.Version,
			Allow: func(sub string) bool {
				ok := f.limiter.allow(sub)
				if !ok {
					f.m.rateLimited.Inc()
				}
				return ok
			},
			Observe: f.observeTool,
		})
		if err != nil {
			return nil, err
		}
		f.mcp = mcpserver.NewStreamableHTTPServer(srv, mcpserver.WithStateLess(true))
	}
	return f, nil
}

// ObserveUpstream records one mctl-api request (wire it to the client's OnCall).
func (f *Facade) ObserveUpstream(op string, status int) {
	f.m.upstream.WithLabelValues(op, codeLabel(status)).Inc()
}

// SetDraining makes readiness fail (SIGTERM).
func (f *Facade) SetDraining() { f.draining.Store(true) }

func (f *Facade) hash(v string) string {
	h := sha256.New()
	h.Write(f.salt)
	h.Write([]byte(v))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// observeTool is the single audit record per tool call: no tokens, handoff
// URLs, arguments or results.
func (f *Facade) observeTool(ev tools.Event) {
	f.m.toolCalls.WithLabelValues(ev.Tool, ev.Outcome).Inc()
	f.m.toolDuration.WithLabelValues(ev.Tool).Observe(ev.Duration.Seconds())
	f.opt.Logger.Info("glovo tool call",
		slog.String("tool", ev.Tool),
		slog.String("outcome", ev.Outcome),
		slog.Int64("latency_ms", ev.Duration.Milliseconds()),
		slog.String("principal_hash", f.hash(ev.Subject)),
		slog.String("tenant_hash", f.hash(ev.Tenant)),
		slog.String("request_id", ev.RequestID),
	)
}

// Handler returns the router.
func (f *Facade) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(f.requestID, f.countHTTP, middleware.Recoverer, middleware.Timeout(requestTimeout))
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	r.Get("/readyz", f.readyz)
	r.Get("/metrics", f.metricsHandler)
	r.Get("/.well-known/oauth-protected-resource", f.meta.ServeHTTP)
	r.Get(authn.MetadataPath, f.meta.ServeHTTP)
	r.Method(http.MethodPost, "/mcp", f.hostGuard(http.HandlerFunc(f.serveMCP)))
	r.Method(http.MethodGet, "/mcp", f.hostGuard(http.HandlerFunc(f.serveMCP)))
	r.Method(http.MethodDelete, "/mcp", f.hostGuard(http.HandlerFunc(f.serveMCP)))
	return r
}

// parseHostAuthority rejects malformed or ambiguous HTTP Host authorities.
// In particular, Host is not a URL: userinfo, paths, or query parameters are
// never allowed. Brackets are required for IPv6 literals.
func parseHostAuthority(raw string) (host, port string, valid bool) {
	if raw == "" || strings.ContainsAny(raw, "/\\?#@ \t\r\n") || strings.HasSuffix(raw, ":") {
		return "", "", false
	}
	u, err := url.Parse("http://" + raw)
	if err != nil || u.User != nil || u.Host != raw || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", false
	}
	host = strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", false
	}
	port = u.Port()
	if port != "" {
		for _, c := range port {
			if c < '0' || c > '9' {
				return "", "", false
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", false
		}
		port = strconv.Itoa(n)
	}
	return host, port, true
}

// hostGuard requires the public hostname and its effective HTTPS/HTTP port
// (DNS-rebinding protection). Explicit default ports such as :443 are valid.
// Dev-only loopback exceptions keep the local MCP harness usable.
func (f *Facade) hostGuard(next http.Handler) http.Handler {
	wantHost, wantPort, defaultPort := "", "", ""
	if u, err := url.Parse(f.opt.Config.PublicBaseURL); err == nil && u.Host != "" {
		wantHost = strings.ToLower(u.Hostname())
		wantPort = u.Port()
		switch u.Scheme {
		case "https":
			defaultPort = "443"
		case "http":
			defaultPort = "80"
		}
		if wantPort == "" {
			wantPort = defaultPort
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantHost != "" {
			host, port, valid := parseHostAuthority(r.Host)
			ok := valid && host == wantHost &&
				(port == wantPort || (port == "" && wantPort == defaultPort))
			if !ok && valid && f.opt.Config.Dev {
				ip := net.ParseIP(host)
				ok = host == "localhost" || (ip != nil && ip.IsLoopback())
			}
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (f *Facade) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(authn.WithRequestID(r.Context(), id)))
	})
}

func routeName(p string) string {
	switch {
	case p == "/mcp":
		return "mcp"
	case strings.HasPrefix(p, "/.well-known/oauth-protected-resource"):
		return "metadata"
	case p == "/healthz", p == "/readyz", p == "/metrics":
		return p[1:]
	}
	return "other"
}

func (f *Facade) countHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		st := ww.Status()
		if st == 0 {
			st = http.StatusOK
		}
		f.m.httpReqs.WithLabelValues(routeName(r.URL.Path), codeLabel(st)).Inc()
	})
}

func (f *Facade) readyz(w http.ResponseWriter, r *http.Request) {
	ok := f.opt.Config.Enabled && !f.draining.Load() && f.opt.Verifier != nil && f.opt.Verifier.JWKSLoaded()
	if ok {
		ok = f.opt.API.Health(r.Context()) == nil
	}
	if !ok {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	_, _ = io.WriteString(w, "ready")
}

func (f *Facade) metricsHandler(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); err != nil || ip == nil || f.allow == nil || !f.allow.Contains(ip) {
		http.NotFound(w, r)
		return
	}
	promhttp.HandlerFor(f.m.reg, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

func (f *Facade) serveMCP(w http.ResponseWriter, r *http.Request) {
	if !f.opt.Config.Enabled {
		http.Error(w, "glovo mcp disabled", http.StatusServiceUnavailable)
		return
	}
	metaURL := f.opt.Config.PublicBaseURL + authn.MetadataPath
	chain := authn.Middleware(f.opt.Verifier, metaURL, f.opt.Contract.Scopes, func(reason string) {
		f.m.authnFail.WithLabelValues(reason).Inc()
	})(http.HandlerFunc(f.guarded))
	chain.ServeHTTP(w, r)
}

// guarded runs after authentication: concurrency cap, body cap, protocol pin.
func (f *Facade) guarded(w http.ResponseWriter, r *http.Request) {
	select {
	case f.inflight <- struct{}{}:
		defer func() { <-f.inflight }()
	default:
		f.m.rateLimited.Inc()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent requests", http.StatusTooManyRequests)
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(SupportedProtocolVersions, v) {
		http.Error(w, "unsupported protocol version", http.StatusBadRequest)
		return
	}
	if r.ContentLength > MaxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > MaxRequestBytes {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if len(body) > 0 {
		var ok bool
		if body, ok = pinProtocol(body); !ok {
			http.Error(w, "unsupported method", http.StatusBadRequest)
			return
		}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	f.mcp.ServeHTTP(w, r)
}

// pinProtocol keeps initialize inside SupportedProtocolVersions by rewriting
// an unsupported requested version to the newest pinned one, and refuses the
// stateless server/discover entry point. Non-object bodies pass unchanged.
func pinProtocol(body []byte) ([]byte, bool) {
	var msg map[string]json.RawMessage
	if json.Unmarshal(body, &msg) != nil {
		return body, true
	}
	var method string
	_ = json.Unmarshal(msg["method"], &method)
	switch method {
	case "server/discover":
		return body, false
	case "initialize":
		var params map[string]json.RawMessage
		if json.Unmarshal(msg["params"], &params) != nil {
			return body, true
		}
		var v string
		_ = json.Unmarshal(params["protocolVersion"], &v)
		if slices.Contains(SupportedProtocolVersions, v) {
			return body, true
		}
		params["protocolVersion"] = json.RawMessage(strconv.Quote(SupportedProtocolVersions[0]))
		pb, err := json.Marshal(params)
		if err != nil {
			return body, true
		}
		msg["params"] = pb
		out, err := json.Marshal(msg)
		if err != nil {
			return body, true
		}
		return out, true
	}
	return body, true
}

// principalLimiter is a per-principal token bucket.
type principalLimiter struct {
	mu    sync.Mutex
	rate  rate.Limit
	burst int
	m     map[string]*rate.Limiter
}

func newPrincipalLimiter(perMin, burst int) *principalLimiter {
	return &principalLimiter{rate: rate.Limit(float64(perMin) / 60), burst: burst, m: map[string]*rate.Limiter{}}
}

func (l *principalLimiter) allow(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > 4096 {
		for k, v := range l.m {
			if v.Tokens() >= float64(l.burst) {
				delete(l.m, k)
			}
		}
	}
	lim, ok := l.m[sub]
	if !ok {
		lim = rate.NewLimiter(l.rate, l.burst)
		l.m[sub] = lim
	}
	return lim.Allow()
}

// Serve runs the HTTP server until ctx is cancelled (SIGTERM), then fails
// readiness, stops accepting and drains in-flight requests for up to drain.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener, f *Facade, drain time.Duration) error {
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	f.SetDraining()
	shut, cancel := context.WithTimeout(context.Background(), drain)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
