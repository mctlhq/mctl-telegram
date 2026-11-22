package linking_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// RequireIss comes from the server's RFC 8414 metadata (#1338), and the
// metadata fails closed: an unreadable or malformed document is an error,
// never "the server does not send iss".

func TestParseASMetadata(t *testing.T) {
	const iss = "https://as.tg.example.test"
	for name, c := range map[string]struct {
		body    string
		want    bool
		wantErr bool
	}{
		"supported":             {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":true}`, want: true},
		"not supported":         {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":false}`},
		"absent means false":    {body: `{"issuer":"` + iss + `"}`},
		"string, not boolean":   {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":"true"}`, wantErr: true},
		"null":                  {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":null}`, wantErr: true},
		"number":                {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":1}`, wantErr: true},
		"other issuer":          {body: `{"issuer":"https://as.evil.example.test","authorization_response_iss_parameter_supported":true}`, wantErr: true},
		"no issuer":             {body: `{"authorization_response_iss_parameter_supported":true}`, wantErr: true},
		"issuer not a string":   {body: `{"issuer":7}`, wantErr: true},
		"not JSON":              {body: `<html>`, wantErr: true},
		"array":                 {body: `[]`, wantErr: true},
		"JSON null":             {body: `null`, wantErr: true},
		"empty":                 {body: ``, wantErr: true},
		"trailing data":         {body: `{"issuer":"` + iss + `"} {}`, wantErr: true},
		"stray closing brace":   {body: `{"issuer":"` + iss + `"}}`, wantErr: true},
		"stray closing bracket": {body: `{"issuer":"` + iss + `"}]`, wantErr: true},
		"trailing whitespace":   {body: `{"issuer":"` + iss + `"}` + "\n"},
		"truncated":             {body: `{"issuer":"` + iss + `","authorization_response_iss_parameter_supported":tr`, wantErr: true},
	} {
		md, err := linking.ParseASMetadata([]byte(c.body), iss)
		if c.wantErr {
			if !errors.Is(err, linking.ErrASMetadata) {
				t.Errorf("%s: %+v, %v; want ErrASMetadata", name, md, err)
			}
			continue
		}
		if err != nil || md.IssParameterSupported != c.want || md.Issuer != iss {
			t.Errorf("%s: %+v, %v; want supported=%v", name, md, err, c.want)
		}
	}
}

func TestMetadataURL(t *testing.T) {
	for issuer, want := range map[string]string{
		"https://as.example.test":         "https://as.example.test/.well-known/oauth-authorization-server",
		"https://as.example.test/":        "https://as.example.test/.well-known/oauth-authorization-server",
		"https://as.example.test/tenant1": "https://as.example.test/.well-known/oauth-authorization-server/tenant1",
	} {
		if got, err := linking.MetadataURL(issuer); err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", issuer, got, err, want)
		}
	}
	for _, bad := range []string{"http://as.example.test", "https://", "https://as.example.test?x=1", "::"} {
		if _, err := linking.MetadataURL(bad); !errors.Is(err, linking.ErrASMetadata) {
			t.Errorf("%s: %v, want ErrASMetadata", bad, err)
		}
	}
}

func TestFetchASMetadata(t *testing.T) {
	var status int
	var body string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	status, body = http.StatusOK, `{"issuer":"`+srv.URL+`","authorization_response_iss_parameter_supported":true}`
	md, err := linking.FetchASMetadata(ctx, srv.Client(), srv.URL)
	if err != nil || !md.IssParameterSupported {
		t.Fatalf("fetch: %+v, %v; want supported", md, err)
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"server error":          {http.StatusInternalServerError, `{"issuer":"` + srv.URL + `"}`},
		"not found":             {http.StatusNotFound, ``},
		"malformed with 200":    {http.StatusOK, `{"issuer":`},
		"other issuer with 200": {http.StatusOK, `{"issuer":"https://as.evil.example.test"}`},
	} {
		status, body = c.status, c.body
		if md, err := linking.FetchASMetadata(ctx, srv.Client(), srv.URL); !errors.Is(err, linking.ErrASMetadata) {
			t.Errorf("%s: %+v, %v; want ErrASMetadata", name, md, err)
		}
	}
	srv.Close()
	if _, err := linking.FetchASMetadata(ctx, srv.Client(), srv.URL); !errors.Is(err, linking.ErrASMetadata) {
		t.Errorf("unreachable server: %v, want ErrASMetadata", err)
	}
	if _, err := linking.FetchASMetadata(ctx, nil, srv.URL); !errors.Is(err, linking.ErrConfig) {
		t.Errorf("nil client: %v, want ErrConfig", err)
	}
}

// RequireIss follows the metadata: a server that sends iss gets a missing
// iss refused (TestLinking_S1L5_CallbackChecks), one that does not gets it
// accepted, a wrong iss is refused either way, and an enabled server
// without metadata for its issuer does not run at all.
func TestLinking_RequireIssFromMetadata(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		ctx := context.Background()
		h := newHarness(t, s, false)
		sc := h.servers[connection.ServerTG]
		sc.Metadata = &linking.ASMetadata{Issuer: sc.Issuer, IssParameterSupported: false}
		h.servers[connection.ServerTG] = sc

		cb := h.toCallback(connection.ServerTG, h.tgLogin(h.alice))
		wrong := cloneValues(cb)
		wrong.Set("iss", "https://as.evil.example.test")
		if _, err := h.svc.Callback(ctx, connection.ServerTG, wrong); err == nil {
			t.Fatal("wrong iss accepted from a server that does not send iss")
		}
		missing := cloneValues(cb)
		missing.Del("iss")
		if _, err := h.svc.Callback(ctx, connection.ServerTG, missing); err != nil {
			t.Fatalf("missing iss from a server whose metadata says it does not send iss: %v", err)
		}

		for name, md := range map[string]*linking.ASMetadata{
			"no metadata":           nil,
			"metadata of another":   {Issuer: "https://as.evil.example.test", IssParameterSupported: true},
			"metadata with no name": {IssParameterSupported: true},
		} {
			sc.Metadata = md
			h.servers[connection.ServerTG] = sc
			if _, err := h.svc.StartLink(ctx, principal(t, h.alice), connection.ServerTG); !errors.Is(err, linking.ErrConfig) {
				t.Errorf("%s: StartLink %v, want ErrConfig", name, err)
			}
			cfg := linking.Config{
				BotToken: paBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
				AppURL: appURL, Servers: h.servers, Manager: h.m, Store: s, Tokens: tokenClient{h.as},
				Accounts: h.accounts, Messenger: h.msgr, Allowed: h.allow,
			}
			if _, err := linking.New(cfg); !errors.Is(err, linking.ErrConfig) {
				t.Errorf("%s: New %v, want ErrConfig", name, err)
			}
		}
	})
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vv := range v {
		out[k] = append([]string(nil), vv...)
	}
	return out
}

// The endpoint fields are read for the startup cross-check (#1318 C2):
// absent is "", and a present value that is not a non-empty string is
// unreadable, never absent.
func TestParseASMetadata_Endpoints(t *testing.T) {
	const iss = "https://as.tg.example.test"
	md, err := linking.ParseASMetadata([]byte(`{"issuer":"`+iss+`","authorization_endpoint":"`+iss+`/a",`+
		`"token_endpoint":"`+iss+`/t","revocation_endpoint":"`+iss+`/r"}`), iss)
	if err != nil || md.AuthorizationEndpoint != iss+"/a" || md.TokenEndpoint != iss+"/t" || md.RevocationEndpoint != iss+"/r" {
		t.Fatalf("%+v, %v", md, err)
	}
	if md, err := linking.ParseASMetadata([]byte(`{"issuer":"`+iss+`"}`), iss); err != nil ||
		md.AuthorizationEndpoint != "" || md.TokenEndpoint != "" || md.RevocationEndpoint != "" {
		t.Fatalf("absent: %+v, %v", md, err)
	}
	for _, field := range []string{"authorization_endpoint", "token_endpoint", "revocation_endpoint"} {
		for _, v := range []string{`""`, `null`, `7`, `["x"]`} {
			body := `{"issuer":"` + iss + `","` + field + `":` + v + `}`
			if _, err := linking.ParseASMetadata([]byte(body), iss); !errors.Is(err, linking.ErrASMetadata) {
				t.Errorf("%s=%s: %v, want ErrASMetadata", field, v, err)
			}
		}
	}
}
