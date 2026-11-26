package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
)

func TestWorkspacePilotOnExistingRoute(t *testing.T) {
	srv := &Server{AppsPilot: true, AllowSend: true, CanaryTelegramIDs: canaryguard.Set{8511: {}}}
	handler := srv.HTTPHandler()
	for _, tc := range []struct {
		name     string
		identity auth.Identity
		wantApp  bool
	}{
		{"canary OAuth", auth.Identity{UserID: 1, TelegramID: 8511, Provider: "tg-mcp", ClientID: "host-fixture"}, true},
		{"ordinary OAuth", auth.Identity{UserID: 2, TelegramID: 8512, Provider: "tg-mcp", ClientID: "host-fixture"}, false},
		{"canary machine credential", auth.Identity{UserID: 1, TelegramID: 8511, Provider: "k8s-sa"}, false},
		{"canary without client binding", auth.Identity{UserID: 1, TelegramID: 8511, Provider: "tg-mcp"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.identity.Scopes = allToolScopes()
			mux := http.NewServeMux()
			mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
				handler.ServeHTTP(w, r.WithContext(auth.With(r.Context(), &tc.identity)))
			})
			target := httptest.NewServer(mux)
			defer target.Close()
			conn, err := client.NewStreamableHttpClient(target.URL + "/mcp")
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			var init mcp.InitializeRequest
			init.Params.ClientInfo = mcp.Implementation{Name: "workspace-pilot-test", Version: "1"}
			init.Params.ProtocolVersion = mcp.ProtocolVersion20250618
			capabilities, err := conn.Initialize(t.Context(), init)
			if err != nil {
				t.Fatal(err)
			}
			if (capabilities.Capabilities.Resources != nil) != tc.wantApp {
				t.Fatalf("unexpected resources capability: %+v", capabilities.Capabilities)
			}
			tools, err := conn.ListTools(t.Context(), mcp.ListToolsRequest{})
			if err != nil {
				t.Fatal(err)
			}
			listed := map[string]mcp.Tool{}
			for _, tool := range tools.Tools {
				listed[tool.Name] = tool
			}
			opener, hasApp := listed["telegram_dashboard"]
			_, hasSend := listed["send_message"]
			if hasApp != tc.wantApp || hasSend == tc.wantApp {
				t.Fatalf("opener available=%v, send available=%v", hasApp, hasSend)
			}
			if !tc.wantApp {
				return
			}
			if opener.Meta == nil || listed["get_my_identity"].Meta == nil ||
				listed["get_my_identity"].Meta.AdditionalFields["openai/widgetAccessible"] != false {
				t.Fatal("missing opener binding or model-only control")
			}
			var send mcp.CallToolRequest
			send.Params.Name = "send_message"
			if _, err := conn.CallTool(t.Context(), send); err == nil {
				t.Fatal("pilot must reject direct write dispatch even with every scope")
			}
		})
	}
}
