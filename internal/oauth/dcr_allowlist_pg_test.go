package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// newPostgresOAuthStore opens TEST_DATABASE_URL in a schema of its own, so
// this package's rows never meet internal/db's tests, which run in parallel
// against the same database and clear oauth_client_registrations.
func newPostgresOAuthStore(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := db.Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	schema := fmt.Sprintf("oauth_dcr_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := db.Open(ctx, u.String(), 2, 1)
	if err != nil {
		t.Fatalf("open schema-scoped conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

func clientRegIDs(t *testing.T, store *db.Store) []string {
	t.Helper()
	rows, err := store.DB.Query(`SELECT client_id FROM oauth_client_registrations ORDER BY client_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestDCRAllowlist_PostgresPinnedWiring drives POST /oauth/register through
// the useDB path, the seam between the handler and the store that the
// in-memory tests and the SQL-only test each miss:
//   - replaying the pinned registration at the registration cap evicts no
//     real dynamic registration (it adds no row, so it needs no room);
//   - the pinned row's client_name is the server-assigned
//     db.PinnedClientName whatever the caller sends, stored and answered;
//   - the pinned client authorizes from the database.
func TestDCRAllowlist_PostgresPinnedWiring(t *testing.T) {
	store := newPostgresOAuthStore(t)
	srv, err := New(context.Background(), Config{
		Issuer:               testIssuer,
		JWTSecret:            testJWTSecret,
		TelegramOIDC:         newFakeAuthenticator(),
		AllowImplicitClient:  true,
		UseDBForOAuth:        true,
		MaxRegisteredClients: 2,
		DCRRedirectURIs:      []string{dcrPortalCallback, dcrDashCallback},
	}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !srv.useDB {
		t.Fatal("server is not on the DB path")
	}
	mux := newMockRouter()
	srv.Register(mux)

	// Fill the cap with two real dynamic registrations.
	for i := 0; i < 2; i++ {
		if code, resp := registerURIs(t, mux, fmt.Sprintf("203.0.113.%d", 70+i), "https://claude.ai/cb"); code != http.StatusCreated {
			t.Fatalf("dynamic register status = %d, body = %v", code, resp)
		}
	}
	before := clientRegIDs(t, store)
	if len(before) != 2 {
		t.Fatalf("rows before = %v, want 2", before)
	}

	register := func(ip, name string) map[string]any {
		t.Helper()
		body := fmt.Sprintf(`{"client_name":%q,"redirect_uris":[%q,%q]}`, name, dcrPortalCallback, dcrDashCallback)
		rec := registerRaw(t, mux, body, ip)
		if rec.Code != http.StatusCreated {
			t.Fatalf("pinned register status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := register("203.0.113.80", "Totally Official Telegram")
	clientID, _ := first["client_id"].(string)
	if first["client_name"] != db.PinnedClientName {
		t.Fatalf("first registration echoed client_name = %v, want %q", first["client_name"], db.PinnedClientName)
	}
	for i := 0; i < 3; i++ {
		replay := register(fmt.Sprintf("203.0.113.%d", 81+i), fmt.Sprintf("Spoof %d", i))
		if replay["client_id"] != clientID {
			t.Fatalf("replay client_id = %v, want %q", replay["client_id"], clientID)
		}
		if replay["client_name"] != db.PinnedClientName {
			t.Fatalf("replay echoed client_name = %v, want %q", replay["client_name"], db.PinnedClientName)
		}
	}

	after := clientRegIDs(t, store)
	for _, id := range before {
		if !containsString(after, id) {
			t.Fatalf("a pinned registration at the cap evicted dynamic registration %q (rows now %v)", id, after)
		}
	}
	if len(after) != 3 || !containsString(after, clientID) {
		t.Fatalf("rows after = %v, want the two dynamic rows plus %q", after, clientID)
	}

	reg, err := store.GetClientReg(context.Background(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if reg.ClientName != db.PinnedClientName {
		t.Fatalf("stored client_name = %q, want %q", reg.ClientName, db.PinnedClientName)
	}
	for _, cb := range []string{dcrPortalCallback, dcrDashCallback} {
		if err := srv.validateClient(context.Background(), clientID, cb); err != nil {
			t.Fatalf("validateClient(%q) on the DB path: %v", cb, err)
		}
	}
	if !strings.HasPrefix(clientID, db.PinnedClientIDPrefix) {
		t.Fatalf("client_id = %q, want the pinned prefix", clientID)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
