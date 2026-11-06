package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const danaTelegramID = 500100101

func readSignUpRecord(t *testing.T, srv *Server) (state, client, heardFrom, utm string) {
	t.Helper()
	err := srv.store.DB.QueryRowContext(context.Background(),
		`SELECT a.state, a.mcp_client, a.heard_from, a.utm_source
		   FROM user_acquisition a JOIN users u ON u.id=a.user_id WHERE u.telegram_login_id=$1`, danaTelegramID).
		Scan(&state, &client, &heardFrom, &utm)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestSignUp_OldCookieIsNeitherReadNorSet(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type": {"code"}, "client_id": {"claude.ai"}, "redirect_uri": {"https://claude.ai/cb"},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	rec := getWithCookie(t, mux, "/oauth/authorize?"+q.Encode(), &http.Cookie{Name: "mctl_acq", Value: "anything"})
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d", rec.Code)
	}
	if got := rec.Header().Get("Set-Cookie"); strings.Contains(got, "mctl_acq") {
		t.Fatalf("authorize set the removed cookie: %s", got)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if cb := callbackViaChi(t, mux, loc.Query().Get("state")); cb.Code != http.StatusOK {
		t.Fatalf("callback = %d", cb.Code)
	}
	state, client, _, utm := readSignUpRecord(t, srv)
	if state != "unknown" || client != "claude" || utm != "" {
		t.Fatalf("record = %q %q %q", state, client, utm)
	}
}

func TestHeardFrom_NewAccountIsAskedAndTheAnswerIsStored(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	_, challenge := pkceVerifierAndChallenge()
	rec := callbackViaChi(t, mux, authorizeViaChi(t, mux, challenge))
	body := rec.Body.String()
	for _, want := range []string{"How did you hear about us? (optional)", `name="heard_from"`, `value="search"`, `value="" selected`} {
		if !strings.Contains(body, want) {
			t.Fatalf("phone step missing %q", want)
		}
	}
	es := extractInputValue(t, body, "es")
	rec = postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}, "heard_from": {"search"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start = %d", rec.Code)
	}
	state, client, heard, utm := readSignUpRecord(t, srv)
	if state != "unknown" || client == "" || heard != "search" || utm != "" {
		t.Fatalf("record = %q %q %q %q", state, client, heard, utm)
	}
}

func TestHeardFrom_SkippedOrUnlistedStoresNothing(t *testing.T) {
	for _, answer := range []string{"", "my friend Dana", "SEARCH"} {
		t.Run(answer, func(t *testing.T) {
			srv, mux := newEnableTestServer(t, stubLogin(false, nil))
			es := driveToPhone(t, mux)
			rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
				url.Values{"es": {es}, "phone": {"+14155551234"}, "heard_from": {answer}})
			if rec.Code != http.StatusOK {
				t.Fatalf("start = %d", rec.Code)
			}
			if _, _, heard, _ := readSignUpRecord(t, srv); heard != "" {
				t.Fatalf("heard_from = %q, want empty", heard)
			}
		})
	}
}

func TestHeardFrom_QRSubmitStoresTheAnswer(t *testing.T) {
	q := newQRStub(danaTelegramID)
	srv, mux := newQRTestServer(t, q, true)
	es, page := driveToPhoneAs(t, mux, desktopUA)
	if !strings.Contains(page, `name="heard_from"`) {
		t.Fatal("the QR variant of the phone step must carry the question")
	}
	rec := postForm(t, mux, "/oauth/telegram/enable_access/qr", url.Values{"es": {es}, "heard_from": {"telegram"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /qr = %d", rec.Code)
	}
	if _, _, heard, _ := readSignUpRecord(t, srv); heard != "telegram" {
		t.Fatalf("heard_from = %q", heard)
	}
}

func TestHeardFrom_ExistingAccountIsNotAsked(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	_, challenge := pkceVerifierAndChallenge()
	state := authorizeViaChi(t, mux, challenge)
	// Pre-create the record outside the window: this account is not new.
	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), danaTelegramID, "dana_tg", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.DB.Exec(
		`INSERT INTO user_acquisition(user_id, state, captured_at, recorded_at) VALUES($1,'unknown',$2,$2)`,
		uid, time.Now().UTC().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if body := callbackViaChi(t, mux, state).Body.String(); strings.Contains(body, "heard_from") {
		t.Fatal("an existing account must not be asked")
	}
}

func TestHeardFrom_LookupFailureHidesTheQuestionAndSignInContinues(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	if _, err := srv.store.DB.Exec(`ALTER TABLE user_acquisition RENAME TO user_acquisition_gone`); err != nil {
		t.Fatal(err)
	}
	_, challenge := pkceVerifierAndChallenge()
	rec := callbackViaChi(t, mux, authorizeViaChi(t, mux, challenge))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "heard_from") ||
		!strings.Contains(rec.Body.String(), "enable_access/start") {
		t.Fatalf("callback = %d", rec.Code)
	}
}

func getWithCookie(t *testing.T, mux http.Handler, target string, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}
