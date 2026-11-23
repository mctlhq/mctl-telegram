package linking

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Paths of the linking routes.
const (
	AppPath      = "/pa/link/app"
	BeginPath    = "/pa/link/begin"
	CompletePath = "/pa/link/complete"
	CallbackPath = "/pa/oauth/callback/{server}"
	HandoffPath  = "/pa/oauth/handoff"
)

// maxBody bounds every request body the routes read.
const maxBody = 8 << 10

// Mount registers the linking routes on r. The caller mounts them only when
// PA_ENABLED is on; each server's own flag is checked again on every step.
func (s *Service) Mount(r chi.Router) {
	r.Get(AppPath, s.serveApp)
	r.Post(BeginPath, s.serveBegin)
	r.Post(CompletePath, s.serveComplete)
	r.Get(CallbackPath, s.serveCallback)
	r.Post(HandoffPath, s.serveHandoff)
}

// pageHeaders sets the headers every linking response carries: no caching,
// no referrer (the callback URL holds the code and state), no sniffing, and
// a CSP that allows only this origin and the page's own nonce-tagged inline
// script and style. No third-party resource can load. frameAncestors is
// "'none'" for the browser pages; the Mini App page allows Telegram Web to
// frame it.
func pageHeaders(w http.ResponseWriter, nonce, frameAncestors string) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	csp := "default-src 'none'; base-uri 'none'; form-action 'self'; connect-src 'self'; frame-ancestors " + frameAncestors
	if nonce != "" {
		csp += "; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'"
	}
	h.Set("Content-Security-Policy", csp)
	if frameAncestors == "'none'" {
		h.Set("X-Frame-Options", "DENY")
	}
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// status maps a flow error to an HTTP status. The body never says more than
// the status: a refusal does not tell a prober which check failed.
func status(err error) int {
	switch {
	case errors.Is(err, ErrServerDisabled):
		return http.StatusNotFound
	case errors.Is(err, ErrInitDataMissing), errors.Is(err, ErrInitDataMalformed):
		return http.StatusBadRequest
	case errors.Is(err, ErrInitDataSignature), errors.Is(err, ErrInitDataExpired),
		errors.Is(err, ErrWrongUser), errors.Is(err, ErrRefused), errors.Is(err, ErrNotOwner),
		errors.Is(err, connection.ErrConflict), errors.Is(err, ErrPrincipalRefused):
		return http.StatusForbidden
	}
	return http.StatusInternalServerError
}

func logRefusal(ctx context.Context, step string, err error) {
	// The error text is built from sentinels and wrapped store errors; no
	// value from the request is ever part of it.
	slog.WarnContext(ctx, "pa linking refused", "step", step, "error", err)
}

type beginRequest struct {
	InitData string `json:"init_data"`
	Link     string `json:"link"`
}

func (s *Service) serveBegin(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w, "", "'none'")
	var req beginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	authURL, err := s.BeginOAuth(r.Context(), req.InitData, req.Link)
	if err != nil {
		logRefusal(r.Context(), "begin", err)
		code := status(err)
		http.Error(w, http.StatusText(code), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"url": authURL})
}

// completeRequest is the whole completion request. The completion code is
// not in it: Complete reads it from the signed start_param only, so a
// "code" or "startapp" field, here or in the URL, is never looked at
// (S1-L12).
type completeRequest struct {
	InitData string `json:"init_data"`
}

func (s *Service) serveComplete(w http.ResponseWriter, r *http.Request) {
	pageHeaders(w, "", "'none'")
	var req completeRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.Complete(r.Context(), req.InitData); err != nil {
		logRefusal(r.Context(), "complete", err)
		code := status(err)
		http.Error(w, http.StatusText(code), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
}

func (s *Service) serveCallback(w http.ResponseWriter, r *http.Request) {
	nonce := newNonce()
	pageHeaders(w, nonce, "'none'")
	if nonce == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	res, err := s.Callback(r.Context(), connection.Server(chi.URLParam(r, "server")), r.URL.Query())
	if err != nil {
		logRefusal(r.Context(), "callback", err)
		code := status(err)
		renderPage(w, code, nonce, pageData{Title: "Link not completed",
			Body: "This link is not valid any more. Start again with /connect in the assistant chat."})
		return
	}
	renderPage(w, http.StatusOK, nonce, pageData{
		Title:   "Confirm your Telegram account",
		Body:    "The " + string(res.Server) + " account you just signed in to will be linked to this Telegram account:",
		Account: res.AccountHint,
		Warning: "If this is not your Telegram account, close this page. Nothing has been linked.",
		Handoff: res.Handoff,
		Action:  HandoffPath,
	})
}

func (s *Service) serveHandoff(w http.ResponseWriter, r *http.Request) {
	nonce := newNonce()
	pageHeaders(w, nonce, "'none'")
	if nonce == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// PostForm, not Form: a handoff value in the URL is not looked at.
	link, server, err := s.Handoff(r.Context(), r.PostForm.Get("handoff"))
	if err != nil {
		logRefusal(r.Context(), "handoff", err)
		renderPage(w, status(err), nonce, pageData{Title: "Link not completed",
			Body: "This link is not valid any more. Start again with /connect in the assistant chat."})
		return
	}
	renderPage(w, http.StatusOK, nonce, pageData{
		Title:   "Finish in Telegram",
		Body:    "Open the assistant to finish linking " + string(server) + ". The link works once, for five minutes, and only for your Telegram account.",
		Warning: "Do not share this link or open it for anyone else.",
		Link:    link,
	})
}

func (s *Service) serveApp(w http.ResponseWriter, r *http.Request) {
	nonce := newNonce()
	// Telegram Web shows Mini Apps in an iframe of web.telegram.org.
	pageHeaders(w, nonce, "https://web.telegram.org")
	if nonce == "" {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = appPage.Execute(w, struct{ Nonce, Begin, Complete string }{nonce, BeginPath, CompletePath})
}

type pageData struct {
	Nonce, Title, Body, Account, Warning, Handoff, Action, Link string
}

func renderPage(w http.ResponseWriter, code int, nonce string, d pageData) {
	d.Nonce = nonce
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = page.Execute(w, d)
}

// style sets its own colours: Telegram paints its webview in the chat
// theme, and default black text on a dark theme is unreadable (#1318).
const style = `:root{color-scheme:light dark}body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#fff;color:#111}
@media (prefers-color-scheme:dark){body{background:#17212b;color:#f5f5f5}.warn{color:#fdba74}}
.acct{font-size:1.25rem;font-weight:600}.warn{color:#9a3412}button,a.btn{display:inline-block;padding:.6rem 1rem;font-size:1rem}`

var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>{{.Title}}</title>
<style nonce="{{.Nonce}}">` + style + `</style></head><body>
<h1>{{.Title}}</h1><p>{{.Body}}</p>
{{if .Account}}<p class="acct">{{.Account}}</p>{{end}}
{{if .Warning}}<p class="warn">{{.Warning}}</p>{{end}}
{{if .Handoff}}<form method="post" action="{{.Action}}"><input type="hidden" name="handoff" value="{{.Handoff}}"><button type="submit">This is my Telegram account</button></form>{{end}}
{{if .Link}}<p><a class="btn" href="{{.Link}}" rel="noreferrer">Open the assistant</a></p>{{end}}
</body></html>`))

// appPage is the Mini App. It reads the raw initData Telegram puts in the
// URL fragment (tgWebAppData), so it needs no Telegram script, and posts it
// as it is: the server verifies it. With a link token in the query it
// starts OAuth; without one it completes, and the server reads the
// completion code from the signed start_param.
var appPage = template.Must(template.New("app").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Connect an account</title>
<style nonce="{{.Nonce}}">` + style + `</style></head><body>
<h1>Connect an account</h1><p id="msg">Working…</p>
<p><button type="button" id="go" hidden>Continue in the browser</button></p>
<script nonce="{{.Nonce}}">
(function(){
  var msg=document.getElementById("msg");
  var frag=new URLSearchParams(location.hash.slice(1));
  var initData=frag.get("tgWebAppData")||"";
  var link=new URLSearchParams(location.search).get("link");
  function post(path,body){return fetch(path,{method:"POST",credentials:"omit",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});}
  function openLink(u){
    var data=JSON.stringify({url:u});
    if(window.TelegramWebviewProxy){window.TelegramWebviewProxy.postEvent("web_app_open_link",data);return;}
    if(window.external&&window.external.notify){window.external.notify(JSON.stringify({eventType:"web_app_open_link",eventData:{url:u}}));return;}
    if(window.parent!==window){window.parent.postMessage(JSON.stringify({eventType:"web_app_open_link",eventData:{url:u}}),"https://web.telegram.org");return;}
    location.href=u;
  }
  if(!initData){msg.textContent="Open this page from the assistant chat in Telegram.";return;}
  if(link){
    post({{.Begin}},{init_data:initData,link:link}).then(function(r){
      if(!r.ok){throw new Error();}return r.json();
    }).then(function(j){
      // Telegram clients ignore web_app_open_link without a user gesture,
      // so the automatic attempt can do nothing: the button opens it from
      // a tap, as often as needed, without spending another link.
      msg.textContent="Tap the button to sign in in your browser.";
      var go=document.getElementById("go");
      go.hidden=false;
      go.addEventListener("click",function(){openLink(j.url);});
      openLink(j.url);
    })
    .catch(function(){msg.textContent="This link is not valid any more. Send /connect again.";});
  }else{
    post({{.Complete}},{init_data:initData}).then(function(r){
      msg.textContent=r.ok?"Almost done: confirm the card in the assistant chat.":"This link is not valid any more. Send /connect again.";
    }).catch(function(){msg.textContent="Something went wrong. Send /connect again.";});
  }
})();
</script></body></html>`))
