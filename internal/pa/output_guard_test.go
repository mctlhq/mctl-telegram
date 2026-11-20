// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pa

// Static guard for threat model T14 (S1-O1): output.Sender is the only code
// under internal/pa that talks to the Bot API to emit anything, so every
// bot message gets disabled previews, plain text and server-only keyboards.
// Production code anywhere under internal/pa must not:
//
//   - name a Bot API method that sends, edits, forwards or answers
//     (sendMessage, editMessageText, answerCallbackQuery, ...; method names
//     are case-insensitive in the Bot API, so the check is too), outside
//     output/sender.go. That also covers a webhook reply carrying
//     {"method": "sendMessage"};
//   - build a raw Bot API URL ("api.telegram.org", a literal ending in
//     "/bot", or "/bot<id>:" with an inline token), outside
//     output/sender.go and the read-only getWebhookInfo helper;
//   - import another Telegram client (internal/botapi, internal/bot,
//     internal/telegram, internal/notify, internal/broadcast, or a
//     third-party Bot API library);
//
// safetext.Text and safetext.Template have unexported fields, so no code
// outside package safetext can make one; inside it,
// TestTemplatesAreLiteralRegistry keeps every Template a string literal in
// templates.go.
//
// String literals joined with + are folded before the check. A method name
// assembled at run time (fmt.Sprintf, a byte slice) is not caught; review
// still has to reject that, as with the egress guard.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// botAPISendMethods are the Bot API methods that make the bot emit or
// change content a user sees, or answer a query with a URL.
var botAPISendMethods = []string{
	"sendMessage", "sendMessageDraft", "sendPhoto", "sendAudio", "sendDocument",
	"sendVideo", "sendAnimation", "sendVoice", "sendVideoNote", "sendPaidMedia",
	"sendMediaGroup", "sendLocation", "sendVenue", "sendContact", "sendPoll",
	"sendChecklist", "sendDice", "sendSticker", "sendInvoice", "sendGame",
	"sendGift", "sendChatAction",
	"forwardMessage", "forwardMessages", "copyMessage", "copyMessages",
	"editMessageText", "editMessageCaption", "editMessageMedia",
	"editMessageLiveLocation", "editMessageReplyMarkup", "editMessageChecklist",
	"answerCallbackQuery", "answerInlineQuery", "answerWebAppQuery",
	"savePreparedInlineMessage", "postStory", "editStory",
	"setChatMenuButton", "setMyCommands", "setMyName", "setMyDescription",
	"setMyShortDescription",
}

const senderFile = "output/sender.go"

// botAPIURLAllowed lists the files allowed to build a Bot API URL, with the
// reason.
var botAPIURLAllowed = map[string]string{
	senderFile:       "the Sender itself",
	"webhookinfo.go": "read-only getWebhookInfo health check (#1313 slice a); sends nothing",
	"setwebhook.go":  "operator-only setWebhook helper (#1313 slice d2, #1318); sends no message, and TestSetWebhookNotCalledByServer keeps it out of the server",
}

var forbiddenBotImports = []string{
	modulePath + "/internal/botapi",
	modulePath + "/internal/bot",
	modulePath + "/internal/telegram",
	modulePath + "/internal/notify",
	modulePath + "/internal/broadcast",
	"github.com/go-telegram-bot-api",
	"github.com/go-telegram/bot",
	"github.com/mymmrac/telego",
	"gopkg.in/telebot",
	"gopkg.in/tucnak/telebot",
	"github.com/tucnak/telebot",
	"github.com/gotd/td/telegram",
}

// inlineTokenPath matches a Bot API path with the token inline,
// "/bot123456:ABC...".
var inlineTokenPath = regexp.MustCompile(`/bot\d+:`)

// foldString returns the value of a string literal or of string literals
// joined with +.
func foldString(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return foldString(x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok := foldString(x.X)
		if !ok {
			return "", false
		}
		r, ok := foldString(x.Y)
		return l + r, ok
	}
	return "", false
}

// scanBotAPIUse returns one finding per violation in f. rel is the file's
// path relative to internal/pa, with forward slashes.
func scanBotAPIUse(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	report := func(n ast.Node, what string) {
		out = append(out, fset.Position(n.Pos()).String()+": "+what)
	}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		for _, p := range forbiddenBotImports {
			if path == p || strings.HasPrefix(path, p+"/") {
				report(imp, "import "+strconv.Quote(path))
			}
		}
	}
	_, urlOK := botAPIURLAllowed[rel]
	checkString := func(n ast.Node, s string) {
		if rel == senderFile {
			return
		}
		low := strings.ToLower(s)
		for _, m := range botAPISendMethods {
			if strings.Contains(low, strings.ToLower(m)) {
				report(n, "Bot API method "+strconv.Quote(m)+" outside output.Sender")
				break
			}
		}
		if !urlOK && (strings.Contains(low, "api.telegram.org") || strings.HasSuffix(low, "/bot") || inlineTokenPath.MatchString(low)) {
			report(n, "raw Bot API URL "+strconv.Quote(s)+" outside output.Sender")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ImportSpec:
			return false // import paths were checked above
		case *ast.BinaryExpr:
			if s, ok := foldString(x); ok {
				// Check the folded whole once and skip the parts, so one
				// literal is not reported twice.
				checkString(x, s)
				return false
			}
		case *ast.BasicLit:
			if s, ok := foldString(x); ok {
				checkString(x, s)
			}
		}
		return true
	})
	return out
}

func TestS1O1_SenderIsTheOnlyBotAPICallSite(t *testing.T) {
	fset := token.NewFileSet()
	var findings []string
	sawSender := false
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(path)
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		if rel == senderFile {
			sawSender = true
		}
		findings = append(findings, scanBotAPIUse(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/pa: %v", err)
	}
	if !sawSender {
		t.Fatalf("%s not found: the allowlist points at nothing", senderFile)
	}
	for _, f := range findings {
		t.Errorf("Bot API use outside output.Sender (T14): %s", f)
	}
}

// The guard is only a guard if it fires: each forbidden form is detected,
// and ordinary code is not.
func TestS1O1_GuardDetects(t *testing.T) {
	bad := map[string]string{
		"sendMessage literal":      `package x; const m = "sendMessage"`,
		"lower case method":        `package x; var m = "sendmessage"`,
		"edit method":              `package x; var m = "editMessageText"`,
		"answer method":            `package x; var m = "answerCallbackQuery"`,
		"photo method":             `package x; var m = "sendPhoto"`,
		"folded method":            `package x; var m = "send" + "Message"`,
		"webhook reply":            `package x; var b = ` + "`" + `{"method":"sendMessage"}` + "`",
		"bot url":                  `package x; func f(t string) string { return "https://api.telegram.org/bot" + t }`,
		"bot path":                 `package x; func f(b, t string) string { return b + "/bot" + t }`,
		"botapi import":            `package x; import "github.com/mctlhq/mctl-telegram/internal/botapi"; var _ = botapi.X`,
		"bot import":               `package x; import "github.com/mctlhq/mctl-telegram/internal/bot"; var _ = bot.X`,
		"telegram import":          `package x; import "github.com/mctlhq/mctl-telegram/internal/telegram"; var _ = telegram.X`,
		"third-party bot lib":      `package x; import tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"; var _ = tgbotapi.X`,
		"method in struct tag-ish": `package x; var m = map[string]string{"method": "copyMessage"}`,
	}
	for name, src := range bad {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name+".go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := scanBotAPIUse(fset, f, "handler.go"); len(got) != 1 {
			t.Errorf("%s: want 1 finding, got %v", name, got)
		}
	}
	good := []struct{ rel, src string }{
		{"handler.go", `package x; var m = "message"; var c = "callback_query"; var p = "/pa/bot/webhook"`},
		{"webhookinfo.go", `package x; func f(b, t string) string { return b + "/bot" + t + "/getWebhookInfo" }`},
		{senderFile, `package x; const m = "sendMessage"; func f(t string) string { return "https://api.telegram.org/bot" + t + "/" + m }`},
	}
	for i, g := range good {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "good.go", g.src, 0)
		if err != nil {
			t.Fatalf("good %d: %v", i, err)
		}
		if got := scanBotAPIUse(fset, f, g.rel); len(got) != 0 {
			t.Errorf("good %d: unexpected findings %v", i, got)
		}
	}
}

func TestS1O1_AllowlistHasReasons(t *testing.T) {
	for file, reason := range botAPIURLAllowed {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("botAPIURLAllowed[%q] has no reason", file)
		}
	}
}
