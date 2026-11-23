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

package output

import (
	"context"
	"fmt"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const bobChat int64 = 100002

// A chat whose client is in Russian gets the Russian server text, button
// labels and web_app label; every other chat, and a Sender without
// Languages, gets English. Model text is sent as it is in both.
func TestSender_AnswersInTheChatsLanguage(t *testing.T) {
	f, s := webAppSender(t)
	s.langs = NewLanguages()
	s.langs.Set(aliceChat, "ru")
	s.langs.Set(bobChat, "en-GB")
	ctx := context.Background()
	kb := Keyboard{{{Label: safetext.LabelConfirm, Data: "pa:lc:x"}}}
	for _, chat := range []int64{aliceChat, bobChat} {
		if err := s.Send(ctx, chat, safetext.ServerText(safetext.TextConnected), kb); err != nil {
			t.Fatal(err)
		}
		if err := s.SendWebApp(ctx, chat, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, testAppURL+"?link="+testLinkToken); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Send(ctx, aliceChat, mustRender(t, "Bob wrote hello", safetext.UserText{}), nil); err != nil {
		t.Fatal(err)
	}
	want := []struct{ text, button string }{
		{safetext.TextConnected.In(safetext.LangRU), "Подтвердить"},
		{safetext.TextConnectOpen.In(safetext.LangRU), "Подключить"},
		{"Your account is connected.", "Confirm"},
		{safetext.TextConnectOpen.String(), "Connect"},
		{"Bob wrote hello", ""},
	}
	if len(f.calls) != len(want) {
		t.Fatalf("%d calls, want %d", len(f.calls), len(want))
	}
	for i, w := range want {
		body := f.calls[i].body
		if body["text"] != w.text {
			t.Errorf("call %d: text %q, want %q", i, body["text"], w.text)
		}
		got := ""
		if rm, ok := body["reply_markup"].(map[string]any); ok {
			got = fmt.Sprint(rm["inline_keyboard"].([]any)[0].([]any)[0].(map[string]any)["text"])
		}
		if got != w.button {
			t.Errorf("call %d: button %q, want %q", i, got, w.button)
		}
	}
	if safetext.TextConnected.In(safetext.LangRU) == safetext.TextConnected.String() {
		t.Fatal("TextConnected has no Russian translation: the test proves nothing")
	}
}

func TestLanguages(t *testing.T) {
	var none *Languages
	none.Set(aliceChat, "ru")
	if none.Of(aliceChat) != safetext.LangEN {
		t.Fatal("nil Languages is not English")
	}
	l := NewLanguages()
	l.Set(aliceChat, "ru")
	l.Set(aliceChat, "") // an update without language_code keeps it
	if l.Of(aliceChat) != safetext.LangRU || l.Of(bobChat) != safetext.LangEN {
		t.Fatal("recorded languages wrong")
	}
	l.Set(aliceChat, "de")
	if l.Of(aliceChat) != safetext.LangEN {
		t.Fatal("a later language does not replace the earlier one")
	}
	for i := int64(1); i <= maxLanguages+1; i++ {
		l.Set(1000000+i, "ru")
	}
	if n := len(l.m); n > maxLanguages {
		t.Fatalf("Languages holds %d entries, cap %d", n, maxLanguages)
	}
}

// The menu goes out twice: English for every client, Russian for clients
// in Russian. A bad command name is refused before anything is sent.
func TestSender_SetCommands(t *testing.T) {
	f, s := newFake(t)
	cmds := []Command{{Name: "new", Description: safetext.CmdNew}, {Name: "connect", Description: safetext.CmdConnect}}
	if err := s.SetCommands(context.Background(), cmds); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("%d calls, want 2", len(f.calls))
	}
	for i, w := range []struct{ lang, first string }{{"", "Start a new conversation"}, {"ru", "Начать новый разговор"}} {
		c := f.calls[i]
		if c.path != "/bot"+testToken+"/setMyCommands" {
			t.Fatalf("call %d path %q", i, c.path)
		}
		if lc, _ := c.body["language_code"].(string); lc != w.lang {
			t.Errorf("call %d: language_code %q, want %q", i, lc, w.lang)
		}
		got := c.body["commands"].([]any)
		if len(got) != 2 || got[0].(map[string]any)["command"] != "new" || got[0].(map[string]any)["description"] != w.first {
			t.Errorf("call %d: commands %v", i, got)
		}
	}
	for _, bad := range [][]Command{nil, {{Name: "/new", Description: safetext.CmdNew}}, {{Name: "new"}}} {
		if err := s.SetCommands(context.Background(), bad); err == nil {
			t.Errorf("SetCommands(%v) accepted", bad)
		}
	}
	if len(f.calls) != 2 {
		t.Fatal("a refused menu was sent")
	}
}
