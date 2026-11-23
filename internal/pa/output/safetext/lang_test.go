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

package safetext

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"
)

func TestLangOf(t *testing.T) {
	for code, want := range map[string]Lang{
		"ru": LangRU, "RU": LangRU, "ru-RU": LangRU, " ru ": LangRU,
		"": LangEN, "en": LangEN, "uk": LangEN, "rue": LangEN, "be": LangEN,
	} {
		if got := LangOf(code); got != want {
			t.Errorf("LangOf(%q) = %d, want %d", code, got, want)
		}
	}
}

// Every registry template has a Russian translation, except the consent
// prompt: its English text is what convo.ConsentText hashes, and a second
// consent text needs its own version and review. A translation must fit as
// many messages as the English (Text.In uses it only then), and one that
// equals the English is a forgotten translation.
func TestTemplatesAreTranslated(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), templatesFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The two consent prompts are one language each (TextConsentPromptRU).
	untranslated := map[string]bool{"TextConsentPrompt": true, "TextConsentPromptRU": true}
	seen := 0
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Values) != 1 {
			return true
		}
		call, ok := vs.Values[0].(*ast.CallExpr)
		if id, ok2 := call.Fun.(*ast.Ident); !ok || !ok2 || id.Name != "tpl" {
			return true
		}
		seen++
		name := vs.Names[0].Name
		if untranslated[name] {
			if len(call.Args) != 1 {
				t.Errorf("%s is translated: a consent prompt must show exactly the text its button binds", name)
			}
			return true
		}
		if len(call.Args) != 2 {
			t.Errorf("%s has no Russian translation", name)
			return true
		}
		en, _ := strconv.Unquote(call.Args[0].(*ast.BasicLit).Value)
		ru, _ := strconv.Unquote(call.Args[1].(*ast.BasicLit).Value)
		if ru == "" || ru == en {
			t.Errorf("%s: Russian text is empty or English", name)
		}
		if len(split(ru, MaxPartUTF16)) != len(split(en, MaxPartUTF16)) {
			t.Errorf("%s: Russian text needs a different number of messages", name)
		}
		return true
	})
	if seen < 30 {
		t.Fatalf("only %d templates parsed: the check would pass vacuously", seen)
	}
}

func TestTextIn(t *testing.T) {
	en := ServerText(TextConnected)
	if got := en.In(LangRU).String(); got != TextConnected.ru {
		t.Fatalf("Russian text %q", got)
	}
	if got := en.In(LangEN).String(); got != TextConnected.s {
		t.Fatalf("English text %q", got)
	}
	if got := ServerText(TextConsentPrompt).In(LangRU).String(); got != TextConsentPrompt.s {
		t.Fatal("an untranslated template is not sent in English")
	}
	model, err := Render("hello", UserText{})
	if err != nil {
		t.Fatal(err)
	}
	if model.In(LangRU).String() != "hello" {
		t.Fatal("model text changed by language")
	}
	ru, _ := Render("привет", UserText{})
	if got := WithRussian(model, ru).In(LangRU).String(); got != "привет" {
		t.Fatalf("WithRussian ru = %q", got)
	}
	// A translation cut into a different number of parts is not used.
	long, _ := Render(repeat("a ", MaxPartUTF16), UserText{})
	if got := WithRussian(model, long).In(LangRU).String(); got != "hello" {
		t.Fatal("a translation with a different part count was used")
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for range n {
		out = append(out, s...)
	}
	return string(out)
}
