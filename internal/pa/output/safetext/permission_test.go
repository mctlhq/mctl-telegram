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
	"errors"
	"strings"
	"testing"
	"time"
)

func permView() PermissionView {
	return PermissionView{ID: "prm_1", Tool: "alice_set_volume", Devices: []string{"dev_1", "Dev-2"}, Ceiling: 5,
		ExpiresAt: time.Date(2026, 12, 18, 12, 0, 0, 0, time.FixedZone("x", 3600))}
}

// TestPermissionScreen_ShowsTheValuesExactly: the tool, device ids,
// ceiling and expiry are on the screen as they are stored, in both
// languages, in one message.
func TestPermissionScreen_ShowsTheValuesExactly(t *testing.T) {
	text, err := PermissionScreen(TextPermissionGrantHead, permView(), TextPermissionGrantFoot)
	if err != nil {
		t.Fatal(err)
	}
	if text.Parts() != 1 {
		t.Fatalf("%d parts", text.Parts())
	}
	for _, l := range []Lang{LangEN, LangRU} {
		s := text.In(l).String()
		for _, want := range []string{
			TextPermissionGrantHead.In(l), TextPermissionGrantFoot.In(l),
			TextPermissionTool.In(l) + " alice_set_volume\n",
			TextPermissionDevices.In(l) + " dev_1, Dev-2\n",
			TextPermissionCeiling.In(l) + " 5\n",
			TextPermissionExpires.In(l) + " 2026-12-18 11:00\n",
			TextPermissionID.In(l) + " prm_1",
		} {
			if !strings.Contains(s, want) {
				t.Errorf("screen in language %d lacks %q:\n%s", l, want, s)
			}
		}
	}
	v := permView()
	v.ID, v.Ceiling = "", -1
	text, err = PermissionScreen(TextPermissionGrantHead, v, TextPermissionGrantFoot)
	if err != nil {
		t.Fatal(err)
	}
	if s := text.String(); !strings.Contains(s, TextPermissionNoCeiling.String()) || strings.Contains(s, TextPermissionID.String()) {
		t.Errorf("a grant screen without a ceiling:\n%s", s)
	}
}

// TestPermissionScreen_RefusesWhatItCannotShow: a value outside its plain
// alphabet has no screen, rather than a screen that shows something else
// than what would be stored.
func TestPermissionScreen_RefusesWhatItCannotShow(t *testing.T) {
	for name, mutate := range map[string]func(*PermissionView){
		"a tool with markup":  func(v *PermissionView) { v.Tool = "alice_*set*" },
		"a tool with a link":  func(v *PermissionView) { v.Tool = "example.com/x" },
		"an empty tool":       func(v *PermissionView) { v.Tool = "" },
		"no devices":          func(v *PermissionView) { v.Devices = nil },
		"a device with a dot": func(v *PermissionView) { v.Devices = []string{"a.b"} },
		"a device with space": func(v *PermissionView) { v.Devices = []string{"a b"} },
		"a device with a tag": func(v *PermissionView) { v.Devices = []string{"@carol"} },
		"an empty device":     func(v *PermissionView) { v.Devices = []string{""} },
		"an id with a slash":  func(v *PermissionView) { v.ID = "a/b" },
		"no expiry":           func(v *PermissionView) { v.ExpiresAt = time.Time{} },
	} {
		v := permView()
		mutate(&v)
		if text, err := PermissionScreen(TextPermissionGrantHead, v, TextPermissionGrantFoot); !errors.Is(err, ErrCardUnshowable) || text.Parts() != 0 {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := PermissionScreen(Template{}, permView(), TextPermissionGrantFoot); !errors.Is(err, ErrCardUnshowable) {
		t.Errorf("no head: %v", err)
	}
	if _, err := PermissionScreen(TextPermissionGrantHead, permView(), Template{}); !errors.Is(err, ErrCardUnshowable) {
		t.Errorf("no foot: %v", err)
	}
}

// TestPermissionList: every permission is listed whole, in as many
// messages as it takes and the same number in both languages; one that
// cannot be shown refuses the listing rather than being left out.
func TestPermissionList(t *testing.T) {
	if _, err := PermissionList(TextPermissionsList, nil, TextPermissionsUsage); !errors.Is(err, ErrCardUnshowable) {
		t.Errorf("no items: %v", err)
	}
	text, err := PermissionList(TextPermissionsList, []PermissionView{permView(), permView()}, TextPermissionsUsage)
	if err != nil || text.Parts() != 1 || strings.Count(text.String(), "prm_1") != 2 ||
		!strings.HasPrefix(text.String(), TextPermissionsList.String()) || !strings.HasSuffix(text.String(), TextPermissionsUsage.String()) {
		t.Fatalf("two permissions: %v\n%s", err, text.String())
	}
	// The widest listing the store allows: ten permissions of ten 64-byte
	// device ids.
	var many []PermissionView
	for i := range 10 {
		v := permView()
		v.ID = "prm_wide_" + string(rune('a'+i))
		v.Devices = nil
		for j := range 10 {
			v.Devices = append(v.Devices, strings.Repeat("d", 63)+string(rune('a'+j)))
		}
		many = append(many, v)
	}
	text, err = PermissionList(TextPermissionsList, many, TextPermissionsUsage)
	if err != nil {
		t.Fatal(err)
	}
	ru := text.In(LangRU)
	if text.Parts() < 2 || ru.Parts() != text.Parts() || ru.Part(0) == text.Part(0) {
		t.Fatalf("%d parts, %d in Russian", text.Parts(), ru.Parts())
	}
	for _, tx := range []Text{text, ru} {
		var all strings.Builder
		for i := range tx.Parts() {
			if UTF16Len(tx.Part(i)) > MaxPartUTF16 {
				t.Errorf("part %d is too long", i)
			}
			all.WriteString(tx.Part(i) + "\n")
		}
		for _, v := range many {
			// Whole: the id line closes the block its tool line opened.
			if strings.Count(all.String(), " "+v.ID) != 1 {
				t.Errorf("permission %s is not listed once", v.ID)
			}
		}
		for i := range tx.Parts() {
			if strings.Count(tx.Part(i), "alice_set_volume") != strings.Count(tx.Part(i), "prm_wide_") {
				t.Errorf("part %d cuts a permission in two", i)
			}
		}
	}
	bad := permView()
	bad.Devices = []string{"a.b"}
	if _, err := PermissionList(TextPermissionsList, append(many[:2:2], bad), TextPermissionsUsage); !errors.Is(err, ErrCardUnshowable) {
		t.Errorf("an unshowable permission: %v", err)
	}
}
