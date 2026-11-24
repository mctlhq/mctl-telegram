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
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PermissionView is one standing permission as a /permissions screen
// shows it (threat model T7: tool, device ids, value ceiling and expiry).
type PermissionView struct {
	// ID is the permission's id; "" on a grant screen, where the
	// permission does not exist yet.
	ID      string
	Tool    string
	Devices []string
	// Ceiling is the highest value covered; negative means the permission
	// has no value ceiling.
	Ceiling   int64
	ExpiresAt time.Time
}

// PermissionTemplates lists every server text PermissionScreen and
// PermissionList can place around the values, besides the head and foot
// the caller passes.
func PermissionTemplates() []Template {
	return []Template{TextPermissionTool, TextPermissionDevices, TextPermissionCeiling, TextPermissionNoCeiling,
		TextPermissionExpires, TextPermissionID}
}

var (
	permissionToolRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	permissionValueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// permissionShowable reports whether every value of it is in its plain
// alphabet, so that the screen shows it exactly.
func permissionShowable(it PermissionView) bool {
	if !permissionToolRE.MatchString(it.Tool) || len(it.Devices) == 0 || it.ExpiresAt.IsZero() ||
		(it.ID != "" && !permissionValueRE.MatchString(it.ID)) {
		return false
	}
	for _, d := range it.Devices {
		if !permissionValueRE.MatchString(d) {
			return false
		}
	}
	return true
}

// permissionBlock is one permission's lines in l.
func permissionBlock(l Lang, it PermissionView) string {
	var b strings.Builder
	b.WriteString(TextPermissionTool.In(l) + " " + it.Tool + "\n")
	b.WriteString(TextPermissionDevices.In(l) + " " + strings.Join(it.Devices, ", ") + "\n")
	if it.Ceiling < 0 {
		b.WriteString(TextPermissionNoCeiling.In(l) + "\n")
	} else {
		b.WriteString(TextPermissionCeiling.In(l) + " " + strconv.FormatInt(it.Ceiling, 10) + "\n")
	}
	b.WriteString(TextPermissionExpires.In(l) + " " + it.ExpiresAt.UTC().Format("2006-01-02 15:04"))
	if it.ID != "" {
		b.WriteString("\n" + TextPermissionID.In(l) + " " + it.ID)
	}
	return b.String()
}

// permissionPart checks one finished message: nothing in it would be
// defanged, and it fits.
func permissionPart(s string) error {
	if neutralise(s, UserText{}) != s {
		return ErrCardUnshowable
	}
	if UTF16Len(s) > MaxPartUTF16 {
		return ErrTooLong
	}
	return nil
}

// PermissionScreen builds a /permissions screen that carries a button:
// head, then the permission's tool, device ids, value ceiling and expiry
// (and its id, when it has one), then foot. head and foot are registry
// templates; the values are shown exactly as given or not at all
// (ErrCardUnshowable): a tool name, device id or permission id outside its
// plain alphabet has no screen, and so does a screen any part of which
// would be defanged. What the principal confirms is therefore what is
// stored.
//
// The screen is one message. One that does not fit is refused with
// ErrTooLong, never cut: its button belongs to all of it.
func PermissionScreen(head Template, it PermissionView, foot Template) (Text, error) {
	if head.s == "" || foot.s == "" || !permissionShowable(it) {
		return Text{}, ErrCardUnshowable
	}
	var out [2]string
	for i, l := range []Lang{LangEN, LangRU} {
		out[i] = head.In(l) + "\n\n" + permissionBlock(l, it) + "\n\n" + foot.In(l)
		if err := permissionPart(out[i]); err != nil {
			return Text{}, err
		}
	}
	return Text{parts: []string{out[0]}, ru: []string{out[1]}}, nil
}

// PermissionList builds the listing of /permissions: head, every
// permission as PermissionScreen shows one, foot. It has no button, so it
// may take several messages; a permission is never cut across two, and
// both languages break at the same permissions (Text.In needs the same
// number of parts). Any value that cannot be shown exactly refuses the
// whole listing: a listing that left a permission out would be read as
// "that is all of them".
func PermissionList(head Template, items []PermissionView, foot Template) (Text, error) {
	if len(items) == 0 || head.s == "" || foot.s == "" {
		return Text{}, ErrCardUnshowable
	}
	for _, it := range items {
		if !permissionShowable(it) {
			return Text{}, ErrCardUnshowable
		}
	}
	langs := []Lang{LangEN, LangRU}
	cur := [2]string{head.In(LangEN), head.In(LangRU)}
	var parts [2][]string
	flush := func() error {
		for i := range langs {
			if err := permissionPart(cur[i]); err != nil {
				return err
			}
			parts[i] = append(parts[i], cur[i])
		}
		return nil
	}
	for _, it := range items {
		var next [2]string
		fits := true
		for i, l := range langs {
			next[i] = cur[i] + "\n\n" + permissionBlock(l, it)
			fits = fits && UTF16Len(next[i]) <= MaxPartUTF16
		}
		if !fits {
			if err := flush(); err != nil {
				return Text{}, err
			}
			for i, l := range langs {
				next[i] = permissionBlock(l, it)
			}
		}
		cur = next
	}
	var last [2]string
	fits := true
	for i, l := range langs {
		last[i] = cur[i] + "\n\n" + foot.In(l)
		fits = fits && UTF16Len(last[i]) <= MaxPartUTF16
	}
	if !fits {
		if err := flush(); err != nil {
			return Text{}, err
		}
		last = [2]string{foot.In(LangEN), foot.In(LangRU)}
	}
	cur = last
	if err := flush(); err != nil {
		return Text{}, err
	}
	if len(parts[0]) > MaxParts {
		return Text{}, ErrTooLong
	}
	return Text{parts: parts[0], ru: parts[1]}, nil
}
