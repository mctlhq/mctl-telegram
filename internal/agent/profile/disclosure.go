package profile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DisclosureLevel says to whom one owner-profile field may be shown (#953).
type DisclosureLevel string

const (
	// DisclosurePublic fields go to every sender, including a cold one.
	DisclosurePublic DisclosureLevel = "public"
	// DisclosureAfterOwnerEngaged fields go to the agent only once the owner
	// has engaged with the peer (db.Conversation.OwnerEngaged). Before that
	// they are hidden from its context, and a draft that still echoes one
	// needs the owner's approval.
	DisclosureAfterOwnerEngaged DisclosureLevel = "after_owner_engaged"
	// DisclosureNever fields never reach the agent, and a draft echoing one
	// is denied even when the owner approves it. Set only by the owner.
	DisclosureNever DisclosureLevel = "never"
)

// skillsPath is the single disclosure path for the skills list, which is an
// array rather than a keyed section.
const skillsPath = "skills"

// minProtectedNeedleRunes is the shortest value fragment MatchProtected
// looks for. Shorter fragments ("UK", "Go") match too much ordinary text to
// be useful, so such values are protected by the context filter alone.
const minProtectedNeedleRunes = 4

// defaultPublicPaths are the fields a profile without an explicit disclosure
// entry shows to a cold sender: enough to answer "who is this and what do
// they do", nothing about where they work, live or want to go next.
var defaultPublicPaths = map[string]bool{
	"identity.name": true,
	"identity.role": true,
	skillsPath:      true,
}

func validLevel(l DisclosureLevel) bool {
	switch l {
	case DisclosurePublic, DisclosureAfterOwnerEngaged, DisclosureNever:
		return true
	}
	return false
}

// defaultLevel is the level of a field the owner did not mark.
func defaultLevel(path string) DisclosureLevel {
	if defaultPublicPaths[path] {
		return DisclosurePublic
	}
	return DisclosureAfterOwnerEngaged
}

// DefaultLevel is the level a field at path has when the profile does not
// mark it.
func DefaultLevel(path string) DisclosureLevel { return defaultLevel(path) }

// level is the effective level of path in data.
func (d Data) level(path string) DisclosureLevel {
	if l, ok := d.Disclosure[path]; ok {
		return l
	}
	return defaultLevel(path)
}

// validateDisclosure rejects an unknown level or a path that names no field
// in the profile. A typo such as identity.compnay would otherwise leave the
// real field at its default level without any error; failing the write is
// the only way the owner learns the marker did nothing.
func validateDisclosure(d Data) error {
	for path, l := range d.Disclosure {
		if !validLevel(l) {
			return fmt.Errorf("disclosure %q: unknown level %q (want public, after_owner_engaged or never)", path, l)
		}
		if path == skillsPath {
			continue
		}
		section, key, ok := strings.Cut(path, ".")
		if !ok || key == "" {
			return fmt.Errorf("disclosure %q: path must be skills or <section>.<field>", path)
		}
		var fields map[string]any
		switch section {
		case "identity":
			fields = d.Identity
		case "public_profile":
			fields = d.PublicProfile
		case "preferences":
			fields = d.Preferences
		default:
			return fmt.Errorf("disclosure %q: unknown section %q (want identity, public_profile or preferences)", path, section)
		}
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("disclosure %q: no such field in the profile", path)
		}
	}
	return nil
}

// visible reports whether a field at level may be shown to the agent.
func visible(l DisclosureLevel, engaged bool) bool {
	return l == DisclosurePublic || (l == DisclosureAfterOwnerEngaged && engaged)
}

// agentProfile is the view of data the agent may see for one conversation:
// the context filter, which is the primary disclosure boundary. never fields
// are always left out, after_owner_engaged fields unless engaged, and the
// restricted section always.
func agentProfile(data Data, engaged bool) map[string]any {
	out := make(map[string]any, 4)
	for _, sec := range []struct {
		name   string
		fields map[string]any
	}{
		{"identity", data.Identity},
		{"public_profile", data.PublicProfile},
		{"preferences", data.Preferences},
	} {
		kept := make(map[string]any, len(sec.fields))
		for k, v := range sec.fields {
			if visible(data.level(sec.name+"."+k), engaged) {
				kept[k] = v
			}
		}
		if len(kept) > 0 {
			out[sec.name] = kept
		}
	}
	if len(data.Skills) > 0 && visible(data.level(skillsPath), engaged) {
		out["skills"] = data.Skills
	}
	// data.Restricted and data.Disclosure are deliberately never added.
	return out
}

// matchProtected reports the strongest profile field the agent may not
// disclose right now whose value appears in text: a never field (rank 2)
// outranks an after_owner_engaged field while not engaged (rank 1).
//
// This is defense in depth behind agentProfile, not a DLP system. It finds a
// value, or one comma/semicolon-separated part of it, of at least
// minProtectedNeedleRunes runes, case-insensitively and only on word
// boundaries. A paraphrase ("a fintech in Berlin" for "Nordbank GmbH,
// Berlin" still matches Berlin, but "a German bank" does not), a translation
// or a summary of long free text is not caught. Keys are returned, never
// values, so callers can log and audit the result.
//
// inbound is what the peer wrote in the turn being answered. A fragment of
// an after_owner_engaged field that the peer used first is not counted:
// repeating a recruiter's own "remote" or "Kubernetes" back discloses
// nothing, and counting it held almost every first reply about a vacancy
// (#992). The agent does not see such fields before the owner engages, so
// it cannot confirm them from the profile either. never fields get no such
// exemption.
func matchProtected(data Data, text, inbound string, engaged bool) (key string, level DisclosureLevel, matched bool) {
	lowered := strings.ToLower(text)
	loweredInbound := strings.ToLower(inbound)
	bestRank := 0
	consider := func(path string, value any) {
		l := data.level(path)
		rank := 0
		switch {
		case l == DisclosureNever:
			rank = 2
		case l == DisclosureAfterOwnerEngaged && !engaged:
			rank = 1
		}
		if rank <= bestRank {
			return
		}
		for _, n := range needles(value) {
			if rank == 1 && containsWord(loweredInbound, n) {
				continue
			}
			if containsWord(lowered, n) {
				key, level, matched, bestRank = path, l, true, rank
				return
			}
		}
	}
	for _, sec := range []struct {
		name   string
		fields map[string]any
	}{
		{"identity", data.Identity},
		{"public_profile", data.PublicProfile},
		{"preferences", data.Preferences},
	} {
		for _, k := range sortedKeys(sec.fields) {
			consider(sec.name+"."+k, sec.fields[k])
		}
	}
	if len(data.Skills) > 0 {
		skills := make([]any, len(data.Skills))
		for i, s := range data.Skills {
			skills[i] = s
		}
		consider(skillsPath, skills)
	}
	return key, level, matched
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// needles flattens a profile value into the lower-cased fragments
// matchProtected looks for: each scalar leaf whole, plus each of its
// comma/semicolon-separated parts. Fragments shorter than
// minProtectedNeedleRunes are dropped.
func needles(value any) []string {
	var out []string
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if utf8.RuneCountInString(s) >= minProtectedNeedleRunes {
			out = append(out, s)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		switch vv := v.(type) {
		case nil:
		case string:
			add(vv)
			parts := strings.FieldsFunc(vv, func(r rune) bool { return r == ',' || r == ';' })
			if len(parts) > 1 {
				for _, p := range parts {
					add(p)
				}
			}
		case json.Number:
			add(vv.String())
		case map[string]any:
			for _, k := range sortedKeys(vv) {
				walk(vv[k])
			}
		case []any:
			for _, e := range vv {
				walk(e)
			}
		case []string:
			for _, e := range vv {
				walk(e)
			}
		case bool:
			// true/false say nothing on their own.
		default:
			add(fmt.Sprint(vv))
		}
	}
	walk(value)
	return out
}

// containsWord reports whether needle occurs in haystack with no letter or
// digit directly before or after it, so "Berlin" matches "in Berlin." but
// "Rome" does not match "Romeo".
func containsWord(haystack, needle string) bool {
	for from := 0; ; {
		i := strings.Index(haystack[from:], needle)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(needle)
		before, _ := utf8.DecodeLastRuneInString(haystack[:start])
		after, _ := utf8.DecodeRuneInString(haystack[end:])
		if !isWordRune(before) && !isWordRune(after) {
			return true
		}
		_, size := utf8.DecodeRuneInString(haystack[start:])
		from = start + size
	}
}

func isWordRune(r rune) bool {
	return r != utf8.RuneError && (unicode.IsLetter(r) || unicode.IsDigit(r))
}
