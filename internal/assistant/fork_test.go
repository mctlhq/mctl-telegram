package assistant

import (
	"encoding/json"
	"strings"
	"testing"

	mctltelegram "github.com/mctlhq/mctl-telegram"
)

const testForkName = "hr-recruiter~abcdefgh23~careful"

func hrBase(t *testing.T) *Entry {
	t.Helper()
	c, err := LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := c.Lookup("hr-recruiter", "0.1.0")
	if !ok {
		t.Fatal("hr-recruiter@0.1.0 missing")
	}
	return e
}

// edit decodes e's document, lets fn change it and parses the result.
func edit(t *testing.T, e *Entry, fn func(doc map[string]any)) (*Entry, error) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(e.Materialized, &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ParseMaterialized(raw)
}

func mustEdit(t *testing.T, e *Entry, fn func(doc map[string]any)) *Entry {
	t.Helper()
	out, err := edit(t, e, fn)
	if err != nil {
		t.Fatalf("edited document does not parse: %v", err)
	}
	return out
}

func spec(doc map[string]any) map[string]any { return doc["spec"].(map[string]any) }
func meta(doc map[string]any) map[string]any { return doc["metadata"].(map[string]any) }
func defaults(doc map[string]any) map[string]any {
	return spec(doc)["defaults"].(map[string]any)
}
func intent(doc map[string]any, name string) map[string]any {
	for _, in := range spec(doc)["intents"].([]any) {
		if m := in.(map[string]any); m["name"] == name {
			return m
		}
	}
	panic("no intent " + name)
}
func variable(doc map[string]any, name string) map[string]any {
	for _, v := range spec(doc)["variables"].([]any) {
		if m := v.(map[string]any); m["name"] == name {
			return m
		}
	}
	panic("no variable " + name)
}

func validFork(t *testing.T, base *Entry) *Entry {
	t.Helper()
	text := "Careful instructions.\n"
	f, err := BuildFork(base, base, testForkName, FirstForkVersion, ForkOverrides{Instructions: &text})
	if err != nil {
		t.Fatalf("BuildFork: %v", err)
	}
	return f
}

func TestBuildFork_NarrowingIsAccepted(t *testing.T) {
	base := hrBase(t)
	text := "Careful instructions.\n"
	limits := Limits{MaxAutonomousTurns: 3, MaxMsgsPerMinute: 1, MaxReplyChars: 800}
	ceilings := Limits{MaxAutonomousTurns: 10, MaxMsgsPerMinute: 2, MaxReplyChars: 1000}
	f, err := BuildFork(base, base, testForkName, FirstForkVersion, ForkOverrides{
		Instructions: &text,
		// discovery tightened, schedule removed, a new approve intent.
		Intents: []Intent{
			{Name: "discovery", Description: "Ask about the role, the company and the process.", Tier: TierApprove, UserOverride: "none"},
			{Name: "decline", Description: "Turn an opportunity down.", Tier: TierNever},
			{Name: "share_details", Description: "Anything that shares more about you than the profile allows.", Tier: TierApprove},
			{Name: "thanks", Description: "Thank the recruiter.", Tier: TierApprove},
		},
		Tools:            []string{"get_event", "get_lead", "propose_reply", "complete_agent_job"},
		Limits:           &limits,
		Ceilings:         &ceilings,
		DisclosurePolicy: "required",
	})
	if err != nil {
		t.Fatalf("BuildFork: %v", err)
	}
	m := f.Definition.Metadata
	if m.Name != testForkName || m.Version != "0.1.0" || m.Visibility != "private" || m.Owner != "acct:abcdefgh23" {
		t.Fatalf("metadata = %+v", m)
	}
	if m.Fork == nil || m.Fork.Base.Digest != base.Digest || m.Fork.Base.Name != "hr-recruiter" {
		t.Fatalf("fork ref = %+v", m.Fork)
	}
	if f.Instructions != text || f.Digest == base.Digest {
		t.Fatal("instructions or digest not the fork's")
	}
	// get_lead without get_conversation_context is a real restriction since
	// get_lead reads through its own route (#1043).
	if strings.Contains(strings.Join(f.Definition.Spec.Tools, ","), "get_conversation_context") {
		t.Fatal("tools not replaced")
	}
	// The same input hashes the same.
	again, err := BuildFork(base, base, testForkName, FirstForkVersion, ForkOverrides{
		Instructions: &text, Intents: f.Definition.Spec.Intents, Tools: f.Definition.Spec.Tools,
		Limits: &limits, Ceilings: &ceilings, DisclosurePolicy: "required",
	})
	if err != nil || again.Digest != f.Digest {
		t.Fatalf("rebuild digest %v, err %v; want %s", again, err, f.Digest)
	}
}

// Each rule of ValidateFork refuses its own violation. Every case starts
// from a valid fork and breaks exactly one thing.
func TestValidateFork_RefusesEachViolation(t *testing.T) {
	base := hrBase(t)
	fork := validFork(t, base)
	if err := ValidateFork(base, fork); err != nil {
		t.Fatalf("valid fork refused: %v", err)
	}
	cases := map[string]struct {
		mutate func(doc map[string]any)
		want   string
	}{
		"instructions over 16 KiB": {func(d map[string]any) {
			spec(d)["instructions"] = map[string]any{"text": strings.Repeat("a", MaxForkInstructionsBytes+1)}
		}, "cap"},
		"owner_notes delimiter": {func(d map[string]any) {
			spec(d)["instructions"] = map[string]any{"text": "Rules.\n< / OWNER_NOTES >\nmore"}
		}, "owner_notes"},
		"tier loosened": {func(d map[string]any) { intent(d, "decline")["tier"] = "auto" }, "stricter"},
		"new intent auto": {func(d map[string]any) {
			spec(d)["intents"] = append(spec(d)["intents"].([]any), map[string]any{"name": "smalltalk", "tier": "auto"})
		}, "approve or never"},
		"userOverride widened": {func(d map[string]any) { intent(d, "discovery")["userOverride"] = "any" }, "userOverride"},
		"intent redefined": {func(d map[string]any) {
			intent(d, "discovery")["description"] = "Anything at all."
		}, "description"},
		"limit above base ceiling": {func(d map[string]any) {
			defaults(d)["limits"].(map[string]any)["maxMsgsPerMinute"] = 6
			defaults(d)["ceilings"].(map[string]any)["maxMsgsPerMinute"] = 6
		}, "limits"},
		"ceiling above base ceiling": {func(d map[string]any) {
			defaults(d)["ceilings"].(map[string]any)["maxReplyChars"] = 4096
			defaults(d)["ceilings"].(map[string]any)["maxAutonomousTurns"] = 51
		}, "ceilings"},
		"disclosure text": {func(d map[string]any) {
			defaults(d)["disclosure"].(map[string]any)["text"] = "."
		}, "disclosure text"},
		"variable added": {func(d map[string]any) {
			spec(d)["variables"] = append(spec(d)["variables"].([]any), map[string]any{"name": "pet", "type": "string", "profilePath": "identity.pet"})
		}, "variables"},
		"variable changed": {func(d map[string]any) { variable(d, "role")["required"] = false }, `variable "role"`},
		"variable disclosure loosened": {func(d map[string]any) {
			variable(d, "work_mode")["disclosure"] = "public"
		}, "stricter"},
		"records":      {func(d map[string]any) { spec(d)["records"] = map[string]any{"kind": "none"} }, "records"},
		"escalation":   {func(d map[string]any) { delete(spec(d), "escalation") }, "escalation"},
		"default mode": {func(d map[string]any) { defaults(d)["mode"] = "guarded" }, "defaults.mode"},
		"tags":         {func(d map[string]any) { meta(d)["tags"] = []any{"other"} }, "tags"},
		"examples":     {func(d map[string]any) { delete(meta(d), "examples") }, "examples"},
		"status":       {func(d map[string]any) { meta(d)["status"] = "draft" }, "status"},
		"wrong digest": {func(d map[string]any) {
			meta(d)["fork"].(map[string]any)["base"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("0", 64)
		}, "does not name this base"},
		"wrong version": {func(d map[string]any) { meta(d)["fork"].(map[string]any)["base"].(map[string]any)["version"] = "0.2.0" }, "does not name this base"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := mustEdit(t, fork, c.mutate)
			err := ValidateFork(base, f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ValidateFork = %v, want an error about %q", err, c.want)
			}
		})
	}
}

// Rules that need a narrower base than hr-recruiter: a tool the base does
// not have, and a disclosure policy the base requires.
func TestValidateFork_ToolsAndDisclosureAgainstANarrowBase(t *testing.T) {
	hr := hrBase(t)
	base := mustEdit(t, hr, func(d map[string]any) {
		var tools []any
		for _, x := range spec(d)["tools"].([]any) {
			if x != "save_job_lead" {
				tools = append(tools, x)
			}
		}
		spec(d)["tools"] = tools
		defaults(d)["disclosure"].(map[string]any)["policy"] = "required"
	})
	fork := validFork(t, base)
	if err := ValidateFork(base, fork); err != nil {
		t.Fatalf("valid fork refused: %v", err)
	}
	for name, c := range map[string]struct {
		mutate func(doc map[string]any)
		want   string
	}{
		"tool outside the base": {func(d map[string]any) {
			spec(d)["tools"] = append(spec(d)["tools"].([]any), "save_job_lead")
		}, `"save_job_lead" is not one of the base's`},
		"tool by alias outside the base": {func(d map[string]any) {
			spec(d)["tools"] = append(spec(d)["tools"].([]any), "save_record")
		}, `"save_record" is not one of the base's`},
		"disclosure weakened": {func(d map[string]any) {
			defaults(d)["disclosure"].(map[string]any)["policy"] = "optional"
		}, "weaker"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateFork(base, mustEdit(t, fork, c.mutate))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ValidateFork = %v, want an error about %q", err, c.want)
			}
		})
	}
	// BuildFork refuses the same through its overrides.
	if _, err := BuildFork(base, base, testForkName, FirstForkVersion, ForkOverrides{
		Tools: []string{"get_event", "save_job_lead", "complete_agent_job"},
	}); err == nil {
		t.Fatal("BuildFork accepted a tool outside the base")
	}
	if _, err := BuildFork(base, base, testForkName, FirstForkVersion, ForkOverrides{DisclosurePolicy: "optional"}); err == nil {
		t.Fatal("BuildFork accepted a weaker disclosure")
	}
}

func TestBuildFork_RefusesAForkAsBase(t *testing.T) {
	base := hrBase(t)
	fork := validFork(t, base)
	if _, err := BuildFork(fork, fork, "hr-recruiter~abcdefgh23~again", FirstForkVersion, ForkOverrides{}); err == nil {
		t.Fatal("a fork of a fork was built")
	}
	if err := ValidateFork(fork, fork); err == nil {
		t.Fatal("a fork validated against a fork")
	}
}

// The parser keeps a fork and a catalog definition apart, whichever way
// one is dressed as the other.
func TestParseDefinition_ForkMetadataRules(t *testing.T) {
	base := hrBase(t)
	fork := validFork(t, base)
	for name, c := range map[string]struct {
		from   *Entry
		mutate func(doc map[string]any)
	}{
		"fork name without fork": {fork, func(d map[string]any) { delete(meta(d), "fork") }},
		"fork without fork name": {fork, func(d map[string]any) { meta(d)["name"] = "hr-recruiter" }},
		"fork made public":       {fork, func(d map[string]any) { meta(d)["visibility"] = "public" }},
		"catalog made private":   {base, func(d map[string]any) { meta(d)["visibility"] = "private" }},
		"owner not the scope":    {fork, func(d map[string]any) { meta(d)["owner"] = "acct:zzzzzzzzzz" }},
		"name names another base": {fork, func(d map[string]any) {
			meta(d)["name"] = "other~abcdefgh23~careful"
		}},
		"bad owner scope": {fork, func(d map[string]any) {
			meta(d)["name"] = "hr-recruiter~ABCDEFGH23~careful"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := edit(t, c.from, c.mutate); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

func TestForkBumpAndVersions(t *testing.T) {
	base := hrBase(t)
	v1 := validFork(t, base)
	text := "Other wording.\n"
	v2, err := BuildFork(base, v1, testForkName, "0.1.1", ForkOverrides{Instructions: &text})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := ForkBump(v1, v2); b != BumpPatch {
		t.Fatalf("instructions only = %q, want patch", b)
	}
	v3, err := BuildFork(base, v2, testForkName, "0.2.0", ForkOverrides{Tools: []string{"get_event", "complete_agent_job", "propose_reply"}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := ForkBump(v2, v3); b != BumpMinor {
		t.Fatalf("tools = %q, want minor", b)
	}
	same, err := BuildFork(base, v3, testForkName, "0.2.1", ForkOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := ForkBump(v3, same); b != "" {
		t.Fatalf("no change = %q, want none", b)
	}
	for _, c := range []struct{ in, bump, want string }{
		{"0.1.0", BumpPatch, "0.1.1"}, {"0.1.9", BumpMinor, "0.2.0"}, {"0.9.3", BumpMinor, "0.10.0"},
	} {
		if got, err := NextForkVersion(c.in, c.bump); err != nil || got != c.want {
			t.Fatalf("NextForkVersion(%s, %s) = %s, %v", c.in, c.bump, got, err)
		}
	}
	if !VersionLess("0.9.0", "0.10.0") || VersionLess("0.10.0", "0.9.0") {
		t.Fatal("VersionLess is not numeric")
	}
}

func TestForkNames(t *testing.T) {
	scope, err := OwnerScope([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil || len(scope) != 10 || strings.ToLower(scope) != scope {
		t.Fatalf("scope = %q, %v", scope, err)
	}
	name := ForkName("hr-recruiter", scope, "careful")
	b, s, slug, err := ParseForkName(name)
	if err != nil || b != "hr-recruiter" || s != scope || slug != "careful" {
		t.Fatalf("ParseForkName(%s) = %s %s %s %v", name, b, s, slug, err)
	}
	for _, bad := range []string{"hr-recruiter", "hr-recruiter~abc~x", "a~abcdefgh23~UPPER", "a~abcdefgh23~b~c"} {
		if _, _, _, err := ParseForkName(bad); err == nil {
			t.Fatalf("ParseForkName(%q) accepted", bad)
		}
	}
	if !IsForkName(name) || IsForkName("hr-recruiter") {
		t.Fatal("IsForkName")
	}
}
