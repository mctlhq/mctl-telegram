package assistant

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
)

const hrDir = "../../assistants/hr-recruiter"

// danaID is the synthetic Dana persona used across the repository's tests.
const danaID = 500100303

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(hrDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func hrDefinition(t *testing.T) *Definition {
	t.Helper()
	def, err := ParseDefinition(readFile(t, "assistant.yaml"))
	if err != nil {
		t.Fatalf("ParseDefinition: %v", err)
	}
	return def
}

func hrInstall(t *testing.T) *Install {
	t.Helper()
	in, err := ParseInstall(readFile(t, "install.example.yaml"))
	if err != nil {
		t.Fatalf("ParseInstall: %v", err)
	}
	return in
}

// editYAML applies old->new replacements to a document and fails if any of
// them does not match, so a test cannot silently mutate nothing.
func editYAML(t *testing.T, raw []byte, pairs ...string) []byte {
	t.Helper()
	s := string(raw)
	for i := 0; i < len(pairs); i += 2 {
		if !strings.Contains(s, pairs[i]) {
			t.Fatalf("edit: %q not found", pairs[i])
		}
		s = strings.Replace(s, pairs[i], pairs[i+1], 1)
	}
	return []byte(s)
}

func TestHRDefinitionInstructionsExist(t *testing.T) {
	def := hrDefinition(t)
	path := filepath.Join(hrDir, def.Spec.Instructions.Path)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("instructions %s: %v", path, err)
	}
}

// TestHRInstallMatchesTodaysProfile pins the claim the format rests on: the
// HR example install yields exactly the profile the agent runs with today.
func TestHRInstallMatchesTodaysProfile(t *testing.T) {
	got, err := ProfileRequest(hrDefinition(t), hrInstall(t), danaID)
	if err != nil {
		t.Fatalf("ProfileRequest: %v", err)
	}
	owner, ok := got["owner_profile"].(json.RawMessage)
	if !ok {
		t.Fatalf("owner_profile is %T", got["owner_profile"])
	}
	delete(got, "owner_profile")

	want := map[string]any{
		"telegram_id":          int64(danaID),
		"mode":                 "guarded",
		"autopilot_paused":     false,
		"listener_enabled":     true,
		"disclosure_text":      "",
		"disclosure_disabled":  true,
		"max_autonomous_turns": 50,
		"max_msgs_per_minute":  2,
		"max_reply_chars":      1200,
		"intent_allowlist":     "discovery,schedule",
		"intent_denylist":      "",
		"working_hours":        "",
		"audience_excludes":    "",
		"blocked_senders":      "",
		"sender_allowlist":     "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("profile request\n got %#v\nwant %#v", got, want)
	}

	d, err := profile.ParseJSON(owner)
	if err != nil {
		t.Fatalf("owner profile does not parse: %v", err)
	}
	if d.Identity["name"] != "Dana" || d.Identity["role"] != "Backend engineer" {
		t.Errorf("identity = %v", d.Identity)
	}
	if !reflect.DeepEqual(d.Skills, []string{"Go", "Kubernetes", "PostgreSQL"}) {
		t.Errorf("skills = %v", d.Skills)
	}
	if d.PublicProfile["headline"] == nil || d.Preferences["work_mode"] != "remote" {
		t.Errorf("public_profile = %v, preferences = %v", d.PublicProfile, d.Preferences)
	}
	salary, ok := d.Restricted["salary_floor"]
	if !ok || !salary.NeverAutoSend || salary.ApprovalRequired {
		t.Errorf("restricted salary_floor = %+v (present %v)", salary, ok)
	}
	wantLevels := map[string]profile.DisclosureLevel{
		"identity.name":           profile.DisclosurePublic,
		"identity.role":           profile.DisclosurePublic,
		"skills":                  profile.DisclosurePublic,
		"public_profile.headline": profile.DisclosurePublic,
		"preferences.work_mode":   profile.DisclosureAfterOwnerEngaged,
		"preferences.relocation":  profile.DisclosureAfterOwnerEngaged,
	}
	if !reflect.DeepEqual(d.Disclosure, wantLevels) {
		t.Errorf("disclosure = %v, want %v", d.Disclosure, wantLevels)
	}
}

func TestDisclosureDefaultsOnForNewInstalls(t *testing.T) {
	raw := editYAML(t, readFile(t, "install.example.yaml"), "disclosure:\n    enabled: false\n", "")
	in, err := ParseInstall(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProfileRequest(hrDefinition(t), in, danaID)
	if err != nil {
		t.Fatal(err)
	}
	if got["disclosure_disabled"] != false || got["disclosure_text"] != "(sent by an AI assistant on the owner's behalf)" {
		t.Fatalf("disclosure = %v / %q", got["disclosure_disabled"], got["disclosure_text"])
	}
}

func TestDefinitionRejected(t *testing.T) {
	base := readFile(t, "assistant.yaml")
	cases := map[string][]string{
		"unknown field":           {"  records:\n", "  surprise: 1\n  records:\n"},
		"unknown tool":            {"    - get_event\n", "    - read_everything\n"},
		"missing instructions":    {"  instructions:\n    path: ../../deploy/agent-worker/system-prompt.txt\n", ""},
		"bad tier":                {"      tier: approve\n", "      tier: sometimes\n"},
		"bad version":             {"  version: 0.1.0\n", "  version: v0.1.0\n"},
		"limit above ceiling":     {"      maxAutonomousTurns: 6\n", "      maxAutonomousTurns: 60\n"},
		"restricted without send": {"      send: never\n", ""},
		"duplicate intent":        {"    - name: schedule\n", "    - name: discovery\n"},
		"send on public field":    {"      profilePath: identity.role\n", "      profilePath: identity.role\n      send: never\n"},
	}
	for name, pair := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDefinition(editYAML(t, base, pair...)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestInstallRejected(t *testing.T) {
	def := hrDefinition(t)
	base := readFile(t, "install.example.yaml")
	cases := map[string]struct {
		pairs       []string
		unsupported bool
	}{
		"wrong version":       {pairs: []string{"version: 0.1.0", "version: 0.2.0"}},
		"missing required":    {pairs: []string{"    name: Dana\n", ""}},
		"unknown variable":    {pairs: []string{"    name: Dana\n", "    name: Dana\n    nickname: D\n"}},
		"choice not allowed":  {pairs: []string{"work_mode: remote", "work_mode: moon"}},
		"wrong type":          {pairs: []string{"skills: [Go, Kubernetes, PostgreSQL]", "skills: Go"}},
		"limit above ceiling": {pairs: []string{"maxAutonomousTurns: 50", "maxAutonomousTurns: 51"}},
		"loosen tier":         {pairs: []string{"  limits:\n", "  intentTiers:\n    decline: auto\n  limits:\n"}},
		"unknown intent":      {pairs: []string{"  limits:\n", "  intentTiers:\n    flirt: auto\n  limits:\n"}},
		"looser disclosure": {pairs: []string{"  limits:\n",
			"  disclosureLevels:\n    work_mode: public\n  limits:\n"}},
		"looser disclosure, value omitted": {pairs: []string{"    relocation: Not planning to relocate\n", "",
			"  limits:\n", "  disclosureLevels:\n    relocation: public\n  limits:\n"}},
		"level on restricted": {pairs: []string{"  limits:\n",
			"  disclosureLevels:\n    salary_floor: never\n  limits:\n"}},
		"unknown key":            {pairs: []string{"  paused: false\n", "  paused: false\n  autopilot: true\n"}},
		"bad mode":               {pairs: []string{"mode: guarded", "mode: yolo"}},
		"schedule without hours": {pairs: []string{"  limits:\n", "  schedule:\n    mode: outside_hours\n    timezone: Europe/Zurich\n  limits:\n"}},
		"schedule bad zone":      {pairs: []string{"  limits:\n", "  schedule:\n    mode: outside_hours\n    timezone: Mars/Olympus\n    hours: [mon-fri 09:00-18:00]\n  limits:\n"}},
		"hours with always":      {pairs: []string{"  limits:\n", "  schedule:\n    mode: always\n    hours: [mon-fri 09:00-18:00]\n  limits:\n"}},
		"nobody by contact":      {pairs: []string{"  limits:\n", "  audience:\n    scope:\n      contacts: false\n      nonContacts: false\n  limits:\n"}},
		"nobody by chat age":     {pairs: []string{"  limits:\n", "  audience:\n    scope:\n      newChats: false\n      existingChats: false\n  limits:\n"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			in, err := ParseInstall(editYAML(t, base, tc.pairs...))
			if err == nil {
				_, err = ProfileRequest(def, in, danaID)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if got := errors.Is(err, ErrUnsupported); got != tc.unsupported {
				t.Fatalf("errors.Is(ErrUnsupported) = %v, err = %v", got, err)
			}
		})
	}
}

func TestInstallAccepted(t *testing.T) {
	def := hrDefinition(t)
	base := readFile(t, "install.example.yaml")
	cases := map[string][]string{
		"tighten tier":    {"  limits:\n", "  intentTiers:\n    discovery: approve\n  limits:\n"},
		"never tier":      {"  limits:\n", "  intentTiers:\n    discovery: never\n    decline: never\n  limits:\n"},
		"stricter level":  {"  limits:\n", "  disclosureLevels:\n    skills: never\n  limits:\n"},
		"schedule always": {"  limits:\n", "  schedule:\n    mode: always\n  limits:\n"},
		"narrow scope":    {"  limits:\n", "  audience:\n    scope:\n      existingChats: false\n      contacts: false\n  limits:\n"},
		"outside hours":   {"  limits:\n", "  schedule:\n    mode: outside_hours\n    timezone: Europe/Zurich\n    hours: [mon-fri 09:00-18:00, sat 22:00-02:00]\n  limits:\n"},
		"owner notes":     {"  limits:\n", "  ownerNotes: Keep replies under three sentences.\n  limits:\n"},
		// Alice and Bob ids from internal/mcp/canary_guard_test.go.
		"blocked and only":   {"  limits:\n", "  audience:\n    onlySenders: [500100101]\n    blockedSenders: [500100202]\n  limits:\n"},
		"no optional values": {"    headline: Backend engineer building messaging infrastructure.\n", ""},
	}
	for name, pairs := range cases {
		t.Run(name, func(t *testing.T) {
			in, err := ParseInstall(editYAML(t, base, pairs...))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ProfileRequest(def, in, danaID)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "tighten tier":
				if got["intent_allowlist"] != "schedule" {
					t.Fatalf("intent_allowlist = %v", got["intent_allowlist"])
				}
			case "narrow scope":
				if got["audience_excludes"] != "contacts,existing_chats" {
					t.Fatalf("audience_excludes = %v", got["audience_excludes"])
				}
			case "outside hours":
				if want := "Europe/Zurich;mon-fri 09:00-18:00;sat 22:00-02:00"; got["working_hours"] != want {
					t.Fatalf("working_hours = %v, want %q", got["working_hours"], want)
				}
			case "never tier":
				if got["intent_allowlist"] != "schedule" || got["intent_denylist"] != "decline,discovery" {
					t.Fatalf("intent lists = %v / %v", got["intent_allowlist"], got["intent_denylist"])
				}
			case "blocked and only":
				if got["sender_allowlist"] != "500100101" || got["blocked_senders"] != "500100202" {
					t.Fatalf("senders = %v / %v", got["sender_allowlist"], got["blocked_senders"])
				}
			}
		})
	}
}

func TestRequiredDisclosureCannotBeDisabled(t *testing.T) {
	raw := editYAML(t, readFile(t, "assistant.yaml"), "policy: optional", "policy: required")
	def, err := ParseDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileRequest(def, hrInstall(t), danaID); err == nil {
		t.Fatal("disclosure turned off on a required-disclosure assistant")
	}
}

func TestRestrictedToolSetUnsupported(t *testing.T) {
	raw := editYAML(t, readFile(t, "assistant.yaml"), "    - pause_autopilot\n", "")
	def, err := ParseDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileRequest(def, hrInstall(t), danaID); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// An unmarked variable is held to the runtime's default level, so an install
// cannot open relocation (after_owner_engaged by default) to everyone.
func TestUnmarkedVariableCannotBeLoosened(t *testing.T) {
	raw := editYAML(t, readFile(t, "assistant.yaml"),
		"      profilePath: preferences.relocation\n      disclosure: after_owner_engaged\n",
		"      profilePath: preferences.relocation\n")
	def, err := ParseDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	base := readFile(t, "install.example.yaml")
	loose, err := ParseInstall(editYAML(t, base, "  limits:\n", "  disclosureLevels:\n    relocation: public\n  limits:\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileRequest(def, loose, danaID); err == nil {
		t.Fatal("unmarked relocation opened to public")
	}
	strict, err := ParseInstall(editYAML(t, base, "  limits:\n", "  disclosureLevels:\n    relocation: never\n  limits:\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileRequest(def, strict, danaID); err != nil {
		t.Fatalf("stricter level rejected: %v", err)
	}
}

func TestRequiredDisclosureTextCannotBeReplaced(t *testing.T) {
	def, err := ParseDefinition(editYAML(t, readFile(t, "assistant.yaml"), "policy: optional", "policy: required"))
	if err != nil {
		t.Fatal(err)
	}
	in, err := ParseInstall(editYAML(t, readFile(t, "install.example.yaml"),
		"disclosure:\n    enabled: false\n", "disclosure:\n    text: \".\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ProfileRequest(def, in, danaID); err == nil {
		t.Fatal("required disclosure text replaced")
	}
}

// A minimal install starts like a new account: default mode, paused, not
// listening.
func TestMinimalInstallStartsSafe(t *testing.T) {
	in, err := ParseInstall([]byte(`apiVersion: assistants.mctl.ai/v1alpha1
kind: AssistantInstall
spec:
  assistant: {name: hr-recruiter, version: 0.1.0}
  values: {name: Dana, role: Backend engineer}
`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProfileRequest(hrDefinition(t), in, danaID)
	if err != nil {
		t.Fatal(err)
	}
	if got["mode"] != "observe" || got["autopilot_paused"] != true || got["listener_enabled"] != false {
		t.Fatalf("mode/paused/listening = %v/%v/%v", got["mode"], got["autopilot_paused"], got["listener_enabled"])
	}
	if got["max_autonomous_turns"] != 6 || got["disclosure_disabled"] != false {
		t.Fatalf("defaults not applied: %v", got)
	}
}

// The worker's model, budget and timeout come from its environment, so a
// definition that sets them must not install as if they applied.
func TestExecutionSettingsUnsupported(t *testing.T) {
	for name, block := range map[string]string{
		"budget":  "  execution:\n    budgetUsd: 0.5\n",
		"timeout": "  execution:\n    timeoutSeconds: 300\n",
		"model":   "  execution:\n    model: some-model\n",
	} {
		t.Run(name, func(t *testing.T) {
			def, err := ParseDefinition(append(readFile(t, "assistant.yaml"), block...))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ProfileRequest(def, hrInstall(t), danaID); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
		})
	}
}
