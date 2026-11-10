package v1alpha1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	digestCommand   = "b857f62b817887f56e5fea785c36f57ede44a5647da7c5cfd7e9d5069656dae1"
	digestResult    = "c91bb86e973aec1c43b8af1b0743c90d23d389cfdd81e9e5b8ab6042a729354f"
	digestWrite     = "38008bfce9887bfb86c610ee37578b41e33b91cc71f439b13e743c3aa253dc8a"
	digestBasket    = "da86bae104d86cdab17b77070d460ecf9d733c271491480ada01fc2ff1b38fb3"
	digestClaimResp = "5f50415d7ec2ba063c5967f2ca6fa70e75f45c419108eb3bf596a149fac70b4f"
)

func sum(t *testing.T, name string) string {
	t.Helper()
	b, err := SchemaFile(name)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// T1: schema pin.
func TestSchemaPins(t *testing.T) {
	for name, want := range map[string]string{
		"command.schema.json":                           digestCommand,
		"result.schema.json":                            digestResult,
		"v1alpha2/command-place-order-fake.schema.json": digestWrite,
		"v1alpha2/approval-basket.schema.json":          digestBasket,
		"v1alpha2/claim-response.schema.json":           digestClaimResp,
	} {
		if got := sum(t, name); got != want {
			t.Errorf("%s sha256 = %s, want %s", name, got, want)
		}
	}
	p, _ := SchemaFile("PROVENANCE")
	for _, s := range []string{digestCommand, digestResult, "14645f93"} {
		if !strings.Contains(string(p), s) {
			t.Errorf("PROVENANCE does not name %s", s)
		}
	}
	p2, _ := SchemaFile("v1alpha2/PROVENANCE")
	for _, s := range []string{digestWrite, digestBasket, digestClaimResp} {
		if !strings.Contains(string(p2), s) {
			t.Errorf("v1alpha2 PROVENANCE does not name %s", s)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("schema", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// T2: golden fixtures.
func TestGoldenFixtures(t *testing.T) {
	if _, _, err := ParseCommand(fixture(t, "testdata/command.valid.json")); err != nil {
		t.Fatalf("command.valid: %v", err)
	}
	if err := ValidateResult(fixture(t, "testdata/result.valid.json")); err != nil {
		t.Fatalf("result.valid: %v", err)
	}
	for _, n := range []string{"command.extra-field", "command.bad-ref-pattern", "command.mutation-missing-approval"} {
		_, _, err := ParseCommand(fixture(t, "testdata/"+n+".json"))
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", n, err)
		}
	}
	if err := ValidateResult(fixture(t, "testdata/result.extra-field.json")); !errors.Is(err, ErrInvalid) {
		t.Errorf("result.extra-field: err = %v", err)
	}
}

func TestBadRefKeepsEnvelope(t *testing.T) {
	_, env, err := ParseCommand(fixture(t, "testdata/command.bad-ref-pattern.json"))
	if !errors.Is(err, ErrInvalid) || !env.Complete() {
		t.Fatalf("err = %v env = %+v", err, env)
	}
	_, env, _ = ParseCommand([]byte(`{"command_id":"bad"}`))
	if env.Complete() || env.CommandID != "" {
		t.Fatalf("env = %+v", env)
	}
}

// T4: an extra field or bad enum never leaves the process.
func TestEncodeResult(t *testing.T) {
	var r Result
	if err := json.Unmarshal(fixture(t, "testdata/result.valid.json"), &r); err != nil {
		t.Fatal(err)
	}
	b, err := EncodeResult(r)
	if err != nil || len(b) == 0 {
		t.Fatalf("valid result: %v", err)
	}
	r.Outcome = "nope"
	if _, err := EncodeResult(r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad enum: %v", err)
	}
	if err := ValidateResult([]byte(`{"x":1}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extra: %v", err)
	}
}

func TestV2PlaceOrder(t *testing.T) {
	c, _, err := ParseCommand(fixture(t, "v1alpha2/command-place-order-fake.valid.json"))
	if err != nil || c.Basket == nil || len(c.Basket.Lines) != 1 || c.Basket.Lines[0].ItemCode != "FAKE-1" {
		t.Fatalf("v2 valid: %+v %v", c, err)
	}
	if _, _, err := ParseCommand(fixture(t, "v1alpha2/command-place-order-fake.v1alpha1-payload.json")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("v2 with v1 payload: %v", err)
	}
}

func mutate(t *testing.T, raw []byte, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, _ := json.Marshal(m)
	return b
}

// T26 (parse half): only place_order_fake is v1alpha2.
func TestV2RefusedForOtherShapes(t *testing.T) {
	v2 := fixture(t, "v1alpha2/command-place-order-fake.valid.json")
	v1 := fixture(t, "testdata/command.valid.json")
	cases := map[string][]byte{
		"v2 cancel":        mutate(t, v2, func(m map[string]any) { m["kind"] = KindCancelOrder }),
		"v2 quote":         mutate(t, v2, func(m map[string]any) { m["kind"] = KindQuote }),
		"v2 read_status":   mutate(t, v2, func(m map[string]any) { m["kind"] = KindReadStatus }),
		"v2 missing field": mutate(t, v2, func(m map[string]any) { delete(m, "approval_ref") }),
		"v2 extra field":   mutate(t, v2, func(m map[string]any) { m["x"] = 1 }),
		"v2 unknown ver":   mutate(t, v2, func(m map[string]any) { m["schema_version"] = "bridge.mctl.ai/v1alpha3" }),
		"v1 basket":        mutate(t, v1, func(m map[string]any) { m["payload"] = map[string]any{"v": "mctl-approval-basket/v1"} }),
		"v1 as v2 version": mutate(t, v1, func(m map[string]any) { m["schema_version"] = VersionV2 }),
	}
	for name, raw := range cases {
		if _, _, err := ParseCommand(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestParseClaimResponse(t *testing.T) {
	ok, err := ParseClaimResponse(fixture(t, "v1alpha2/claim-response.v1alpha2.valid.json"))
	if err != nil || ok.SchemaVersion != ClaimV2 {
		t.Fatalf("v2 claim: %+v %v", ok, err)
	}
	empty, err := ParseClaimResponse([]byte(`{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[]}`))
	if err != nil || len(empty.Commands) != 0 {
		t.Fatalf("empty: %v", err)
	}
	for name, body := range map[string]string{
		"missing":   `{"schema_version":"bridge.mctl.ai/v1alpha1"}`,
		"null":      `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":null}`,
		"not array": `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":{}}`,
		"extra":     `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[],"x":1}`,
		"trailing":  `{"schema_version":"bridge.mctl.ai/v1alpha1","commands":[]} {}`,
		"unknown":   `{"schema_version":"bridge.mctl.ai/claim/v1alpha3","commands":[]}`,
		"no ver":    `{"commands":[]}`,
		"not json":  `<html>`,
	} {
		if _, err := ParseClaimResponse([]byte(body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
