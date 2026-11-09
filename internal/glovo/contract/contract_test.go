package contract

import (
	"bytes"
	"os"
	"testing"
)

func TestEmbeddedCopyEqualsDocsContract(t *testing.T) {
	docs, err := os.ReadFile("../../../docs/contracts/glovo-mcp-tools.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(docs, Raw()) {
		t.Fatal("internal/glovo/contract/glovo-mcp-tools.json drifted from docs/contracts/glovo-mcp-tools.json; update both together")
	}
}

func TestLoad(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tools) != 7 {
		t.Fatalf("tools = %d, want 7", len(c.Tools))
	}
	if c.Resource != "https://glovo.mctl.ai/mcp" {
		t.Fatalf("resource = %q", c.Resource)
	}
	if len(c.Scopes) != 2 {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	hist := c.Tool("glovo_get_order_history")
	if err := hist.ValidateInput([]byte(`{"limit":20}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"limit":0}`, `{"limit":21}`, `{"tenant":"x"}`, `{"limit":"3"}`, `[]`} {
		if err := hist.ValidateInput([]byte(bad)); err == nil {
			t.Errorf("input %s accepted", bad)
		}
	}
	basket := c.Tool("glovo_get_basket")
	if err := basket.ValidateOutput([]byte(`{"items":[],"totals_label":"0","fingerprint":"f","x":1}`)); err == nil {
		t.Error("extra output field accepted")
	}
}
