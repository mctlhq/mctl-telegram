package executor

import (
	"os"
	"testing"
)

// TestDumpTable writes MarkdownTable to the path in DUMP_OUTCOME_TABLE, for
// regenerating the runbook section. It does nothing when the variable is unset.
func TestDumpTable(t *testing.T) {
	p := os.Getenv("DUMP_OUTCOME_TABLE")
	if p == "" {
		t.Skip("DUMP_OUTCOME_TABLE not set")
	}
	if err := os.WriteFile(p, []byte(MarkdownTable()), 0o644); err != nil {
		t.Fatal(err)
	}
}
