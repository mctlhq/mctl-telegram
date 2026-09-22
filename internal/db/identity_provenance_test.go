package db

import "testing"

// TestResolveIdentityProvenance is the table-driven test for the pure
// three-valued rule: identity_captured_at IS NULL -> unknown; captured_at
// set + empty attribute -> not_supplied; non-empty -> supplied. Covers each
// of username / first name / last name / language code by exercising the
// same (capturedAtSet, attribute) shape they all share.
func TestResolveIdentityProvenance(t *testing.T) {
	tests := []struct {
		name          string
		capturedAtSet bool
		attribute     string
		want          AttributeProvenance
	}{
		{"unknown: no capture, empty attribute", false, "", ProvenanceUnknown},
		{"unknown: no capture, non-empty attribute (should not happen but still unknown)", false, "alice", ProvenanceUnknown},
		{"not_supplied: captured, empty username", true, "", ProvenanceNotSupplied},
		{"supplied: captured, non-empty username", true, "alice", ProvenanceSupplied},
		{"not_supplied: captured, empty first name", true, "", ProvenanceNotSupplied},
		{"supplied: captured, non-empty first name", true, "Alice", ProvenanceSupplied},
		{"not_supplied: captured, empty last name", true, "", ProvenanceNotSupplied},
		{"supplied: captured, non-empty last name", true, "Example", ProvenanceSupplied},
		{"not_supplied: captured, empty language code", true, "", ProvenanceNotSupplied},
		{"supplied: captured, non-empty language code", true, "en", ProvenanceSupplied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveIdentityProvenance(tc.capturedAtSet, tc.attribute)
			if got != tc.want {
				t.Errorf("ResolveIdentityProvenance(%v, %q) = %q, want %q",
					tc.capturedAtSet, tc.attribute, got, tc.want)
			}
		})
	}
}
