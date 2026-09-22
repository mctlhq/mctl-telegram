package db

// AttributeProvenance answers "can this attribute's emptiness be trusted?"
// for a single captured Telegram identity attribute (username, first name,
// last name, language code). It is three-valued rather than boolean because
// an empty column means two different things depending on whether capture
// has ever run for the row at all.
type AttributeProvenance string

const (
	// ProvenanceUnknown means identity_captured_at IS NULL: capture (or the
	// legacy backfill) has never run for this row, so an empty attribute
	// says nothing about what Telegram actually supplied.
	ProvenanceUnknown AttributeProvenance = "unknown"
	// ProvenanceNotSupplied means capture ran (identity_captured_at is set)
	// and the attribute came back empty: Telegram genuinely did not supply
	// it.
	ProvenanceNotSupplied AttributeProvenance = "not_supplied"
	// ProvenanceSupplied means the attribute is non-empty, attributable to
	// whatever identity_source captured it.
	ProvenanceSupplied AttributeProvenance = "supplied"
)

// ResolveIdentityProvenance implements the three-valued provenance rule
// described in design.md: it is a pure function of "has capture ever run"
// and "is the attribute value empty", with no DB access, so every consumer
// (the admin projection, MCP tools, tests) can apply it identically.
//
//   - capturedAtSet == false -> unknown: capture/backfill never ran for this
//     row; an empty attribute says nothing about what Telegram supplied.
//   - capturedAtSet == true, attribute == "" -> not_supplied: Telegram
//     genuinely did not send this attribute.
//   - attribute != "" -> supplied.
func ResolveIdentityProvenance(capturedAtSet bool, attribute string) AttributeProvenance {
	if !capturedAtSet {
		return ProvenanceUnknown
	}
	if attribute == "" {
		return ProvenanceNotSupplied
	}
	return ProvenanceSupplied
}
