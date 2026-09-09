package mcpprobe

import "time"

// ReportMeta carries the provenance fields every Report needs, independent
// of which protocol mode(s) it covers.
type ReportMeta struct {
	// EvidenceSource labels which row of the compatibility matrix this
	// report is (design.md section 3). Required.
	EvidenceSource EvidenceSource
	// Label is an operator-supplied, human-readable description of the
	// target. Must not itself be or contain a secret.
	Label string
	// BuildRef identifies the code under test (e.g. a git SHA or image
	// tag), when known.
	BuildRef string
}

// NewReport assembles a Report from the independently-run Modern/Legacy/
// OAuth results. Any of modern, legacy, oauthResult may be nil: a run that
// only probed one Mode leaves the other nil rather than fabricating a zero
// value that could be misread as "probed and empty" (requirements.md
// acceptance criterion B: no result SHALL combine modern and legacy
// semantics).
func NewReport(meta ReportMeta, modern *ModernResult, legacy *LegacyResult, oauthResult *OAuthResult) *Report {
	return &Report{
		EvidenceSource: meta.EvidenceSource,
		Label:          meta.Label,
		Timestamp:      time.Now().UTC(),
		BuildRef:       meta.BuildRef,
		Modern:         modern,
		Legacy:         legacy,
		OAuth:          oauthResult,
	}
}
