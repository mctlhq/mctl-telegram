package productupdate

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// GateReport is the release gate's verdict on one tool diff: the diff from
// the latest released snapshot (the baseline) to the snapshot at HEAD, and
// whether the feed covers it.
type GateReport struct {
	// Baseline is the release tag the diff is taken against, or "" when no
	// release carries a snapshot yet (then nothing can be required).
	Baseline string `json:"baseline"`
	Diff     Diff   `json:"diff"`
	// Required is every diff item a curated entry must cover: added and
	// removed tools, schema and annotation changes. Text and other changes
	// may be covered but need not be.
	Required []Claim `json:"required"`
	// Covered maps each covered item ("tool change") to the entry covering it.
	Covered map[string]string `json:"covered"`
	// Problems are why the gate fails; empty means it passes.
	Problems []string `json:"problems"`
}

// Passed reports a gate with nothing to fix.
func (r GateReport) Passed() bool { return len(r.Problems) == 0 }

func claimKey(c Claim) string { return c.Tool + " " + string(c.Change) }

// Gate holds the feed to the diff between the baseline release's snapshot and
// the current one.
//
//   - Every required item is covered by exactly one APPROVED entry whose
//     evidence.from is the baseline. A draft covers nothing.
//   - Every item an entry with that evidence.from claims is in the diff: an
//     entry cannot state a change the tool surface does not show.
//   - An item claimed by two entries is a duplicate, draft or not.
//   - A tool an entry for this baseline names exists at HEAD, or is one the
//     diff removed.
//   - No entry cites a release newer than the baseline.
//
// Entries for older baselines are history: their changes shipped in an
// earlier release, and they are held only to Validate.
//
// A no-op release (identical snapshots) requires nothing, and a rename is a
// removal plus an addition, each of which must be covered -- one entry may
// claim both.
func Gate(feed Feed, baseline string, previous, current Snapshot) (GateReport, error) {
	report := GateReport{Baseline: baseline, Required: []Claim{}, Covered: map[string]string{}, Problems: []string{}}
	if baseline == "" {
		report.Diff = Diff{Added: []string{}, Removed: []string{}, Changed: []ToolChange{}}
		for _, e := range feed.Entries {
			if e.Evidence.From != "" {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s cites release %s, but no release carries a tool snapshot yet", e.ID, e.Evidence.From))
			}
		}
		return report, nil
	}
	diff, err := Compare(previous, current)
	if err != nil {
		return report, err
	}
	report.Diff = diff

	shown := map[string]bool{}
	require := func(c Claim) {
		report.Required = append(report.Required, c)
		shown[claimKey(c)] = true
	}
	for _, tool := range diff.Added {
		require(Claim{Tool: tool, Change: ClaimAdded})
	}
	for _, tool := range diff.Removed {
		require(Claim{Tool: tool, Change: ClaimRemoved})
	}
	for _, change := range diff.Changed {
		for _, kind := range change.Kinds {
			switch kind {
			case ChangeSchema, ChangeAnnotations:
				require(Claim{Tool: change.Tool, Change: ClaimChange(kind)})
			case ChangeText:
				shown[claimKey(Claim{Tool: change.Tool, Change: ClaimText})] = true
			}
		}
	}
	removed := map[string]bool{}
	for _, tool := range diff.Removed {
		removed[tool] = true
	}

	claimedBy := map[string]string{}
	// staleClaim: an item an entry claims under an OLDER baseline -- usually a
	// pull request opened before the latest release, whose evidence.from now
	// needs bumping. Used only to make the failure say so.
	staleClaim := map[string]string{}
	for _, e := range feed.Entries {
		from := e.Evidence.From
		if from == "" {
			// A links-only maintenance or security notice: no diff to hold it
			// to, but the tools it names are current ones.
			for _, tool := range e.Tools {
				if _, ok := current.Tools[tool]; !ok {
					report.Problems = append(report.Problems, fmt.Sprintf(
						"%s names tool %s, which does not exist at HEAD", e.ID, tool))
				}
			}
			continue
		}
		newer, err := releaseAfter(from, baseline)
		if err != nil {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: %v", e.ID, err))
			continue
		}
		if newer {
			report.Problems = append(report.Problems, fmt.Sprintf(
				"%s cites release %s, newer than the latest released snapshot %s", e.ID, from, baseline))
			continue
		}
		if from != baseline {
			for _, c := range e.Evidence.Changes {
				staleClaim[claimKey(c)] = e.ID + " (evidence.from " + from + ")"
			}
			continue
		}
		for _, tool := range e.Tools {
			if _, ok := current.Tools[tool]; !ok && !removed[tool] {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s names tool %s, which neither exists at HEAD nor was removed since %s", e.ID, tool, baseline))
			}
		}
		for _, c := range e.Evidence.Changes {
			key := claimKey(c)
			if !shown[key] {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s claims %s %s, which the tool diff from %s does not show", e.ID, c.Tool, c.Change, baseline))
				continue
			}
			if other, dup := claimedBy[key]; dup {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s and %s both claim %s %s; one change is one update", other, e.ID, c.Tool, c.Change))
				continue
			}
			claimedBy[key] = e.ID
			if e.Status == StatusApproved {
				report.Covered[key] = e.ID
			}
		}
	}
	for _, c := range report.Required {
		key := claimKey(c)
		if _, ok := report.Covered[key]; ok {
			continue
		}
		if id, drafted := claimedBy[key]; drafted {
			report.Problems = append(report.Problems, fmt.Sprintf(
				"%s %s since %s is claimed only by draft %s; it needs review", c.Tool, c.Change, baseline, id))
			continue
		}
		if stale, ok := staleClaim[key]; ok {
			report.Problems = append(report.Problems, fmt.Sprintf(
				"%s %s since %s is claimed only by %s: a release was cut since; bump its evidence.from to %s",
				c.Tool, c.Change, baseline, stale, baseline))
			continue
		}
		report.Problems = append(report.Problems, fmt.Sprintf(
			"%s %s since %s has no product update: add docs/product-updates/<id>.yaml with evidence.from %s claiming it",
			c.Tool, c.Change, baseline, baseline))
	}
	sort.Strings(report.Problems)
	return report, nil
}

// releaseAfter reports whether release a is later than release b. Both are
// MAJOR.MINOR.PATCH.
func releaseAfter(a, b string) (bool, error) {
	pa, err := parseRelease(a)
	if err != nil {
		return false, err
	}
	pb, err := parseRelease(b)
	if err != nil {
		return false, err
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] > pb[i], nil
		}
	}
	return false, nil
}

func parseRelease(v string) ([3]int, error) {
	var out [3]int
	if !releasePattern.MatchString(v) {
		return out, fmt.Errorf("%q is not a MAJOR.MINOR.PATCH release", v)
	}
	for i, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return out, fmt.Errorf("%q is not a MAJOR.MINOR.PATCH release", v)
		}
		out[i] = n
	}
	return out, nil
}

// LatestRelease returns the latest of the given tags that is a
// MAJOR.MINOR.PATCH release and satisfies has, or "" when none does. The gate
// uses it to find the latest release whose tree carries a tool snapshot.
func LatestRelease(tags []string, has func(tag string) bool) string {
	var releases []string
	for _, t := range tags {
		if releasePattern.MatchString(t) {
			releases = append(releases, t)
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		after, _ := releaseAfter(releases[i], releases[j])
		return after
	})
	for _, t := range releases {
		if has(t) {
			return t
		}
	}
	return ""
}
