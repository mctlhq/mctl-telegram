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
	// Unverified lists entries whose citation the gate could not check,
	// because no release carries a snapshot yet. They pass: nothing can be
	// required or verified before the first baseline exists.
	Unverified []string `json:"unverified"`
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
//
// releases are the repository's tags, snapshot or not; anything that is not
// MAJOR.MINOR.PATCH is ignored. They are used only in the bootstrap window (no
// baseline), where a citation cannot be held to a diff but can still be held
// to reality: it must cite a release that exists as a tag -- not merely one
// no newer than the latest, since an entry citing a version below the oldest
// tag would count as shipped at once -- every tool it names must exist at HEAD
// unless it claims that tool's removal, and no change may be claimed twice. A
// repository with no release tag at all cannot carry a product update yet.
func Gate(feed Feed, baseline string, releases []string, previous, current Snapshot) (GateReport, error) {
	report := GateReport{Baseline: baseline, Required: []Claim{}, Covered: map[string]string{}, Problems: []string{}, Unverified: []string{}}
	if baseline == "" {
		// The bootstrap window: no release carries a snapshot, so there is no
		// diff to require anything from or to hold a citation to. A product
		// update written now must still cite a release (Validate), so the
		// citation is recorded as unverified rather than refused.
		report.Diff = Diff{Added: []string{}, Removed: []string{}, Changed: []ToolChange{}}
		bootstrapClaims := map[string]string{}
		released := map[string]bool{}
		for _, t := range releases {
			if releasePattern.MatchString(t) {
				released[t] = true
			}
		}
		latestTag := LatestRelease(releases, func(string) bool { return true })
		for _, e := range feed.Entries {
			from := e.Evidence.From
			if from == "" {
				continue
			}
			if latestTag == "" {
				report.Problems = append(report.Problems, fmt.Sprintf("%s cites release %s, but no release exists yet", e.ID, from))
				continue
			}
			newer, err := releaseAfter(from, latestTag)
			if err != nil {
				report.Problems = append(report.Problems, fmt.Sprintf("%s: evidence.from: %v", e.ID, err))
				continue
			}
			if newer {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s cites release %s, which is not a released version (latest: %s); cite the latest release", e.ID, from, latestTag))
				continue
			}
			if !released[from] {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"%s cites release %s, which is not a release tag of this repository (latest: %s); cite the latest release", e.ID, from, latestTag))
				continue
			}
			// Such an entry becomes history at the first snapshot release and is
			// never held to a diff, so what can be checked is checked now: every
			// tool it names exists at HEAD or is claimed as removed, and no
			// change is claimed twice.
			claimedRemoved := map[string]bool{}
			for _, c := range e.Evidence.Changes {
				if c.Change == ClaimRemoved {
					claimedRemoved[c.Tool] = true
				}
				if other, dup := bootstrapClaims[claimKey(c)]; dup {
					report.Problems = append(report.Problems, fmt.Sprintf(
						"%s and %s both claim %s %s; one change is one update", other, e.ID, c.Tool, c.Change))
				} else {
					bootstrapClaims[claimKey(c)] = e.ID
				}
			}
			for _, tool := range e.Tools {
				if _, ok := current.Tools[tool]; !ok && !claimedRemoved[tool] {
					report.Problems = append(report.Problems, fmt.Sprintf(
						"%s names tool %s, which does not exist at HEAD and is not claimed as removed", e.ID, tool))
				}
			}
			report.Unverified = append(report.Unverified, fmt.Sprintf("%s (evidence.from %s)", e.ID, from))
		}
		sort.Strings(report.Problems)
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
			// A links-only maintenance or security notice: it claims no
			// capability and has no diff to be held to. Its tool names are
			// syntax-checked by Validate only; checking them against HEAD
			// would never age out and would fail the day a tool it once named
			// is removed.
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
				"%s %s since %s has no product update citing %s; %s claims it under an older baseline: if that entry comes from a pull request opened before %s was cut, bump its evidence.from to %s, otherwise add a new entry",
				c.Tool, c.Change, baseline, baseline, stale, baseline, baseline))
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
