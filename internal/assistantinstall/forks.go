package assistantinstall

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Private forks (#1043, docs/assistants/adr-forks.md). A fork lives in
// assistant_forks, sealed with its owner's key, and narrows one catalog
// version, its base: the registry stays the authority through the base,
// whose lifecycle is the fork's. Forks are self-only: every method here
// acts on the caller's own account, and an install of a fork is refused
// for any other one.
//
// Nothing here returns, logs or audits a fork's instructions: they are the
// owner's data. Errors name rules, never the text.

// MsgForksDisabled answers every fork call while ASSISTANT_FORKS_ENABLED
// is off.
const MsgForksDisabled = "assistant forks are not enabled on this server"

// MsgForkObserveOnly refuses a fork in guarded mode: a fork version runs in
// observe mode until it is promoted, and P4.2 has no promotion.
const MsgForkObserveOnly = "invalid install: a fork runs in observe mode until it is promoted; set mode to observe or off"

// ForkBase names the catalog version a fork narrows.
type ForkBase struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// ForkVersion is one fork version as the fork tools report it: its
// reference and state, never its instructions.
type ForkVersion struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Digest    string   `json:"digest"`
	Base      ForkBase `json:"base"`
	Promotion string   `json:"promotion"`
}

// ForkWrite is the result of fork_assistant and update_fork: the new
// version, and the bump that made it ("" for a new fork).
type ForkWrite struct {
	ForkVersion
	Bump string `json:"bump,omitempty"`
}

// ForkSummary is one of the caller's forks with every version it holds,
// oldest first.
type ForkSummary struct {
	Name     string        `json:"name"`
	Base     ForkBase      `json:"base"`
	Latest   string        `json:"latest"`
	Versions []ForkVersion `json:"versions"`
}

type resolvedFork struct {
	entry     *assistant.Entry
	base      *assistant.Entry
	lifecycle string
}

// prepareFork resolves userID's fork name@version for an install: the
// fork's own document, checked against its digest and its base, and the
// base's lifecycle, read the same way as for a catalog install.
func (s *Service) prepareFork(ctx context.Context, userID int64, name, version string) (*resolvedFork, error) {
	if !s.ForksEnabled {
		return nil, fail(KindForksDisabled, MsgForksDisabled)
	}
	ref := name + "@" + version
	row, err := s.Store.GetAssistantFork(ctx, userID, name, version)
	if errors.Is(err, db.ErrAssistantForkNotFound) {
		return nil, fail(KindNotFound, "unknown assistant "+ref)
	}
	if err != nil {
		return nil, internal("failed to load assistant fork", err)
	}
	entry, err := forkEntry(row)
	if err != nil {
		return nil, err
	}
	base, lifecycle, err := s.forkBaseForInstall(ctx, row)
	if err != nil {
		return nil, err
	}
	if lifecycle == db.AssistantLifecycleDisabled {
		return nil, fail(KindLifecycle, "the base of assistant "+ref+" is disabled")
	}
	if err := assistant.ValidateFork(base, entry); err != nil {
		return nil, internal("stored fork does not narrow its base", errors.New("stored fork failed fork validation"))
	}
	return &resolvedFork{entry: entry, base: base, lifecycle: lifecycle}, nil
}

// forkEntry parses a stored fork version and checks it hashes to the
// digest it is stored under. The parse error can quote the document, so it
// is not passed on.
func forkEntry(row *db.AssistantFork) (*assistant.Entry, error) {
	e, err := assistant.ParseMaterialized(row.Document)
	if err != nil {
		return nil, internal("stored fork no longer parses", fmt.Errorf("fork %s does not parse", row.Digest))
	}
	if e.Digest != row.Digest || e.Definition.Metadata.Name != row.Name || e.Definition.Metadata.Version != row.Version {
		return nil, internal("stored fork does not match its digest", fmt.Errorf("fork %s hashes to %s", row.Digest, e.Digest))
	}
	return e, nil
}

// forkBaseForInstall reads the base of a stored fork with a current
// lifecycle: from the registry when one is configured (falling back to the
// stored snapshot when the registry's document under that version is no
// longer the pinned one), else from the embedded catalog.
func (s *Service) forkBaseForInstall(ctx context.Context, row *db.AssistantFork) (*assistant.Entry, string, error) {
	ref := row.BaseName + "@" + row.BaseVersion
	if s.Registry == nil {
		e, ok := s.Catalog.Lookup(row.BaseName, row.BaseVersion)
		if !ok || e.Digest != row.BaseDigest {
			return nil, "", fail(KindLifecycle, "the base "+ref+" of this fork is no longer available")
		}
		return e, db.AssistantLifecyclePublished, nil
	}
	fetched, err := s.Registry.Fetch(ctx, row.BaseName, row.BaseVersion)
	switch {
	case errors.Is(err, assistantregistry.ErrNotFound):
		// The registry's own answer that the version is gone: disabled.
		return nil, "", fail(KindLifecycle, "the base "+ref+" of this fork is disabled")
	case errors.Is(err, assistantregistry.ErrDigestMismatch), errors.Is(err, assistantregistry.ErrInvalid):
		return nil, "", &Error{Kind: KindUpstream, Msg: "assistant registry returned an invalid definition: install refused", Err: err}
	case err != nil:
		return nil, "", &Error{Kind: KindUnavailable, Msg: "assistant registry unavailable", Err: err}
	}
	if fetched.Entry.Digest == row.BaseDigest {
		return fetched.Entry, fetched.Lifecycle, nil
	}
	// Only a draft changes under its version; the fork keeps the base it
	// pinned, which must then be in the snapshot store.
	def, err := s.Store.GetAssistantDefinition(ctx, row.BaseDigest)
	if errors.Is(err, db.ErrAssistantDefinitionNotFound) {
		return nil, "", fail(KindLifecycle, "the base "+ref+" this fork pinned is no longer available")
	}
	if err != nil {
		return nil, "", internal("failed to load the fork's base", err)
	}
	e, perr := assistant.ParseMaterialized(def.Document)
	if perr != nil || e.Digest != row.BaseDigest {
		return nil, "", internal("stored base does not match its digest", fmt.Errorf("base %s", row.BaseDigest))
	}
	return e, fetched.Lifecycle, nil
}

// checkForkInstall holds a prepared fork install to the fork rules: the
// caller's own fork (prepareFork already refused it with forks off), and
// never guarded.
func (s *Service) checkForkInstall(userID int64, p *Prepared) error {
	if p.fork.owner != userID {
		return fail(KindNotFound, "unknown assistant "+p.Name()+"@"+p.Version())
	}
	if p.resolved.Mode == db.AgentModeGuarded {
		return fail(KindInvalid, MsgForkObserveOnly)
	}
	return nil
}

// ownerScope is the owner scope of userID's fork names.
func (s *Service) ownerScope(userID int64) (string, error) {
	mac, err := s.Store.ForkOwnerMAC(userID)
	if err != nil {
		return "", err
	}
	return assistant.OwnerScope(mac)
}

// forkBaseForCreate resolves name@version as a new install would: the
// registry with its lifecycle when configured (published, or deprecated
// only for the name@version the account already runs), else a public,
// non-draft entry of the embedded catalog or the one the account runs.
func (s *Service) forkBaseForCreate(ctx context.Context, userID int64, name, version string) (*assistant.Entry, error) {
	ref := name + "@" + version
	if assistant.IsForkName(name) {
		return nil, fail(KindInvalid, "invalid fork: the base must be a catalog assistant, not a fork")
	}
	current, err := s.Store.GetAgentAssistantRef(ctx, userID)
	if err != nil && !errors.Is(err, db.ErrAgentProfileNotFound) {
		return nil, internal("failed to load current assistant", err)
	}
	runs := err == nil && current.Installed && current.Name == name && current.Version == version
	if s.Registry == nil {
		e, ok := s.Catalog.Lookup(name, version)
		if !ok {
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		}
		if m := e.Definition.Metadata; !runs && (m.Visibility != "public" || m.Status == "draft") {
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		}
		return e, nil
	}
	fetched, err := s.Registry.Fetch(ctx, name, version)
	switch {
	case errors.Is(err, assistantregistry.ErrNotFound):
		return nil, fail(KindNotFound, "unknown assistant "+ref)
	case errors.Is(err, assistantregistry.ErrDigestMismatch):
		return nil, &Error{Kind: KindUpstream, Msg: "assistant registry digest mismatch: fork refused", Err: err}
	case errors.Is(err, assistantregistry.ErrInvalid):
		return nil, &Error{Kind: KindUpstream, Msg: "assistant registry returned an invalid definition: fork refused", Err: err}
	case err != nil:
		return nil, &Error{Kind: KindUnavailable, Msg: "assistant registry unavailable", Err: err}
	}
	switch fetched.Lifecycle {
	case db.AssistantLifecycleDisabled:
		return nil, fail(KindLifecycle, "assistant "+ref+" is disabled")
	case db.AssistantLifecycleDeprecated:
		if !runs {
			return nil, fail(KindLifecycle, "assistant "+ref+" is deprecated: only an account already running it may fork it")
		}
	}
	return fetched.Entry, nil
}

// forkBaseForUpdate reads the base a fork already pins: its stored
// snapshot when the account installed it, else the registry or the
// embedded catalog, by digest. A disabled base takes no new versions.
func (s *Service) forkBaseForUpdate(ctx context.Context, row *db.AssistantFork) (*assistant.Entry, error) {
	ref := row.BaseName + "@" + row.BaseVersion
	def, err := s.Store.GetAssistantDefinition(ctx, row.BaseDigest)
	switch {
	case err == nil:
		if def.Lifecycle == db.AssistantLifecycleDisabled {
			return nil, fail(KindLifecycle, "the base "+ref+" of this fork is disabled")
		}
		e, perr := assistant.ParseMaterialized(def.Document)
		if perr != nil || e.Digest != row.BaseDigest {
			return nil, internal("stored base does not match its digest", fmt.Errorf("base %s", row.BaseDigest))
		}
		return e, nil
	case !errors.Is(err, db.ErrAssistantDefinitionNotFound):
		return nil, internal("failed to load the fork's base", err)
	}
	e, _, ferr := s.forkBaseForInstall(ctx, row)
	if ferr != nil {
		return nil, ferr
	}
	return e, nil
}

func forkVersionOf(row *db.AssistantFork) ForkVersion {
	return ForkVersion{
		Name: row.Name, Version: row.Version, Digest: row.Digest,
		Base:      ForkBase{Name: row.BaseName, Version: row.BaseVersion, Digest: row.BaseDigest},
		Promotion: row.Promotion,
	}
}

// forkNotice is the owner alert queued with every fork write: what was
// saved, never the instructions.
func forkNotice(name, version, digest, bump string) string {
	what := "A new private assistant fork was saved"
	if bump != "" {
		what = "A new version (" + bump + " change) of your private assistant fork was saved"
	}
	return fmt.Sprintf("%s: %s@%s (%s). It runs in observe mode only: every reply waits for your approval. If you did not make this change, delete it with delete_fork and review which apps can manage your account.",
		what, name, version, digest)
}

// storeFork saves fork as the next version of its name after after, and
// maps the store's refusals.
func (s *Service) storeFork(ctx context.Context, userID int64, fork, base *assistant.Entry, after, bump string) (*ForkWrite, error) {
	m := fork.Definition.Metadata
	row := db.AssistantFork{
		UserID: userID, Name: m.Name, Version: m.Version, Digest: fork.Digest,
		BaseName: base.Definition.Metadata.Name, BaseVersion: base.Definition.Metadata.Version, BaseDigest: base.Digest,
		Document: fork.Materialized, Promotion: db.ForkPromotionObserve,
	}
	err := s.Store.InsertAssistantFork(ctx, row, after, forkNotice(m.Name, m.Version, fork.Digest, bump))
	switch {
	case errors.Is(err, db.ErrForkLimit):
		return nil, fail(KindForkLimit, fmt.Sprintf("fork_limit: an account holds at most %d forks and a fork at most %d versions; nothing changed. Delete a fork or unused versions with delete_fork first.",
			db.MaxForksPerAccount, db.MaxVersionsPerFork))
	case errors.Is(err, db.ErrForkConflict):
		if after == "" {
			return nil, fail(KindForkConflict, "a fork named "+m.Name+" already exists: change it with update_fork")
		}
		return nil, fail(KindForkConflict, "the fork changed while this update was prepared; nothing changed, retry")
	case err != nil:
		return nil, internal("failed to save assistant fork", err)
	}
	return &ForkWrite{ForkVersion: forkVersionOf(&row), Bump: bump}, nil
}

// forkInvalid turns a fork build error into KindInvalid. The rules name
// intents, tools, limits and variables, never the instructions, but a
// schema message can quote a submitted value: Msg names only the rule.
func forkInvalid(err error) *Error {
	e := invalid(err)
	e.Msg = strings.Replace(e.Msg, "invalid install", "invalid fork", 1)
	e.Detail = strings.Replace(e.Detail, "invalid install", "invalid fork", 1)
	return e
}

// CreateFork creates userID's fork <base>~<owner-scope>~<slug> of
// baseName@baseVersion with ov applied, at version 0.1.0.
func (s *Service) CreateFork(ctx context.Context, userID int64, baseName, baseVersion, slug string, ov assistant.ForkOverrides) (*ForkWrite, error) {
	if !s.ForksEnabled {
		return nil, fail(KindForksDisabled, MsgForksDisabled)
	}
	if !assistant.ValidForkSlug(slug) {
		return nil, fail(KindInvalid, "invalid fork: slug must match ^[a-z0-9][a-z0-9_-]{0,31}$")
	}
	base, err := s.forkBaseForCreate(ctx, userID, baseName, baseVersion)
	if err != nil {
		return nil, err
	}
	scope, err := s.ownerScope(userID)
	if err != nil {
		return nil, internal("failed to derive the fork owner scope", err)
	}
	name := assistant.ForkName(base.Definition.Metadata.Name, scope, slug)
	fork, err := assistant.BuildFork(base, base, name, assistant.FirstForkVersion, ov)
	if err != nil {
		return nil, forkInvalid(err)
	}
	return s.storeFork(ctx, userID, fork, base, "", "")
}

// UpdateFork writes the next version of userID's fork name: its latest
// version with ov applied, a patch bump when only the instructions change
// and a minor one otherwise. An update that changes nothing is refused.
func (s *Service) UpdateFork(ctx context.Context, userID int64, name string, ov assistant.ForkOverrides) (*ForkWrite, error) {
	if !s.ForksEnabled {
		return nil, fail(KindForksDisabled, MsgForksDisabled)
	}
	if !assistant.IsForkName(name) {
		return nil, fail(KindNotFound, "unknown fork "+name)
	}
	latest, err := s.Store.GetLatestAssistantFork(ctx, userID, name)
	if errors.Is(err, db.ErrAssistantForkNotFound) {
		return nil, fail(KindNotFound, "unknown fork "+name)
	}
	if err != nil {
		return nil, internal("failed to load assistant fork", err)
	}
	prev, err := forkEntry(latest)
	if err != nil {
		return nil, err
	}
	base, err := s.forkBaseForUpdate(ctx, latest)
	if err != nil {
		return nil, err
	}
	// The bump depends on what changed, so the fork is built once to see,
	// and again under its version.
	draft, err := assistant.BuildFork(base, prev, name, latest.Version, ov)
	if err != nil {
		return nil, forkInvalid(err)
	}
	bump, err := assistant.ForkBump(prev, draft)
	if err != nil {
		return nil, internal("failed to compare fork versions", err)
	}
	if bump == "" {
		return nil, fail(KindInvalid, "invalid fork: the update changes nothing")
	}
	version, err := assistant.NextForkVersion(latest.Version, bump)
	if err != nil {
		return nil, internal("failed to number the fork version", err)
	}
	fork, err := assistant.BuildFork(base, prev, name, version, ov)
	if err != nil {
		return nil, forkInvalid(err)
	}
	return s.storeFork(ctx, userID, fork, base, latest.Version, bump)
}

// DeleteFork deletes userID's fork name@version, or every version of it
// when version is "". The version the install pins is refused
// (fork_in_use). Deleting stays possible with forks disabled, so an owner
// can always remove their data.
func (s *Service) DeleteFork(ctx context.Context, userID int64, name, version string) (int, error) {
	n, err := s.Store.DeleteAssistantFork(ctx, userID, name, version)
	switch {
	case errors.Is(err, db.ErrAssistantForkNotFound):
		return 0, fail(KindNotFound, "unknown fork "+name)
	case errors.Is(err, db.ErrForkInUse):
		return 0, fail(KindForkInUse, "fork_in_use: the install runs this fork version; install another assistant or version first. Nothing was deleted.")
	case err != nil:
		return 0, internal("failed to delete assistant fork", err)
	}
	return n, nil
}

// ListForks returns userID's own forks, never anyone else's. It lists them
// whether or not forks are enabled, so an owner can always see and delete
// their own data.
func (s *Service) ListForks(ctx context.Context, userID int64) ([]ForkSummary, error) {
	rows, err := s.Store.ListAssistantForks(ctx, userID)
	if err != nil {
		return nil, internal("failed to list assistant forks", err)
	}
	out := []ForkSummary{}
	idx := map[string]int{}
	for i := range rows {
		r := &rows[i]
		j, ok := idx[r.Name]
		if !ok {
			j = len(out)
			idx[r.Name] = j
			out = append(out, ForkSummary{Name: r.Name, Base: ForkBase{Name: r.BaseName, Version: r.BaseVersion, Digest: r.BaseDigest}})
		}
		out[j].Versions = append(out[j].Versions, forkVersionOf(r))
		if out[j].Latest == "" || assistant.VersionLess(out[j].Latest, r.Version) {
			out[j].Latest = r.Version
		}
	}
	return out, nil
}
