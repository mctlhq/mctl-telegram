// Package assistantinstall is the one application service behind every
// way an account's assistant install changes (#1021): the admin route
// PUT /api/admin/agent/install, the MCP tools install_assistant and
// update_install, and the web page that follows. Each surface translates
// its own request into a call here and the result back into its own
// answer; resolving the definition, the lifecycle gate, the snapshot and
// the revision move happen nowhere else.
package assistantinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	agentprofile "github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Kind classifies an *Error so each surface can answer it its own way.
type Kind int

const (
	// KindInvalid: the install, or a patch of it, does not validate.
	KindInvalid Kind = iota + 1
	// KindNotFound: no such assistant name@version (for this caller).
	KindNotFound
	// KindLifecycle: the registry lifecycle refuses this install
	// (disabled, or deprecated for an account not already running it).
	KindLifecycle
	// KindRevisionConflict: the install moved past the expected revision;
	// nothing changed. CurrentRevision says where it is.
	KindRevisionConflict
	// KindNoInstall: there is no stored install to patch.
	KindNoInstall
	// KindUpstream: the registry answered with a definition that failed
	// its digest check or does not parse.
	KindUpstream
	// KindUnavailable: the registry could not be read. Retryable.
	KindUnavailable
	// KindInternal: a database or encryption fault.
	KindInternal
	// KindForkLimit: a fork quota refused the write (fork_limit); nothing
	// changed.
	KindForkLimit
	// KindForkInUse: the delete would remove the fork version the install
	// pins (fork_in_use); nothing changed.
	KindForkInUse
	// KindForkConflict: the fork moved while the write was prepared;
	// nothing changed.
	KindForkConflict
	// KindForksDisabled: ASSISTANT_FORKS_ENABLED is off.
	KindForksDisabled
	// KindManagedConsentRequired: switching to the managed runtime needs
	// the current consent (managed_consent_required); nothing changed.
	KindManagedConsentRequired
	// KindManagedDisabled: MANAGED_RUNTIME_ENABLED is off (managed_disabled).
	KindManagedDisabled
	// KindManagedQuota: the managed-account quota is exhausted
	// (managed_quota); nothing changed.
	KindManagedQuota
)

// Error is a refused or failed install. Msg is meant for the caller who
// sent the document; it never quotes an install value. Detail, when set,
// is the full validator message, which can quote a submitted value: only
// a surface that hands it straight back to the sender may show it, and no
// surface logs it.
type Error struct {
	Kind            Kind
	Msg             string
	Detail          string
	CurrentRevision int64
	// Err is the underlying fault, for KindUpstream, KindUnavailable and
	// KindInternal; it reaches logs and never holds install content.
	Err error
}

func (e *Error) Error() string { return e.Msg }

func (e *Error) Unwrap() error { return e.Err }

// Full is Detail when set, else Msg.
func (e *Error) Full() string {
	if e.Detail != "" {
		return e.Detail
	}
	return e.Msg
}

// MsgSaveFailed is the KindInternal message of a failed install write.
const MsgSaveFailed = "failed to save agent install"

func fail(kind Kind, msg string) *Error { return &Error{Kind: kind, Msg: msg} }

func internal(msg string, err error) *Error {
	return &Error{Kind: KindInternal, Msg: msg, Err: err}
}

// Service applies installs. Registry nil means the embedded catalog is the
// source of definitions (ASSISTANT_REGISTRY_ENABLED off).
type Service struct {
	Store    *db.Store
	Catalog  *assistant.Catalog
	Registry *assistantregistry.Client
	// ForksEnabled is ASSISTANT_FORKS_ENABLED: with it off, no fork is
	// created, changed or installed (#1043).
	ForksEnabled bool
	// Managed is the managed-runtime gate (ADR 0008).
	Managed ManagedRuntime
	// Now is the clock for install times; nil means time.Now.
	Now func() time.Time
	// beforeWrite, when set, runs between the read of the current install
	// and the UPDATE; tests use it to race a concurrent install.
	beforeWrite func()
}

// New returns a Service. registry may be nil.
func New(store *db.Store, catalog *assistant.Catalog, registry *assistantregistry.Client) *Service {
	return &Service{Store: store, Catalog: catalog, Registry: registry}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Prepared is an install validated against its definition and ready to be
// committed for an account.
type Prepared struct {
	install      *assistant.Install
	document     []byte
	entry        *assistant.Entry
	lifecycle    string
	resolved     *assistant.Profile
	ownerProfile []byte
	// consent is spec.consent as asserted by this call. It is stripped from
	// document, so it is never stored.
	consent string
	// fork is set when the install names one of the caller's forks: entry
	// is then the fork and lifecycle its base's.
	fork *preparedFork
}

// preparedFork is the fork side of a Prepared: whose fork it is and the
// base it narrows, whose snapshot is stored with the install.
type preparedFork struct {
	owner int64
	base  *assistant.Entry
}

// Name and Version are the definition the install resolved against.
func (p *Prepared) Name() string    { return p.entry.Definition.Metadata.Name }
func (p *Prepared) Version() string { return p.entry.Definition.Metadata.Version }

// Prepare parses raw as an AssistantInstall, fetches its definition (from
// the registry when one is configured, else the embedded catalog) and
// resolves the install against it. Nothing is written. It installs for no
// account in particular, so it never resolves a fork: forks are installed
// only by their owner, through Apply.
func (s *Service) Prepare(ctx context.Context, raw json.RawMessage) (*Prepared, error) {
	return s.prepare(ctx, 0, raw)
}

// prepare is Prepare for userID, whose own forks it also resolves; 0 is no
// account.
func (s *Service) prepare(ctx context.Context, userID int64, raw json.RawMessage) (*Prepared, error) {
	in, err := assistant.ParseInstall(raw)
	if err != nil {
		return nil, invalid(err)
	}
	ref := in.Spec.Assistant.Name + "@" + in.Spec.Assistant.Version
	var entry *assistant.Entry
	var fork *preparedFork
	lifecycle := ""
	if assistant.IsForkName(in.Spec.Assistant.Name) {
		if userID <= 0 {
			// The admin route installs for another account; a fork is
			// installed only by its owner.
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		}
		pf, err := s.prepareFork(ctx, userID, in.Spec.Assistant.Name, in.Spec.Assistant.Version)
		if err != nil {
			return nil, err
		}
		entry, lifecycle, fork = pf.entry, pf.lifecycle, &preparedFork{owner: userID, base: pf.base}
	} else if s.Registry == nil {
		e, ok := s.Catalog.Lookup(in.Spec.Assistant.Name, in.Spec.Assistant.Version)
		if !ok {
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		}
		entry = e
	} else {
		fetched, err := s.Registry.Fetch(ctx, in.Spec.Assistant.Name, in.Spec.Assistant.Version)
		switch {
		case errors.Is(err, assistantregistry.ErrNotFound):
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		case errors.Is(err, assistantregistry.ErrDigestMismatch):
			return nil, &Error{Kind: KindUpstream, Msg: "assistant registry digest mismatch: install refused", Err: err}
		case errors.Is(err, assistantregistry.ErrInvalid):
			return nil, &Error{Kind: KindUpstream, Msg: "assistant registry returned an invalid definition: install refused", Err: err}
		case err != nil:
			return nil, &Error{Kind: KindUnavailable, Msg: "assistant registry unavailable", Err: err}
		}
		entry, lifecycle = fetched.Entry, fetched.Lifecycle
		if lifecycle == db.AssistantLifecycleDisabled {
			return nil, fail(KindLifecycle, "assistant "+ref+" is disabled")
		}
	}
	resolved, err := assistant.Resolve(entry.Definition, in)
	if err != nil {
		return nil, invalid(err)
	}
	parsed, err := agentprofile.ParseJSON(resolved.OwnerProfile)
	if err != nil {
		return nil, fail(KindInvalid, "invalid install: owner profile")
	}
	ownerProfile, err := json.Marshal(parsed)
	if err != nil {
		return nil, fail(KindInvalid, "invalid install: owner profile")
	}
	var doc bytes.Buffer
	if err := json.Compact(&doc, raw); err != nil {
		return nil, fail(KindInvalid, "invalid install")
	}
	document := doc.Bytes()
	if in.Spec.Consent != "" || bytes.Contains(document, []byte(`"consent"`)) {
		document, err = stripConsent(document)
		if err != nil {
			return nil, fail(KindInvalid, "invalid install")
		}
	}
	return &Prepared{
		consent: in.Spec.Consent,
		install: in, document: document, entry: entry, lifecycle: lifecycle,
		resolved: resolved, ownerProfile: ownerProfile, fork: fork,
	}, nil
}

// stripConsent removes spec.consent from an install document, so a consent
// is an act of one call and is never stored or inherited by a later patch.
func stripConsent(document []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, err
	}
	if spec, ok := doc["spec"].(map[string]any); ok {
		if _, has := spec["consent"]; !has {
			return document, nil
		}
		delete(spec, "consent")
	}
	return json.Marshal(doc)
}

// invalid turns a parse or resolve error into KindInvalid. A schema error
// can quote the value that failed, so Msg names only where and which rule;
// the full text goes to Detail.
func invalid(err error) *Error {
	full := "invalid install: " + err.Error()
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return &Error{Kind: KindInvalid, Msg: full}
	}
	var where []string
	var walk func(v *jsonschema.ValidationError)
	walk = func(v *jsonschema.ValidationError) {
		if len(v.Causes) == 0 {
			loc := "/" + strings.Join(v.InstanceLocation, "/")
			if kp := v.ErrorKind.KeywordPath(); len(kp) > 0 {
				loc += " (" + strings.Join(kp, "/") + ")"
			}
			where = append(where, loc)
			return
		}
		for _, c := range v.Causes {
			walk(c)
		}
	}
	walk(ve)
	sort.Strings(where)
	return &Error{Kind: KindInvalid, Msg: "invalid install: does not match the AssistantInstall schema at " + strings.Join(where, ", "), Detail: full}
}

// CommitOptions qualify one commit.
type CommitOptions struct {
	// ExpectedRevision is the install revision the caller read. Every
	// commit is a compare-and-set; without this, it is against the
	// revision Commit itself reads.
	ExpectedRevision *int64
	// SelfService is set when the account's owner installs for themselves
	// (MCP, web): only public, non-draft definitions are offered, except
	// the name@version the account already runs, which it may keep
	// reconfiguring. The admin route installs anything in the catalog.
	SelfService bool
}

// Result is a committed install.
type Result struct {
	Name, Version string
	// Profile is the saved profile, read back after the commit.
	Profile *db.AgentProfile
	// CleanupErr is set when the install was saved but denying the
	// actions of earlier revisions failed. The install stands, since the
	// revision check already fences them; the caller logs it.
	CleanupErr error
}

// Commit applies p to userID's profile: every setting it resolves to, the
// owner profile, the assistant reference and the install, with the install
// revision moved and, with a registry, the definition snapshot stored, all
// in one transaction. Work created under the earlier revision is fenced by
// that revision (#1018); the proposed and approved actions it left are
// then denied as cleanup.
func (s *Service) Commit(ctx context.Context, userID int64, p *Prepared, opts CommitOptions) (*Result, error) {
	if err := s.Store.EnsureAgentProfile(ctx, userID); err != nil {
		return nil, internal("failed to initialize agent profile", err)
	}
	name, version := p.Name(), p.Version()
	ref := name + "@" + version
	current, err := s.Store.GetAgentAssistantRef(ctx, userID)
	if err != nil {
		return nil, internal("failed to load current assistant", err)
	}
	if opts.ExpectedRevision != nil && current.InstallRevision != *opts.ExpectedRevision {
		return nil, conflict(current.InstallRevision)
	}
	// The gates below are decided from current, so the UPDATE must find
	// the install exactly as read: without a caller's revision the one
	// just read is the compare-and-set, and a concurrent install in
	// between answers a conflict instead of reinstalling a deprecated or
	// private version the account no longer runs.
	cas := current.InstallRevision
	if opts.ExpectedRevision != nil {
		cas = *opts.ExpectedRevision
	}
	switching := current.Name != name
	keeps := current.Installed && !switching && current.Version == version
	if p.fork != nil {
		if err := s.checkForkInstall(userID, p); err != nil {
			return nil, err
		}
		// A deprecated base keeps the fork the account runs, in any of
		// its versions: they all narrow the same base.
		keeps = current.Installed && !switching
	} else if opts.SelfService && !keeps {
		meta := p.entry.Definition.Metadata
		if meta.Visibility != "public" || meta.Status == "draft" {
			return nil, fail(KindNotFound, "unknown assistant "+ref)
		}
	}
	// A deprecated version stays with the accounts that installed it; it
	// is not offered to new ones. A never-installed profile names
	// hr-recruiter@0.1.0 only through the column defaults, which is not an
	// install of it.
	if p.lifecycle == db.AssistantLifecycleDeprecated && !keeps {
		return nil, fail(KindLifecycle, "assistant "+ref+" is deprecated: only an account already running it may reinstall it")
	}
	r := p.resolved
	installedAt := s.now()
	digest := p.entry.Digest
	document := p.document
	ownerProfile := p.ownerProfile
	update := db.AgentProfileUpdate{
		Mode:                    &r.Mode,
		AutopilotPaused:         &r.AutopilotPaused,
		ListenerEnabled:         &r.ListenerEnabled,
		DisclosureText:          &r.DisclosureText,
		DisclosureDisabled:      &r.DisclosureDisabled,
		MaxAutonomousTurns:      &r.MaxAutonomousTurns,
		MaxMsgsPerMinute:        &r.MaxMsgsPerMinute,
		MaxReplyChars:           &r.MaxReplyChars,
		IntentAllowlist:         &r.IntentAllowlist,
		IntentDenylist:          &r.IntentDenylist,
		WorkingHours:            &r.WorkingHours,
		AudienceExcludes:        &r.AudienceExcludes,
		BumpInstallRevision:     true,
		ExpectedInstallRevision: &cas,
		AssistantDigest:         &digest,
		BlockedSenders:          &r.BlockedSenders,
		SenderAllowlist:         &r.SenderAllowlist,
		AssistantName:           &name,
		AssistantVersion:        &version,
		InstallDocument:         &document,
		OwnerProfileDocument:    &ownerProfile,
	}
	// A new assistant's new chats start at the switch; a reinstall of the
	// same one keeps its first install moment.
	if switching {
		update.ResetInstalledAt = &installedAt
	} else {
		update.MarkInstalledAt = &installedAt
	}
	change, rerr := s.Managed.DecideRuntime(current.Runtime, r.Runtime, p.consent, s.now())
	if rerr != nil {
		return nil, rerr
	}
	change.Apply(&update)
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	switch {
	case p.fork != nil:
		// The base's snapshot goes with the install, so a claim checks the
		// base's lifecycle without the registry.
		var base *db.AssistantDefinition
		if s.Registry != nil {
			b := p.fork.base
			base = &db.AssistantDefinition{
				Digest: b.Digest, Name: b.Definition.Metadata.Name, Version: b.Definition.Metadata.Version,
				Document: b.Materialized, Lifecycle: p.lifecycle,
			}
		}
		err = s.Store.InstallAgentFork(ctx, userID, digest, base, update)
	case s.Registry != nil:
		err = s.Store.InstallAgentAssistant(ctx, userID, db.AssistantDefinition{
			Digest: digest, Name: name, Version: version,
			Document: p.entry.Materialized, Lifecycle: p.lifecycle,
		}, update)
	default:
		err = s.Store.UpdateAgentProfileFields(ctx, userID, update)
	}
	var rc *db.InstallRevisionConflict
	if errors.As(err, &rc) {
		return nil, conflict(rc.Current)
	}
	if errors.Is(err, db.ErrManagedQuota) {
		return nil, fail(KindManagedQuota, "no managed capacity is available right now")
	}
	if errors.Is(err, db.ErrAssistantForkNotFound) {
		return nil, fail(KindNotFound, "unknown assistant "+ref)
	}
	if err != nil {
		return nil, internal(MsgSaveFailed, err)
	}
	if change.Changed || change.Consented {
		s.AuditRuntime(ctx, userID, change)
	}
	// Cleanup only: the revision check already keeps these from acting,
	// so the install stands if this fails. Drafts awaiting approval are
	// left for /mctl approve, which tells the owner why it refuses them.
	res := &Result{Name: name, Version: version}
	if _, err := s.Store.DenyActionsFromEarlierInstalls(ctx, userID, policy.ReasonInstallChanged); err != nil {
		res.CleanupErr = err
	}
	if res.Profile, err = s.Store.GetAgentProfile(ctx, userID); err != nil {
		return nil, internal("failed to load saved profile", err)
	}
	return res, nil
}

// AuditRuntime writes the audit row of a runtime change or consent refresh:
// the runtimes and the consent version, never message content or install
// values. Like every audit write it is non-fatal.
func (s *Service) AuditRuntime(ctx context.Context, userID int64, c RuntimeChange) {
	consent := "none"
	if c.ConsentVersion != nil {
		consent = *c.ConsentVersion
	}
	to := c.To
	if to == "" {
		to = c.From
	}
	s.Store.LogToolCall(ctx, db.ToolCall{
		UserID: userID, Tool: "assistant.runtime", Status: "ok",
		Reason: c.From + "->" + to + " consent=" + consent,
	})
}

func conflict(current int64) *Error {
	return &Error{
		Kind:            KindRevisionConflict,
		Msg:             "install revision conflict: the install is at revision " + strconv.FormatInt(current, 10),
		CurrentRevision: current,
	}
}

// Apply prepares and commits raw for userID, which may install one of its
// own forks.
func (s *Service) Apply(ctx context.Context, userID int64, raw json.RawMessage, opts CommitOptions) (*Result, error) {
	p, err := s.prepare(ctx, userID, raw)
	if err != nil {
		return nil, err
	}
	return s.Commit(ctx, userID, p, opts)
}

// Patch applies an RFC 7396 JSON merge patch to the spec of userID's
// stored install and commits the result as a whole new install, if the
// install is still at expected. The stored install is decrypted here, so
// the caller never reads back private values to change one setting. A
// patch that leaves an invalid install, or arrives at another revision,
// changes nothing.
func (s *Service) Patch(ctx context.Context, userID int64, patch json.RawMessage, expected int64) (*Result, error) {
	return s.PatchWithConsent(ctx, userID, patch, expected, "")
}

// PatchWithConsent is Patch with the managed-data-flow consent asserted by
// this call, outside the merge patch. A consent inside the patch is also
// honoured; the top-level one wins.
func (s *Service) PatchWithConsent(ctx context.Context, userID int64, patch json.RawMessage, expected int64, consent string) (*Result, error) {
	var patchObj map[string]any
	if err := json.Unmarshal(patch, &patchObj); err != nil || patchObj == nil {
		return nil, fail(KindInvalid, "patch must be a JSON object")
	}
	current, err := s.Store.GetAgentAssistant(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		return nil, fail(KindNoInstall, "no assistant is installed on this account: install one first")
	}
	if err != nil {
		return nil, internal("failed to load current install", err)
	}
	if len(current.Install) == 0 {
		return nil, fail(KindNoInstall, "no assistant is installed on this account: install one first")
	}
	if current.InstallRevision != expected {
		return nil, conflict(current.InstallRevision)
	}
	var doc map[string]any
	if err := json.Unmarshal(current.Install, &doc); err != nil {
		return nil, internal("stored install does not decode", errors.New("stored install is not a JSON object"))
	}
	spec, _ := doc["spec"].(map[string]any)
	merged, _ := mergePatch(spec, patchObj).(map[string]any)
	if merged == nil {
		return nil, fail(KindInvalid, "patch must leave a spec object")
	}
	if consent != "" {
		merged["consent"] = consent
	}
	doc["spec"] = merged
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, internal("failed to encode patched install", err)
	}
	return s.Apply(ctx, userID, raw, CommitOptions{ExpectedRevision: &expected, SelfService: true})
}

// mergePatch is RFC 7396: an object patch merges member by member, a null
// member removes the target's member, and anything else replaces the
// target outright.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	out := make(map[string]any, len(t))
	for k, v := range t {
		out[k] = v
	}
	for k, v := range p {
		if v == nil {
			delete(out, k)
			continue
		}
		out[k] = mergePatch(out[k], v)
	}
	return out
}

// CatalogEntry is one installable assistant version as the catalog tools
// show it: what a user needs to choose and fill an install, and nothing
// else. No instructions, tools, owner or profile paths.
type CatalogEntry struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Examples    []string          `json:"examples"`
	Lifecycle   string            `json:"lifecycle"`
	Variables   []CatalogVariable `json:"variables"`
	Intents     []CatalogIntent   `json:"intents"`
	Defaults    CatalogDefaults   `json:"defaults"`
}

// CatalogVariable is one value an install supplies.
type CatalogVariable struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required"`
	Default     any      `json:"default,omitempty"`
	Choices     []string `json:"choices,omitempty"`
	Description string   `json:"description"`
}

// CatalogIntent is one reply intent, by which an install's intentTiers
// are keyed.
type CatalogIntent struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Tier        string `json:"tier"`
}

// CatalogDefaults are what an install that sets nothing gets.
type CatalogDefaults struct {
	Mode             string            `json:"mode"`
	Limits           *assistant.Limits `json:"limits,omitempty"`
	DisclosurePolicy string            `json:"disclosure_policy"`
}

// Catalog sources.
const (
	SourceRegistry = "registry"
	SourceEmbedded = "embedded"
)

// ListCatalog returns the installable catalog and where it came from: the
// registry's public catalog when a registry is configured, else the public,
// non-draft entries of the embedded catalog. A registry that cannot be read
// is an *Error of KindUnavailable or KindUpstream, never an empty list.
func (s *Service) ListCatalog(ctx context.Context) (string, []CatalogEntry, error) {
	if s.Registry == nil {
		var out []CatalogEntry
		for _, e := range s.Catalog.Entries() {
			m := e.Definition.Metadata
			if m.Visibility != "public" || m.Status == "draft" {
				continue
			}
			out = append(out, embeddedEntry(e.Definition))
		}
		sortCatalog(out)
		return SourceEmbedded, out, nil
	}
	items, err := s.Registry.ListCatalog(ctx)
	switch {
	case errors.Is(err, assistantregistry.ErrInvalid):
		return "", nil, &Error{Kind: KindUpstream, Msg: "assistant registry returned an invalid catalog", Err: err}
	case err != nil:
		return "", nil, &Error{Kind: KindUnavailable, Msg: "assistant registry unavailable", Err: err}
	}
	out := make([]CatalogEntry, 0, len(items))
	for _, it := range items {
		out = append(out, registryEntry(it))
	}
	sortCatalog(out)
	return SourceRegistry, out, nil
}

func embeddedEntry(d *assistant.Definition) CatalogEntry {
	e := CatalogEntry{
		Name: d.Metadata.Name, Version: d.Metadata.Version,
		Title: d.Metadata.Title, Description: d.Metadata.Description,
		Tags:      nonNil(d.Metadata.Tags),
		Examples:  nonNil(d.Metadata.Examples),
		Lifecycle: db.AssistantLifecyclePublished,
		Variables: make([]CatalogVariable, 0, len(d.Spec.Variables)),
		Intents:   make([]CatalogIntent, 0, len(d.Spec.Intents)),
		Defaults: CatalogDefaults{
			Mode:             d.Spec.Defaults.Mode,
			DisclosurePolicy: d.Spec.Defaults.Disclosure.Policy,
		},
	}
	limits := d.Spec.Defaults.Limits
	e.Defaults.Limits = &limits
	for _, v := range d.Spec.Variables {
		e.Variables = append(e.Variables, CatalogVariable{
			Name: v.Name, Type: v.Type, Required: v.Required,
			Choices: v.Choices, Description: v.Description,
		})
	}
	for _, in := range d.Spec.Intents {
		e.Intents = append(e.Intents, CatalogIntent{Name: in.Name, Description: in.Description, Tier: string(in.Tier)})
	}
	return e
}

func registryEntry(it assistantregistry.CatalogEntry) CatalogEntry {
	e := CatalogEntry{
		Name: it.Name, Version: it.Version, Title: it.Title, Description: it.Description,
		Tags: nonNil(it.Tags), Examples: nonNil(it.Examples), Lifecycle: it.Lifecycle,
		Variables: make([]CatalogVariable, 0, len(it.Variables)),
		Intents:   make([]CatalogIntent, 0, len(it.Intents)),
		Defaults: CatalogDefaults{
			Mode: it.Defaults.Mode, Limits: it.Defaults.Limits,
			DisclosurePolicy: it.Defaults.Disclosure.Policy,
		},
	}
	for _, v := range it.Variables {
		cv := CatalogVariable{
			Name: v.Name, Type: v.Type, Required: v.Required,
			Choices: v.Choices, Description: v.Description,
		}
		// The registry already leaves out a secret variable's default.
		if len(v.Default) > 0 {
			var d any
			if json.Unmarshal(v.Default, &d) == nil {
				cv.Default = d
			}
		}
		e.Variables = append(e.Variables, cv)
	}
	for _, in := range it.Intents {
		e.Intents = append(e.Intents, CatalogIntent{Name: in.Name, Description: in.Description, Tier: in.Tier})
	}
	return e
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// sortCatalog orders entries by name, then by version, highest first.
func sortCatalog(es []CatalogEntry) {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].Name != es[j].Name {
			return es[i].Name < es[j].Name
		}
		return versionLess(es[j].Version, es[i].Version)
	})
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, errx := strconv.Atoi(pa[i])
		y, erry := strconv.Atoi(pb[i])
		if errx != nil || erry != nil {
			return a < b
		}
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

// Installed is what an account runs, without the install itself.
type Installed struct {
	// Assistant and Version are "" when the account has no agent profile.
	Assistant       string
	Version         string
	InstallRevision int64
	// Installed is false for a profile that only carries the column
	// defaults and was never configured through an install.
	Installed bool
	// Runtime is "own" or "managed"; ManagedReconsentRequired is set for a
	// managed account whose stored consent is not the current version.
	Runtime                  string
	ManagedReconsentRequired bool
}

// firstInstallRevision is the revision a new agent profile starts at
// (the install_revision column default).
const firstInstallRevision = 1

// Settings is what an install resolved to: the settings the agent runs
// with, never the values or notes they were derived from. The MCP tools
// answer it and the manage page shows it.
type Settings struct {
	Mode                string   `json:"mode"`
	Paused              bool     `json:"paused"`
	Listening           bool     `json:"listening"`
	DisclosureEnabled   bool     `json:"disclosure_enabled"`
	DisclosureText      string   `json:"disclosure_text"`
	MaxAutonomousTurns  int      `json:"max_autonomous_turns"`
	MaxMsgsPerMinute    int      `json:"max_msgs_per_minute"`
	MaxReplyChars       int      `json:"max_reply_chars"`
	AutoIntents         []string `json:"auto_intents"`
	NeverIntents        []string `json:"never_intents"`
	WorkingHours        string   `json:"working_hours"`
	AudienceExcludes    []string `json:"audience_excludes"`
	OnlySendersCount    int      `json:"only_senders_count"`
	BlockedSendersCount int      `json:"blocked_senders_count"`
	Runtime             string   `json:"runtime"`
	// ManagedReconsentRequired: managed, and consented to an older version.
	ManagedReconsentRequired bool `json:"managed_reconsent_required"`
}

// SettingsOf summarizes a saved profile.
func SettingsOf(p *db.AgentProfile) Settings {
	return Settings{
		Mode: p.Mode, Paused: p.AutopilotPaused, Listening: p.ListenerEnabled,
		DisclosureEnabled: !p.DisclosureDisabled, DisclosureText: p.DisclosureText,
		MaxAutonomousTurns: p.MaxAutonomousTurns, MaxMsgsPerMinute: p.MaxMsgsPerMinute,
		MaxReplyChars: p.MaxReplyChars,
		AutoIntents:   csvList(p.IntentAllowlist), NeverIntents: csvList(p.IntentDenylist),
		WorkingHours: p.WorkingHours, AudienceExcludes: csvList(p.AudienceExcludes),
		OnlySendersCount: len(csvList(p.SenderAllowlist)), BlockedSendersCount: len(csvList(p.BlockedSenders)),
		Runtime: runtimeOrOwn(p.Runtime), ManagedReconsentRequired: p.NeedsManagedReconsent(),
	}
}

func runtimeOrOwn(r string) string {
	if r == "" {
		return db.RuntimeOwn
	}
	return r
}

func csvList(s string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, ",")
}

// CurrentSettings reads the settings userID's profile resolved to, or nil
// when the account has no agent profile.
func (s *Service) CurrentSettings(ctx context.Context, userID int64) (*Settings, error) {
	p, err := s.Store.GetAgentProfile(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, internal("failed to load agent profile", fmt.Errorf("agent profile: %w", err))
	}
	st := SettingsOf(p)
	return &st, nil
}

// AuditText is the audit text of a failed call: the error kind, never the
// message, which for a validation error names variables.
func AuditText(err error) string {
	var ie *Error
	if !errors.As(err, &ie) {
		return "internal error"
	}
	switch ie.Kind {
	case KindInvalid:
		return "invalid install"
	case KindNotFound:
		return "assistant not found"
	case KindLifecycle:
		return "lifecycle refused"
	case KindRevisionConflict:
		return "install revision conflict"
	case KindNoInstall:
		return "no install"
	case KindUpstream:
		return "registry returned an invalid answer"
	case KindUnavailable:
		return "registry unavailable"
	case KindForkLimit:
		return "fork limit"
	case KindForkInUse:
		return "fork in use"
	case KindForkConflict:
		return "fork conflict"
	case KindForksDisabled:
		return "forks disabled"
	case KindManagedConsentRequired:
		return "managed consent required"
	case KindManagedDisabled:
		return "managed disabled"
	case KindManagedQuota:
		return "managed quota"
	}
	return "internal error"
}

// Current reads what userID runs. An account with no agent profile has
// nothing installed and reports the revision its profile will start at, so
// a client that passes it back as expected_revision succeeds.
func (s *Service) Current(ctx context.Context, userID int64) (*Installed, error) {
	ref, err := s.Store.GetAgentAssistantRef(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		return &Installed{InstallRevision: firstInstallRevision}, nil
	}
	if err != nil {
		return nil, internal("failed to load current assistant", fmt.Errorf("current assistant: %w", err))
	}
	return &Installed{Assistant: ref.Name, Version: ref.Version, InstallRevision: ref.InstallRevision, Installed: ref.Installed,
		Runtime:                  runtimeOrOwn(ref.Runtime),
		ManagedReconsentRequired: ref.Runtime == db.RuntimeManaged && ref.ManagedConsentVersion != db.ManagedConsentCurrent}, nil
}
