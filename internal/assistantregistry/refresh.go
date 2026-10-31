package assistantregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	// RefreshInterval is how often every pinned version's lifecycle is read
	// again; a disabled version stops new jobs within it.
	RefreshInterval = 5 * time.Minute
	// StaleAfter is how long the last known lifecycle stands without a
	// successful read. After it the lifecycle is unknown.
	StaleAfter = 24 * time.Hour
)

// Gate is what a stored definition's lifecycle allows at a moment.
type Gate int

const (
	// GateRun: published, or deprecated and kept by an existing pin.
	GateRun Gate = iota
	// GateDisabled: the registry said disabled (or that the pinned version
	// no longer exists).
	GateDisabled
	// GateUnknown: no successful read for longer than StaleAfter. Unknown
	// is not published, so it does not run either.
	GateUnknown
)

// LifecycleGate decides whether new jobs may run on def at now.
// Staleness is checked first: a lifecycle not confirmed within StaleAfter
// is unknown whatever it last was.
func LifecycleGate(def *db.AssistantDefinition, now time.Time) Gate {
	if now.Sub(def.LifecycleCheckedAt) > StaleAfter {
		return GateUnknown
	}
	switch def.Lifecycle {
	case db.AssistantLifecyclePublished, db.AssistantLifecycleDeprecated:
		return GateRun
	default:
		return GateDisabled
	}
}

// UnreachableNotice is the owner alert sent once when an account's
// assistant stops because its lifecycle became unknown.
func UnreachableNotice(name, version string) string {
	return fmt.Sprintf("Your assistant %s@%s has stopped taking new messages: the assistant registry could not be reached for over %s, so whether this version may still run is unknown. Messages that arrive meanwhile stay queued and are answered once the registry is reachable again.",
		name, version, "24 hours")
}

// NotifyUnreachable queues UnreachableNotice for every listening account
// pinned to def, once per outage (db.NotifyAssistantRegistryUnreachable).
func NotifyUnreachable(ctx context.Context, store *db.Store, def *db.AssistantDefinition) {
	users, err := store.ListListeningUsersPinnedTo(ctx, def.Digest)
	if err != nil {
		slog.Warn("assistant registry: list pinned accounts failed", "digest", def.Digest, "err", err)
		return
	}
	for _, uid := range users {
		NotifyUserUnreachable(ctx, store, uid, def)
	}
}

// NotifyUserUnreachable queues UnreachableNotice for one account, once per
// outage.
func NotifyUserUnreachable(ctx context.Context, store *db.Store, userID int64, def *db.AssistantDefinition) {
	sent, err := store.NotifyAssistantRegistryUnreachable(ctx, userID, def.Digest, def.LifecycleCheckedAt,
		UnreachableNotice(def.Name, def.Version))
	if err != nil {
		slog.Warn("assistant registry: queue owner notice failed", "user_id", userID, "err", err)
		return
	}
	if sent {
		slog.Warn("assistant registry: lifecycle unknown, owner notified",
			"user_id", userID, "assistant", def.Name+"@"+def.Version, "last_checked_at", def.LifecycleCheckedAt)
	}
}

// Refresher re-reads the lifecycle of every pinned definition.
type Refresher struct {
	Store  *db.Store
	Client *Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (r *Refresher) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Run refreshes at once and then every interval until ctx ends.
func (r *Refresher) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		r.RefreshOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshOnce reads each pinned name@version once. A registry answer
// (a lifecycle, or 404 assistant_not_found, recorded as disabled) is
// stored with the time it was read. Anything else is a failed read: it
// leaves the last known lifecycle and its check time as they were, so it
// can only age into unknown, never turn a known lifecycle into another
// one. Definitions whose lifecycle has aged past StaleAfter get their
// owners notified.
func (r *Refresher) RefreshOnce(ctx context.Context) {
	defs, err := r.Store.ListPinnedAssistantDefinitions(ctx)
	if err != nil {
		slog.Warn("assistant registry: list pinned definitions failed", "err", err)
		return
	}
	// Registry lifecycles belong to name@version; read each once even if
	// several digests were stored under it.
	type answer struct {
		lifecycle string
		err       error
	}
	seen := map[string]answer{}
	for i := range defs {
		def := &defs[i]
		key := def.Name + "@" + def.Version
		a, ok := seen[key]
		if !ok {
			got, ferr := r.Client.Fetch(ctx, def.Name, def.Version)
			switch {
			case ferr == nil:
				a = answer{lifecycle: got.Lifecycle}
				if got.Entry.Digest != def.Digest {
					// Only a draft may change under its version. The pin
					// keeps its own document; the lifecycle still belongs
					// to the version.
					slog.Info("assistant registry: content under a pinned version changed",
						"assistant", key, "pinned", def.Digest, "registry", got.Entry.Digest)
				}
			case errors.Is(ferr, ErrNotFound):
				a = answer{lifecycle: db.AssistantLifecycleDisabled}
			default:
				a = answer{err: ferr}
			}
			seen[key] = a
		}
		if a.err != nil {
			slog.Warn("assistant registry: lifecycle refresh failed", "assistant", key, "err", a.err)
		} else {
			checked := r.now().UTC().Truncate(time.Microsecond)
			if err := r.Store.SetAssistantDefinitionLifecycle(ctx, def.Digest, a.lifecycle, checked); err != nil {
				slog.Warn("assistant registry: store lifecycle failed", "assistant", key, "err", err)
			} else {
				def.Lifecycle, def.LifecycleCheckedAt = a.lifecycle, checked
			}
		}
		if LifecycleGate(def, r.now()) == GateUnknown {
			NotifyUnreachable(ctx, r.Store, def)
		}
	}
}
