package humaninput

import (
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// Deps are what the adapter needs from the process: the store, the mctl-api
// relay client, the Saved Messages replier, metrics and the kill switch.
type Deps struct {
	Store      *db.Store
	API        API
	Replier    Replier
	Metrics    *metrics.Registry
	GlobalKill func() bool
}

// New builds the command handler and the poller when enabled is true
// (HUMAN_INPUT_ENABLED), and nothing at all otherwise: with it false both
// results are nil, so the router keeps /mctl input as an unknown command, no
// poll goroutine can be started and no human-input request is ever sent.
func New(enabled bool, d Deps) (*Handler, *Poller) {
	if !enabled {
		return nil, nil
	}
	h := &Handler{Store: d.Store, API: d.API, Replier: d.Replier, Metrics: d.Metrics}
	p := &Poller{Store: d.Store, API: d.API, Metrics: d.Metrics, GlobalKill: d.GlobalKill}
	return h, p
}
