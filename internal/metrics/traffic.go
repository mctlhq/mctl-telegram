package metrics

import "context"

// Traffic classes for the `traffic` label on the two series the user-facing
// SLIs read: mctl_tool_invocations_total and mctl_sessions_borrow_total
// (mctl-telegram#974).
//
// The monitoring canary is a synthetic probe with its own alert
// (MctlTelegramCanaryFailing). Counted as user traffic it made up about a
// third of the 28-day denominator: its outages paged a second time through
// the SLO burn alerts, and its successes flattered the SLI whenever real
// traffic was degraded. The label lets the SLI rules select
// traffic!="canary".
//
// The set is closed and server-side: the class comes from CANARY_TELEGRAM_IDS
// (config), never from anything the caller sends, so the label cannot be
// used to move a call out of the SLI and its cardinality is fixed at two.
const (
	// TrafficUser is every call not made as a canary account, and the
	// default whenever the class is unknown. A call the server cannot place
	// stays inside the SLI.
	TrafficUser = "user"
	// TrafficCanary is a call made as one of the CANARY_TELEGRAM_IDS
	// accounts.
	TrafficCanary = "canary"
)

type trafficCtxKey struct{}

// WithTraffic returns ctx carrying the traffic class for the metrics recorded
// while serving it. Only TrafficCanary is stored as such; any other value is
// recorded as TrafficUser.
func WithTraffic(ctx context.Context, class string) context.Context {
	if class != TrafficCanary {
		class = TrafficUser
	}
	return context.WithValue(ctx, trafficCtxKey{}, class)
}

// TrafficFrom returns the traffic class carried by ctx, or TrafficUser when
// ctx carries none: background work (the executor, the agent listener) and
// any path that never set a class count as user traffic.
func TrafficFrom(ctx context.Context) string {
	if ctx == nil {
		return TrafficUser
	}
	if class, ok := ctx.Value(trafficCtxKey{}).(string); ok && class == TrafficCanary {
		return TrafficCanary
	}
	return TrafficUser
}
