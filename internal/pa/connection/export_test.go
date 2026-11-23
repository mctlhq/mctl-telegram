package connection

import "context"

// RefreshFrom exposes refreshFrom to the external tests: it stands in
// for a caller that read generation from before another flight rotated it.
func (m *Manager) RefreshFrom(ctx context.Context, principal int64, id string, fn RefreshFunc, from int64) (Connection, error) {
	return m.refreshFrom(ctx, principal, id, fn, from)
}
