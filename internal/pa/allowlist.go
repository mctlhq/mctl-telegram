package pa

// PrincipalAllowlist says which principals may use the PA at all (the
// preview allowlist, PA_ALLOWED_PRINCIPALS; owner decision on #1318,
// 2026-11-21). It is checked at ingress (Conversations.HandleUpdate) and
// again at every run step (RunLoop.gate), next to the admin disable.
type PrincipalAllowlist interface {
	Allowed(principal int64) bool
}

// Allowlist is a fixed set of Telegram user ids. The zero value and a nil
// *Allowlist allow nobody: an unset list is never "everyone".
type Allowlist struct {
	ids map[int64]struct{}
}

var _ PrincipalAllowlist = (*Allowlist)(nil)

// NewAllowlist builds an Allowlist of ids. Ids that are not positive are
// ignored (they name no principal).
func NewAllowlist(ids []int64) *Allowlist {
	a := &Allowlist{ids: make(map[int64]struct{}, len(ids))}
	for _, id := range ids {
		if id > 0 {
			a.ids[id] = struct{}{}
		}
	}
	return a
}

// Allowed implements PrincipalAllowlist.
func (a *Allowlist) Allowed(principal int64) bool {
	if a == nil || principal <= 0 {
		return false
	}
	_, ok := a.ids[principal]
	return ok
}

// Len is the number of allowed principals.
func (a *Allowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.ids)
}
