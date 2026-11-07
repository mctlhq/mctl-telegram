package mcp

import "testing"

// Every registered tool is classified exactly once, every classified tool is
// registered, and the hints a client sees agree with the classification.
func TestToolClasses_CoverAndAgreeWithRegistry(t *testing.T) {
	registered := fullSurfaceServer(&Server{}).ListTools()
	for name := range toolClasses {
		if _, ok := registered[name]; !ok {
			t.Errorf("%s is classified but not registered", name)
		}
	}
	for name, st := range registered {
		c, ok := toolClasses[name]
		if !ok {
			t.Errorf("%s is registered but has no class in toolClasses", name)
			continue
		}
		a := st.Tool.Annotations
		if a.ReadOnlyHint == nil || a.DestructiveHint == nil || a.IdempotentHint == nil {
			t.Errorf("%s: readOnly, destructive and idempotent hints must all be explicit", name)
			continue
		}
		wantReadOnly := c.tier == tierRead
		wantDestructive := c.tier == tierDestructive
		if *a.ReadOnlyHint != wantReadOnly || *a.DestructiveHint != wantDestructive {
			t.Errorf("%s: readOnly=%v destructive=%v, its tier wants readOnly=%v destructive=%v",
				name, *a.ReadOnlyHint, *a.DestructiveHint, wantReadOnly, wantDestructive)
		}
		if *a.IdempotentHint != c.idempotent {
			t.Errorf("%s: idempotent=%v, toolClasses says %v", name, *a.IdempotentHint, c.idempotent)
		}
		if c.idempotent && c.tier != tierRead {
			t.Errorf("%s: only reads may be marked idempotent until a write is shown to be repeat-safe", name)
		}
	}
}
