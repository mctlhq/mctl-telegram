// Package tools names the communication agent's MCP tools. The worker
// implements each tool once under its canonical name; an assistant
// definition may call a tool by a generic alias instead, and the worker then
// registers it under that name. Both the server (validating definitions,
// sending names with each job) and the worker (registering and allowing
// them) use this table, so the two cannot drift.
package tools

import "fmt"

// Canonical is every tool the worker implements, by canonical name.
var Canonical = []string{
	"get_event", "get_conversation_context", "get_recruiter_profile", "get_lead", "get_policy",
	"propose_reply", "save_job_lead", "request_owner_approval", "send_owner_summary",
	"pause_autopilot", "complete_agent_job",
}

// Aliases maps a generic name to the canonical tool it stands for. The
// recruiter-specific canonical names stay valid, so an existing definition
// keeps working unchanged.
var Aliases = map[string]string{
	"get_owner_profile": "get_recruiter_profile",
	"get_record":        "get_lead",
	"save_record":       "save_job_lead",
}

// Binding is one tool as a job exposes it: the name the model sees and the
// canonical tool behind it.
type Binding struct {
	Name, Canonical string
}

// Resolve maps names, each canonical or an alias, to bindings in the given
// order. It rejects an unknown name and a tool named twice (for example both
// save_job_lead and save_record). It does not require every tool; Complete
// does.
func Resolve(names []string) ([]Binding, error) {
	known := make(map[string]bool, len(Canonical))
	for _, c := range Canonical {
		known[c] = true
	}
	seen := make(map[string]string, len(names))
	out := make([]Binding, 0, len(names))
	for _, n := range names {
		c := n
		if a, ok := Aliases[n]; ok {
			c = a
		}
		if !known[c] {
			return nil, fmt.Errorf("unknown tool %q", n)
		}
		if prev, dup := seen[c]; dup {
			return nil, fmt.Errorf("tools %q and %q are the same tool", prev, n)
		}
		seen[c] = n
		out = append(out, Binding{Name: n, Canonical: c})
	}
	return out, nil
}

// Complete reports whether bindings cover every canonical tool.
func Complete(bindings []Binding) bool {
	return len(bindings) == len(Canonical)
}

// Default is every canonical tool under its own name.
func Default() []Binding {
	out := make([]Binding, len(Canonical))
	for i, c := range Canonical {
		out[i] = Binding{Name: c, Canonical: c}
	}
	return out
}
