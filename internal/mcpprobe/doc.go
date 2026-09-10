// Package mcpprobe measures what an MCP endpoint actually does, so that
// compatibility claims about it rest on evidence rather than on the version
// of a dependency or the shape of a configuration file.
//
// It exists for one question: can this server be driven over the modern
// stateless MCP 2026-07-28 path, and what happens on the legacy path that
// existing clients still use? Those two are probed as separate modes with
// separate results. A modern run never quietly retries as a legacy one — a
// silent downgrade reported as success is exactly the failure this package
// is meant to make impossible.
//
// Everything it emits is safe to paste into an issue. The report model
// carries labels, protocol versions, status and error codes, capability
// names, annotation booleans and lengths. It cannot carry a token, an
// authorization code, a session identifier, a message body or any value a
// tool returned, because no field of Report has a type those could be
// assigned to. Redaction here is a property of the type, not a discipline
// applied at each call site.
//
// The single tool invocation a run performs is guarded structurally: the
// tool must be present in tools/list and must be annotated read-only, or
// the step is skipped and says so.
package mcpprobe
