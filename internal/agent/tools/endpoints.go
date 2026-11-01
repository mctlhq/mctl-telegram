package tools

// Endpoints maps each agent API route a worker's MCP tool calls, as
// "METHOD pattern" relative to /api/agent/v1 (agentapi.Server.Register), to
// the canonical tools it serves. The agent API refuses a request to a route
// here unless the caller's tool set holds at least one of its tools. Routes
// that serve no tool (claim, job status, cost report) are absent and not
// gated.
//
// A route may serve more than one tool. get_lead reads its conversation's
// leads through GET /conversations/{id}/leads, which returns no messages,
// so a tool set with get_lead but without get_conversation_context cannot
// read the conversation (#1043). The context route returns the leads too,
// so it serves get_conversation_context alone, and GET /leads/{id}, called
// by no tool today, returns a saved lead, which either tool may see.
var Endpoints = map[string][]string{
	"GET /event/{eventID}":                 {"get_event"},
	"GET /conversations/{id}/context":      {"get_conversation_context"},
	"GET /conversations/{id}/leads":        {"get_lead"},
	"GET /recruiters/{peer}":               {"get_recruiter_profile"},
	"GET /leads/{id}":                      {"get_lead", "get_conversation_context"},
	"GET /policy":                          {"get_policy"},
	"POST /actions/propose_reply":          {"propose_reply"},
	"POST /leads":                          {"save_job_lead"},
	"POST /actions/request_owner_approval": {"request_owner_approval"},
	"POST /notify/summary":                 {"send_owner_summary"},
	"POST /autopilot/pause":                {"pause_autopilot"},
	"POST /jobs/{id}/complete":             {"complete_agent_job"},
}
