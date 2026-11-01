package audit

// Keep the OpenAI-compatible runner's credentials covered by the same
// structured slog redaction map as every other bearer/secret. These names
// match both env-style keys after lower-casing and the explicit header key.
func init() {
	sensitiveKeys["agent_openai_api_key"] = struct{}{}
	sensitiveKeys["agent_gateway_token"] = struct{}{}
	sensitiveKeys["cf-aig-authorization"] = struct{}{}
}
