package agentworker

func init() {
	// OpenAIRunner maps an exhausted provider retry loop to
	// error_provider_429. Keep the existing CheckResult/metrics path shared
	// with Claude by teaching the common subtype classifier this token.
	usageLimitSubtypes = append(usageLimitSubtypes, "provider_429")
}
