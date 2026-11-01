package agentworker

// Prices are list prices in USD per million tokens for one model.
type Prices struct {
	InputUSDPerMTok  float64
	OutputUSDPerMTok float64
}

func (p Prices) Cost(u ChatUsage) float64 {
	if u.PromptTokens < 0 || u.CompletionTokens < 0 {
		return 0
	}
	return (float64(u.PromptTokens)*p.InputUSDPerMTok + float64(u.CompletionTokens)*p.OutputUSDPerMTok) / 1_000_000
}
