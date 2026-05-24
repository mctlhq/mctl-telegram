package web

import "net/http"

// openAIAppsChallengeToken is the domain-verification token issued by the
// OpenAI Apps submission dashboard for this app. It is NOT a secret: OpenAI
// fetches it openly from the origin-root well-known URL to confirm we control
// tg.mctl.ai, and it grants no access on its own. The submission flow pings
// https://tg.mctl.ai/.well-known/openai-apps-challenge and expects the token
// back as plain text.
const openAIAppsChallengeToken = "0m4KRGIDeXQuTvd0yg2SuFKUbImXDEazQfriLci-X5k"

// OpenAIAppsChallenge serves the OpenAI Apps domain-verification token as plain
// text at /.well-known/openai-apps-challenge.
func OpenAIAppsChallenge() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(openAIAppsChallengeToken))
	}
}
