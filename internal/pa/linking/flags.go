package linking

import (
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// FlagEnv returns the environment variable holding a server's linking flag,
// e.g. PA_SERVER_TG_ENABLED.
func FlagEnv(server connection.Server) string {
	return "PA_SERVER_" + strings.ToUpper(string(server)) + "_ENABLED"
}

// LoadServerFlags reads every catalog server's linking flag. A missing or
// empty variable is off. Only "true" and "false" are accepted, so a typo is
// a startup error rather than a silent on or off.
//
// alice is off unless its flag says otherwise. Its accounts are not
// Telegram identities, so the get_my_identity owner binding of S1-L13 does
// not apply to it; the owner turns the flag on only after recording
// acceptance of that residual risk (S1-L14).
func LoadServerFlags(getenv func(string) string) (map[connection.Server]bool, error) {
	out := map[connection.Server]bool{}
	for _, s := range []connection.Server{connection.ServerTG, connection.ServerAlice} {
		v := strings.TrimSpace(getenv(FlagEnv(s)))
		switch v {
		case "", "false":
			out[s] = false
		case "true":
			out[s] = true
		default:
			return nil, fmt.Errorf("%w: %s must be true or false", ErrConfig, FlagEnv(s))
		}
	}
	return out, nil
}
