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

// FlagServers lists the catalog servers that have a linking flag.
func FlagServers() []connection.Server {
	return []connection.Server{connection.ServerTG, connection.ServerAlice}
}

// ServerFlag reads one server's linking flag: missing or empty is off,
// "true" and "false" are themselves, anything else wraps ErrConfig, so a
// typo is an error rather than a silent on or off.
//
// alice is off unless its flag says otherwise. Its accounts are not
// Telegram identities, so the get_my_identity owner binding of S1-L13 does
// not apply to it; the owner turns the flag on only after recording
// acceptance of that residual risk (S1-L14).
func ServerFlag(getenv func(string) string, s connection.Server) (bool, error) {
	switch strings.TrimSpace(getenv(FlagEnv(s))) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%w: %s must be true or false", ErrConfig, FlagEnv(s))
	}
}
