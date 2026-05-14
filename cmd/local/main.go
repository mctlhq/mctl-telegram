// Command mctl-telegram-local is the Local Bridge daemon (M4).
//
// In Local Bridge mode the MTProto session lives on the user's
// machine; tg.mctl.ai is reduced to a relay that forwards MCP tool
// calls down to this daemon and shuttles responses back. The server
// never sees the user's session bytes.
//
// This is a scaffolding commit — the subcommands print informational
// stubs. The full implementation (config init, interactive Telegram
// login, OAuth-with-mctl-api, persistent websocket loop, MCP-call
// dispatcher) is tracked under internal/bridge/DESIGN.md.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-scaffolding"

const usage = `mctl-telegram-local — Local Bridge daemon for mctl-telegram

Usage:
  mctl-telegram-local <subcommand> [args]

Subcommands:
  init       Create ~/.config/mctl-telegram-local/config.json with TG api_id/api_hash + passphrase.
  login      Interactive Telegram login (phone, SMS code, optional 2FA).
  connect    Open a browser to api.mctl.ai for GitHub OAuth and start the daemon loop.
  daemon     Long-running daemon: holds the websocket to tg.mctl.ai/bridge.
  version    Print the daemon version.
  help       Show this message.

Status: this binary is M4 scaffolding. The init / login / connect /
daemon subcommands print a TODO message and exit non-zero. The
server-side hub (internal/bridge) is wired but not yet exposed via a
websocket transport. See internal/bridge/DESIGN.md for the remaining
work checklist before this binary is production-usable.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "init", "login", "connect", "daemon":
		fmt.Fprintf(os.Stderr,
			"mctl-telegram-local %s: subcommand %q is not implemented yet.\n"+
				"This is M4 scaffolding; see internal/bridge/DESIGN.md.\n",
			version, os.Args[1])
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
