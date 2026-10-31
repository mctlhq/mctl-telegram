#!/bin/bash
# Install the self-update timer for the off-cluster agent worker.
#
# Run on the worker host, from a checkout of this repository or with this
# directory copied over. It copies self-update.sh into $BASE and loads a
# LaunchAgent that runs it every 10 minutes and at login. The worker itself
# (com.mctl.agent-worker, run-worker.sh, tokens in ~/.config/agent-worker) is
# set up separately and is not touched here.
#
# Prerequisites: git, curl, and Go at $HOME/.local/go (the official
# darwin archive; the build switches toolchains itself via GOTOOLCHAIN=auto).
set -euo pipefail

BASE="${AGENT_WORKER_BASE:-$HOME/agent-worker}"
LABEL="com.mctl.agent-worker-update"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HERE="$(cd "$(dirname "$0")" && pwd)"

[ -d "$BASE" ] || { echo "$BASE does not exist; set up the worker first" >&2; exit 1; }
[ -x "$HOME/.local/go/bin/go" ] || { echo "Go not found at $HOME/.local/go" >&2; exit 1; }
bash -n "$HERE/self-update.sh"
install -m 755 "$HERE/self-update.sh" "$BASE/self-update.sh"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$BASE/self-update.sh</string></array>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>StartInterval</key><integer>600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/$LABEL.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/$LABEL.log</string>
</dict>
</plist>
PLIST

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "loaded $LABEL; log: $HOME/Library/Logs/$LABEL.log"
