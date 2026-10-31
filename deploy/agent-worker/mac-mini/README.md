# Agent worker on a Mac host: self-update

The communication agent worker (`cmd/agent-worker`) runs off-cluster on a
Mac (LaunchAgent `com.mctl.agent-worker`) and talks to tg-preview's
`/api/agent/v1`. It must run the same commit as the server, with the system
prompt from that commit.

`self-update.sh` keeps it there without anyone remembering to redeploy. A
LaunchAgent (`com.mctl.agent-worker-update`, installed by `install.sh`) runs
it every 10 minutes:

1. Read the image tag tg-preview runs from mctl-gitops (public; no token).
   A failed or unparsable read changes nothing and logs an error.
2. If the installed commit (`~/agent-worker/VERSION`) or the installed
   prompt's sha256 differ from that commit, build the worker at that commit
   and install the binary and `deploy/agent-worker/system-prompt.txt` from
   the same commit.
3. Restart the worker and wait for `/readyz`. If it does not answer 200,
   restore both the previous binary and prompt.
4. On success, take `self-update.sh` itself from the same commit for the
   next run.

A prompt edited by hand on the host is replaced by the commit's version on
the next run: the prompt is canonical in this repository.

## Operations

| Task | Command (on the host) |
|---|---|
| Install or reinstall the timer | `deploy/agent-worker/mac-mini/install.sh` |
| What runs now | `cat ~/agent-worker/VERSION; shasum -a 256 ~/agent-worker/system-prompt.txt` |
| Update log | `tail ~/Library/Logs/com.mctl.agent-worker-update.log` |
| Run once now | `bash ~/agent-worker/self-update.sh` (add `--dry-run` to build only) |
| Hold or roll back to a commit | `echo <sha> > ~/agent-worker/PIN` (the next run installs it) |
| Follow tg-preview again | `rm ~/agent-worker/PIN` |
| Stop updating | `launchctl bootout gui/$(id -u)/com.mctl.agent-worker-update` |

Prerequisites: git, curl and Go at `~/.local/go` (the official darwin
archive from go.dev, checksum-verified). The source clone lives in
`~/agent-worker/src`.
