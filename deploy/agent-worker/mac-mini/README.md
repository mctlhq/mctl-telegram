# Agent worker on a Mac host: self-update

The communication agent worker (`cmd/agent-worker`) runs off-cluster on a
Mac (LaunchAgent `com.mctl.agent-worker`) and talks to one mctl-telegram
server's `/api/agent/v1`: tg-preview or production (see [Track](#track)). It
must run the same commit as that server, with the system prompt from that
commit.

`self-update.sh` keeps it there without anyone remembering to redeploy. A
LaunchAgent (`com.mctl.agent-worker-update`, installed by `install.sh`) runs
it every 10 minutes:

1. Read the image tag the tracked environment runs from mctl-gitops
   (public; no token). A failed or unparsable read changes nothing and logs
   an error.
2. If the installed commit (`~/agent-worker/VERSION`) or the installed
   prompt's sha256 differ from that commit, build the worker at that commit
   and install the binary and `deploy/agent-worker/system-prompt.txt` from
   the same commit.
3. Restart the worker and wait until a new process (a launchd PID other
   than the old one) answers `/readyz` and is still the same process 30 s
   later. Otherwise restore both the previous binary and prompt, record the
   commit in `~/agent-worker/FAILED`, and skip it until the target changes.
4. On success, take `self-update.sh` itself from the same commit for the
   next run (not while a `PIN` is set, and never a copy that predates track
   support: see below).

A lock in `~/agent-worker/.update.lock` records its owner's PID; a lock
whose owner is gone, or one older than an hour, is reclaimed.

A prompt edited by hand on the host is replaced by the commit's version on
the next run: the prompt is canonical in this repository.

## Track

`~/agent-worker/TRACK` names the environment the worker follows:

| Content | Values read from mctl-gitops | `image.tag` shape | Resolved to |
|---|---|---|---|
| missing file, or `preview` | `services/labs/mctl-telegram-preview/values.yaml` | `main-<sha>` | that commit |
| `prod` | `services/labs/mctl-telegram/values.yaml` | `x.y.z` (a release) | the commit the git tag `x.y.z` points at |

Any other content (including an empty file) is an error: the run logs it
and changes nothing. There is no default other than the missing file.

The worker must run the same commit as the server it talks to, so the track
and the server address have to agree: `AGENT_API_BASE_URL` in `run-worker.sh`
points at the preview server on the `preview` track and at the production
server on the `prod` track. Switch both, then restart the worker:

```sh
echo prod > ~/agent-worker/TRACK      # or: rm ~/agent-worker/TRACK  (back to preview)
# edit AGENT_API_BASE_URL in run-worker.sh to the same environment
bash ~/agent-worker/self-update.sh    # or wait for the next timer run
```

The update log names the track and the tag it resolved, for example
`source: prod 0.116.0 -> <sha>`. `PIN` wins over either track.

On the `prod` track the release may be older than the running script. The
script still installs the worker and prompt from that commit, but only
replaces itself with the commit's `self-update.sh` when that copy knows
about `TRACK`; otherwise it logs "target commit's self-update.sh predates
TRACK support, keeping the current script" and keeps the current one. A copy
without track support would follow tg-preview again on the next run.

## Operations

| Task | Command (on the host) |
|---|---|
| Install or reinstall the timer | `deploy/agent-worker/mac-mini/install.sh` |
| What runs now | `cat ~/agent-worker/VERSION; shasum -a 256 ~/agent-worker/system-prompt.txt` |
| Update log | `tail ~/Library/Logs/com.mctl.agent-worker-update.log` |
| Run once now | `bash ~/agent-worker/self-update.sh` (add `--dry-run` to build only) |
| Hold or roll back to a commit | `echo <sha> > ~/agent-worker/PIN` (the next run installs it) |
| Follow the track again | `rm ~/agent-worker/PIN` |
| Follow production releases | `echo prod > ~/agent-worker/TRACK` (and point `AGENT_API_BASE_URL` at production) |
| Follow tg-preview | `rm ~/agent-worker/TRACK` (and point `AGENT_API_BASE_URL` at tg-preview) |
| Which track | `cat ~/agent-worker/TRACK 2>/dev/null \|\| echo preview` |
| Retry a commit that failed | `rm ~/agent-worker/FAILED` |
| Stop updating | `launchctl bootout gui/$(id -u)/com.mctl.agent-worker-update` |

Prerequisites: git, curl and Go at `~/.local/go` (the official darwin
archive from go.dev, checksum-verified). The source clone lives in
`~/agent-worker/src`.

`self-update_test.sh` exercises target resolution for both tracks offline (a
fake `curl` serves the values files, a fake `go` stands in for the build,
every run is `--dry-run`); CI runs it from `build.yml`.
