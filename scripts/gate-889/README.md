# Gate #889, Part B evidence tooling

Used by `docs/plans/gate-889-managed-soak.md`. Everything here reads; nothing
changes the cluster or the database. No identifier, handle or message body is
collected or committed.

| File | Purpose |
|---|---|
| `criteria.sql` | Detectors for criteria 3 to 11. Each row is `id value verdict`, verdict `green`, `red`, `unknown` or `info`. `unknown` is never green. Needs psql variables `ws` and `we`. |
| `mutations.py` | Proves each detector both ways against a throwaway schema-only database. Rows are synthetic and every run is rolled back. |
| `sampler.sh` | Takes a sample every 5 minutes and saves logs, route reasons, and detector output. |
| `sampler_test.sh` | Offline test of the sampler against a fake kubectl. Runs in CI. |

## Proving the detectors

```sh
pg_dump --schema-only <preview database> > schema.sql   # no data
# Load it into an empty local database on 127.0.0.1:15544, database scratch,
# dropping NOT NULL on non-key columns so that a mutation can plant partial rows.
python3 -I scripts/gate-889/mutations.py scripts/gate-889/criteria.sql
```

The script prints `caught` or `SURVIVED` per mutation and exits non-zero if a
mutation survives or the converged window is not green.

## Running the sampler

The evidence directory stays outside any repository, because logs are private
data. `GATE889_DIR` must be set; there is no default.

```sh
export GATE889_DIR=... GATE889_WS=2030-06-15T00:00:00Z GATE889_WE=2030-06-18T00:00:00Z
scripts/gate-889/sampler.sh pin    # record images, pod templates and pod names under test
scripts/gate-889/sampler.sh once   # a dry run; exit 0 only if every collector worked
scripts/gate-889/sampler.sh loop
```

| Output | Meaning |
|---|---|
| `samples/<ts>.txt` | One file per sample. `COLLECT_ERROR` marks a read that failed or returned nothing. |
| `ticks.log` | One line per sample with its error count. Gaps are computed from it. |
| `errors.log` | Every collection error. |
| `alerts.log` | Gaps over 15 minutes, restarts, replaced pods, image or pod template changes, a listening account with sending on, red detectors, managed jobs routed as `worker_unclaimed`. `c5_coalesced_turns` is left out because it stays red until the third burst; it is judged at the end of the window. |
| `route-reasons.log` | `job_id runtime reason` for routed jobs in the window, saved while `event_outbox` still holds them; `unobserved` when it does not. |
| `logs/` | Server and worker logs since the last sample; `*.previous.*` after a restart. A failed fetch keeps the cursor, so lines can repeat: remove duplicates at analysis. |

A sample with `COLLECT_ERROR` is not evidence of anything. Any gap over 15 minutes
makes the dependent criteria INCONCLUSIVE, never PASS.
