"""Prove each detector of criteria.sql both ways against a throwaway, schema-only database.

All rows are synthetic. Each mutation runs in a transaction that is rolled back.
"""
import subprocess
import sys

PSQL = ["psql", "-h", "127.0.0.1", "-p", "15544", "-U", "postgres", "-d", "scratch",
        "-X", "-q", "-A", "-t", "-F", "|",
        "-v", "ws=2026-01-01", "-v", "we=2027-01-01"]
SQL = open(sys.argv[1]).read()

JOB = ("insert into agent_jobs(id,event_id,user_id,conversation_id,status,attempts,max_attempts,"
       "next_run_at,created_at,updated_at,runtime,turn_id,claimed_at,last_error) values ")


def job(i, status="completed", rt="managed", attempts=1, turn=None, conv=None, claimed="null", err="null", age="1 hour", took="10 seconds"):
    turn = f"'{turn}'" if turn else f"'t{i}'"
    conv = conv if conv is not None else i
    return (f"({i},'e{i}',1001,{conv},'{status}',{attempts},5,now(),now()-interval '{age}',"
            f"now()-interval '{age}'+interval '{took}','{rt}',{turn},{claimed},{err})")


def jobs(*rows):
    return JOB + ",".join(rows) + ";"


def attempt(i, job_id, start, end):
    e = "null" if end is None else f"now()-interval '{end}'"
    return (f"insert into agent_job_attempts(id,job_id,attempt,started_at,finished_at,status) "
            f"values ({i},{job_id},1,now()-interval '{start}',{e},'x');")


def usage(i, job_id, status="settled", rt="managed", cost="0.02", age="1 hour"):
    return (f"insert into agent_usage(id,job_id,attempt,user_id,runtime,runner,model,input_tokens,output_tokens,"
            f"reserved_usd,cost_usd,status,created_at,updated_at) values ({i},{job_id},1,1001,'{rt}','openai','m',1,1,0.25,{cost},"
            f"'{status}',now()-interval '{age}',now());")


def action(i, typ="propose_reply", status="pending_approval", msg="null", sends=0):
    return (f"insert into agent_actions(id,user_id,action_type,status,executed_tg_message_id,send_attempts,created_at,updated_at) "
            f"values ({i},1001,'{typ}','{status}',{msg},{sends},now()-interval '1 hour',now());")


def note(i, kind="summary", status="sent", msg="1"):
    return (f"insert into owner_notifications(id,user_id,kind,status,tg_message_id,created_at) "
            f"values ({i},1001,'{kind}','{status}',{msg},now()-interval '1 hour');")


# A converged window: three coalesced turns, cheap, fast, nothing wrong.
BASE = (
    jobs(job(1, turn="a"), job(2, "coalesced", turn="a"),
         job(3, turn="b", age="50 minutes"), job(4, "coalesced", turn="b", age="50 minutes"),
         job(5, turn="c", age="40 minutes"), job(6, "coalesced", turn="c", age="40 minutes"))
    + attempt(1, 1, "60 minutes", "59 minutes") + attempt(2, 3, "50 minutes", "49 minutes") + attempt(3, 5, "40 minutes", "39 minutes")
    + usage(1, 1) + usage(2, 3) + usage(3, 5)
    + action(1) + note(1)
)

OUT = ("insert into event_outbox(id,event_id,user_id,stream,envelope,created_at) values "
       "(1,'e50',1001,'s','{{\"subject\":{{\"routing_reason\":\"{r}\"}}}}',now());")

# name: (detector expected to go red or unknown, expected verdict, planted SQL)
MUT = {
    "dead_letter": ("c3a_dead_letter", "red", jobs(job(50, "dead_letter"))),
    "stuck": ("c3b_processing_past_5m", "red", jobs(job(50, "processing", claimed="now()-interval '6 minutes'"))),
    "unclaimed": ("c3d_routed_worker_unclaimed", "red", jobs(job(50, "routed")) + OUT.format(r="worker_unclaimed")),
    "route_unobserved": ("c3e_routed_reason_unobserved", "unknown", jobs(job(50, "routed"))),
    "overlap": ("c4a_global_overlap", "red", jobs(job(50), job(51)) + attempt(50, 50, "30 minutes", "20 minutes") + attempt(51, 51, "25 minutes", "15 minutes")),
    "conv_overlap": ("c4b_conversation_overlap", "red", jobs(job(50, conv=7), job(51, conv=7)) + attempt(50, 50, "30 minutes", "20 minutes") + attempt(51, 51, "25 minutes", "15 minutes")),
    "own_claimed": ("c6a_own_jobs_claimed", "red", jobs(job(50, "pending", rt="own", attempts=1))),
    "own_attempt": ("c6b_own_attempt_rows", "red", jobs(job(50, "pending", rt="own", attempts=0)) + attempt(50, 50, "30 minutes", "20 minutes")),
    "own_usage": ("c6c_own_usage_rows", "red", jobs(job(50, "pending", rt="own", attempts=0)) + usage(50, 50, rt="own")),
    "own_status": ("c6d_own_status_outside_allowed", "red", jobs(job(50, "completed", rt="own", attempts=0))),
    "held": ("c7_usage_unsettled_past_grace", "red", jobs(job(50)) + usage(50, 50, status="held", cost="null")),
    "cost": ("c8_cost_per_completed_turn", "red", jobs(job(50)) + usage(50, 50, cost="5.0")),
    "latency": ("c9_p95_latency_s", "red", jobs(*[job(50 + n, took="10 minutes") for n in range(4)])),
    "provider": ("c10_provider_run", "red", jobs(*[job(50 + n, "failed", err="'error_provider_429'", age=f"{20 + n} minutes") for n in range(3)])),
    "sent_msg": ("c11a_peer_send", "red", action(50, msg="99")),
    "sent_status": ("c11a_peer_send", "red", action(50, status="delivery_unknown")),
    "sent_attempt": ("c11a_peer_send", "red", action(50, sends=1)),
    "proposed": ("c11a2_still_proposed", "unknown", action(50, status="proposed")),
    "action_unknown": ("c11b_action_delivery_unknown", "red", action(50, typ="send_owner_summary", status="delivery_unknown")),
    "note_unknown": ("c11c_notification_delivery_unknown", "red", note(50, status="delivery_unknown", msg="null")),
    "note_kind": ("c11d_notification_kind_outside_list", "red", note(50, kind="peer")),
    "note_nomsg": ("c11e_sent_without_message_id", "red", note(50, msg="null")),
}


def run(planted):
    script = "begin; set local session_replication_role = replica;\n" + planted + "\n" + SQL + "\nrollback;\n"
    p = subprocess.run(PSQL, input=script, text=True, capture_output=True)
    if p.returncode or "ERROR" in p.stderr:
        sys.exit("psql failed:\n" + p.stderr)
    out = {}
    for line in p.stdout.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            out[parts[0]] = (parts[1], parts[2])
    return out


base = run(BASE)
bad = {k: v for k, v in base.items() if v[1] not in ("green", "info")}
print("converged window:", "all green" if not bad else bad)
empty = run("")
print("empty window, not green:", {k: v[1] for k, v in empty.items() if v[1] == "unknown"})
fails = 0 if not bad else 1
for name, (det, want, planted) in MUT.items():
    got = run(BASE + planted).get(det, ("?", "missing"))
    # Only the named detector is asserted; a planted row may also move others.
    ok = got[1] == want
    fails += not ok
    print(f"{'caught' if ok else 'SURVIVED':8} {name:18} {det} = {got[0]} {got[1]}")
# Below the minimum: only two coalesced turns.
two = jobs(job(1, turn="a"), job(2, "coalesced", turn="a"), job(3, turn="b"), job(4, "coalesced", turn="b")) + usage(1, 1)
got = run(two).get("c5_coalesced_turns")
ok = got[1] == "red"; fails += not ok
print("caught  " if ok else "SURVIVED", "two_turns", got)
# A provider run broken by a success is not a run of 3: must stay green.
mix = BASE + jobs(job(50, "failed", err="'error_provider'", age="30 minutes"), job(51, "failed", err="'error_provider'", age="29 minutes"),
                  job(52, age="28 minutes"), job(53, "failed", err="'error_provider'", age="27 minutes"), job(54, "failed", err="'error_provider'", age="26 minutes"))
got = run(mix).get("c10_provider_run")
ok = got[1] == "green"; fails += not ok
print("caught  " if ok else "SURVIVED", "broken_run_stays_green", got)
sys.exit(1 if fails else 0)
