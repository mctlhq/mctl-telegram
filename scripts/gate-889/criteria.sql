-- Part B criteria 3 to 11b. Metadata only: no body, payload or identifier column
-- is selected. psql vars: ws, we (window start and end).
-- Verdict: green, red, unknown or info. unknown is never green.
with
j as (select * from agent_jobs where created_at >= :'ws'::timestamptz and created_at < :'we'::timestamptz),
m as (select * from j where runtime = 'managed'),
o as (select * from j where runtime = 'own'),
a as (select t.*, jb.status as job_status, jb.conversation_id, jb.runtime
        from agent_job_attempts t join m jb on jb.id = t.job_id),
iv as (select id, job_id, conversation_id, started_at,
              case when finished_at is not null then finished_at
                   when job_status = 'processing' then now() end as ended_at
         from a),
reason as (
  select distinct on (x.event_id) x.event_id, x.r
    from (select event_id, id, (envelope::jsonb -> 'subject' ->> 'routing_reason') r from event_outbox
           where created_at >= :'ws'::timestamptz) x
   where x.r is not null
   order by x.event_id, x.id),
mrouted as (select m.id, reason.r from m left join reason on reason.event_id = m.event_id where m.status = 'routed'),
act as (select * from agent_actions where created_at >= :'ws'::timestamptz and created_at < :'we'::timestamptz),
noti as (select * from owner_notifications where created_at >= :'ws'::timestamptz and created_at < :'we'::timestamptz),
us as (select u.* from agent_usage u join j on j.id = u.job_id),
turns as (select count(distinct turn_id) n from m where status = 'completed' and turn_id is not null),
cost as (select sum(coalesce(u.cost_usd, u.reserved_usd)) c from us u where u.runtime = 'managed'),
prov as (
  select id, last_error like 'error_provider%' or last_error like '%error_provider%' as bad,
         row_number() over (order by id) - row_number() over (partition by (coalesce(last_error,'') like '%error_provider%') order by id) as grp
    from m where status not in ('pending','processing','coalesced')),
provrun as (select coalesce(max(c),0) n from (select count(*) c from prov where bad group by grp) s),
lat as (select percentile_cont(0.95) within group (order by extract(epoch from updated_at - created_at)) p95, count(*) n
          from m where status = 'completed')
select * from (
  select 'c3a_dead_letter' id, count(*)::text val, case when count(*)=0 then 'green' else 'red' end verdict from m where status='dead_letter'
  union all select 'c3b_processing_past_5m', count(*)::text, case when count(*)=0 then 'green' else 'red' end from m where status='processing' and claimed_at < now() - interval '5 minutes'
  union all select 'c3c_attempts_gt_1_listed', count(*)::text, 'info' from m where attempts > 1
  union all select 'c3d_routed_worker_unclaimed', count(*)::text, case when count(*)=0 then 'green' else 'red' end from mrouted where r='worker_unclaimed'
  union all select 'c3e_routed_reason_unobserved', count(*)::text, case when count(*)=0 then 'green' else 'unknown' end from mrouted where r is null
  union all select 'c4a_global_overlap', count(*)::text, case when count(*)=0 then 'green' else 'red' end
    from iv x join iv y on x.id < y.id and x.ended_at is not null and y.ended_at is not null and x.started_at < y.ended_at and y.started_at < x.ended_at
  union all select 'c4b_conversation_overlap', count(*)::text, case when count(*)=0 then 'green' else 'red' end
    from iv x join iv y on x.id < y.id and x.conversation_id = y.conversation_id and x.ended_at is not null and y.ended_at is not null and x.started_at < y.ended_at and y.started_at < x.ended_at
  union all select 'c4c_crashed_attempts', count(*)::text, 'info' from iv where ended_at is null
  union all select 'c5_coalesced_turns', count(*)::text, case when count(*)>=3 then 'green' when count(*)=0 and (select count(*) from m)=0 then 'unknown' else 'red' end
    from (select turn_id from m where turn_id is not null group by turn_id having count(*) >= 2) s
  union all select 'c6a_own_jobs_claimed', count(*)::text, case when count(*)=0 then 'green' else 'red' end from o where attempts > 0 or claimed_at is not null
  union all select 'c6b_own_attempt_rows', count(*)::text, case when count(*)=0 then 'green' else 'red' end from agent_job_attempts t join o on o.id=t.job_id
  union all select 'c6c_own_usage_rows', count(*)::text, case when count(*)=0 then 'green' else 'red' end from us where job_id in (select id from o)
  union all select 'c6d_own_status_outside_allowed', count(*)::text, case when count(*)=0 then 'green' else 'red' end from o where status not in ('pending','routed')
  union all select 'c7_usage_unsettled_past_grace', count(*)::text, case when count(*)=0 then 'green' else 'red' end from us where status <> 'settled' and created_at < now() - interval '7 minutes'
  union all select 'c8_cost_per_completed_turn', coalesce(round(((select c from cost)/nullif((select n from turns),0))::numeric,4)::text,'n/a'),
    case when (select n from turns)=0 then 'unknown' when (select coalesce(c,0) from cost)/(select n from turns) <= 0.0572 then 'green' else 'red' end
  union all select 'c8b_total_cost', coalesce(round((select c from cost)::numeric,4)::text,'0'), 'info'
  union all select 'c9_p95_latency_s', coalesce(round((select p95 from lat)::numeric,1)::text,'n/a'),
    case when (select n from lat)=0 then 'unknown' when (select p95 from lat) <= 60 then 'green' else 'red' end
  union all select 'c10_provider_run', (select n from provrun)::text, case when (select n from provrun) >= 3 then 'red' else 'green' end
  union all select 'c11a_peer_send', count(*)::text, case when count(*)=0 then 'green' else 'red' end from act where action_type='propose_reply'
     and (executed_tg_message_id is not null or status in ('approved','executing','executed','delivery_unknown') or send_attempts > 0)
  union all select 'c11a2_still_proposed', count(*)::text, case when count(*)=0 then 'green' else 'unknown' end from act where action_type='propose_reply' and status='proposed'
  union all select 'c11b_action_delivery_unknown', count(*)::text, case when count(*)=0 then 'green' else 'red' end from act where status='delivery_unknown'
  union all select 'c11c_notification_delivery_unknown', count(*)::text, case when count(*)=0 then 'green' else 'red' end from noti where status='delivery_unknown'
  union all select 'c11d_notification_kind_outside_list', count(*)::text, case when count(*)=0 then 'green' else 'red' end from noti where kind not in ('summary','approval_request','alert','human_input','budget')
  union all select 'c11e_sent_without_message_id', count(*)::text, case when count(*)=0 then 'green' else 'red' end from noti where status='sent' and tg_message_id is null
  union all select 'c_jobs_in_window', (select count(*) from j)::text, 'info'
) r order by id;
