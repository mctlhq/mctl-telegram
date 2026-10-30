package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Turn context for edits (#962). An edit of a message that was part of a
// coalesced turn supersedes that turn's draft (#950), and the edit's own job
// would otherwise see only the corrected message, losing what the rest of the
// turn said. When the earlier turn's reply was never sent, the edit job also
// gets the turn's other messages, each at its latest version (a deleted one
// is left out). When the reply was sent, those messages were already
// answered, and showing them again would invite a second answer.
//
// The set is computed when the job is claimed and stored in
// agent_jobs.turn_context, so get_event authorizes exactly the events the
// worker was handed, and the send-time supersession check compares against
// the versions the model read.

// eventRef is the part of an incoming event the context build needs.
type eventRef struct {
	id        int64
	eventID   string
	kind      string
	chatTGID  int64
	messageID int64
}

func loadEventRef(ctx context.Context, q rowQueryer, userID int64, eventID string) (eventRef, bool, error) {
	r := eventRef{eventID: eventID}
	err := q.QueryRowContext(ctx,
		`SELECT id, kind, chat_tg_id, message_id FROM incoming_events WHERE user_id = $1 AND event_id = $2`,
		userID, eventID,
	).Scan(&r.id, &r.kind, &r.chatTGID, &r.messageID)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, fmt.Errorf("load event: %w", err)
	}
	return r, true, nil
}

// originalMessage returns the private_message event a message was first
// recorded as, if the account has it.
func originalMessage(ctx context.Context, q rowQueryer, userID int64, chatTGID, messageID int64) (eventRef, bool, error) {
	r := eventRef{kind: EventKindPrivateMessage, chatTGID: chatTGID, messageID: messageID}
	err := q.QueryRowContext(ctx,
		`SELECT id, event_id FROM incoming_events
		  WHERE user_id = $1 AND chat_tg_id = $2 AND message_id = $3 AND kind = $4
		  ORDER BY id LIMIT 1`,
		userID, chatTGID, messageID, EventKindPrivateMessage,
	).Scan(&r.id, &r.eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	if err != nil {
		return r, false, fmt.Errorf("load original message: %w", err)
	}
	return r, true, nil
}

// latestVersion returns the newest event of a message recorded after src: an
// edit's event id, or deleted=true when the message was deleted. With
// neither, it returns src's own event id.
func latestVersion(ctx context.Context, q rowQueryer, userID int64, src eventRef) (eventID string, deleted bool, err error) {
	var kind string
	err = q.QueryRowContext(ctx,
		`SELECT kind, event_id FROM incoming_events
		  WHERE user_id = $1 AND chat_tg_id = $2 AND message_id = $3 AND id > $4
		    AND kind IN ($5, $6)
		  ORDER BY CASE WHEN kind = $6 THEN 0 ELSE 1 END, id DESC
		  LIMIT 1`,
		userID, src.chatTGID, src.messageID, src.id, EventKindMessageEdit, EventKindMessageDelete,
	).Scan(&kind, &eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return src.eventID, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("load latest message version: %w", err)
	}
	return eventID, kind == EventKindMessageDelete, nil
}

// unsentTurnSources returns the source events of the turn that first carried
// the given message, when no reply covering that turn was sent: neither the
// turn's own nor one of a later job that carried it as context. Otherwise it
// returns nil. A one-message turn yields only the edited message itself,
// which the caller already has, so it adds nothing.
func unsentTurnSources(ctx context.Context, q queryer, userID int64, original eventRef) ([]eventRef, error) {
	var jobID, coalescedInto, convID sql.NullInt64
	err := q.QueryRowContext(ctx,
		`SELECT id, coalesced_into, conversation_id FROM agent_jobs WHERE user_id = $1 AND event_id = $2`,
		userID, original.eventID,
	).Scan(&jobID, &coalescedInto, &convID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load original job: %w", err)
	}
	head := jobID.Int64
	if coalescedInto.Valid && coalescedInto.Int64 != 0 {
		head = coalescedInto.Int64
	}
	var sent int
	err = q.QueryRowContext(ctx,
		`SELECT 1 FROM agent_actions
		  WHERE user_id = $1 AND job_id = $2 AND action_type = $3 AND status IN ($4, $5)
		  LIMIT 1`,
		userID, head, ActionTypeReply, ActionExecuting, ActionExecuted,
	).Scan(&sent)
	if err == nil {
		return nil, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("check turn reply sent: %w", err)
	}
	rows, err := q.QueryContext(ctx,
		`SELECT e.id, e.event_id, e.kind, e.chat_tg_id, e.message_id
		   FROM agent_jobs j
		   JOIN incoming_events e ON e.event_id = j.event_id AND e.user_id = j.user_id
		  WHERE j.user_id = $1 AND (j.id = $2 OR j.coalesced_into = $2)
		  ORDER BY e.id`,
		userID, head)
	if err != nil {
		return nil, fmt.Errorf("load turn sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []eventRef
	for rows.Next() {
		var r eventRef
		if err := rows.Scan(&r.id, &r.eventID, &r.kind, &r.chatTGID, &r.messageID); err != nil {
			return nil, fmt.Errorf("scan turn source: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	answered, err := answeredThroughContext(ctx, q, userID, convID.Int64, head, out)
	if err != nil || answered {
		return nil, err
	}
	return out, nil
}

// answeredThroughContext reports whether a later job that carried messages of
// the turn as turn context already sent its reply. #950 withdraws the head's
// draft on an edit, so after the first edit job answers the whole turn the
// head still shows no sent reply; without this check a second edit would be
// handed the turn again and answer it twice.
func answeredThroughContext(ctx context.Context, q queryer, userID, convID, head int64, turnSources []eventRef) (bool, error) {
	if convID == 0 {
		return false, nil
	}
	rows, err := q.QueryContext(ctx,
		`SELECT j.turn_context FROM agent_jobs j
		  WHERE j.user_id = $1 AND j.conversation_id = $2 AND j.id > $3
		    AND j.turn_context IS NOT NULL
		    AND EXISTS (
		        SELECT 1 FROM agent_actions a
		         WHERE a.user_id = j.user_id AND a.job_id = j.id
		           AND a.action_type = $4 AND a.status IN ($5, $6)
		    )`,
		userID, convID, head, ActionTypeReply, ActionExecuting, ActionExecuted)
	if err != nil {
		return false, fmt.Errorf("load answered turn contexts: %w", err)
	}
	var stored []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("scan turn context: %w", err)
		}
		stored = append(stored, raw)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	_ = rows.Close()
	inTurn := map[messageKey]bool{}
	for _, src := range turnSources {
		inTurn[messageKey{src.chatTGID, src.messageID}] = true
	}
	for _, raw := range stored {
		var ids []string
		if err := json.Unmarshal([]byte(raw), &ids); err != nil {
			return false, fmt.Errorf("decode turn context: %w", err)
		}
		for _, id := range ids {
			r, ok, err := loadEventRef(ctx, q, userID, id)
			if err != nil {
				return false, err
			}
			if ok && inTurn[messageKey{r.chatTGID, r.messageID}] {
				return true, nil
			}
		}
	}
	return false, nil
}

type messageKey struct{ chat, msg int64 }

// buildTurnContext returns the events a claimed job should see: its own
// source events plus, for every edit among them, the other messages of the
// unsent turn the edited message belonged to, at their latest versions. The
// result is in the arrival order of the original messages. It returns nil
// when nothing is added, so the job keeps its plain source list.
func buildTurnContext(ctx context.Context, q queryer, userID int64, own []string) ([]string, error) {
	type item struct {
		eventID string
		order   int64 // id of the message's original event
	}
	var items []item
	have := map[messageKey]bool{}
	var edits []eventRef
	for _, id := range own {
		r, ok, err := loadEventRef(ctx, q, userID, id)
		if err != nil {
			return nil, err
		}
		order := r.id
		if ok {
			have[messageKey{r.chatTGID, r.messageID}] = true
			if r.kind == EventKindMessageEdit {
				edits = append(edits, r)
				if orig, found, err := originalMessage(ctx, q, userID, r.chatTGID, r.messageID); err != nil {
					return nil, err
				} else if found {
					order = orig.id
				}
			}
		}
		items = append(items, item{eventID: id, order: order})
	}
	added := false
	for _, e := range edits {
		orig, found, err := originalMessage(ctx, q, userID, e.chatTGID, e.messageID)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		sources, err := unsentTurnSources(ctx, q, userID, orig)
		if err != nil {
			return nil, err
		}
		for _, src := range sources {
			key := messageKey{src.chatTGID, src.messageID}
			if have[key] {
				continue
			}
			have[key] = true
			version, deleted, err := latestVersion(ctx, q, userID, src)
			if err != nil {
				return nil, err
			}
			if deleted {
				continue
			}
			items = append(items, item{eventID: version, order: src.id})
			added = true
		}
	}
	if !added {
		return nil, nil
	}
	sort.SliceStable(items, func(i, k int) bool { return items[i].order < items[k].order })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.eventID
	}
	return out, nil
}

// storeTurnContext computes and persists the turn context of a job that was
// just claimed (see buildTurnContext), replacing SourceEventIDs when it adds
// anything. A re-claim recomputes it, so a retried attempt reads the latest
// versions.
func storeTurnContext(ctx context.Context, tx *sql.Tx, j *AgentJob) error {
	full, err := buildTurnContext(ctx, tx, j.UserID, j.SourceEventIDs)
	if err != nil {
		return err
	}
	var stored any
	if full != nil {
		raw, err := json.Marshal(full)
		if err != nil {
			return fmt.Errorf("encode turn context: %w", err)
		}
		stored = string(raw)
		j.SourceEventIDs = full
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs SET turn_context = $1 WHERE id = $2 AND user_id = $3`,
		stored, j.ID, j.UserID,
	); err != nil {
		return fmt.Errorf("store turn context: %w", err)
	}
	return nil
}

// loadTurnContext returns the stored turn context of a job, or nil.
func loadTurnContext(ctx context.Context, q rowQueryer, userID, jobID int64) ([]string, error) {
	var raw sql.NullString
	err := q.QueryRowContext(ctx,
		`SELECT turn_context FROM agent_jobs WHERE id = $1 AND user_id = $2`,
		jobID, userID,
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (!raw.Valid || raw.String == "")) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load turn context: %w", err)
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw.String), &ids); err != nil {
		return nil, fmt.Errorf("decode turn context: %w", err)
	}
	return ids, nil
}

// turnContextSuperseded reports whether a message the job read through its
// turn context has been edited or deleted since the version it read. Same
// result shape as jobSourceSuperseded.
func turnContextSuperseded(ctx context.Context, q rowQueryer, userID, jobID int64) (string, error) {
	ids, err := loadTurnContext(ctx, q, userID, jobID)
	if err != nil || len(ids) == 0 {
		return "", err
	}
	args := []any{userID, EventKindMessageEdit, EventKindMessageDelete}
	marks := make([]string, len(ids))
	for i, id := range ids {
		args = append(args, id)
		marks[i] = "$" + strconv.Itoa(len(args))
	}
	var kind string
	err = q.QueryRowContext(ctx,
		`SELECT later.kind
		   FROM incoming_events v
		   JOIN incoming_events later
		     ON later.user_id = v.user_id
		    AND later.chat_tg_id = v.chat_tg_id
		    AND later.message_id = v.message_id
		    AND later.id > v.id
		    AND later.kind IN ($2, $3)
		  WHERE v.user_id = $1 AND v.event_id IN (`+strings.Join(marks, ",")+`)
		  ORDER BY CASE WHEN later.kind = $3 THEN 0 ELSE 1 END
		  LIMIT 1`,
		args...,
	).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("check turn context supersession: %w", err)
	}
	if kind == EventKindMessageDelete {
		return SourceDeleted, nil
	}
	return SourceEdited, nil
}
