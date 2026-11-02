// Command fakeworker is a scripted worker for the agent-conformance tests. It
// speaks the agent job API with no model: for each claimed fixture it does
// what a correct worker would, or misbehaves as AGENT_FAKE_MODE says.
//
// It is built by the tests, never shipped, and links nothing of the
// harness's fake: it reads the suite only to know what a correct answer to a
// fixture is.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/agenteval"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

type job struct {
	JobID          int64  `json:"job_id"`
	EventID        string `json:"event_id"`
	ConversationID int64  `json:"conversation_id"`
	Attempt        int    `json:"attempt"`
	JobToken       string `json:"job_token"`
}

var (
	base, account string
	mode          string
	lateDelay     time.Duration
)

func call(ctx context.Context, token, method, path string, body any) (int, map[string]any, error) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, &buf)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

func main() {
	base, account = os.Getenv("AGENT_API_BASE_URL"), os.Getenv("AGENT_API_TOKEN")
	mode = os.Getenv("AGENT_FAKE_MODE")
	lateDelay, _ = time.ParseDuration(os.Getenv("AGENT_FAKE_LATE"))
	if base == "" || account == "" {
		fmt.Fprintln(os.Stderr, "AGENT_API_BASE_URL and AGENT_API_TOKEN are required")
		os.Exit(2)
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	entry, _ := catalog.Lookup("hr-recruiter", "0.1.0")
	suite, err := agenteval.LoadSuite(mctltelegram.Catalog, entry)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	n := 0
	for ctx.Err() == nil {
		var claim struct {
			Jobs []job `json:"jobs"`
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/jobs/claim?limit=1", nil)
		req.Header.Set("Authorization", "Bearer "+account)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "claim:", err)
				os.Exit(1)
			}
			break
		}
		err = json.NewDecoder(resp.Body).Decode(&claim)
		resp.Body.Close()
		if err != nil {
			os.Exit(1)
		}
		for _, j := range claim.Jobs {
			n++
			f, ok := suite.Fixture(strings.TrimPrefix(j.EventID, "eval-"))
			if !ok {
				fmt.Fprintln(os.Stderr, "unknown fixture", j.EventID)
				os.Exit(1)
			}
			handle(ctx, j, f, n)
		}
	}
}

func handle(ctx context.Context, j job, f agenteval.Fixture, n int) {
	bound := func(m map[string]any) map[string]any {
		m["job_id"], m["attempt"], m["conversation_id"] = j.JobID, j.Attempt, j.ConversationID
		return m
	}
	path := "/jobs/" + strconv.FormatInt(j.JobID, 10)
	switch {
	case mode == "stall" && n == 2:
		// Claims the fixture and never completes it.
		return
	case f.ExpectedAction == agenteval.ActionIgnored:
		call(ctx, j.JobToken, http.MethodPost, path+"/complete", map[string]any{"attempt": j.Attempt, "status": "ignored"})
	default:
		lead := map[string]any{}
		for k, v := range f.RequiredLead {
			lead[k] = v
		}
		call(ctx, j.JobToken, http.MethodPost, "/leads", bound(lead))
		intent, text := "discovery", "Thanks for reaching out. Could you share more about the team and the interview process?"
		if f.ExpectedDecision != "allow" {
			intent = "compensation"
		}
		if mode == "leak" && len(f.ForbiddenOutput) > 0 {
			text = "Sure: " + f.ForbiddenOutput[0]
		}
		call(ctx, j.JobToken, http.MethodPost, "/actions/propose_reply", bound(map[string]any{"intent": intent, "text": text}))
		call(ctx, j.JobToken, http.MethodPost, path+"/complete", map[string]any{"attempt": j.Attempt, "status": "completed"})
	}
	finish := func() {
		call(ctx, account, http.MethodGet, path, nil)
		call(ctx, account, http.MethodPost, path+"/cost", map[string]any{"attempt": j.Attempt, "cost_usd": 0.01})
	}
	if lateDelay > 0 {
		// As a worker that reports after the job, while it already polls
		// for the next claim.
		go func() {
			time.Sleep(lateDelay)
			finish()
		}()
		return
	}
	finish()
}
