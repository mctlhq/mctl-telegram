// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

// scenario.go is what alice_trigger_scenario must pass before it gets a
// card (#1322 slice P2-S9, threat model T6, S2-D6). A scenario is a list
// of steps the account's owner set up at the service: the call names it
// and says nothing of what it does, so a card that showed only the
// arguments would ask the principal to approve something it cannot see.
//
// The card therefore shows the steps, read from the server for that card,
// or there is no card. Every check here refuses:
//
//   - No ScenarioSteps reader for the server: refused before anything is
//     read. No server tool returns a scenario's steps today, so no
//     production reader exists and every call ends here.
//   - A scenario whose name or id starts with "mctl-" is the service's
//     own (it carries speech and commands to a speaker) and is never run
//     through this tool, with or without a reader.
//   - The scenario must be named by the id the reader returns for it. The
//     server would also match a name, by substring, so a name could run
//     another scenario than the one the card showed.
//   - A read that failed, or returned no steps or steps that cannot be
//     shown, is a refusal of its own: never a card without steps.
//
// Like the rest of the card path, none of this runs in a deployed service.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Reasons a scenario gets no card.
const (
	// ReasonScenarioReserved: the scenario is one of the service's own.
	ReasonScenarioReserved = "scenario_reserved"
	// ReasonScenarioNotListed: the call names the scenario by anything
	// other than the id the read returned for it.
	ReasonScenarioNotListed = "scenario_not_listed"
	// ReasonScenarioUnreadable: the steps could not be read, or the read
	// was empty or malformed. That is not "a scenario without steps".
	ReasonScenarioUnreadable = "scenario_unreadable"
)

// reservedScenarioPrefix marks the scenarios the alice server creates for
// itself. It is matched without regard to case, as the server matches
// names.
const reservedScenarioPrefix = "mctl-"

// MaxScenarioSteps is the most steps a card lists. A longer scenario is
// refused, not shortened.
const MaxScenarioSteps = 20

// Scenario is one scenario as the server describes it. Everything in it
// is the server's text: it is shown to the principal on a card and never
// to the model.
type Scenario struct {
	ID, Name string
	// Steps are what running the scenario does, in order, one line each.
	Steps []string
}

// ScenarioRequest names the connection and the scenario whose steps are
// read. Scenario is the call's argument, as the worker sent it.
type ScenarioRequest struct {
	Principal         int64
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Token             connection.Secret
	Scenario          string
}

// ErrScenarioUnreadable is any read that did not yield one scenario with
// all of its steps.
var ErrScenarioUnreadable = errors.New("pa connector: scenario unreadable")

// ScenarioSteps reads, now, the scenario a call would run and every step
// of it. It never answers from a cache, and it returns an error for
// anything but a complete answer: a failed call, a tool error, a result it
// does not recognise, a scenario it cannot find. "Could not read" is never
// a scenario without steps.
type ScenarioSteps interface {
	ScenarioSteps(ctx context.Context, req ScenarioRequest) (Scenario, error)
}

// scenarioTools names, per scenario tool, the argument that holds the
// scenario. The table is code, not pin data.
var scenarioTools = map[string]string{
	"alice_trigger_scenario": "scenario",
}

// detailScenario is a scenario as sealed into an approval's card detail.
type detailScenario struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Steps []string `json:"steps"`
}

func reservedScenario(v string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), reservedScenarioPrefix)
}

// scenarioArg returns the scenario a call names, from its canonical
// arguments.
func scenarioArg(tool string, canonical []byte) (string, bool) {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil || args == nil {
		return "", false
	}
	name, ok := stringArg(args, scenarioTools[tool])
	return name, ok && name != ""
}

// precheckScenario runs the checks of a scenario call that read nothing
// from the server: its argument is readable and not reserved, and the
// server has a reader. Without a reader there is no card and no call at
// all, to the scenario or to anything else.
func (c *Cards) precheckScenario(server, tool string, canonical []byte) (string, *refusal) {
	name, ok := scenarioArg(tool, canonical)
	if !ok {
		return "", &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	if reservedScenario(name) {
		return "", &refusal{ReasonScenarioReserved, http.StatusForbidden}
	}
	if c.cfg.Scenarios[server] == nil {
		return "", &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	return name, nil
}

// scenarioTarget reads the scenario name would run and returns what the
// card shows and the detail to seal with the arguments.
func (c *Cards) scenarioTarget(ctx context.Context, req CardRequest, name string) (shown safetext.Scenario, detail []byte, ref *refusal) {
	unreadable := &refusal{ReasonScenarioUnreadable, http.StatusServiceUnavailable}
	reader := c.cfg.Scenarios[req.Server]
	if reader == nil {
		return shown, nil, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	sc, err := reader.ScenarioSteps(ctx, ScenarioRequest{
		Principal: req.Policy.Principal().TelegramID(), ConnectionID: req.ConnectionID,
		AuthorityRevision: req.AuthorityRevision, Server: req.Server, Token: req.Token, Scenario: name,
	})
	if err != nil || sc.ID == "" || sc.Name == "" || len(sc.Steps) == 0 || len(sc.Steps) > MaxScenarioSteps {
		return shown, nil, unreadable
	}
	for _, step := range sc.Steps {
		if strings.TrimSpace(step) == "" {
			return shown, nil, unreadable
		}
	}
	// The call may name the scenario by a name that only now resolves to
	// one of the service's own.
	if reservedScenario(sc.ID) || reservedScenario(sc.Name) {
		return shown, nil, &refusal{ReasonScenarioReserved, http.StatusForbidden}
	}
	// The id, byte for byte: what is approved is this scenario, not
	// whatever the name matches when the call is made.
	if sc.ID != name {
		return shown, nil, &refusal{ReasonScenarioNotListed, http.StatusUnprocessableEntity}
	}
	detail, err = json.Marshal(cardDetail{Scenario: &detailScenario{ID: sc.ID, Name: sc.Name, Steps: sc.Steps}})
	if err != nil {
		return shown, nil, &refusal{ReasonInternal, http.StatusInternalServerError}
	}
	return safetext.Scenario{ID: sc.ID, Name: sc.Name, Steps: sc.Steps}, detail, nil
}

// scenarioOf rebuilds what a scenario card shows from the approval's
// sealed arguments and detail. The detail must be of the scenario the
// arguments name, must hold its steps, and must pass the reserved check
// again.
func scenarioOf(tool string, args, detail []byte) (safetext.Scenario, error) {
	name, ok := scenarioArg(tool, args)
	if !ok {
		return safetext.Scenario{}, errors.New("pa card: scenario arguments unreadable")
	}
	var cd cardDetail
	dec := json.NewDecoder(strings.NewReader(string(detail)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cd); err != nil || cd.Scenario == nil {
		return safetext.Scenario{}, errors.New("pa card: scenario detail unreadable")
	}
	if cd.Scenario.ID != name || cd.Scenario.Name == "" || len(cd.Scenario.Steps) == 0 || len(cd.Scenario.Steps) > MaxScenarioSteps {
		return safetext.Scenario{}, errors.New("pa card: scenario detail does not match the arguments")
	}
	// As when the card was made: one of the service's own is never shown
	// for approval.
	if reservedScenario(cd.Scenario.ID) || reservedScenario(cd.Scenario.Name) {
		return safetext.Scenario{}, errors.New("pa card: scenario is reserved")
	}
	return safetext.Scenario{ID: cd.Scenario.ID, Name: cd.Scenario.Name, Steps: cd.Scenario.Steps}, nil
}
