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

import (
	"slices"
	"testing"
)

// TestScenarioOf_ChecksTheSealedDetailAgain: the card of a pending
// approval is rebuilt only from detail that names the scenario of the
// arguments, holds its steps and is not one of the service's own.
func TestScenarioOf_ChecksTheSealedDetailAgain(t *testing.T) {
	const tool = "alice_trigger_scenario"
	const args = `{"scenario":"scn-night-0000001"}`
	good := `{"scenario":{"id":"scn-night-0000001","name":"Good night","steps":["Turn off Kitchen lamp","Lock the front door"]}}`
	sc, err := scenarioOf(tool, []byte(args), []byte(good))
	if err != nil || sc.ID != "scn-night-0000001" || sc.Name != "Good night" || !slices.Equal(sc.Steps, []string{"Turn off Kitchen lamp", "Lock the front door"}) {
		t.Fatalf("scenarioOf = %+v, %v", sc, err)
	}
	for name, c := range map[string][2]string{
		"no detail":            {args, ``},
		"detail of a speaker":  {args, `{"speaker":{"id":"spk-kitchen-0001","name":"Kitchen speaker","room":"Kitchen","home":""}}`},
		"an unknown field":     {args, `{"scenario":{"id":"scn-night-0000001","name":"Good night","steps":["x"],"more":1}}`},
		"another scenario":     {args, `{"scenario":{"id":"scn-day-00000002","name":"Good night","steps":["x"]}}`},
		"no name":              {args, `{"scenario":{"id":"scn-night-0000001","name":"","steps":["x"]}}`},
		"no steps":             {args, `{"scenario":{"id":"scn-night-0000001","name":"Good night","steps":[]}}`},
		"a reserved name":      {args, `{"scenario":{"id":"scn-night-0000001","name":"MCTL-tts","steps":["x"]}}`},
		"a reserved id":        {`{"scenario":"mctl-0001"}`, `{"scenario":{"id":"mctl-0001","name":"Good night","steps":["x"]}}`},
		"arguments of no name": {`{}`, good},
	} {
		if sc, err := scenarioOf(tool, []byte(c[0]), []byte(c[1])); err == nil {
			t.Errorf("%s: built %+v", name, sc)
		}
	}
}
