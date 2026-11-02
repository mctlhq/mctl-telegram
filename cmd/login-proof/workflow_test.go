package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const proofWorkflow = "live-telegram-login.yml"

// triggers returns the keys under the top-level "on:" of a workflow file.
func triggers(src string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "on:") {
			in = true
			rest := strings.TrimSpace(strings.TrimPrefix(line, "on:"))
			if rest != "" {
				out = append(out, strings.Trim(rest, "[] "))
			}
			continue
		}
		if !in {
			continue
		}
		if line != "" && line[0] != ' ' && line[0] != '#' {
			break
		}
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			out = append(out, strings.TrimSuffix(strings.Fields(t)[0], ":"))
		}
	}
	return out
}

// checkProofWorkflow reports what is wrong with the proof workflow source, and
// with the other workflows, that could make the proof run unattended.
func checkProofWorkflow(proof string, others map[string]string) []string {
	var bad []string
	for _, tr := range triggers(proof) {
		if tr != "workflow_dispatch" {
			bad = append(bad, "trigger "+tr)
		}
	}
	if len(triggers(proof)) == 0 {
		bad = append(bad, "no workflow_dispatch trigger")
	}
	if !strings.Contains(proof, "cancel-in-progress: false") {
		bad = append(bad, "concurrency must not cancel in progress")
	}
	if !strings.Contains(proof, "environment: live-telegram-login") {
		bad = append(bad, "missing environment")
	}
	for name, src := range others {
		if strings.Contains(src, proofWorkflow) {
			bad = append(bad, name+" refers to "+proofWorkflow)
		}
	}
	return bad
}

func loadWorkflows(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := filepath.Join("..", "..", ".github", "workflows")
	b, err := os.ReadFile(filepath.Join(dir, proofWorkflow))
	if err != nil {
		t.Fatal(err)
	}
	others := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == proofWorkflow || e.IsDir() {
			continue
		}
		ob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		others[e.Name()] = string(ob)
	}
	return string(b), others
}

func TestProofWorkflowIsDispatchOnly(t *testing.T) {
	proof, others := loadWorkflows(t)
	if bad := checkProofWorkflow(proof, others); len(bad) != 0 {
		t.Fatalf("live-telegram-login workflow violates its invariants: %v", bad)
	}
}

func TestProofWorkflowGuardCatchesMutations(t *testing.T) {
	proof, others := loadWorkflows(t)
	mutations := map[string]func() (string, map[string]string){
		"schedule": func() (string, map[string]string) {
			return strings.Replace(proof, "on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 3 * * *'\n", 1), others
		},
		"pull_request": func() (string, map[string]string) {
			return strings.Replace(proof, "on:\n  workflow_dispatch:\n", "on:\n  workflow_dispatch:\n  pull_request:\n", 1), others
		},
		"push": func() (string, map[string]string) {
			return strings.Replace(proof, "on:\n  workflow_dispatch:\n", "on:\n  push:\n", 1), others
		},
		"release-please dispatch": func() (string, map[string]string) {
			m := map[string]string{}
			for k, v := range others {
				m[k] = v
			}
			m["release-please.yml"] += "\n      gh workflow run live-telegram-login.yml\n"
			return proof, m
		},
		"cancel in progress": func() (string, map[string]string) {
			return strings.Replace(proof, "cancel-in-progress: false", "cancel-in-progress: true", 1), others
		},
	}
	for name, mut := range mutations {
		p, o := mut()
		if p == proof && name != "release-please dispatch" {
			t.Fatalf("%s: mutation did not change the workflow", name)
		}
		if len(checkProofWorkflow(p, o)) == 0 {
			t.Errorf("%s: guard did not fail", name)
		}
	}
}
