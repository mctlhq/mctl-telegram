package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

const guardScript = ".github/scripts/gitops-values-present.sh"

var inputRe = regexp.MustCompile(`-f\s+(\w+)=(\S+)`)

// step is one "- name:" entry of a workflow job.
type step struct {
	name   string
	text   string
	inputs map[string]string // -f key=value of the release-deploy dispatch, quotes stripped
}

func splitSteps(src string) []step {
	var out []step
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		text := strings.Join(cur, "\n")
		s := step{text: text, inputs: map[string]string{}}
		for _, l := range cur {
			if strings.HasPrefix(l, "      - name: ") {
				s.name = strings.TrimPrefix(l, "      - name: ")
			}
		}
		if strings.Contains(text, "gh workflow run release-deploy.yaml") {
			for _, m := range inputRe.FindAllStringSubmatch(text, -1) {
				s.inputs[m[1]] = strings.Trim(m[2], `"`)
			}
		}
		out = append(out, s)
		cur = nil
	}
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "      - ") {
			flush()
		}
		// A non-empty line indented less than a step (the next job, or a
		// comment above it) ends the current step instead of joining it.
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "      ") {
			flush()
			continue
		}
		cur = append(cur, l)
	}
	flush()
	return out
}

func dispatchSteps(src string) map[string]step {
	m := map[string]step{}
	for _, s := range splitSteps(src) {
		if c, ok := s.inputs["component_name"]; ok {
			m[c] = s
		}
	}
	return m
}

func checkGuardedStep(s step, component string) []string {
	var bad []string
	want := fmt.Sprintf("platform-gitops/services/labs/%s/values.yaml", component)
	if !strings.Contains(s.text, guardScript) {
		return []string{component + ": no existence guard call"}
	}
	if !strings.Contains(s.text, "VALUES="+want) {
		bad = append(bad, component+": guard path does not match component")
	}
	zero := armIndex(s.text, "0")
	run := strings.Index(s.text, "gh workflow run release-deploy.yaml")
	three := armIndex(s.text, "3")
	if zero < 0 || run < zero || (three >= 0 && run > three) {
		bad = append(bad, component+": dispatch is not under the 0) arm")
	}
	star := armIndex(s.text, `\*`)
	if star < 0 || !strings.Contains(s.text[star:], "exit 1") {
		bad = append(bad, component+": no failing *) arm")
	}
	if three < 0 || !strings.Contains(s.text, "::notice::") {
		bad = append(bad, component+": no 3) skip notice")
	}
	return bad
}

// armIndex returns the offset of the case arm "<label>)" written on a line of
// its own, or -1. Matching the whole line keeps a "0)" inside a comment or an
// expression from passing for the arm.
func armIndex(text, label string) int {
	loc := regexp.MustCompile(`(?m)^[ \t]+` + label + `\)[ \t]*$`).FindStringIndex(text)
	if loc == nil {
		return -1
	}
	return loc[0]
}

// jobBlock returns the text of one top-level job of a workflow, or "".
func jobBlock(src, job string) string {
	i := strings.Index(src, "\n  "+job+":\n")
	if i < 0 {
		return ""
	}
	rest := src[i+1:]
	if j := regexp.MustCompile(`(?m)^  [A-Za-z0-9_-]+:\n`).FindAllStringIndex(rest, 2); len(j) == 2 {
		rest = rest[:j[1][0]]
	}
	return rest
}

func checkInputs(s step, want map[string]string) []string {
	var bad []string
	for k, v := range want {
		if s.inputs[k] != v {
			bad = append(bad, fmt.Sprintf("%s: %s=%q, want %q", s.inputs["component_name"], k, s.inputs[k], v))
		}
	}
	return bad
}

// checkDeployWorkflows reports what is wrong with the managed-runtime deploy
// dispatches in the three workflow files.
func checkDeployWorkflows(preview, release, build string) []string {
	var bad []string

	p := dispatchSteps(preview)
	mp, ok := p["agent-worker-managed-preview"]
	if !ok {
		bad = append(bad, "preview: no agent-worker-managed-preview dispatch")
	} else {
		bad = append(bad, checkInputs(mp, map[string]string{
			"image_name":      "ghcr.io/mctlhq/agent-worker-preview",
			"image_tag":       "main-${SHORT_SHA}",
			"git_ref":         "$SHA",
			"repo":            "mctlhq/mctl-telegram",
			"dockerfile_path": "Dockerfile.agent-worker",
			"team_name":       "labs",
		})...)
		bad = append(bad, checkGuardedStep(mp, "agent-worker-managed-preview")...)
	}
	for _, c := range []string{"agent-worker-preview", "mctl-telegram-preview"} {
		s, ok := p[c]
		if !ok {
			bad = append(bad, "preview: missing existing dispatch "+c)
		} else if strings.Contains(s.text, guardScript) {
			bad = append(bad, "preview: existing dispatch "+c+" must stay unguarded")
		}
	}

	r := dispatchSteps(release)
	rs, ok := r["agent-worker-managed"]
	if !ok {
		bad = append(bad, "release: no agent-worker-managed dispatch")
	} else {
		bad = append(bad, checkInputs(rs, map[string]string{
			"image_name":      "ghcr.io/mctlhq/agent-worker",
			"image_tag":       "$TAG",
			"git_ref":         "$TAG",
			"repo":            "mctlhq/mctl-telegram",
			"dockerfile_path": "Dockerfile.agent-worker",
			"team_name":       "labs",
		})...)
		bad = append(bad, checkGuardedStep(rs, "agent-worker-managed")...)
		// Its own job: a failed guard must fail visibly (no continue-on-error)
		// without skipping the Local Bridge steps of the release-please job.
		job := jobBlock(release, "agent-worker-release")
		if job == "" || !strings.Contains(job, rs.text) {
			bad = append(bad, "release: dispatch must live in its own agent-worker-release job")
		} else {
			if !strings.Contains(job, "    needs: release-please\n") ||
				!strings.Contains(job, "    if: ${{ !cancelled() && needs.release-please.outputs.release_created == 'true' }}\n") {
				bad = append(bad, "release: agent-worker-release lacks needs/release_created guard")
			}
			if !strings.Contains(job, "ref: ${{ needs.release-please.outputs.tag_name }}") {
				bad = append(bad, "release: agent-worker-release must check out the released tag")
			}
		}
		if strings.Contains(jobBlock(release, "release-please"), rs.text) {
			bad = append(bad, "release: dispatch must not run inside the release-please job")
		}
		if strings.Contains(job, "continue-on-error") {
			bad = append(bad, "release: a failed guard must fail the job, not continue")
		}
	}
	if s, ok := r["mctl-telegram"]; !ok {
		bad = append(bad, "release: missing existing server dispatch")
	} else if strings.Contains(s.text, guardScript) {
		bad = append(bad, "release: existing server dispatch must stay unguarded")
	}

	if !strings.Contains(build, "docker-agent-worker:") ||
		!strings.Contains(build, "file: Dockerfile.agent-worker") ||
		strings.Contains(build, "push: true") || !strings.Contains(build, "push: false") {
		bad = append(bad, "build.yml: docker-agent-worker must build Dockerfile.agent-worker with push: false")
	}
	return bad
}

func readRepoFile(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func loadDeployWorkflows(t *testing.T) (string, string, string) {
	return readRepoFile(t, ".github", "workflows", "preview-deploy.yml"),
		readRepoFile(t, ".github", "workflows", "release-please.yml"),
		readRepoFile(t, ".github", "workflows", "build.yml")
}

func TestDeployWorkflows(t *testing.T) {
	preview, release, build := loadDeployWorkflows(t)
	for _, b := range checkDeployWorkflows(preview, release, build) {
		t.Error(b)
	}
}

func TestDeployWorkflowsGuardCatchesMutations(t *testing.T) {
	preview, release, build := loadDeployWorkflows(t)
	mp := dispatchSteps(preview)["agent-worker-managed-preview"].text
	rs := dispatchSteps(release)["agent-worker-managed"].text
	if mp == "" || rs == "" {
		t.Fatal("new dispatch steps not found")
	}
	cases := []struct {
		name string
		mut  func(p, r, b string) (string, string, string)
	}{
		{"remove managed-preview block", func(p, r, b string) (string, string, string) {
			return strings.Replace(p, mp, "", 1), r, b
		}},
		{"rename managed-preview component", func(p, r, b string) (string, string, string) {
			return strings.Replace(p, "-f component_name=agent-worker-managed-preview", "-f component_name=agent-worker-managed-previewx", 1), r, b
		}},
		{"release image to preview image", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "image_name=ghcr.io/mctlhq/agent-worker \\", "image_name=ghcr.io/mctlhq/agent-worker-preview \\", 1), b
		}},
		{"drop dockerfile_path from release", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "                -f dockerfile_path=Dockerfile.agent-worker \\\n", "", 1), b
		}},
		{"drop release_created guard", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "    if: ${{ !cancelled() && needs.release-please.outputs.release_created == 'true' }}\n", "", 1), b
		}},
		{"drop !cancelled() so a failed Local Bridge build skips the dispatch", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "if: ${{ !cancelled() && needs.release-please.outputs.release_created == 'true' }}", "if: ${{ needs.release-please.outputs.release_created == 'true' }}", 1), b
		}},
		{"move release dispatch back into the release-please job", func(p, r, b string) (string, string, string) {
			moved := strings.Replace(r, rs, "", 1)
			i := strings.Index(moved, "      - name: Set up Go")
			return p, moved[:i] + rs + "\n" + moved[i:], b
		}},
		{"continue-on-error on the release dispatch", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "      - name: Dispatch agent-worker release-deploy\n", "      - name: Dispatch agent-worker release-deploy\n        continue-on-error: true\n", 1), b
		}},
		{"release job checks out main instead of the tag", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "ref: ${{ needs.release-please.outputs.tag_name }}", "ref: main", 1), b
		}},
		{"zero arm only in a comment", func(p, r, b string) (string, string, string) {
			mutated := strings.Replace(rs, "            0)\n", "            # 0) handled below\n            9)\n", 1)
			return p, strings.Replace(r, rs, mutated, 1), b
		}},
		{"push true in build.yml", func(p, r, b string) (string, string, string) {
			return p, r, strings.Replace(b, "push: false", "push: true", 1)
		}},
		{"remove guard from preview step", func(p, r, b string) (string, string, string) {
			return strings.Replace(p, mp, strings.ReplaceAll(mp, guardScript, "true"), 1), r, b
		}},
		{"remove guard from release step", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, rs, strings.ReplaceAll(rs, guardScript, "true"), 1), b
		}},
		{"guard points at other component", func(p, r, b string) (string, string, string) {
			return p, strings.Replace(r, "labs/agent-worker-managed/values.yaml", "labs/agent-worker-managed-preview/values.yaml", 1), b
		}},
		{"star arm skips instead of failing", func(p, r, b string) (string, string, string) {
			i := strings.Index(rs, "*)")
			mutated := rs[:i] + strings.Replace(rs[i:], "exit 1", "true", 1)
			return p, strings.Replace(r, rs, mutated, 1), b
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, r, b := c.mut(preview, release, build)
			if p == preview && r == release && b == build {
				t.Fatal("mutation changed nothing")
			}
			if len(checkDeployWorkflows(p, r, b)) == 0 {
				t.Error("guard did not catch the mutation")
			}
		})
	}
}

func runGuardScript(t *testing.T, apiURL, token, path string) int {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", guardScript))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", script, path)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GITHUB_API_URL=" + apiURL, "GITOPS_VALUES_RETRIES=0"}
	if token != "" {
		cmd.Env = append(cmd.Env, "GH_TOKEN="+token)
	}
	err = cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	t.Fatal(err)
	return -1
}

func TestGitopsValuesPresent(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	const path = "platform-gitops/services/labs/agent-worker-managed/values.yaml"
	var hits atomic.Int32
	var status atomic.Int32
	var gotAuth, gotPath, gotRef atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		gotPath.Store(r.URL.Path)
		gotRef.Store(r.URL.Query().Get("ref"))
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	for st, want := range map[int]int{200: 0, 404: 3, 403: 1, 500: 1, 502: 1} {
		status.Store(int32(st))
		if got := runGuardScript(t, srv.URL, "tok", path); got != want {
			t.Errorf("HTTP %d: exit %d, want %d", st, got, want)
		}
	}
	if a := gotAuth.Load(); a != "Bearer tok" {
		t.Errorf("Authorization = %v", a)
	}
	if p := gotPath.Load(); p != "/repos/mctlhq/mctl-gitops/contents/"+path {
		t.Errorf("path = %v", p)
	}
	if r := gotRef.Load(); r != "main" {
		t.Errorf("ref = %v", r)
	}

	before := hits.Load()
	if got := runGuardScript(t, srv.URL, "", path); got != 1 {
		t.Errorf("unset token: exit %d, want 1", got)
	}
	if got := runGuardScript(t, srv.URL, "tok", "platform-gitops/services/../x/values.yaml"); got != 1 {
		t.Errorf("dotdot path: exit %d, want 1", got)
	}
	if hits.Load() != before {
		t.Error("request sent for unset token or invalid path")
	}

	url := srv.URL
	srv.Close()
	if got := runGuardScript(t, url, "tok", path); got != 1 {
		t.Errorf("transport error: exit %d, want 1", got)
	}
}
