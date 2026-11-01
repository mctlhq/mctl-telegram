package assistant

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// PublishRepo and PublishOwner are what every version published from this
// repository records as its source repository and registry owner.
const (
	PublishRepo  = "mctlhq/mctl-telegram"
	PublishOwner = "mctl-telegram"
)

var gitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// PublishRequest is the body of mctl-api's
// POST /api/v1/agents/{name}/definition-versions for catalog entry e built
// at commit gitSHA: the materialized document as the spec string, and a
// source manifest naming the file it came from and its digest. Publishing
// is a human-admin call (docs/assistants/spec.md); this only builds the
// body, so CI and the owner's script send the same bytes for the same
// commit.
func PublishRequest(e *Entry, gitSHA string) ([]byte, error) {
	if !gitSHAPattern.MatchString(gitSHA) {
		return nil, fmt.Errorf("git sha %q is not a full lowercase commit id", gitSHA)
	}
	if e.Source == "" {
		return nil, fmt.Errorf("%s@%s has no source path: only a catalog entry can be published",
			e.Definition.Metadata.Name, e.Definition.Metadata.Version)
	}
	type sourceManifest struct {
		Repo        string `json:"repo"`
		Path        string `json:"path"`
		GitSHA      string `json:"git_sha"`
		ContentHash string `json:"content_hash"`
	}
	return json.Marshal(struct {
		Version        string         `json:"version"`
		Spec           string         `json:"spec"`
		Owner          string         `json:"owner"`
		SourceManifest sourceManifest `json:"source_manifest"`
	}{
		Version: e.Definition.Metadata.Version,
		Spec:    string(e.Materialized),
		Owner:   PublishOwner,
		SourceManifest: sourceManifest{
			Repo:        PublishRepo,
			Path:        e.Source,
			GitSHA:      gitSHA,
			ContentHash: e.Digest,
		},
	})
}
