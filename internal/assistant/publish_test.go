package assistant

import "testing"

func TestPublishRequestRefusesWhatCannotBePublished(t *testing.T) {
	def := &Definition{}
	def.Metadata.Name, def.Metadata.Version = "hr-recruiter", "0.1.1"
	e := &Entry{Definition: def, Materialized: []byte(`{}`), Digest: "sha256:00", Source: "assistants/hr-recruiter/versions/0.1.1/assistant.yaml"}
	for _, sha := range []string{"", "3322543", "0123456789ABCDEF0123456789abcdef01234567", "main"} {
		if _, err := PublishRequest(e, sha); err == nil {
			t.Errorf("git sha %q accepted", sha)
		}
	}
	e.Source = ""
	if _, err := PublishRequest(e, "0123456789abcdef0123456789abcdef01234567"); err == nil {
		t.Error("an entry with no source path was accepted")
	}
}
