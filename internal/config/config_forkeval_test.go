package config

import "testing"

func TestLoadAssistantForkEvalEnabled(t *testing.T) {
	for _, tc := range []struct {
		name, val string
		set       bool
		want      bool
	}{
		{"unset", "", false, false},
		{"true", "true", true, true},
		{"false", "false", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("ASSISTANT_FORK_EVAL_ENABLED", tc.val)
			}
			cfg, err := Load()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.AssistantForkEvalEnabled != tc.want {
				t.Fatalf("AssistantForkEvalEnabled = %v, want %v", cfg.AssistantForkEvalEnabled, tc.want)
			}
		})
	}
}
