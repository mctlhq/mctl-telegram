package config

import (
	"testing"
)

// TestConfigReplicaID verifies the three-way fallback for the ReplicaID field:
// REPLICA_ID > POD_NAME > "unknown".
func TestConfigReplicaID(t *testing.T) {
	t.Run("REPLICA_ID set", func(t *testing.T) {
		t.Setenv("REPLICA_ID", "pod-42")
		t.Setenv("POD_NAME", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ReplicaID != "pod-42" {
			t.Errorf("ReplicaID = %q; want %q", cfg.ReplicaID, "pod-42")
		}
	})

	t.Run("POD_NAME fallback", func(t *testing.T) {
		t.Setenv("REPLICA_ID", "")
		t.Setenv("POD_NAME", "mctl-telegram-7f9d")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ReplicaID != "mctl-telegram-7f9d" {
			t.Errorf("ReplicaID = %q; want %q", cfg.ReplicaID, "mctl-telegram-7f9d")
		}
	})

	t.Run("unknown fallback", func(t *testing.T) {
		t.Setenv("REPLICA_ID", "")
		t.Setenv("POD_NAME", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ReplicaID != "unknown" {
			t.Errorf("ReplicaID = %q; want %q", cfg.ReplicaID, "unknown")
		}
	})
}
