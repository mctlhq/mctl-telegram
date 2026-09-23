package main

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// The broadcast audience tiers must come from the same allowlists the OAuth
// server resolves scopes from; a swapped field would silently widen or
// narrow every "client"/"admin" campaign.
func TestBroadcastPolicyMirrorsLoginAllowlists(t *testing.T) {
	p := broadcastPolicy(&config.Config{
		TGLoginAdmins:       []int64{1},
		TGLoginLookupAdmins: []int64{2},
		TGLoginClients:      []int64{3},
		AutoApproveClients:  true,
	})
	if !p.AdminTelegramIDs[1] || len(p.AdminTelegramIDs) != 1 {
		t.Fatalf("admins = %v", p.AdminTelegramIDs)
	}
	if !p.LookupAdminTelegramIDs[2] || len(p.LookupAdminTelegramIDs) != 1 {
		t.Fatalf("lookup admins = %v", p.LookupAdminTelegramIDs)
	}
	if !p.ClientTelegramIDs[3] || len(p.ClientTelegramIDs) != 1 {
		t.Fatalf("clients = %v", p.ClientTelegramIDs)
	}
	if !p.AutoApproveClients {
		t.Fatal("AutoApproveClients not carried over")
	}
}
