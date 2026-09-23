package main

import (
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/config"
)

// broadcastPolicy builds the audience tier policy from the same inputs the
// OAuth server resolves scopes from, so a broadcast's "client" and "admin"
// are exactly what a login would get.
func broadcastPolicy(cfg *config.Config) broadcast.Policy {
	return broadcast.Policy{
		AdminTelegramIDs:       telegramIDSet(cfg.TGLoginAdmins),
		LookupAdminTelegramIDs: telegramIDSet(cfg.TGLoginLookupAdmins),
		ClientTelegramIDs:      telegramIDSet(cfg.TGLoginClients),
		AutoApproveClients:     cfg.AutoApproveClients,
	}
}
