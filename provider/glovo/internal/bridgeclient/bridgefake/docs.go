package bridgefake

import (
	"fmt"
	"sync/atomic"
)

var seq atomic.Int64

func nextID() string { return fmt.Sprintf("cmd_%026d", seq.Add(1)) }

// Command builds a schema-valid v1alpha1 command document of the given kind
// for the synthetic personas of the tests. Mutating kinds carry approval_ref.
func Command(kind string) map[string]any {
	d := map[string]any{
		"schema_version": "bridge.mctl.ai/v1alpha1", "command_id": nextID(),
		"execution_id": "we_0123456789abcdef0123", "work_item_id": "wi_0123456789abcdef0123",
		"kind": kind, "attempt": 1, "tenant_ref": "tnr_0123456789abcdef0123", "principal_ref": "prr_0123456789abcdef0123",
		"order_ref": "ordr_0123456789abcdef0123", "connection_ref": "gcn_0123456789abcdef0123",
		"intent_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"issuer":      "mctl-api", "audience": "provider:glovo", "nonce": "AAAAAAAAAAAAAAAAAAAAAA",
		"issued_at": "2026-11-08T10:00:00Z", "expires_at": "2099-01-01T00:00:00Z", "ttl_seconds": 600,
		"cancel_requested": false,
		"payload":          map[string]any{"item_codes": []any{"FAKE-1"}, "quantity_total": 1},
	}
	if kind == "place_order_fake" || kind == "cancel_order_fake" {
		d["approval_ref"] = "aar_0123456789abcdef0123"
	}
	return d
}

// PlaceOrderV2 builds a v1alpha2 place_order_fake document.
func PlaceOrderV2() map[string]any {
	d := Command("place_order_fake")
	d["schema_version"] = "bridge.mctl.ai/v1alpha2"
	d["payload"] = map[string]any{
		"v": "mctl-approval-basket/v1", "store_ref": "pst_0123456789abcdef0123", "currency": "EUR",
		"lines":          []any{map[string]any{"item_code": "FAKE-1", "quantity": 1, "unit_price_minor": 500}},
		"subtotal_minor": 500, "delivery_fee_minor": 199, "service_fee_minor": 50, "discount_minor": 0, "total_minor": 749,
	}
	return d
}
