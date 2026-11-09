package v1alpha1

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func good() map[string]any {
	return map[string]any{
		"version": Version, "execution_ref": "we_1", "tenant_ref": "tenant-alpha", "owner_ref": "principal-alice",
		"connection_ref": "gcn_1", "install_ref": "inst-alpha", "install_revision": 1,
		"order_ref": "ord-1", "intent_hash": hash, "approval_ref": "aar_1",
	}
}

func enc(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeGood(t *testing.T) {
	if _, err := Decode(enc(t, good())); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeForbiddenKeys(t *testing.T) {
	for _, k := range []string{"namespace", "workflow_id", "run_id", "task_queue", "role", "url", "endpoint", "cookie", "session", "token", "password", "Token"} {
		m := good()
		m[k] = "x"
		_, err := Decode(enc(t, m))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), strings.ToLower(k)) {
			t.Errorf("%s: err=%v", k, err)
		}
	}
	m := good()
	m["nested"] = map[string]any{"list": []any{map[string]any{"cookie": "x"}}}
	if _, err := Decode(enc(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nested forbidden key accepted: %v", err)
	}
}

func TestDecodeUnknownFieldAndTrailing(t *testing.T) {
	m := good()
	m["surprise"] = 1
	if _, err := Decode(enc(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown field accepted: %v", err)
	}
	if _, err := Decode(append(enc(t, good()), []byte(" {}")...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing data accepted: %v", err)
	}
	if _, err := Decode([]byte("not json")); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed accepted")
	}
}

func TestDecodeMalformedRefs(t *testing.T) {
	for field, bad := range map[string]any{
		"version": "v2", "execution_ref": "gcn_1", "connection_ref": "we_1", "approval_ref": "we_1",
		"tenant_ref": "", "owner_ref": "has space", "install_ref": "../x", "order_ref": strings.Repeat("a", 65),
		"install_revision": 0, "intent_hash": "ABC",
	} {
		m := good()
		m[field] = bad
		_, err := Decode(enc(t, m))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), field) {
			t.Errorf("%s: err=%v", field, err)
		}
	}
	m := good()
	m["execution_ref"] = "we_"
	if _, err := Decode(enc(t, m)); !errors.Is(err, ErrInvalid) {
		t.Fatal("bare prefix accepted")
	}
}

func TestErrorsCarryNoValues(t *testing.T) {
	m := good()
	m["owner_ref"] = "secret value"
	_, err := Decode(enc(t, m))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err=%v", err)
	}
}

func TestRequireApproval(t *testing.T) {
	m := good()
	delete(m, "approval_ref")
	r, err := Decode(enc(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.RequireApproval(); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing approval accepted")
	}
}
