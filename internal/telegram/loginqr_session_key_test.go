package telegram

import (
	"errors"
	"testing"
)

func TestSessionAuthKeyID(t *testing.T) {
	valid := `{"Version":1,"Data":{"DC":2,"Addr":"x","AuthKey":"AQID","AuthKeyID":"BAUG"}}`
	id, err := SessionAuthKeyID([]byte(valid))
	if err != nil || id != "040506" {
		t.Fatalf("id = %q err = %v", id, err)
	}
	if _, err := SessionAuthKeyID(nil); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("empty: %v", err)
	}
	if _, err := SessionAuthKeyID([]byte(`{"Version":1,"Data":{"DC":2}}`)); !errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := SessionAuthKeyID([]byte(`{not json`)); err == nil || errors.Is(err, ErrNoAuthKey) {
		t.Fatalf("malformed must be an error, never no key: %v", err)
	}
}
