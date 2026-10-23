package telegram

import (
	"testing"
	"time"

	"github.com/gotd/td/telegram/dcs"
)

func TestDCList(t *testing.T) {
	if !dcList(false).Zero() {
		t.Error("dcList(false) is not the zero List gotd replaces with dcs.Prod()")
	}
	got, want := dcList(true), dcs.Test()
	if got.Zero() || len(got.Options) != len(want.Options) {
		t.Fatalf("dcList(true) has %d options, want dcs.Test()'s %d", len(got.Options), len(want.Options))
	}
	for i := range want.Options {
		if got.Options[i].IPAddress != want.Options[i].IPAddress {
			t.Fatalf("dcList(true).Options[%d] = %s, want %s", i, got.Options[i].IPAddress, want.Options[i].IPAddress)
		}
	}
}

// Every client constructor must carry the setting through; dcList alone
// being right proves nothing about the clients built from it.
func TestClientOptionsCarryTestDC(t *testing.T) {
	for _, on := range []bool{false, true} {
		pool := NewClientPool(1, "hash", time.Minute, nil).WithTestDC(on)
		if got := pool.clientOptions(&SessionStore{}).DCList.Zero(); got == on {
			t.Errorf("pool WithTestDC(%v): DCList.Zero() = %v", on, got)
		}
		if got := loginClientOptions(&SessionStore{}, LoginConfig{TestDC: on}).DCList.Zero(); got == on {
			t.Errorf("login TestDC=%v: DCList.Zero() = %v", on, got)
		}
	}
}
