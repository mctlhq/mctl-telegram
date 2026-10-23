package telegram

import (
	"testing"

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
