package telegram

import "github.com/gotd/td/telegram/dcs"

// dcList returns the MTProto datacenter list for a client: Telegram's test
// configuration when testDC is set (issue #854; test accounts are numbers
// 99966XYYYY whose login code is the DC digit five times, see
// https://core.telegram.org/api/auth#test-accounts), and gotd's production
// default otherwise. A zero List is what gotd itself replaces with
// dcs.Prod(), so production stays exactly what it was.
//
// The test DCs hold their own accounts: a session created on one side is
// unknown on the other, and the pool revokes a session Telegram rejects.
// That is why every process that can open stored sessions also checks the
// store's DC stamp (db.Store.EnsureDCMode) before it builds a client.
func dcList(testDC bool) dcs.List {
	if testDC {
		return dcs.Test()
	}
	return dcs.List{}
}
