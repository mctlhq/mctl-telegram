//go:build l2finance

package listener

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func l2Push(t *testing.T, l *Listener, acct *account, msg *tg.Message) {
	t.Helper()
	upd := &tg.Updates{
		Updates: []tg.UpdateClass{&tg.UpdateNewMessage{Message: msg}},
		Users:   []tg.UserClass{&tg.User{ID: l2BobTG, FirstName: "Bob"}},
	}
	if err := l.dispatcherFor(acct).Handle(context.Background(), upd); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
}

func l2SelfMsg(id int, out bool, text string) *tg.Message {
	return &tg.Message{ID: id, Out: out, PeerID: &tg.PeerUser{UserID: selfTG}, Message: text}
}

func l2Cursor(t *testing.T, h *l2Harness) int64 {
	t.Helper()
	return cursorForTest(t, h.store, h.uid)
}

func l2Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestL2Finance_T1_ListenerStatus(t *testing.T) {
	h := l2NewHarness(t)
	l2Push(t, h.l, h.acct, l2SelfMsg(10, true, "/mctl status"))
	l2Must(t, l2CheckRoutedOnce(h, 1))
	l2Must(t, l2CheckSavedEvents(h, 1))
	if got := h.sink.snapshot()[0].text; !strings.Contains(got, "Mode: observe") {
		t.Fatalf("reply = %q, want Mode: observe", got)
	}
	l2Record(t, "T1.listener_status", l2Pass, "one owner reply, one saved_command event, peer sink empty")
}

// The canonical #1244 T1 contract distinguishes a working /mctl status
// command from the finance verb which is not implemented. Do not turn this
// absence into a security PASS, and fail if the rubric changes silently.
func TestL2Finance_T1_FinanceCommandNotImplemented(t *testing.T) {
	h := l2NewHarness(t)
	l2Push(t, h.l, h.acct, l2SelfMsg(13, true, "/mctl finance"))
	l2Must(t, l2CheckRoutedOnce(h, 1))
	l2Must(t, l2CheckSavedEvents(h, 1))
	reply := h.sink.snapshot()[0].text
	if !strings.HasPrefix(reply, "Unknown command. Try:\n/mctl status") || strings.Contains(reply, "/mctl finance") {
		t.Fatalf("finance verb unexpectedly recognized: %q; rubric must be reviewed", reply)
	}
	l2Record(t, "T1.finance_command", l2NotImplemented,
		"owner-only unknownCommandReply observed; no finance command or peer send")
}

func TestL2Finance_T2_BobDM(t *testing.T) {
	h := l2NewHarness(t)
	l2Push(t, h.l, h.acct, &tg.Message{ID: 11, PeerID: &tg.PeerUser{UserID: l2BobTG}, Message: "/mctl status"})
	l2Must(t, l2CheckNotRouted(h))
	priv, err := l2CountEvents(h, db.EventKindPrivateMessage)
	l2Must(t, err)
	l2Record(t, "T2.bob_dm", l2Pass, "not routed; no saved_command event; private_message events="+itoa(priv))
}

func TestL2Finance_T2_SpoofFrom(t *testing.T) {
	h := l2NewHarness(t)
	m := l2SelfMsg(12, false, "/mctl status")
	m.SetFromID(&tg.PeerUser{UserID: l2BobTG})
	l2Push(t, h.l, h.acct, m)
	l2Must(t, l2CheckNotRouted(h))
	l2Record(t, "T2.spoof_from", l2Pass, "self peer with foreign from_id not routed")
}

func TestL2Finance_T4_GroupChat(t *testing.T) {
	h := l2NewHarness(t)
	for i, out := range []bool{true, false} {
		l2Push(t, h.l, h.acct, &tg.Message{ID: 13 + i, Out: out, PeerID: &tg.PeerChat{ChatID: 1}, Message: "/mctl status"})
	}
	l2Must(t, l2CheckNotRouted(h))
	all, err := l2CountEvents(h, "")
	l2Must(t, err)
	if all != 0 {
		t.Fatalf("events = %d, want 0", all)
	}
	l2Record(t, "T4.group_chat", l2Pass, "Out true and false not routed, no event")
}

func TestL2Finance_T4_Channel(t *testing.T) {
	h := l2NewHarness(t)
	for i, out := range []bool{true, false} {
		l2Push(t, h.l, h.acct, &tg.Message{ID: 15 + i, Out: out, PeerID: &tg.PeerChannel{ChannelID: 2}, Message: "/mctl status"})
	}
	l2Must(t, l2CheckNotRouted(h))
	all, err := l2CountEvents(h, "")
	l2Must(t, err)
	if all != 0 {
		t.Fatalf("events = %d, want 0", all)
	}
	l2Record(t, "T4.channel", l2Pass, "Out true and false not routed, no event")
}

func TestL2Finance_T4_Forwarded(t *testing.T) {
	h := l2NewHarness(t)
	m := l2SelfMsg(17, true, "/mctl status")
	m.SetFwdFrom(tg.MessageFwdHeader{Date: 1})
	l2Push(t, h.l, h.acct, m)
	l2Must(t, l2CheckNotRouted(h))
	l2Record(t, "T4.forwarded", l2Pass, "forwarded self message not routed")
}

func TestL2Finance_T4_SavedPeer(t *testing.T) {
	h := l2NewHarness(t)
	m := l2SelfMsg(18, true, "/mctl status")
	m.SetSavedPeerID(&tg.PeerUser{UserID: l2BobTG})
	l2Push(t, h.l, h.acct, m)
	l2Must(t, l2CheckNotRouted(h))
	l2Record(t, "T4.saved_peer", l2Pass, "foreign saved_peer_id not routed")
}

func TestL2Finance_T5_1_PushThenHistory(t *testing.T) {
	h := l2NewHarness(t)
	ctx := context.Background()
	l2Must(t, h.store.AdvanceSavedCommandCursor(ctx, h.uid, 19))
	l2Push(t, h.l, h.acct, l2SelfMsg(20, true, "/mctl status"))
	api := &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{l2SelfMsg(20, false, "/mctl status")}}}}
	l2Must(t, h.l.pollSavedHistory(ctx, h.acct, api))
	l2Must(t, l2CheckRoutedOnce(h, 1))
	if c := l2Cursor(t, h); c != 20 {
		t.Fatalf("cursor = %d, want 20", c)
	}
	l2Record(t, "T5.1.push_then_history", l2Pass, "1 reply total; cursor=20")
}

func TestL2Finance_T5_3_CursorMonotonic(t *testing.T) {
	h := l2NewHarness(t)
	ctx := context.Background()
	l2Must(t, h.store.AdvanceSavedCommandCursor(ctx, h.uid, 20))
	h.sink.failNext = 1
	cmd := func(id int) tg.MessageClass { return l2SelfMsg(id, false, "/mctl status") }
	api := &fakeSavedHistoryAPI{results: []historyResult{
		{messages: []tg.MessageClass{l2SelfMsg(21, false, "just a note"), cmd(22), cmd(23)}},
		{messages: []tg.MessageClass{cmd(22), cmd(23)}},
	}}
	if err := h.l.pollSavedHistory(ctx, h.acct, api); err == nil {
		t.Fatal("first poll: want routing error")
	}
	first := l2Cursor(t, h)
	if first != 21 {
		t.Fatalf("cursor after failed route = %d, want 21", first)
	}
	l2Must(t, h.l.pollSavedHistory(ctx, h.acct, api))
	second := l2Cursor(t, h)
	if second != 23 || second < first {
		t.Fatalf("cursor = %d, want 23 and monotonic", second)
	}
	l2Must(t, l2CheckRoutedOnce(h, 2))
	l2Record(t, "T5.3.cursor_monotonic", l2Pass, "cursor 21 then 23; 22 and 23 routed once each")
}

func TestL2Finance_T6_OutFalsePush(t *testing.T) {
	h := l2NewHarness(t)
	l2Push(t, h.l, h.acct, l2SelfMsg(30, false, "/mctl status"))
	l2Must(t, l2CheckRoutedOnce(h, 1))
	l2Record(t, "T6.out_false_push", l2Pass, "Out=false self push routed once")
}

func TestL2Finance_T6_ReconnectReplay(t *testing.T) {
	h := l2NewHarness(t)
	ctx := context.Background()
	l2Must(t, h.store.AdvanceSavedCommandCursor(ctx, h.uid, 39))
	l2Push(t, h.l, h.acct, l2SelfMsg(40, false, "/mctl status"))
	// Simulated reconnect/restart: a fresh Listener on the same store.
	l2 := New(h.store, h.l.Queue, h.l.Router, nil)
	acct2 := &account{userID: h.uid, tgID: selfTG}
	l2Push(t, l2, acct2, l2SelfMsg(40, false, "/mctl status"))
	api := &fakeSavedHistoryAPI{results: []historyResult{{messages: []tg.MessageClass{l2SelfMsg(40, false, "/mctl status")}}}}
	l2Must(t, l2.pollSavedHistory(ctx, acct2, api))
	l2Must(t, l2CheckRoutedOnce(h, 1))
	l2Must(t, l2CheckSavedEvents(h, 1))
	if c := l2Cursor(t, h); c != 40 {
		t.Fatalf("cursor = %d, want 40", c)
	}
	l2Record(t, "T6.reconnect_replay", l2Pass, "replay by push and history on a second Listener produced no second reply")
}

func TestL2Finance_T6_Gap(t *testing.T) {
	l2Record(t, "T6.gap", l2CannotObserve, "updates.Manager getDifference needs a fake MTProto server; not built in this slice")
}

// M1: bypass the classifier by handing persistExtracted a hand-built saved
// command for Bob. The T2 helper must detect the resulting routing.
func TestL2Finance_M1_ClassifierBypass(t *testing.T) {
	h := l2NewHarness(t)
	ex := Extracted{Event: db.IncomingEvent{
		EventID: "evt:v1:100:600:50", UserID: h.uid, Kind: db.EventKindSavedCommand,
		ChatTGID: l2BobTG, SenderTGID: l2BobTG, MessageID: 50, Body: "/mctl status",
	}, SavedCommandText: "/mctl status"}
	l2Must(t, h.l.persistExtracted(context.Background(), h.acct, ex))
	if l2CheckNotRouted(h) == nil {
		t.Fatal("negative control M1 not detected")
	}
	l2Record(t, "M1", l2Pass, "detected")
}

func itoa(n int) string { return strconv.Itoa(n) }

// TestL2Finance_OfflineGuard shows that the DEFAULT transport and resolver
// refuse non-loopback traffic. It is not a whole-process egress firewall.
func TestL2Finance_OfflineGuard(t *testing.T) {
	tr := http.DefaultTransport.(*http.Transport)
	if _, err := tr.DialContext(context.Background(), "tcp", "192.0.2.1:443"); !errors.Is(err, errL2ExternalDial) {
		t.Fatalf("TEST-NET-1 dial err = %v, want errL2ExternalDial", err)
	}
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "example.invalid"); err == nil ||
		!strings.Contains(err.Error(), errL2ExternalDial.Error()) {
		t.Fatalf("DNS lookup err = %v, want refusal", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c, err := tr.DialContext(context.Background(), "tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("loopback dial: %v", err)
	}
	_ = c.Close()
	l2Record(t, "OFFLINE.default_paths", l2Pass, "TEST-NET-1 dial and external DNS refused via http.DefaultTransport and net.DefaultResolver; loopback allowed")
	l2Record(t, "OFFLINE.whole_process", l2CannotObserve, "custom net.Dialer, custom transports and gotd internals are not intercepted; no gotd client is constructed")
}
