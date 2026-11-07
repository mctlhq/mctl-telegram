package fakeglovo

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func setup(t *testing.T) (*Server, *Client) {
	t.Helper()
	s := New()
	t.Cleanup(s.Close)
	s.AddSession("tok", "addr-ref")
	c, err := NewClient(s.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func TestT1_SearchMenuStructuredAndSanitized(t *testing.T) {
	_, c := setup(t)
	stores, err := c.SearchStores(context.Background(), "pizz")
	if err != nil || len(stores) != 1 || stores[0].ID != "s1" {
		t.Fatalf("stores = %v err = %v", stores, err)
	}
	menu, err := c.GetMenu(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range menu {
		if strings.ContainsAny(it.Name, ".,:;!?") || len(it.Name) > 24 {
			t.Fatalf("unsanitized name %q", it.Name)
		}
		if strings.Contains(it.Name, "session token") {
			t.Fatalf("raw menu text leaked: %q", it.Name)
		}
	}
}

func TestT2_RepeatPreviousOrderWithoutDrink(t *testing.T) {
	_, c := setup(t)
	ctx := context.Background()
	menu, _ := c.GetMenu(ctx, "s1")
	orders, err := c.GetPastOrders(ctx)
	if err != nil || len(orders) != 1 || orders[0].Weekday != "Wednesday" {
		t.Fatal("no past order")
	}
	d := RepeatWithout(menu, orders[0], "drink")
	if len(d.Lines) != 1 || d.Lines[0].ItemID != "m1" {
		t.Fatalf("draft = %+v", d)
	}
	q, err := c.QuoteBasket(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if q.Fingerprint != Fingerprint(q) || q.Total != 800+199 {
		t.Fatalf("quote = %+v", q)
	}
	full, _ := c.QuoteBasket(ctx, orders[0].Draft)
	if full.Fingerprint == q.Fingerprint {
		t.Fatal("dropping the drink must change the fingerprint")
	}
}

func TestT3_Modifiers(t *testing.T) {
	_, c := setup(t)
	menu, _ := c.GetMenu(context.Background(), "s1")
	missing := Draft{Store: "s1", Lines: []Line{{ItemID: "m1", Qty: 1}}}
	if err := Validate(menu, missing); !errors.Is(err, ErrMissingModifier) {
		t.Fatalf("err = %v", err)
	}
	bad := Draft{Store: "s1", Lines: []Line{{ItemID: "m1", Qty: 1, Modifiers: map[string]string{"size": "huge"}}}}
	if err := Validate(menu, bad); !errors.Is(err, ErrInvalidModifier) {
		t.Fatalf("err = %v", err)
	}
	stray := Draft{Store: "s1", Lines: []Line{{ItemID: "m2", Qty: 1, Modifiers: map[string]string{"x": "y"}}}}
	if err := Validate(menu, stray); !errors.Is(err, ErrInvalidModifier) {
		t.Fatalf("err = %v", err)
	}
}

func TestAvailabilityAndFeeChangeFingerprint(t *testing.T) {
	s, c := setup(t)
	ctx := context.Background()
	d := Draft{Store: "s1", Lines: []Line{{ItemID: "m2", Qty: 1}}}
	q1, _ := c.QuoteBasket(ctx, d)
	s.SetFee(250)
	q2, _ := c.QuoteBasket(ctx, d)
	if q1.Fingerprint == q2.Fingerprint {
		t.Fatal("fee change must change fingerprint")
	}
	s.SetAvailable("m2", false)
	if _, err := c.QuoteBasket(ctx, d); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRefusesNonLoopback(t *testing.T) {
	for _, u := range []string{"https://example.com", "http://10.0.0.5:80", "http://169.254.169.254"} {
		if _, err := NewClient(u, "t"); !errors.Is(err, ErrNonLoopback) {
			t.Fatalf("%s: err = %v", u, err)
		}
	}
}

func TestSessionsAreIsolated(t *testing.T) {
	s, c := setup(t)
	s.AddSession("other", "addr-2")
	s.SeedCart("other", Draft{Store: "s1", Lines: []Line{{ItemID: "m2", Qty: 9}}})
	d, err := c.ReadCart(context.Background())
	if err != nil || len(d.Lines) != 0 {
		t.Fatalf("cart leaked across sessions: %+v %v", d, err)
	}
}
