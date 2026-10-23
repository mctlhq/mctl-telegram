package localjwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMint_Verify_JobBindingRoundtrip(t *testing.T) {
	iss, err := NewIssuer(testSecret, testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := iss.Mint(Claims{
		Subject: "tg:1", TelegramID: 1, Audience: []string{"agent-job"},
		JobID: 11, JobAttempt: 2, ConversationID: 33,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	if c.JobID != 11 || c.JobAttempt != 2 || c.ConversationID != 33 {
		t.Fatalf("claims = %+v", c)
	}
	if !needsRevocationCheck(c) {
		t.Fatal("agent-job tokens must be revocation-checked")
	}
}

func TestMint_OmitsEmptyJobBinding(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"job_id", "job_attempt", "conv_id"} {
		if _, ok := raw[k]; ok {
			t.Errorf("%s present on a token without a job binding", k)
		}
	}
}
