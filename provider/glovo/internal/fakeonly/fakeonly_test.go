package fakeonly

import (
	"errors"
	"strings"
	"testing"
)

func TestRealAdapterNotCompiled(t *testing.T) {
	if RealAdapterCompiled {
		t.Fatal("default build must not contain a real adapter")
	}
}

func TestCheckFakeOnlyValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		ok   bool
	}{
		{"missing", []string{"PATH=/bin"}, false},
		{"false", []string{"FAKE_ONLY=false"}, false},
		{"upper", []string{"FAKE_ONLY=TRUE"}, false},
		{"empty", []string{"FAKE_ONLY="}, false},
		{"true", []string{"FAKE_ONLY=true"}, true},
	} {
		err := Check(tc.env)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.name, err)
		}
		if err != nil && !errors.Is(err, ErrNotFakeOnly) {
			t.Errorf("%s: wrong error %v", tc.name, err)
		}
	}
}

func TestCheckDeniesCredentialNamesWithoutValues(t *testing.T) {
	for _, name := range []string{
		"GLOVO_SESSION_TOKEN", "GLOVO_ACCESS_TOKEN", "GLOVO_SESSION_ID", "GLOVO_COOKIE_JAR",
		"GLOVO_PASSWORD", "GLOVO_USER_PASSWORD", "GLOVO_API_KEY", "GLOVO_BASE_URL", "glovo_session_x",
	} {
		err := Check([]string{"FAKE_ONLY=true", name + "=s3cret-value"})
		if !errors.Is(err, ErrCredentialEnv) {
			t.Errorf("%s: err=%v", name, err)
			continue
		}
		if strings.Contains(err.Error(), "s3cret-value") || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: message must carry the name only: %v", name, err)
		}
	}
}

func TestCheckAllowsUnrelatedGlovoNames(t *testing.T) {
	if err := Check([]string{"FAKE_ONLY=true", "GLOVO_PROVIDER_DISABLED=false"}); err != nil {
		t.Fatal(err)
	}
}
