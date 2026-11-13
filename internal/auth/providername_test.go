package auth

import (
	"net/http"
	"testing"
)

type sharedhmacStub struct{}

func (sharedhmacStub) Authenticate(*http.Request) (*Identity, error) { return nil, nil }

type frontStub struct{ next Provider }

func (frontStub) Authenticate(*http.Request) (*Identity, error) { return nil, nil }
func (f frontStub) Unwrap() Provider                            { return f.next }

func TestProviderName_LabelsWrapperByWrappedProvider(t *testing.T) {
	if got := providerName(frontStub{next: sharedhmacStub{}}); got != "shared-hmac" {
		t.Fatalf("providerName(wrapper) = %q, want shared-hmac", got)
	}
}
