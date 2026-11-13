// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cimd

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The /platforms page shows integrators a client-metadata.json to copy. That
// example must pass this package's own document parser, or the page teaches
// a document the server refuses.
func TestPlatformsPageCIMDExampleParses(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "web", "platforms.html"))
	if err != nil {
		t.Fatalf("read platforms.html: %v", err)
	}
	m := regexp.MustCompile(`(?s)<code id="cimd-example">(.*?)</code>`).FindSubmatch(page)
	if m == nil {
		t.Fatal(`platforms.html has no <code id="cimd-example"> block`)
	}
	body := []byte(html.UnescapeString(string(m[1])))
	const clientID = "https://platform.example/oauth/client-metadata.json"
	doc, err := parseDocument(body, clientID)
	if err != nil {
		t.Fatalf("the /platforms CIMD example is refused by the parser: %v", err)
	}
	if doc.AuthMethod != AuthMethodPrivateKeyJWT || doc.SigningAlg == "" || doc.JWKSURI == "" {
		t.Fatalf("example should be a complete private_key_jwt document, got %+v", doc)
	}
	if len(doc.RedirectURIs) != 1 || len(doc.DroppedRedirectURIs) != 0 {
		t.Fatalf("example redirect_uris: accepted %v, dropped %v", doc.RedirectURIs, doc.DroppedRedirectURIs)
	}
}
