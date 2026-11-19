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

package output

// Template is server-authored message text. Its field is unexported, so
// code outside this package cannot make one from a string, by conversion, a
// type alias or a generic: the only Templates are the variables declared in
// this file, each built by tpl from a string literal
// (TestTemplatesAreLiteralRegistry). That is what keeps model text from
// skipping Render through ServerText. The zero Template is empty.
type Template struct {
	s string
}

// tpl builds a registry entry. Call it only in this file, only with a
// string literal.
func tpl(s string) Template { return Template{s: s} }

// The registry. Later slices add their server texts here (consent prompt,
// /new and /forget confirmations, button labels), each as a literal.
var (
	// LabelCancel is a generic Cancel button label.
	LabelCancel = tpl("Cancel")
)
