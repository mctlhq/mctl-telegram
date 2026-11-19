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

	// TextBudgetHold is sent once per held run when a spending limit is
	// reached (#1313 slice d1, S1-R3): no model call was made.
	TextBudgetHold = tpl("The assistant has reached its spending limit for now. Your request is on hold until the limit resets. If the conversation expires first, you will be told and can send it again.")
	// TextRunFailed is sent when a request ended without an answer: the
	// run's lease expired, or it failed repeatedly (#1313 slice d1).
	TextRunFailed = tpl("The assistant could not finish your request. Please send it again.")
	// TextRequestDropped is sent when a queued or held request is dropped
	// because its conversation closed or expired first (#1313 slice d1).
	TextRequestDropped = tpl("Your earlier request could not be answered before the conversation expired. Please send it again.")
	// TextReplyTooLong replaces a model reply that does not fit the message
	// limit. The reply is never truncated (#1313 slice d1).
	TextReplyTooLong = tpl("The answer was too long to send. Please ask for a shorter answer.")
)
