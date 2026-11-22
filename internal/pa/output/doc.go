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

// Package output is the only way the Personal Assistant bot sends anything
// to Telegram. It implements the sending half of threat model T14, output
// exfiltration through the bot's own messages
// (docs/agent-runtime/personal-assistant-threat-model.md); package
// safetext builds the only values it sends.
//
//   - Sender takes a safetext.Text, which only safetext.Render (model text)
//     and safetext.ServerText (server templates) can build. A string cannot
//     be sent.
//   - Sender sends plain text only (no parse_mode, no entities), with link
//     previews disabled on every message, and inline keyboards made only of
//     server-authored callback buttons. A URL, login, web app or inline
//     query button cannot be expressed in a Keyboard.
//   - The one exception is SendWebApp: a single web_app button whose URL
//     must be exactly the configured linking Mini App URL (PA_APP_URL) with
//     a link token, for /connect (threat model T1 step 1). Any other URL is
//     refused before anything is sent.
//
// A static test (TestS1O1_SenderIsTheOnlyBotAPICallSite) keeps every Bot API
// send method and raw Bot API URL under internal/pa inside sender.go.
//
// cmd/server builds the Sender only for the PA runtime, which PA_ENABLED
// (default off) gates.
package output
