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

import (
	"sync"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// maxLanguages bounds Languages: past it the map starts over, and the
// principals it forgot get English until their next update.
const maxLanguages = 10000

// Languages remembers the language of each principal's Telegram client, as
// the last accepted update reported it (from.language_code). It is a
// display preference, not state anything depends on: a principal it does
// not know, after a restart or on another replica, is answered in English.
// The zero value is not usable; a nil *Languages answers English.
type Languages struct {
	mu sync.Mutex
	m  map[int64]safetext.Lang
}

// NewLanguages returns an empty Languages.
func NewLanguages() *Languages {
	return &Languages{m: map[int64]safetext.Lang{}}
}

// Set records the language_code of principal's latest update. An empty
// code leaves the recorded language as it is: Telegram omits the field
// for some updates.
func (l *Languages) Set(principal int64, code string) {
	if l == nil || principal <= 0 || code == "" {
		return
	}
	lang := safetext.LangOf(code)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.m[principal]; !ok && len(l.m) >= maxLanguages {
		l.m = map[int64]safetext.Lang{}
	}
	l.m[principal] = lang
}

// Of returns the principal's language, English when unknown.
func (l *Languages) Of(principal int64) safetext.Lang {
	if l == nil {
		return safetext.LangEN
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[principal]
}
