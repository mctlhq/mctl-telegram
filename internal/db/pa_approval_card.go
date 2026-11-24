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

package db

import (
	"context"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
)

// PAApprovalForCard returns principal's approval whose Approve callback is
// approveCallbackID, with its sealed arguments, for the deliverer that
// builds the approval card (#1320 slice P2-S5). The read is keyed by
// (principal, callback id) like every read of the ledger (I10): another
// principal's id is approval.ErrNotFound. An approval that ended has no
// arguments left; the caller decides from its status. A failed read wraps
// approval.ErrUnreadable and says nothing about the approval (I9).
func (s *Store) PAApprovalForCard(ctx context.Context, principal int64, approveCallbackID string) (approval.Approval, error) {
	if principal <= 0 || approveCallbackID == "" {
		return approval.Approval{}, fmt.Errorf("%w: approval for card", approval.ErrInvalid)
	}
	var sealed []byte
	a, err := scanPAApproval(s.DB.QueryRowContext(ctx,
		`SELECT `+paApprovalCols+`, sealed_args FROM pa_approvals WHERE principal = $1 AND approve_cb_id = $2`,
		principal, approveCallbackID), &sealed)
	if err != nil {
		return approval.Approval{}, err
	}
	a.SealedArgs = sealed
	return a, nil
}
