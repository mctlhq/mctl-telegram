package workctx

import "fmt"

// SchemaVersion is the only envelope version this client understands. Any
// response naming a different value is rejected outright — see
// docs/contracts/mctl-api-work-context.md's "workitem/v1 envelope" section
// and the schema-version-rejection acceptance criterion.
const SchemaVersion = "workitem/v1"

// versionedEnvelope is implemented by every response envelope this package
// decodes through relay, so relay can check schema_version generically
// without a type switch per route.
type versionedEnvelope interface {
	schemaVersion() string
}

// validatedEnvelope is implemented by response envelopes that carry a
// required field relay cannot leave unchecked. A 2xx response that omits it
// (whether the body is empty or just missing the field) must not be treated
// as success: the caller would persist the zero value as a durable
// identifier — for ItemView that is an empty WorkItem.ID written into a
// work-item binding — and every subsequent command on that thread would
// then operate on an empty id, wedging the owner's whole Saved Messages
// command channel on what looks like a permanently "open" binding.
type validatedEnvelope interface {
	validate() error
}

// emptyBodyTolerant is implemented by response envelopes for which an empty
// 2xx body (e.g. 204 No Content) is a legitimate success: a list read that
// persists nothing, where "no body" honestly means "no entries". Every other
// envelope keeps the strict empty-body rejection above.
type emptyBodyTolerant interface {
	emptyBodyMeansNone()
}

// validate reports an error when WorkItem.ID is empty. Every route that
// returns an ItemView (POST /api/v1/work-items, GET
// /api/v1/work-items/{id}) promises at least this field per envelope.go's
// ItemView doc, so a response missing it is malformed, not merely sparse.
func (v *ItemView) validate() error {
	if v.WorkItem.ID == "" {
		return fmt.Errorf("%w: response missing work_item.id", ErrIncompatibleSchema)
	}
	return nil
}

// WorkItemDTO is the work_item object nested in ItemView. Deliberately thin
// — this package reads it for correlation and status rendering only, never
// to make policy decisions (those are mctl-api's).
type WorkItemDTO struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	Title  string `json:"title"`
	State  string `json:"state"`
}

// ExecutionRef is the latest_execution pointer on an ItemView. ExecutionID
// and the rest are read-only facts about platform-owned execution identity
// — this package never constructs one.
type ExecutionRef struct {
	ExecutionID string `json:"execution_id"`
	State       string `json:"state,omitempty"`
}

// ApprovalRef is the pending_approval pointer on an ItemView.
type ApprovalRef struct {
	ID string `json:"id"`
}

// SnapshotRef is the latest_snapshot pointer on an ItemView.
type SnapshotRef struct {
	SnapshotID string `json:"snapshot_id"`
}

// ItemView is the workitem/v1 item view returned by
// POST /api/v1/work-items and GET /api/v1/work-items/{id}. The open
// question in requirements.md ("does POST return the full view, or a bare
// id?") is handled by tolerating a response that carries only WorkItem.ID
// and StateVersion — every field below is optional from this package's
// point of view except those two.
type ItemView struct {
	SchemaVersionField string        `json:"schema_version"`
	WorkItem           WorkItemDTO   `json:"work_item"`
	StateVersion       int64         `json:"state_version"`
	LatestExecution    *ExecutionRef `json:"latest_execution,omitempty"`
	PendingApproval    *ApprovalRef  `json:"pending_approval,omitempty"`
	LatestSnapshot     *SnapshotRef  `json:"latest_snapshot,omitempty"`
}

func (v *ItemView) schemaVersion() string { return v.SchemaVersionField }

// ExecutionRequestView is the mctl-api#368 execution-request view: what
// GET .../execution-requests[/{id}] and the POST that creates one return.
// ExecutionID and Reason are only ever read back, never sent — this package
// has no field anywhere a caller can set either one.
//
// State is one of: pending, claimed, fulfilled, rejected.
type ExecutionRequestView struct {
	SchemaVersionField string `json:"schema_version"`
	ID                 string `json:"id"`
	Kind               string `json:"kind"`
	State              string `json:"state"`
	ExecutionID        string `json:"execution_id,omitempty"`
	Reason             string `json:"reason,omitempty"`
}

func (v *ExecutionRequestView) schemaVersion() string { return v.SchemaVersionField }

// validate reports an error when ID is empty: handleOpen and handleResume
// persist it as the binding's last_request_id and echo it to the owner.
func (v *ExecutionRequestView) validate() error {
	if v.ID == "" {
		return fmt.Errorf("%w: response missing execution request id", ErrIncompatibleSchema)
	}
	return nil
}

// executionRequestListEnvelope is the wire shape of
// GET /api/v1/work-items/{id}/execution-requests (no id): a list, newest
// first per docs/contracts/mctl-api-work-context.md.
type executionRequestListEnvelope struct {
	SchemaVersionField string                 `json:"schema_version"`
	ExecutionRequests  []ExecutionRequestView `json:"execution_requests"`
}

func (v *executionRequestListEnvelope) schemaVersion() string { return v.SchemaVersionField }

func (v *executionRequestListEnvelope) emptyBodyMeansNone() {}

// Execution request kinds — the only two values RequestExecution.Kind may
// hold. There is deliberately no "wake" or "attach" kind: this package only
// ever asks the platform to run or continue, never declares execution
// identity itself.
const (
	ExecutionKindStart  = "start"
	ExecutionKindResume = "resume"
)

// Execution request states, as rendered by /mctl work status.
const (
	RequestStatePending   = "pending"
	RequestStateClaimed   = "claimed"
	RequestStateFulfilled = "fulfilled"
	RequestStateRejected  = "rejected"
)

// Work item states, as returned on WorkItemDTO.State.
const (
	ItemStateActive     = "active"
	ItemStateWaiting    = "waiting"
	ItemStateCompleted  = "completed"
	ItemStateSuperseded = "superseded"
	ItemStateArchived   = "archived"
)
