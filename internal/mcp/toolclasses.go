package mcp

// toolTier is the effect class of a tool: what calling it can do to the
// caller's Telegram account or to server state.
type toolTier int

const (
	// tierRead changes nothing beyond the audit row every call writes.
	tierRead toolTier = iota + 1
	// tierWrite adds or changes state without destroying any.
	tierWrite
	// tierDestructive can remove, revoke or overwrite state, or acts on
	// Telegram in a way the caller cannot take back (a sent message).
	tierDestructive
)

// toolClass is a tool's classification, declared once for the whole surface
// (mctl-telegram#1174). The readOnly and destructive hints each builder sets
// must agree with tier, and TestToolClasses_CoverAndAgreeWithRegistry fails
// when a tool is missing here or disagrees. The idempotent hint is applied
// from this table at registration (addTool), so it cannot drift.
type toolClass struct {
	tier toolTier
	// idempotent: repeating the call with the same arguments has no further
	// effect, so a client may retry it. Only reads are marked. Reads tied to a
	// one-shot confirmation are not: prepare_get_media and draft_reply issue a
	// fresh one per call, and get_media consumes the one it is given. Writes
	// stay unmarked until a handler is shown to have no repeated side effect:
	// a false "no" costs a client a retry it could have made; a false "yes"
	// invites one it should not.
	idempotent bool
}

// toolClasses classifies every registered tool. A new tool must be added here
// in the same change, or the coverage test fails.
var toolClasses = map[string]toolClass{
	// Reads.
	"draft_reply":                     {tier: tierRead, idempotent: false},
	"get_acquisition_report":          {tier: tierRead, idempotent: true},
	"get_broadcast":                   {tier: tierRead, idempotent: true},
	"get_media":                       {tier: tierRead, idempotent: false},
	"get_messages":                    {tier: tierRead, idempotent: true},
	"get_my_audit_log":                {tier: tierRead, idempotent: true},
	"get_my_identity":                 {tier: tierRead, idempotent: true},
	"get_my_notification_preferences": {tier: tierRead, idempotent: true},
	"get_my_send_status":              {tier: tierRead, idempotent: true},
	"get_unread_messages":             {tier: tierRead, idempotent: true},
	"get_user_audit_log":              {tier: tierRead, idempotent: true},
	"list_assistants":                 {tier: tierRead, idempotent: true},
	"list_broadcasts":                 {tier: tierRead, idempotent: true},
	"list_dialogs":                    {tier: tierRead, idempotent: true},
	"list_telegram_identities":        {tier: tierRead, idempotent: true},
	"prepare_get_media":               {tier: tierRead, idempotent: false},
	"search_messages":                 {tier: tierRead, idempotent: true},
	// Writes that destroy nothing.
	"fork_assistant":       {tier: tierWrite, idempotent: false},
	"prepare_broadcast":    {tier: tierWrite, idempotent: false},
	"prepare_pin_message":  {tier: tierWrite, idempotent: false},
	"prepare_send_message": {tier: tierWrite, idempotent: false},
	"update_fork":          {tier: tierWrite, idempotent: false},
	// Destructive.
	"cancel_broadcast":                {tier: tierDestructive, idempotent: false},
	"delete_fork":                     {tier: tierDestructive, idempotent: false},
	"delete_messages":                 {tier: tierDestructive, idempotent: false},
	"delete_telegram_account":         {tier: tierDestructive, idempotent: false},
	"disconnect_telegram_account":     {tier: tierDestructive, idempotent: false},
	"edit_message":                    {tier: tierDestructive, idempotent: false},
	"forward_messages":                {tier: tierDestructive, idempotent: false},
	"install_assistant":               {tier: tierDestructive, idempotent: false},
	"mint_worker_token":               {tier: tierDestructive, idempotent: false},
	"pin_message":                     {tier: tierDestructive, idempotent: false},
	"provision_local_account":         {tier: tierDestructive, idempotent: false},
	"revoke_local_bridge_device":      {tier: tierDestructive, idempotent: false},
	"revoke_telegram_session":         {tier: tierDestructive, idempotent: false},
	"revoke_worker_token":             {tier: tierDestructive, idempotent: false},
	"send_media":                      {tier: tierDestructive, idempotent: false},
	"send_message":                    {tier: tierDestructive, idempotent: false},
	"send_reply":                      {tier: tierDestructive, idempotent: false},
	"set_account_mode":                {tier: tierDestructive, idempotent: false},
	"set_account_send":                {tier: tierDestructive, idempotent: false},
	"set_my_notification_preferences": {tier: tierDestructive, idempotent: false},
	"set_reaction":                    {tier: tierDestructive, idempotent: false},
	"set_send_consent":                {tier: tierDestructive, idempotent: false},
	"set_telegram_access":             {tier: tierDestructive, idempotent: false},
	"update_install":                  {tier: tierDestructive, idempotent: false},
}
