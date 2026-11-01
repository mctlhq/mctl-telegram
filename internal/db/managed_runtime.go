package db

// Runtime values of agent_profiles.runtime (ADR 0008).
const (
	RuntimeOwn     = "own"
	RuntimeManaged = "managed"
)

// ManagedConsentCurrent is the consent version an owner must assert to
// switch to the managed runtime.
const ManagedConsentCurrent = "managed-data-flow/v1"

// ManagedConsentText is the verbatim consent text of ADR 0008, section 1.
const ManagedConsentText = "Messages needed to perform assistant tasks will be sent to MCTL's configured third-party AI provider through MCTL's AI gateway; gateway logging and caching are disabled."
