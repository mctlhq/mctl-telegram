package pa

import "github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"

// toolStatus is the server-authored status shown while a pinned read tool
// runs. It names the kind of work only: no model text, tool argument or
// chat title. A tool with no entry gets the generic text
// (TestToolStatus makes a newly pinned tool a decision).
func toolStatus(name string) safetext.Template {
	switch name {
	case "tg/get_messages":
		return safetext.TextStatusReadingMessages
	case "tg/search_messages":
		return safetext.TextStatusSearchingMessages
	case "tg/list_dialogs":
		return safetext.TextStatusListingChats
	case "tg/list_folders":
		return safetext.TextStatusListingFolders
	case "tg/list_topics":
		return safetext.TextStatusListingTopics
	case "tg/get_my_identity":
		return safetext.TextStatusCheckingAccount
	case "alice/alice_get_device_history", "alice/alice_get_device_state",
		"alice/alice_get_home_summary", "alice/alice_list_devices":
		return safetext.TextStatusCheckingHome
	default:
		return safetext.TextStatusUsingTool
	}
}

// hasToolStatus reports whether name has its own status (tests).
func hasToolStatus(name string) bool { return toolStatus(name) != safetext.TextStatusUsingTool }
