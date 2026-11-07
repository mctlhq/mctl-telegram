package web

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed examples.html
var examplesHTML string

var examplesTmpl = ui.New("examples", examplesHTML)

// examplePrompt is one prompt a new user can paste into their AI client.
// Tools names the MCP tools the prompt is expected to call; a test checks
// each one against docs/tool-descriptors.json, and Send must be true exactly
// when one of them is not read-only, so the "needs sending" chip cannot
// drift from what the tools really do.
type examplePrompt struct {
	Text  string
	Tools []string
	Send  bool
}

type exampleCategory struct {
	ID      string
	Title   string
	Lead    string
	Prompts []examplePrompt
}

// exampleCategories is the curated list behind /examples (mctl-telegram#1156).
// It is written and reviewed by hand, by owner decision: it is not generated
// from the assistant catalog. Words in square brackets are for the user to
// replace.
var exampleCategories = []exampleCategory{
	{
		ID: "briefing", Title: "Catch up",
		Lead: "Start the day without scrolling every chat.",
		Prompts: []examplePrompt{
			{Text: "Summarise my unread Telegram messages, grouped by chat, most important first. Skip channels.", Tools: []string{"get_unread_messages"}},
			{Text: "What did I miss in [chat name] since yesterday? List the decisions, the open questions and anything addressed to me.", Tools: []string{"list_dialogs", "get_messages"}},
		},
	},
	{
		ID: "search", Title: "Find things",
		Lead: "Telegram search matches the words as typed, so the assistant can try other forms for you.",
		Prompts: []examplePrompt{
			{Text: "Find the message where someone sent me the address for [event]. Tell me who sent it and when.", Tools: []string{"search_messages"}},
			{Text: "Search my chats for \"invoice\" from the last 30 days and list each one with the sender, the date and the amount if it is mentioned.", Tools: []string{"search_messages"}},
		},
	},
	{
		ID: "extract", Title: "Pull out details",
		Lead: "Turn a long thread into something you can act on.",
		Prompts: []examplePrompt{
			{Text: "Collect every link shared in [chat name] this week into a table with who shared it and a one-line description.", Tools: []string{"list_dialogs", "get_messages"}},
			{Text: "Read my chat with [person] from this month and list every date, deadline and promise either of us made.", Tools: []string{"get_messages"}},
		},
	},
	{
		ID: "organise", Title: "Chats and folders",
		Lead: "See where the conversations are before you read them.",
		Prompts: []examplePrompt{
			{Text: "List the chats in my [folder name] folder that have unread messages, busiest first.", Tools: []string{"list_folders", "list_dialogs"}},
			{Text: "List my private chats with unread messages, oldest last message first, so I can see who has waited longest.", Tools: []string{"list_dialogs"}},
		},
	},
	{
		ID: "media", Title: "Photos and files",
		Lead: "Media is downloaded one item at a time, after the assistant asks for it.",
		Prompts: []examplePrompt{
			{Text: "Find the last PDF [person] sent me and summarise it.", Tools: []string{"get_messages", "prepare_get_media", "get_media"}},
			{Text: "Describe the photos posted in [chat name] today.", Tools: []string{"get_messages", "prepare_get_media", "get_media"}},
		},
	},
	{
		ID: "reply", Title: "Reply",
		Lead: "Accounts start read-only. Until you turn sending on, these show you a preview and send nothing.",
		Prompts: []examplePrompt{
			{Text: "Draft a reply to [person]'s last message saying I will be there at 7. Show me the text before you send it.", Tools: []string{"get_messages", "send_message"}, Send: true},
			{Text: "React with a thumbs-up to the last message in [chat name].", Tools: []string{"get_messages", "set_reaction"}, Send: true},
		},
	},
}

type examplesData struct {
	ui.Data
	Categories []exampleCategory
}

// Examples serves the curated prompt list at /examples. Anonymous-accessible
// like /demo: nothing on it is user-specific.
func Examples(publicBaseURL string, showManage bool) http.HandlerFunc {
	data := examplesData{
		Data: ui.Data{
			Title:         "MCTL — examples",
			Description:   "Prompts to try once your Telegram account is connected to Claude, ChatGPT or another MCP client: catch up, search, extract, organise, media and replies.",
			NavActive:     "examples",
			PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
			ShowManage:    showManage,
		},
		Categories: exampleCategories,
	}
	return chromePage(examplesTmpl, "examples", data)
}
