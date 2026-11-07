package web

import (
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed examples.html
var examplesHTML string

var examplesTmpl = ui.New("examples", examplesHTML)

// example is one curated prompt. The list below is written and reviewed by
// hand: it is deliberately NOT generated from the assistant catalog, so the
// page does not depend on the catalog being available and does not suggest
// that an example is an installed assistant. They are plain prompts for any
// connected MCP client.
type example struct {
	ID     string   // stable anchor, unique across the page
	Title  string   // short heading
	Prompt string   // the text the copy button puts on the clipboard
	Tools  []string // MCP tools the prompt exercises, by their shipped names
	// Sends is true when the prompt can end in a real message to someone. It
	// is checked against the shipped tool descriptors (validateExamples): an
	// example is a sending one exactly when it uses a tool that is not
	// read-only.
	Sends bool
	Note  string // optional caveat on what the tools can and cannot do
}

type exampleCategory struct {
	Slug     string
	Name     string
	Intro    string
	Examples []example
}

// curatedExamples is the page content: 12 prompts, two per category. Every
// tool named here must exist in docs/tool-descriptors.json, and the prompts
// must stay within what those tools return; examples_test.go enforces the
// first and the review of this list the second.
var curatedExamples = []exampleCategory{
	{
		Slug:  "briefing",
		Name:  "Briefing",
		Intro: "Catch up without opening every chat.",
		Examples: []example{
			{
				ID:     "unread-digest",
				Title:  "Digest of unread messages",
				Prompt: "Summarize my unread Telegram messages, grouped by chat. For each chat give two lines at most, and list anything that looks like it is waiting for an answer from me.",
				Tools:  []string{"get_unread_messages"},
			},
			{
				ID:     "busiest-chats",
				Title:  "Where to look first",
				Prompt: "List my Telegram chats that have unread messages, the ones with the most unread first, with the unread count for each. Then suggest which three I should open first and why.",
				Tools:  []string{"list_dialogs"},
				Note:   "The ranking uses the unread counts Telegram reports for each chat; the model does not read the messages for this one.",
			},
		},
	},
	{
		Slug:  "search",
		Name:  "Search",
		Intro: "Find a message by what it said, across all chats or in one.",
		Examples: []example{
			{
				ID:     "search-recent-keyword",
				Title:  "A word across every chat",
				Prompt: "Search all my Telegram chats for \"invoice\" from the last 30 days. List each hit with the chat name, the date and the message text, newest first. If nothing matches, retry with the stem \"invoic\" and say so.",
				Tools:  []string{"search_messages"},
				Note:   "Telegram search matches the words as typed and does not expand word forms, which is why the prompt asks for a shorter stem as a fallback.",
			},
			{
				ID:     "search-one-chat",
				Title:  "A word in one chat",
				Prompt: "Find my chat named \"Family\", search it for \"dinner\" and show me the three most recent matches with their dates.",
				Tools:  []string{"list_dialogs", "search_messages"},
			},
		},
	},
	{
		Slug:  "extract",
		Name:  "Extract",
		Intro: "Pull structured facts out of a conversation.",
		Examples: []example{
			{
				ID:     "extract-dates",
				Title:  "Dates and deadlines",
				Prompt: "In my chat named \"Project Team\", read the latest 50 messages and list every date, deadline and meeting time that is mentioned, as a table with the date, what it is for and the date of the message that mentioned it.",
				Tools:  []string{"list_dialogs", "get_messages"},
			},
			{
				ID:     "extract-links",
				Title:  "Links and bookings",
				Prompt: "In my chat named \"Travel Group\", read the latest 100 messages and collect every link and every booking or flight detail into a checklist, one line each, with the date of the message it came from.",
				Tools:  []string{"list_dialogs", "get_messages"},
			},
		},
	},
	{
		Slug:  "people",
		Name:  "People",
		Intro: "Keep up with the people waiting on you.",
		Examples: []example{
			{
				ID:     "people-waiting",
				Title:  "Who is waiting for a reply",
				Prompt: "From my unread Telegram messages, list the people in direct chats who have written to me, oldest message first, with one line on what each of them is asking.",
				Tools:  []string{"get_unread_messages"},
			},
			{
				ID:     "people-draft-reply",
				Title:  "Draft a reply, then confirm",
				Prompt: "Find my direct chat with Alice, read her last few messages and draft a short, polite reply. Show me the exact recipient and text, and do not send anything until I tell you to.",
				Tools:  []string{"list_dialogs", "get_messages", "draft_reply", "send_reply"},
				Sends:  true,
				Note:   "draft_reply sends nothing. Only send_reply sends, and only after you confirm and only when sending is allowed for your account; otherwise it returns an error and nothing is sent.",
			},
		},
	},
	{
		Slug:  "analytics",
		Name:  "Analytics",
		Intro: "Count and chart what the tools can see.",
		Examples: []example{
			{
				ID:     "analytics-busy-hours",
				Title:  "When a chat is busiest",
				Prompt: "Read the latest 200 messages in my chat named \"Project Team\" and tell me which weekdays and which hours of the day it is busiest, as a small table of message counts.",
				Tools:  []string{"list_dialogs", "get_messages"},
				Note:   "Based on the latest 200 messages only, which is the most one call returns, so it describes recent activity, not the whole history.",
			},
			{
				ID:     "analytics-audit",
				Title:  "What your assistant did",
				Prompt: "Read the latest 100 entries of my MCTL audit log and show how many calls each tool made and how many of them failed.",
				Tools:  []string{"get_my_audit_log"},
				Note:   "The audit log records tool names, redacted peers and status, never message text.",
			},
		},
	},
	{
		Slug:  "media",
		Name:  "Media",
		Intro: "See what was shared, and fetch a file only when you ask.",
		Examples: []example{
			{
				ID:     "media-inventory",
				Title:  "What was shared in a chat",
				Prompt: "In my chat named \"Family\", look at the latest 50 messages and list the photos, videos and documents among them with the type, file name and size. Do not download anything.",
				Tools:  []string{"list_dialogs", "get_messages"},
			},
			{
				ID:     "media-download",
				Title:  "Fetch one file",
				Prompt: "In my chat named \"Project Team\", find the most recent document, tell me its name and size and ask me before downloading it. If I agree, download it and describe what it contains.",
				Tools:  []string{"list_dialogs", "get_messages", "prepare_get_media", "get_media"},
				Note:   "A download is limited to the server's per-file size cap, and what the assistant can say about the file depends on whether your AI client can read that file type.",
			},
		},
	},
}

// validateExamples checks the curated list against the shipped tool
// descriptors: readOnly maps every shipped tool name to its readOnlyHint. It
// fails on an unknown tool, on a consent label that does not match the tools
// used, and on duplicate or empty fields. It is run by the tests, not at
// request time, because the descriptors live outside the binary.
func validateExamples(cats []exampleCategory, readOnly map[string]bool) error {
	ids := map[string]bool{}
	for _, c := range cats {
		if c.Slug == "" || c.Name == "" || len(c.Examples) == 0 {
			return fmt.Errorf("category %q: slug, name and examples are required", c.Slug)
		}
		for _, e := range c.Examples {
			if e.ID == "" || e.Title == "" || strings.TrimSpace(e.Prompt) == "" || len(e.Tools) == 0 {
				return fmt.Errorf("example %q: id, title, prompt and tools are required", e.ID)
			}
			if ids[e.ID] {
				return fmt.Errorf("example id %q is used twice", e.ID)
			}
			ids[e.ID] = true
			writes := false
			for _, tool := range e.Tools {
				ro, ok := readOnly[tool]
				if !ok {
					return fmt.Errorf("example %q uses tool %q, which is not in the shipped tool descriptors", e.ID, tool)
				}
				writes = writes || !ro
			}
			if e.Sends != writes {
				return fmt.Errorf("example %q: Sends=%v but its tools %v make the opposite true", e.ID, e.Sends, e.Tools)
			}
			if e.Sends && !strings.Contains(strings.ToLower(e.Prompt), "until i tell you") {
				return fmt.Errorf("example %q can send but its prompt does not ask to wait for confirmation", e.ID)
			}
		}
	}
	return nil
}

type examplesData struct {
	ui.Data
	Categories []exampleCategory
}

// Examples renders /examples, a hand-curated page of ready-to-copy prompts.
// Anonymous-accessible and static: it holds no user data, makes no model or
// Telegram call, and does not read the assistant catalog.
func Examples(publicBaseURL string, showManage bool) http.HandlerFunc {
	return examplesHandler(publicBaseURL, showManage, curatedExamples)
}

func examplesHandler(publicBaseURL string, showManage bool, cats []exampleCategory) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	return chromePage(examplesTmpl, "examples", examplesData{
		Data: ui.Data{
			Title:         "MCTL — example prompts",
			Description:   "Twelve ready-to-copy prompts for Claude, ChatGPT or any MCP client connected to Telegram, with the tools each one uses and whether it can send anything.",
			NavActive:     "",
			PublicBaseURL: base,
			ShowManage:    showManage,
			CanonicalPath: "/examples",
		},
		Categories: cats,
	})
}
