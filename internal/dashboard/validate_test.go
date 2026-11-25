package dashboard

import (
	"strings"
	"testing"
)

func TestBuiltinsMatchSchema(t *testing.T) {
	got := Builtins()
	if len(got) != 5 {
		t.Fatalf("builtins = %d, want 5", len(got))
	}
	want := []string{"unread_pulse", "groups_tiles", "folders_board", "forum_topics", "watchlist_digest"}
	for i, id := range want {
		if got[i].ID != id || got[i].Schema != SchemaID {
			t.Fatalf("builtin[%d] = %s %s", i, got[i].ID, got[i].Schema)
		}
		raw := got[i].MustCanonical()
		again, err := Parse(raw)
		if err != nil {
			t.Fatalf("reparse %s: %v", id, err)
		}
		if again.ID != id {
			t.Fatalf("reparse id = %s", again.ID)
		}
	}
}

func TestParseRejectsWriteToolsAndBadBindings(t *testing.T) {
	base := `{
	  "schema": "tg-dashboard/v1",
	  "id": "custom_pulse",
	  "title": "Мой",
	  "layout": {"columns": 12, "gap": 8},
	  "dataSources": [{"id": "dialogs", "tool": "list_dialogs", "args": {"limit": 10}}],
	  "tiles": [{"id": "k", "component": "kpi", "colSpan": 4, "props": {"label": "N", "value": "@data:dialogs.stats.unread_dialogs"}}]
	}`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"send tool", strings.Replace(base, `"list_dialogs"`, `"send_message"`, 1), "tg-dashboard/v1"},
		{"delete action", strings.Replace(base, `"props": {"label": "N", "value": "@data:dialogs.stats.unread_dialogs"}`, `"props": {"label": "N", "value": "1"}, "actions": [{"action": "delete_messages", "label": "Удалить"}]`, 1), "tg-dashboard/v1"},
		{"fetch media", strings.Replace(base, `"limit": 10`, `"limit": 10, "fetch_media": true`, 1), "not allowed"},
		{"unknown input", strings.Replace(base, `"limit": 10`, `"query": "@input:missing"`, 1), "unknown input"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestParseFillsRefresh(t *testing.T) {
	raw := []byte(`{
	  "schema": "tg-dashboard/v1",
	  "id": "custom_pulse",
	  "title": "Мой",
	  "layout": {"columns": 4, "gap": 8},
	  "dataSources": [{"id": "folders", "tool": "list_folders"}],
	  "tiles": [{"id": "b", "component": "folder_board", "colSpan": 4, "props": {"source": "folders", "title": "Папки"}}]
	}`)
	tpl, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tpl.RefreshIntervalSec != DefaultRefreshSec {
		t.Fatalf("refresh = %d", tpl.RefreshIntervalSec)
	}
}
