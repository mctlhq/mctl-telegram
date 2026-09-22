// Package mcpui holds the flag-gated MCP Apps (SEP-1865) prototype: a single
// self-contained HTML document served as a "ui://" resource, plus the tiny
// amount of metadata that links it and its backing tools together. There is
// no MCP-Apps helper in the pinned mark3labs/mcp-go v1.0.0 SDK -- no
// NewUIResource, no WithUIResourceMeta -- so every literal key here (the
// extension id, the URI scheme, the mimeType, the nested _meta.ui shape) is
// written by hand and asserted by the tests in this package plus
// internal/mcpprobe's Apps conformance step.
//
// This package is deliberately separate from internal/mcp: tools.go is
// already large, and the asset-embedding precedent for this repository lives
// in a UI package (internal/ui), not in the MCP package.
package mcpui

import (
	_ "embed"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// ExtensionID is the MCP Apps extension identifier from SEP-1865, advertised
// in capabilities.extensions and used to key ExtensionCapability's map.
const ExtensionID = "io.modelcontextprotocol/ui"

// ResourceURI is the stable, unversioned URI of the triage App document. It
// does not change across builds -- the design decision recorded in the
// proposal is that a changing URI would break any host that cached the
// tool->resource link. The build travels in Version instead, and drift in
// the document itself is caught by a content-hash test
// (TestTriageHTMLContentHash), not by the URI.
const ResourceURI = "ui://mctl-telegram/triage"

// MIMEType is the MCP Apps content type for an inline HTML App resource.
const MIMEType = "text/html;profile=mcp-app"

// Version is the build version recorded in the resource's _meta, independent
// of ResourceURI. It is a plain constant rather than a linker-set variable:
// this is a prototype whose whole document changes together, so there is no
// intermediate build pipeline to thread a version through, and bumping this
// by hand is exactly the "deliberate, reviewable change" the content-hash
// test (see mcpui_test.go) also demands of any edit to triage.html.
const Version = "0.1.0"

//go:embed triage.html
var triageHTML string

// Resource returns the mcplib.Resource descriptor for the triage App
// document. Meta.AdditionalFields carries the MCP Apps "ui" object with an
// empty CSP domain allowlist, so a conforming host applies a
// "default-src 'none'" baseline: this prototype declares no origin the App
// is allowed to reach, because it reaches none.
func Resource() mcplib.Resource {
	return mcplib.Resource{
		URI:         ResourceURI,
		Name:        "telegram-triage",
		Title:       "Telegram research and triage",
		Description: "Scan unread dialogs, search across channels, and draft a reply with an explicit send/preview verdict before anything is delivered.",
		MIMEType:    MIMEType,
		Meta:        mcplib.NewMetaFromMap(uiResourceMeta()),
	}
}

// Contents returns the resource contents for a resources/read of uri. The
// caller (internal/mcp's resource handler) is expected to have already
// checked uri == ResourceURI; Contents does not re-validate it, matching how
// the mcp-go server routes resources/read to the handler registered for an
// exact URI. The returned slice always has exactly one element: the whole
// document, inline, as text.
func Contents(uri string) []mcplib.ResourceContents {
	return []mcplib.ResourceContents{
		mcplib.TextResourceContents{
			URI:      uri,
			MIMEType: MIMEType,
			Text:     triageHTML,
			Meta:     uiResourceMeta(),
		},
	}
}

// uiResourceMeta is the "ui" object shared by Resource().Meta and
// Contents()'s TextResourceContents.Meta. connectDomains, resourceDomains,
// frameDomains and baseUriDomains are all empty on purpose: this App makes
// no network call of its own (see triage.html's transport section, which
// talks to the host over postMessage and nothing else), so there is no
// domain a conforming host needs to allow through the CSP it applies to the
// iframe.
func uiResourceMeta() map[string]any {
	return map[string]any{
		"ui": map[string]any{
			"csp": map[string]any{
				"connectDomains":  []string{},
				"resourceDomains": []string{},
				"frameDomains":    []string{},
				"baseUriDomains":  []string{},
			},
			"prefersBorder": true,
		},
	}
}

// ExtensionCapability returns the capabilities.extensions entry this server
// advertises when MCP_APPS_ENABLED is true, keyed by ExtensionID per
// server.WithExtensions' contract (mark3labs/mcp-go server/server.go:675).
func ExtensionCapability() map[string]any {
	return map[string]any{
		ExtensionID: map[string]any{
			"mimeTypes": []string{MIMEType},
		},
	}
}

// ToolMeta returns the nested _meta.ui object linking a tool to this App's
// resource: {"ui": {"resourceUri": ResourceURI, "visibility": [...]}}. This
// is the nested form only -- the deprecated flat "ui/resourceUri" key is
// never emitted.
//
// visibility is a host-side hint, not server authorization: a host MAY use
// it to decide which tools the App itself is allowed to invoke versus which
// stay model-only, but no code in this repository reads it, and requireScope
// plus the send gate remain the only things that decide whether a call is
// permitted. See the proposal's "Open questions" for the reasoning.
func ToolMeta() map[string]any {
	return map[string]any{
		"ui": map[string]any{
			"resourceUri": ResourceURI,
			"visibility":  []string{"model", "app"},
		},
	}
}
