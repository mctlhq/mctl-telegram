package mcpprobe

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
)

// appsExtensionID is the MCP Apps (SEP-1865) extension id this probe checks
// for. It is a literal here, deliberately, rather than an import of
// internal/mcpui: this package must stay servable against ANY MCP endpoint,
// not just this repository's own build, and a probe that only recognised its
// own package's constant would be checking itself rather than the wire
// contract every conforming server and host share.
const appsExtensionID = "io.modelcontextprotocol/ui"

// appsMIMEType is the MCP Apps inline HTML content type this probe checks
// resources/list and resources/read against.
const appsMIMEType = "text/html;profile=mcp-app"

// AppsProbe records what a target advertises and serves for MCP Apps
// (SEP-1865): whether initialize advertises the extension id and mimeType,
// whether resources/list carries a "ui://" resource with that mimeType,
// whether resources/read returns non-empty inline text for it, and which
// tools carry a nested _meta.ui.resourceUri.
//
// This step is deliberately additive and never affects Report.Summary (see
// Run): an endpoint that never heard of MCP Apps -- which is exactly what
// this repository's own default, flag-off deployment looks like -- reports
// ExtensionAdvertised=false with Outcome=SKIPPED, not a failure.
type AppsProbe struct {
	ExtensionAdvertised bool     `json:"extension_advertised"`
	ExtensionMimeTypes  []string `json:"extension_mime_types,omitempty"`
	ResourceListed      bool     `json:"resource_listed"`
	ResourceURI         string   `json:"resource_uri,omitempty"`
	ResourceMimeType    string   `json:"resource_mime_type,omitempty"`
	ResourceReadable    bool     `json:"resource_readable"`
	UIToolNames         []string `json:"ui_tool_names,omitempty"`
	Outcome             Outcome  `json:"outcome"`
	Reason              Reason   `json:"reason,omitempty"`
}

// appsInitializeResult is the slice of an initialize response this probe
// reads: just enough of capabilities.extensions to answer "was MCP Apps
// advertised", never the whole capabilities document.
type appsInitializeResult struct {
	Capabilities struct {
		Extensions map[string]struct {
			MimeTypes []string `json:"mimeTypes"`
		} `json:"extensions"`
		Resources *struct{} `json:"resources"`
	} `json:"capabilities"`
}

// appsResourcesListResult is the slice of resources/list this probe reads.
type appsResourcesListResult struct {
	Resources []struct {
		URI      string `json:"uri"`
		MIMEType string `json:"mimeType"`
	} `json:"resources"`
}

// appsResourcesReadResult is the slice of resources/read this probe reads.
type appsResourcesReadResult struct {
	Contents []struct {
		Text string `json:"text"`
	} `json:"contents"`
}

// appsToolsListResult is the slice of tools/list this probe reads to find
// which tools carry a nested _meta.ui.resourceUri. Only presence of that one
// nested key is recorded (as a tool name in AppsProbe.UIToolNames) -- the
// rest of _meta, and the resourceUri value itself, never reaches the report.
type appsToolsListResult struct {
	Tools []struct {
		Name string `json:"name"`
		Meta *struct {
			UI *struct {
				ResourceURI string `json:"resourceUri"`
			} `json:"ui"`
		} `json:"_meta"`
	} `json:"tools"`
}

// probeApps runs the MCP Apps conformance check and attaches the result to
// r.Apps. It always uses the classic "initialize" method regardless of the
// run's configured Mode: capabilities.extensions is carried on the
// InitializeResult (mcp-go mcp/types.go ServerCapabilities.Extensions), and
// the modern, stateless "server/discover" response this package otherwise
// parses (discoverResult, modern.go) does not include it. A target that has
// removed "initialize" entirely (a strict modern-only deployment) is
// reported as not advertised rather than as a transport failure: this step
// answers "does MCP Apps work here", and an endpoint with no classic
// lifecycle at all cannot be carrying it either way.
func probeApps(ctx context.Context, c *rpcClient, r *Report) {
	probe := AppsProbe{}

	initOut, err := c.do(ctx, rpcRequest{
		method: mcp.MethodInitialize,
		id:     900001,
		params: map[string]any{
			"protocolVersion": mcp.LATEST_LEGACY_PROTOCOL_VERSION,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": probeClientName, "version": probeClientVersion},
		},
	})
	if err != nil && !errors.Is(err, errMalformedBody) {
		probe.Outcome, probe.Reason = OutcomeSkipped, ReasonNotApplicable
		r.Apps = &probe
		return
	}
	if errors.Is(err, errMalformedBody) || initOut.errorCode != nil || initOut.httpStatus != 200 {
		probe.Outcome, probe.Reason = OutcomeSkipped, ReasonNotApplicable
		r.Apps = &probe
		return
	}
	var initResult appsInitializeResult
	if json.Unmarshal(initOut.result, &initResult) != nil {
		probe.Outcome, probe.Reason = OutcomeSkipped, ReasonNotApplicable
		r.Apps = &probe
		return
	}
	ext, advertised := initResult.Capabilities.Extensions[appsExtensionID]
	probe.ExtensionAdvertised = advertised
	if !advertised {
		// This is the flag-off shape: not a failure, just nothing to measure.
		probe.Outcome, probe.Reason = OutcomeSkipped, ReasonNotApplicable
		r.Apps = &probe
		return
	}
	probe.ExtensionMimeTypes = ext.MimeTypes

	if initResult.Capabilities.Resources == nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonUnexpectedSuccess
		r.Apps = &probe
		return
	}

	// Carry forward whatever session identifier initialize minted (possibly
	// none): a legacy-mode server in this repository requires it on every
	// call after initialize (see legacy.go / TestLegacyRun_RequiresSession),
	// and a server that mints none simply ignores an empty sessionID here.
	session := initOut.sessionID

	listOut, err := c.do(ctx, rpcRequest{method: mcp.MethodResourcesList, id: 900002, sessionID: session})
	if err != nil && !errors.Is(err, errMalformedBody) {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonTransport
		r.Apps = &probe
		return
	}
	if errors.Is(err, errMalformedBody) || listOut.errorCode != nil || listOut.httpStatus != 200 {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonJSONRPCError
		r.Apps = &probe
		return
	}
	var listResult appsResourcesListResult
	if json.Unmarshal(listOut.result, &listResult) != nil {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonMalformedBody
		r.Apps = &probe
		return
	}
	var resourceURI string
	for _, res := range listResult.Resources {
		if res.MIMEType == appsMIMEType {
			resourceURI = res.URI
			probe.ResourceListed = true
			probe.ResourceURI = res.URI
			probe.ResourceMimeType = res.MIMEType
			break
		}
	}
	if !probe.ResourceListed {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonUnexpectedSuccess
		r.Apps = &probe
		return
	}

	readOut, err := c.do(ctx, rpcRequest{
		method: mcp.MethodResourcesRead, id: 900003, sessionID: session,
		params: map[string]any{"uri": resourceURI},
	})
	if err == nil && !errors.Is(err, errMalformedBody) && readOut.errorCode == nil && readOut.httpStatus == 200 {
		var readResult appsResourcesReadResult
		if json.Unmarshal(readOut.result, &readResult) == nil {
			for _, content := range readResult.Contents {
				if content.Text != "" {
					probe.ResourceReadable = true
					break
				}
			}
		}
	}

	toolsOut, err := c.do(ctx, rpcRequest{method: mcp.MethodToolsList, id: 900004, sessionID: session})
	if err == nil && !errors.Is(err, errMalformedBody) && toolsOut.errorCode == nil && toolsOut.httpStatus == 200 {
		var toolsResult appsToolsListResult
		if json.Unmarshal(toolsOut.result, &toolsResult) == nil {
			for _, tool := range toolsResult.Tools {
				if tool.Meta != nil && tool.Meta.UI != nil && tool.Meta.UI.ResourceURI != "" {
					probe.UIToolNames = append(probe.UIToolNames, tool.Name)
				}
			}
		}
	}

	if probe.ResourceReadable && len(probe.UIToolNames) > 0 {
		probe.Outcome = OutcomePass
	} else {
		probe.Outcome, probe.Reason = OutcomeFail, ReasonUnexpectedSuccess
	}
	r.Apps = &probe
}
