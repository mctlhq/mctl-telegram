// Command mcpprobe is a standalone Cloudflare MCP Portal compatibility probe
// (issue #585, execution child of mctlhq/.github#44). It measures whether a
// target mctl-telegram deployment -- direct, or through a configured
// Cloudflare Portal -- correctly serves the modern (protocol version
// 2026-07-28) or legacy MCP protocol path, and reports OAuth metadata
// relevant to Cloudflare's public-client + PKCE compatibility.
//
// It has no imports from internal/mcp, internal/telegram, or any other
// application package: it is a black-box HTTP client, like cmd/canary, and
// does not touch cmd/canary or the load generator.
//
// Usage:
//
//	MCPPROBE_BASE_URL=https://tg.mctl.ai \
//	MCPPROBE_MODE=modern \
//	MCPPROBE_EVIDENCE_SOURCE=direct-deployed \
//	go run ./cmd/mcpprobe
//
// The report is printed to stdout as JSON. See internal/mcpprobe's package
// doc for the redaction guarantee: the report can never carry a bearer
// token, authorization code, tool result body, chat title, peer id, phone
// number, or full session id.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// cliConfig holds the environment-sourced configuration for one probe run.
type cliConfig struct {
	baseURL         string
	mcpPath         string
	mode            mcpprobe.Mode
	protocolVersion string
	bearerToken     string
	readOnlyTool    string
	evidenceSource  mcpprobe.EvidenceSource
	label           string
	buildRef        string
	timeout         time.Duration
}

func loadConfig() (*cliConfig, error) {
	cfg := &cliConfig{}

	cfg.baseURL = os.Getenv("MCPPROBE_BASE_URL")
	if cfg.baseURL == "" {
		return nil, errors.New("MCPPROBE_BASE_URL is required")
	}

	cfg.mcpPath = os.Getenv("MCPPROBE_MCP_PATH")

	switch mode := mcpprobe.Mode(os.Getenv("MCPPROBE_MODE")); mode {
	case mcpprobe.ModeModern, mcpprobe.ModeLegacy:
		cfg.mode = mode
	case "":
		return nil, errors.New(`MCPPROBE_MODE is required and must be "modern" or "legacy" -- ` +
			"there is no default and no fallback between them")
	default:
		return nil, fmt.Errorf(`MCPPROBE_MODE must be "modern" or "legacy", got %q`, mode)
	}

	cfg.protocolVersion = os.Getenv("MCPPROBE_PROTOCOL_VERSION")
	cfg.bearerToken = os.Getenv("MCPPROBE_BEARER_TOKEN")
	cfg.readOnlyTool = os.Getenv("MCPPROBE_READ_ONLY_TOOL")
	cfg.label = os.Getenv("MCPPROBE_LABEL")
	cfg.buildRef = os.Getenv("MCPPROBE_BUILD_REF")

	switch source := mcpprobe.EvidenceSource(os.Getenv("MCPPROBE_EVIDENCE_SOURCE")); source {
	case mcpprobe.EvidenceInProcessCurrentMain, mcpprobe.EvidenceDirectDeployed, mcpprobe.EvidenceCloudflarePortal:
		cfg.evidenceSource = source
	case "":
		return nil, errors.New("MCPPROBE_EVIDENCE_SOURCE is required: " +
			"in-process-current-main, direct-deployed, or cloudflare-portal")
	default:
		return nil, fmt.Errorf("MCPPROBE_EVIDENCE_SOURCE must be one of "+
			"in-process-current-main, direct-deployed, cloudflare-portal, got %q", source)
	}
	if cfg.evidenceSource == mcpprobe.EvidenceInProcessCurrentMain {
		// This binary always makes a real network call; an in-process
		// httptest fixture is not something an operator running this
		// command can produce. Mislabeling a live run as in-process would
		// violate requirements.md acceptance criterion D.
		return nil, errors.New("MCPPROBE_EVIDENCE_SOURCE=in-process-current-main is produced only by " +
			"internal/mcpprobe's own tests (CI), never by running this binary against a live endpoint")
	}

	cfg.timeout = 30 * time.Second
	if v := os.Getenv("MCPPROBE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("MCPPROBE_TIMEOUT invalid duration %q: %w", v, err)
		}
		cfg.timeout = d
	}

	return cfg, nil
}

func run(ctx context.Context, cfg *cliConfig) (*mcpprobe.Report, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	oauthResult, err := mcpprobe.ProbeOAuth(ctx, mcpprobe.OAuthProbeConfig{
		BaseURL:     cfg.baseURL,
		MCPPath:     cfg.mcpPath,
		BearerToken: cfg.bearerToken,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth probe: %w", err)
	}

	var modernResult *mcpprobe.ModernResult
	var legacyResult *mcpprobe.LegacyResult

	switch cfg.mode {
	case mcpprobe.ModeModern:
		modernResult, err = mcpprobe.ProbeModern(ctx, mcpprobe.ModernConfig{
			BaseURL:         cfg.baseURL,
			MCPPath:         cfg.mcpPath,
			ProtocolVersion: cfg.protocolVersion,
			BearerToken:     cfg.bearerToken,
			ReadOnlyTool:    cfg.readOnlyTool,
		})
		if err != nil {
			return nil, fmt.Errorf("modern probe: %w", err)
		}
	case mcpprobe.ModeLegacy:
		legacyResult, err = mcpprobe.ProbeLegacy(ctx, mcpprobe.LegacyConfig{
			BaseURL:         cfg.baseURL,
			MCPPath:         cfg.mcpPath,
			ProtocolVersion: cfg.protocolVersion,
			BearerToken:     cfg.bearerToken,
			ReadOnlyTool:    cfg.readOnlyTool,
		})
		if err != nil {
			return nil, fmt.Errorf("legacy probe: %w", err)
		}
	}

	report := mcpprobe.NewReport(mcpprobe.ReportMeta{
		EvidenceSource: cfg.evidenceSource,
		Label:          cfg.label,
		BuildRef:       cfg.buildRef,
	}, modernResult, legacyResult, oauthResult)

	return report, nil
}

func main() {
	inner := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(inner))

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	report, err := run(context.Background(), cfg)
	if err != nil {
		slog.Error("probe failed", "err", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		slog.Error("encode report", "err", err)
		os.Exit(1)
	}
}
