package mcpprobe

import (
	"context"
	"net/url"
)

// Run probes the configured endpoint once and returns the report.
//
// The returned error is reserved for failures of the probe itself — invalid
// options, an unreachable host. A server that rejects a request has been
// measured, not errored: that outcome belongs in the report, where it can be
// compared against what the protocol requires.
func Run(ctx context.Context, o Options) (*Report, error) {
	if err := o.normalize(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(o.URL)
	if err != nil {
		return nil, err
	}
	report := &Report{
		Schema:          ReportSchema,
		Timestamp:       o.Now().UTC(),
		GitRef:          o.GitRef,
		Source:          o.Source,
		Mode:            o.Mode,
		ProtocolVersion: o.protocolVersion(),
		TargetHost:      parsed.Host,
	}
	client := &rpcClient{httpClient: o.HTTPClient, url: o.URL, token: o.Token}

	switch o.Mode {
	case ModeModern:
		if err := runModern(ctx, client, &o, report); err != nil {
			// Finalize even on the way out: a report that escapes without a
			// verdict carries the zero Outcome, and a caller reading Summary
			// would see a value the enum does not name.
			report.finalize()
			return report, err
		}
		runModernNegatives(ctx, client, &o, report)
	case ModeLegacy:
		if err := runLegacy(ctx, client, &o, report); err != nil {
			report.finalize()
			return report, err
		}
	}

	if !o.SkipOAuth {
		oauth := probeOAuth(ctx, o.HTTPClient, o.URL)
		report.OAuth = &oauth
	}
	report.finalize()
	return report, nil
}
