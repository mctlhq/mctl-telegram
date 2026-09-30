package main

// feed.go loads the product-update feed (issue-683) exactly once at server
// start and resolves the release this build claims to be. Both are then held
// for the process lifetime by main and handed to whatever needs them (the
// broadcasts page's "Prepare from digest" action, the /docs/product-updates
// page) rather than re-read from disk on every request.

import (
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

// ProductUpdateFeedSource holds the parsed feed plus any load error (a
// missing directory or an invalid entry): LoadFeed returns a partial feed
// alongside its error, so both are kept. Err being non-nil, or LatestRelease
// being empty, makes every digest-freeze refuse with that reason; nothing
// else in the server depends on it, so a feed problem never blocks boot.
type ProductUpdateFeedSource struct {
	Feed          productupdate.Feed
	LatestRelease string
	Err           error
}

// loadProductUpdateFeed reads dir once (LoadFeed is not re-called anywhere
// else in this binary) and resolves LatestRelease from version (the
// main.version build var, set via -ldflags at build time) when it satisfies
// productupdate.ValidRelease. A non-release version (the "dev" default, or
// anything else that is not MAJOR.MINOR.PATCH) resolves to "": a release
// image knows exactly which release it is, a dev build honestly does not,
// and FreezeNextDigest with an empty baseline would treat unshipped entries
// as already shipped (see productupdate.Entry.Shipped) -- so freezing must
// refuse instead of guessing.
func loadProductUpdateFeed(dir, version string) ProductUpdateFeedSource {
	feed, err := productupdate.LoadFeed(dir)
	if err != nil {
		slog.Error("product update feed load failed; digest freezing will refuse until fixed", "dir", dir, "err", err)
	}
	latest := ""
	if productupdate.ValidRelease(version) {
		latest = version
	}
	slog.Info("product update feed loaded", "dir", dir, "entries", len(feed.Entries), "latest_release", latest, "load_ok", err == nil)
	return ProductUpdateFeedSource{Feed: feed, LatestRelease: latest, Err: err}
}
