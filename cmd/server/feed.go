package main

// feed.go loads the product-update feed (issue-683) exactly once at server
// start and resolves the release this build claims to be. Both are then held
// for the process lifetime by main and handed to whatever needs them (the
// broadcasts page's "Prepare from digest" action, the /docs/product-updates
// page) rather than re-read from disk on every request.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/web"
)

// ProductUpdateFeedSource holds the parsed feed plus any load error (a
// missing or unreadable directory, or an invalid entry): LoadFeed returns a partial feed
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
//
// A missing dir is a load error here, unlike in productupdate.LoadFeed
// (which the CLI and release gate use, where "no feed yet" is an empty
// feed). The server is always configured with a feed directory, so its
// absence means a packaging or configuration mistake; loading it as an empty
// feed would make every freeze refuse with a misleading "has no entries".
func loadProductUpdateFeed(dir, version string) ProductUpdateFeedSource {
	var feed productupdate.Feed
	err := feedDirPresent(dir)
	if err == nil {
		feed, err = productupdate.LoadFeed(dir)
	}
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

// feedDirPresent is nil when dir exists and is a directory. A failed stat is
// an error in its own right, never read as "present" or "absent".
func feedDirPresent(dir string) error {
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("product update feed directory %q does not exist (check PRODUCT_UPDATE_FEED_DIR)", dir)
	case err != nil:
		return fmt.Errorf("product update feed directory %q: %w", dir, err)
	case !info.IsDir():
		return fmt.Errorf("product update feed directory %q is not a directory", dir)
	}
	return nil
}

// DigestSource is what main hands the broadcasts page: the loaded feed, its
// load error and the resolved release, unchanged. Kept here so the wiring
// the server does is the wiring its tests exercise.
func (s ProductUpdateFeedSource) DigestSource() web.DigestSource {
	return web.DigestSource{Feed: s.Feed, LoadErr: s.Err, LatestRelease: s.LatestRelease}
}
