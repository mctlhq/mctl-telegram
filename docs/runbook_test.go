package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRunbookAnchorsPresent(t *testing.T) {
	data, err := os.ReadFile("runbook.md")
	if err != nil {
		t.Fatalf("failed to read runbook.md: %v", err)
	}
	content := string(data)

	anchors := []string{
		"mctltelegramnearcapacity",
		"mctltelegramfloodwaitspike",
		"mctltelegramoauthpendingstuck",
		"jwtfailures",
		"telegramclienterrors",
		"ratelimitspike",
		"sloburnrate",
	}

	for _, anchor := range anchors {
		want := `id="` + anchor + `"`
		if !strings.Contains(content, want) {
			t.Errorf("runbook.md missing anchor: %s", want)
		}
	}
}

func TestRunbookMetricNamesRegistered(t *testing.T) {
	runbookData, err := os.ReadFile("runbook.md")
	if err != nil {
		t.Fatalf("failed to read runbook.md: %v", err)
	}

	metricsData, err := os.ReadFile("../internal/metrics/metrics.go")
	if err != nil {
		t.Fatalf("failed to read internal/metrics/metrics.go: %v", err)
	}
	metricsSource := string(metricsData)

	re := regexp.MustCompile(`mctl_[a-z_]+`)
	names := re.FindAllString(string(runbookData), -1)

	seen := make(map[string]bool)
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		if strings.Contains(metricsSource, baseSeriesName(name)) {
			continue
		}
		t.Errorf("metric name %q found in runbook.md but not in internal/metrics/metrics.go", name)
	}
}

// histogramSuffixes are the series Prometheus derives from a single registered
// histogram or summary. Only the base name appears in metrics.go, but a
// histogram_quantile query cannot be written without the _bucket series, so a
// correct runbook necessarily names one that the registry source never spells
// out. Stripping the suffix keeps the check on the registered metric.
var histogramSuffixes = []string{"_bucket", "_count", "_sum"}

// baseSeriesName maps a derived series back to the metric it belongs to.
// Names that carry no derived suffix are returned unchanged.
func baseSeriesName(name string) string {
	for _, suffix := range histogramSuffixes {
		if trimmed, ok := strings.CutSuffix(name, suffix); ok {
			return trimmed
		}
	}
	return name
}
