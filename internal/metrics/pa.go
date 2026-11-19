// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import "github.com/prometheus/client_golang/prometheus"

// Personal Assistant connector dispatch metrics (#1315). Every label value
// comes from a closed set in internal/pa/connector: catalog server names,
// deny reasons, dispatch statuses and refusal reasons.

// paMetrics are the PA collectors, embedded in Registry.
type paMetrics struct {
	// PAPinDrift is 1 while the last observed tools/list of a server
	// differs from the committed pin for at least one pinned tool (missing,
	// changed schema, description or annotations), 0 when it matches. It
	// has no series while the listing could not be observed: a failed read
	// is not "no drift" (I9); PAPinListingUnknown says so instead.
	PAPinDrift *prometheus.GaugeVec
	// PAPinListingUnknown is 1 while the last tools/list of a server could
	// not be read or parsed, 0 once one was.
	PAPinListingUnknown *prometheus.GaugeVec
	// PAPinDeniedTools counts, per server and deny reason, the tools of the
	// last observed listing the pin denies. not_pinned is expected (tg lists
	// its write tools too) and is not drift.
	PAPinDeniedTools *prometheus.GaugeVec
	// PADispatchTotal counts dispatcher outcomes: an executed call's status
	// (reason "") or a refusal's reason (status "refused").
	PADispatchTotal *prometheus.CounterVec
}

func newPAMetrics(reg *prometheus.Registry) paMetrics {
	m := paMetrics{
		PAPinDrift: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_pin_drift",
			Help: "1 while a PA catalog server's live tools/list differs from the committed pin for a pinned tool, 0 when it matches; absent while the listing is unknown.",
		}, []string{"server"}),
		PAPinListingUnknown: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_pin_listing_unknown",
			Help: "1 while the last tools/list of a PA catalog server could not be read or parsed.",
		}, []string{"server"}),
		PAPinDeniedTools: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_pin_denied_tools",
			Help: "Tools of the last observed PA catalog listing the pin denies, by server and deny reason.",
		}, []string{"server", "reason"}),
		PADispatchTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_dispatch_total",
			Help: "PA connector dispatcher outcomes, by server, status and refusal reason.",
		}, []string{"server", "status", "reason"}),
	}
	reg.MustRegister(m.PAPinDrift, m.PAPinListingUnknown, m.PAPinDeniedTools, m.PADispatchTotal)
	return m
}

// PAPinObserved records a successfully read listing of server: drift says
// whether any pinned tool is denied, denied counts denied tools by reason.
// Reasons absent from denied are set to 0, so a cleared reason does not
// keep its last count.
func (r *Registry) PAPinObserved(server string, drift bool, denied map[string]int, reasons []string) {
	v := 0.0
	if drift {
		v = 1
	}
	r.PAPinDrift.WithLabelValues(server).Set(v)
	r.PAPinListingUnknown.WithLabelValues(server).Set(0)
	for _, reason := range reasons {
		r.PAPinDeniedTools.WithLabelValues(server, reason).Set(float64(denied[reason]))
	}
}

// PAPinUnknown records that server's listing could not be observed. The
// drift series is removed rather than set to 0.
func (r *Registry) PAPinUnknown(server string) {
	r.PAPinDrift.DeleteLabelValues(server)
	r.PAPinListingUnknown.WithLabelValues(server).Set(1)
}

// CountPADispatch counts one dispatcher outcome.
func (r *Registry) CountPADispatch(server, status, reason string) {
	r.PADispatchTotal.WithLabelValues(server, status, reason).Inc()
}
