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
	// Listings are read per connection; the dispatcher aggregates the
	// fresh observations of every connection of a server before it sets
	// these gauges, so one connection cannot hide another's.
	//
	// PAPinDrift is 1 while any fresh observed tools/list of a server
	// differs from the committed pin for at least one pinned tool (missing,
	// changed schema, description or annotations), 0 when they all match.
	// It has no series while no listing of the server could be observed: a
	// failed read is not "no drift" (I9); PAPinListingUnknown says so.
	PAPinDrift *prometheus.GaugeVec
	// PAPinListingUnknown is 1 while no fresh tools/list of a server could
	// be read or parsed, 0 once one was.
	PAPinListingUnknown *prometheus.GaugeVec
	// PAPinDeniedTools counts, per server and deny reason, the tools of the
	// fresh observed listings the pin denies (the largest count of any
	// connection). not_pinned is expected (tg lists its write tools too)
	// and is not drift. No series while the listing is unknown.
	PAPinDeniedTools *prometheus.GaugeVec
	// PAPinListingFailures counts failed tools/list reads by server and
	// reason: unauthorized (the server refused one connection's token, a
	// problem of that connection, not of the listing), unavailable (the
	// read failed) or invalid (the listing did not parse). Every reason of
	// every configured server exists at 0 from the dispatcher's start.
	PAPinListingFailures *prometheus.CounterVec
	// PADispatchTotal counts dispatcher outcomes: an executed call's status
	// (reason "") or a refusal's reason (status "refused").
	PADispatchTotal *prometheus.CounterVec
	// PAWriteListingRefusals counts calls refused because of the fresh
	// tools/list read for that one call, for its card or at dispatch:
	// the listing could not be read or used, or the tool in it is not the
	// one the pin and the card name. The reason set is closed
	// (connector.WriteListingRefusalReasons) and every reason of every
	// write endpoint exists at 0 from the executor's construction.
	PAWriteListingRefusals *prometheus.CounterVec
	// PAAuditEventsQueued is the number of audit events still queued after
	// the last sweep. It has no labels; it is a vector so that it can be
	// absent, which it is while the queue could not be counted.
	PAAuditEventsQueued *prometheus.GaugeVec
	// PAAuditEventSweepProblems counts what a sweep of that queue could
	// not do (connector.AuditEventProblems).
	PAAuditEventSweepProblems *prometheus.CounterVec
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
		PAPinListingFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_pin_listing_failures_total",
			Help: "Failed PA catalog tools/list reads, by server and reason (unauthorized, unavailable, invalid).",
		}, []string{"server", "reason"}),
		PADispatchTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_dispatch_total",
			Help: "PA connector dispatcher outcomes, by server, status and refusal reason.",
		}, []string{"server", "status", "reason"}),
		PAWriteListingRefusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_write_listing_refusals_total",
			Help: "PA calls refused, for a card or at dispatch, because of the tool's fresh tools/list, by server and reason.",
		}, []string{"server", "reason"}),
		PAAuditEventsQueued: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_audit_events_queued",
			Help: "PA audit events still queued after the last sweep; absent while the queue cannot be counted.",
		}, nil),
		PAAuditEventSweepProblems: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_audit_event_sweep_problems_total",
			Help: "PA audit event sweep problems: passes that could not read the queue, events not appended, events dropped.",
		}, []string{"problem"}),
	}
	reg.MustRegister(m.PAPinDrift, m.PAPinListingUnknown, m.PAPinDeniedTools, m.PAPinListingFailures, m.PADispatchTotal,
		m.PAWriteListingRefusals, m.PAAuditEventsQueued, m.PAAuditEventSweepProblems)
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
// drift and denied-tool series are removed rather than set to 0 or left at
// their last counts.
func (r *Registry) PAPinUnknown(server string) {
	r.PAPinDrift.DeleteLabelValues(server)
	r.PAPinDeniedTools.DeletePartialMatch(prometheus.Labels{"server": server})
	r.PAPinListingUnknown.WithLabelValues(server).Set(1)
}

// CountPAListingFailure counts one failed tools/list read.
func (r *Registry) CountPAListingFailure(server, reason string) {
	r.PAPinListingFailures.WithLabelValues(server, reason).Inc()
}

// PreparePAListingFailures creates server's listing-failure series at 0,
// so that increase() sees the first failure.
func (r *Registry) PreparePAListingFailures(server string, reasons []string) {
	for _, reason := range reasons {
		r.PAPinListingFailures.WithLabelValues(server, reason).Add(0)
	}
}

// CountPADispatch counts one dispatcher outcome.
func (r *Registry) CountPADispatch(server, status, reason string) {
	r.PADispatchTotal.WithLabelValues(server, status, reason).Inc()
}

// CountPAWriteListingRefusal counts one call refused because of the tool's
// fresh listing.
func (r *Registry) CountPAWriteListingRefusal(server, reason string) {
	r.PAWriteListingRefusals.WithLabelValues(server, reason).Inc()
}

// PreparePAWriteListingRefusals creates server's series at 0, so that
// increase() sees the first refusal.
func (r *Registry) PreparePAWriteListingRefusals(server string, reasons []string) {
	for _, reason := range reasons {
		r.PAWriteListingRefusals.WithLabelValues(server, reason).Add(0)
	}
}

// SetPAAuditEventsQueued records how many audit events are queued.
func (r *Registry) SetPAAuditEventsQueued(n int64) {
	r.PAAuditEventsQueued.WithLabelValues().Set(float64(n))
}

// ForgetPAAuditEventsQueued removes the queue gauge: a queue that could
// not be counted is not an empty one.
func (r *Registry) ForgetPAAuditEventsQueued() {
	r.PAAuditEventsQueued.Reset()
}

// CountPAAuditEventProblem adds n to one sweep problem.
func (r *Registry) CountPAAuditEventProblem(problem string, n int) {
	r.PAAuditEventSweepProblems.WithLabelValues(problem).Add(float64(n))
}
