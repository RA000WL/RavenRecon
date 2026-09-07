// Derivation bridge: completed pool-job rule results become canonical
// finding observations in the event stream.
//
// Engines never emit derived events themselves: the runtime pool wraps the
// configured Observer in an event.Deriving bridge holding this Deriver, so
// raw ruleJobResult job results are converted at the pool-job boundary. A
// nil Observer stays the off switch (the bridge is inert); unknown results
// derive nothing.
package detect

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob bounds one pool job's derived FindingCreated events.
// It is defense-in-depth, not the operative cap: the engine validates
// every rule's output BEFORE it reaches a pool-job result (engine.go:
// len(findings) > maxFindingsPerRule = 256 is a rule error, and every
// finding passes validateFinding — canonical round-trip, known priority
// vocabulary, observed subject), so an engine-path job result never
// carries more than 256 findings and the 512 cut is unreachable there
// (256 < 512, pinned by TestDerivedCapExceedsEngineBound). The cap only
// bites for foreign/hand-rolled ruleJobResult values fed to this
// exported Deriver directly — where a silent unbounded fan-out would be
// worse than a marked cut.
const maxDerivedPerJob = 512

// ruleJobResult is the raw result of one rule's pool job: the rule's honest
// outcome plus the validated findings it produced. It is the pool-job-
// boundary hand-off the Deriver converts into FindingCreated events; the
// accumulator merge still owns reporting.
type ruleJobResult struct {
	Result   RuleResult
	Findings []asset.Finding
}

// Deriver converts completed pool-job ruleJobResult results into canonical
// derived events: one FindingCreated per finding the rule produced.
type Deriver struct{}

var _ event.Deriver = Deriver{}

// Derive implements event.Deriver. It accepts ruleJobResult (and
// *ruleJobResult); every other result — including nil — yields nil.
// Findings with a zero identity or zero subject are skipped (the same
// floor the engine's validateFinding enforces: a finding must be about
// an observed asset — but where the engine FAILS the rule, the derived
// stream only DROPS the entry, because derivation is an observation aid
// and must never fail a run). A nil Observer stays the off switch one
// layer up (the event.Deriving bridge emits nothing without an
// Observer); Derive itself is a pure function of (event, result).
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	var res ruleJobResult
	switch r := result.(type) {
	case ruleJobResult:
		res = r
	case *ruleJobResult:
		if r == nil {
			return nil
		}
		res = *r
	default:
		return nil
	}
	if len(res.Findings) == 0 {
		return nil
	}
	at := ev.At
	var out []event.Event
	for _, f := range res.Findings {
		if len(out) >= maxDerivedPerJob {
			break
		}
		if f.Identity().IsZero() || f.Subject.IsZero() {
			continue
		}
		out = append(out, event.New(event.KindFindingCreated, at, event.FindingCreated{
			Identity:   f.ID(),
			RuleID:     f.RuleID,
			Subject:    f.Subject.String(),
			Priority:   f.Priority,
			Category:   f.Category,
			Confidence: clampConfidence(f.Confidence),
		}))
	}
	return out
}

// clampConfidence maps a rule confidence into the event payload's [0,1]
// contract: NaN and out-of-range values become 0 (unknown).
func clampConfidence(c float64) float64 {
	if c != c || c < 0 || c > 1 {
		return 0
	}
	return c
}
