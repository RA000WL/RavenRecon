package dns

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps the derived events emitted for one completed pool
// job. Derivation is an observation aid only: reports never read the bus,
// so excess observations are dropped rather than buffered.
const maxDerivedPerJob = 512

// Deriver converts completed Resolve pool-job results into canonical live
// asset/finding stream events. It implements event.Deriver and is wired
// into the pool as a stateless package value (see Resolve); a nil observer
// preserves today's behavior byte-for-byte.
//
// For every HostResult it emits one AssetDiscovered per asset — the input
// host, every IP, every target host — followed by one RelationshipCreated
// per edge, in result order. HostResult carries no asset.Evidence records
// (TXT strings and SRV ports are published as adapter evidence downstream,
// never as engine evidence), so no EvidenceCreated events are emitted and
// no secret values can ever enter the stream. Unknown or nil results yield
// nil.
type Deriver struct{}

// Derive implements event.Deriver.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	var hr HostResult
	switch v := result.(type) {
	case HostResult:
		hr = v
	case *HostResult:
		if v == nil {
			return nil
		}
		hr = *v
	default:
		return nil
	}
	var out []event.Event
	push := func(e event.Event) {
		if len(out) >= maxDerivedPerJob {
			return
		}
		out = append(out, e)
	}
	emitAsset := func(id asset.Identity, confidence float64) {
		if id.IsZero() {
			return
		}
		push(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   id.String(),
			Kind:       string(id.Kind),
			Confidence: confidence,
		}))
	}
	emitAsset(hr.Host.Identity(), hr.Host.Prov.Confidence)
	for _, ip := range hr.IPs {
		emitAsset(ip.Identity(), ip.Prov.Confidence)
	}
	for _, tgt := range hr.Targets {
		emitAsset(tgt.Identity(), tgt.Prov.Confidence)
	}
	for _, rel := range hr.Relationships {
		if rel.From.IsZero() || rel.To.IsZero() {
			continue
		}
		push(event.New(event.KindRelationshipCreated, ev.At, event.RelationshipCreated{
			From: rel.From.String(),
			To:   rel.To.String(),
			Kind: string(rel.Kind),
		}))
	}
	return out
}
