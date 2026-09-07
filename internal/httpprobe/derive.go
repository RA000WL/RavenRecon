package httpprobe

import (
	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/event"
)

// maxDerivedPerJob caps the derived events emitted for one completed pool
// job. Derivation is an observation aid only: reports never read the bus,
// so excess observations are dropped rather than buffered.
const maxDerivedPerJob = 512

// Deriver converts completed pool-job results into canonical live
// asset/finding stream events. It implements event.Deriver and is wired
// into every pool of this package as a stateless package value (see Probe,
// ProbeURLs, runReflect, ConfirmTakeoverHosts); a nil observer preserves
// today's behavior byte-for-byte.
//
// It recognizes the four job-result types of this package:
//
//   - HostResult: one AssetDiscovered per asset (input host, URLs, ports,
//     services, endpoints, TLS certificates, IPs) followed by one
//     RelationshipCreated per edge, in result order.
//   - LiveRecord: the probed URL asset plus the leaf TLS certificate when
//     an https handshake completed.
//   - ReflectRecord: the probed URL asset (verdicts are observations, not
//     assets).
//   - TakeoverVerdict: the input host asset (provider/fingerprint strings
//     are plain labels, not assets).
//
// None of these results carries asset.Evidence records, so no
// EvidenceCreated events are emitted and no secret values can ever enter
// the stream. Unknown or nil results yield nil.
type Deriver struct{}

// Derive implements event.Deriver.
func (Deriver) Derive(ev event.Event, result any) []event.Event {
	switch v := result.(type) {
	case HostResult:
		return deriveHostResult(ev, v)
	case *HostResult:
		if v == nil {
			return nil
		}
		return deriveHostResult(ev, *v)
	case LiveRecord:
		return deriveLiveRecord(ev, v)
	case *LiveRecord:
		if v == nil {
			return nil
		}
		return deriveLiveRecord(ev, *v)
	case ReflectRecord:
		return deriveReflectRecord(ev, v)
	case *ReflectRecord:
		if v == nil {
			return nil
		}
		return deriveReflectRecord(ev, *v)
	case TakeoverVerdict:
		return deriveTakeoverVerdict(ev, v)
	case *TakeoverVerdict:
		if v == nil {
			return nil
		}
		return deriveTakeoverVerdict(ev, *v)
	default:
		return nil
	}
}

func deriveHostResult(ev event.Event, hr HostResult) []event.Event {
	var out []event.Event
	push := func(e event.Event) {
		if len(out) >= maxDerivedPerJob {
			return
		}
		out = append(out, e)
	}
	emitAsset := func(id asset.Identity, method, path string, confidence float64) {
		if id.IsZero() {
			return
		}
		push(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   id.String(),
			Kind:       string(id.Kind),
			Method:     method,
			Path:       path,
			Confidence: confidence,
		}))
	}
	emitAsset(hr.Host.Identity(), "", "", hr.Host.Prov.Confidence)
	for _, u := range hr.URLs {
		emitAsset(u.Identity(), "", u.Path, u.Prov.Confidence)
	}
	for _, p := range hr.Ports {
		emitAsset(p.Identity(), "", "", p.Prov.Confidence)
	}
	for _, s := range hr.Services {
		emitAsset(s.Identity(), "", "", s.Prov.Confidence)
	}
	for _, ep := range hr.Endpoints {
		emitAsset(ep.Identity(), ep.Method, ep.URL.Path, ep.Prov.Confidence)
	}
	for _, c := range hr.TLSCertificates {
		emitAsset(c.Identity(), "", "", c.Prov.Confidence)
	}
	for _, ip := range hr.IPs {
		emitAsset(ip.Identity(), "", "", ip.Prov.Confidence)
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

func deriveLiveRecord(ev event.Event, rec LiveRecord) []event.Event {
	var out []event.Event
	push := func(e event.Event) {
		if len(out) >= maxDerivedPerJob {
			return
		}
		out = append(out, e)
	}
	if id := rec.URL.Identity(); !id.IsZero() {
		push(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   id.String(),
			Kind:       string(id.Kind),
			Path:       rec.URL.Path,
			Confidence: rec.URL.Prov.Confidence,
		}))
	}
	if rec.TLS != nil {
		if id := rec.TLS.Identity(); !id.IsZero() {
			push(event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
				Identity:   id.String(),
				Kind:       string(id.Kind),
				Confidence: rec.TLS.Prov.Confidence,
			}))
		}
	}
	return out
}

func deriveReflectRecord(ev event.Event, rec ReflectRecord) []event.Event {
	if id := rec.URL.Identity(); !id.IsZero() {
		return []event.Event{event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   id.String(),
			Kind:       string(id.Kind),
			Path:       rec.URL.Path,
			Confidence: rec.URL.Prov.Confidence,
		})}
	}
	return nil
}

func deriveTakeoverVerdict(ev event.Event, rec TakeoverVerdict) []event.Event {
	if id := rec.Host.Identity(); !id.IsZero() {
		return []event.Event{event.New(event.KindAssetDiscovered, ev.At, event.AssetDiscovered{
			Identity:   id.String(),
			Kind:       string(id.Kind),
			Confidence: rec.Host.Prov.Confidence,
		})}
	}
	return nil
}
