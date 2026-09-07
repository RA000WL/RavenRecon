// Package dnsrec is RavenRecon's DNS-record intelligence pack (NEW-126 T3,
// informational recon observations over the DNS channels T1+T2 publish).
//
// T1+T2 (engine + pipeline adapter, already in tree) publish mail/delegation
// topology as host_to_mx / host_to_ns / host_to_srv edges in
// Results.Relationships (cross-domain targets kept as observations) and
// record detail as dns:txt (Value = the record string) + dns:srv (Value =
// "target:port") evidence with MethodDNS sourced at the queried host. Values
// longer than the asset package's 256-byte evidence bound arrive clipped
// with the "…" suffix marker (see asset.NewEvidence). The pipeline snapshot
// carries Relationships + Evidence verbatim to rules; this pack reads only
// those two channels plus Assets and performs no I/O of its own.
//
// Rules (5, each deterministic, informational per AGENTS §0.1 — recon
// observations, never vulnerability or exploitability claims):
//
//	dnsrec.ns.dangling-delegation — information — relationships+assets —
//	per-source-host dangling NS delegation shape: a host_to_ns edge whose
//	nameserver target has no host_to_ip (no A/AAAA observed). There is no
//	curated provider-suffix list for nameservers, so unlike
//	takeover.cname.unclaimed this rule fires on the orphan shape alone.
//	dnsrec.mx.dangling — information — relationships+assets — per-source-host
//	dangling MX shape: a host_to_mx edge whose exchanger target has no
//	host_to_ip, mirroring the dangling-CNAME signal exactly.
//	dnsrec.spf.weak — information — assets+evidence — per-host weak SPF
//	policy: a complete (unclipped) dns:txt record starting "v=spf1" with
//	neither "-all" nor "~all" among its whitespace-separated mechanisms.
//	dnsrec.dmarc.missing — information — assets+evidence — per-host absent
//	DMARC record: a non-empty dns:txt set with no "v=DMARC*" record and no
//	clipped values.
//	dnsrec.srv.exposure — information — assets+evidence — per-host
//	advertised services: complete dns:srv evidence citing target:port.
//
// Negative-claim guards (absence must never be derived from truncated
// input — a clipped value may hide the very directive whose absence is
// claimed, so every guard below fails OPEN, i.e. stays silent):
//
//   - SPF: "…"-suffixed values are skipped for every SPF claim, positive or
//     negative. A host whose SPF records are all clipped stays silent.
//   - DMARC: if ANY dns:txt value for the host is clipped, the host's TXT
//     set is incomplete and the rule stays silent for that host.
//   - SRV: clipped values are skipped; a host with only clipped SRV values
//     stays silent.
//
// DMARC scope note: DMARC records canonically live at _dmarc.<host>, not at
// the queried host itself. This rule reports only what the queried host's
// own observed TXT set shows ("no DMARC record observed in this host's TXT
// set") — an observed-corpus signal, never a standards-compliant DMARC
// evaluation. Correlating with MX edges or _dmarc.* queries is a consumer
// concern, deliberately out of scope here.
//
// Each rule honors context.Context, builds findings via asset.NewFinding
// (CategoryInformation, PriorityInfo, Confidence 0.6, MethodDetection
// evidence citing the subject, observed subjects only), respects
// RequiredAssetTypes (single primary kind KindHost — the census gate is
// conjunctive, so one kind per the web-pack precedent), handles Config
// deterministically (sorted keys, explicit <rule>.disabled lookups), and
// caps emission at 256 subjects deterministically with subjects_dropped +
// truncated metadata and a LevelWarn log.
//
// Loading sketch (SDK-only, no core edits; the pack is library-only until a
// pipeline milestone wires it — packs are explicitly loaded, never
// auto-loaded, so this pack changes no pipeline surface on its own):
//
//	rules, err := dnsrec.Rules() // CheckAPIVersion(2,0) first
//	if err != nil { return err }
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err } // ValidateRule → deep copy
//	}
//	if err := reg.Validate(); err != nil { return err } // graph
//	reg.Seal() // startup confinement
//	cfg := detect.DefaultEngineConfig(reg)
//	rep, err := detect.Run(ctx, cfg, snap)
package dnsrec
