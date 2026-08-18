// Package examples is RavenRecon's example detection rule pack: six
// mechanical demonstration rules that exercise the detection SDK (milestone
// v1.2.5, "SDK v1 (Core)" freeze at API level 1.0) entirely through its
// EXPORTED surface. The pack lives in a SIBLING package of the framework
// (internal/detect/examples, package examples): it can use only what
// internal/detect exports, so — by construction — it proves that a rule pack
// loads, validates, and runs through the SDK without any special-case code
// in the framework.
//
// # The rules
//
// Each of the seven fixed Context domains is exercised by at least one rule
// (the audit rule covers secrets and javascript together), with the remaining
// demonstrations folded in:
//
//	example.assets.census                assets        discovery
//	    Counts the corpus assets per kind; one finding per kind present.
//	    Dependency root of the pack.
//	example.relationships.degree-index   relationships discovery
//	    In/out degree of every node in the relationship graph; one finding
//	    per node — but only for nodes present in the observed corpus (a
//	    relationship edge is validated for canonical form only, so its
//	    endpoints may legally cite identities the snapshot never observed),
//	    the pack's second observed-corpus demonstration after
//	    endpoint-coverage. Declares a dependency on example.assets.census, so
//	    the engine schedules it one level later — the dependency-graph demo
//	    (Registry.Validate accepts the pair).
//	example.evidence.method-inventory   evidence      information
//	    Groups evidence records by detection method; one finding per
//	    method present.
//	example.technology.version-listing  technology    information
//	    One finding per observed technology with name, category, and
//	    version metadata. Demonstrates RequiredAssetTypes: the rule only
//	    runs when the corpus carries a technology asset.
//	example.endpoints.url-coverage      endpoints     discovery
//	    One finding per endpoint; the finding carries a MethodDetection
//	    evidence record and cites the endpoint's URL as a related asset —
//	    but only when the corpus observed that URL (the engine rejects
//	    findings that cite assets the snapshot never produced).
//	example.config.audit-summary        secrets, javascript  information
//	    Summarizes secret candidates and script assets through the Context
//	    configuration and the Logger, and emits NO findings — the
//	    config/logging demo and the empty-output path (an empty rule
//	    output is a valid, cacheable outcome).
//
// # Loading and running the pack
//
//	ctx := context.Background()
//	rules, err := examples.Rules() // the API-compatibility check runs first
//	if err != nil { return err }
//
//	reg := detect.NewRegistry()
//	for _, r := range rules {
//	    if err := reg.Register(r); err != nil { return err }
//	}
//	if err := reg.Validate(); err != nil { return err } // dependency graph
//	reg.Seal() // optional: confine registration to startup
//
//	cfg := detect.DefaultEngineConfig(reg)
//	cfg.Cache = fs              // optional cache-before-execute (cache.Cache)
//	cfg.Config = map[string]string{"example.audit_detail": "true"}
//	rep, err := detect.Run(ctx, cfg, snap) // snap is a detect.Snapshot
//	_ = rep                                 // deterministic detect.Report
//
// Run performs the registry validation itself, so a caller may skip the
// explicit Validate; calling it once at startup is the documented pattern.
// The sketch's fs, ctx, and snap stand for a cache.Cache, a
// context.Context, and a detect.Snapshot built through the Phase 2 asset
// builders; ExampleRun in package detect_test is the compilable demonstration
// of the same pattern — the runnable end-to-end example.
//
// # API compatibility
//
// Rules verifies the SDK surface level through detect.CheckAPIVersion(1, 0)
// before any rule is returned: a major mismatch means the pack must be
// recompiled against the current SDK, and a too-new required minor means
// this build predates the pack. The check surfaces as a load-time error
// instead of a panic — library code never panics for ordinary failures.
//
// # Content policy
//
// These rules are mechanical demonstrations only, never vulnerability
// detections: rule IDs carry the "example." prefix, categories are
// restricted to information and discovery, and no rule claims to detect a
// vulnerability, misconfiguration, exposure, or secret. The pack exists to
// teach the SDK surface (context domains, dependencies, required asset
// kinds, config, logging, evidence and related-asset citations, empty
// outputs, caching) — copy the shapes, not the semantics.
package examples
