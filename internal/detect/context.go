package detect

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/runtime"
)

// Snapshot bounds (fixed constants; they never enter cache keys — a bound
// change never invalidates a cached rule result, and an over-bound snapshot
// is rejected outright rather than truncated: silently truncating input
// would silently change findings).
const (
	maxSnapshotAssets        = 100_000
	maxSnapshotRelationships = 200_000
	maxSnapshotEvidence      = 100_000
	maxSnapshotTechnologies  = 50_000
	maxSnapshotSecrets       = 50_000
	maxSnapshotJavaScript    = 50_000
	maxSnapshotEndpoints     = 100_000
)

// Snapshot is the caller-composed input of one detection run: the canonical
// structured corpus the earlier phases produced. It is NOT untrusted tool
// output — every entry must already be a canonical Phase 2 value, and
// normalization rejects the run (with a structured error naming the first
// invalid entry) rather than counting and dropping: a snapshot with garbage
// in it is a caller bug, not a noisy observation.
type Snapshot struct {
	// Assets carries the core graph assets (domains, hosts, IPs, ports,
	// services, URLs) as canonical identities. Validation is deliberately
	// lax about WHICH kind: any valid asset kind is accepted, so a caller
	// may also carry findings, parameters, or TLS certificates here — they
	// are deduplicated and counted like any other asset, but the framework
	// gives non-core kinds no core-graph semantics.
	Assets []asset.Identity `json:"assets,omitempty"`

	// Relationships carries the typed graph edges.
	Relationships []asset.Relationship `json:"relationships,omitempty"`

	// Evidence carries the Phase 2 evidence records (technology markers,
	// secret-engine records, ...).
	Evidence []asset.Evidence `json:"evidence,omitempty"`

	// Technologies carries the technology detections.
	Technologies []asset.Technology `json:"technologies,omitempty"`

	// Secrets carries the secret candidates (detected, never verified).
	Secrets []asset.SecretCandidate `json:"secrets,omitempty"`

	// JavaScript carries the observed script assets.
	JavaScript []asset.JavaScript `json:"javascript,omitempty"`

	// Endpoints carries the observed endpoints.
	Endpoints []asset.Endpoint `json:"endpoints,omitempty"`
}

// GraphQuerier is the read-only graph view over the snapshot's asset
// graph (SDK v2). It is the ONLY inter-rule dataflow beyond
// PriorFindings: dependencies order execution, but now PriorFindings and
// GraphView flow read-only data (see Context.PriorFindings and
// Context.GraphView). The view is built once per Run from the normalized
// Snapshot.Relationships+Assets, is deterministically sorted, and never
// mutates — a rule cannot add or remove nodes/edges, only traverse the
// observed graph the earlier phases produced. Hermetic and deterministic:
// the same snapshot always yields the same Neighbors/Path results, and
// traversal never performs I/O.
type GraphQuerier interface {
	// Neighbors returns every relationship incident to id (outgoing edges
	// where From == id, deterministically sorted by Relationship.ID).
	// An unknown identity yields nil (never an empty non-nil slice — the
	// canonical empty-set representation).
	Neighbors(id asset.Identity) []asset.Relationship
	// Path returns the directed shortest path from → to as a list of
	// identities (inclusive, from as first element, to as last), or nil
	// when no directed path exists or either endpoint was never observed.
	// The result is deterministically sorted: BFS explores adjacencies in
	// Relationship.ID order, so the same graph always yields the same path.
	Path(from, to asset.Identity) []asset.Identity
}

// Context is the detection context every rule receives: the normalized
// snapshot domains, the run's bounded configuration, a bounded Logger, and
// the injected Clock — plus (SDK v2) the read-only inter-rule views
// PriorFindings and GraphView. The cancellation context is passed
// separately (it is the detector's first argument). "Immutable" here was a
// convention until OPT-P1-2: the engine now clones the Context per rule job
// (cloneContextForRule) so a buggy or hostile rule that mutates its view
// cannot affect peers running in parallel. Dependencies order execution;
// they do not flow data — now PriorFindings/GraphView are the ONLY
// read-only dataflow (SDK v2, see GraphQuerier and the api.go reopening
// note).
type Context struct {
	// Assets is the deduplicated, identity-sorted core asset list.
	Assets []asset.Identity `json:"assets"`

	// Relationships is the deduplicated, ID-sorted edge list.
	Relationships []asset.Relationship `json:"relationships"`

	// Evidence is the identity-sorted, merged evidence records.
	Evidence []asset.Evidence `json:"evidence"`

	// Technologies is the identity-sorted, merged technology detections.
	Technologies []asset.Technology `json:"technologies"`

	// Secrets is the identity-sorted, merged secret candidates.
	Secrets []asset.SecretCandidate `json:"secrets"`

	// JavaScript is the identity-sorted, merged script assets.
	JavaScript []asset.JavaScript `json:"javascript"`

	// Endpoints is the identity-sorted, merged endpoints.
	Endpoints []asset.Endpoint `json:"endpoints"`

	// PriorFindings holds findings from completed dependency levels only,
	// deterministically sorted by finding identity (asset.Finding.Identity).
	// It is empty for level-0 rules and grows level by level as the
	// engine's level barrier collects completed findings. See GraphQuerier
	// for the companion view. A rule that declares dependencies can read
	// the findings its dependencies produced through this view; a rule
	// without dependencies sees an empty or nil slice. The slice is a
	// per-rule clone — a rule mutating it cannot affect peers — and its
	// contents obey the same observed-corpus contract as the snapshot
	// domains (findings cite only observed assets).
	PriorFindings []asset.Finding `json:"-"`

	// GraphView is the read-only traversal view over
	// Snapshot.Relationships+Assets (see GraphQuerier). Built once per Run
	// with a map index and shared immutably across rules; a per-rule clone
	// copies the handle, not the index. Never nil in a real Run — the
	// engine always installs it; a hand-constructed Context outside the
	// engine may carry nil (callers must nil-check).
	GraphView GraphQuerier `json:"-"`

	// Config is the run's bounded configuration map (typed strings only).
	Config map[string]string `json:"config,omitempty"`

	// Logger is the bounded logging seam (never nil).
	Logger Logger `json:"-"`

	// Clock is the injectable time seam (never nil).
	Clock runtime.Clock `json:"-"`
}

// cloneContextForRule returns a per-rule copy of src so parallel detectors
// cannot observe each other's mutations. Depth contract, pinned by
// TestCloneContextForRuleDepth (context_isolation_test.go) and the
// end-to-end TestContextIsolation:
//
//   - one level deep at the Context's own fields: every corpus slice
//     (Assets, Relationships, Evidence, Technologies, Secrets, JavaScript,
//     Endpoints) is cloned via slices.Clone into a fresh backing array and
//     Config via maps.Clone into a fresh map;
//   - no deeper copy is needed: the slice element types
//     (asset.Identity/Relationship/Evidence/Technology/SecretCandidate/
//     JavaScript/Endpoint) are immutable-by-value structs with no interior
//     slices, maps, or pointers, so copying the struct isolates it fully —
//     a rule mutating cp.Evidence[i].Value or appending to cp.Evidence
//     cannot affect siblings or the engine's original corpus;
//   - Logger and Clock are shared interfaces (they are documented
//     concurrency-safe seams, not per-rule state);
//   - PriorFindings is the SDK v2 inter-rule view: the slice header is
//     cloned via slices.Clone into a fresh backing array, and each
//     element's Metadata map layer is deep-cloned via maps.Clone into a
//     fresh map (maps.Clone is nil-safe: a nil Metadata stays nil). The
//     Finding values' inner Evidence/RelatedAssets/Relationships slice
//     elements remain shared read-only, like the other corpus domains —
//     a rule mutating cp.PriorFindings[i].Metadata cannot affect peers,
//     while the shared inner slices must only be read, never written;
//   - GraphView is the SDK v2 graph handle: it is a read-only index built
//     once per Run and shared immutably — the clone copies the interface
//     handle, not the index.
//
// Unexported: per-job cloning is an internal isolation mechanism; the
// exported Context type and its API remain frozen (SDK v2 golden).
func cloneContextForRule(src *Context) *Context {
	if src == nil {
		return nil
	}
	cp := *src
	cp.Assets = slices.Clone(src.Assets)
	cp.Relationships = slices.Clone(src.Relationships)
	cp.Evidence = slices.Clone(src.Evidence)
	cp.Technologies = slices.Clone(src.Technologies)
	cp.Secrets = slices.Clone(src.Secrets)
	cp.JavaScript = slices.Clone(src.JavaScript)
	cp.Endpoints = slices.Clone(src.Endpoints)
	cp.PriorFindings = slices.Clone(src.PriorFindings)
	for i := range cp.PriorFindings {
		cp.PriorFindings[i].Metadata = maps.Clone(src.PriorFindings[i].Metadata)
	}
	cp.GraphView = src.GraphView
	cp.Config = maps.Clone(src.Config)
	return &cp
}

// graphView is the engine's one-per-Run read-only graph index backing
// Context.GraphView. It is built once in Run from the normalized
// Snapshot.Relationships+Assets, is deterministically sorted, and never
// mutates after construction — a per-rule clone shares the handle.
type graphView struct {
	// adj maps From identity → outgoing relationships, each list sorted
	// by Relationship.ID(). The map and its slices are immutable after
	// newGraphView returns.
	adj map[asset.Identity][]asset.Relationship
	// nodes is the observed node set (Assets plus every relationship
	// endpoint) for Path endpoint validation.
	nodes map[asset.Identity]struct{}
}

var _ GraphQuerier = (*graphView)(nil)

// newGraphView builds the read-only index over the normalized corpus.
// Relationships are assumed ID-sorted and deduplicated (the corpus contract);
// outgoing lists are resorted by ID for determinism even if the input was
// already sorted.
func newGraphView(assets []asset.Identity, rels []asset.Relationship) *graphView {
	gv := &graphView{
		adj:   make(map[asset.Identity][]asset.Relationship, len(rels)),
		nodes: make(map[asset.Identity]struct{}, len(assets)+2*len(rels)),
	}
	for _, id := range assets {
		gv.nodes[id] = struct{}{}
	}
	for _, rel := range rels {
		gv.nodes[rel.From] = struct{}{}
		gv.nodes[rel.To] = struct{}{}
		gv.adj[rel.From] = append(gv.adj[rel.From], rel)
	}
	for from, list := range gv.adj {
		sort.Slice(list, func(i, j int) bool { return list[i].ID() < list[j].ID() })
		gv.adj[from] = list
	}
	return gv
}

// Neighbors implements GraphQuerier.
func (g *graphView) Neighbors(id asset.Identity) []asset.Relationship {
	if g == nil {
		return nil
	}
	list, ok := g.adj[id]
	if !ok || len(list) == 0 {
		return nil
	}
	out := make([]asset.Relationship, len(list))
	copy(out, list)
	return out
}

// Path implements GraphQuerier via deterministic BFS over the directed
// graph. Adjacencies are explored in Relationship.ID order, so the same
// graph always yields the same shortest path for the same endpoints.
// Returns nil when no directed path exists or either endpoint was never
// observed. The returned slice is a fresh copy; the caller may mutate it.
func (g *graphView) Path(from, to asset.Identity) []asset.Identity {
	if g == nil || from.IsZero() || to.IsZero() {
		return nil
	}
	if _, ok := g.nodes[from]; !ok {
		return nil
	}
	if _, ok := g.nodes[to]; !ok {
		return nil
	}
	if from == to {
		return []asset.Identity{from}
	}
	// BFS.
	queue := []asset.Identity{from}
	visited := map[asset.Identity]bool{from: true}
	parent := make(map[asset.Identity]asset.Identity)
	found := false
	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		for _, rel := range g.adj[cur] {
			nxt := rel.To
			if visited[nxt] {
				continue
			}
			visited[nxt] = true
			parent[nxt] = cur
			if nxt == to {
				found = true
				break
			}
			queue = append(queue, nxt)
		}
	}
	if !found {
		return nil
	}
	// Reconstruct reverse.
	path := []asset.Identity{to}
	for cur := to; cur != from; {
		p, ok := parent[cur]
		if !ok {
			return nil
		}
		path = append(path, p)
		cur = p
	}
	// Reverse.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// LogLevel is the severity of one rule log entry.
type LogLevel string

// Log levels.
const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// Valid reports whether l is one of the known levels.
func (l LogLevel) Valid() bool {
	switch l {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
		return true
	}
	return false
}

// LogEntry is one bounded rule log record.
type LogEntry struct {
	Level   LogLevel `json:"level"`
	Rule    string   `json:"rule"`
	Message string   `json:"message"`
}

// Logger is the logging seam rules receive. Implementations must be safe
// for concurrent use. The engine installs a bounded default logger when the
// EngineConfig carries none.
type Logger interface {
	Log(level LogLevel, ruleID, message string)
}

// boundedLogger is the engine's default Logger: it retains at most
// MaxLogEntries entries (sorted for the report) and counts the excess, so a
// flooding rule can never grow run memory without bound.
type boundedLogger struct {
	mu      sync.Mutex
	entries []LogEntry
	dropped int
}

// newBoundedLogger returns an empty bounded logger.
func newBoundedLogger() *boundedLogger {
	return &boundedLogger{}
}

// Log implements Logger.
func (l *boundedLogger) Log(level LogLevel, ruleID, message string) {
	if !level.Valid() {
		level = LevelInfo
	}
	if len(message) > MaxLogMessageBytes {
		message = message[:MaxLogMessageBytes]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= MaxLogEntries {
		l.dropped++
		return
	}
	l.entries = append(l.entries, LogEntry{Level: level, Rule: ruleID, Message: message})
}

// snapshot returns the retained entries sorted by (rule, level, message) —
// the deterministic report order (arrival order across parallel rules is
// nondeterministic and is deliberately not reported) — and the dropped count.
func (l *boundedLogger) snapshot() ([]LogEntry, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LogEntry, len(l.entries))
	copy(out, l.entries)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].Level != out[j].Level {
			return out[i].Level < out[j].Level
		}
		return out[i].Message < out[j].Message
	})
	return out, l.dropped
}

// corpus is the internal normalized run input: the Context plus the derived
// observation set rules' findings are validated against.
type corpus struct {
	context  Context
	observed map[asset.Identity]struct{}
	kinds    map[asset.Kind]int
}

// normalizeSnapshot validates, bounds, deduplicates, and sorts a caller
// snapshot and derives the observed identity set and the per-kind census
// (the required-asset-type gate). Every list is sorted by its canonical
// identity so the corpus — and therefore the cache fingerprint — is a
// deterministic function of the input multiset. Assets accepts any valid
// kind, not only the core graph kinds; non-core entries (findings,
// parameters, ...) are inert members of the observed set and the census —
// carried, never interpreted.
func normalizeSnapshot(s Snapshot) (*corpus, error) {
	if len(s.Assets) > maxSnapshotAssets {
		return nil, fmt.Errorf("detect: snapshot carries %d assets over bound %d", len(s.Assets), maxSnapshotAssets)
	}
	if len(s.Relationships) > maxSnapshotRelationships {
		return nil, fmt.Errorf("detect: snapshot carries %d relationships over bound %d", len(s.Relationships), maxSnapshotRelationships)
	}
	if len(s.Evidence) > maxSnapshotEvidence {
		return nil, fmt.Errorf("detect: snapshot carries %d evidence records over bound %d", len(s.Evidence), maxSnapshotEvidence)
	}
	if len(s.Technologies) > maxSnapshotTechnologies {
		return nil, fmt.Errorf("detect: snapshot carries %d technologies over bound %d", len(s.Technologies), maxSnapshotTechnologies)
	}
	if len(s.Secrets) > maxSnapshotSecrets {
		return nil, fmt.Errorf("detect: snapshot carries %d secret candidates over bound %d", len(s.Secrets), maxSnapshotSecrets)
	}
	if len(s.JavaScript) > maxSnapshotJavaScript {
		return nil, fmt.Errorf("detect: snapshot carries %d javascript assets over bound %d", len(s.JavaScript), maxSnapshotJavaScript)
	}
	if len(s.Endpoints) > maxSnapshotEndpoints {
		return nil, fmt.Errorf("detect: snapshot carries %d endpoints over bound %d", len(s.Endpoints), maxSnapshotEndpoints)
	}

	c := &corpus{
		observed: make(map[asset.Identity]struct{}, len(s.Assets)+len(s.Evidence)),
		kinds:    make(map[asset.Kind]int),
	}

	// Assets.
	assets := make([]asset.Identity, 0, len(s.Assets))
	for i, id := range s.Assets {
		if id.IsZero() {
			return nil, fmt.Errorf("detect: snapshot asset %d is a zero identity", i)
		}
		if !id.Kind.Valid() {
			return nil, fmt.Errorf("detect: snapshot asset %d (%s) has an unknown kind", i, id)
		}
		assets = append(assets, id)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].String() < assets[j].String() })
	assets = dedupeIdentities(assets)
	c.context.Assets = assets

	// Relationships.
	rels := make([]asset.Relationship, 0, len(s.Relationships))
	for i, rel := range s.Relationships {
		canonical, err := asset.NewRelationship(rel.From, rel.Kind, rel.To)
		if err != nil {
			return nil, fmt.Errorf("detect: snapshot relationship %d: %w", i, err)
		}
		if canonical != rel {
			return nil, fmt.Errorf("detect: snapshot relationship %d is not canonical", i)
		}
		rels = append(rels, rel)
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].ID() < rels[j].ID() })
	rels = dedupeRelationships(rels)
	c.context.Relationships = rels

	// Evidence.
	evidence := make([]asset.Evidence, 0, len(s.Evidence))
	for i, ev := range s.Evidence {
		canonical, err := asset.NewEvidence(ev.Method, ev.Indicator, ev.Value, ev.Source, ev.Prov)
		if err != nil {
			return nil, fmt.Errorf("detect: snapshot evidence %d: %w", i, err)
		}
		if canonical != ev {
			return nil, fmt.Errorf("detect: snapshot evidence %d is not canonical", i)
		}
		evidence = append(evidence, ev)
	}
	c.context.Evidence = mergeSortedEvidence(evidence)

	// Technologies.
	techs := make([]asset.Technology, 0, len(s.Technologies))
	for i, tech := range s.Technologies {
		canonical, err := asset.NewTechnology(tech.Name, tech.Category, tech.Prov)
		if err != nil {
			return nil, fmt.Errorf("detect: snapshot technology %d: %w", i, err)
		}
		if canonical.Identity() != tech.Identity() {
			return nil, fmt.Errorf("detect: snapshot technology %d is not canonical", i)
		}
		techs = append(techs, tech)
	}
	c.context.Technologies = mergeSortedTechnologies(techs)

	// Secrets.
	secrets := make([]asset.SecretCandidate, 0, len(s.Secrets))
	for i, sec := range s.Secrets {
		canonical, err := asset.NewSecretCandidate(sec.Type, sec.Value, sec.Source, sec.Prov)
		if err != nil {
			return nil, fmt.Errorf("detect: snapshot secret candidate %d: %w", i, err)
		}
		if canonical != sec {
			return nil, fmt.Errorf("detect: snapshot secret candidate %d is not canonical", i)
		}
		secrets = append(secrets, sec)
	}
	c.context.Secrets = mergeSortedSecrets(secrets)

	// JavaScript.
	scripts := make([]asset.JavaScript, 0, len(s.JavaScript))
	for i, js := range s.JavaScript {
		if js.URL.IsZero() {
			return nil, fmt.Errorf("detect: snapshot javascript %d has a zero URL", i)
		}
		reparsed, err := asset.ParseURL(js.URL.String(), js.Prov)
		if err != nil || reparsed.Identity() != js.URL.Identity() {
			return nil, fmt.Errorf("detect: snapshot javascript %d has a non-canonical URL", i)
		}
		scripts = append(scripts, js)
	}
	c.context.JavaScript = mergeSortedScripts(scripts)

	// Endpoints.
	endpoints := make([]asset.Endpoint, 0, len(s.Endpoints))
	for i, ep := range s.Endpoints {
		canonical, err := asset.NewEndpoint(ep.Method, ep.URL.String(), ep.Prov)
		if err != nil {
			return nil, fmt.Errorf("detect: snapshot endpoint %d: %w", i, err)
		}
		if canonical.Identity() != ep.Identity() {
			return nil, fmt.Errorf("detect: snapshot endpoint %d is not canonical", i)
		}
		endpoints = append(endpoints, ep)
	}
	c.context.Endpoints = mergeSortedEndpoints(endpoints)

	// Observed identity set and kind census.
	for _, id := range c.context.Assets {
		c.observed[id] = struct{}{}
		c.kinds[id.Kind]++
	}
	for _, ev := range c.context.Evidence {
		c.observed[ev.Identity()] = struct{}{}
		c.kinds[asset.KindEvidence]++
		if !ev.Source.IsZero() {
			c.observed[ev.Source] = struct{}{}
		}
	}
	for _, tech := range c.context.Technologies {
		c.observed[tech.Identity()] = struct{}{}
		c.kinds[asset.KindTechnology]++
	}
	for _, sec := range c.context.Secrets {
		c.observed[sec.Identity()] = struct{}{}
		c.kinds[asset.KindSecretCandidate]++
	}
	for _, js := range c.context.JavaScript {
		c.observed[js.Identity()] = struct{}{}
		c.kinds[asset.KindJavaScript]++
	}
	for _, ep := range c.context.Endpoints {
		c.observed[ep.Identity()] = struct{}{}
		c.kinds[asset.KindEndpoint]++
	}
	return c, nil
}

// validateConfig checks the bounded configuration map delivered to rules.
func validateConfig(cfg map[string]string) error {
	if len(cfg) > MaxContextConfigEntries {
		return fmt.Errorf("detect: configuration carries %d entries over bound %d", len(cfg), MaxContextConfigEntries)
	}
	for k, v := range cfg {
		if k == "" || len(k) > MaxContextConfigKeyBytes {
			return fmt.Errorf("detect: configuration key %q is empty or over %d bytes", k, MaxContextConfigKeyBytes)
		}
		if len(v) > MaxContextConfigValueBytes {
			return fmt.Errorf("detect: configuration value for %q is over %d bytes", k, MaxContextConfigValueBytes)
		}
	}
	return nil
}

func dedupeIdentities(list []asset.Identity) []asset.Identity {
	out := make([]asset.Identity, 0, len(list))
	for _, id := range list {
		if n := len(out); n > 0 && out[n-1] == id {
			continue
		}
		out = append(out, id)
	}
	return out
}

func dedupeRelationships(list []asset.Relationship) []asset.Relationship {
	out := make([]asset.Relationship, 0, len(list))
	for _, rel := range list {
		if n := len(out); n > 0 && out[n-1].ID() == rel.ID() {
			continue
		}
		out = append(out, rel)
	}
	return out
}

// mergeSortedEvidence merges same-identity evidence (input sorted by
// identity value) through the Phase 2 merge primitive.
func mergeSortedEvidence(list []asset.Evidence) []asset.Evidence {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().Value < list[j].Identity().Value
	})
	out := make([]asset.Evidence, 0, len(list))
	for _, ev := range list {
		if n := len(out); n > 0 {
			if merged, err := asset.MergeEvidence(out[n-1], ev); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, ev)
	}
	return out
}

func mergeSortedTechnologies(list []asset.Technology) []asset.Technology {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().Value < list[j].Identity().Value
	})
	out := make([]asset.Technology, 0, len(list))
	for _, t := range list {
		if n := len(out); n > 0 {
			if merged, err := asset.MergeTechnologies(out[n-1], t); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, t)
	}
	return out
}

func mergeSortedSecrets(list []asset.SecretCandidate) []asset.SecretCandidate {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().Value < list[j].Identity().Value
	})
	out := make([]asset.SecretCandidate, 0, len(list))
	for _, s := range list {
		if n := len(out); n > 0 {
			if merged, err := asset.MergeSecretCandidates(out[n-1], s); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

func mergeSortedScripts(list []asset.JavaScript) []asset.JavaScript {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().Value < list[j].Identity().Value
	})
	out := make([]asset.JavaScript, 0, len(list))
	for _, j := range list {
		if n := len(out); n > 0 {
			if merged, err := asset.MergeJavaScripts(out[n-1], j); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, j)
	}
	return out
}

func mergeSortedEndpoints(list []asset.Endpoint) []asset.Endpoint {
	sort.Slice(list, func(i, j int) bool {
		return list[i].Identity().Value < list[j].Identity().Value
	})
	out := make([]asset.Endpoint, 0, len(list))
	for _, e := range list {
		if n := len(out); n > 0 {
			if merged, err := asset.MergeEndpoints(out[n-1], e); err == nil {
				out[n-1] = merged
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// engineClock is the production runtime.Clock (local twin, mirroring the
// other consumer stages).
type engineClock struct{}

func (engineClock) Now() time.Time                         { return time.Now() }
func (engineClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
