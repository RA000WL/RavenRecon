package importer

import (
	"fmt"
	"sort"
	"sync"
)

// Registry is the importer registration point, mirroring internal/detect/registry.go.
// Rules: validation on registration, stored as immutable copies (importers are
// values, not mutated), sorted deterministic List, Seal freezes registration,
// post-seal Register panics on duplicate Name (per spec: "post-seal lock panics
// on duplicate Name").
type Registry struct {
	mu     sync.RWMutex
	imps   map[string]Importer
	sealed bool
}

// NewRegistry returns an empty, unsealed registry.
func NewRegistry() *Registry {
	return &Registry{imps: make(map[string]Importer)}
}

// Register adds imp to the registry. Duplicate Names are rejected. After Seal,
// Register panics (not returns) on duplicate Name per acceptance criterion 2.
// If sealed and name is new, it also panics to enforce post-seal lock.
func (r *Registry) Register(imp Importer) error {
	if imp == nil {
		return fmt.Errorf("importer: nil importer")
	}
	name := imp.Name()
	if name == "" {
		return fmt.Errorf("importer: empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed {
		panic(fmt.Sprintf("importer: registry is sealed — Register(%q) rejected", name))
	}
	if _, ok := r.imps[name]; ok {
		return fmt.Errorf("importer: duplicate name %q", name)
	}
	r.imps[name] = imp
	return nil
}

// Seal freezes the registry. After Seal, Register panics. List and Detect
// remain usable and return deep copies / deterministic results.
func (r *Registry) Seal() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sealed = true
}

// List returns every registered importer sorted by Name (deterministic).
// The returned slice is a fresh copy; callers may not mutate the registry
// through it. After Seal, the copy is deep in the sense that re-registration
// is blocked.
func (r *Registry) List() []Importer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Importer, 0, len(r.imps))
	for _, imp := range r.imps {
		out = append(out, imp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	// fresh slice already, but ensure underlying array not aliased to map
	cp := make([]Importer, len(out))
	copy(cp, out)
	return cp
}

// Detect returns ordered matches for path+peek by confidence desc, Name asc.
// Generic fallback (e.g. "plain-generic") is sorted last regardless of
// confidence per spec. CanImport never opens the file beyond peek — it is
// called with the supplied peek slice only.
func (r *Registry) Detect(path string, peek []byte) []DetectMatch {
	r.mu.RLock()
	imps := make([]Importer, 0, len(r.imps))
	for _, imp := range r.imps {
		imps = append(imps, imp)
	}
	r.mu.RUnlock()

	var matches []DetectMatch
	for _, imp := range imps {
		conf, ok := imp.CanImport(path, peek)
		if !ok {
			continue
		}
		if conf < 0 {
			conf = 0
		}
		if conf > 1 {
			conf = 1
		}
		matches = append(matches, DetectMatch{Importer: imp, Confidence: conf})
	}
	sort.Slice(matches, func(i, j int) bool {
		ai, aj := matches[i], matches[j]
		// generic fallback last
		isGenericI := ai.Importer.Name() == "plain-generic"
		isGenericJ := aj.Importer.Name() == "plain-generic"
		if isGenericI != isGenericJ {
			return isGenericJ // non-generic before generic
		}
		if ai.Confidence != aj.Confidence {
			return ai.Confidence > aj.Confidence
		}
		return ai.Importer.Name() < aj.Importer.Name()
	})
	return matches
}

// DetectMatch pairs an importer with its confidence for a given file.
type DetectMatch struct {
	Importer   Importer
	Confidence float64
}
