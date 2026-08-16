package priority

// Recommendation is one piece of evidence-tied reconnaissance guidance for
// a scored surface, projected from the surface's factor list. The text was
// rendered at score time from the winning catalog entry's template (the
// first %s substituted with the matched term), so it cites exactly the
// evidence the factor cites.
//
// Recommendation language is reconnaissance guidance only: inventory,
// verify, record, route to the verification queue. It is never an
// exploitation instruction and never a vulnerability claim.
type Recommendation struct {
	// Factor is the name of the factor the guidance resolves from
	// ("interestingness:admin", "risk:high_value_secret", ...).
	Factor string `json:"factor"`

	// Text is the rendered guidance.
	Text string `json:"text"`

	// Evidence is the cited factor's evidence references — the audit trail
	// from guidance to observation.
	Evidence []string `json:"evidence,omitempty"`

	// Weight is the cited factor's weight.
	Weight float64 `json:"weight"`
}

// Recommend projects a scored surface's factor list into its
// evidence-tied reconnaissance guidance, in the surface's deterministic
// factor order. Only indicator factors carry recommendations; confidence
// factors (not indicator-driven) contribute none. The projection is pure:
// it reads the factor list alone, keeps the rendered texts verbatim, and
// involves no catalogs, no clock, no I/O, and no mutable state — a
// cache-served SurfaceAsset therefore recommends identically to the fresh
// one that was stored.
func Recommend(s SurfaceAsset) []Recommendation {
	var out []Recommendation
	for _, f := range s.Factors {
		if f.Recommendation == "" {
			continue
		}
		out = append(out, Recommendation{
			Factor:   f.Name,
			Text:     f.Recommendation,
			Evidence: f.Evidence,
			Weight:   f.Weight,
		})
	}
	return out
}
