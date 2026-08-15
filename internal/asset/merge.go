package asset

import "fmt"

// Merge functions combine two observations of the same asset into a single
// representation. They are the primitives a future correlation engine will
// build on; they never merge distinct assets.
//
// Merge rules are deterministic:
//   - identities must match exactly, otherwise an error is returned
//   - the earliest discovery time wins for provenance
//   - the first non-empty original representation is kept
//   - URL fragments are preserved from whichever side has one

func earliestProv(a, b Provenance) Provenance {
	if a.DiscoveredAt.IsZero() {
		return b
	}
	if b.DiscoveredAt.IsZero() {
		return a
	}
	if a.DiscoveredAt.After(b.DiscoveredAt) {
		return b
	}
	return a
}

func preferOriginal(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func mergeMismatch(kind Kind, a, b Identity) error {
	return fmt.Errorf("cannot merge %s: identities differ (%s != %s)", kind, a, b)
}

// MergeDomains combines two observations of the same domain.
func MergeDomains(a, b Domain) (Domain, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Domain{}, mergeMismatch(KindDomain, a.Identity(), b.Identity())
	}
	m := a
	m.Original = preferOriginal(a.Original, b.Original)
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergeHosts combines two observations of the same host.
func MergeHosts(a, b Host) (Host, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Host{}, mergeMismatch(KindHost, a.Identity(), b.Identity())
	}
	m := a
	m.Original = preferOriginal(a.Original, b.Original)
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergeIPs combines two observations of the same IP address.
func MergeIPs(a, b IP) (IP, error) {
	if !a.Identity().Equal(b.Identity()) {
		return IP{}, mergeMismatch(KindIP, a.Identity(), b.Identity())
	}
	m := a
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergePorts combines two observations of the same port.
func MergePorts(a, b Port) (Port, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Port{}, mergeMismatch(KindPort, a.Identity(), b.Identity())
	}
	m := a
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergeServices combines two observations of the same service.
func MergeServices(a, b Service) (Service, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Service{}, mergeMismatch(KindService, a.Identity(), b.Identity())
	}
	m := a
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergeURLs combines two observations of the same canonical URL.
func MergeURLs(a, b URL) (URL, error) {
	if !a.Identity().Equal(b.Identity()) {
		return URL{}, mergeMismatch(KindURL, a.Identity(), b.Identity())
	}
	m := a
	m.Original = preferOriginal(a.Original, b.Original)
	if m.Fragment == "" {
		m.Fragment = b.Fragment
	}
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// MergeEndpoints combines two observations of the same endpoint.
func MergeEndpoints(a, b Endpoint) (Endpoint, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Endpoint{}, mergeMismatch(KindEndpoint, a.Identity(), b.Identity())
	}
	mergedURL, err := MergeURLs(a.URL, b.URL)
	if err != nil {
		return Endpoint{}, err
	}
	out := a
	out.URL = mergedURL
	out.Method = a.Method
	out.Prov = earliestProv(a.Prov, b.Prov)
	return out, nil
}

// MergeJavaScripts combines two observations of the same script resource.
func MergeJavaScripts(a, b JavaScript) (JavaScript, error) {
	if !a.Identity().Equal(b.Identity()) {
		return JavaScript{}, mergeMismatch(KindJavaScript, a.Identity(), b.Identity())
	}
	mergedURL, err := MergeURLs(a.URL, b.URL)
	if err != nil {
		return JavaScript{}, err
	}
	out := a
	out.URL = mergedURL
	if a.Hash != "" {
		out.Hash = a.Hash
	} else {
		out.Hash = b.Hash
	}
	out.Prov = earliestProv(a.Prov, b.Prov)
	return out, nil
}

// MergeParameters combines two observations of the same parameter.
//
// The value lists are unioned preserving a's order first, then b's new
// values in first-seen order; values beyond maxParameterValues are dropped
// (existing values are never evicted) and Truncated is set when either side
// was truncated or the union exceeded the cap. FirstSeen is the earliest
// and LastSeen the latest of the two observations; Sources are unioned in
// order, deduplicated; provenance is the earliest observation's.
func MergeParameters(a, b Parameter) (Parameter, error) {
	if !a.Identity().Equal(b.Identity()) {
		return Parameter{}, mergeMismatch(KindParameter, a.Identity(), b.Identity())
	}
	m := a
	truncated := a.Truncated
	seen := make(map[string]struct{}, len(a.ObservedValues)+len(b.ObservedValues))
	for _, v := range a.ObservedValues {
		seen[v] = struct{}{}
	}
	for _, v := range b.ObservedValues {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		if len(m.ObservedValues) >= maxParameterValues {
			truncated = true
			continue
		}
		m.ObservedValues = append(m.ObservedValues, v)
	}
	if a.FirstSeen.IsZero() {
		m.FirstSeen = b.FirstSeen
	} else if !b.FirstSeen.IsZero() && b.FirstSeen.Before(a.FirstSeen) {
		m.FirstSeen = b.FirstSeen
	}
	if b.LastSeen.After(a.LastSeen) {
		m.LastSeen = b.LastSeen
	}
	for _, s := range b.Sources {
		if !containsString(m.Sources, s) {
			m.Sources = append(m.Sources, s)
		}
	}
	m.Truncated = truncated || b.Truncated
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}
