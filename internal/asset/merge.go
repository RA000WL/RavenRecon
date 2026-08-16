package asset

import (
	"fmt"
	"time"
)

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
//
// Rules, mirroring the other Merge primitives:
//   - identities (canonical URLs) must match exactly, otherwise an error is
//     returned
//   - the URL fields themselves merge via MergeURLs (Original first-wins,
//     Fragment preserved)
//   - provenance is the earliest observation's
//   - conflicting observation fields (Hash, Host, ContentHash, Size,
//     ContentType, ETag, LastModified, DiscoverySource, StatusCode, FinalURL):
//     the unset value loses to the set one; when both are set and DIFFER, the
//     value from the observation with the EARLIER DiscoveredAt wins, and an
//     exact tie (or an unresolvable comparison, e.g. a zero timestamp)
//     resolves deterministically to a's value. This deliberately mirrors the
//     TLS certificate merge: the fields describe ONE script resource, and the
//     earliest observation is the canonical record
//
// The result is deterministic and order-independent: merge(a, b) equals
// merge(b, a) field-for-field whenever the two observations' DiscoveredAt
// times differ (exact ties resolve to the first argument, like the other
// merge primitives).
func MergeJavaScripts(a, b JavaScript) (JavaScript, error) {
	if !a.Identity().Equal(b.Identity()) {
		return JavaScript{}, mergeMismatch(KindJavaScript, a.Identity(), b.Identity())
	}
	mergedURL, err := MergeURLs(a.URL, b.URL)
	if err != nil {
		return JavaScript{}, err
	}
	m := a
	m.URL = mergedURL
	m.Hash = preferJavaScriptString(a, b, a.Hash, b.Hash)
	m.Host = preferJavaScriptHost(a, b)
	m.ContentHash = preferJavaScriptString(a, b, a.ContentHash, b.ContentHash)
	m.Size = preferJavaScriptInt64(a, b, a.Size, b.Size)
	m.ContentType = preferJavaScriptString(a, b, a.ContentType, b.ContentType)
	m.ETag = preferJavaScriptString(a, b, a.ETag, b.ETag)
	m.LastModified = preferJavaScriptTime(a, b, a.LastModified, b.LastModified)
	m.DiscoverySource = preferJavaScriptString(a, b, a.DiscoverySource, b.DiscoverySource)
	m.StatusCode = preferJavaScriptInt(a, b, a.StatusCode, b.StatusCode)
	m.FinalURL = preferJavaScriptFinalURL(a, b)
	m.Prov = earliestProv(a.Prov, b.Prov)
	return m, nil
}

// jsObservedEarlier reports whether b's observation predates a's. A
// zero-time observation on either side is unresolvable and reports false
// (ties resolve to a, the first argument).
func jsObservedEarlier(a, b JavaScript) bool {
	return !a.Prov.DiscoveredAt.IsZero() && !b.Prov.DiscoveredAt.IsZero() && b.Prov.DiscoveredAt.Before(a.Prov.DiscoveredAt)
}

// preferJavaScriptString picks the deterministic merged value for a
// conflicting observation field: the non-empty value wins; when both are
// non-empty and DIFFER, the earlier observation's value wins (see
// MergeJavaScripts); an exact tie or an unresolvable comparison resolves to
// a's value.
func preferJavaScriptString(a, b JavaScript, av, bv string) string {
	if av == "" {
		return bv
	}
	if bv == "" {
		return av
	}
	if av == bv {
		return av
	}
	if jsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferJavaScriptInt is preferJavaScriptString for ints; zero is the unset
// value (status code).
func preferJavaScriptInt(a, b JavaScript, av, bv int) int {
	if av == 0 {
		return bv
	}
	if bv == 0 {
		return av
	}
	if av == bv {
		return av
	}
	if jsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferJavaScriptInt64 is preferJavaScriptInt for int64 (script body size).
func preferJavaScriptInt64(a, b JavaScript, av, bv int64) int64 {
	if av == 0 {
		return bv
	}
	if bv == 0 {
		return av
	}
	if av == bv {
		return av
	}
	if jsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferJavaScriptTime is preferJavaScriptString for times; the zero time is
// the unset value (Last-Modified).
func preferJavaScriptTime(a, b JavaScript, av, bv time.Time) time.Time {
	if av.IsZero() {
		return bv
	}
	if bv.IsZero() {
		return av
	}
	if av.Equal(bv) {
		return av
	}
	if jsObservedEarlier(a, b) {
		return bv
	}
	return av
}

// preferJavaScriptHost resolves a conflicting observed host: the set host
// wins over the zero host; when both are set and DIFFER, the earlier
// observation's host wins; an unresolvable comparison resolves to a's.
func preferJavaScriptHost(a, b JavaScript) Host {
	aSet := !a.Host.Identity().IsZero()
	bSet := !b.Host.Identity().IsZero()
	switch {
	case !aSet:
		return b.Host
	case !bSet:
		return a.Host
	case a.Host == b.Host:
		return a.Host
	case jsObservedEarlier(a, b):
		return b.Host
	default:
		return a.Host
	}
}

// preferJavaScriptFinalURL resolves a conflicting observed final URL: the set
// URL wins over the zero URL; when both are set and DIFFER, the earlier
// observation's URL wins; an unresolvable comparison resolves to a's. Set
// URLs are compared by canonical identity, so two raw forms that canonicalize
// to the same URL are the same observation.
func preferJavaScriptFinalURL(a, b JavaScript) URL {
	switch {
	case a.FinalURL == (URL{}):
		return b.FinalURL
	case b.FinalURL == (URL{}):
		return a.FinalURL
	case a.FinalURL.Identity().Equal(b.FinalURL.Identity()):
		return a.FinalURL
	case jsObservedEarlier(a, b):
		return b.FinalURL
	default:
		return a.FinalURL
	}
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
