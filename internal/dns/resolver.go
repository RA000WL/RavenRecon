package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// RecordType identifies the DNS record family a query asks for. The string
// values are stable identifiers used in cache keys and stored records; they
// must not change.
type RecordType string

// Supported record types. The package resolves exactly these three; other
// record families are outside the 5A milestone.
const (
	// TypeA queries IPv4 (A) records.
	TypeA RecordType = "A"
	// TypeAAAA queries IPv6 (AAAA) records.
	TypeAAAA RecordType = "AAAA"
	// TypeCNAME queries the CNAME chain's final canonical target.
	TypeCNAME RecordType = "CNAME"
)

// String returns the stable record-type identifier.
func (t RecordType) String() string { return string(t) }

// ErrorKind classifies a failed DNS query so callers can react per kind
// without parsing resolver-specific messages.
type ErrorKind int

const (
	// ErrCancelled: the query was cancelled (context cancellation or
	// deadline exceeded while the query was in flight or waiting for a rate
	// limit token).
	ErrCancelled ErrorKind = iota
	// ErrTimeout: the resolver reported a timeout.
	ErrTimeout
	// ErrTemporary: the resolver reported a temporary failure (for example
	// SERVFAIL as classified by the standard library).
	ErrTemporary
	// ErrNotFound: the name does not exist (NXDOMAIN-equivalent per the
	// standard library's IsNotFound classification).
	ErrNotFound
	// ErrFailure: any other resolver failure (including SERVFAIL and REFUSED
	// when the standard library does not classify them as temporary).
	ErrFailure
)

// String returns a stable label for k.
func (k ErrorKind) String() string {
	switch k {
	case ErrCancelled:
		return "cancelled"
	case ErrTimeout:
		return "timeout"
	case ErrTemporary:
		return "temporary"
	case ErrNotFound:
		return "not-found"
	case ErrFailure:
		return "failure"
	default:
		return fmt.Sprintf("error-kind(%d)", int(k))
	}
}

// QueryError is the typed classification of one failed DNS query. It wraps
// the underlying cause, so errors.Is/errors.As still reach context errors and
// *net.DNSError values.
type QueryError struct {
	// Kind classifies the failure.
	Kind ErrorKind
	// Host is the queried hostname (canonical form).
	Host string
	// Type is the queried record type.
	Type RecordType
	// Err is the underlying resolver error; never nil.
	Err error
}

// Error implements error.
func (e *QueryError) Error() string {
	return fmt.Sprintf("dns: query %s %s: %s: %v", e.Host, e.Type, e.Kind, e.Err)
}

// Unwrap exposes the underlying cause for errors.Is/errors.As.
func (e *QueryError) Unwrap() error { return e.Err }

// KindOf reports the ErrorKind of err, or 0 (ErrCancelled) plus ok=false when
// err is nil. Callers that only care whether err is a typed query failure use
// this instead of peeling QueryError themselves.
func KindOf(err error) (ErrorKind, bool) {
	var qe *QueryError
	if errors.As(err, &qe) {
		return qe.Kind, true
	}
	return 0, false
}

// Resolver is the minimal query abstraction the pipeline needs: per-record
// type queries returning multiple or empty answers. Implementations return
// raw answer strings (hostnames for CNAME, address strings for A/AAAA); every
// string is re-validated and normalized through the Phase 2 asset model by
// the pipeline before it becomes an observation — a resolver can never inject
// non-canonical assets.
//
// Errors must be typed: a *QueryError classifying NXDOMAIN (ErrNotFound),
// timeout (ErrTimeout), temporary failure (ErrTemporary), cancellation
// (ErrCancelled), or any other failure (ErrFailure). Returning a plain error
// is treated as ErrFailure.
type Resolver interface {
	// Lookup resolves host for the given record type. It returns a nil error
	// with an empty answer slice for legitimate empty answers (NODATA-style:
	// the name exists but has no records of the requested type), and a
	// *QueryError with Kind ErrNotFound for NXDOMAIN-equivalent results so
	// the two negative outcomes stay distinguishable.
	Lookup(ctx context.Context, host string, rt RecordType) ([]string, error)
}

// NetResolver is the production Resolver over the standard library's pure-Go
// resolver (net.Resolver with PreferGo): it honors the system resolver
// configuration (/etc/resolv.conf and friends), supports context
// cancellation, and surfaces *net.DNSError classifications that this adapter
// maps into the package's typed QueryError kinds.
//
// A and AAAA queries use LookupNetIP with the "ip4"/"ip6" network families.
// CNAME queries use LookupCNAME, which follows the chain to the final
// canonical target: single-hop chains are returned directly, and multi-hop
// chains are flattened to their final target (captured as host ->
// canonical-target; see the multi-hop flattening limitation in the package
// documentation). LookupCNAME returns the host itself when it has no CNAME
// record; the pipeline treats a target identical to the queried host as "no
// CNAME observation".
type NetResolver struct {
	r *net.Resolver
}

// NewNetResolver returns a Resolver backed by a fresh pure-Go net.Resolver.
func NewNetResolver() *NetResolver {
	return &NetResolver{r: &net.Resolver{PreferGo: true}}
}

// Lookup implements Resolver.
func (n *NetResolver) Lookup(ctx context.Context, host string, rt RecordType) ([]string, error) {
	if n.r == nil {
		n.r = &net.Resolver{PreferGo: true}
	}
	switch rt {
	case TypeA:
		addrs, err := n.r.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, classifyQueryError(host, rt, err)
		}
		return netIPsToStrings(addrs), nil
	case TypeAAAA:
		addrs, err := n.r.LookupNetIP(ctx, "ip6", host)
		if err != nil {
			return nil, classifyQueryError(host, rt, err)
		}
		return netIPsToStrings(addrs), nil
	case TypeCNAME:
		cname, err := n.r.LookupCNAME(ctx, host)
		if err != nil {
			return nil, classifyQueryError(host, rt, err)
		}
		// LookupCNAME returns the host itself when it has no CNAME record.
		// The pipeline drops self-targets after normalization, so returning
		// the raw string here is safe and keeps the adapter dumb.
		if cname == "" {
			return []string{}, nil
		}
		return []string{cname}, nil
	default:
		return nil, &QueryError{
			Kind: ErrFailure,
			Host: host,
			Type: rt,
			Err:  fmt.Errorf("dns: unsupported record type %q", rt),
		}
	}
}

// netIPsToStrings renders netip.Addr values in canonical string form.
func netIPsToStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	return out
}

// classifyQueryError maps a resolver error into a typed QueryError.
//
// Context errors are checked FIRST: errors.Is unwraps through
// *net.DNSError.Unwrap natively, so a stdlib-shaped cancellation — the
// *net.DNSError wrapping ctx.Err() that the pure-Go resolver surfaces when
// a query's context fires — classifies as ErrCancelled even when the
// resolver stamped IsTimeout/IsTemporary on it as well. Cancellation wins
// over every resolver flag: a cancelled query is a teardown event, never a
// failure or a timeout the caller could retry.
//
// Only when no context error is reachable do the standard library's flags
// apply, in its own priority order: IsNotFound (NXDOMAIN) -> ErrNotFound;
// IsTimeout -> ErrTimeout; IsTemporary -> ErrTemporary; everything else ->
// ErrFailure. Errors without a *net.DNSError classification that are not
// context errors are reported as ErrFailure.
//
// Cancellation-in-flight honesty: the stdlib pure-Go resolver does NOT
// abort an in-flight UDP query when its context is cancelled — the read
// fails only at the per-attempt deadline (resolv.conf timeout, retried per
// the attempts count), which the resolver then surfaces as a *net.DNSError
// with IsTimeout|IsTemporary and NO reachable context error. Because no
// context error is reachable, that shape classifies as ErrTimeout — the
// honest classification for the query the resolver actually performed.
// RavenRecon's own code issues no further queries once its context is done,
// and the pool shutdown budgets bound the overall drain (see ARCHITECTURE.md
// "DNS pipeline" — cancellation).
func classifyQueryError(host string, rt RecordType, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &QueryError{Kind: ErrCancelled, Host: host, Type: rt, Err: err}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return &QueryError{Kind: ErrNotFound, Host: host, Type: rt, Err: err}
		case dnsErr.IsTimeout:
			return &QueryError{Kind: ErrTimeout, Host: host, Type: rt, Err: err}
		case dnsErr.IsTemporary:
			return &QueryError{Kind: ErrTemporary, Host: host, Type: rt, Err: err}
		default:
			return &QueryError{Kind: ErrFailure, Host: host, Type: rt, Err: err}
		}
	}
	return &QueryError{Kind: ErrFailure, Host: host, Type: rt, Err: err}
}
