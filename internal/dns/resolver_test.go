package dns

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestClassifyQueryErrorDnsError maps every *net.DNSError flag combination
// into the typed QueryError kinds, exactly as the production adapter would
// classify the stdlib pure-Go resolver's errors. Hermetic: synthetic errors,
// no network.
func TestClassifyQueryErrorDnsError(t *testing.T) {
	const host = "www.example.com"
	cases := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"nxdomain", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}, ErrNotFound},
		{"timeout", &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true}, ErrTimeout},
		{"temporary", &net.DNSError{Err: "server misbehaving", Name: host, IsTemporary: true}, ErrTemporary},
		{"temporary plus timeout", &net.DNSError{Err: "i/o timeout", Name: host, IsTimeout: true, IsTemporary: true}, ErrTimeout},
		{"notfound wins over temporary", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true, IsTemporary: true}, ErrNotFound},
		{"servfail without flags", &net.DNSError{Err: "server misbehaving", Name: host}, ErrFailure},
		{"refused", &net.DNSError{Err: "refused", Name: host}, ErrFailure},
		{"plain error", errors.New("boom"), ErrFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyQueryError(host, TypeA, tc.err)
			kind, ok := KindOf(got)
			if !ok {
				t.Fatalf("classifyQueryError returned %T, want a *QueryError", got)
			}
			if kind != tc.want {
				t.Fatalf("kind = %s, want %s", kind, tc.want)
			}
			// The underlying cause must stay reachable.
			if !errors.Is(got, tc.err) {
				t.Fatal("QueryError must unwrap to the underlying error")
			}
		})
	}
}

// TestClassifyQueryErrorCancellation maps context cancellation and deadline
// errors (as a resolver would surface them on a cancelled query) to
// ErrCancelled.
func TestClassifyQueryErrorCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := classifyQueryError("www.example.com", TypeA, ctx.Err())
	kind, ok := KindOf(got)
	if !ok || kind != ErrCancelled {
		t.Fatalf("cancelled query kind = %v/%v, want ErrCancelled", kind, ok)
	}
	if !errors.Is(got, context.Canceled) {
		t.Fatal("QueryError must unwrap to context.Canceled")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 0)
	defer cancel2()
	got = classifyQueryError("www.example.com", TypeA, ctx2.Err())
	kind, _ = KindOf(got)
	if kind != ErrCancelled {
		t.Fatalf("deadline query kind = %s, want ErrCancelled", kind)
	}
}

// TestClassifyQueryErrorStdlibShapedCancellation covers the exact error
// shape the Go stdlib pure-Go resolver surfaces for a query cancelled
// mid-flight (verified against the Go 1.26 stdlib source: the surfaced
// error is a *net.DNSError whose UnwrapErr is the context error; the
// read-deadline path additionally stamps IsTimeout|IsTemporary). Both
// shapes must classify as ErrCancelled — the context error wins over the
// resolver flags — never as ErrFailure or ErrTimeout, so the pipeline
// records the type cancelled and the host StatusCancelled.
func TestClassifyQueryErrorStdlibShapedCancellation(t *testing.T) {
	const host = "www.example.com"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelErr := ctx.Err()

	shapes := []struct {
		name string
		err  error
	}{
		{"no flags", &net.DNSError{Err: cancelErr.Error(), Name: host, UnwrapErr: cancelErr}},
		{"timeout flags", &net.DNSError{Err: cancelErr.Error(), Name: host, IsTimeout: true, IsTemporary: true, UnwrapErr: cancelErr}},
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			got := classifyQueryError(host, TypeA, sh.err)
			kind, ok := KindOf(got)
			if !ok || kind != ErrCancelled {
				t.Fatalf("kind = %v/%v, want ErrCancelled", kind, ok)
			}
			if !errors.Is(got, context.Canceled) {
				t.Fatal("QueryError must unwrap to context.Canceled")
			}
		})
	}
}

// TestClassifyQueryErrorNil verifies nil maps to nil.
func TestClassifyQueryErrorNil(t *testing.T) {
	if got := classifyQueryError("www.example.com", TypeA, nil); got != nil {
		t.Fatalf("classifyQueryError(nil) = %v, want nil", got)
	}
}

// TestNetResolverUnsupportedType verifies the production adapter rejects
// record types outside the supported set without touching the network.
func TestNetResolverUnsupportedType(t *testing.T) {
	r := NewNetResolver()
	_, err := r.Lookup(context.Background(), "www.example.com", RecordType("MX"))
	if err == nil {
		t.Fatal("Lookup(MX) succeeded; want an error")
	}
	if kind, ok := KindOf(err); !ok || kind != ErrFailure {
		t.Fatalf("unsupported type kind = %v/%v, want ErrFailure", kind, ok)
	}
}

// TestKindOfUntypedError verifies KindOf reports false for non-typed errors
// and true for *QueryError values.
func TestKindOfUntypedError(t *testing.T) {
	if _, ok := KindOf(errors.New("plain")); ok {
		t.Fatal("KindOf(plain error) = true; want false")
	}
	qe := &QueryError{Kind: ErrNotFound, Host: "x", Type: TypeA, Err: errors.New("no such host")}
	if k, ok := KindOf(qe); !ok || k != ErrNotFound {
		t.Fatalf("KindOf(QueryError) = %v/%v, want ErrNotFound/true", k, ok)
	}
}

// TestQueryErrorStrings verifies stable, bounded error rendering.
func TestQueryErrorStrings(t *testing.T) {
	qe := &QueryError{Kind: ErrTimeout, Host: "www.example.com", Type: TypeA, Err: errors.New("i/o timeout")}
	want := `dns: query www.example.com A: timeout: i/o timeout`
	if got := qe.Error(); got != want {
		t.Fatalf("QueryError.Error() = %q, want %q", got, want)
	}
}
