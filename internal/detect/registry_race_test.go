package detect

import (
	"fmt"
	"sync"
	"testing"
)

// TestRegistrySealRegisterRace hammers Seal and Register concurrently and
// pins the race-freedom of the sealed fast path (regression for LOW-1: the
// unsynchronized readonly read in Register, plus the check-then-act window
// that let a registration pass the check and complete after Seal). The
// assertions are deterministic: every Register that ran to completion
// either succeeded before the seal (its rule is present afterwards) or
// failed with exactly the sealed error; the pre-seal rule survives; Len
// equals the pre-seal rule plus every recorded success; and a final
// Register after the dust settles still fails with the sealed error. No
// sleeps — the sealer runs unconditionally, so the registrars always
// terminate and the WaitGroup always completes. Must be clean under
// `go test -race`.
func TestRegistrySealRegisterRace(t *testing.T) {
	const (
		iterations      = 100
		registrars      = 4
		maxPerRegistrar = 32
	)

	// outcome is a registrar's complete report: every rule it managed to
	// register before the seal, plus the terminal error, if any.
	type outcome struct {
		registered []string
		err        error
	}

	for iter := 0; iter < iterations; iter++ {
		reg := NewRegistry()
		preID := fmt.Sprintf("race.pre.%d", iter)
		if err := reg.Register(makeRule(t, preID, nil)); err != nil {
			t.Fatalf("iteration %d: register pre-seal rule: %v", iter, err)
		}

		outcomes := make(chan outcome, registrars)
		var wg sync.WaitGroup
		for w := 0; w < registrars; w++ {
			wg.Add(1)
			go func(w, iter int) {
				defer wg.Done()
				var o outcome
				sealed := false
				for i := 0; i < maxPerRegistrar && !sealed; i++ {
					id := fmt.Sprintf("race.w%d.%d.%d", w, iter, i)
					err := reg.Register(makeRule(t, id, nil))
					switch {
					case err == nil:
						o.registered = append(o.registered, id)
					case err.Error() == "detect: registry is sealed":
						sealed = true
					default:
						o.err = fmt.Errorf("register %q: %w", id, err)
						outcomes <- o
						return
					}
				}
				outcomes <- o
			}(w, iter)
		}

		// The single sealer: every registrar terminates once the seal
		// lands, so the WaitGroup always completes (no deadlock).
		reg.Seal()
		wg.Wait()
		close(outcomes)

		// Every Register that ran to completion either succeeded before
		// the seal (rule present) or failed with the sealed error.
		totalRegistered := 0
		for o := range outcomes {
			if o.err != nil {
				t.Fatalf("iteration %d: %v", iter, o.err)
			}
			for _, id := range o.registered {
				totalRegistered++
				if _, ok := reg.Get(id); !ok {
					t.Fatalf("iteration %d: rule %q registered before seal is missing", iter, id)
				}
			}
		}

		// Pre-seal rule survives, and the count is exact.
		if _, ok := reg.Get(preID); !ok {
			t.Fatalf("iteration %d: pre-seal rule %q missing", iter, preID)
		}
		if want := 1 + totalRegistered; reg.Len() != want {
			t.Fatalf("iteration %d: Len = %d, want %d (pre-seal rule + %d registered)",
				iter, reg.Len(), want, totalRegistered)
		}

		// Registration after the seal still fails with the sealed error.
		if err := reg.Register(makeRule(t, fmt.Sprintf("race.after.%d", iter), nil)); err == nil || err.Error() != "detect: registry is sealed" {
			t.Fatalf("iteration %d: register after seal must fail with the sealed error, got %v", iter, err)
		}
	}
}
