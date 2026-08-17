package report

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func okReporter(id string) Reporter {
	return Reporter{
		ID: id, Name: "Reporter " + id, Description: "test reporter",
		Version: "1.0.0", Format: FormatJSON, Enabled: true,
		Render: func(ctx context.Context, m *Model, s Sink) error { return nil },
	}
}

func TestRegistryRegisterValidates(t *testing.T) {
	cases := []struct {
		name string
		rep  Reporter
		want string
	}{
		{"empty id", Reporter{ID: "", Name: "n", Description: "d", Version: "1.0.0", Format: FormatJSON, Render: func(context.Context, *Model, Sink) error { return nil }}, "report id"},
		{"uppercase id", okReporter("JSON"), "outside [a-z0-9.-]"},
		{"empty name", func() Reporter { r := okReporter("x"); r.Name = ""; return r }(), "report name"},
		{"long description", func() Reporter { r := okReporter("x"); r.Description = strings.Repeat("d", 600); return r }(), "description"},
		{"bad format", func() Reporter { r := okReporter("x"); r.Format = Format("pdf"); return r }(), "unknown format"},
		{"nil render", func() Reporter { r := okReporter("x"); r.Render = nil; return r }(), "render function"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewRegistry()
			if err := reg.Register(tc.rep); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestRegistryDuplicateIDAndName(t *testing.T) {
	reg := NewRegistry()
	if err := reg.Register(okReporter("json")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := reg.Register(okReporter("json")); err == nil || !strings.Contains(err.Error(), "duplicate reporter id") {
		t.Fatalf("duplicate id accepted: %v", err)
	}
	second := okReporter("other")
	second.Name = "REPORTER JSON" // case-insensitive duplicate
	if err := reg.Register(second); err == nil || !strings.Contains(err.Error(), "duplicates reporter") {
		t.Fatalf("duplicate name accepted: %v", err)
	}
}

func TestRegistryReportsSortedAndSeal(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	if reg.Len() != 4 {
		t.Fatalf("builtins = %d, want 4", reg.Len())
	}
	reps := reg.Reports()
	if len(reps) != 4 {
		t.Fatalf("reports = %d", len(reps))
	}
	for i := 1; i < len(reps); i++ {
		if reps[i-1].ID >= reps[i].ID {
			t.Fatalf("registry order not sorted: %q >= %q", reps[i-1].ID, reps[i].ID)
		}
	}
	if _, ok := reg.Get("csv"); !ok {
		t.Fatalf("csv reporter missing")
	}
	reg.Seal()
	if err := reg.Register(okReporter("new")); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("sealed registry accepted registration: %v", err)
	}
}

func TestRegistryConcurrentReaders(t *testing.T) {
	reg, err := NewDefaultRegistry()
	if err != nil {
		t.Fatalf("default registry: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = reg.Reports()
				_, _ = reg.Get("json")
			}
		}()
	}
	wg.Wait()
}

func TestBuiltinMetadataComplete(t *testing.T) {
	for _, rep := range BuiltinReporters() {
		if rep.ID == "" || rep.Name == "" || rep.Description == "" || rep.Version == "" {
			t.Fatalf("reporter %q has incomplete metadata", rep.ID)
		}
		if !rep.Format.Valid() {
			t.Fatalf("reporter %q has invalid format", rep.ID)
		}
		if rep.Render == nil {
			t.Fatalf("reporter %q has no render function", rep.ID)
		}
		if rep.Validate == nil {
			t.Fatalf("reporter %q has no validator", rep.ID)
		}
		if !rep.Enabled {
			t.Fatalf("builtin reporter %q is disabled", rep.ID)
		}
	}
}
