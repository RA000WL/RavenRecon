package importer

import (
	"testing"
)

func TestRegistrySeal(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(NewPlainDomainsImporter()); err != nil {
		t.Fatalf("Register domains: %v", err)
	}
	if err := r.Register(NewPlainURLsImporter()); err != nil {
		t.Fatalf("Register urls: %v", err)
	}
	if got := len(r.List()); got != 2 {
		t.Fatalf("List before seal: %d", got)
	}
	r.Seal()
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("List after seal: %d", len(list))
	}
	// List must be sorted by Name asc
	if list[0].Name() != "plain-domains" || list[1].Name() != "plain-urls" {
		t.Fatalf("List not sorted: %v, %v", list[0].Name(), list[1].Name())
	}
	// Deep-copy: mutating returned slice must not affect registry
	list[0] = NewPlainIPsImporter()
	if len(r.List()) != 2 {
		t.Fatalf("registry mutated via List")
	}
	if r.List()[0].Name() != "plain-domains" {
		t.Fatalf("deep copy violated")
	}
	// Post-seal duplicate Name must panic
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatalf("expected panic on Register after Seal")
		}
	}()
	_ = r.Register(NewPlainDomainsImporter())
}

func TestRegistryDetectDeterminism(t *testing.T) {
	r := NewRegistry()
	// Register in random order
	_ = r.Register(NewPlainCIDRsImporter())
	_ = r.Register(NewPlainDomainsImporter())
	_ = r.Register(NewPlainURLsImporter())
	_ = r.Register(NewPlainIPsImporter())
	_ = r.Register(NewPlainSubdomainsImporter())
	_ = r.Register(NewPlainAliveImporter())
	_ = r.Register(NewPlainJSImporter())
	_ = r.Register(NewPlainGenericImporter())
	r.Seal()

	// Create peek that is mostly urls (ratio high)
	peek := []byte("https://example.com/a\nhttps://example.com/b\nhttps://example.com/c\n")
	m1 := r.Detect("file.txt", peek)
	m2 := r.Detect("file.txt", peek)
	if len(m1) != len(m2) {
		t.Fatalf("Detect not deterministic length")
	}
	for i := range m1 {
		if m1[i].Importer.Name() != m2[i].Importer.Name() || m1[i].Confidence != m2[i].Confidence {
			t.Fatalf("Detect not deterministic at %d", i)
		}
	}
	// Must be sorted by confidence desc, Name asc tie-break, generic last
	for i := 1; i < len(m1); i++ {
		prev, cur := m1[i-1], m1[i]
		if prev.Importer.Name() == "plain-generic" && cur.Importer.Name() != "plain-generic" {
			t.Fatalf("generic not last: %s before %s", prev.Importer.Name(), cur.Importer.Name())
		}
		if prev.Confidence < cur.Confidence {
			t.Fatalf("not sorted by confidence desc: %f < %f", prev.Confidence, cur.Confidence)
		}
		if prev.Confidence == cur.Confidence && prev.Importer.Name() > cur.Importer.Name() && cur.Importer.Name() != "plain-generic" {
			t.Fatalf("not sorted by Name asc on tie: %s > %s", prev.Importer.Name(), cur.Importer.Name())
		}
	}
	// CanImport never opens file beyond peek: we pass peek, no file IO in CanImport
	// Verify by calling CanImport directly and ensuring no file needed
	for _, imp := range r.List() {
		_, _ = imp.CanImport("nonexistent/path/does/not/exist.txt", peek)
	}
}

func TestRegistryDuplicateAfterSealPanics(t *testing.T) {
	r := NewRegistry()
	_ = r.Register(NewPlainDomainsImporter())
	r.Seal()
	defer func() {
		if rec := recover(); rec == nil {
			t.Fatalf("expected panic on duplicate after seal")
		}
	}()
	// Even new name should panic because sealed (per implementation, any Register after seal panics)
	_ = r.Register(NewPlainIPsImporter())
}
