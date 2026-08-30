package asset

import "testing"

// TestRelationshipIDCollision is the R2-M6 regression: Relationship.ID()
// concatenated unencoded components with "\x00" separator, so two distinct
// edges shared one ID and were silently dropped in dedupeFindingRelationships.
// The fix encodes components ( '%'->"%25", "\x00"->"%00", controls->"%XX")
// and pins Kind.Valid() vocabulary. This test constructs a collision pair
// that WITHOUT encoding shared one ID and asserts they are distinct after fix.
// Reverting encodeIdentity to `return s` makes the two IDs equal and fails.
func TestRelationshipIDCollision(t *testing.T) {
	// Pair that collides raw but not encoded.
	//   r1: From="host:a", To="host_to_ip\x00host:c" (exotic Identity Kind
	//       "host_to_ip\x00host" + Value "c" => String "host_to_ip\x00host:c"),
	//       Kind="host_to_ip"
	//   r2: From="host:a\x00host_to_ip", To="host:c", Kind="host_to_ip"
	//
	// Raw (no encode):
	//   r1 raw = "host:a" + "\x00" + "host_to_ip" + "\x00" + "host_to_ip\x00host:c"
	//          = "host:a\x00host_to_ip\x00host_to_ip\x00host:c"
	//   r2 raw = "host:a\x00host_to_ip" + "\x00" + "host_to_ip" + "\x00" + "host:c"
	//          = "host:a\x00host_to_ip\x00host_to_ip\x00host:c"
	//   => equal
	//
	// Encoded (fixed):
	//   r1 enc = "host:a" + "\x00" + "host_to_ip" + "\x00" + "host_to_ip%00host:c"
	//   r2 enc = "host:a%00host_to_ip" + "\x00" + "host_to_ip" + "\x00" + "host:c"
	//   => distinct (%00 at different positions)
	from1 := Identity{Kind: KindHost, Value: "a"}
	// exotic: Kind contains "\x00" so String is "host_to_ip\x00host:c" == K + "\x00" + "host:c"
	to1 := Identity{Kind: Kind("host_to_ip\x00host"), Value: "c"}
	from2 := Identity{Kind: KindHost, Value: "a\x00host_to_ip"}
	to2 := Identity{Kind: KindHost, Value: "c"}
	kind := RelationshipHostToIP

	r1, err := NewRelationship(from1, kind, to1)
	if err != nil {
		t.Fatalf("NewRelationship r1: %v", err)
	}
	r2, err := NewRelationship(from2, kind, to2)
	if err != nil {
		t.Fatalf("NewRelationship r2: %v", err)
	}
	if r1.From == r2.From && r1.To == r2.To && r1.Kind == r2.Kind {
		t.Fatal("test setup: r1 and r2 must be distinct triples")
	}
	id1 := r1.ID()
	id2 := r2.ID()
	if id1 == id2 {
		t.Fatalf("R2-M6: distinct edges must have distinct IDs after fix; got equal IDs %q (from1=%q to1=%q vs from2=%q to2=%q kind=%q)", id1, from1.String(), to1.String(), from2.String(), to2.String(), kind)
	}
	// Red-proof: without encoding the two IDs would be equal.
	// Compute raw IDs by concatenating unencoded components.
	raw1 := from1.String() + "\x00" + string(kind) + "\x00" + to1.String()
	raw2 := from2.String() + "\x00" + string(kind) + "\x00" + to2.String()
	if raw1 != raw2 {
		t.Fatalf("test invariant: raw (unencoded) IDs must be equal to demonstrate collision, got %q vs %q", raw1, raw2)
	}
	// Also verify that the encoded IDs are not just different by accident but
	// carry the expected escapes at the expected positions.
	if len(id1) == len(raw1) {
		t.Errorf("encoded ID should be longer than raw due to %%00 escape, raw len %d enc len %d", len(raw1), len(id1))
	}
	// Ensure the distinctness is due to encodeIdentity, not Kind difference.
	if r1.Kind != r2.Kind {
		t.Error("kinds must be same for this collision pair")
	}
}

// TestRelationshipIDCollisionPrefixPair is a second illustrative pair using
// the classic separator-shift pattern described in the acceptance
// (From="a", To="b\x00c" vs From="a\x00b", To="c") adapted to the real
// Identity model with an exotic Kind that lets the raw strings coincide.
// It also fails if encodeIdentity is reverted.
func TestRelationshipIDCollisionPrefixPair(t *testing.T) {
	// Use asset Kind "a" for simplicity so Identity strings are "a:x".
	// Let K="host_to_ip" (valid). Construct raw equality via the same
	// exotic technique but with values "a" / "b\x00c" etc., lifted to
	// Identity strings that contain the separator.
	//
	// For host-only identities the raw equality is impossible without
	// exotic Kind (see analysis), so we reuse the proven exotic construction
	// with a different payload to show the same class.
	from1 := Identity{Kind: Kind("a"), Value: "x"}
	to1 := Identity{Kind: Kind("host_to_ip\x00a"), Value: "y"} // String "host_to_ip\x00a:y"
	from2 := Identity{Kind: Kind("a"), Value: "x\x00host_to_ip"}
	to2 := Identity{Kind: Kind("a"), Value: "y"}
	kind := RelationshipHostToIP
	r1, err := NewRelationship(from1, kind, to1)
	if err != nil {
		t.Fatalf("NewRelationship r1: %v", err)
	}
	r2, err := NewRelationship(from2, kind, to2)
	if err != nil {
		t.Fatalf("NewRelationship r2: %v", err)
	}
	if r1.ID() == r2.ID() {
		t.Fatalf("R2-M6 prefix-pair: distinct edges must have distinct IDs, got %q", r1.ID())
	}
	raw1 := from1.String() + "\x00" + string(kind) + "\x00" + to1.String()
	raw2 := from2.String() + "\x00" + string(kind) + "\x00" + to2.String()
	if raw1 != raw2 {
		t.Fatalf("prefix-pair invariant: raw IDs must be equal, got %q vs %q", raw1, raw2)
	}
}
