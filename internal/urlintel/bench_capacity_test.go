package urlintel

// Regression coverage for TODO.md NEW-57's capacity arithmetic: a cold pass
// needs want entry files + the bounded shard tree + headroom as free
// INODES — the million-line benchmark's shortfall was inode exhaustion on a
// 2^20-inode tmpfs, invisible to byte-based thinking.

import "testing"

func TestVolumeFitsInodes(t *testing.T) {
	const want = uint64(1_000_000)
	need := want + shardDirBound + inodeHeadroom

	if volumeFitsInodes(need-1, want) {
		t.Fatalf("volume with %d free inodes accepted for %d entries (need %d)", need-1, want, need)
	}
	if !volumeFitsInodes(need, want) {
		t.Fatalf("volume with exactly %d free inodes rejected for %d entries", need, want)
	}
	// A 2^20-inode tmpfs can never host the million-line workload, even
	// completely empty: this is the NEW-57 environment, and the benchmark
	// must move to another volume instead of failing mid-pass.
	if volumeFitsInodes(1<<20, want) {
		t.Fatal("a fully empty 1Mi-inode volume accepted for the million-line workload")
	}
}
