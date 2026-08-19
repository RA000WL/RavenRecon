package pipeline

import "github.com/RA000WL/RavenRecon/internal/asset"

// corpusIdentity is satisfied by the canonical asset corpus types
// (asset.Domain, asset.Host, asset.URL) via their deterministic
// Identity method — the dedup key.
type corpusIdentity interface {
	Identity() asset.Identity
}

// mergeCorpus appends add to cur, dropping entries whose identity
// already appeared (first-seen wins, stable order). The returned slice
// is fresh whenever add is non-empty and never aliases add or cur; when
// add is empty it returns cur unchanged (the runner owns cur and no
// stage ever aliases it).
func mergeCorpus[T corpusIdentity](cur []T, add []T, seen map[asset.Identity]struct{}) []T {
	if len(add) == 0 {
		return cur
	}
	out := make([]T, 0, len(cur)+len(add))
	out = append(out, cur...)
	for _, a := range add {
		id := a.Identity()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, a)
	}
	return out
}

// capCorpus truncates the corpus to at most max hosts+URLs entries.
// Domains are scope, not corpus entries, and are excluded from the
// count. Truncation is deterministic: hosts are kept first (in order),
// then URLs, and the tail is dropped. It reports whether anything was
// cut.
//
// Permanence: entries cut by a cap remain first-seen — their identities
// stay in the run-wide dedup map — and cannot re-enter the corpus, even
// if a later stage's cap is larger. The final corpus is bounded by the
// smallest-effective cap; the corpus_capped flag and Truncated mark the
// run honestly (AGENTS §0.6).
func capCorpus(max int, hosts []asset.Host, urls []asset.URL) ([]asset.Host, []asset.URL, bool) {
	total := len(hosts) + len(urls)
	if total <= max {
		return hosts, urls, false
	}
	keep := max
	if keep < 0 {
		keep = 0
	}
	cut := false
	if len(hosts) > keep {
		hosts = hosts[:keep]
		keep = 0
		cut = true
	} else {
		keep -= len(hosts)
	}
	if keep < len(urls) {
		urls = urls[:keep]
		cut = true
	}
	return hosts, urls, cut
}
