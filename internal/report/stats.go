package report

import (
	"sort"
	"time"
)

// maxErrorSamples bounds the per-category sample records the error summary
// retains (fixed constant): a flooding category reports its totals with a
// bounded, deterministic sample, never an unbounded list.
const maxErrorSamples = 8

// Statistics is the report's computed dataset census: one count per
// normalized model list, plus the run's runtime, cache, and execution
// statistics and duration. It is computed once by NewModel; every renderer
// presents the same numbers.
type Statistics struct {
	// AssetCount is the total number of distinct assets across every kind.
	AssetCount int `json:"asset_count"`

	DomainCount         int `json:"domain_count"`
	HostCount           int `json:"host_count"`
	IPCount             int `json:"ip_count"`
	PortCount           int `json:"port_count"`
	ServiceCount        int `json:"service_count"`
	URLCount            int `json:"url_count"`
	EndpointCount       int `json:"endpoint_count"`
	JavaScriptCount     int `json:"javascript_count"`
	ParameterCount      int `json:"parameter_count"`
	TechnologyCount     int `json:"technology_count"`
	SecretCount         int `json:"secret_count"`
	EvidenceCount       int `json:"evidence_count"`
	FindingCount        int `json:"finding_count"`
	TLSCertificateCount int `json:"tls_certificate_count"`
	SourceMapCount      int `json:"source_map_count"`
	RelationshipCount   int `json:"relationship_count"`
	LiveRecordCount     int `json:"live_record_count"`

	// Priority outputs.
	SurfaceCount        int `json:"surface_count"`
	GroupCount          int `json:"group_count"`
	AttackPathCount     int `json:"attack_path_count"`
	RecommendationCount int `json:"recommendation_count"`
	RuleCount           int `json:"rule_count"`

	// Runtime carries the run's worker-pool statistics.
	Runtime RuntimeStats `json:"runtime"`

	// Cache carries the run's cache statistics.
	Cache CacheStats `json:"cache"`

	// Execution carries the run's rule-execution statistics.
	Execution ExecStats `json:"execution"`

	// Duration is EndedAt - StartedAt in milliseconds (zero when either is
	// unset).
	Duration Milliseconds `json:"duration_ms"`
}

// RunSummary is the one-block summary of the whole run: the numbers a
// researcher reads first. It is derived from Statistics; the fields are the
// phase's fixed run-summary vocabulary.
type RunSummary struct {
	Target    string       `json:"target"`
	StartedAt time.Time    `json:"started_at,omitempty"`
	EndedAt   time.Time    `json:"ended_at,omitempty"`
	Duration  Milliseconds `json:"duration_ms,omitempty"`

	Assets          int `json:"assets"`
	Hosts           int `json:"hosts"`
	URLs            int `json:"urls"`
	JavaScript      int `json:"javascript"`
	Secrets         int `json:"secrets"`
	Findings        int `json:"findings"`
	Rules           int `json:"rules"`
	Relationships   int `json:"relationships"`
	Recommendations int `json:"recommendations"`

	CacheHits   int          `json:"cache_hits"`
	CacheMisses int          `json:"cache_misses"`
	WorkerTime  Milliseconds `json:"worker_time_ms,omitempty"`
}

// ErrorCategorySummary is one category's slice of the error summary.
type ErrorCategorySummary struct {
	// Category is the group's category.
	Category ErrorCategory `json:"category"`

	// Total is the summed count of every error in the category.
	Total int `json:"total"`

	// Unique is the number of distinct error records in the category.
	Unique int `json:"unique"`

	// Samples are the retained sample records (bounded at maxErrorSamples),
	// sorted by (stage, message).
	Samples []ErrorRecord `json:"samples"`
}

// ErrorSummary groups the run's error records by category with totals and
// bounded samples. Categories are sorted by name; an error-free run carries
// Total 0 and no categories.
type ErrorSummary struct {
	// Total is the summed count of every error record.
	Total int `json:"total"`

	// Unique is the number of distinct error records.
	Unique int `json:"unique"`

	// Categories is the per-category breakdown, sorted by category name.
	Categories []ErrorCategorySummary `json:"categories,omitempty"`
}

// buildErrorSummary groups normalized, sorted error records by category.
// Input must already be sorted by (category, stage, message) — identical
// records are adjacent and merge by summing counts.
func buildErrorSummary(records []ErrorRecord) ErrorSummary {
	summary := ErrorSummary{Unique: len(records)}
	byCat := make(map[ErrorCategory]*ErrorCategorySummary, len(KnownErrorCategories()))
	for _, r := range records {
		summary.Total += r.Count
		cat, ok := byCat[r.Category]
		if !ok {
			cat = &ErrorCategorySummary{Category: r.Category}
			byCat[r.Category] = cat
		}
		cat.Total += r.Count
		cat.Unique++
		if len(cat.Samples) < maxErrorSamples {
			cat.Samples = append(cat.Samples, r)
		}
	}
	if len(byCat) > 0 {
		summary.Categories = make([]ErrorCategorySummary, 0, len(byCat))
		for _, cat := range byCat {
			summary.Categories = append(summary.Categories, *cat)
		}
		sort.Slice(summary.Categories, func(i, j int) bool {
			return summary.Categories[i].Category < summary.Categories[j].Category
		})
	}
	return summary
}

// buildStatistics computes the dataset census from the normalized model
// lists. It runs once, inside NewModel.
func buildStatistics(m *Model) Statistics {
	s := Statistics{
		DomainCount:         len(m.Domains),
		HostCount:           len(m.Hosts),
		IPCount:             len(m.IPs),
		PortCount:           len(m.Ports),
		ServiceCount:        len(m.Services),
		URLCount:            len(m.URLs),
		EndpointCount:       len(m.Endpoints),
		JavaScriptCount:     len(m.JavaScript),
		ParameterCount:      len(m.Parameters),
		TechnologyCount:     len(m.Technologies),
		SecretCount:         len(m.Secrets),
		EvidenceCount:       len(m.Evidence),
		FindingCount:        len(m.Findings),
		TLSCertificateCount: len(m.TLSCertificates),
		SourceMapCount:      len(m.SourceMaps),
		RelationshipCount:   len(m.Relationships),
		LiveRecordCount:     len(m.LiveRecords),
		SurfaceCount:        len(m.Surfaces),
		GroupCount:          len(m.Groups),
		AttackPathCount:     len(m.AttackPaths),
		RecommendationCount: len(m.Recommendations),
		RuleCount:           m.Execution.Rules,
		Runtime:             m.Runtime,
		Cache:               m.Cache,
		Execution:           m.Execution,
	}
	s.AssetCount = s.DomainCount + s.HostCount + s.IPCount + s.PortCount +
		s.ServiceCount + s.URLCount + s.EndpointCount + s.JavaScriptCount +
		s.ParameterCount + s.TechnologyCount + s.SecretCount +
		s.EvidenceCount + s.FindingCount + s.TLSCertificateCount +
		s.SourceMapCount
	if !m.StartedAt.IsZero() && !m.EndedAt.IsZero() && m.EndedAt.After(m.StartedAt) {
		s.Duration = Ms(m.EndedAt.Sub(m.StartedAt))
	}
	return s
}

// buildRunSummary projects the statistics into the fixed run-summary
// vocabulary.
func buildRunSummary(m *Model) RunSummary {
	return RunSummary{
		Target:          m.Target,
		StartedAt:       m.StartedAt,
		EndedAt:         m.EndedAt,
		Duration:        m.Stats.Duration,
		Assets:          m.Stats.AssetCount,
		Hosts:           m.Stats.HostCount,
		URLs:            m.Stats.URLCount,
		JavaScript:      m.Stats.JavaScriptCount,
		Secrets:         m.Stats.SecretCount,
		Findings:        m.Stats.FindingCount,
		Rules:           m.Stats.RuleCount,
		Relationships:   m.Stats.RelationshipCount,
		Recommendations: m.Stats.RecommendationCount,
		CacheHits:       m.Stats.Cache.Hits,
		CacheMisses:     m.Stats.Cache.Misses,
		WorkerTime:      m.Stats.Runtime.WorkerTime,
	}
}
