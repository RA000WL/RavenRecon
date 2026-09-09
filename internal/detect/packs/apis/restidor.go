package apis

import (
	"context"
	"fmt"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
)

func restIDORIndicatorDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config[ruleRestIDORIndicator+".disabled"] == "true" {
		return nil, nil
	}
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, ep := range dctx.Endpoints {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := ep.URL.Path
		if hasIDORSegment(path) {
			id := ep.Identity()
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				subjects = append(subjects, id)
			}
		}
	}
	subjects, dropped := capSubjects(subjects, nil)
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "rest_idor_indicator"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := apisFinding(dctx, ruleRestIDORIndicator, "REST IDOR Indicator", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleRestIDORIndicator, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleRestIDORIndicator)
	return out, nil
}

func hasIDORSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if isNumericSegment(seg) || isUUIDSegment(seg) {
			return true
		}
	}
	return false
}

// Exported Rule 2 shared symbols (review fix): thin wrappers over the
// unexported predicates above — zero behavior change to this pack. The
// authz path-object rule derives its per-endpoint token set from the SAME
// symbols (single implementation, drift class eliminated) instead of a
// forked copy. HasIDORSegment is the boolean gate; IDORSegments returns
// the qualifying tokens lowercased for deterministic cross-endpoint
// comparison (UUID hex is case-insensitive; numerics are unaffected).
func HasIDORSegment(path string) bool { return hasIDORSegment(path) }

// IsNumericSegment reports whether s is a qualifying numeric object id:
// all digits, excluding year-shaped 4-digit 1900-2100 and short
// pagination (1-2 digits).
func IsNumericSegment(s string) bool { return isNumericSegment(s) }

// IsUUIDSegment reports whether s is a hyphenated 8-4-4-4-12 hex UUID.
func IsUUIDSegment(s string) bool { return isUUIDSegment(s) }

// IDORSegments returns the qualifying IDOR tokens in path, lowercased.
func IDORSegments(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if isNumericSegment(seg) || isUUIDSegment(seg) {
			out = append(out, strings.ToLower(seg))
		}
	}
	return out
}

func isNumericSegment(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	// R2-M4: exclude year-shaped (1900-2100) and short pagination (1-2 digits).
	if len(s) == 4 {
		if s >= "1900" && s <= "2100" {
			return false
		}
	}
	if len(s) <= 2 {
		return false
	}
	return true
}

func isUUIDSegment(s string) bool {
	if len(s) != 36 {
		return false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
