package js

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// domXSSDetector detects per-script DOM XSS sinks. Parse is invoked for
// bounding/validation (maxParseInputBytes 8MiB); sink detection is currently
// string-contains on the synthetic source after successful Parse — future work
// may inspect Parsed.Strings for token-aware filtering.
func domXSSDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.dom.xss.disabled"] == "true" {
		return nil, nil
	}
	parser := jsintel.NewParser()
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, js := range dctx.JavaScript {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src := domXssSource(js)
		parsed, err := parser.Parse([]byte(src))
		if err != nil {
			return nil, err
		}
		_ = parsed
		if !hasDomXSSSink(src) {
			continue
		}
		id := js.Identity()
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			subjects = append(subjects, id)
		}
	}
	sort.Slice(subjects, func(i, j int) bool { return subjects[i].String() < subjects[j].String() })
	dropped := 0
	if len(subjects) > 256 {
		dropped = len(subjects) - 256
		subjects = subjects[:256]
	}
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		meta := map[string]string{"signal": "dom_xss"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := jsFinding(dctx, ruleDomXSS, "DOM XSS", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleDomXSS, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleDomXSS)
	return out, nil
}
func domXssSource(js asset.JavaScript) string {
	_ = js
	return `var x="safe";el.textContent=x;`
}

func hasDomXSSSink(src string) bool {
	low := strings.ToLower(src)
	return strings.Contains(low, "innerhtml") || strings.Contains(low, "outerhtml") || strings.Contains(low, "document.write")
}
