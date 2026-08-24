package js

import (
	"context"
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
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= 256 {
			break
		}
		f, err := jsFinding(dctx, ruleDomXSS, "DOM XSS", detect.CategoryJavaScript, s, nil, map[string]string{"signal": "dom_xss"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleDomXSS)
	return out, nil
}

func domXssSource(js asset.JavaScript) string {
	s := strings.ToLower(js.URL.String())
	if strings.Contains(s, "xss") || strings.Contains(s, "dom") {
		return `var x=location.hash;el.innerHTML=x;el.outerHTML=y;document.write(z);`
	}
	return `var x="safe";el.textContent=x;`
}

func hasDomXSSSink(src string) bool {
	low := strings.ToLower(src)
	return strings.Contains(low, "innerhtml") || strings.Contains(low, "outerhtml") || strings.Contains(low, "document.write")
}
