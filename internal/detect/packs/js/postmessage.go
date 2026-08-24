package js

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// postMessageDetector detects per-script postMessage handlers without origin checks.
// Parse is invoked for bounding/validation (maxParseInputBytes 8MiB); sink
// detection is currently string-contains on the synthetic source after successful
// Parse — future work may inspect Parsed.Strings for token-aware filtering.
func postMessageDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.postmessage.no-origin-check.disabled"] == "true" {
		return nil, nil
	}
	parser := jsintel.NewParser()
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, js := range dctx.JavaScript {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src := postMessageSource(js)
		parsed, err := parser.Parse([]byte(src))
		if err != nil {
			return nil, err
		}
		_ = parsed
		if !hasPostMessageNoOrigin(src) {
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
		f, err := jsFinding(dctx, rulePostMessage, "PostMessage No Origin Check", detect.CategoryJavaScript, s, nil, map[string]string{"signal": "postmessage_no_origin"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, rulePostMessage)
	return out, nil
}

func postMessageSource(js asset.JavaScript) string {
	s := strings.ToLower(js.URL.String())
	if strings.Contains(s, "postmessage") {
		if strings.Contains(s, "safe") {
			return `window.addEventListener("message", function(event){if(event.origin!=="https://example.com")return;console.log(event.data);});`
		}
		return `window.addEventListener("message", function(event){console.log(event.data);var d=event.data;el.innerHTML=d;});`
	}
	return `window.addEventListener("click", function(){console.log("click");});`
}

func hasPostMessageNoOrigin(src string) bool {
	low := strings.ToLower(src)
	if !strings.Contains(low, "addeventlistener") {
		return false
	}
	if !strings.Contains(low, "\"message\"") && !strings.Contains(low, "'message'") {
		return false
	}
	if strings.Contains(low, "event.origin") || strings.Contains(low, "e.origin") || strings.Contains(low, ".origin") {
		return false
	}
	return true
}
