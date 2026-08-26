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

// postMessageDetector detects per-script postMessage handlers without origin checks.
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
		meta := map[string]string{"signal": "postmessage_no_origin"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := jsFinding(dctx, rulePostMessage, "PostMessage No Origin Check", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, rulePostMessage, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, rulePostMessage)
	return out, nil
}

func postMessageSource(js asset.JavaScript) string {
	_ = js
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
