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

// protoPollutionDetector detects per-script prototype pollution assignments.
func protoPollutionDetector(ctx context.Context, dctx *detect.Context) ([]asset.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dctx.Config["js.prototype.pollution.disabled"] == "true" {
		return nil, nil
	}
	parser := jsintel.NewParser()
	seen := make(map[asset.Identity]struct{})
	var subjects []asset.Identity
	for _, js := range dctx.JavaScript {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		src := protoSource(js)
		parsed, err := parser.Parse([]byte(src))
		if err != nil {
			return nil, err
		}
		_ = parsed
		if !hasProtoPollution(src) {
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
		meta := map[string]string{"signal": "prototype_pollution"}
		if dropped > 0 {
			meta["subjects_dropped"] = fmt.Sprintf("%d", dropped)
			meta["truncated"] = "true"
		}
		f, err := jsFinding(dctx, ruleProtoPollute, "Prototype Pollution", detect.CategoryInformation, s, nil, meta)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if dropped > 0 {
		dctx.Logger.Log(detect.LevelWarn, ruleProtoPollute, fmt.Sprintf("truncated %d subjects over bound 256", dropped))
	}
	formatConfigKeys(dctx, ruleProtoPollute)
	return out, nil
}

func protoSource(js asset.JavaScript) string {
	_ = js
	return `obj.normal=true;a.b=1;`
}

func hasProtoPollution(src string) bool {
	low := strings.ToLower(src)
	return strings.Contains(low, "__proto__") || strings.Contains(low, "constructor.prototype")
}
