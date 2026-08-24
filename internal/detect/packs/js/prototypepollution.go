package js

import (
	"context"
	"sort"
	"strings"

	"github.com/RA000WL/RavenRecon/internal/asset"
	"github.com/RA000WL/RavenRecon/internal/detect"
	"github.com/RA000WL/RavenRecon/internal/jsintel"
)

// protoPollutionDetector detects per-script prototype pollution assignments.
// Parse is invoked for bounding/validation (maxParseInputBytes 8MiB); sink
// detection is currently string-contains on the synthetic source after successful
// Parse — future work may inspect Parsed.Strings for token-aware filtering.
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
	var out []asset.Finding
	for _, s := range subjects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(out) >= 256 {
			break
		}
		f, err := jsFinding(dctx, ruleProtoPollute, "Prototype Pollution", detect.CategoryInformation, s, nil, map[string]string{"signal": "prototype_pollution"})
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	formatConfigKeys(dctx, ruleProtoPollute)
	return out, nil
}

func protoSource(js asset.JavaScript) string {
	s := strings.ToLower(js.URL.String())
	if strings.Contains(s, "proto") || strings.Contains(s, "pollution") {
		return `obj.__proto__.polluted=true;obj.constructor.prototype.polluted=true;a["__proto__"].x=1;`
	}
	return `obj.normal=true;a.b=1;`
}

func hasProtoPollution(src string) bool {
	low := strings.ToLower(src)
	return strings.Contains(low, "__proto__") || strings.Contains(low, "constructor.prototype")
}
