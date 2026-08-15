package fingerprints

import "github.com/RA000WL/RavenRecon/internal/asset"

// apiTable returns the API protocol and API gateway fingerprints.
//
// Category note: GraphQL and its ecosystems live under CategoryGraphQL;
// every other API protocol marker (gRPC-Web, JSON-RPC, SOAP, OpenAPI,
// Swagger UI, REST-generic) is bucketed under CategoryAPIGateway because the
// 21-category enum has no generic "api" category — documented here so the
// bucket is a deliberate choice, not an accident.
func apiTable() []Fingerprint {
	return []Fingerprint{
		{
			// GraphQL's /graphql and /graphiql endpoints and the
			// application/graphql+json response content type.
			Name:     "graphql",
			Category: asset.CategoryGraphQL,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/graphql", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/graphiql", Weight: 0.6},
				{Kind: IndicatorHeader, Match: "content-type: application/graphql+json", Weight: 0.9},
			},
		},
		{
			// Apollo Client hydrates its cache into the __APOLLO_STATE__
			// global; apollo-* bundle names also appear in script tags
			// (lower weight).
			Name:     "apollo",
			Category: asset.CategoryGraphQL,
			Indicators: []Indicator{
				{Kind: IndicatorHTMLSubstring, Match: "__APOLLO_STATE__", Weight: 0.7},
				{Kind: IndicatorScriptName, Match: "apollo", Weight: 0.4},
			},
		},
		{
			// Relay has no documented passive HTML marker; react-relay
			// bundle names are the only real observable. UNCERTAIN: low
			// weight, kept for spec coverage.
			Name:     "relay",
			Category: asset.CategoryGraphQL,
			Indicators: []Indicator{
				{Kind: IndicatorScriptName, Match: "react-relay", Weight: 0.3},
			},
		},
		{
			// gRPC-Web responses use application/grpc-web (+proto) content
			// types.
			Name:     "grpc-web",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "content-type: application/grpc-web", Weight: 0.9},
			},
		},
		{
			// The JSON-RPC content type; many servers use plain
			// application/json instead (cross-ref rest-generic).
			Name:     "json-rpc",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "content-type: application/json-rpc", Weight: 0.7},
			},
		},
		{
			// SOAP's application/soap+xml content type and .wsdl service
			// descriptions.
			Name:     "soap",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "content-type: application/soap+xml", Weight: 0.9},
				{Kind: IndicatorEndpointPath, Match: ".wsdl", Weight: 0.6},
			},
		},
		{
			// OpenAPI documents served at their conventional URLs;
			// /openapi.json is also FastAPI's default (cross-ref the
			// fastapi entry).
			Name:     "openapi",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorEndpointPath, Match: "/openapi.json", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/openapi.yaml", Weight: 0.7},
				{Kind: IndicatorEndpointPath, Match: "/swagger.json", Weight: 0.8},
			},
		},
		{
			// Swagger UI's /swagger-ui asset prefix and the swagger-ui
			// identifiers in its HTML.
			Name:     "swagger ui",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorScriptPath, Match: "/swagger-ui", Weight: 0.9},
				{Kind: IndicatorHTMLSubstring, Match: "swagger-ui", Weight: 0.8},
			},
		},
		{
			// REST-generic is the fallback for JSON APIs: application/json
			// fires on nearly every JSON API and /api/ is an explicit path
			// convention. EVIDENCE-ONLY at low weight — the engine pass
			// combines these indicators and must not treat either alone as
			// a strong signal.
			Name:     "rest-generic",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "content-type: application/json", Weight: 0.2},
				{Kind: IndicatorEndpointPath, Match: "/api/", Weight: 0.3},
			},
		},
		{
			// Kong's "Server: kong/2.8.1" banner carries the version.
			Name:     "kong",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: kong", Weight: 0.8, Version: &VersionSpec{Pattern: `(?i)kong/([0-9.]+)`, Group: 1}},
			},
		},
		{
			// Tyk's "Server: tyk" banner (observed in Tyk's own response
			// dumps) and the /tyk/apis gateway management API path.
			Name:     "tyk",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "server: tyk", Weight: 0.8},
				{Kind: IndicatorEndpointPath, Match: "/tyk/apis", Weight: 0.5},
			},
		},
		{
			// Amazon API Gateway's x-amzn-requestid and x-amz-apigw-id
			// response headers (cross-ref the aws cloud entry).
			Name:     "amazon api gateway",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "x-amzn-requestid", Weight: 0.8},
				{Kind: IndicatorHeader, Match: "x-amz-apigw-id", Weight: 0.9},
			},
		},
		{
			// Azure API Management's Ocp-Apim-* header family (subscription
			// key, trace).
			Name:     "azure api management",
			Category: asset.CategoryAPIGateway,
			Indicators: []Indicator{
				{Kind: IndicatorHeader, Match: "ocp-apim", Weight: 0.8},
			},
		},
	}
}
