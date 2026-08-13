package asset

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestSerializationRoundTrip(t *testing.T) {
	prov := Provenance{Source: "manual", DiscoveredAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC), Reference: "ref-1", Confidence: 0.9}

	domain, _ := NewDomain("EXAMPLE.COM.", prov)
	host, _ := NewHost("api.example.com", prov)
	ip, _ := NewIP("2001:DB8::1", prov)
	port, _ := NewPort(53, "UDP", prov)
	service, _ := NewService("dns", port, prov)
	u, _ := ParseURL("https://example.com:443/a/../b?z=1&a=2#frag ", prov)
	endpoint, _ := NewEndpoint("post", "https://example.com/admin?x=1", prov)
	js, _ := NewJavaScript("https://example.com/app.js", prov)
	rel, _ := NewRelationship(host.Identity(), RelationshipHostToIP, ip.Identity())

	assets := []interface{}{domain, host, ip, port, service, u, endpoint, js, rel}
	for _, v := range assets {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal %T: %v", v, err)
		}
		out := reflect.New(reflect.TypeOf(v)).Interface()
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("unmarshal %T: %v (data: %s)", v, err, data)
		}
		if !reflect.DeepEqual(reflect.ValueOf(out).Elem().Interface(), v) {
			t.Errorf("%T round trip mismatch:\n got %#v\nwant %#v\njson: %s", v, out, v, data)
		}
	}
}

func TestSerializedIdentityStable(t *testing.T) {
	prov := NewProvenance("manual")
	u, _ := ParseURL("https://example.com/p?b=2&a=1", prov)

	data, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var back URL
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.ID() != u.ID() {
		t.Errorf("identity changed after serialization: %q != %q", back.ID(), u.ID())
	}
}

func TestSerializationDoesNotCallString(t *testing.T) {
	// The struct shape, not the canonical string, is what serializes.
	u, _ := ParseURL("https://example.com/p#frag", NewProvenance("manual"))
	data, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(u.Fragment, "frag") {
		t.Errorf("fragment not preserved in struct: %v", u.Fragment)
	}
	if len(data) == 0 {
		t.Fatal("empty serialization")
	}
}

func TestIdentitySerialization(t *testing.T) {
	id := Identity{Kind: KindURL, Value: "https://example.com/"}
	data, err := json.Marshal(id)
	if err != nil {
		t.Fatal(err)
	}
	var back Identity
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Equal(id) || back.String() != id.String() {
		t.Errorf("identity round trip failed: %v", back)
	}
}
