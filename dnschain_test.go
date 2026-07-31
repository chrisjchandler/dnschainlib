package dnschainlib

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mockResolver struct {
	ips    map[string][]string
	ns     map[string][]string
	ptr    map[string][]string
	cname  map[string][]CNAMEHop
	ipErr  map[string]error
	nsErr  map[string]error
	ptrErr map[string]error
}

func (m *mockResolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	if err := m.ipErr[host]; err != nil {
		return nil, err
	}
	return m.ips[host], nil
}
func (m *mockResolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	if err := m.nsErr[host]; err != nil {
		return nil, err
	}
	return m.ns[host], nil
}
func (m *mockResolver) LookupPTR(ctx context.Context, addr string) ([]string, error) {
	if err := m.ptrErr[addr]; err != nil {
		return nil, err
	}
	return m.ptr[addr], nil
}
func (m *mockResolver) LookupCNAMEChain(ctx context.Context, host string, maxDepth int) ([]CNAMEHop, error) {
	return m.cname[host], nil
}

type stubGeo struct{ fail bool }

func (s stubGeo) LookupIP(ctx context.Context, ip string) (*GeoInfo, error) {
	if s.fail {
		return nil, errors.New("geo failed")
	}
	return &GeoInfo{Country: "Testland", Source: "stub"}, nil
}

type stubASN struct{ fail bool }

func (s stubASN) LookupIP(ctx context.Context, ip string) (*ASNInfo, error) {
	if s.fail {
		return nil, errors.New("asn failed")
	}
	return &ASNInfo{Prefix: "203.0.113.0/24", ASNs: []string{"AS64500"}, Source: "stub"}, nil
}

type stubWhois struct{}

func (s stubWhois) LookupDomain(ctx context.Context, domain string) (*WhoisRecord, error) {
	return &WhoisRecord{Query: domain, Response: "Domain Name: EXAMPLE.COM", Source: "stub"}, nil
}

type badWhois struct{}

func (s badWhois) LookupDomain(ctx context.Context, domain string) (*WhoisRecord, error) {
	return nil, errors.New("timeout")
}

func TestLookupDomain(t *testing.T) {
	res, err := Lookup(context.Background(), "www.example.com", &Options{Resolver: &mockResolver{
		ips:   map[string][]string{"target.example.net": {"203.0.113.10", "203.0.113.11"}},
		ns:    map[string][]string{"example.com": {"ns2.example.com", "ns1.example.com"}},
		cname: map[string][]CNAMEHop{"www.example.com": {{From: "www.example.com", To: "target.example.net"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Zone != "example.com" || res.CanonicalName != "target.example.net" {
		t.Fatalf("unexpected zone/canonical: %+v", res)
	}
	if got := strings.Join(res.ChainedIPs, ","); got != "203.0.113.10,203.0.113.11" {
		t.Fatalf("unexpected ips: %s", got)
	}
	if got := strings.Join(res.Nameservers, ","); got != "ns1.example.com,ns2.example.com" {
		t.Fatalf("unexpected ns: %s", got)
	}
}

func TestLookupIPIPsOnly(t *testing.T) {
	res, err := Lookup(context.Background(), "203.0.113.5", &Options{IPsOnly: true, Resolver: &mockResolver{ptr: map[string][]string{"203.0.113.5": {"ptr.example.com."}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChainedIPs) != 1 || res.ChainedIPs[0] != "203.0.113.5" {
		t.Fatalf("unexpected ips: %+v", res.ChainedIPs)
	}
	if len(res.Nameservers) != 0 || len(res.CNAMEChain) != 0 {
		t.Fatalf("IPsOnly should suppress detail: %+v", res)
	}
}

func TestLookupEnhanced(t *testing.T) {
	res, err := LookupEnhanced(context.Background(), "www.example.com", &Options{Resolver: &mockResolver{
		ips: map[string][]string{
			"target.example.net": {"203.0.113.10"},
			"ns1.example.com":    {"198.51.100.53"},
			"alias.example.net":  {"203.0.113.20"},
		},
		ns: map[string][]string{"example.com": {"ns1.example.com"}},
		cname: map[string][]CNAMEHop{"www.example.com": {
			{From: "www.example.com", To: "alias.example.net"},
			{From: "alias.example.net", To: "target.example.net"},
		}},
	}, GeoIP: stubGeo{}, ASN: stubASN{}, Whois: stubWhois{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.ZoneWhois == nil || !strings.Contains(res.ZoneWhois.Response, "EXAMPLE.COM") {
		t.Fatalf("missing whois: %+v", res.ZoneWhois)
	}
	if len(res.IPDetails) != 1 || res.IPDetails[0].Geo == nil || res.IPDetails[0].ASN == nil {
		t.Fatalf("missing ip enrichment: %+v", res.IPDetails)
	}
	if len(res.NameserverDetails) != 1 || len(res.CNAMEDetails) != 2 {
		t.Fatalf("missing enhanced details: %+v", res)
	}
}

func TestGeoProviderUnexpectedResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"success":false,"message":"oops"}`))
	}))
	defer ts.Close()
	provider := &ipWhoisProvider{client: ts.Client(), baseURL: ts.URL}
	if _, err := provider.LookupIP(context.Background(), "203.0.113.10"); err == nil || !strings.Contains(err.Error(), "oops") {
		t.Fatalf("expected upstream parse failure, got %v", err)
	}
}

func TestGracefulFailures(t *testing.T) {
	res, err := LookupEnhanced(context.Background(), "www.example.com", &Options{Resolver: &mockResolver{
		ips:   map[string][]string{"www.example.com": {"203.0.113.10"}},
		nsErr: map[string]error{"example.com": errors.New("timeout")},
	}, GeoIP: stubGeo{fail: true}, ASN: stubASN{fail: true}, Whois: badWhois{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) == 0 {
		t.Fatalf("expected recorded errors")
	}
}
