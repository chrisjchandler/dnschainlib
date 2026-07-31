// Package dnschainlib turns the original asnlookup-Go option 32
// (RIPEstat dns-chain lookups) into a reusable Go library.
package dnschainlib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultTimeout = 45 * time.Second
	ripestatBase   = "https://stat.ripe.net/data"
	ipWhoisBase    = "https://ipwho.is"
	maxCNAMEDepth  = 12
)

type Result struct {
	Input         string     `json:"input"`
	InputType     string     `json:"input_type"`
	LookupMode    string     `json:"lookup_mode"`
	Zone          string     `json:"zone,omitempty"`
	CanonicalName string     `json:"canonical_name,omitempty"`
	PTRNames      []string   `json:"ptr_names,omitempty"`
	CNAMEChain    []CNAMEHop `json:"cname_chain,omitempty"`
	ChainedIPs    []string   `json:"chained_ips"`
	Nameservers   []string   `json:"nameservers,omitempty"`
	Errors        []Issue    `json:"errors,omitempty"`
	Source        string     `json:"source"`
	Notes         []string   `json:"notes,omitempty"`
}

type EnhancedResult struct {
	Result
	IPDetails         []IPDetail         `json:"ip_details,omitempty"`
	NameserverDetails []NameserverDetail `json:"nameserver_details,omitempty"`
	CNAMEDetails      []CNAMEGeoDetail   `json:"cname_details,omitempty"`
	ZoneWhois         *WhoisRecord       `json:"zone_whois,omitempty"`
}

type CNAMEHop struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type GeoInfo struct {
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Source      string  `json:"source,omitempty"`
}

type ASNInfo struct {
	Prefix string   `json:"prefix,omitempty"`
	ASNs   []string `json:"asns,omitempty"`
	Holder string   `json:"holder,omitempty"`
	Source string   `json:"source,omitempty"`
}

type IPDetail struct {
	IP  string   `json:"ip"`
	Geo *GeoInfo `json:"geo,omitempty"`
	ASN *ASNInfo `json:"asn,omitempty"`
}

type NameserverDetail struct {
	Host string     `json:"host"`
	IPs  []IPDetail `json:"ips,omitempty"`
}

type CNAMEGeoDetail struct {
	Host string     `json:"host"`
	IPs  []IPDetail `json:"ips,omitempty"`
}

type WhoisRecord struct {
	Query    string `json:"query"`
	Response string `json:"response"`
	Source   string `json:"source"`
}

type Issue struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type Options struct {
	Timeout  time.Duration
	IPsOnly  bool
	Resolver Resolver
	HTTP     *http.Client
	GeoIP    GeoIPProvider
	ASN      ASNProvider
	Whois    WhoisProvider
}

type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]string, error)
	LookupNS(ctx context.Context, host string) ([]string, error)
	LookupPTR(ctx context.Context, addr string) ([]string, error)
	LookupCNAMEChain(ctx context.Context, host string, maxDepth int) ([]CNAMEHop, error)
}

type GeoIPProvider interface {
	LookupIP(ctx context.Context, ip string) (*GeoInfo, error)
}
type ASNProvider interface {
	LookupIP(ctx context.Context, ip string) (*ASNInfo, error)
}
type WhoisProvider interface {
	LookupDomain(ctx context.Context, domain string) (*WhoisRecord, error)
}

func Lookup(ctx context.Context, input string, opts *Options) (*Result, error) {
	cfg := buildOptions(opts)
	ctx, cancel := cfg.context(ctx)
	defer cancel()
	return lookup(ctx, input, cfg)
}

func LookupEnhanced(ctx context.Context, input string, opts *Options) (*EnhancedResult, error) {
	cfg := buildOptions(opts)
	ctx, cancel := cfg.context(ctx)
	defer cancel()
	base, err := lookup(ctx, input, cfg)
	if err != nil {
		return nil, err
	}
	out := &EnhancedResult{Result: *base}
	for _, ip := range base.ChainedIPs {
		out.IPDetails = append(out.IPDetails, enrichIP(ctx, cfg, ip, &out.Result))
	}
	for _, ns := range base.Nameservers {
		ips, err := cfg.Resolver.LookupIP(ctx, ns)
		if err != nil {
			out.Errors = append(out.Errors, Issue{Stage: "nameserver_lookup", Message: fmt.Sprintf("%s: %v", ns, err)})
			continue
		}
		d := NameserverDetail{Host: ns}
		for _, ip := range uniqueSortedStrings(ips) {
			d.IPs = append(d.IPs, enrichIP(ctx, cfg, ip, &out.Result))
		}
		out.NameserverDetails = append(out.NameserverDetails, d)
	}
	for _, hop := range base.CNAMEChain {
		host := trimDot(hop.To)
		if host == "" {
			continue
		}
		ips, err := cfg.Resolver.LookupIP(ctx, host)
		if err != nil {
			out.Errors = append(out.Errors, Issue{Stage: "cname_lookup", Message: fmt.Sprintf("%s: %v", host, err)})
			continue
		}
		d := CNAMEGeoDetail{Host: host}
		for _, ip := range uniqueSortedStrings(ips) {
			d.IPs = append(d.IPs, enrichIP(ctx, cfg, ip, &out.Result))
		}
		out.CNAMEDetails = append(out.CNAMEDetails, d)
	}
	if base.InputType == "domain" && base.Zone != "" {
		who, err := cfg.Whois.LookupDomain(ctx, base.Zone)
		if err != nil {
			out.Errors = append(out.Errors, Issue{Stage: "whois", Message: err.Error()})
		} else {
			out.ZoneWhois = who
		}
	}
	return out, nil
}

type resolvedOptions struct {
	Timeout  time.Duration
	IPsOnly  bool
	Resolver Resolver
	HTTP     *http.Client
	GeoIP    GeoIPProvider
	ASN      ASNProvider
	Whois    WhoisProvider
}

func buildOptions(opts *Options) resolvedOptions {
	if opts == nil {
		opts = &Options{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := opts.HTTP
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = newNetResolver(timeout)
	}
	geo := opts.GeoIP
	if geo == nil {
		geo = &ipWhoisProvider{client: client, baseURL: ipWhoisBase}
	}
	asn := opts.ASN
	if asn == nil {
		asn = &ripeASNProvider{client: client}
	}
	who := opts.Whois
	if who == nil {
		who = &defaultWhoisProvider{}
	}
	return resolvedOptions{Timeout: timeout, IPsOnly: opts.IPsOnly, Resolver: resolver, HTTP: client, GeoIP: geo, ASN: asn, Whois: who}
}

func (o resolvedOptions) context(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, o.Timeout)
}

func lookup(ctx context.Context, input string, cfg resolvedOptions) (*Result, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, errors.New("input is required")
	}
	mode := "full"
	if cfg.IPsOnly {
		mode = "ips_only"
	}
	res := &Result{Input: input, ChainedIPs: []string{}, Source: "dnschainlib", LookupMode: mode}
	if ip, err := netip.ParseAddr(input); err == nil {
		res.InputType = "ip"
		res.ChainedIPs = []string{ip.String()}
		ptrs, err := cfg.Resolver.LookupPTR(ctx, ip.String())
		if err != nil {
			res.Errors = append(res.Errors, Issue{Stage: "ptr_lookup", Message: err.Error()})
			return res, nil
		}
		res.PTRNames = uniqueSortedTrimmed(ptrs)
		if cfg.IPsOnly {
			return finalize(res, cfg), nil
		}
		zoneSet := map[string]struct{}{}
		for _, host := range res.PTRNames {
			chain, finalHost, ips := resolveDomain(ctx, cfg, host, res)
			res.CNAMEChain = append(res.CNAMEChain, chain...)
			res.ChainedIPs = append(res.ChainedIPs, ips...)
			if finalHost != "" && res.CanonicalName == "" {
				res.CanonicalName = finalHost
			}
			if zone, ok := registrableZone(host); ok {
				zoneSet[zone] = struct{}{}
			}
		}
		for zone := range zoneSet {
			ns, err := cfg.Resolver.LookupNS(ctx, zone)
			if err != nil {
				res.Errors = append(res.Errors, Issue{Stage: "ns_lookup", Message: fmt.Sprintf("%s: %v", zone, err)})
				continue
			}
			res.Nameservers = append(res.Nameservers, ns...)
		}
		return finalize(res, cfg), nil
	}

	res.InputType = "domain"
	if zone, ok := registrableZone(input); ok {
		res.Zone = zone
	}
	chain, finalHost, ips := resolveDomain(ctx, cfg, input, res)
	res.CNAMEChain = chain
	res.CanonicalName = finalHost
	res.ChainedIPs = ips
	if !cfg.IPsOnly && res.Zone != "" {
		ns, err := cfg.Resolver.LookupNS(ctx, res.Zone)
		if err != nil {
			res.Errors = append(res.Errors, Issue{Stage: "ns_lookup", Message: fmt.Sprintf("%s: %v", res.Zone, err)})
		} else {
			res.Nameservers = ns
		}
	}
	return finalize(res, cfg), nil
}

func finalize(res *Result, cfg resolvedOptions) *Result {
	res.ChainedIPs = uniqueSortedStrings(res.ChainedIPs)
	res.Nameservers = uniqueSortedTrimmed(res.Nameservers)
	res.CNAMEChain = uniqueChain(res.CNAMEChain)
	if cfg.IPsOnly {
		res.CNAMEChain = nil
		res.Nameservers = nil
		res.Notes = append(res.Notes, "IPsOnly suppresses nameserver and CNAME detail while preserving deterministic chained IP ordering.")
	}
	return res
}

func resolveDomain(ctx context.Context, cfg resolvedOptions, host string, res *Result) ([]CNAMEHop, string, []string) {
	host = trimDot(host)
	chain, err := cfg.Resolver.LookupCNAMEChain(ctx, host, maxCNAMEDepth)
	if err != nil {
		res.Errors = append(res.Errors, Issue{Stage: "cname_lookup", Message: fmt.Sprintf("%s: %v", host, err)})
	}
	finalHost := host
	if len(chain) > 0 {
		finalHost = trimDot(chain[len(chain)-1].To)
	}
	ips, err := cfg.Resolver.LookupIP(ctx, finalHost)
	if err != nil {
		res.Errors = append(res.Errors, Issue{Stage: "ip_lookup", Message: fmt.Sprintf("%s: %v", finalHost, err)})
	}
	return uniqueChain(chain), finalHost, uniqueSortedStrings(ips)
}

func enrichIP(ctx context.Context, cfg resolvedOptions, ip string, res *Result) IPDetail {
	detail := IPDetail{IP: ip}
	if geo, err := cfg.GeoIP.LookupIP(ctx, ip); err == nil {
		detail.Geo = geo
	} else {
		res.Errors = append(res.Errors, Issue{Stage: "geoip", Message: fmt.Sprintf("%s: %v", ip, err)})
	}
	if asn, err := cfg.ASN.LookupIP(ctx, ip); err == nil {
		detail.ASN = asn
	} else {
		res.Errors = append(res.Errors, Issue{Stage: "asn_lookup", Message: fmt.Sprintf("%s: %v", ip, err)})
	}
	return detail
}

type netResolver struct {
	resolver *net.Resolver
	dnscli   *dns.Client
	server   string
}

func newNetResolver(timeout time.Duration) *netResolver {
	return &netResolver{resolver: net.DefaultResolver, dnscli: &dns.Client{Timeout: timeout}, server: recursiveServer()}
}

func (r *netResolver) LookupIP(ctx context.Context, host string) ([]string, error) {
	ips, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.IP.String())
	}
	return uniqueSortedStrings(out), nil
}

func (r *netResolver) LookupNS(ctx context.Context, host string) ([]string, error) {
	ns, err := r.resolver.LookupNS(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ns))
	for _, item := range ns {
		out = append(out, trimDot(item.Host))
	}
	return uniqueSortedTrimmed(out), nil
}

func (r *netResolver) LookupPTR(ctx context.Context, addr string) ([]string, error) {
	names, err := r.resolver.LookupAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	return uniqueSortedTrimmed(names), nil
}

func (r *netResolver) LookupCNAMEChain(ctx context.Context, host string, maxDepth int) ([]CNAMEHop, error) {
	current := dns.Fqdn(host)
	var chain []CNAMEHop
	seen := map[string]struct{}{}
	for i := 0; i < maxDepth; i++ {
		if _, ok := seen[current]; ok {
			return chain, fmt.Errorf("cname loop detected at %s", trimDot(current))
		}
		seen[current] = struct{}{}
		msg := &dns.Msg{}
		msg.SetQuestion(current, dns.TypeCNAME)
		resp, _, err := r.dnscli.ExchangeContext(ctx, msg, r.server)
		if err != nil {
			return chain, err
		}
		found := false
		for _, ans := range resp.Answer {
			if rr, ok := ans.(*dns.CNAME); ok && strings.EqualFold(rr.Hdr.Name, current) {
				chain = append(chain, CNAMEHop{From: trimDot(rr.Hdr.Name), To: trimDot(rr.Target)})
				current = rr.Target
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return uniqueChain(chain), nil
}

func recursiveServer() string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		return net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return "8.8.8.8:53"
}

type ipWhoisProvider struct {
	client  *http.Client
	baseURL string
}

type ipWhoisResponse struct {
	Success bool    `json:"success"`
	Country string  `json:"country"`
	Code    string  `json:"country_code"`
	Region  string  `json:"region"`
	City    string  `json:"city"`
	Lat     float64 `json:"latitude"`
	Lon     float64 `json:"longitude"`
	Message string  `json:"message"`
}

func (p *ipWhoisProvider) LookupIP(ctx context.Context, ip string) (*GeoInfo, error) {
	u := fmt.Sprintf("%s/%s", strings.TrimRight(p.baseURL, "/"), url.PathEscape(ip))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("geoip http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed ipWhoisResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if !parsed.Success && parsed.Message != "" {
		return nil, errors.New(parsed.Message)
	}
	return &GeoInfo{Country: parsed.Country, CountryCode: parsed.Code, Region: parsed.Region, City: parsed.City, Latitude: parsed.Lat, Longitude: parsed.Lon, Source: "ipwho.is"}, nil
}

type ripeASNProvider struct{ client *http.Client }

type ripeNetworkInfo struct {
	Data struct {
		Prefix string `json:"prefix"`
	} `json:"data"`
}

type ripeRoutingStatus struct {
	Data struct {
		Origins []struct {
			ASN    any    `json:"asn"`
			Holder string `json:"holder"`
		} `json:"origining"`
	} `json:"data"`
}

func (p *ripeASNProvider) LookupIP(ctx context.Context, ip string) (*ASNInfo, error) {
	prefixURL := fmt.Sprintf("%s/network-info/data.json?resource=%s", ripestatBase, url.QueryEscape(ip))
	prefixBody, err := doJSON(ctx, p.client, prefixURL)
	if err != nil {
		return nil, err
	}
	var ni ripeNetworkInfo
	if err := json.Unmarshal(prefixBody, &ni); err != nil {
		return nil, err
	}
	if ni.Data.Prefix == "" {
		return nil, errors.New("ripe network-info returned no prefix")
	}
	routeURL := fmt.Sprintf("%s/routing-status/data.json?resource=%s", ripestatBase, url.QueryEscape(ni.Data.Prefix))
	routeBody, err := doJSON(ctx, p.client, routeURL)
	if err != nil {
		return nil, err
	}
	var rs ripeRoutingStatus
	if err := json.Unmarshal(routeBody, &rs); err != nil {
		return nil, err
	}
	var asns []string
	var holder string
	for _, origin := range rs.Data.Origins {
		v := fmt.Sprint(origin.ASN)
		if v == "" || v == "<nil>" {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(v), "AS") {
			v = "AS" + v
		}
		asns = append(asns, v)
		if holder == "" {
			holder = origin.Holder
		}
	}
	return &ASNInfo{Prefix: ni.Data.Prefix, ASNs: uniqueSortedTrimmed(asns), Holder: holder, Source: "RIPEstat"}, nil
}

type defaultWhoisProvider struct{}

func (p *defaultWhoisProvider) LookupDomain(ctx context.Context, domain string) (*WhoisRecord, error) {
	_ = ctx
	resp, err := whois.Whois(domain)
	if err != nil {
		return nil, err
	}
	return &WhoisRecord{Query: domain, Response: resp, Source: "whois"}, nil
}

func doJSON(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func registrableZone(host string) (string, bool) {
	host = trimDot(host)
	if host == "" {
		return "", false
	}
	zone, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host, true
	}
	return zone, true
}

func trimDot(s string) string { return strings.TrimSuffix(strings.TrimSpace(s), ".") }

func uniqueSortedTrimmed(in []string) []string {
	trimmed := make([]string, 0, len(in))
	for _, item := range in {
		trimmed = append(trimmed, trimDot(item))
	}
	return uniqueSortedStrings(trimmed)
}

func uniqueSortedStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func uniqueChain(in []CNAMEHop) []CNAMEHop {
	seen := map[string]struct{}{}
	out := make([]CNAMEHop, 0, len(in))
	for _, hop := range in {
		hop = CNAMEHop{From: trimDot(hop.From), To: trimDot(hop.To)}
		key := strings.ToLower(hop.From + "->" + hop.To)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, hop)
	}
	return out
}
