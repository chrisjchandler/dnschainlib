[![Go Reference](https://pkg.go.dev/badge/github.com/chrisjchandler/entropy.svg)](https://pkg.go.dev/github.com/chrisjchandler/dnschainlib)
# dnschainlib

`dnschainlib` is a small Go package used to do one thing: call RIPEstat's `dns-chain` endpoint for a hostname or IP, print the JSON, and save it. Useful enough, but awkward to reuse from other code. This package keeps the same general purpose and turns it into a normal importable library.

## What it does

Give it either a domain name or an IP address and it will:

- collect the chained IPs it can see
- follow visible CNAME hops for DNS names
- look up the nameservers for the relevant zone
- optionally return only the chained IP list if that's all you want

There is also an enriched path that adds:

- GeoIP data for each IP
- GeoIP data for nameserver IPs
- GeoIP data for visible CNAME targets
- ASN data using RIPEstat
- WHOIS output for the zone when the input is a DNS name

## Why the output looks the way it does

The package is meant to be predictable enough to drop into someone else's scripts without making them guess what they'll get back.

For a DNS name, it:

- follows visible CNAME hops in order
- resolves the final hostname to A and AAAA records
- de-duplicates and sorts the IP list
- derives the registrable zone
- looks up nameservers for that zone

For an IP input, it:

- keeps the input IP in `ChainedIPs`
- collects PTR names if any exist
- resolves PTR targets like DNS names unless `IPsOnly` is set
- looks up nameservers for PTR-derived zones when available

If `IPsOnly` is enabled, the package still fills `ChainedIPs`, but it intentionally skips nameserver and CNAME detail. That behavior is called out in the returned notes so downstream code is not left guessing.

## API

```go
type Options struct {
    Timeout  time.Duration
    IPsOnly  bool
    Resolver Resolver
    HTTP     *http.Client
    GeoIP    GeoIPProvider
    ASN      ASNProvider
    Whois    WhoisProvider
}

func Lookup(ctx context.Context, input string, opts *Options) (*Result, error)
func LookupEnhanced(ctx context.Context, input string, opts *Options) (*EnhancedResult, error)
```

If you do not pass custom providers, the package uses built-in defaults.

## Quick use

```go
res, err := dnschainlib.Lookup(context.Background(), "cnn.com", nil)
if err != nil {
    panic(err)
}
fmt.Println(res.ChainedIPs)
```

## Included example program

```bash
cd /home/cchandler/asnlookup-Go/dnschainlib
go run ./examples/basic.go
```

## Included JSON wrapper

There is also a tiny CLI wrapper if you want to call the library from a shell script.

```bash
go run ./cmd/dnschainjson cnn.com
go run ./cmd/dnschainjson --ips-only 8.8.8.8
go run ./cmd/dnschainjson --enhanced cnn.com
```

If you want to see how timeout handling behaves:

```bash
go run ./cmd/dnschainjson --enhanced --timeout 2s cnn.com
```

## Development

Run tests:

```bash
go test ./...
```

Run the example:

```bash
go run ./examples/basic.go
```

## Notes

A few things are worth knowing up front:

- DNS answers change over time, so live runs are observations, not permanent truth.
- GeoIP data comes from `ipwho.is`, so quality and rate limits depend on that service.
- ASN enrichment depends on what RIPEstat returns for a given address.
- WHOIS output is raw upstream text and is not uniform across registries.
- The enhanced path can be noticeably slower than the basic lookup, especially when nameservers fan out to a lot of A and AAAA records.

## Example Usage Output

##command
```bash
go run ./cmd/dnschainjson --enhanced cnn.com
```
##output
```json
{
  "input": "cnn.com",
  "input_type": "domain",
  "lookup_mode": "full",
  "zone": "cnn.com",
  "canonical_name": "cnn.com",
  "chained_ips": [
    "151.101.131.5",
    "151.101.195.5",
    "151.101.3.5",
    "151.101.67.5",
    "2a04:4e42:200::773",
    "2a04:4e42:400::773",
    "2a04:4e42:600::773",
    "2a04:4e42::773"
  ],
  "nameservers": [
    "ns-1242.awsdns-27.org",
    "ns-1652.awsdns-14.co.uk",
    "ns-378.awsdns-47.com",
    "ns-587.awsdns-09.net"
  ],
  "source": "dnschainlib",
  "ip_details": [
    {
      "ip": "151.101.131.5",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "151.101.128.0/22",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "151.101.195.5",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "151.101.192.0/22",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "151.101.3.5",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "151.101.0.0/22",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "151.101.67.5",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "151.101.64.0/22",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "2a04:4e42:200::773",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "2a04:4e42:200::/48",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "2a04:4e42:400::773",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "2a04:4e42:400::/48",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "2a04:4e42:600::773",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "2a04:4e42:600::/48",
        "source": "RIPEstat"
      }
    },
    {
      "ip": "2a04:4e42::773",
      "geo": {
        "country": "United States",
        "country_code": "US",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749113,
        "longitude": -122.4185412,
        "source": "ipwho.is"
      },
      "asn": {
        "prefix": "2a04:4e42::/48",
        "source": "RIPEstat"
      }
    }
  ],
  "nameserver_details": [
    {
      "host": "ns-1242.awsdns-27.org",
      "ips": [
        {
          "ip": "205.251.196.218",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Virginia",
            "city": "Washington",
            "latitude": 38.7129721,
            "longitude": -78.1593468,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "205.251.196.0/24",
            "source": "RIPEstat"
          }
        },
        {
          "ip": "2600:9000:5304:da00::1",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Virginia",
            "city": "Washington",
            "latitude": 38.7129721,
            "longitude": -78.1593468,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "2600:9000:5304::/48",
            "source": "RIPEstat"
          }
        }
      ]
    },
    {
      "host": "ns-1652.awsdns-14.co.uk",
      "ips": [
        {
          "ip": "205.251.198.116",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Virginia",
            "city": "Washington",
            "latitude": 38.7129721,
            "longitude": -78.1593468,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "205.251.198.0/24",
            "source": "RIPEstat"
          }
        },
        {
          "ip": "2600:9000:5306:7400::1",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6043089,
            "longitude": -122.3298447,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "2600:9000:5306::/48",
            "source": "RIPEstat"
          }
        }
      ]
    },
    {
      "host": "ns-378.awsdns-47.com",
      "ips": [
        {
          "ip": "205.251.193.122",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6043089,
            "longitude": -122.3298447,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "205.251.193.0/24",
            "source": "RIPEstat"
          }
        },
        {
          "ip": "2600:9000:5301:7a00::1",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6043089,
            "longitude": -122.3298447,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "2600:9000:5301::/48",
            "source": "RIPEstat"
          }
        }
      ]
    },
    {
      "host": "ns-587.awsdns-09.net",
      "ips": [
        {
          "ip": "205.251.194.75",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Virginia",
            "city": "Washington",
            "latitude": 38.7129721,
            "longitude": -78.1593468,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "205.251.194.0/24",
            "source": "RIPEstat"
          }
        },
        {
          "ip": "2600:9000:5302:4b00::1",
          "geo": {
            "country": "United States",
            "country_code": "US",
            "region": "Washington",
            "city": "Seattle",
            "latitude": 47.6043089,
            "longitude": -122.3298447,
            "source": "ipwho.is"
          },
          "asn": {
            "prefix": "2600:9000:5302::/48",
            "source": "RIPEstat"
          }
        }
      ]
    }
  ],
  "zone_whois": {
    "query": "cnn.com",
    "source": "whois",
    "response": "Domain Name: CNN.COM\\n... full WHOIS omitted here in chat for sanity ..."
  }
}
```
