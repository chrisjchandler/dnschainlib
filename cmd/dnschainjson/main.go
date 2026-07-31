package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chrisjchandler/dnschainlib"
)

func main() {
	enhanced := flag.Bool("enhanced", false, "include GeoIP, ASN, CNAME, nameserver, and WHOIS enrichment")
	ipsOnly := flag.Bool("ips-only", false, "return only deterministic chained IPs")
	timeout := flag.Duration("timeout", 45*time.Second, "lookup timeout")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: dnschainjson [--enhanced] [--ips-only] <hostname-or-ip>\n")
		os.Exit(2)
	}
	ctx := context.Background()
	opts := &dnschainlib.Options{Timeout: *timeout, IPsOnly: *ipsOnly}
	var (
		out any
		err error
	)
	if *enhanced {
		out, err = dnschainlib.LookupEnhanced(ctx, flag.Arg(0), opts)
	} else {
		out, err = dnschainlib.Lookup(ctx, flag.Arg(0), opts)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}
