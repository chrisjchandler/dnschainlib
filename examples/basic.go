package main

import (
	"context"
	"fmt"

	"github.com/cchandler/asnlookup-go/dnschainlib"
)

func main() {
	res, err := dnschainlib.Lookup(context.Background(), "cnn.com", nil)
	if err != nil {
		panic(err)
	}
	fmt.Println("canonical:", res.CanonicalName)
	fmt.Println("ips:", res.ChainedIPs)
	fmt.Println("nameservers:", res.Nameservers)
}
