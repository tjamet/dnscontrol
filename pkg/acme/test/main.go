package main

import (
	"github.com/StackExchange/dnscontrol/pkg/acme"
)

func main() {
	acme.IssueCerts(nil, nil)
}
