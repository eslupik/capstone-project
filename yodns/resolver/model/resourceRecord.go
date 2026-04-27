package model

import (
	"github.com/miekg/dns"
	"strings"
)

func GetRRValue(rr dns.RR) string {
	// This prints the record and splits away the header.
	// The alternative would be writing a huge switch statement with all
	// implementations of dns.RR and implement string conversion for all of them.
	// But the miekg library already does this, so we want to utilize it

	if opt, isOpt := rr.(*dns.OPT); isOpt {
		return strings.ReplaceAll(opt.String(), "\n", " ")
	}
	// Name \t TTL \t Class \t Type \t Value
	parts := strings.Split(rr.String(), "\t")
	return strings.Join(parts[4:], "\t")
}
