package resolver

import (
	"github.com/alphadose/haxmap"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net/netip"
	"strconv"
	"strings"
)

// The beenThereMap prevents loops. At each step, when a nameserver is queried, it is added to the beenthere set.
// No nameserver in the set will ever be queried again for the same question in the recursion process - we know for a fact it won’t help us further.
// This prevents the process from getting stuck in loops. (from powerDNS documentation https://doc.powerdns.com/recursor/appendices/internals.html?highlight=cache)
type beenThereMap struct {
	// haxMap is a little faster than sync.Map. Since the beenThereMap is called extremely often it pays off.
	innerMap *haxmap.Map[string, int]
	log      zerolog.Logger
	maxsize  uint
}

// track tracks a question that we ask to a name server. Returns true, if we have already 'beenThere'.
//
//	nsIP - Conn of the name server to which the message is sent
//	qType - Type of records that is queried
//	qName - Name that is queried
func (beenThereMap *beenThereMap) track(nsIP netip.Addr, qType uint16, qClass uint16, qName model.DomainName) bool {
	_, wasLoaded := beenThereMap.innerMap.GetOrSet(getKey(nsIP, qType, qClass, qName), 0)

	// Once the max size is reached, we always return true.
	// That means, we stop asking queries and terminate the resolution.
	if beenThereMap.innerMap.Len() > uintptr(beenThereMap.maxsize) {
		return true
	}

	if wasLoaded {
		// Can be useful to see if you wonder why some requests were not sent
		beenThereMap.log.Debug().Msgf("Been here: %v %v %v", nsIP, qType, qName)
	}

	return wasLoaded // If it was loaded, that means it was already stored (aka we have been there)
}

func getKey(nsIp netip.Addr, qType uint16, qClass uint16, qname model.DomainName) string {
	// We do not use fmt.Sprintf or nsIp.String().
	// This function here is called very often and therefore, time critical
	var builder strings.Builder
	builder.Write(nsIp.AsSlice())
	builder.WriteString(string(qname))
	builder.WriteString(strconv.Itoa(int(qType)))
	builder.WriteString(strconv.Itoa(int(qClass)))
	return builder.String()
}
