package resolver

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net/netip"
	"sync"
)

// NameServerMap is a thread-safe map that can be used to store and create name server during the resolution process.
type NameServerMap struct {
	servers sync.Map
}

// NameServerSeed is a helper for seeding Root servers to the NameServerMap
type NameServerSeed struct {
	Name       model.DomainName
	IPVersion4 string
	IPVersion6 string
}

// NewNameServerMap creates a new NameServerMap.
func NewNameServerMap(rootServerSeeds ...NameServerSeed) *NameServerMap {
	nsMap := new(NameServerMap)
	for _, rootServer := range rootServerSeeds {
		ns, _ := nsMap.CreateOrGet(rootServer.Name)

		ns.AddIPs(netip.MustParseAddr(rootServer.IPVersion4),
			netip.MustParseAddr(rootServer.IPVersion6))
	}

	return nsMap
}

// Values returns all name servers that are stored inside the map.
func (nsMap *NameServerMap) Values() []*model.NameServer {
	var result []*model.NameServer

	nsMap.servers.Range(func(k, v any) bool {
		result = append(result, v.(*model.NameServer))
		return true
	})

	return result
}

// CreateOrGet returns a name server with the provided domain name. If a server with
// that name exists, it is returned. Otherwise a new one is created.
// The second argument indicates  whether the server was loaded (true) or created (false)
func (nsMap *NameServerMap) CreateOrGet(nsName model.DomainName) (ns *model.NameServer, loaded bool) {
	nsEntry, loaded := nsMap.servers.LoadOrStore(nsName, model.NewNameServer(nsName))
	return nsEntry.(*model.NameServer), loaded
}

// Get returns a name server with the provided domain name. If a server with that name exists, it is returned.
func (nsMap *NameServerMap) Get(nsName model.DomainName) (ns *model.NameServer, loaded bool) {
	if nsEntry, loaded := nsMap.servers.Load(nsName); loaded {
		return nsEntry.(*model.NameServer), loaded
	}
	return nil, false
}
