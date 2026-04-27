package qmin

import (
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
)

// Module is a collection of callbacks that can be used to extend the functionality of the resolver.
type Module struct {
	OnZoneCreated func(job *resolver.ResolutionJob, zone *model.Zone)

	// OnFullNameResolved is invoked when a full name is resolved. This can be either
	// - the original FQDN,
	// - a nameserver name,
	// - any name added by modules on the way (e.g. MX names)
	// - or a CNAME of any of the above
	// You may not assume in this callback that
	// - the set of nameservers of the zone is complete
	// - the set of IPs of nameservers is complete
	OnFullNameResolved func(job *resolver.ResolutionJob, name model.DomainName, zone *model.Zone)

	// OnMessageReceived is invoked when a message is received.
	OnMessageReceived func(job *resolver.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange)
}

type ModuleCollection []Module

func (mc ModuleCollection) OnFullNameResolved(job *resolver.ResolutionJob, name model.DomainName, zone *model.Zone) {
	for _, module := range mc {
		if module.OnFullNameResolved != nil {
			module.OnFullNameResolved(job, name, zone)
		}
	}
}

func (mc ModuleCollection) OnZoneCreated(job *resolver.ResolutionJob, zone *model.Zone) {
	for _, module := range mc {
		if module.OnZoneCreated != nil {
			module.OnZoneCreated(job, zone)
		}
	}
}

func (mc ModuleCollection) OnMessageReceived(job *resolver.ResolutionJob, ns *model.NameServer, msgEx model.MessageExchange) {
	for _, module := range mc {
		if module.OnMessageReceived != nil {
			module.OnMessageReceived(job, ns, msgEx)
		}
	}
}
