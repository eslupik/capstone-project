package qmin

import (
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"strings"
)

const (
	PlaceholderName string = "{name}"
	PlaceholderZone        = "{zone}"
)

type QuestionTemplate struct {
	NameTemplate      string
	Type              uint16
	Class             uint16
	TCPOnly           bool
	UDPOnly           bool
	SkipCache         bool
	MaxRetries        *uint
	DisableInfraCache bool
	SkipRoot          bool
	SkipTLD           bool
	AskParent         bool
	DoNotFollow       bool
}

func QTModule(
	onFullNameResolved []QuestionTemplate,
	onZoneCreated []QuestionTemplate) Module {

	return Module{
		OnFullNameResolved: func(job *resolver.ResolutionJob, name model.DomainName, zone *model.Zone) {
			for _, qt := range onFullNameResolved {
				q, err := qt.ToQuestion(name, zone.Name)
				if err != nil {
					return
				}

				opts := resolver.EnqueueOpts{
					DisableTCPFallback: qt.UDPOnly,
					SkipCache:          qt.SkipCache,
					MaxRetries:         qt.MaxRetries,
					DisableInfraCache:  qt.DisableInfraCache,
				}

				job.EnqueueRequestForFutureNameServersAndIps(zone, q, carryOverArgsQmin{zone: zone, doNotFollow: qt.DoNotFollow}, opts)
			}
		},
		OnZoneCreated: func(job *resolver.ResolutionJob, zone *model.Zone) {
			for _, qt := range onZoneCreated {
				if qt.SkipRoot && zone.Parent == nil {
					continue
				}
				if qt.SkipTLD && zone.Name.IsTopLevelDomain() {
					continue
				}

				q, err := qt.ToQuestion(zone.Name, zone.Name)
				if err != nil {
					return
				}

				opts := resolver.EnqueueOpts{
					DisableTCPFallback: qt.UDPOnly,
					SkipCache:          qt.SkipCache,
					MaxRetries:         qt.MaxRetries,
					DisableInfraCache:  qt.DisableInfraCache,
				}

				if qt.AskParent && zone.Parent != nil {
					job.EnqueueRequestForFutureNameServersAndIps(zone.Parent, q, carryOverArgsQmin{zone: zone, doNotFollow: qt.DoNotFollow}, opts)
				} else {
					job.EnqueueRequestForFutureNameServersAndIps(zone, q, carryOverArgsQmin{zone: zone, doNotFollow: qt.DoNotFollow}, opts)
				}

			}
		},
	}
}

func (qt QuestionTemplate) ToQuestion(name model.DomainName, zoneName model.DomainName) (model.Question, error) {
	q := model.Question{
		Type:  qt.Type,
		Class: qt.Class,
	}

	qname := strings.ReplaceAll(qt.NameTemplate, PlaceholderName, string(name))
	qname = strings.ReplaceAll(qname, PlaceholderZone, string(zoneName))

	// Errors can happen, for example when the templates tries to append www to a domain name that is already 255 labels long.
	var err error
	q.Name, err = model.NewDomainName(qname)
	return q, err
}
