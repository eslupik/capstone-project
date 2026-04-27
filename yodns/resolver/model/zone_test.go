package model

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"net/netip"
	"reflect"
	"testing"
)

func TestZone_GetClosestEnclosingZone(t *testing.T) {
	type args struct {
		domainName DomainName
	}
	tests := []struct {
		name string
		zone *Zone
		args args
		want *Zone
	}{
		{
			name: "OnlyRootZone_ShouldReturnRootZone",
			zone: &Zone{Name: "."},
			args: args{domainName: "test."},
			want: &Zone{Name: "."},
		},
		{
			name: "DomainIsInSubzone_ShouldReturnSubZone",
			zone: &Zone{Name: ".", Subzones: []*Zone{{Name: "com.", Subzones: []*Zone{{Name: "example.com."}}}}},
			args: args{domainName: "test.com."},
			want: &Zone{Name: "com."},
		},
		{
			name: "DomainIsEqualToSubzone_ShouldReturnSubZone",
			zone: &Zone{Name: ".", Subzones: []*Zone{{Name: "com.", Subzones: []*Zone{{Name: "test.com."}}}}},
			args: args{domainName: "test.com."},
			want: &Zone{Name: "test.com."},
		},
		{
			name: "DomainIsEqualToSubzone_ShouldReturnSubZone",
			zone: &Zone{Name: ".", Subzones: []*Zone{{Name: "pl.", Subzones: []*Zone{{Name: "cyf-kr.edu.pl."}}}}},
			args: args{domainName: "icm.edu.pl."},
			want: &Zone{Name: "pl."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.zone.GetClosestEnclosingZone(tt.args.domainName); !reflect.DeepEqual(got.Name, tt.want.Name) {
				t.Errorf("Zone.GetClosestEnclosingZone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZone_AppendNameServersTwice_ExpectUniqueness(t *testing.T) {
	zone := Zone{Name: "example.com."}

	zone.AppendNameServers(&NameServer{
		Name:        "myns.com",
		IPAddresses: common.NewCompSet[netip.Addr](),
	})
	zone.AppendNameServers(&NameServer{
		Name:        "myns.com",
		IPAddresses: common.NewCompSet[netip.Addr](),
	})

	if len(zone.NameServers) != 1 {
		t.Errorf("Expected zone.NameServers to have length 1 but found %v", len(zone.NameServers))
	}
}

func TestZone_AppendNameServersDistinctIPs_ExpectIPsAreMerged(t *testing.T) {
	zone := Zone{Name: "example.com."}

	zone.AppendNameServers(&NameServer{
		Name: "myns.com",
		IPAddresses: common.NewCompSet(netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("::")),
	})
	zone.AppendNameServers(&NameServer{
		Name: "myns.com",
		IPAddresses: common.NewCompSet(netip.MustParseAddr("0.0.0.0"),
			netip.MustParseAddr("::")),
	})

	if len(zone.NameServers) != 1 {
		t.Errorf("Expected zone.NameServers to have length 1 but found %v", len(zone.NameServers))
	}

	ips := zone.NameServers[0].IPAddresses.Items()
	if len(ips) != 3 {
		t.Errorf("NameServer.IPAddresses to have length 3 but found %v", len(ips))
	}

	for _, ip := range ips {
		if ip.String() != "0.0.0.0" && ip.String() != "9.9.9.9" && ip.String() != "::" {
			t.Errorf("Did not expect to find Conn %v in nameserver ", ip)
		}
	}
}

func TestZone_CreateOrGetSubzone_ExpectNewZoneIsCreated(t *testing.T) {
	expectedName := DomainName("my.example.com.")
	zone := Zone{Name: "example.com."}
	subzone, loaded, err := zone.CreateOrGetSubzone(expectedName)

	if loaded {
		t.Errorf("Expected loaded to be false, got true")
	}
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if subzone.Name != expectedName {
		t.Errorf("Expected subzone.Name to be %v but found %v", expectedName, subzone.Name)
	}
	if len(zone.Subzones) != 1 {
		t.Errorf("Expected zone.Subzones to have length 1 but found %v", len(zone.NameServers))
	}
	if zone.Subzones[0] != subzone {
		t.Errorf("Expected zone.Subzones to contain the returned subzone")
	}
	if subzone.Parent != &zone {
		t.Errorf("Expected subzone.Parent to be equal to the zone.")
	}
}

func TestZone_CreateOrGetSubzone_NameIsNotProperSubdomain_ExpectError(t *testing.T) {
	childName := DomainName("notasubdomain.com.")
	parentName := DomainName("example.com.")
	zone := Zone{Name: parentName}

	subzone, _, err := zone.CreateOrGetSubzone(childName)
	if subzone != nil {
		t.Errorf("Expected subzone to be ni, got %v", subzone.Name)
	}
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestZone_CreateOrGetSubzone_ExpectExistingZoneIsReturned(t *testing.T) {
	expectedName := MustNewDomainName("my.example.com.")
	expectedSubzone := &Zone{Name: expectedName}
	zone := Zone{Name: DomainName("example.com."), Subzones: []*Zone{expectedSubzone}}

	subzone, loaded, err := zone.CreateOrGetSubzone(DomainName(expectedName))

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !loaded {
		t.Errorf("Expected loaded to be true, got false")
	}
	if len(zone.Subzones) != 1 {
		t.Errorf("Expected zone.Subzones to have length 1 but found %v", len(zone.NameServers))
	}
	if subzone != expectedSubzone {
		t.Errorf("Expected returned subzone to be equal to the already existing subzone")
	}
}
