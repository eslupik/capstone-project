package resolver

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"testing"
)

func TestNameServerMap_CanCreateOrGetTwice_SameServerIsReturned(t *testing.T) {
	domain := model.MustNewDomainName("ns1.domain.test.")
	nsMap := NewNameServerMap()
	nameServer1, loaded1 := nsMap.CreateOrGet(domain)
	nameServer2, loaded2 := nsMap.CreateOrGet(domain)

	if loaded1 {
		t.Errorf("First CreateOrGet should return loaded=false")
	}
	if !loaded2 {
		t.Errorf("Second CreateOrGet should return loaded=true")
	}
	if nameServer1 != nameServer2 {
		t.Errorf("Expected the same server to be returned for %v", domain)
	}
}

func TestNameServerMap_CanCreateOrGetTwice_DifferentServersAreReturned(t *testing.T) {
	domain1 := model.MustNewDomainName("ns1.domain.test.")
	domain2 := model.MustNewDomainName("ns2.domain.test.")
	nsMap := NewNameServerMap()
	nameServer1, loaded1 := nsMap.CreateOrGet(domain1)
	nameServer2, loaded2 := nsMap.CreateOrGet(domain2)

	if loaded1 {
		t.Errorf("Expected %v, got %v", loaded1, !loaded1)
	}
	if loaded2 {
		t.Errorf("Expected %v, got %v", loaded2, !loaded2)
	}
	if nameServer1 == nameServer2 {
		t.Errorf("Expected the different servers to be returned for %v and %v", domain1, domain2)
	}
}

func TestNameServerMap_CanEnumerate(t *testing.T) {
	domain1 := model.MustNewDomainName("ns1.domain.test.")
	domain2 := model.MustNewDomainName("ns2.domain.test.")
	nsMap := NewNameServerMap()
	nameServer1, _ := nsMap.CreateOrGet(domain1)
	nameServer2, _ := nsMap.CreateOrGet(domain2)

	values := nsMap.Values()

	if len(values) != 2 {
		t.Errorf("Expected Values() to contain 2 items.")
	}
	if values[0] != nameServer1 && values[1] != nameServer1 {
		t.Errorf("Expected nameserver %v to be contained in Values()", nameServer1.Name)
	}
	if values[0] != nameServer2 && values[1] != nameServer2 {
		t.Errorf("Expected nameserver %v to be contained in Values()", nameServer2.Name)
	}
}
