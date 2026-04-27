package resolver

import (
	"fmt"
	"github.com/alphadose/haxmap"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net/netip"
	"testing"
)

func Test_beenThereMap_MaxQueries(t *testing.T) {
	maxSize := uint(4)
	m := beenThereMap{
		innerMap: haxmap.New[string, int](),
		maxsize:  maxSize,
	}
	ip := netip.MustParseAddr("192.0.2.1")

	for i := uint(0); i < maxSize; i++ {

		// Ask twice - should only be counted once because it is the same
		beenThere := m.track(ip, 1, 1, model.MustNewDomainName(fmt.Sprintf("%v.example.com.", i)))
		if beenThere {
			t.Errorf("Expected beenThere to be false")
			t.Fail()
		}

		beenThere = m.track(ip, 1, 1, model.MustNewDomainName(fmt.Sprintf("%v.example.com.", i)))
		if !beenThere {
			t.Errorf("Expected beenThere to be true")
			t.Fail()
		}
	}

	beenThere := m.track(ip, 1, 1, model.MustNewDomainName("neverasked.example.com."))
	if !beenThere {
		t.Errorf("Expected beenThere to be true")
		t.Fail()
	}
}
