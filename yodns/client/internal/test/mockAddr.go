package test

import (
	crand "crypto/rand"
	"github.com/DNS-MSMT-INET/yodns/client"
	mrand "math/rand"
	"net"
)

var _ client.Address = new(MockAddr)

type MockAddr struct {
	Value string
	V6    bool
}

func (m MockAddr) Is6() bool {
	return m.V6
}

func (m MockAddr) String() string {
	return m.Value
}

func (m MockAddr) NewRandom() MockAddr {
	if mrand.Int31n(2) == 0 { //nolint:gosec,mnd
		return m.NewRandomV4()
	}

	return m.NewRandomV6()
}

func (m MockAddr) NewRandomV4() MockAddr {
	return MockAddr{
		Value: randomIP(net.IPv4len),
		V6:    false,
	}
}

func (m MockAddr) NewRandomV6() MockAddr {
	return MockAddr{
		Value: randomIP(net.IPv6len),
		V6:    true,
	}
}

func randomIP(length int) string {
	var result = make([]byte, length)
	if _, err := crand.Read(result); err != nil {
		panic(err)
	}

	return net.IP(result).String()
}
