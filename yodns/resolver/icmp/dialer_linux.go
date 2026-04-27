package icmp

import (
	"fmt"
	"golang.org/x/net/icmp"
	"kernel.org/pub/linux/libs/security/libcap/cap"
	"net"
)

func newICMPListener(localAddress net.IP) (net.PacketConn, error) {
	network := ""
	if localAddress.To4() != nil {
		network = "ip4:icmp"
	} else if localAddress.To16() != nil {
		network = "ip6:ipv6-icmp"
	} else {
		return nil, fmt.Errorf("local address %v used for ICMP listener is invalid", localAddress)
	}

	return icmp.ListenPacket(network, localAddress.String())
}

func dropRawSocketCaps() {

	// TODO - this drops all capabilities.
	// Should drop only raw sockets.

	old := cap.GetProc()
	empty := cap.NewSet()
	if err := empty.SetProc(); err != nil {
		panic(fmt.Errorf("failed to drop privileges: %v with error %v", old, err))
	}
}
