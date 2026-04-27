package icmp

import (
	"net"
)

func newICMPListener(localAddress net.IP) (net.PacketConn, error) {
	return nil, nil
}

func dropRawSocketCaps() {
	return
}
