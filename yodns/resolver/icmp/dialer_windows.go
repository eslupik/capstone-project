package icmp

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	SioRcvall     = syscall.IOC_IN | syscall.IOC_VENDOR | 1
	RcvallIplevel = 3
)

// newICMPListener opens a connection that can be used to receive ICMP messages.
// This is an attempt to work around the problem described here at https://github.com/golang/go/issues/38427
// Solution copied from https://github.com/safing/portmaster/blob/e9881e2f15affbc0c6023278e69268dd0e523f47/netenv/location_windows.go
// We have to use the concrete local interface address, as SioRcvall can't be set on a 0.0.0.0 listeners.
func newICMPListener(localAddress net.IP) (net.PacketConn, error) {
	var network string

	switch {
	case localAddress.To4() != nil:
		network = "ip4:icmp"
	case localAddress.To16() != nil:
		network = "ip6:ipv6-icmp"
	default:
		return nil, fmt.Errorf("local address %v used for ICMP listener is invalid", localAddress)
	}

	// Configure the setup routine in order to extract the socket handle.
	var socketHandle syscall.Handle
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(s uintptr) {
				socketHandle = syscall.Handle(s)
			})
		},
	}

	// Bind to interface.
	conn, err := cfg.ListenPacket(context.Background(), network, localAddress.String())
	if err != nil {
		return nil, err
	}

	// Set socket option to receive all packets, such as ICMP error messages.
	// This is somewhat dirty, as there is guarantee that socketHandle is still valid.
	// WARNING: The Windows Firewall might just drop the incoming packets you might want to receive.
	unused := uint32(0) // Documentation states that this is unused, but WSAIoctl fails without it.
	flag := uint32(RcvallIplevel)
	size := uint32(unsafe.Sizeof(flag))
	err = syscall.WSAIoctl(socketHandle, SioRcvall, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &unused, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to set socket to listen to all packets: %s", os.NewSyscallError("WSAIoctl", err))
	}

	return conn, nil
}

func dropRawSocketCaps() {
	// This does not exist under windows.
}
