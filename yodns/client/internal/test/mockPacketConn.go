package test

import (
	"net"
	"time"
)

var _ net.PacketConn = new(MockPacketConn)

// MockPacketConn is a customizable mock implementation of net.PacketConn to be used for testing
type MockPacketConn struct {
	ReadFromFunc         func([]byte) (int, net.Addr, error)
	WriteToFunc          func([]byte, net.Addr) (int, error)
	CloseFunc            func() error
	SetWriteDeadlineFunc func(time.Time) error
}

func (m MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return m.ReadFromFunc(p)
}

func (m MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return m.WriteToFunc(p, addr)
}

func (m MockPacketConn) Close() error {
	return m.CloseFunc()
}

func (m MockPacketConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (m MockPacketConn) SetDeadline(_ time.Time) error {
	panic("implement me")
}

func (m MockPacketConn) SetReadDeadline(_ time.Time) error {
	panic("implement me")
}

func (m MockPacketConn) SetWriteDeadline(t time.Time) error {
	return m.SetWriteDeadlineFunc(t)
}
