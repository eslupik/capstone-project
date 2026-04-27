package test

import (
	"net"
	"time"
)

var _ net.Conn = new(MockConn)

// MockConn is a customizable mock implementation of net.Conn to be used for testing
type MockConn struct {
	ReadFunc  func([]byte) (int, error)
	WriteFunc func([]byte) (int, error)
	CloseFunc func() error
}

func (m MockConn) Read(b []byte) (int, error) {
	if m.ReadFunc != nil {
		return m.ReadFunc(b)
	}

	return 0, nil
}

func (m MockConn) Write(b []byte) (int, error) {
	if m.WriteFunc != nil {
		return m.WriteFunc(b)
	}

	return 0, nil
}

func (m MockConn) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}

	return nil
}

func (m MockConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (m MockConn) RemoteAddr() net.Addr {
	panic("implement me")
}

func (m MockConn) SetDeadline(_ time.Time) error {
	return nil
}

func (m MockConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (m MockConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
