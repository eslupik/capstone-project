package tcp

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// Test Cases for verifying TCP error handling (especially on different OSes)

func TestTCP_ServerRST(t *testing.T) {
	t.Skip()

	go func() {
		listener, err := net.Listen("tcp", ":9000")
		if err != nil {
			t.Error(err)
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		time.Sleep(100 * time.Millisecond)
		tcpConn := conn.(*net.TCPConn)
		tcpConn.SetLinger(0) // Close with RST instead of FIN
		tcpConn.Close()
	}()

	conn, _ := net.DialTimeout("tcp", ":9000", time.Second)

	res := make([]byte, 1024)
	_, err := conn.Read(res)

	fmt.Println(err)
}

func TestTCP_ServerFIN(t *testing.T) {
	t.Skip()

	go func() {
		listener, err := net.Listen("tcp", ":9000")
		if err != nil {
			t.Error(err)
			return
		}

		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}

		time.Sleep(time.Second)
		_ = conn.Close()
	}()

	conn, _ := net.DialTimeout("tcp", ":9000", time.Second)

	res := make([]byte, 1024)
	_, err := conn.Read(res)

	fmt.Println(err)
}
