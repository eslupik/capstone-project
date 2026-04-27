package udp

import (
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"net"
	"testing"
	"time"
)

func TestUDPPool_FaultyConn_ExpectReplaced(t *testing.T) {
	pool := NewPool(net.ParseIP("127.0.0.1"), 512, 1)

	conn1, _ := pool.GetOrCreate(nil)

	conn1.faulty = 1

	conn2, _ := pool.GetOrCreate(nil)

	if conn1 == conn2 {
		t.Errorf("Expected faulty connection to be replaced.")
	}
}

func TestUDPPool_ExpectConnReuse_RoundRobin(t *testing.T) {
	pool := NewPool(net.ParseIP("127.0.0.1"), 512, 2)

	conn1, _ := pool.GetOrCreate(nil)
	conn2, _ := pool.GetOrCreate(nil)
	conn3, _ := pool.GetOrCreate(nil)
	conn4, _ := pool.GetOrCreate(nil)

	if conn1 == conn2 {
		t.Errorf("Expected connection to be reused in round robin manner")
	}

	if conn2 == conn3 {
		t.Errorf("Expected connection to be reused in round robin manner")
	}

	if conn3 == conn4 {
		t.Errorf("Expected connection to be reused in round robin manner")
	}

	if conn1 != conn3 {
		t.Errorf("Expected connection to be reused in round robin manner")
	}
	
	if conn2 != conn4 {
		t.Errorf("Expected connection to be reused in round robin manner")
	}
}

func TestUDPPool_NumberOfConnections(t *testing.T) {
	size := 123

	calls := 0
	dialFunc = func(localIp net.IP) (net.PacketConn, error) {
		calls++

		return test.MockPacketConn{
			ReadFromFunc: func(bytes []byte) (int, net.Addr, error) {
				time.Sleep(time.Second)
				return 0, nil, nil
			},
		}, nil
	}

	pool := NewPool(net.ParseIP("127.0.0.1"), 512, uint16(size))

	for i := 0; i < 2*size; i++ {
		pool.GetOrCreate(nil)
	}

	if calls != size {
		t.Errorf("Expected only %v connections to be opened, got %v", size, calls)
	}
}
