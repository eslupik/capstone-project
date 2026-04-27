package tcp

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTCPPool_CreateEphemeral(t *testing.T) {
	expectedAddr := new(test.MockAddr).NewRandom()
	expectedPort := uint16(123)

	dialCalled := false
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(50 * time.Millisecond) // The test will fail if the pool does not wait for dial to finish.
		dialCalled = true
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 12, 1)
	go pool.Start(context.Background())

	conn, err := pool.CreateEphemeral(expectedAddr, expectedPort)

	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if !dialCalled {
		t.Errorf("Expected dial to be called")
	}

	if conn == nil {
		t.Fatalf("Expected conn to be not nil")
	}
	if conn.DestinationPort != expectedPort {
		t.Errorf("Expected conn.DestinationPort to be %v, got %v", expectedPort, conn.DestinationPort)
	}
	if conn.DestinationIP != expectedAddr {
		t.Errorf("Expected conn.DestinationIP to be %v, got %v", expectedAddr, conn.DestinationIP)
	}
}

func TestTCPPool_CreateEphemeral_Exhausted(t *testing.T) {
	expectedAddr := new(test.MockAddr).NewRandom()
	expectedPort := uint16(123)

	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 12, 1)
	go pool.Start(context.Background())

	_, _ = pool.CreateEphemeral(expectedAddr, expectedPort)
	conn, err := pool.CreateEphemeral(expectedAddr, expectedPort)

	if !errors.Is(err, client.ErrEphemeralExhausted) {
		t.Errorf("Expected err code to be %v, got %v", client.ErrorCodeEphemeralExhausted, err)
	}
	if conn != nil {
		t.Errorf("Expected conn to be nil")
	}
}

func TestTCPPool_CreateEphemeral_Released(t *testing.T) {
	expectedAddr := new(test.MockAddr).NewRandom()
	expectedPort := uint16(123)

	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 12, 1)
	go pool.Start(context.Background())
	pool.closeWithRST = true

	conn, err := pool.CreateEphemeral(expectedAddr, expectedPort)
	conn.CloseNow() // Free the place, so the next call succeeds
	conn, err = pool.CreateEphemeral(expectedAddr, expectedPort)

	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if conn == nil {
		t.Errorf("Expected conn to be not nil")
	}
	if dialCalls != 2 {
		t.Errorf("Expected exactly 2 calls to dial")
	}
}

func TestTCPPool_GetOrCreate(t *testing.T) {
	expectedAddr := new(test.MockAddr).NewRandom()
	expectedPort := uint16(123)

	dialCalled := false
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(50 * time.Millisecond) // The test will fail if the pool does not wait for dial to finish.
		dialCalled = true
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 1, 1)

	conn, err := pool.GetOrCreate(expectedAddr, expectedPort, nil)

	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if !dialCalled {
		t.Errorf("Expected dial to be called")
	}
	if conn == nil {
		t.Fatalf("Expected conn to be not nil")
	}
	if conn.DestinationPort != expectedPort {
		t.Errorf("Expected conn.DestinationPort to be %v, got %v", expectedPort, conn.DestinationPort)
	}
	if conn.DestinationIP != expectedAddr {
		t.Errorf("Expected conn.DestinationIP to be %v, got %v", expectedAddr, conn.DestinationIP)
	}
}

func TestTCPPool_GetOrCreate_Exhausted(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 1, 1)

	_, _ = pool.GetOrCreate(test.MockAddr{Value: "1.2.3.4"}, 53, nil)
	conn, err := pool.GetOrCreate(test.MockAddr{Value: "4.3.2.1"}, 53, nil)

	if !errors.Is(err, client.ErrPoolExhausted) {
		t.Errorf("Expected err code to be %v, got %v", client.ErrorCodePoolExhausted, err)
	}
	if conn != nil {
		t.Errorf("Expected conn to be nil")
	}
}

func TestTCPPool_GetOrCreate_Released(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 1, 1)
	pool.closeWithRST = true

	conn, err := pool.GetOrCreate(test.MockAddr{Value: "1.2.3.4"}, 53, nil)
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}

	conn.CloseNow() // Free the place, so the next call succeeds
	conn, err = pool.GetOrCreate(test.MockAddr{Value: "4.3.2.1"}, 53, nil)

	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if conn == nil {
		t.Errorf("Expected conn to be not nil")
	}
	if dialCalls != 2 {
		t.Errorf("Expected exactly 2 calls to dial")
	}
}

func TestTCPPool_GetOrCreate_Parallel(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 1, 1)
	pool.closeWithRST = true

	var wg sync.WaitGroup
	wg.Add(3)

	ip := new(test.MockAddr).NewRandom()
	for i := 0; i < 3; i++ {
		go func() {
			conn, err := pool.GetOrCreate(ip, 53, nil)
			if err != nil {
				t.Errorf("Expected err to be nil, got %v", err)
			}
			if conn == nil {
				t.Errorf("Expected conn to be not nil")
			}
			wg.Done()
		}()
	}
	wg.Wait()
	if dialCalls != 1 {
		t.Errorf("Expected exactly 1 call to dial, got %v", dialCalls)
	}
}

func TestTCPPool_GetOrCreate_ConnectionRemovedAfterIdlePeriod(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(500*time.Millisecond, time.Second, time.Second, time.Second, 1, 1)
	go pool.Start(context.Background())

	ip := new(test.MockAddr).NewRandom()
	conn1, _ := pool.GetOrCreate(ip, 53, nil)
	time.Sleep(time.Second)
	conn2, _ := pool.GetOrCreate(ip, 53, nil)

	if conn1 == conn2 {
		t.Errorf("Expected different conns because time-interval between calls was too large")
	}
	if dialCalls != 2 {
		t.Errorf("Expected exactly 2 call to dial, got %v", dialCalls)
	}
	if pool.connections.Len() != 1 {
		t.Errorf("Expected exactly 1 connection in the pool")
	}
}

func TestTCPPool_GetOrCreate_IdlePeriodIsReset(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(time.Second, time.Second, time.Second, time.Second, 1, 1)
	go pool.Start(context.Background())
	pool.closeWithRST = true

	ip := new(test.MockAddr).NewRandom()
	conn1, _ := pool.GetOrCreate(ip, 53, nil)
	time.Sleep(700 * time.Millisecond)
	conn2, _ := pool.GetOrCreate(ip, 53, nil)
	time.Sleep(700 * time.Millisecond)

	if dialCalls != 1 {
		t.Errorf("Expected exactly 1 call to dial, got %v", dialCalls)
	}
	if conn1 != conn2 {
		t.Errorf("Expected conn to be the same")
	}
}

// Tests that a server can send the edns0-tcp-keepalive option to specify the keepalive of the TCP connection
func TestTCPPool_GetOrCreate_TCPKeepAlive(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(500*time.Millisecond, time.Second, time.Second, time.Second, 1, 1)
	go pool.Start(context.Background())
	pool.closeWithRST = true

	msg := new(dns.Msg).SetQuestion("test.com.", 1).SetEdns0(1232, true)
	internal.SetTCPKeepalive(msg, time.Second)

	ip := new(test.MockAddr).NewRandom()
	conn1, _ := pool.GetOrCreate(ip, 53, nil)
	conn1.onReceive(conn1, msg, "1.2.3.4", nil) // Emulate receiving a message. The idleTime should be adapted to the TCP keepalive

	time.Sleep(700 * time.Millisecond) // After 700ms, the connection will be removed if the edns0-keepalive was not respected

	conn2, _ := pool.GetOrCreate(ip, 53, nil)

	if dialCalls != 1 {
		t.Errorf("Expected exactly 1 call to dial, got %v", dialCalls)
	}
	if conn1 != conn2 {
		t.Errorf("Expected conn to be the same")
	}
}

// Tests that a keepalive set via the edns0-tcp-keepalive option is not overwritten with the default value
// by subsequent calls to GetOrCreate
func TestTCPPool_GetOrCreate_LongerTCPKeepAlive_IsNotOverwritten(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(100*time.Millisecond, time.Second, time.Second, time.Second, 1, 1)
	go pool.Start(context.Background())
	pool.closeWithRST = true

	msg := new(dns.Msg).SetQuestion("test.com.", 1).SetEdns0(1232, true)
	internal.SetTCPKeepalive(msg, time.Second)

	ip := new(test.MockAddr).NewRandom()
	conn1, _ := pool.GetOrCreate(ip, 53, nil)
	conn1.onReceive(conn1, msg, ip.Value, nil) // Emulate receiving a message. The idleTime should be adapted to the TCP keepalive

	// Make sure this call does not reset the second long idle period back to 100ms
	_, _ = pool.GetOrCreate(ip, 53, nil)

	time.Sleep(500 * time.Millisecond) // After 500, the connection will be if the idle period was reset to the original value

	conn2, _ := pool.GetOrCreate(ip, 53, nil)

	if dialCalls != 1 {
		t.Errorf("Expected exactly 1 call to dial, got %v", dialCalls)
	}
	if conn1 != conn2 {
		t.Errorf("Expected conn to be the same")
	}
}

func TestTCPPool_GetOrCreate_ShorterTCPKeepAlive_IsNotOverwritten(t *testing.T) {
	dialCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		dialCalls++
		return test.MockConn{}, nil
	}

	pool := NewTCPPool(1*time.Second, time.Second, time.Second, time.Second, 1, 1)
	go pool.Start(context.Background())
	pool.closeWithRST = true

	msg := new(dns.Msg).SetQuestion("test.com.", 1).SetEdns0(1232, true)
	internal.SetTCPKeepalive(msg, 500*time.Millisecond)

	// Remaining TTL = 300
	ip := new(test.MockAddr).NewRandom()
	conn1, _ := pool.GetOrCreate(ip, 53, nil)
	conn1.onReceive(conn1, msg, ip.Value, nil) // Emulate receiving a message. The idleTime should be adapted to the TCP keepalive

	// Remaining TTL = 200
	time.Sleep(100 * time.Millisecond)

	// TTL extended. New TTL = 300
	// --> This is the essence of the test, it MUST NOT extend the TTL by 1 second (default) but by 200ms
	conn2, _ := pool.GetOrCreate(ip, 53, nil)

	// TTL expired
	time.Sleep(450 * time.Millisecond)

	// New conn opened
	conn3, _ := pool.GetOrCreate(ip, 53, nil)

	if dialCalls != 2 {
		t.Errorf("Expected exactly 2 calls to dial, got %v", dialCalls)
	}
	if conn1 != conn2 {
		t.Errorf("Expected conn1 and conn2 to be equal")
	}
	if conn1 == conn3 {
		t.Errorf("Expected conn3 to be fresh")
	}
}
