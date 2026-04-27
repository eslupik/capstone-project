package tcp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal/test"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPooledTCPConn_Discard(t *testing.T) {
	onClose := false

	conn := newPooledConn(new(test.MockAddr).NewRandom(), 53)
	conn.onClose = func() {
		onClose = true
	}

	conn.CloseNow()

	if !onClose {
		t.Errorf("Expected discard to be called")
	}
}

func TestPooledTCPConn_DialOnce_Error(t *testing.T) {
	dialErr := fmt.Errorf("connection refused")
	dialCalls := int32(0)
	closeCalls := int32(0)

	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt32(&dialCalls, 1)
		return nil, dialErr
	}

	conn := newPooledConn(new(test.MockAddr).NewRandom(), 53)
	conn.onClose = func() {
		closeCalls++
	}

	var wg sync.WaitGroup
	wg.Add(3)

	dialAndAssert := func() {
		err := conn.DialOnce(time.Second)
		if !errors.Is(err, dialErr) {
			t.Errorf("Expected error %v, got %v", dialErr, err)
		}
		wg.Done()
	}

	go dialAndAssert()
	go dialAndAssert()
	go dialAndAssert()

	wg.Wait()

	if dialCalls != 1 {
		t.Errorf("Expected dial to be called exactly once")
	}
}

func TestPooledTCPConn_DialOnce_Parallel(t *testing.T) {
	conn := newPooledConn(new(test.MockAddr).NewRandom(), 53)

	dialCalls := int32(0)
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		atomic.AddInt32(&dialCalls, 1)
		return nil, nil
	}

	var wg sync.WaitGroup
	wg.Add(3)

	dialAndAssert := func() {
		err := conn.DialOnce(time.Second)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		wg.Done()
	}

	go dialAndAssert()
	go dialAndAssert()
	go dialAndAssert()

	wg.Wait()

	if dialCalls != 1 {
		t.Errorf("Expected dial to be called exactly once")
	}
}

func TestEphemeralTCPConn_Close(t *testing.T) {
	expectedAddress := "1.2.3.4"
	closeCalled := false
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return test.MockConn{
			CloseFunc: func() error {
				closeCalled = true
				return nil
			},
		}, nil
	}

	conn := newPooledConn(test.MockAddr{Value: expectedAddress}, 53)

	if err := conn.DialOnce(time.Second); err != nil {
		t.Errorf("Expected dial to succeed")
	}

	conn.Close(context.Background(), 0)

	if !closeCalled {
		t.Errorf("Expected inner connection to be closed")
	}
}

func TestPooledTCPConn_CloseWithGracePeriod_WaitsForReceive(t *testing.T) {
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	remoteAddr := new(test.MockAddr).NewRandom()
	remotePort := uint16(332)
	readCalls := 0
	closeCalls := 0

	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return test.MockConn{
			WriteFunc: func(bytes []byte) (int, error) {
				return len(bytes), nil
			},
			CloseFunc: func() error {
				closeCalls++
				return nil
			},
			ReadFunc: func(bytes []byte) (int, error) {
				p, _ := responseMsg.Pack()
				if readCalls == 0 {
					binary.BigEndian.PutUint16(bytes, uint16(len(p)))
					readCalls++
					return 2, nil
				}
				copy(bytes, p)
				return len(p), nil
			},
		}, nil
	}

	conn := newPooledConn(remoteAddr, remotePort)
	responseMsg.Id = conn.GetFreeMessageID()

	if err := conn.DialOnce(time.Second); err != nil {
		t.Fatalf("Expected dial to succeed, got %v", err)
	}

	if err := conn.WriteMessage(new(dns.Msg).SetQuestion("test.com.", 1), time.Second); err != nil {
		t.Fatalf("Expected write to succeed, got %v", err)
	}

	time.AfterFunc(500*time.Millisecond, func() {
		conn.ReadMessage(time.Now().Add(time.Minute))
	})

	start := time.Now()
	conn.Close(context.Background(), time.Second)
	duration := time.Since(start)

	if 450*time.Millisecond > duration || duration > 550*time.Millisecond {
		t.Errorf("Expected CloseWithGracePeriod to last approximately 500ms, got %v", duration)
	}
	if closeCalls != 1 {
		t.Errorf("Expected 1 call to close, got %v", closeCalls)
	}
}

func TestPooledTCPConn_CloseWithGracePeriod_Timeout(t *testing.T) {
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	remoteAddr := new(test.MockAddr).NewRandom()
	remotePort := uint16(332)
	expectedTimeout := 300 * time.Millisecond
	closeCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return test.MockConn{
			CloseFunc: func() error {
				closeCalls++
				return nil
			},
			WriteFunc: func(bytes []byte) (int, error) {
				return len(bytes), nil
			},
		}, nil
	}

	conn := newPooledConn(remoteAddr, remotePort)
	responseMsg.Id = conn.GetFreeMessageID()

	if err := conn.DialOnce(time.Second); err != nil {
		t.Fatalf("Expected dial to succeed, got %v", err)
	}

	if err := conn.WriteMessage(new(dns.Msg).SetQuestion("test.com.", 1), time.Second); err != nil {
		t.Fatalf("Expected write to succeed, got %v", err)
	}

	start := time.Now()
	conn.Close(context.Background(), expectedTimeout)
	duration := time.Since(start)

	if expectedTimeout-50*time.Millisecond > duration || duration > expectedTimeout+50*time.Millisecond {
		t.Errorf("Expected CloseWithGracePeriod to last approximately %v, got %v", expectedTimeout, duration)
	}
	if closeCalls != 1 {
		t.Errorf("Expected 1 call to close, got %v", closeCalls)
	}
}

func TestEphemeralTCPConn_GracePeriod_ReturnsImmediatelyIfFaulty(t *testing.T) {
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	remoteAddr := new(test.MockAddr).NewRandom()
	remotePort := uint16(332)
	expectedTimeout := 300 * time.Millisecond

	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return test.MockConn{
			WriteFunc: func(bytes []byte) (int, error) {
				return len(bytes), nil
			},
		}, nil
	}

	conn := newPooledConn(remoteAddr, remotePort)
	responseMsg.Id = conn.GetFreeMessageID()

	if err := conn.DialOnce(time.Second); err != nil {
		t.Fatalf("Expected dial to succeed, got %v", err)
	}

	if err := conn.WriteMessage(new(dns.Msg).SetQuestion("test.com.", 1), time.Second); err != nil {
		t.Fatalf("Expected write to succeed, got %v", err)
	}

	conn.Close(context.Background(), expectedTimeout)

	start := time.Now()
	conn.Close(context.Background(), expectedTimeout)
	duration := time.Since(start)

	if time.Millisecond < duration {
		t.Errorf("Expected second Close() to return immediately")
	}
}

func TestPooledTCPConn_CloseWithGracePeriod_WriteFails(t *testing.T) {
	responseMsg := new(dns.Msg).SetQuestion("the.response.com.", 1)
	remoteAddr := new(test.MockAddr).NewRandom()
	remotePort := uint16(332)
	writeCalls := 0
	dialFunc = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return test.MockConn{
			WriteFunc: func(bytes []byte) (int, error) {
				writeCalls++
				return len(bytes), nil
			},
		}, nil
	}

	conn := newPooledConn(remoteAddr, remotePort)
	responseMsg.Id = conn.GetFreeMessageID()

	if err := conn.DialOnce(time.Second); err != nil {
		t.Fatalf("Expected dial to succeed, got %v", err)
	}

	if err := conn.WriteMessage(new(dns.Msg).SetQuestion("test.com.", 1), time.Second); err != nil {
		t.Fatalf("Expected write to succeed, got %v", err)
	}

	go conn.Close(context.Background(), time.Second)

	time.Sleep(10 * time.Millisecond) // Allow go routine above to start
	err := conn.WriteMessage(new(dns.Msg).SetQuestion("test.com.", 1), time.Second)

	if writeCalls != 1 {
		t.Errorf("Expected only one message to be written to the wire, got %v", writeCalls)
	}

	if !errors.Is(err, client.ErrGracePeriodBegun) {
		t.Errorf("Expected error to indicate that grace period has begun, got %v", err)
	}
}
