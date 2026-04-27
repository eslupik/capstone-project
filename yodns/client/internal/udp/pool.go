package udp

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/client"
	"net"
	"sync/atomic"
	"time"
)

type Pool struct {
	localIP        net.IP
	udpSize        uint16
	connCount      int32
	maxSize        int32
	connQueue      chan *PooledConn
	acquireTimeout time.Duration
}

var dialFunc = func(localIp net.IP) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIp, Port: 0, Zone: ""})
	if err != nil {
		return nil, client.ErrDial.Wrap(err)
	}
	return conn, nil
}

func NewPool(localIP net.IP, udpSize uint16, poolSize uint16) *Pool {
	if localIP == nil {
		panic("localIP must not be nil")
	}

	if udpSize < dns.MinMsgSize {
		panic(fmt.Sprintf("udp packet size must be at least %v byte", dns.MinMsgSize))
	}

	p := &Pool{
		localIP:        localIP,
		udpSize:        udpSize,
		maxSize:        int32(poolSize),
		connCount:      0,
		connQueue:      make(chan *PooledConn, poolSize),
		acquireTimeout: time.Second,
	}

	return p
}

func (pool *Pool) GetOrCreate(onReceive ReceiveCallback) (*PooledConn, error) {
	if atomic.AddInt32(&pool.connCount, 1) <= pool.maxSize {
		conn, err := createConn(pool.localIP, pool.udpSize, onReceive)
		if err != nil {
			atomic.AddInt32(&pool.connCount, -1)
			return nil, err
		}

		pool.connQueue <- conn // move to end of queue

		return conn, nil
	}

	// remove what we added above, the pool is already full
	atomic.AddInt32(&pool.connCount, -1)

	select {
	case <-time.After(pool.acquireTimeout):
		return nil, client.ErrPoolExhausted
	case conn := <-pool.connQueue:
		if conn.IsFaulty() { // The faulty connection is not put back into the queue
			atomic.AddInt32(&pool.connCount, -1)
			return pool.GetOrCreate(onReceive)
		}

		pool.connQueue <- conn // Move conn to back of the queue again

		return conn, nil
	}
}

func createConn(localIp net.IP, udpSize uint16, onReceive ReceiveCallback) (*PooledConn, error) {
	udpConn, err := dialFunc(localIp)
	if err != nil {
		return nil, client.ErrDial.Wrap(err)
	}

	pc := newPooledUDPConn(udpSize, localIp.To4() == nil, udpConn)
	pc.StartReceiving(onReceive)

	return pc, nil
}
