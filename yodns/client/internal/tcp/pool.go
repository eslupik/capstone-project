package tcp

import (
	"context"
	"github.com/jellydator/ttlcache/v3"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

const (
	// KeepAliveTimeFactor is a factor for the duration specified in the TCP keepalive.
	// RFC7828 TCP keepalive is specified in units of 100ms
	KeepAliveTimeFactor = 100 * time.Millisecond
)

// Pool manages pooling and closing of TCP connections.
//
// For efficient use of TCP connections we need to consider multiple things:
//  1. Optimally, TCP connections should stay open and be used for multiple requests (rfc7766) for performance
//  2. We need to be nice to the servers - do not open hundreds of connections to them in parallel
//  3. Servers may close the TCP connections at any time, e.g. because long-open connections can be a potential vector for DOS attacks
//  4. In the past, connections were usually used for a single request. Some servers may still behave that way and drop the connection after the first request.
//
// Our strategy is as follows
//   - We have pooled connections (GetOrCreate) for case (1).
//     A pooled connection may be used by the client concurrently to send multiple requests without waiting for responses.
//   - If a pooled connections is closed (e.g. forcibly closed by remote host or EOF), multiple outstanding requests could be left unanswered
//   - We cannot really distinguish between (3) and (4), therefore we do the following:
//   - Each unanswered request is send via an ephemeral (one-time) connection (CreateEphemeral).
//   - The pooled connection is marked as unresponse (Discard)
//   - The next time we need to send the server a request, a new pooled connection is created again (and we start from the beginning)
//
// Relevant excerpts from RFCs
//
//	To mitigate the risk of unintentional server overload, DNS clients
//	MUST take care to minimize the number of concurrent TCP connections
//	made to any individual server.  It is RECOMMENDED that for any given
//	client/server interaction there SHOULD be no more than one connection
//	for regular queries [...] (RFC7766)
type Pool struct {

	// closeWithRST toggles whether tcp connections are closed gracefully.
	// If false (default), connections are closed via RST signal (disgraceful)
	// If true, are closed via the FIN signal and the connection will end up in TIME_WAIT state.
	// RFC1035: Since the server would be unable to answer queries anyway, a unilateral close or reset may be used instead of a graceful close.
	closeWithRST bool

	// idlePeriod is the time that idle TCP connections are kept in the pool.
	// After expiring, connections are removed from the pool and closed.
	// Using the tcp-keepalive mechanism the idlePeriod can be overwritten for individual connections.
	idlePeriod time.Duration

	// dialTimeout is the timeout when establishing TCP connections.
	dialTimeout time.Duration

	// acquireTimeout is the timeout that controls the time that the pool is waiting for a free spot for an open connection.
	// It comes into play, when either the ephemeralConns or the maxConnsPerServer is reached
	// and the pool has to wait until it is allowed to open a new connection.
	acquireTimeout time.Duration

	// gracePeriod is the time that the pool waits when terminating a connection according to rfc 7828.
	// After the server sends a keep-alive of 0, we wait for the gracePeriod until closing the connection.
	// This allows us to receive open queries. Consider using the tcp receiveTimeout here.
	gracePeriod time.Duration

	// connectionsMu synchronizes access to connections
	connectionsMu sync.RWMutex

	// connections is the cache holding active connections .
	connections *ttlcache.Cache[string, *PooledConn]

	// ephemeralConns controls the total (ephemeral) number of open tcp connections
	ephemeralConns *semaphore.Weighted

	// poolSize holds the number of current entries in the pool
	maxPoolSize int
}

// NewTCPPool initializes a new TCP connection pool
func NewTCPPool(idlePeriod time.Duration,
	dialTimeout time.Duration,
	acquireTimeout time.Duration,
	gracePeriod time.Duration,
	poolSize uint16,
	maxEphemeralConns uint16) *Pool {
	// RFC7766:
	// To mitigate the risk of unintentional server overload, it is
	// RECOMMENDED that the default server application-level idle period be
	// on the order of seconds.
	// For now, we enforce this recommendation
	if idlePeriod > time.Minute {
		panic("Idle period should be in the order of seconds")
	}

	pool := Pool{
		closeWithRST:   true,
		idlePeriod:     idlePeriod,
		dialTimeout:    dialTimeout,
		ephemeralConns: semaphore.NewWeighted(int64(maxEphemeralConns)),
		maxPoolSize:    int(poolSize),
		acquireTimeout: acquireTimeout,
		gracePeriod:    gracePeriod,

		// If capacity is reached, ttlcache evicts based on a LRU policy.
		connections: ttlcache.New(ttlcache.WithTTL[string, *PooledConn](idlePeriod)),
	}

	pool.connections.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[string, *PooledConn]) {
		// Unfortunately, there is a bug in the library where the cache.Set() method does not update the
		// TTL of an item if the new value is lower than the old (important feature for edns0-tcp-keepalive)
		// So to achieve this, we have to delete and set. Consequently, we cannot start closing the connection on delete,
		// because it might be just a reinsert to update the TTL. If we want to delete the conn for good, we have to call deleteWithClose()
		if reason == ttlcache.EvictionReasonDeleted {
			return
		}

		// Case: Eviction by expiry
		// This may keep TCP connections open for a bit after removal from the pool
		// This means that for a short period of time, more TCP connections can be open than specified by the poolSize
		i.Value().Close(ctx, gracePeriod)
	})

	return &pool
}

func (pool *Pool) Start(ctx context.Context) {
	go pool.connections.Start()
	<-ctx.Done()
	pool.connections.Stop()
}

// GetOrCreate retrieves a connection to the specified Conn and port from the pool or opens a new one, if no connection is available.
func (pool *Pool) GetOrCreate(remoteIP client.Address, remotePort uint16, onReceive ReceiveCallback) (*PooledConn, error) {
	ipWithPort := internal.FormatWithPort(remoteIP, remotePort)

	// Check
	if entry := pool.connections.Get(ipWithPort); entry != nil {
		conn := entry.Value()

		if err := conn.DialOnce(pool.dialTimeout); err != nil {
			return nil, client.ErrDial.Wrap(err)
		}

		return conn, nil
	}

	// Lock
	pool.connectionsMu.Lock()

	// Check
	if entry := pool.connections.Get(ipWithPort); entry != nil {
		pool.connectionsMu.Unlock()
		conn := entry.Value()

		if err := conn.DialOnce(pool.dialTimeout); err != nil {
			return nil, client.ErrDial.Wrap(err)
		}

		return conn, nil
	}

	// If the pool is exhausted, we return an error.
	if pool.connections.Len() >= pool.maxPoolSize {
		pool.connectionsMu.Unlock()
		client.Metrics.TCPPoolExhausted.Inc()

		return nil, client.ErrPoolExhausted
	}

	newConn := newPooledConn(remoteIP, remotePort)
	newConn.closeWithRST = pool.closeWithRST
	newConn.onClose = func() {
		pool.delete(internal.FormatWithPort(newConn.DestinationIP, newConn.DestinationPort))
		client.Metrics.ClosePooledTCPConn()
	}

	pool.connections.Set(ipWithPort, newConn, pool.idlePeriod)

	// Make sure DialOnce is outside the mutex scope
	pool.connectionsMu.Unlock()

	// For the purpose of this metric, connections "in-dialing" count as open
	// When changing this, we have to take check that the connection was actually open at some point when decreasing the counter again.
	client.Metrics.OpenPooledTCPConn()
	if err := newConn.DialOnce(pool.dialTimeout); err != nil {
		return nil, client.ErrDial.Wrap(err)
	}

	err := newConn.StartReceiving(func(conn *PooledConn, msg *dns.Msg, s string, err error) {
		// We inject this before the actual callback to update the keepalive in the pool if edns0-tcp-keepalive is used
		if err == nil {
			pool.updateKeepAlive(conn, msg)
		}

		if onReceive != nil {
			onReceive(conn, msg, s, err)
		}
	})

	return newConn, err
}

// CreateEphemeral creates a new connection
func (pool *Pool) CreateEphemeral(remoteIP client.Address, remotePort uint16) (*PooledConn, error) {
	ctx, cncl := context.WithTimeout(context.Background(), pool.acquireTimeout)
	defer cncl()

	if err := pool.ephemeralConns.Acquire(ctx, 1); err != nil { // Ensure we are allowed to open a connection
		client.Metrics.TCPPoolEphemeralExhausted.Inc()
		return nil, client.ErrEphemeralExhausted
	}

	releaseOnce := sync.Once{}
	conn := newPooledConn(remoteIP, remotePort)
	conn.closeWithRST = pool.closeWithRST
	conn.onClose = func() {
		client.Metrics.CloseEphemeralTCPConn()
		releaseOnce.Do(func() { pool.ephemeralConns.Release(1) })
	}

	if err := conn.DialOnce(pool.dialTimeout); err != nil {
		releaseOnce.Do(func() { pool.ephemeralConns.Release(1) })
		return nil, err
	}

	client.Metrics.OpenEphemeralTCPConn()
	return conn, nil
}

func (pool *Pool) updateKeepAlive(conn *PooledConn, msg *dns.Msg) {
	opt := msg.IsEdns0()

	// From RFC7828
	// A DNS client that sent a query containing the edns-keepalive-option
	// but receives a response that does not contain the edns-keepalive-
	// option SHOULD assume the server does not support keepalive and behave
	// following the guidance in [RFC7766]. This holds true even if a
	// previous edns-keepalive-option exchange occurred on the existing TCP
	// connection.
	if opt == nil {
		return // Will be automatically extended by the default idleTimeout
	}
	keepAlive := getKeepaliveOpt(opt)
	if keepAlive == nil {
		return // Will be automatically extended by the default idleTimeout
	}

	key := internal.FormatWithPort(conn.DestinationIP, conn.DestinationPort)

	// From RFC7828
	// A DNS client that receives a response that includes the edns-tcp-
	// keepalive option with a TIMEOUT value of 0 SHOULD send no more
	// queries on that connection and initiate closing the connection as
	// soon as it has received all outstanding responses.
	if keepAlive.Timeout == 0 {
		pool.deleteWithClose(key)
	}

	// From RFC7828
	// A DNS client that receives a response using TCP transport that
	// includes the edns-tcp-keepalive option MAY keep the existing TCP
	// session open when it is idle. It SHOULD honour the timeout received
	// in that response (overriding any previous timeout) and initiate close
	// of the connection before the timeout expires.

	// Just setting (without deleting first) does only seem to update the TTL if the
	// new TTL is larger than the previous one. Delete and Set makes sure the TTL is used.
	// Could be a bug in the ttlcache library.
	newTTL := KeepAliveTimeFactor * time.Duration(keepAlive.Timeout)
	newTTL -= KeepAliveTimeFactor // From RFC7828: and initiate close of the connection >>>>BEFORE<<<< the timeout expires.
	if newTTL < 0 {
		newTTL = 0
	}

	pool.connectionsMu.Lock()
	pool.connections.Delete(key)
	pool.connections.Set(key, conn, newTTL)
	pool.connectionsMu.Unlock()
}

func (pool *Pool) deleteWithClose(key string) {
	pool.connectionsMu.Lock()
	i := pool.connections.Get(key)
	pool.connections.Delete(key)
	pool.connectionsMu.Unlock()

	if i != nil && i.Value() != nil {
		// This may keep TCP connections open for a bit after removal from the pool
		// This means that for a short period of time, more TCP connections can be open than specified by the poolSize
		go func() {
			i.Value().Close(context.Background(), pool.gracePeriod)
		}()
	}
}

func (pool *Pool) delete(key string) {
	pool.connectionsMu.Lock()
	pool.connections.Delete(key)
	pool.connectionsMu.Unlock()
}

func getKeepaliveOpt(opt *dns.OPT) *dns.EDNS0_TCP_KEEPALIVE {
	for _, edns0 := range opt.Option {
		if edns0.Option() == dns.EDNS0TCPKEEPALIVE {
			if keepAliveOption, ok := edns0.(*dns.EDNS0_TCP_KEEPALIVE); ok {
				return keepAliveOption
			}
		}
	}
	return nil
}
