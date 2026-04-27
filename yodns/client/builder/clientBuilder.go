package builder

// builder has separate package because it references basically everything and we don't want import cycles.

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/internal"
	"github.com/DNS-MSMT-INET/yodns/client/internal/tcp"
	"github.com/DNS-MSMT-INET/yodns/client/internal/udp"
	"math"
	"net"
	"time"
)

const (
	defaultUDPTimeout          = 5 * time.Second
	defaultAcquireTimeout      = 2 * time.Second
	defaultTCPTimeout          = 5 * time.Second
	defaultTCPDialTimeout      = 5 * time.Second
	defaultTCPIdleTimeout      = 30 * time.Second
	defaultRateLimitingTimeout = 60 * time.Second
	defaultEDNSBufferSize      = 1232 // Why 1232? => http://www.dnsflagday.net/2020/
)

// Builder is used to initialize new DNS clients.
type Builder struct {
	maxInflightPerIP         int64
	maxQueriesPerSecondPerIP int64
	metricsReg               *prometheus.Registerer

	messageBufferSize uint

	tcpPoolSize       uint16
	tcpEphemeralConns uint16
	udpPoolSize       uint16
	ednsBufferSize    uint16

	log zerolog.Logger

	localIPV4 net.IP
	localIPV6 net.IP

	tcpTimeout          time.Duration
	tcpAcquireTimeout   time.Duration
	tcpDialTimeout      time.Duration
	tcpIdleTimeout      time.Duration
	tcpKeepAlive        time.Duration
	rateLimitingTimeout time.Duration
	useTCPKeepAlive     bool

	udpTimeout time.Duration
}

// WithRateLimiting enables rate-limiting for the DNS client.
//
//   - maxInflightPerIP is the maximum allowed number of inflight queries per IP address.
//   - maxQueriesPerSecondPerIP is the maximum query rate of per second IP address.
//   - timeout is the maximum time that a request can be delayed by the rate limiter. After this time, the request will be returned as timeout.
func (builder Builder) WithRateLimiting(maxInflightPerIP int64, maxQueriesPerSecondPerIP int64, timeout time.Duration) Builder {
	builder.maxInflightPerIP = maxInflightPerIP
	builder.maxQueriesPerSecondPerIP = maxQueriesPerSecondPerIP
	builder.rateLimitingTimeout = timeout

	return builder
}

// RegisterMetrics adds the clients exported metrics to the provided registerer.
func (builder Builder) RegisterMetrics(reg *prometheus.Registerer) Builder {
	builder.metricsReg = reg
	return builder
}

// WithTimeout sets the timeout for udp and tcp queries to the specified duration
// Will overwrite WithTCPTimeout and WithUDPTimeout
func (builder Builder) WithTimeout(timeout time.Duration) Builder {
	builder.tcpTimeout = timeout
	builder.udpTimeout = timeout

	return builder
}

// WithTCPTimeout sets the timeout for tcp queries to the specified duration
// Will overwrite previous calls to WithTimeout
func (builder Builder) WithTCPTimeout(timeout time.Duration) Builder {
	builder.tcpTimeout = timeout
	return builder
}

// UseTCPKeepAlive enables or disables usage of the EDNS0 extension for TCP Keepalive (RFC7828)
func (builder Builder) UseTCPKeepAlive(useKeepAlive bool) Builder {
	builder.useTCPKeepAlive = useKeepAlive
	return builder
}

// WithTCPDialTimeout sets the timeout for dialing a tcp connection to the specified duration
func (builder Builder) WithTCPDialTimeout(timeout time.Duration) Builder {
	builder.tcpDialTimeout = timeout
	return builder
}

// WithTCPIdlePeriod sets the time that idle TCP connections are kept in the pool.
// After idling for this period, connections are removed from the pool and closed.
// Using the tcp-keepalive mechanism the idlePeriod can be overwritten for individual connections.
func (builder Builder) WithTCPIdlePeriod(timeout time.Duration) Builder {
	builder.tcpIdleTimeout = timeout
	return builder
}

// WithTCPPoolSize sets the maximum number of connections that are kept in the pool.
func (builder Builder) WithTCPPoolSize(tcpPoolSize uint16) Builder {
	builder.tcpPoolSize = tcpPoolSize
	return builder
}

// WithTCPEphemeralConns sets the maximum number of ephemeral connections that can be opened in parallel.
// An ephemeral connection is a connection that is not kept in the TCP pool and is closed after the query is done.
func (builder Builder) WithTCPEphemeralConns(tcpEphemeralConns uint16) Builder {
	builder.tcpEphemeralConns = tcpEphemeralConns
	return builder
}

// WithUDPTimeout sets the timeout for udp queries to the specified duration
// Will overwrite previous calls to WithTimeout
func (builder Builder) WithUDPTimeout(timeout time.Duration) Builder {
	builder.udpTimeout = timeout
	return builder
}

// WithUDPPoolSize sets the maximum number of allocated UPD sockets that are kept in the pool.
func (builder Builder) WithUDPPoolSize(udpPoolSize uint16) Builder {
	builder.udpPoolSize = udpPoolSize
	return builder
}

// WithLogger adds the specified logger to the client.
func (builder Builder) WithLogger(log zerolog.Logger) Builder {
	builder.log = log
	return builder
}

// WithLocalIPs configures the local IP addresses that will be used by the client.
// IP addresses can be null, if no IPv4 (IPv6) connectivity is desired.
func (builder Builder) WithLocalIPs(ipv4 net.IP, ipv6 net.IP) Builder {
	builder.localIPV4 = ipv4
	builder.localIPV6 = ipv6
	return builder
}

// WithEDNSBufferSize sets the EDNS0 buffer size that is used for requests.
// Default is 1232 bytes (http://www.dnsflagday.net/2020/)
func (builder Builder) WithEDNSBufferSize(size uint16) Builder {
	builder.ednsBufferSize = size
	return builder
}

// Build initializes and starts the client
// Associated go-routines will be stopped if ctx is cancelled
func (builder Builder) Build(ctx context.Context) client.DNSClient {
	builder = builder.fillDefaults().verify()

	if builder.metricsReg != nil {
		client.RegisterMetrics(*builder.metricsReg)
	}

	var udpPoolV4 udp.ConnFactory
	if builder.localIPV4 != nil {
		udpPoolV4 = udp.NewPool(builder.localIPV4, builder.ednsBufferSize, builder.udpPoolSize)
	}

	var udpPoolV6 udp.ConnFactory
	if builder.localIPV6 != nil {
		udpPoolV6 = udp.NewPool(builder.localIPV6, builder.ednsBufferSize, builder.udpPoolSize)
	}

	udpClient := udp.NewClient(udpPoolV4, udpPoolV6, builder.udpTimeout, builder.ednsBufferSize)

	tcpPool := tcp.NewTCPPool(builder.tcpIdleTimeout,
		builder.tcpDialTimeout,
		builder.tcpAcquireTimeout,
		builder.tcpTimeout, // We use the receive-timeout as grace period
		builder.tcpPoolSize,
		builder.tcpEphemeralConns)
	go tcpPool.Start(ctx)

	tcpClient := tcp.NewClient(tcpPool, builder.tcpTimeout, builder.tcpKeepAlive)

	var innerClient client.DNSClientDecorator = internal.NewReusingClient(udpClient, tcpClient).Start(ctx)

	if builder.maxInflightPerIP > 0 || builder.maxQueriesPerSecondPerIP > 0 {
		innerClient = internal.
			NewClient(innerClient, builder.maxQueriesPerSecondPerIP, builder.maxInflightPerIP, builder.rateLimitingTimeout, builder.log).
			Start(ctx)
	}

	return client.DNSClient{
		Inner: innerClient,
	}
}

func (builder Builder) fillDefaults() Builder {
	if builder.tcpTimeout == 0 {
		builder.tcpTimeout = defaultTCPTimeout
	}

	if builder.udpTimeout == 0 {
		builder.udpTimeout = defaultUDPTimeout
	}

	if builder.tcpAcquireTimeout == 0 {
		builder.tcpAcquireTimeout = defaultAcquireTimeout
	}

	if builder.tcpDialTimeout == 0 {
		builder.tcpDialTimeout = defaultTCPDialTimeout
	}

	if builder.tcpIdleTimeout == 0 {
		builder.tcpIdleTimeout = defaultTCPIdleTimeout
	}

	if builder.rateLimitingTimeout == 0 {
		builder.rateLimitingTimeout = defaultRateLimitingTimeout
	}

	if builder.ednsBufferSize == 0 {
		builder.ednsBufferSize = defaultEDNSBufferSize
	}

	if builder.useTCPKeepAlive {
		builder.tcpKeepAlive = builder.tcpIdleTimeout
	}

	return builder
}

func (builder Builder) verify() Builder {
	if uint(builder.udpPoolSize)+uint(builder.tcpPoolSize)+uint(builder.tcpEphemeralConns) > math.MaxUint16 {
		panic("Number of allowed connections exceeds maximum number of ports on a machine")
	}

	if builder.localIPV4 == nil && builder.localIPV6 == nil {
		panic("No local IP addresses were provided")
	}

	return builder
}
