package cache

import (
	"context"
	"encoding/json"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"sync"
	"time"
)

// RTTEstimator is the function used by the InfraCache to estimate the RTT
var RTTEstimator = func(oldEstimate time.Duration, sampleRTT time.Duration) time.Duration {
	// exponential moving average
	return time.Duration(0.875*float64(oldEstimate) + 0.125*float64(sampleRTT))
}

// Make sure the interface is implemented.
var _ resolver.InfraCache = new(InfraCache)

// InfraCache caches statistics per IP to determine if name servers are responsive.
// Loosely inspired by this: https://unbound.docs.nlnetlabs.nl/en/latest/reference/history/info-timeout-server-selection.html
type InfraCache struct {
	innerCache   *ttlcache.Cache[netip.Addr, *infraEntry]
	innerCacheMu sync.Mutex

	cancelOnEviction func()

	log zerolog.Logger

	// ttl is the time that an entry remains in the cache.
	ttl time.Duration

	// Backoff implements the strategy for determining Backoff intervals
	// if servers are not responsive (e.g. exponential Backoff)
	Backoff Backoff

	// initialRTTEstimate is the initial value used for the rtt estimate.
	initialRTTEstimate time.Duration

	// dumpWriter is the writer used for writing evicted entries
	dumpWriter io.Writer

	// dumpWriterMu synchronizes access to dumpWriter because
	// io.Writer is not necessarily thread-safe
	dumpWriterMu sync.Mutex

	// deadServerThreshold is the number of unresponsive queries after which a server is considered dead
	// iff there is not at least one responsive query in the history.
	deadServerThreshold int
}

type infraEntry struct {
	IP netip.Addr

	LastUDPDeadServerIndication time.Time
	NrUDPDeadServerIndications  int

	LastTCPDeadServerIndication time.Time
	NrTCPDeadServerIndications  int

	MarkedUnresponsive bool
	UnresponsiveReason string
	RTTEstimate        time.Duration
	Mu                 sync.RWMutex `json:"-"`
	LastBackOffUpdate  time.Time
	NextBackoff        time.Duration

	CreatedDate time.Time
	// TODO Future Ideas:
	// Add EDNS0-responsiveness
	// Add an estimate for the RTT variance
	// Using RTT and RTT variance, we can dynamically set timeouts (e.g. RTT + 4*RTTVar)
}

func NewInfraCache(ttl time.Duration, capacity uint64, backoff Backoff, log zerolog.Logger) *InfraCache {
	inner := ttlcache.New(
		ttlcache.WithDisableTouchOnHit[netip.Addr, *infraEntry](),
		ttlcache.WithCapacity[netip.Addr, *infraEntry](capacity))

	inner.OnInsertion(func(ctx context.Context, i *ttlcache.Item[netip.Addr, *infraEntry]) {
		Metrics.InfraSize.Inc()
	})
	inner.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[netip.Addr, *infraEntry]) {
		Metrics.InfraSize.Dec()
	})

	result := InfraCache{
		log:                 log,
		ttl:                 ttl,
		innerCache:          inner,
		initialRTTEstimate:  400 * time.Millisecond,
		Backoff:             backoff,
		deadServerThreshold: 4,
	}

	return &result
}

func (c *InfraCache) Start() {
	c.innerCache.Start()
}

func (c *InfraCache) Stop() {
	// OnEviction will not be called anymore
	c.innerCache.Stop()

	// If a writer is registered, dump the remaining items.
	if c.dumpWriter != nil {
		for _, item := range c.innerCache.Items() {
			c.dumpEntry(item.Value())
		}
	}
}

// GetBackoff returns the recommended Backoff interval for the name server.
// The duration is calculated according to the provided Backoff strategy
// and a random jitter is added.
//
// If more message exchanges to the IP fail, Backoff intervals will be increased.
// If messages are exchanged successfully backoffs are decreased.
func (c *InfraCache) GetBackoff(nsIP netip.Addr) time.Duration {
	entry := c.getOrCreate(nsIP)
	entry.Mu.RLock()
	defer entry.Mu.RUnlock()

	backOff := float64(entry.NextBackoff)
	backOff += float64(rand.Int31n(200) - 100)                 // Add -100 to 100ms jitter
	backOff = backOff * (105 - float64(rand.Int31n(10))) / 100 // Add up to +-5% jitter on top
	backOff = math.Max(0, backOff)
	backOffDur := time.Duration(backOff)

	Metrics.InfraBackoffs.Observe(backOffDur.Seconds())
	return backOffDur
}

// IsResponsive returns information about the responsiveness of the name server
//
// isUDPResponsive is false, if at least 5 UDP queries were sent, and none of them received a response OR if MarkUnresponsive was called
// isTCPResponsive is false, if at least 5 TCP queries were sent, and none of them received a response OR if MarkUnresponsive was called
// reason may contain additional information, e.g. reasons provided by the MarkUnresponsive function
func (c *InfraCache) IsResponsive(nsIP netip.Addr) (udpResponsive bool, tcpResponsive bool, reason string) {
	entry := c.getOrCreate(nsIP)
	entry.Mu.RLock()
	defer entry.Mu.RUnlock()

	udpResponsive = !entry.MarkedUnresponsive && entry.NrUDPDeadServerIndications < c.deadServerThreshold
	tcpResponsive = !entry.MarkedUnresponsive && entry.NrTCPDeadServerIndications < c.deadServerThreshold
	reason = entry.UnresponsiveReason
	return
}

// MarkUnresponsive marks the specified IP as unresponsive for the
// default time-to-live of the cache. If an entry for this IP already
// exists, it is overwritten.
func (c *InfraCache) MarkUnresponsive(nsIP netip.Addr, reason string) {
	c.innerCacheMu.Lock()
	c.innerCache.Set(nsIP, &infraEntry{
		IP:                 nsIP,
		MarkedUnresponsive: true,
		UnresponsiveReason: reason,
		CreatedDate:        time.Now(),
	}, c.ttl)
	c.innerCacheMu.Unlock()
}

// Track updates the cache according to the message exchange information
// that is provided. Statistics (like the RTT estimate) are updated,
// and Backoff intervals are increased (or decreased), depending on the
// success of the exchange.
// For ease of use (and performance), the new server status is returned
func (c *InfraCache) Track(msg model.MessageExchange) {
	val := c.getOrCreate(msg.NameServerIP)

	val.Mu.Lock()
	defer val.Mu.Unlock()

	now := time.Now()
	// Track UDP responsiveness
	if !msg.Metadata.TCP {
		if msg.Error != nil &&
			now.After(val.LastUDPDeadServerIndication.Add(5*time.Second)) {
			val.LastUDPDeadServerIndication = now
			val.NrUDPDeadServerIndications++
		} else if msg.Error == nil {
			val.LastUDPDeadServerIndication = now
			val.NrUDPDeadServerIndications = common.MaxInt(val.NrUDPDeadServerIndications-1, 0)
		}
	}

	// Track TCP responsiveness
	if msg.Metadata.TCP {
		if msg.Error != nil &&
			now.After(val.LastTCPDeadServerIndication.Add(5*time.Second)) {
			val.LastTCPDeadServerIndication = now
			val.NrTCPDeadServerIndications++
		} else if msg.Error == nil {
			val.LastTCPDeadServerIndication = now
			val.NrTCPDeadServerIndications = common.MaxInt(val.NrTCPDeadServerIndications-1, 0)
		}
	}

	// Update RTT estimate
	val.RTTEstimate = RTTEstimator(val.RTTEstimate, msg.Metadata.RTT)

	// Only increase the Backoff if the query that was received was sent
	// AFTER the last update. This prevents the situation where n inflight
	// queries all timeout and effectively increase the Backoff n times
	if msg.Error != nil && msg.Metadata.EnqueueTime.After(val.LastBackOffUpdate) {
		val.NextBackoff = c.Backoff.Increase(val.NextBackoff)
		val.LastBackOffUpdate = time.Now()
	}

	// Decreasing the Backoff is always possible
	if msg.Error == nil {
		val.NextBackoff = c.Backoff.Decrease(val.NextBackoff)
		val.LastBackOffUpdate = time.Now()
	}
}

// DumpTo register a handler that writes evicted cache entries to the specified output.
// On Stop, all remaining entries will also be written to the writer.
func (c *InfraCache) DumpTo(writer io.Writer) {
	if writer == nil {
		return
	}
	c.innerCacheMu.Lock()
	defer c.innerCacheMu.Unlock()

	c.dumpWriter = writer
	c.cancelOnEviction = c.innerCache.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[netip.Addr, *infraEntry]) {
		c.dumpEntry(i.Value())
	})
}

func (c *InfraCache) dumpEntry(entry *infraEntry) {
	bytes, err := json.Marshal(entry)
	if err != nil {
		c.log.Err(err).Msgf("infra cache entry expired")
	}

	c.dumpWriterMu.Lock()
	if _, err = c.dumpWriter.Write(bytes); err != nil {
		c.log.Err(err).Msgf("dumped infra cache entry")
	}
	if _, err = c.dumpWriter.Write([]byte("\r\n")); err != nil {
		c.log.Err(err).Msgf("dumped infra cache entry")
	}
	c.dumpWriterMu.Unlock()
}

func (c *InfraCache) getOrCreate(key netip.Addr) *infraEntry {
	// Check
	entry := c.innerCache.Get(key)
	if entry != nil {
		return entry.Value()
	}

	// Lock
	c.innerCacheMu.Lock()
	defer c.innerCacheMu.Unlock()

	// Check
	if entry = c.innerCache.Get(key); entry != nil {
		return entry.Value()
	}

	// Act
	entry = c.innerCache.Set(key, &infraEntry{
		IP:          key,
		RTTEstimate: c.initialRTTEstimate,
		NextBackoff: c.Backoff.Initial(),
		CreatedDate: time.Now(),
	}, c.ttl)
	return entry.Value()
}
