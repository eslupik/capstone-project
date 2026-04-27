package cache

import (
	"context"
	"encoding/gob"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

// DNSCache is used to cache DNS responses and dead server indications.
//
// Below are some relevant excerpts from RFCs. Some of them might not be unconditionally valid,
// since our tool is not a typical resolver.
//
// From rfc1035 Section 7.4:
//
// However, there are several types of data which should not be cached:
//
//   - When several RRs of the same type are available for a
//     particular owner name, the resolver should either cache them
//     all or none at all.  When a response is truncated, and a
//     resolver doesn't know whether it has a complete set, it should
//     not cache a possibly partial set of RRs.
//
//   - The results of standard queries where the QNAME contains "*"
//     labels if the data might be used to construct wildcards.  The
//     reason is that the cache does not necessarily contain existing
//     RRs or zone boundary information which is necessary to
//     restrict the application of the wildcard RRs.
//
//   - ...
//
// From rfc2181 Section 5.2:
//
//   - Resource Records also have a time to live (TTL).  It is possible for
//     the RRs in an RRSet to have different TTLs.  No uses for this have
//     been found that cannot be better accomplished in other ways.  This
//     can, however, cause partial replies (not marked "truncated") from a
//     caching server, where the TTLs for some but not all the RRs in the
//     RRSet have expired.
//     Consequently, the use of differing TTLs in an RRSet is hereby
//     de-pre-cated, the TTLs of all RRs in an RRSet must be the same.
//     Should a client receive a response containing [...] the
//     client should treat the RRs for all purposes as if all TTLs in the
//     RRSet had been set to the value of the lowest TTL in the RRSet. In
//     no case may a server send an RRSet with TTLs not all equal.
type DNSCache struct {
	innerCache *ttlcache.Cache[string, *Entry]
}

// Make sure the interface is implemented.
var _ resolver.QueryCache = new(DNSCache)

type Entry struct {
	Msg model.MessageExchange
}

type serializedCacheEntry struct {
	Key       string
	Msg       []byte
	ExpiresAt int64
}

func NewDNSCache(capacity uint64) *DNSCache {
	inner := ttlcache.New(ttlcache.WithDisableTouchOnHit[string, *Entry](), ttlcache.WithCapacity[string, *Entry](capacity))

	// If OnInsertion and OnEviction are too expensive, we can
	// just periodically poll inner.len and write it to the gauge.
	inner.OnInsertion(func(ctx context.Context, i *ttlcache.Item[string, *Entry]) {
		Metrics.Size.Inc()
	})
	inner.OnEviction(func(ctx context.Context, reason ttlcache.EvictionReason, i *ttlcache.Item[string, *Entry]) {
		Metrics.Size.Dec()
	})

	return &DNSCache{
		innerCache: inner,
	}
}

func (cache *DNSCache) Start() {
	cache.innerCache.Start()
}

func (cache *DNSCache) Stop() {
	cache.innerCache.Stop()
}

func (cache *DNSCache) Set(ex model.MessageExchange) {
	// Don't cache very large messages.
	//if ex.Message != nil && ex.Message.Len() > 8*1024 {
	//	Metrics.Discard.Inc()
	//	return
	//}

	ttl := getTTL(ex)
	key := getKey(ex.NameServerIP, ex.OriginalQuestion)
	ex.Metadata.FromCache = true
	cache.innerCache.Set(key, &Entry{
		Msg: ex,
	}, ttl)
}

func (cache *DNSCache) Get(ipAddress netip.Addr, q model.Question) (model.MessageExchange, bool) {
	key := getKey(ipAddress, q)
	if entry := cache.innerCache.Get(key); entry != nil {
		Metrics.Hits.Inc()
		msg := entry.Value().Msg
		return msg, true
	}

	Metrics.Misses.Inc()
	return model.MessageExchange{}, false
}

// DumpCacheAsBinary writes the contents of the cache to a file in binary format.
// You can pass notAfter in order to exclude items added after a certain time in order to go back to a safe and defined state.
func (cache *DNSCache) DumpCacheAsBinary(notAfter time.Time, writer io.Writer) error {
	enc := gob.NewEncoder(writer)
	for _, entry := range cache.innerCache.Items() {
		// Don't write expired items.
		if entry.IsExpired() {
			continue
		}

		// Don't write items that were added after 'notAfter'
		if entry.ExpiresAt().Add(-entry.TTL()).After(notAfter) {
			continue
		}

		serWrapper, err := wrapForSerialization(entry)
		if err != nil { // Skip this entry if it was faulty but keep dumping
			continue
		}

		// Usually not recoverable (closed file and such)
		if err := enc.Encode(serWrapper); err != nil {
			return err
		}
	}

	return nil
}

// LoadCacheFromBinary loads the content of a file serialized using DumpCacheAsBinary into the cache.
func (cache *DNSCache) LoadCacheFromBinary(reader io.Reader) error {

	dec := gob.NewDecoder(reader)

	var data serializedCacheEntry
	var err error
	for err = dec.Decode(&data); err == nil; err = dec.Decode(&data) {
		remainingTimeToLive := time.Until(time.Unix(data.ExpiresAt, 0))
		if remainingTimeToLive < 0 {
			continue // Don't load expired items.
		}

		var protoMsgEx protobuf.MessageExchange
		if err := proto.Unmarshal(data.Msg, &protoMsgEx); err != nil {
			continue
		}

		msgEx, err := protoMsgEx.ToModel()
		if err != nil {
			continue
		}

		cache.innerCache.Set(data.Key, &Entry{
			Msg: msgEx,
		}, remainingTimeToLive)
	}

	if err != io.EOF {
		return err
	}
	return nil
}

func wrapForSerialization(entry *ttlcache.Item[string, *Entry]) (serializedCacheEntry, error) {
	value := entry.Value()
	key := entry.Key()

	out := new(protobuf.MessageExchange)
	if err := out.From(&value.Msg); err != nil {
		return serializedCacheEntry{}, err
	}

	msgBytes, packErr := proto.MarshalOptions{}.Marshal(out)
	if packErr != nil {
		return serializedCacheEntry{}, packErr
	}

	return serializedCacheEntry{
		Key:       key,
		Msg:       msgBytes,
		ExpiresAt: entry.ExpiresAt().Unix(),
	}, nil
}

func getKey(ip netip.Addr, q model.Question) string {
	var builder strings.Builder
	builder.Write(ip.AsSlice())
	builder.WriteString(string(q.Name))
	builder.WriteString(strconv.Itoa(int(q.Class)))
	builder.WriteString(strconv.Itoa(int(q.Type)))
	return builder.String()
}

func getTTL(ex model.MessageExchange) time.Duration {

	// CHAOS responses (like version.bind.) responses often have no TTL -
	// nevertheless we don't want to spam servers with these, so we need caching
	if ex.OriginalQuestion.Class == dns.ClassCHAOS {
		return 15 * time.Minute
	}

	// rfc2308
	// A server MAY cache a dead server indication.  If it does so it MUST
	// NOT be deemed dead for longer than five (5) minutes.  The indication
	// MUST be stored against query tuple <query name, type, class, server
	// Conn address> unless there was a transport layer indication that the
	// server does not exist, in which case it applies to all queries to
	// that specific Conn address.
	if ex.Error != nil || ex.Message == nil {
		return 5 * time.Minute
	}

	// rfc2308
	// In either case a resolver MAY cache a server failure response.  If it
	// does so it MUST NOT cache it for longer than five (5) minutes, and it
	// MUST be cached against the specific query tuple <query name, type,
	// class, server Conn address.
	if ex.Message.Rcode == dns.RcodeServerFailure || ex.Message.Rcode == dns.RcodeRefused {
		return 5 * time.Minute
	}

	// We cache the whole message using the minimum TTL in the message.
	// This avoids problems that occur when caching by RRset - e.g. if the glue has a lower ttl than the NS entries
	// This can cause performance degradation, but it is correct, since we can interpret the TTL as the maximum time to live.

	// A mildly relevant comment from rfc1912:
	// If your nameserver is multi-homed (has more than one Conn address), you
	// must list all of its addresses in the glue to avoid cache
	// inconsistency due to differing TTL values, causing some lookups to
	// not find all addresses for your nameserver.

	ttl := uint32(math.MaxUint32)
	for _, rr := range ex.Message.Answer {
		ttl = common.MinUInt32(ttl, rr.Header().Ttl)
	}
	for _, rr := range ex.Message.Ns {
		ttl = common.MinUInt32(ttl, rr.Header().Ttl)
	}
	for _, rr := range ex.Message.Extra {
		ttl = common.MinUInt32(ttl, rr.Header().Ttl)
	}

	return time.Second * time.Duration(ttl)
}
