package resolver

import (
	"github.com/enriquebris/goconcurrentqueue"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/builder"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net"
	"net/netip"
	"testing"
	"time"
)

var _ QueryCache = &MockCache{}

type MockCache struct {
}

func (m MockCache) Set(_ model.MessageExchange) {

}

func (m MockCache) Get(_ netip.Addr, _ model.Question) (model.MessageExchange, bool) {
	return model.MessageExchange{}, false
}

var _ InfraCache = &MockInfraCache{}

type MockInfraCache struct {
}

func (m MockInfraCache) Track(_ model.MessageExchange) {
}

func (m MockInfraCache) GetBackoff(_ netip.Addr) time.Duration {
	return 0
}

func (m MockInfraCache) IsResponsive(nsIP netip.Addr) (udpResponsive bool, tcpResponsive bool, reason string) {
	return true, true, ""
}

func TestRequestWorker_Integration_Enqueue(t *testing.T) {
	t.Skip()

	nsIP := "<enter here>"
	q := model.Question{
		Name:  "<enter here>",
		Type:  client.TypeNS,
		Class: client.ClassINET,
	}

	worker := initWorker(common.Background())

	queue := goconcurrentqueue.NewFIFO()
	worker.Enqueue(Request{
		question:      q,
		nameServerIP:  netip.MustParseAddr(nsIP),
		responseQueue: queue,
	})

	for {
		response, err := queue.Dequeue()
		if err != nil {
			return
		}

		t.Log(response)
	}
}

func initWorker(ctx common.Context) *RequestWorker {
	dnsCache := MockCache{}

	infraCache := MockInfraCache{}

	var localIPV4 net.IP
	if conn, err := net.Dial("udp", "9.9.9.9:53"); err == nil {
		localIPV4 = conn.LocalAddr().(*net.UDPAddr).IP
		conn.Close()
	} else {
		panic("Failed to resolve local IPv4 address")
	}

	var localIPV6 net.IP
	if conn, err := net.Dial("udp", "[2001:4860:4860::8888]:53"); err == nil {
		localIPV6 = conn.LocalAddr().(*net.UDPAddr).IP
		conn.Close()
	} else {
		panic("Failed to resolve local IPv6 address")
	}

	c := new(builder.Builder).
		WithTCPPoolSize(100).
		WithTCPEphemeralConns(100).
		WithUDPPoolSize(10).
		WithLocalIPs(localIPV4, localIPV6).
		Build(ctx)

	worker := NewWorker(c, dnsCache, infraCache, 1)

	// If this becomes a bottleneck, it should
	// be safe to start multiple dequeue workers.
	go worker.Dequeue(ctx)

	return worker
}
