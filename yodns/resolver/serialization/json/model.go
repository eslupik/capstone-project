package json

import (
	"encoding/base64"
	"net/netip"
	"time"

	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/miekg/dns"
)

type TaggedDomain struct {
	Idx  uint
	Name model.DomainName
	Tags string
}

// WriteModel defines the format that is written to the file.
type WriteModel struct {
	Domains   []TaggedDomain
	StartTime time.Time
	Duration  time.Duration
	Zonedata  Zone
	Messages  []MessageExchange
}

type Zone struct {
	Name            string
	Subzones        []Zone
	NameServers     []NameServer
	ResourceRecords []string
}

type NameServer struct {
	Name        string
	IPAddresses []netip.Addr
}

type MessageExchange struct {
	OriginalQuestion model.Question
	ResponseAddr     string
	NameServerIP     netip.Addr
	Metadata         model.Metadata
	Message          *Message
	Error            *model.SendError
}

type Message struct {
	Id                   uint16
	RCode                int
	Opcode               int
	IsResponse           bool // Corresponds to the QR bit
	IsAuthoritative      bool // Corresponds to the AA bit
	IsTruncated          bool // Corresponds to the TC bit
	IsRecursionDesired   bool // Corresponds to the RD bit
	IsRecursionAvailable bool // Corresponds to the RA bit
	IsAuthenticatedData  bool // Corresponds to the AD bit (DNSSEC)
	IsCheckingDisabled   bool // Corresponds to the CD bit (DNSSEC)

	// Question contains the question as returned by the name server.
	Question   []ResourceRecord
	Answer     []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord

	// OriginalBytes bytes of the message to restore it on deserialization.
	// This is the downside of working with the wire format of miekg dns, we can't really
	// serialize/deserialize well unless we use pack()/unpack()
	OriginalBytes string
}

// ResourceRecord represents a DNS record
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Value string
}

func From(ex *model.MessageExchange) MessageExchange {
	return MessageExchange{
		OriginalQuestion: ex.OriginalQuestion,
		ResponseAddr:     ex.ResponseAddr,
		NameServerIP:     ex.NameServerIP,
		Metadata:         ex.Metadata,
		Message:          toMessage(ex.Message),
		Error:            ex.Error,
	}
}

func toMessage(msg *dns.Msg) *Message {
	if msg == nil {
		return nil
	}

	originalBytes, err := msg.Pack()
	if err != nil {
		panic(err)
	}

	return &Message{
		Id:                   msg.Id,
		RCode:                msg.Rcode,
		Opcode:               msg.Opcode,
		IsResponse:           msg.Response,
		IsAuthoritative:      msg.Authoritative,
		IsTruncated:          msg.Truncated,
		IsRecursionDesired:   msg.RecursionDesired,
		IsRecursionAvailable: msg.RecursionAvailable,
		IsAuthenticatedData:  msg.AuthenticatedData,
		IsCheckingDisabled:   msg.CheckingDisabled,
		Question:             toResourceRecordsFromQ(msg.Question),
		Answer:               ToResourceRecords(msg.Answer),
		Authority:            ToResourceRecords(msg.Ns),
		Additional:           ToResourceRecords(msg.Extra),
		OriginalBytes:        base64.StdEncoding.EncodeToString(originalBytes),
	}
}

func ToResourceRecords(rrs []dns.RR) []ResourceRecord {
	records := make([]ResourceRecord, len(rrs))
	for i, rr := range rrs {
		records[i] = ResourceRecord{
			Name:  rr.Header().Name,
			Type:  rr.Header().Rrtype,
			Class: rr.Header().Class,
			Value: model.GetRRValue(rr),
			TTL:   rr.Header().Ttl,
		}
	}
	return records
}

func ToResourceRecordsFiltered(rrs []dns.RR) []ResourceRecord {
	records := make([]ResourceRecord, len(rrs))
	for i, rr := range rrs {
		records[i] = ResourceRecord{
			Name:  rr.Header().Name,
			Type:  rr.Header().Rrtype,
			Class: rr.Header().Class,
			Value: model.GetRRValue(rr),
			TTL:   rr.Header().Ttl,
		}
	}
	return records
}

func toResourceRecordsFromQ(qs []dns.Question) []ResourceRecord {
	records := make([]ResourceRecord, len(qs))
	for i, q := range qs {
		records[i] = ResourceRecord{
			Name:  q.Name,
			Type:  q.Qtype,
			Class: q.Qclass,
		}
	}
	return records
}
