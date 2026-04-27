package model

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"net/netip"
	"reflect"
	"testing"
)

func TestMsgIdx_CanIterate(t *testing.T) {
	msgIdx := NewMessageIdx()

	exchanges := []MessageExchange{
		{
			OriginalQuestion: Ask("example.com.", client.TypeA),
			NameServerIP:     netip.MustParseAddr("192.0.2.1"),
		},
		{
			OriginalQuestion: Ask("example.org.", client.TypeA),
			NameServerIP:     netip.MustParseAddr("192.0.2.1"),
		},
		{
			OriginalQuestion: Ask("example.com.", client.TypeAAAA),
			NameServerIP:     netip.MustParseAddr("2001:db8::1"),
		},
	}

	msgIdx.AppendMessage(exchanges[0])
	msgIdx.AppendMessage(exchanges[1])
	msgIdx.AppendMessage(exchanges[2])

	count := 0
	for iter := msgIdx.Iterate(); iter.HasNext() || count > 3; count++ {
		msg := iter.Next()
		if !reflect.DeepEqual(msg.OriginalQuestion, exchanges[0].OriginalQuestion) &&
			!reflect.DeepEqual(msg.OriginalQuestion, exchanges[1].OriginalQuestion) &&
			!reflect.DeepEqual(msg.OriginalQuestion, exchanges[2].OriginalQuestion) {
			t.Errorf("Unexpected message: %v", msg)
		}
	}

	if count != 3 {
		t.Errorf("expected 3 messages, got %d", count)
	}

}
