package internal

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"testing"
)

func TestCreateWireMessage_QuestionIsConverted(t *testing.T) {
	q := client.Question{
		Name:  "test.com.",
		Type:  27,
		Class: 123,
	}
	msg := CreateWireMessage(q, false, 1232, true)

	if len(msg.Question) != 1 {
		t.Errorf("Expected msg to have exactly one question record")
	}

	if msg.Question[0].Qclass != q.Class {
		t.Errorf("Expected QClass %v, got %v", q.Class, msg.Question[0].Qclass)
	}

	if msg.Question[0].Qtype != q.Type {
		t.Errorf("Expected QType %v, got %v", q.Type, msg.Question[0].Qtype)
	}

	if msg.Question[0].Name != q.Name {
		t.Errorf("Expected Name %v, got %v", q.Name, msg.Question[0].Name)
	}
}

func TestCreateWireMessage_EnableEDNS(t *testing.T) {
	tests := []struct {
		name    string
		do      bool
		udpSize uint16
	}{
		{name: "SetDO", do: true, udpSize: 512},
		{name: "UnsetDO", do: false, udpSize: 512},
		{name: "CustomUDPSize", do: true, udpSize: 1232},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := CreateWireMessage(client.Question{
				Name:  "test.com.",
				Type:  1,
				Class: 1,
			}, false, tt.udpSize, tt.do)

			opt := msg.IsEdns0()
			if opt == nil {
				t.Errorf("Expected Edns0 to be enabled")
			}
			if opt.Do() != tt.do {
				t.Errorf("Expected Do to be %v", tt.do)
			}
			if opt.UDPSize() != tt.udpSize {
				t.Errorf("Expected UDPSize to be %v", tt.udpSize)
			}
		})
	}
}

func TestCreateWireMessage_DisableEDNS(t *testing.T) {
	msg := CreateWireMessage(client.Question{
		Name:  "test.com",
		Type:  1,
		Class: 2,
	}, true, 1232, true)

	if msg.IsEdns0() != nil {
		t.Errorf("Expected Edns0 to be disabled")
	}
}
