package test

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"testing"
)

const (
	bufferSize = 1024
)

func ServeUDPResponse(t *testing.T,
	port uint16,
	callbackFunc func(*dns.Msg, *net.UDPAddr) *dns.Msg) {
	t.Helper()

	s, err := net.ResolveUDPAddr("udp4", fmt.Sprintf(":%v", port))
	if err != nil {
		t.Error(err)
		return
	}
	connection, err := net.ListenUDP("udp4", s)

	if err != nil {
		t.Error(err)
		return
	}

	defer connection.Close()

	buffer := make([]byte, bufferSize)
	_, addr, err := connection.ReadFromUDP(buffer)

	if err != nil {
		t.Error(err)
		return
	}

	question := new(dns.Msg)
	if err := question.Unpack(buffer); err != nil {
		t.Error(err)
		return
	}

	answer := callbackFunc(question, addr)
	answerBuffer, err := answer.Pack()

	if err != nil {
		t.Error(err)
		return
	}

	if _, err = connection.WriteTo(answerBuffer, addr); err != nil {
		t.Error(err)
		return
	}
}
