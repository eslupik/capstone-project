package input

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"net/netip"
	"os"
	"strings"
)

// IPRange allows
type IPRange struct {
	FilePath       string
	CsvColumnIndex int
	Offset         uint
	Len            uint
	Log            zerolog.Logger
}

type Item struct {
	Idx  uint
	Name model.DomainName
	Tags string
}

func (in IPRange) Read(ctx common.Context) <-chan []Item {
	f, err := os.Open(in.FilePath)
	if err != nil {
		in.Log.Panic().Err(err).
			Str("filePath", in.FilePath).
			Msg("Can not open input file")
	}

	reader := bufio.NewScanner(f)
	reader.Split(bufio.ScanLines)

	inputChan := make(chan []Item)

	ctx.Go(func() {
		defer f.Close()
		defer close(inputChan)

		idx := uint(0)
		for reader.Scan() {
			line := reader.Text()

			p, err := netip.ParsePrefix(strings.TrimSpace(line))
			if err = reader.Err(); err != nil {
				in.Log.Panic().Err(err).Msgf("Failed to parse %v", line)
			}

			p = p.Masked()
			addr := p.Addr()

			for ; p.Contains(addr); addr = addr.Next() {
				name, err := toReverseDNSName(addr)
				if err != nil {
					in.Log.Panic().Err(err).Msg("Error reading input")
				}

				select {
				case <-ctx.Done():
					return
				case inputChan <- []Item{{
					Idx:  idx,
					Name: name,
					Tags: ""}}:
					idx++
				}
			}

		}

		if err := reader.Err(); err != nil {
			in.Log.Panic().Err(err).Msg("Error scanning input file")
		}
	})

	return inputChan

}

func toReverseDNSName(addr netip.Addr) (model.DomainName, error) {

	// Convert from 192.0.2.123 to
	// 123.2.0.192.in-addr.arpa
	if addr.Is4() {
		parts := strings.Split(addr.StringExpanded(), ".")
		builder := strings.Builder{}
		for i := len(parts) - 1; i >= 0; i-- {
			builder.WriteString(parts[i])
			builder.WriteString(".")
		}
		builder.WriteString("in-addr.arpa.")
		return model.MustNewDomainName(builder.String()), nil
	}

	// Convert from 2001:db8::a to
	// to a.0.0....0.0.8.b.d.1.0.0.2.ip6.arpa
	if addr.Is6() {
		builder := strings.Builder{}
		plainString := strings.ReplaceAll(addr.StringExpanded(), ":", "")
		for i := len(plainString) - 1; i >= 0; i-- {

			builder.WriteString(string(plainString[i]))
			builder.WriteString(".")
		}
		builder.WriteString("ip6.arpa.")
		return model.MustNewDomainName(builder.String()), nil
	}

	return "", fmt.Errorf("unsupported address type %v", addr)
}
