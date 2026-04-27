package runner

import (
	"bufio"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"math"
	"strconv"
)

// ScanProgress is a utility type that tracks which domains are currently being resolved.
// on crash, it helps to determine from where the scanning should resume.
type ScanProgress struct {
	trackFinished chan uint
	Count         uint
	Log           zerolog.Logger
	Missing       map[uint]any
	minMissing    uint
	max           uint
	isLoaded      bool
}

// Load loads the dump from a file and creates an index of domains that have not been scanned yet.
func (p *ScanProgress) Load(in io.Reader) {
	scanner := bufio.NewScanner(in)

	idxs := make(map[uint]any)
	p.max = uint(0)
	for scanner.Scan() {
		line := scanner.Text()
		idx, err := strconv.Atoi(line)
		if err != nil {
			p.Log.Panic().Err(err).Msgf("failed to parse line in ScanProgress %s", line)
		}
		idxs[uint(idx)] = nil
		if uint(idx) > p.max {
			p.max = uint(idx)
		}
		p.Count++
	}

	p.Missing = make(map[uint]any)      // Map of Missing indexes
	p.minMissing = uint(math.MaxUint32) // The smallest Missing index
	for i := uint(0); i <= p.max; i++ {
		if _, ok := idxs[i]; !ok {
			p.Missing[i] = nil
			if i < p.minMissing {
				p.minMissing = i
			}
		}
	}

	p.isLoaded = true
}

func (p *ScanProgress) TrackFinished(idx uint) {
	if p.trackFinished != nil {
		p.trackFinished <- idx
	}
}

func (p *ScanProgress) Close() {
	if p.trackFinished != nil {
		close(p.trackFinished)
	}
}

func (p *ScanProgress) CanSkip(idx uint) bool {
	if !p.isLoaded {
		return false
	}
	if idx < p.minMissing {
		return true
	}
	if idx > p.max {
		return false
	}

	_, ok := p.Missing[idx]
	return !ok
}

func (p *ScanProgress) WriteWorker(out io.Writer) {
	p.trackFinished = make(chan uint, 1000)
	for idx := range p.trackFinished {
		_, err := out.Write([]byte(fmt.Sprintf("%d\n", idx)))
		if err != nil {
			p.Log.Err(err).Msg("failed to write to scan progress file. Exiting worker...")
			return
		}
	}
}
