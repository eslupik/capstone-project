package cache

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"math"
	"time"
)

var _ Backoff = new(ExponentialBackoff)
var _ Backoff = new(ConstantBackoff)
var _ Backoff = new(ValuesBackoff)

type Backoff interface {
	Initial() time.Duration
	Increase(oldBackOff time.Duration) time.Duration
	Decrease(oldBackOff time.Duration) time.Duration
}

type ConstantBackoff struct {
	Value time.Duration
}

type ExponentialBackoff struct {
	Min    time.Duration
	Max    time.Duration
	Factor float64
}

type ValuesBackoff struct {
	Values []time.Duration
}

func (e ExponentialBackoff) Initial() time.Duration {
	return e.Min
}

func (e ExponentialBackoff) Increase(oldBackOff time.Duration) time.Duration {
	return time.Duration(math.Min(e.Factor*float64(oldBackOff), float64(e.Max)))
}

func (e ExponentialBackoff) Decrease(oldBackOff time.Duration) time.Duration {
	return time.Duration(math.Max(float64(oldBackOff)/e.Factor, float64(e.Min)))
}

func (c ConstantBackoff) Initial() time.Duration {
	return c.Value
}

func (c ConstantBackoff) Increase(_ time.Duration) time.Duration {
	return c.Value
}

func (c ConstantBackoff) Decrease(_ time.Duration) time.Duration {
	return c.Value
}

func (c ValuesBackoff) Initial() time.Duration {
	return c.Values[0]
}

func (c ValuesBackoff) Increase(oldBackOff time.Duration) time.Duration {
	idx := 0
	for i, v := range c.Values {
		if v == oldBackOff {
			idx = i + 1
			break
		}
	}
	return c.Values[common.MinInt(idx, len(c.Values)-1)]
}

func (c ValuesBackoff) Decrease(oldBackOff time.Duration) time.Duration {
	idx := 0
	for i, v := range c.Values {
		if v == oldBackOff {
			idx = i - 1
			break
		}
	}
	return c.Values[common.MaxInt(0, idx)]
}
