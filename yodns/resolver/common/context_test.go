package common

import (
	"testing"
	"time"
)

func TestContext_CanDefer(t *testing.T) {
	ctx := Background()
	deferCalled := false
	ctx = ctx.WithDefer(func() {
		deferCalled = true
	})

	ctx.Go(func() {
		// Do nothing
	})

	time.Sleep(50 * time.Millisecond)

	if !deferCalled {
		t.Error("defer was not called")
	}
}
