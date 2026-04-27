package runner

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestRun_CanCancel(t *testing.T) {
	timeout := 10 * time.Second
	gracePeriod := 2 * time.Second // 2 seconds grace period - for now we do not need to be particularly efficient with that

	ctx, cancel := common.WithTimeout(common.Background(), timeout)
	defer cancel()

	opts := DefaultOptions
	opts.Input.Path = "./test/test_input.csv"
	opts.Input.Len = 1
	opts.Output.Path = "./test/out"

	initialNrOfRoutines := runtime.NumGoroutine()

	fin := make(chan bool, 1)

	go func() {
		Run(ctx, opts)
		fin <- true
	}()

	wasAbleToCancel := false
	select {
	case <-time.After(timeout + gracePeriod):
	case <-fin:
		wasAbleToCancel = true
	}

	// Small delay helps getting more consistent results
	// from runtime.NumGorountine()
	time.Sleep(time.Second)

	finalNumberOfRoutines := runtime.NumGoroutine()

	// This is a bit flaky. It serves as an indicator and is very useful for debugging.
	// But if you get a few too many, it might as well be a broken library or unfortunate timing.
	// But if 100 routines are still running, we have a leak.
	if initialNrOfRoutines != finalNumberOfRoutines {
		t.Errorf("Expected %v goroutines after cancellation, got %v. There might be a goroutine leaking.", initialNrOfRoutines, finalNumberOfRoutines)
		buf := make([]byte, 1<<16)
		stackSize := runtime.Stack(buf, true)
		t.Logf("%s\n", string(buf[0:stackSize]))
	}
	if !wasAbleToCancel {
		t.Errorf("Provided context was not able to cancel Run()")
	}
}

type panicStrategy struct {
	qmin.Qmin
}

func (s panicStrategy) OnResponse(job *resolver.ResolutionJob, msgEx model.MessageExchange, ns *model.NameServer, args any) {
	// Delay resolution a bit to change the order of the results
	if job.ContainsName("d7.example.com.") {
		time.Sleep(30 * time.Second)
	}

	// Panic when the 11th domain is encountered
	if job.ContainsName("d11.example.com.") {
		time.Sleep(5 * time.Second)
		panic("panic")
	}

	s.Qmin.OnResponse(job, msgEx, ns, args)
}

func TestRun_CanResumeScanningAfterCrash(t *testing.T) {
	if matches, _ := filepath.Glob("cache_*.zst"); len(matches) > 0 {
		t.Errorf("Found cache dump files before test started. Please remove them.")
		t.FailNow()
	}

	ctx := common.Background()

	opts := DefaultOptions
	opts.Input.Path = "./test/test_input.csv"
	opts.Input.Len = 20
	opts.Output.Path = "./test/out"
	opts.Output.FileSize = 5
	opts.MaxParallelism = 3

	originalStrategyFac := StrategyFac
	StrategyFac = func(opts Options) resolver.Strategy {
		return panicStrategy{
			Qmin: qmin.New(),
		}
	}

	var logBuf bytes.Buffer
	LogFac = func(opts Options) (zerolog.Logger, func() error) {
		return zerolog.New(&logBuf), func() error { return nil }
	}

	hasPanicked := make(chan bool, 1)
	ctx = ctx.WithDefer(func() {
		if r := recover(); r != nil {
			hasPanicked <- true
		}
	})

	go Run(ctx, opts)

	<-hasPanicked

	regex := regexp.MustCompile("Resume scanning from (\\d+)")
	groups := regex.FindSubmatch(logBuf.Bytes())

	if idx, err := strconv.Atoi(string(groups[1])); err != nil || idx != 7 {
		t.Errorf("Expected a log entry telling the user to resume scanning from index 7, got %v, %v", idx, err)
	}

	match, _ := filepath.Glob("cache_*.zst")
	if len(match) == 0 {
		t.Errorf("Expected a cache dump to be created")
	}
	if stat, _ := os.Stat(match[0]); stat.Size() == 0 {
		t.Errorf("Expected cache dump to be non-empty")
	}
	defer os.Remove(match[0])

	// Try continuing from index 7
	StrategyFac = originalStrategyFac // remove our panicking strategy
	opts.Input.Offset = 7
	opts.CacheDumpFile = match[0]

	Run(common.Background(), opts)

	// TODO add some assertions
}
