package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/client/builder"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/cache"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/icmp"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/qmin"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/input"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/json"
	"github.com/DNS-MSMT-INET/yodns/resolver/serialization/protobuf"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricDomainsResolving = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "resolver_domains_resolving",
		Help: "The number of domains that are currently being resolved",
	})
	metricBatchesResolving = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "resolver_batches_resolving",
		Help: "The number of batches that are currently being resolved",
	})
	metricDomainsResolved = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "resolver_domains_resolved",
		Help: "The total number of resolved domains",
	})
)

type Outputter interface {
	Wait() error
	WriteAsync(result resolver.Result) error
}

type Inputter interface {
	Read(ctx common.Context) <-chan []input.Item
}

// StrategyFac is the factory method initializing the resolution strategy.
// Overwrite it if you want to inject a custom strategy into the resolver
var StrategyFac = func(opts Options) resolver.Strategy {
	return qmin.New().
		AddModule(opts.InitModules()...).
		TrustTLDs(opts.TrustAllTLDs).
		TrustZones(opts.GetTrustedZones()).
		TrustedNameserverCount(opts.TrustedZoneNSCount)
}

// ClientFac is the factory method initializing the DNS client.
// Overwrite it if you want to modify or change the DNS client that is used.
var ClientFac = func(ctx common.Context, localIPv4 net.IP, localIPv6 net.IP, opts Options, log zerolog.Logger) client.DNSClient {
	return new(builder.Builder).
		WithRateLimiting(int64(opts.MaxInflightPerIP), int64(opts.MaxQueriesPerSecondPerIP), opts.RateLimitingTimeout()).
		WithTCPPoolSize(opts.TCP.PoolSize).
		WithTCPEphemeralConns(opts.TCP.EphemeralConns).
		WithTCPTimeout(opts.TCP.Timeout()).
		WithTCPDialTimeout(opts.TCP.DialTimeout()).
		WithUDPTimeout(opts.UDPTimeout()).
		WithEDNSBufferSize(opts.UDP.BufferSize).
		UseTCPKeepAlive(opts.TCP.UseKeepAlive).
		WithTCPIdlePeriod(opts.TCP.IdlePeriod()).
		WithUDPPoolSize(opts.UDP.PoolSize).
		WithLocalIPs(localIPv4, localIPv6).
		WithLogger(log).
		Build(ctx)
}

// CacheFac is the factory method initializing the DNS cache.
// Overwrite it if you want to modify or use a custom DNS cache.
var CacheFac = func(ctx common.Context, opts Options) *cache.DNSCache {
	dnsCache := cache.NewDNSCache(opts.Caching.Capacity)

	ctx.Go(dnsCache.Start)
	return dnsCache
}

// ResolverFac is the factory method initializing the resolver
// Overwrite it if you want to modify or change the resolver logic.
var ResolverFac = func(log zerolog.Logger, worker resolver.Worker, strategy resolver.Strategy, opts Options) resolver.Resolver {
	return resolver.New(worker, strategy, opts.RootServers...).
		UseAllNameServerIPs(true).
		GatherDNSSEC(opts.GatherDNSSEC).
		DisableIPv4(opts.IPV6Only).
		DisableIPv6(opts.IPV4Only).
		FollowCNAMEsToDepth(opts.MaxCNAMEDepth).
		WithMaxQueries(opts.MaxQueriesPerResolution).
		LogTo(log)
}

// WorkerFac is the factory initializing the request worker
var WorkerFac = func(ctx common.Context, client client.DNSClient, cache *cache.DNSCache, infraCache *cache.InfraCache, opts Options, log zerolog.Logger) resolver.Worker {
	worker := resolver.NewWorker(client, cache, infraCache, opts.Retry.MaxRetries)
	if opts.TCP.Disable {
		worker.DisableTCP()
	}
	if opts.UDP.Disable {
		worker.DisableUDP()
	}

	// If this becomes a bottleneck, it should
	// be safe to start multiple dequeue workers.
	ctx.Go(func() { worker.Dequeue(ctx) })

	return worker
}

// InfraCacheFac is the factory initializing the infrastructure cache on startup
var InfraCacheFac = func(ctx common.Context, log zerolog.Logger, opts Options) *cache.InfraCache {
	var backoff cache.Backoff
	if strings.EqualFold(opts.Retry.Backoff, "exponential") {
		backoff = cache.ExponentialBackoff{
			Min:    time.Second,
			Max:    30 * time.Second,
			Factor: 1.8, // apx. 1, 2, 3, 6, 11, 19, 34
		}
	}
	if strings.EqualFold(opts.Retry.Backoff, "constant") {
		backoff = cache.ConstantBackoff{
			Value: 20 * time.Second,
		}
	}
	if strings.EqualFold(opts.Retry.Backoff, "values") {
		backoff = cache.ValuesBackoff{
			Values: opts.Retry.BackoffValues(),
		}
	}

	infraCache := cache.NewInfraCache(opts.Caching.InfraTTL(), opts.Caching.InfraCapacity, backoff, log)

	ctx.Go(infraCache.Start)
	ctx.OnDone(infraCache.Stop)

	return infraCache
}

var LogFac = func(opts Options) (zerolog.Logger, func() error) {
	// Set the log level
	zerolog.SetGlobalLevel(zerolog.Disabled)
	if strings.EqualFold(opts.Loglevel, "debug") {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	if strings.EqualFold(opts.Loglevel, "info") {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	if strings.EqualFold(opts.Loglevel, "warn") {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	// Initialize logging to file if necessary
	if opts.Logfile != "" {
		logFile, logFileErr := os.OpenFile(
			opts.Logfile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664,
		)

		if logFileErr != nil {
			panic(logFileErr)
		}

		return zerolog.New(logFile).Level(zerolog.GlobalLevel()).With().Timestamp().Logger(), logFile.Close
	}

	return zerolog.New(os.Stderr).Level(zerolog.GlobalLevel()).With().Timestamp().Logger(), func() error { return nil }
}

// PreResolveHook is invoked right before the call to resolve.
// Allows modifying the target list last-minute.
var PreResolveHook = func(ctx context.Context, batch []resolver.TaggedDomainName) []resolver.TaggedDomainName {
	return batch
}

// Run runs the data collection using the specified options.
func Run(c context.Context, opts Options) {
	// Variables that holds the logger to use.
	log, _ := LogFac(opts)
	ctx := common.Wrap(c)

	// Only close this, if we can flush the log file.
	// otherwise zerolog tries to write some entries after close.
	// defer closeFunc()

	log.Info().
		Interface("args", opts).
		Msgf("Called with arguments")

	if opts.IPV4Only && opts.IPV6Only {
		log.Panic().
			Msg("Cannot disable both, IPv4 and IPv6 connectivity.")
	}

	if opts.TCP.Disable && opts.UDP.Disable {
		log.Panic().
			Msg("Cannot disable both, TCP and UDP.")
	}

	if opts.DoNotScanList != "" {
		initDoNotScanList(ctx, opts.DoNotScanList, log, time.Second*time.Duration(opts.DoNotScanListReloadIntervalInSeconds))
	}

	if opts.Metrics != (MetricsConfig{}) {
		initMetrics(ctx, log, opts.Metrics)
	}

	// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
	// Find local Conn address
	var localIPV4 net.IP
	if !opts.IPV6Only {
		if conn, err := net.Dial("udp", "192.0.2.0:53"); err == nil {
			localIPV4 = conn.LocalAddr().(*net.UDPAddr).IP
			_ = conn.Close()
		} else {
			log.Panic().Err(err).Msg("Failed to resolve local IPv4 address. Check IPv4 connectivity or consider using --ipv6-only")
		}
	}

	var localIPV6 net.IP
	if !opts.IPV4Only {
		if conn, err := net.Dial("udp", "[2001:db8::1]:53"); err == nil {
			localIPV6 = conn.LocalAddr().(*net.UDPAddr).IP
			_ = conn.Close()
		} else {
			log.Panic().Err(err).Msg("Failed to resolve local IPv6 address. Check IPv6 connectivity or consider using --ipv4-only")
		}

	}

	var infraCacheDump *bufio.Writer
	if opts.Caching.InfraDumpFile != "" {
		file, err := os.Create(opts.Caching.InfraDumpFile)
		if err != nil {
			log.Panic().Err(err).Msg("failed to create dump file for infrastructure cache")
		}
		bufWriter := bufio.NewWriter(file)

		defer file.Close()
		defer bufWriter.Flush()
		infraCacheDump = bufWriter
	}

	pd := ScanProgress{
		Log: log,
	}
	pdFlush := func() {}
	if opts.ProgressDumpFile != "" {
		progressFile, err := os.OpenFile(opts.ProgressDumpFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			log.Panic().Err(err).Str("file", opts.ProgressDumpFile).Msgf("Failed to load or create progress dump")
		}

		reader := bufio.NewReader(progressFile)
		writer := bufio.NewWriterSize(progressFile, 512) // Use a small buffer, we don't want many writes to be lost on crash

		pd.Load(reader)
		ctx.Go(func() {
			pd.WriteWorker(writer)
		})

		pdFlush = func() {
			writer.Flush()
			progressFile.Close()
		}

		defer pd.Close()
		defer pdFlush()
	}

	// Defers cache dumping for all panics encountered in the context.
	var dnsCache cache.DNSCache
	var infraCache cache.InfraCache

	// This is the sequence that will be executed when a goroutine
	// that is executed in the context (aka invoked by ctx.Go) panics
	ctx = ctx.WithDefer(func() {
		if r := recover(); r != nil {
			pdFlush() // Flush progress dump

			// Log panic with stack trace for debugging
			log.WithLevel(zerolog.PanicLevel).
				Interface("panic", r).
				Str("stack", string(debug.Stack())).Msg("Panic")

			// Stops and dumps the infrastructure cache
			infraCache.Stop()
			if infraCacheDump != nil {
				if err := infraCacheDump.Flush(); err != nil {
					log.Err(err).Msgf("Failed to flush infrastructure cache dump")
				}
			}

			// Dump the DNS cache - exclude the last 10 minutes in case the issues that crashed the program manifested themselves in the cache
			dumpDNSCache(&dnsCache, time.Now().Add(-10*time.Minute), log)

			// Continue panicking
			panic(r)
		}
	})

	dnsCache = *CacheFac(ctx, opts)
	infraCache = *InfraCacheFac(ctx, log, opts)

	if infraCacheDump != nil {
		infraCache.DumpTo(infraCacheDump)
	}

	if opts.EnableICMP {
		var icmpOut io.Writer
		if opts.ICMPOutPath != "" {
			file, err := os.Create(opts.ICMPOutPath)
			if err != nil {
				log.Panic().Err(err).Msgf("Failed to create ICMP trace file at %v", opts.ICMPOutPath)
			}
			bufWriter := bufio.NewWriter(file)

			defer file.Close()
			defer bufWriter.Flush()

			icmpOut = bufWriter
		}

		err := new(icmp.CacheInjector).
			Inject(&infraCache).
			LogTo(log).
			WriteTo(icmpOut).
			ListenV4(localIPV4).
			ListenV6(localIPV6).
			Start(ctx)

		if err != nil {
			log.Panic().Err(err).Msg("Failed to start ICMP listener")
		}
	}

	// Load cache from file if necessary, for example when resuming scan after a crash
	if opts.CacheDumpFile != "" {
		inputFile, err := os.Open(opts.CacheDumpFile)
		if err != nil {
			log.Panic().Err(err).Str("file", opts.CacheDumpFile).Msgf("Failed to load dumped cache")
		}

		reader := bufio.NewReader(inputFile)
		zReader, err := zstd.NewReader(reader)
		if err != nil {
			log.Panic().Err(err).Str("file", opts.CacheDumpFile).Msgf("Failed to load dumped cache")
		}

		if err := dnsCache.LoadCacheFromBinary(zReader); err != nil {
			log.Panic().Err(err).Str("file", opts.CacheDumpFile).Msgf("Failed to load dumped cache")
		}

		zReader.Close()
		_ = inputFile.Close()
	}

	if err := os.MkdirAll(opts.Output.Path, 0700); err != nil {
		log.Panic().Err(err).Msgf("Error creating output path %v", opts.Output.Path)
	}

	dnsClient := ClientFac(ctx, localIPV4, localIPV6, opts, log)
	strategy := StrategyFac(opts)
	worker := WorkerFac(ctx, dnsClient, &dnsCache, &infraCache, opts, log)
	res := ResolverFac(log, worker, strategy, opts)

	// Do the actual work
	tStart := time.Now()
	resolveRecords(ctx, opts, res, &pd, log)

	log.Info().Msgf("Resolved domains in %v seconds", time.Since(tStart).Seconds())

	// Stop and dump
	infraCache.Stop()
}

func initMetrics(ctx common.Context, log zerolog.Logger, opts MetricsConfig) {
	var reg = prometheus.NewRegistry()

	if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		log.Panic().Err(err).Msg("Failed to register process metrics")
	}
	if err := reg.Register(collectors.NewGoCollector()); err != nil {
		log.Panic().Err(err).Msg("Failed to register go runtime metrics")
	}
	if err := reg.Register(metricDomainsResolved); err != nil {
		log.Panic().Err(err).Msg("Failed to register metricDomainsResolved")
	}
	if err := reg.Register(metricDomainsResolving); err != nil {
		log.Panic().Err(err).Msg("Failed to register metricDomainsResolving")
	}
	if err := reg.Register(metricBatchesResolving); err != nil {
		log.Panic().Err(err).Msg("Failed to register metricBatchesResolving")
	}

	cache.RegisterMetrics(reg)
	client.RegisterMetrics(reg)
	resolver.RegisterMetrics(reg)

	// File reporting
	if opts.FilePath != "" {
		ctx.Go(func() {
			t := time.NewTicker(15 * time.Second)
			for {
				select {
				case <-ctx.Done():
					t.Stop()
					return
				case <-t.C:
					if err := prometheus.WriteToTextfile(opts.FilePath, reg); err != nil {
						log.Err(err).Msg("Failed to report metrics to file")
					}
				}
			}
		})
	}

	// HTTP reporting
	metricsHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})

	// Add basic auth if configured
	if opts.PasswordChecksum != "" || opts.UserNameChecksum != "" {
		user := common.Must(hex.DecodeString(opts.UserNameChecksum))
		pw := common.Must(hex.DecodeString(opts.PasswordChecksum))
		metricsHandler = basicAuthHandler(metricsHandler, *(*[32]byte)(user), *(*[32]byte)(pw))
	}

	if opts.ServerCrtPath == "" && opts.ServerKeyPath != "" ||
		opts.ServerCrtPath != "" && opts.ServerKeyPath == "" {
		log.Panic().Msg("Either provide both, 'ServerCrtPath' and 'ServerKeyPath' to enable TLS for the metrics endpoint, or none to disable it.")
	}

	if opts.ServerCrtPath != "" {
		if _, err := os.Stat(opts.ServerCrtPath); err != nil {
			log.Panic().Msgf("ServerCrtPath '%v' does not exist or cannot be accessed", opts.ServerCrtPath)
		}
	}

	if opts.ServerKeyPath != "" {
		if _, err := os.Stat(opts.ServerKeyPath); err != nil {
			log.Panic().Msgf("ServerKeyPath '%v' does not exist or cannot be accessed", opts.ServerKeyPath)
		}
	}

	http.Handle("/metrics", metricsHandler)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%v", opts.EndpointPort),
		Handler: http.DefaultServeMux,
	}

	// No ServerCrt => Expose HTTP endpoint
	if opts.ServerCrtPath == "" {
		ctx.Go(func() {
			if err := server.ListenAndServe(); err != nil {
				log.Info().Err(err).Msg("error serving metrics endpoint")
				return
			}
		})
	} else {
		// else: ServerCrt provided, expose HTTPS endpoint
		ctx.Go(func() {
			if err := server.ListenAndServeTLS(opts.ServerCrtPath, opts.ServerKeyPath); err != nil {
				log.Info().Err(err).Msg("error serving metrics endpoint")
				return
			}
		})
	}

	ctx.OnDone(func() {
		err := server.Shutdown(ctx) // shutdown ends the go routine started above
		log.Info().Err(err).Msg("shutting down metrics endpoint")
	})
}

func resolveRecords(ctx common.Context, opts Options, resv resolver.Resolver, pm *ScanProgress, log zerolog.Logger) {
	// If there's a panic, dump the cache so we can pick our scan up from here again.

	in := initInputter(opts, log)
	out := initOutputter(opts)

	// If there is a offset, start the metric there (for continuing scans)
	metricDomainsResolved.Add(float64(pm.Count))

	// There are MaxParallelism workers.
	// Each worker can resolve one domain at a time => The parallelism is bounded.
	inputChan := in.Read(ctx)

	rg, ctx := ctx.Errgroup()
	domainsInflightSem := semaphore.NewWeighted(int64(opts.MaxParallelism))
	batchesInflightSem := semaphore.NewWeighted(int64(opts.MaxBatchParallelism))

	if opts.MemoryLimitInGB > 0 {
		go newMemoryThrottle(ctx, uint64(opts.MemoryLimitInGB), batchesInflightSem)
	}

	for batch := range inputChan {
		select {
		case <-ctx.Done():
			break
		default:
			// capture variables for use in go function below.
			// (modification outside leads to unexpected behaviour)
			batchNames := make([]resolver.TaggedDomainName, 0, len(batch))
			for _, item := range batch {

				// If this scan is a continuation after crash,
				// ensure that we haven't scanned the item already
				if pm.CanSkip(item.Idx) {
					continue
				}

				batchNames = append(batchNames, resolver.TaggedDomainName{
					Idx:  item.Idx,
					Name: item.Name,
					Tags: item.Tags,
				})
			}

			// All items have been scanned previously
			if len(batchNames) == 0 {
				continue
			}

			if err := domainsInflightSem.Acquire(ctx, int64(len(batch))); err != nil {
				return
			}
			if err := batchesInflightSem.Acquire(ctx, 1); err != nil {
				return
			}

			rg.Go(func() error {
				defer func() {
					domainsInflightSem.Release(int64(len(batchNames)))
					batchesInflightSem.Release(1)
					for _, n := range batchNames {
						pm.TrackFinished(n.Idx)
					}
				}()

				batchLen := float64(len(batchNames))
				metricDomainsResolving.Add(batchLen)
				metricBatchesResolving.Inc()

				ctx, cncl := common.WithTimeout(ctx, time.Second*time.Duration(opts.ResolutionTimeoutInSeconds))

				result := resv.Resolve(ctx, PreResolveHook(ctx, batchNames)...)
				cncl()

				if err := out.WriteAsync(result); err != nil {
					arr := zerolog.Arr()
					for _, n := range batchNames {
						arr.Str(string(n.Name))
					}
					log.Err(err).
						Array("domainnames", arr).
						Msg("Error writing to out")

					return err
				}

				metricDomainsResolved.Add(batchLen)
				metricDomainsResolving.Sub(batchLen)
				metricBatchesResolving.Dec()

				return nil
			})

			if opts.WarmUp && batch[0].Idx < opts.MaxParallelism {
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	// Wait until all domains are resolved
	if err := rg.Wait(); err != nil {
		log.Err(err).Msg("Error resolving domains")
	}

	// Wait until writing has finished
	if err := out.Wait(); err != nil {
		log.Err(err).Msg("Error writing to out")
	}
}

func newMemoryThrottle(ctx common.Context, memoryLimit uint64, inflightSem *semaphore.Weighted) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var throttled = uint(0)
	stepSize := uint(20)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			samples := make([]metrics.Sample, 1)
			samples[0].Name = "/memory/classes/heap/objects:bytes"
			metrics.Read(samples)
			if sample := samples[0]; sample.Value.Kind() == metrics.KindUint64 {
				if sample.Value.Uint64() > memoryLimit {
					ctx, cancel := common.WithTimeout(ctx, time.Second)
					if err := inflightSem.Acquire(ctx, int64(stepSize)); err == nil {
						throttled += stepSize
					}
					cancel()
					continue
				}

				// else: we are below the limit - release semaphore is held
				if throttled > 0 {
					throttled -= stepSize
					inflightSem.Release(int64(stepSize))
				}

				continue
			}

			// else: error reading the metric - in doubt, release the throttling
			if throttled > 0 {
				throttled -= stepSize
				inflightSem.Release(int64(stepSize))
			}
		}
	}
}

func basicAuthHandler(h http.Handler, expectedUserNameHash [32]byte, expectedPasswordHash [32]byte) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			userHash := sha256.Sum256([]byte(user))
			passHash := sha256.Sum256([]byte(pass))
			validUser := subtle.ConstantTimeCompare(userHash[:], expectedUserNameHash[:]) == 1
			validPass := subtle.ConstantTimeCompare(passHash[:], expectedPasswordHash[:]) == 1
			if validPass && validUser {
				h.ServeHTTP(rw, r)
				return
			}
		}
		http.Error(rw, "No/Invalid Credentials", http.StatusUnauthorized)
	}
}

func initOutputter(opts Options) Outputter { //nolint:ireturn
	zipAlgo, compression, err := serialization.ParseZip(opts.Output.Zip)
	if err != nil {
		log.Panic().Err(err).Msgf("Unable to initialize output: %v", err)
	}

	// Avoids overwriting data from previous runs
	// Just an additional safeguard against data loss
	if strings.EqualFold(opts.Output.Format, "json") {
		w := json.NewWriter(opts.Output.Path, "output", opts.Output.FileSize, zipAlgo, compression, opts.Output.ParallelFiles)
		return w
	}
	if strings.EqualFold(opts.Output.Format, "protobuf") {
		w := protobuf.NewWriter(opts.Output.Path, "output", opts.Output.FileSize, zipAlgo, compression, opts.Output.ParallelFiles)
		w.ZipAlgorithm = zipAlgo
		w.CompressionLevel = compression
		return w
	}

	log.Panic().Msgf("OutputFormat %v is not known", opts.Output.Format)
	return nil
}

func initInputter(opts Options, log zerolog.Logger) Inputter {
	if strings.EqualFold(opts.Input.Format, "csv") {
		var psl *model.PSL
		var err error
		if opts.Input.BatchSize > 1 {
			psl, err = model.LoadPSL(opts.Input.PSLPath)
			if err != nil {
				log.Panic().Err(err).Msg("PSL is needed for batching in CSV inputter")
			}
		}

		return input.BatchingCSV{
			FilePath:       opts.Input.Path,
			CsvColumnIndex: opts.Input.CSVColumnIndex,
			TagColumnIndex: opts.Input.CSVColumnIndex + 1,
			Separator:      []rune(opts.Input.CSVSeparator)[0],
			Offset:         opts.Input.Offset,
			Len:            opts.Input.Len,
			Log:            log,
			BatchSize:      opts.Input.BatchSize,
			Psl:            psl,
		}
	}

	if strings.EqualFold(opts.Input.Format, "iprange") {
		return input.IPRange{
			FilePath: opts.Input.Path,
			Offset:   opts.Input.Offset,
			Len:      opts.Input.Len,
			Log:      log,
		}
	}

	log.Panic().Msgf("Input %v is not known", opts.Output.Format)
	return nil
}

func initDoNotScanList(ctx context.Context, filepath string, log zerolog.Logger, reloadInterval time.Duration) {
	if err := resolver.DoNotScanList.FromFile(filepath); err != nil {
		log.Panic(). // Stop execution. Don't start scanning without respecting the do not scan list.
			Err(err).
			Str("filePath", filepath).
			Msgf("Error opening do-not-scan list. The system cannot find the file %v.", filepath)
	}

	go func() {
		t := time.NewTicker(reloadInterval)
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				// Reload the entry - if it fails we do not panic
				if err := resolver.DoNotScanList.FromFile(filepath); err != nil {
					log.Err(err).Msg("Failed to update do not scan list")
				}
			}
		}
	}()
}

func dumpDNSCache(cache *cache.DNSCache, notAfter time.Time, log zerolog.Logger) {
	if cache == nil {
		return
	}

	output, err := os.Create(fmt.Sprintf("./cache_%v.zst", time.Now().Format("Jan-2-15-04-05")))
	if err != nil {
		log.Error().Err(err).Msgf("Unable to dump cache")
	}
	defer output.Close()

	writer := bufio.NewWriter(output)
	zWriter, err := zstd.NewWriter(writer, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		log.Error().Err(err).Msgf("Unable to dump cache. Cannot open zip writer")
		return
	}

	if err := cache.DumpCacheAsBinary(notAfter, zWriter); err != nil {
		log.Error().Err(err).Msgf("Error dumping cache")
	}

	if err = zWriter.Close(); err != nil {
		log.Error().Err(err).Msgf("Unable to close cache dump")
	}
	if err = writer.Flush(); err != nil {
		log.Error().Err(err).Msgf("Unable to close cache dump")
	}
}
