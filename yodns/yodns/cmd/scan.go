package cmd

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strings"

	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/runner"
	"github.com/ilibs/json5"
	"github.com/nightlyone/lockfile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var Scan = &cobra.Command{
	Use:   "scan",
	Args:  cobra.OnlyValidArgs,
	Short: "Runs the DNS data collection",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		// First, get the config file flag (if provided)
		configFilePath, _ := cmd.Flags().GetString("config")
		cpuProfilePath, _ := cmd.Flags().GetString("cpu-profile-file")
		threads, _ := cmd.Flags().GetInt("threads")
		maxMem, _ := cmd.Flags().GetInt64("maxMem")
		disableMetrics, _ := cmd.Flags().GetBool("disable-metrics")
		prependWWW, _ := cmd.Flags().GetBool("prepend-www")
		enablePprof, _ := cmd.Flags().GetBool("enable-pprof")
		lockfilePath, _ := cmd.Flags().GetString("lockfile")
		if lockfilePath != "" {
			absPath, err := filepath.Abs(lockfilePath)
			if err != nil {
				panic(fmt.Errorf("cannot create lock file at %v with err %w", absPath, err))
			}

			lf, err := lockfile.New(absPath)
			if err != nil {
				panic(fmt.Errorf("cannot create lock file at %v with err %w", absPath, err))
			}

			if err := lf.TryLock(); err != nil {
				panic(fmt.Errorf("cannot lock file at %v with err %w", absPath, err))
			}

			defer lf.Unlock()
		}

		if enablePprof {
			go func() { _ = http.ListenAndServe("localhost:8081", nil) }()
		}

		if cpuProfilePath != "" {
			cpuFile, err := os.Create(cpuProfilePath)
			defer cpuFile.Close()
			if err != nil {
				panic(fmt.Errorf("cannot create cpu profile file at %v with err %w", cpuProfilePath, err))
			}
			if err := pprof.StartCPUProfile(cpuFile); err != nil {
				panic(fmt.Errorf("cannot start cpu profile with err %w", err))
			}
			defer pprof.StopCPUProfile()
		}

		// If provided, load the config file,
		options := runner.DefaultOptions
		if configFilePath != "" {
			bytes, err := os.ReadFile(configFilePath)
			if err != nil {
				panic(fmt.Errorf("error reading config file from %v with err %w", configFilePath, err))
			}

			if err := json5.Unmarshal(bytes, &options); err != nil {
				panic(fmt.Errorf("error parsing config file %v with err %w", configFilePath, err))
			}
		}

		// Update runtime settings
		// -x means use all CPUs except x
		if threads < 0 {
			threads = runtime.NumCPU() + threads
		}
		if threads != 0 {
			runtime.GOMAXPROCS(threads)
		}

		// https://tip.golang.org/doc/gc-guide#The_GC_cycle
		// Going from 100 -> 200, CPU for GC goes from 13.5% -> 8.5%
		// Going from 100 -> 50, CPU for GC goes from 13.5% -> 16%
		debug.SetGCPercent(200)
		if maxMem > 0 {
			maxMemBytes := maxMem * 1024 * 1024 * 1024
			debug.SetMemoryLimit(maxMemBytes)
			options.MemoryLimitInGB = int(0.70 * float64(maxMemBytes))
		}

		// We reparse the args to overwrite what's in the config file with the flags (if provided)
		// This way we get the desired priority (args > configFile > default)
		flags := pflag.NewFlagSet("args", pflag.PanicOnError)
		defineFlags(flags, &options)
		flags.Parse(os.Args[2:]) // First arg is the program name, second arg is "scan"

		if disableMetrics {
			options.Metrics = runner.MetricsConfig{}
		}

		if prependWWW {
			psl, err := model.LoadPSL(options.Input.PSLPath)
			if err != nil {
				panic(fmt.Errorf("PSL is required for www. prepending: %w", err))
			}
			runner.PreResolveHook = func(ctx context.Context, batch []resolver.TaggedDomainName) []resolver.TaggedDomainName {
				return expandTargetList(batch, psl)
			}
		}

		ctx, cncl := common.WithCancel(common.Background())
		defer cncl()

		runner.Run(ctx, options)
	},
}

func init() {
	rootCmd.AddCommand(Scan)
	defineFlags(Scan.Flags(), &runner.DefaultOptions)
}

// expandTargetList adds www. of the private-level domain and all ancestors of the name to the target list directly.
// This is done, so that TXT/A/AAAA records of those names are retrieved (via "OnFullNameResolved") without
// also retrieving these records for all intermediate names of name server zones.
func expandTargetList(names []resolver.TaggedDomainName, psl *model.PSL) []resolver.TaggedDomainName {
	result := make(map[model.DomainName]resolver.TaggedDomainName, 2*len(names))
	for _, name := range names {
		result[name.Name] = name
	}
	for _, name := range names {
		parents, _ := psl.GetPrivateParents(name.Name)

		// It is a public suffix
		if len(parents) == 0 {
			continue
		}

		// ask for www. of the private-level domain
		pld := parents[0]
		if !strings.HasPrefix(string(pld), "www.") {
			if www, err := pld.PrependLabel("www"); err == nil {
				if _, ok := result[www]; !ok {
					result[www] = resolver.TaggedDomainName{Name: www}
				}
			}
		}

		// ask for all ancestors
		for _, ancestor := range parents {
			// Don't overwrite existing names, that may be tagged
			if _, ok := result[ancestor]; !ok {
				result[ancestor] = resolver.TaggedDomainName{Name: ancestor}
			}
		}
	}

	return common.Values(result)
}

func defineFlags(flags *pflag.FlagSet, options *runner.Options) {
	flags.String("config", "", "Path to the config file. Values from the file will be overwritten by command line options.")
	flags.String("cpu-profile-file", "", "Enables CPU profiling and sets the path where to store the profile")
	flags.Int("threads", -1, "Sets the maximum number of hardware threads to use. By default, use all available threads. "+
		"Negative number mean all available threads minus the number specified.")
	flags.Int64("maxMem", -1, "Sets the maximum number memory to use in GB (soft limit)")

	flags.String("lockfile", "", "Path to a lockfile. Program MUST obtain a lock on startup, otherwise it will exit. No value means no lockfile.")
	flags.Bool("disable-metrics", false, "If true, metric endpoint will be disabled.")
	flags.Bool("enable-pprof", false, "If true, the tool will provide a pprof endpoint for profiling at localhost:8081")
	flags.Bool("prepend-www", false, "If true, prepend the second level domain with a www. prefix and adds it to the target list before the resolution is happening.")

	// Continuation options
	flags.StringVar(&options.ProgressDumpFile, "progress-file", options.ProgressDumpFile, "Path to the progress file.")
	flags.StringVar(&options.CacheDumpFile, "cache-dump", options.CacheDumpFile, "The path to a dumped cache to load")

	flags.StringVar(&options.Input.Path, "i", options.Input.Path, "The path to the input file in alexa format")
	flags.UintVar(&options.Input.Len, "len", options.Input.Len,
		"Specifies how many entries of the input list should be read")
	flags.UintVar(&options.Input.Offset, "offset", options.Input.Offset,
		"Number of entries that is skipped from the input list. Can be used to restart the mergeSingleFile at a later point in time")
	flags.StringVar(&options.Input.PSLPath, "pslPath", options.Input.PSLPath,
		"Path to the PSL file.")

	flags.IntVar(&options.Input.CSVColumnIndex, "csvidx", options.Input.CSVColumnIndex, "Index of the domain name in the input csv file.")

	flags.StringVar(&options.Output.Path, "o", options.Output.Path, "The path to the output directory")
	flags.UintVar(&options.Output.FileSize, "s", options.Output.FileSize,
		"The maximum number of elements that is written to a single file. There is no guarantee that any fill will actually contain that many elements.")
	flags.Uint32Var(&options.Output.ParallelFiles, "paraFiles", options.Output.ParallelFiles, "Number of parallel files")

	flags.UintVar(&options.MaxParallelism, "p", options.MaxParallelism, "The amount of domains that are resolved in parallel.")
	flags.StringVar(&options.Loglevel, "loglevel", options.Loglevel, "Sets the log level. Values are 'debug', 'info', 'warning' and 'disabled'")
	flags.StringVar(&options.Logfile, "logfile", options.Logfile, "Sets the path to the logfile. If empty, no log file will be used.")
	flags.IntVar(&options.Metrics.EndpointPort, "metrics-port", options.Metrics.EndpointPort, "Port number on which metrics are exposed if enable-metrics is set.")

	flags.IntVar(&options.MaxQueriesPerSecondPerIP, "m", options.MaxQueriesPerSecondPerIP,
		"The maximum query rate per IP.")
	flags.IntVar(&options.MaxInflightPerIP, "mip", options.MaxInflightPerIP,
		"The maximum number of requests send in parallel to a single Conn. Use this to avoid spamming small servers with requests. "+
			"Use 0 or negative values to disable rate-limiting per Conn.")
	flags.StringVar(&options.DoNotScanList, "doNotScan", options.DoNotScanList,
		"The path to a do not scan list.")
	flags.BoolVar(&options.IPV6Only, "ipv6-only", options.IPV6Only,
		"Turns off IPv4 connectivity and uses IPv6 exclusively")
	flags.BoolVar(&options.IPV4Only, "ipv4-only", options.IPV4Only,
		"Turns off IPv6 connectivity and uses IPv4 exclusively")
	flags.BoolVar(&options.TCP.Disable, "-no-tcp", options.TCP.Disable,
		"If true, all requests will be send using TCP. Be aware of the performance impact.")
	flags.BoolVar(&options.UDP.Disable, "-no-udp", options.UDP.Disable,
		"If true, all requests will be send using UDP. No TCP fallback (e.g. for truncation) will be possible")
	flags.BoolVar(&options.GatherDNSSEC, "gather-dnssec", options.GatherDNSSEC,
		"If true, DNSSEC data will be gathered. ")
	flags.UintVar(&options.MaxCNAMEDepth, "max-cname-depth", options.MaxCNAMEDepth,
		"Sets the depth to which CNAMEs will be followed. Set to 0 to disable CNAME following.")
	flags.BoolVar(&options.EnableICMP, "enable-icmp", options.EnableICMP,
		"If true, the tool will receive and mergeSingleFile ICMP messages to recognize unavailable servers")
	flags.StringVar(&options.ICMPOutPath, "icmp-out", options.ICMPOutPath,
		"The path to which ICMP messages will be logged")
}
