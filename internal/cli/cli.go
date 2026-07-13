package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Zetascrub/net-link/internal/link"
	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/report"
	"github.com/Zetascrub/net-link/internal/runner"
	"github.com/Zetascrub/net-link/internal/scanner"
	"github.com/Zetascrub/net-link/internal/store"
	"github.com/Zetascrub/net-link/internal/targets"
)

const (
	maxConcurrency = 1024
	maxTimeout     = 10 * time.Minute
)

func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "test":
		return runTest(ctx, args[1:])
	case "discover":
		return runDiscover(ctx, args[1:])
	case "link":
		return runLink(ctx, args[1:])
	case "scan":
		return runScan(ctx, args[1:])
	case "report":
		return runReport(args[1:])
	case "version":
		fmt.Println(model.Version)
		return 0
	case "help", "-h", "--help":
		printUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		printUsage()
		return 2
	}
}

func runLink(ctx context.Context, args []string) int {
	if len(args) == 0 {
		printLinkUsage()
		return 2
	}

	switch args[0] {
	case "listen":
		return runLinkListen(ctx, args[1:])
	case "discover":
		return runLinkDiscover(ctx, args[1:])
	case "matrix":
		return runLinkMatrix(ctx, args[1:])
	case "help", "-h", "--help":
		printLinkUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown link command %q\n\n", args[0])
		printLinkUsage()
		return 2
	}
}

func runLinkListen(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"allow-remote-checks": true,
	}, map[string]bool{
		"name":           true,
		"bind-address":   true,
		"discovery-port": true,
		"link-port":      true,
		"remote-scope":   true,
		"remote-ports":   true,
	})
	fs := flag.NewFlagSet("link listen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "peer name")
	bindAddress := fs.String("bind-address", "0.0.0.0", "IPv4 address on which to listen")
	discoveryPort := fs.Int("discovery-port", link.DefaultDiscoveryPort, "UDP discovery port")
	linkPort := fs.Int("link-port", link.DefaultLinkPort, "TCP link verification port")
	allowRemoteChecks := fs.Bool("allow-remote-checks", false, "allow unauthenticated peers to request service checks (unsafe)")
	remoteScope := fs.String("remote-scope", "", "comma-separated internal CIDRs allowed for remote checks")
	remotePortsInput := fs.String("remote-ports", "", "ports allowed for remote checks")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link link listen [--name pager] [--bind-address 192.168.1.10] [--allow-remote-checks]")
		return 2
	}
	if err := validateLinkOptions(*discoveryPort, *linkPort, time.Second); err != nil {
		return fail(err)
	}
	remotePorts, err := targets.ParsePorts(*remotePortsInput)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(os.Stderr, "WARNING: link mode is experimental and unauthenticated; use only on networks you control.")

	if err := link.Listen(ctx, link.ListenOptions{
		Name:              *name,
		BindAddress:       *bindAddress,
		DiscoveryPort:     *discoveryPort,
		LinkPort:          *linkPort,
		AllowRemoteChecks: *allowRemoteChecks,
		RemoteScopes:      splitScopes(*remoteScope),
		RemotePorts:       remotePorts,
	}, os.Stdout); err != nil && ctx.Err() == nil {
		return fail(err)
	}
	return 0
}

func runLinkDiscover(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"json": true,
	}, map[string]bool{
		"name":           true,
		"discovery-port": true,
		"link-port":      true,
		"timeout":        true,
		"out":            true,
		"remote-scope":   true,
		"remote-ports":   true,
	})
	fs := flag.NewFlagSet("link discover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "local peer name")
	discoveryPort := fs.Int("discovery-port", link.DefaultDiscoveryPort, "UDP discovery port")
	linkPort := fs.Int("link-port", link.DefaultLinkPort, "local TCP link port advertised in probes")
	timeoutInput := fs.Duration("timeout", 3*time.Second, "discovery timeout")
	out := fs.String("out", "", "write full JSON link evidence to this path")
	jsonOut := fs.Bool("json", false, "print full JSON link evidence to stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link link discover")
		return 2
	}
	if err := validateLinkOptions(*discoveryPort, *linkPort, *timeoutInput); err != nil {
		return fail(err)
	}

	started := time.Now().UTC()
	opts := link.DiscoverOptions{
		Name:          *name,
		DiscoveryPort: *discoveryPort,
		LinkPort:      *linkPort,
		Timeout:       *timeoutInput,
	}
	links, err := link.Discover(ctx, opts)
	if err != nil {
		return fail(err)
	}
	local, err := link.LocalPeer(*name, *discoveryPort, *linkPort)
	if err != nil {
		return fail(err)
	}
	run := link.NewDiscoveryRun("link discover "+strings.Join(args, " "), local, links, started)
	printLinks(links)
	if err := writeJSONOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runLinkMatrix(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"json":                true,
		"allow-remote-checks": true,
	}, map[string]bool{
		"name":           true,
		"discovery-port": true,
		"link-port":      true,
		"timeout":        true,
		"ports":          true,
		"out":            true,
	})
	fs := flag.NewFlagSet("link matrix", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "local peer name")
	discoveryPort := fs.Int("discovery-port", link.DefaultDiscoveryPort, "UDP discovery port")
	linkPort := fs.Int("link-port", link.DefaultLinkPort, "local TCP link port")
	timeoutInput := fs.Duration("timeout", 3*time.Second, "matrix timeout")
	portsInput := fs.String("ports", "22,80,443,47889", "comma-separated ports or ranges")
	out := fs.String("out", "", "write full JSON matrix evidence to this path")
	jsonOut := fs.Bool("json", false, "print full JSON matrix evidence to stdout")
	allowRemoteChecks := fs.Bool("allow-remote-checks", false, "allow unauthenticated peers to request checks from this temporary responder (unsafe)")
	remoteScope := fs.String("remote-scope", "", "comma-separated internal CIDRs allowed for remote checks")
	remotePortsInput := fs.String("remote-ports", "", "ports allowed for remote checks")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link link matrix [--ports 22,80,443,47889]")
		return 2
	}
	if err := validateLinkOptions(*discoveryPort, *linkPort, *timeoutInput); err != nil {
		return fail(err)
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}
	remotePorts, err := targets.ParsePorts(*remotePortsInput)
	if err != nil {
		return fail(err)
	}
	started := time.Now().UTC()
	opts := link.MatrixOptions{
		Name:              *name,
		DiscoveryPort:     *discoveryPort,
		LinkPort:          *linkPort,
		Timeout:           *timeoutInput,
		Ports:             ports,
		AllowRemoteChecks: *allowRemoteChecks,
		RemoteScopes:      splitScopes(*remoteScope),
		RemotePorts:       remotePorts,
	}
	matrices, err := link.Matrix(ctx, opts)
	if err != nil {
		return fail(err)
	}
	local, err := link.LocalPeer(*name, *discoveryPort, *linkPort)
	if err != nil {
		return fail(err)
	}
	run := link.NewMatrixRun("link matrix "+strings.Join(args, " "), local, ports, matrices, started)
	printMatrices(matrices)
	if err := writeJSONOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runDiscover(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"allow-public":   true,
		"json":           true,
		"dry-run":        true,
		"auto":           true,
		"include-routes": true,
	}, map[string]bool{
		"scope":             true,
		"ports":             true,
		"out":               true,
		"timeout":           true,
		"concurrency":       true,
		"max-hosts":         true,
		"max-total-hosts":   true,
		"interface":         true,
		"exclude-interface": true,
	})
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scope := fs.String("scope", "", "comma-separated IPv4 CIDR scopes; defaults to local private networks")
	auto := fs.Bool("auto", false, "automatically discover private scopes from active interfaces")
	includeRoutes := fs.Bool("include-routes", false, "include private non-default routes (requires --auto)")
	interfaces := fs.String("interface", "", "comma-separated interfaces to include in auto discovery")
	excludeInterfaces := fs.String("exclude-interface", "", "comma-separated interfaces to exclude")
	portsInput := fs.String("ports", "22,80,443,8080,8443", "comma-separated ports or ranges")
	out := fs.String("out", "", "write full JSON results to this path")
	jsonOut := fs.Bool("json", false, "print full JSON results to stdout")
	timeoutInput := fs.Duration("timeout", 500*time.Millisecond, "TCP connect timeout")
	concurrency := fs.Int("concurrency", 256, "maximum concurrent probes")
	maxHosts := fs.Int("max-hosts", 1024, "maximum addresses allowed per CIDR scope")
	maxTotalHosts := fs.Int("max-total-hosts", 4096, "maximum unique addresses across automatic scopes")
	allowPublic := fs.Bool("allow-public", false, "allow public IP targets")
	dryRun := fs.Bool("dry-run", false, "print scope and target count without running probes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link discover [--scope 192.168.1.0/24] [--ports 22,80,443]")
		return 2
	}
	if *auto && strings.TrimSpace(*scope) != "" {
		return fail(fmt.Errorf("--auto and --scope cannot be used together"))
	}
	if *includeRoutes && !*auto {
		return fail(fmt.Errorf("--include-routes requires --auto"))
	}
	if err := validateProbeOptions(*timeoutInput, *concurrency); err != nil {
		return fail(err)
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}

	var targetList []model.Target
	var scopes []string
	if strings.TrimSpace(*scope) == "" {
		if *auto {
			scopes, err = targets.AutoPrivateIPv4Networks(targets.AutoNetworkOptions{
				IncludeInterfaces: splitScopes(*interfaces),
				ExcludeInterfaces: splitScopes(*excludeInterfaces),
				ExcludeVirtual:    true,
				IncludeRoutes:     *includeRoutes,
			})
			if err == nil && len(scopes) == 0 {
				err = fmt.Errorf("automatic discovery found no private IPv4 networks")
			}
			if err == nil {
				targetList, err = targets.FromNetworks(scopes, ports, *maxHosts, *maxTotalHosts)
			}
		} else {
			targetList, scopes, err = targets.FromLocalNetworks(ports, *maxHosts)
		}
	} else {
		scopes = splitScopes(*scope)
		targetList, err = targets.FromCIDRList(*scope, ports, *maxHosts, *allowPublic)
	}
	if err != nil {
		return fail(err)
	}
	if len(targetList) == 0 {
		return fail(fmt.Errorf("no discovery targets generated"))
	}

	if *dryRun {
		if *auto {
			fmt.Fprintf(os.Stderr, "Automatic scope discovery: interfaces=%s excluded=%s routes=%t\n",
				valueOrDefault(*interfaces, "active physical"), valueOrDefault(*excludeInterfaces, "virtual defaults"), *includeRoutes)
		}
		fmt.Fprintf(os.Stderr, "Dry run: %d scope(s), %d target(s), %d port(s)\n",
			len(scopes), len(targetList), len(ports))
		fmt.Fprintf(os.Stderr, "Scopes: %s\n", strings.Join(scopes, ", "))
		fmt.Fprintf(os.Stderr, "Ports:  %s\n", *portsInput)
		return 0
	}

	fmt.Fprintf(os.Stderr, "Discovery scopes: %s\n", strings.Join(scopes, ", "))
	run := runner.Run(ctx, runner.Options{
		Command:     "discover " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stderr, run)
	if err := writeRunOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func runTest(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"allow-public": true,
		"json":         true,
		"dry-run":      true,
	}, map[string]bool{
		"ports":       true,
		"nmap":        true,
		"out":         true,
		"timeout":     true,
		"concurrency": true,
	})
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	portsInput := fs.String("ports", "", "comma-separated ports or ranges, for example 22,80,443 or 1-1024")
	nmapFile := fs.String("nmap", "", "parse targets from Nmap XML")
	out := fs.String("out", "", "write full JSON results to this path")
	jsonOut := fs.Bool("json", false, "print full JSON results to stdout")
	timeoutInput := fs.Duration("timeout", 2*time.Second, "TCP connect timeout")
	concurrency := fs.Int("concurrency", 64, "maximum concurrent probes")
	allowPublic := fs.Bool("allow-public", false, "allow public IP targets")
	dryRun := fs.Bool("dry-run", false, "print targets without running probes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := validateProbeOptions(*timeoutInput, *concurrency); err != nil {
		return fail(err)
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}

	var targetList []model.Target
	if *nmapFile != "" {
		targetList, err = scanner.ParseNmapXMLFile(*nmapFile, *allowPublic)
	} else {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: net-link test <target> [--ports 22,80,443]")
			return 2
		}
		targetList, err = targets.FromHost(fs.Arg(0), ports, *allowPublic)
	}
	if err != nil {
		return fail(err)
	}
	if len(targetList) == 0 {
		return fail(fmt.Errorf("no targets to test"))
	}

	if *dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: %d target(s)\n", len(targetList))
		for _, t := range targetList {
			fmt.Fprintf(os.Stderr, "  %s:%d/%s\n", t.Host, t.Port, t.Protocol)
		}
		return 0
	}

	run := runner.Run(ctx, runner.Options{
		Command:     "test " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stderr, run)
	if err := writeRunOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runScan(ctx context.Context, args []string) int {
	args = reorderFlags(args, map[string]bool{
		"allow-public": true,
		"json":         true,
		"dry-run":      true,
	}, map[string]bool{
		"scanner":     true,
		"ports":       true,
		"out":         true,
		"timeout":     true,
		"concurrency": true,
	})
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scannerName := fs.String("scanner", "nmap", "scanner backend: nmap")
	portsInput := fs.String("ports", "", "comma-separated ports or ranges")
	out := fs.String("out", "", "write full JSON results to this path")
	jsonOut := fs.Bool("json", false, "print full JSON results to stdout")
	timeoutInput := fs.Duration("timeout", 2*time.Second, "TCP connect timeout")
	concurrency := fs.Int("concurrency", 64, "maximum concurrent probes")
	allowPublic := fs.Bool("allow-public", false, "allow public IP targets")
	dryRun := fs.Bool("dry-run", false, "print what nmap would scan without executing")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: net-link scan <target-or-cidr> [--scanner nmap]")
		return 2
	}
	if err := validateProbeOptions(*timeoutInput, *concurrency); err != nil {
		return fail(err)
	}
	if *scannerName != "nmap" {
		return fail(fmt.Errorf("scanner %q is not implemented yet", *scannerName))
	}

	if *dryRun {
		portsDesc := "default"
		if *portsInput != "" {
			portsDesc = *portsInput
		}
		fmt.Fprintf(os.Stderr, "Dry run: nmap %s ports=%s\n", fs.Arg(0), portsDesc)
		return 0
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}
	targetList, err := scanner.RunNmap(ctx, fs.Arg(0), ports, *allowPublic)
	if err != nil {
		return fail(err)
	}
	if len(targetList) == 0 {
		return fail(fmt.Errorf("nmap found no open tcp targets"))
	}

	run := runner.Run(ctx, runner.Options{
		Command:     "scan " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stderr, run)
	if err := writeRunOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runReport(args []string) int {
	args = reorderFlags(args, nil, map[string]bool{
		"format": true,
		"out":    true,
	})
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "markdown", "report format: markdown")
	out := fs.String("out", "-", "output report path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: net-link report <run.nljson> [--format markdown]")
		return 2
	}
	if *format != "markdown" {
		return fail(fmt.Errorf("report format %q is not implemented yet", *format))
	}
	run, err := store.ReadRun(fs.Arg(0))
	if err != nil {
		return fail(err)
	}
	if err := report.WriteMarkdown(*out, run); err != nil {
		return fail(err)
	}
	return 0
}

func printSummary(run model.Run) {
	fmt.Fprintf(os.Stderr, "Net-Link run %s\n", run.ID)
	fmt.Fprintf(os.Stderr, "Targets: %d  Reachable: %d  Refused: %d  Timed out: %d  Canceled: %d  Blocked: %d  Denied: %d  Errors: %d\n",
		run.Summary.Targets,
		run.Summary.Reachable,
		run.Summary.Refused,
		run.Summary.TimedOut,
		run.Summary.Canceled,
		run.Summary.Blocked,
		run.Summary.Denied,
		run.Summary.Errors,
	)
}

func printReachable(out *os.File, run model.Run) {
	grouped := map[string][]int{}
	for _, result := range run.Results {
		if result.State == model.StateReachable {
			grouped[result.Host] = append(grouped[result.Host], result.Port)
		}
	}
	if len(grouped) == 0 {
		return
	}

	fmt.Fprintln(out, "Reachable:")
	hosts := make([]string, 0, len(grouped))
	for host := range grouped {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		ports := uniqueSortedInts(grouped[host])
		fmt.Fprintf(out, "  %-15s %s\n", host, joinInts(ports))
	}
}

func writeRunOutput(path string, jsonOut bool, run model.Run) error {
	if jsonOut {
		return store.WriteJSON("-", run)
	}
	if path == "" {
		return nil
	}
	return store.WriteRun(path, run)
}

func writeJSONOutput(path string, jsonOut bool, value any) error {
	if jsonOut {
		return store.WriteJSON("-", value)
	}
	if path == "" {
		return nil
	}
	return store.WriteJSON(path, value)
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}

func printUsage() {
	fmt.Fprint(os.Stderr, `net-link validates network segmentation from one or more vantage points.

Usage:
  net-link link listen [--name pager]
  net-link link discover [--out links.nljson]
  net-link link matrix [--ports 22,80,443,47889] [--out matrix.nljson]
  net-link discover [--scope 192.168.1.0/24] [--ports 22,80,443]
  net-link discover --auto [--include-routes] [--interface eth0]
  net-link test <target> [--ports 22,80,443]
  net-link test --nmap scan.xml
  net-link scan <target-or-cidr> --scanner nmap
  net-link report <run.nljson> --format markdown [--out report.md]
  net-link version

Output:
  Human summaries are printed by default. Use --out run.nljson to save full JSON,
  or --json to print full JSON to stdout.

Safety:
  Public IP targets are blocked by default. Use --allow-public to override.
  Use --dry-run on any command to preview targets without executing probes.
  Link mode is experimental and unauthenticated. Remote checks are disabled by
  default; --allow-remote-checks is an unsafe opt-in for controlled networks.

`)
}

func printLinkUsage() {
	fmt.Fprint(os.Stderr, `net-link peer mode is EXPERIMENTAL and discovers other Net-Link instances.

The protocol is unauthenticated. Remote service checks are disabled by default.
Enabling them also requires explicit --remote-scope and --remote-ports policy.
Only use these options on networks you control.

Usage:
  net-link link listen [--name pager] [--bind-address 192.168.1.10]
                       [--allow-remote-checks --remote-scope 192.168.1.0/24
                        --remote-ports 22,80,443]
  net-link link discover [--out links.nljson]
  net-link link matrix [--ports 22,80,443,47889] [--out matrix.nljson]
                       [--allow-remote-checks --remote-scope 192.168.1.0/24
                        --remote-ports 22,80,443]

`)
}

func printLinks(links []link.Link) {
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "No Net-Link peers found.")
		return
	}

	fmt.Fprintf(os.Stderr, "Net-Link peers: %d\n", len(links))
	for _, item := range links {
		state := "failed"
		if item.Linked && item.ReverseLinked {
			state = "linked_both_ways"
		} else if item.Linked {
			state = "linked_one_way"
		}

		fmt.Fprintf(os.Stderr, "  %s at %s:%d  %s  %s\n",
			item.Peer.Name,
			item.Address,
			item.Peer.LinkPort,
			state,
			item.Duration.String(),
		)
		if len(item.Peer.Addresses) > 0 {
			fmt.Fprintf(os.Stderr, "    addresses: %s\n", strings.Join(item.Peer.Addresses, ", "))
		}
		if item.Error != "" {
			fmt.Fprintf(os.Stderr, "    error: %s\n", item.Error)
		}
		if item.ReverseError != "" {
			fmt.Fprintf(os.Stderr, "    reverse: %s\n", item.ReverseError)
		}
	}
}

func printMatrices(matrices []link.ServiceMatrix) {
	if len(matrices) == 0 {
		fmt.Fprintln(os.Stderr, "No Net-Link peers found.")
		return
	}

	for _, matrix := range matrices {
		fmt.Fprintf(os.Stderr, "Peer: %s\n", matrix.Peer.Name)
		if matrix.RequestError != "" {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", matrix.RequestError)
		}
		printServiceResults("  local -> peer", matrix.LocalToPeer)
		printServiceResults("  peer  -> local", matrix.PeerToLocal)
	}
}

func printServiceResults(label string, results []link.ServiceResult) {
	grouped := map[string][]int{}
	for _, result := range results {
		if result.State == model.StateReachable {
			grouped[result.Target.Host] = append(grouped[result.Target.Host], result.Target.Port)
		}
	}
	fmt.Fprintln(os.Stderr, label)
	if len(grouped) == 0 {
		fmt.Fprintln(os.Stderr, "    no reachable services")
		return
	}
	hosts := make([]string, 0, len(grouped))
	for host := range grouped {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		fmt.Fprintf(os.Stderr, "    %-15s %s\n", host, joinInts(uniqueSortedInts(grouped[host])))
	}
}

func uniqueSortedInts(values []int) []int {
	sort.Ints(values)
	out := values[:0]
	last := 0
	for i, value := range values {
		if i == 0 || value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ",")
}

func splitScopes(input string) []string {
	var scopes []string
	for _, scope := range strings.Split(input, ",") {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

func validateProbeOptions(timeout time.Duration, concurrency int) error {
	if timeout <= 0 || timeout > maxTimeout {
		return fmt.Errorf("timeout must be greater than zero and at most %s", maxTimeout)
	}
	if concurrency < 1 || concurrency > maxConcurrency {
		return fmt.Errorf("concurrency must be between 1 and %d", maxConcurrency)
	}
	return nil
}

func validateLinkOptions(discoveryPort, linkPort int, timeout time.Duration) error {
	if discoveryPort < 1 || discoveryPort > 65535 {
		return fmt.Errorf("discovery port must be between 1 and 65535")
	}
	if linkPort < 1 || linkPort > 65535 {
		return fmt.Errorf("link port must be between 1 and 65535")
	}
	if timeout <= 0 || timeout > maxTimeout {
		return fmt.Errorf("timeout must be greater than zero and at most %s", maxTimeout)
	}
	return nil
}

func reorderFlags(args []string, boolFlags map[string]bool, valueFlags map[string]bool) []string {
	var flags []string
	var positionals []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			positionals = append(positionals, arg)
			continue
		}

		name := strings.TrimPrefix(arg, "--")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}

		flags = append(flags, arg)
		if strings.Contains(arg, "=") || boolFlags[name] {
			continue
		}
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}

	return append(flags, positionals...)
}
