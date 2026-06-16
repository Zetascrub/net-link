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

func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}

	switch args[0] {
	case "test":
		return runTest(args[1:])
	case "discover":
		return runDiscover(args[1:])
	case "link":
		return runLink(args[1:])
	case "scan":
		return runScan(args[1:])
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

func runLink(args []string) int {
	if len(args) == 0 {
		printLinkUsage()
		return 2
	}

	switch args[0] {
	case "listen":
		return runLinkListen(args[1:])
	case "discover":
		return runLinkDiscover(args[1:])
	case "matrix":
		return runLinkMatrix(args[1:])
	case "help", "-h", "--help":
		printLinkUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown link command %q\n\n", args[0])
		printLinkUsage()
		return 2
	}
}

func runLinkListen(args []string) int {
	args = reorderFlags(args, nil, map[string]bool{
		"name":           true,
		"discovery-port": true,
		"link-port":      true,
	})
	fs := flag.NewFlagSet("link listen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	name := fs.String("name", "", "peer name")
	discoveryPort := fs.Int("discovery-port", link.DefaultDiscoveryPort, "UDP discovery port")
	linkPort := fs.Int("link-port", link.DefaultLinkPort, "TCP link verification port")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link link listen [--name pager]")
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := link.Listen(ctx, link.ListenOptions{
		Name:          *name,
		DiscoveryPort: *discoveryPort,
		LinkPort:      *linkPort,
	}, os.Stdout); err != nil && ctx.Err() == nil {
		return fail(err)
	}
	return 0
}

func runLinkDiscover(args []string) int {
	args = reorderFlags(args, map[string]bool{
		"json": true,
	}, map[string]bool{
		"name":           true,
		"discovery-port": true,
		"link-port":      true,
		"timeout":        true,
		"out":            true,
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

	started := time.Now().UTC()
	opts := link.DiscoverOptions{
		Name:          *name,
		DiscoveryPort: *discoveryPort,
		LinkPort:      *linkPort,
		Timeout:       *timeoutInput,
	}
	links, err := link.Discover(context.Background(), opts)
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

func runLinkMatrix(args []string) int {
	args = reorderFlags(args, map[string]bool{
		"json": true,
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link link matrix [--ports 22,80,443,47889]")
		return 2
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}
	started := time.Now().UTC()
	opts := link.MatrixOptions{
		Name:          *name,
		DiscoveryPort: *discoveryPort,
		LinkPort:      *linkPort,
		Timeout:       *timeoutInput,
		Ports:         ports,
	}
	matrices, err := link.Matrix(context.Background(), opts)
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

func runDiscover(args []string) int {
	args = reorderFlags(args, map[string]bool{
		"allow-public": true,
		"json":         true,
		"dry-run":      true,
	}, map[string]bool{
		"scope":       true,
		"ports":       true,
		"out":         true,
		"timeout":     true,
		"concurrency": true,
		"max-hosts":   true,
	})
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scope := fs.String("scope", "", "comma-separated IPv4 CIDR scopes; defaults to local private networks")
	portsInput := fs.String("ports", "22,80,443,8080,8443", "comma-separated ports or ranges")
	out := fs.String("out", "", "write full JSON results to this path")
	jsonOut := fs.Bool("json", false, "print full JSON results to stdout")
	timeoutInput := fs.Duration("timeout", 500*time.Millisecond, "TCP connect timeout")
	concurrency := fs.Int("concurrency", 256, "maximum concurrent probes")
	maxHosts := fs.Int("max-hosts", 1024, "maximum addresses allowed per CIDR scope")
	allowPublic := fs.Bool("allow-public", false, "allow public IP targets")
	dryRun := fs.Bool("dry-run", false, "print scope and target count without running probes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: net-link discover [--scope 192.168.1.0/24] [--ports 22,80,443]")
		return 2
	}

	ports, err := targets.ParsePorts(*portsInput)
	if err != nil {
		return fail(err)
	}

	var targetList []model.Target
	var scopes []string
	if strings.TrimSpace(*scope) == "" {
		targetList, scopes, err = targets.FromLocalNetworks(ports, *maxHosts)
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
		fmt.Fprintf(os.Stderr, "Dry run: %d scope(s), %d target(s), %d port(s)\n",
			len(scopes), len(targetList), len(ports))
		fmt.Fprintf(os.Stderr, "Scopes: %s\n", strings.Join(scopes, ", "))
		fmt.Fprintf(os.Stderr, "Ports:  %s\n", *portsInput)
		return 0
	}

	fmt.Fprintf(os.Stderr, "Discovery scopes: %s\n", strings.Join(scopes, ", "))
	run := runner.Run(context.Background(), runner.Options{
		Command:     "discover " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stdout, run)
	if err := writeRunOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runTest(args []string) int {
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

	run := runner.Run(context.Background(), runner.Options{
		Command:     "test " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stdout, run)
	if err := writeRunOutput(*out, *jsonOut, run); err != nil {
		return fail(err)
	}
	return 0
}

func runScan(args []string) int {
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
	targetList, err := scanner.RunNmap(context.Background(), fs.Arg(0), ports, *allowPublic)
	if err != nil {
		return fail(err)
	}
	if len(targetList) == 0 {
		return fail(fmt.Errorf("nmap found no open tcp targets"))
	}

	run := runner.Run(context.Background(), runner.Options{
		Command:     "scan " + strings.Join(args, " "),
		Timeout:     *timeoutInput,
		Concurrency: *concurrency,
	}, targetList)
	printSummary(run)
	printReachable(os.Stdout, run)
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
	fmt.Fprintf(os.Stderr, "Targets: %d  Reachable: %d  Refused: %d  Timed out: %d  Blocked: %d  Denied: %d  Errors: %d\n",
		run.Summary.Targets,
		run.Summary.Reachable,
		run.Summary.Refused,
		run.Summary.TimedOut,
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

`)
}

func printLinkUsage() {
	fmt.Fprint(os.Stderr, `net-link peer mode discovers and verifies other Net-Link instances.

Usage:
  net-link link listen [--name pager]
  net-link link discover [--out links.nljson]
  net-link link matrix [--ports 22,80,443,47889] [--out matrix.nljson]

`)
}

func printLinks(links []link.Link) {
	if len(links) == 0 {
		fmt.Println("No Net-Link peers found.")
		return
	}

	fmt.Printf("Net-Link peers: %d\n", len(links))
	for _, item := range links {
		state := "failed"
		if item.Linked && item.ReverseLinked {
			state = "linked_both_ways"
		} else if item.Linked {
			state = "linked_one_way"
		}

		fmt.Printf("  %s at %s:%d  %s  %s\n",
			item.Peer.Name,
			item.Address,
			item.Peer.LinkPort,
			state,
			item.Duration.String(),
		)
		if len(item.Peer.Addresses) > 0 {
			fmt.Printf("    addresses: %s\n", strings.Join(item.Peer.Addresses, ", "))
		}
		if item.Error != "" {
			fmt.Printf("    error: %s\n", item.Error)
		}
		if item.ReverseError != "" {
			fmt.Printf("    reverse: %s\n", item.ReverseError)
		}
	}
}

func printMatrices(matrices []link.ServiceMatrix) {
	if len(matrices) == 0 {
		fmt.Println("No Net-Link peers found.")
		return
	}

	for _, matrix := range matrices {
		fmt.Printf("Peer: %s\n", matrix.Peer.Name)
		if matrix.RequestError != "" {
			fmt.Printf("  warning: %s\n", matrix.RequestError)
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
	fmt.Println(label)
	if len(grouped) == 0 {
		fmt.Println("    no reachable services")
		return
	}
	hosts := make([]string, 0, len(grouped))
	for host := range grouped {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		fmt.Printf("    %-15s %s\n", host, joinInts(uniqueSortedInts(grouped[host])))
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
