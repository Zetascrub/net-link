package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Zetascrub/net-link/internal/model"
)

func WriteMarkdown(path string, run model.Run) error {
	var w io.Writer
	var file *os.File
	if path == "" || path == "-" {
		w = os.Stdout
	} else {
		var err error
		file, err = os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
		w = file
	}

	sourceNames := map[string]string{}
	for _, source := range run.Sources {
		sourceNames[source.ID] = source.Name
	}

	// Sort results by host then port for consistent output.
	results := append([]model.Result(nil), run.Results...)
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})

	// --- Header ---
	fmt.Fprintf(w, "# Net-Link Report\n\n")
	fmt.Fprintf(w, "- Run ID: `%s`\n", run.ID)
	fmt.Fprintf(w, "- Started: `%s`\n", run.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "- Duration: `%s`\n", run.Duration.String())
	fmt.Fprintf(w, "- Command: `%s`\n\n", run.Command)

	// --- Sources ---
	fmt.Fprintf(w, "## Sources\n\n")
	for _, source := range run.Sources {
		fmt.Fprintf(w, "- `%s` (%s)\n", source.Name, source.ID)
	}
	fmt.Fprintln(w)

	// --- Summary table ---
	fmt.Fprintf(w, "## Summary\n\n")
	fmt.Fprintf(w, "| Targets | Reachable | Refused | Timed Out | Canceled | Blocked | Denied | Errors |\n")
	fmt.Fprintf(w, "| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	fmt.Fprintf(w, "| %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		run.Summary.Targets,
		run.Summary.Reachable,
		run.Summary.Refused,
		run.Summary.TimedOut,
		run.Summary.Canceled,
		run.Summary.Blocked,
		run.Summary.Denied,
		run.Summary.Errors,
	)

	// --- Reachable section ---
	var reachable []model.Result
	for _, r := range results {
		if r.State == model.StateReachable {
			reachable = append(reachable, r)
		}
	}

	fmt.Fprintf(w, "## Reachable Services\n\n")
	if len(reachable) == 0 {
		fmt.Fprintf(w, "_No reachable services._\n\n")
	} else {
		// Group reachable by host for a compact list.
		hostPorts := map[string][]string{}
		var hostOrder []string
		for _, r := range reachable {
			if _, seen := hostPorts[r.Host]; !seen {
				hostOrder = append(hostOrder, r.Host)
			}
			svc := fmt.Sprintf("%d/%s", r.Port, r.Protocol)
			if r.Protocol == "" {
				svc = fmt.Sprintf("%d", r.Port)
			}
			hostPorts[r.Host] = append(hostPorts[r.Host], svc)
		}
		for _, host := range hostOrder {
			fmt.Fprintf(w, "- `%s`: %s\n", host, strings.Join(hostPorts[host], ", "))
		}
		fmt.Fprintln(w)
	}

	// --- Full results table ---
	fmt.Fprintf(w, "## All Results\n\n")

	// Group by host.
	type hostGroup struct {
		host    string
		results []model.Result
	}
	groupMap := map[string]*hostGroup{}
	var groupOrder []string
	for _, r := range results {
		if _, ok := groupMap[r.Host]; !ok {
			groupMap[r.Host] = &hostGroup{host: r.Host}
			groupOrder = append(groupOrder, r.Host)
		}
		groupMap[r.Host].results = append(groupMap[r.Host].results, r)
	}

	for _, host := range groupOrder {
		g := groupMap[host]
		fmt.Fprintf(w, "### %s\n\n", g.host)
		fmt.Fprintf(w, "| Port | Protocol | Probe | State | Duration | Source | Evidence |\n")
		fmt.Fprintf(w, "| --- | --- | --- | --- | --- | --- | --- |\n")
		for _, r := range g.results {
			evidence := ""
			if len(r.Evidence) > 0 {
				evidence = "yes"
			}
			fmt.Fprintf(w, "| %d | %s | `%s` | `%s` | `%s` | `%s` | %s |\n",
				r.Port,
				r.Protocol,
				r.Probe,
				r.State,
				r.Duration.String(),
				sourceNames[r.SourceNodeID],
				evidence,
			)
		}
		fmt.Fprintln(w)
	}

	return nil
}
