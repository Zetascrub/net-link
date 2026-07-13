package runner

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Zetascrub/net-link/internal/ids"
	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/probes"
)

type Options struct {
	Command     string
	Timeout     time.Duration
	Concurrency int
	// Probe selects the probe implementation. Defaults to TCPConnect when nil.
	Probe probes.Probe
}

func Run(ctx context.Context, opts Options, targets []model.Target) model.Run {
	started := time.Now().UTC()
	runID := ids.New("run")
	node := model.Node{
		ID:          model.DefaultLocalNodeID,
		Name:        hostname(),
		Version:     model.Version,
		BuildCommit: model.BuildCommit,
		BuildDate:   model.BuildDate,
	}

	probe := opts.Probe
	if probe == nil {
		probe = probes.TCPConnect{Timeout: opts.Timeout}
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 64
	}

	results := make([]model.Result, 0, len(targets))
	resultCh := make(chan model.Result)
	workCh := make(chan model.Target)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range workCh {
				var result model.Result
				if strings.ToLower(target.Protocol) != model.ProtocolTCP {
					result = unsupported(runID, node.ID, target)
				} else {
					result = probe.Run(ctx, runID, node.ID, target)
				}
				select {
				case resultCh <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(workCh)
		for _, target := range targets {
			select {
			case workCh <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		results = append(results, result)
	}

	ended := time.Now().UTC()
	run := model.Run{
		ID:        runID,
		StartedAt: started,
		EndedAt:   ended,
		Duration:  model.Duration(ended.Sub(started)),
		Command:   opts.Command,
		Sources:   []model.Node{node},
		Targets:   targets,
		Results:   results,
	}
	run.Summary = summarize(results, len(targets))
	return run
}

func unsupported(runID string, sourceNodeID string, target model.Target) model.Result {
	return model.Result{
		ID:           ids.New("probe"),
		RunID:        runID,
		SourceNodeID: sourceNodeID,
		TargetID:     target.ID,
		Host:         target.Host,
		Port:         target.Port,
		Protocol:     target.Protocol,
		Probe:        model.ProbeTCPConnect,
		State:        model.StateUnsupported,
		StartedAt:    time.Now().UTC(),
		Error:        "only tcp targets are supported in this build slice",
	}
}

func summarize(results []model.Result, targetCount int) model.Summary {
	summary := model.Summary{Targets: targetCount}
	for _, result := range results {
		switch result.State {
		case model.StateReachable:
			summary.Reachable++
		case model.StateRefused:
			summary.Refused++
		case model.StateTimedOut:
			summary.TimedOut++
		case model.StateCanceled:
			summary.Canceled++
		case model.StateBlocked:
			summary.Blocked++
		case model.StateUnsupported:
			summary.Unsupported++
		case model.StatePermissionDenied:
			summary.Denied++
		default:
			summary.Errors++
		}
	}
	return summary
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return model.DefaultLocalNodeName
	}
	return name
}
