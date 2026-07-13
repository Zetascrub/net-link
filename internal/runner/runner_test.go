package runner

import (
	"context"
	"testing"
	"time"

	"github.com/Zetascrub/net-link/internal/model"
)

type canceledProbe struct{}

func (canceledProbe) Run(ctx context.Context, runID, sourceNodeID string, target model.Target) model.Result {
	<-ctx.Done()
	return model.Result{RunID: runID, SourceNodeID: sourceNodeID, TargetID: target.ID}
}

func TestRunStopsDispatchingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	targets := make([]model.Target, 10_000)
	for i := range targets {
		targets[i] = model.Target{Protocol: model.ProtocolTCP}
	}

	started := time.Now()
	run := Run(ctx, Options{Concurrency: 4, Probe: canceledProbe{}}, targets)
	if time.Since(started) > time.Second {
		t.Fatal("Run did not return promptly after cancellation")
	}
	if len(run.Results) >= len(targets) {
		t.Fatalf("processed %d cancelled targets; dispatch did not stop", len(run.Results))
	}
}
