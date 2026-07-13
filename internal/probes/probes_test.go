package probes

import (
	"context"
	"testing"

	"github.com/Zetascrub/net-link/internal/model"
)

func TestClassifyConnectErrorDistinguishesCancellation(t *testing.T) {
	if got := ClassifyConnectError(context.Canceled); got != model.StateCanceled {
		t.Fatalf("canceled state = %q, want %q", got, model.StateCanceled)
	}
	if got := ClassifyConnectError(context.DeadlineExceeded); got != model.StateTimedOut {
		t.Fatalf("deadline state = %q, want %q", got, model.StateTimedOut)
	}
}
