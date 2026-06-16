package probes

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/Zetascrub/net-link/internal/model"
)

// Probe runs a connectivity check against a single target and returns a result.
type Probe interface {
	Run(ctx context.Context, runID, sourceNodeID string, target model.Target) model.Result
}

// ClassifyConnectError maps a dial/connect error to a model state string.
func ClassifyConnectError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || errors.Is(err, os.ErrDeadlineExceeded) {
		return model.StateTimedOut
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return model.StateTimedOut
	}

	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "connection refused"):
		return model.StateRefused
	case strings.Contains(text, "i/o timeout"), strings.Contains(text, "timed out"):
		return model.StateTimedOut
	case strings.Contains(text, "operation not permitted"), strings.Contains(text, "permission denied"):
		return model.StatePermissionDenied
	case strings.Contains(text, "network is unreachable"), strings.Contains(text, "no route to host"), strings.Contains(text, "host is down"):
		return model.StateBlocked
	}

	return model.StateError
}
