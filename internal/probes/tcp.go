package probes

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/Zetascrub/net-link/internal/ids"
	"github.com/Zetascrub/net-link/internal/model"
)

type TCPConnect struct {
	Timeout time.Duration
}

func (p TCPConnect) Run(ctx context.Context, runID string, sourceNodeID string, target model.Target) model.Result {
	started := time.Now().UTC()
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	result := model.Result{
		ID:           ids.New("probe"),
		RunID:        runID,
		SourceNodeID: sourceNodeID,
		TargetID:     target.ID,
		Host:         target.Host,
		Port:         target.Port,
		Protocol:     target.Protocol,
		Probe:        model.ProbeTCPConnect,
		StartedAt:    started,
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	result.Duration = model.Duration(time.Since(started))
	if err != nil {
		result.State = ClassifyConnectError(err)
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	result.State = model.StateReachable
	result.Evidence = map[string]string{
		"local_addr":  conn.LocalAddr().String(),
		"remote_addr": conn.RemoteAddr().String(),
	}
	return result
}
