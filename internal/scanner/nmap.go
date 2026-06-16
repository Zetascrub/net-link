package scanner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/policy"
)

func RunNmap(ctx context.Context, target string, ports []int, allowPublic bool) ([]model.Target, error) {
	if err := policy.CheckTargetAllowed(target, allowPublic); err != nil {
		return nil, err
	}

	args := []string{"-oX", "-"}
	if len(ports) > 0 {
		args = append(args, "-p", portsArg(ports))
	}
	args = append(args, target)

	runCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "nmap", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("nmap failed: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("nmap failed: %w", err)
	}
	return ParseNmapXML(stdout.Bytes(), "nmap:-", allowPublic)
}

func portsArg(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, ",")
}
