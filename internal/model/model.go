package model

import (
	"encoding/json"
	"fmt"
	"time"
)

var (
	Version     = "0.2.1-dev"
	BuildCommit = "unknown"
	BuildDate   = "unknown"
)

// Duration wraps time.Duration with human-readable JSON serialization ("142ms").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// Support legacy nanosecond integer format.
		var n int64
		if err2 := json.Unmarshal(b, &n); err2 != nil {
			return err
		}
		*d = Duration(n)
		return nil
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(dur)
	return nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

type Run struct {
	ID        string    `json:"id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Duration  Duration  `json:"duration"`
	Command   string    `json:"command"`
	Sources   []Node    `json:"sources"`
	Targets   []Target  `json:"targets"`
	Results   []Result  `json:"results"`
	Summary   Summary   `json:"summary"`
}

type Node struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Addresses   []string `json:"addresses,omitempty"`
	BuildCommit string   `json:"build_commit,omitempty"`
	BuildDate   string   `json:"build_date,omitempty"`
}

type Target struct {
	ID       string       `json:"id"`
	Host     string       `json:"host"`
	Port     int          `json:"port"`
	Protocol string       `json:"protocol"`
	Service  string       `json:"service,omitempty"`
	Source   TargetSource `json:"source"`
}

type TargetSource struct {
	Type string `json:"type"`
	File string `json:"file,omitempty"`
}

type Result struct {
	ID           string            `json:"id"`
	RunID        string            `json:"run_id"`
	SourceNodeID string            `json:"source_node_id"`
	TargetID     string            `json:"target_id"`
	Host         string            `json:"host"`
	Port         int               `json:"port"`
	Protocol     string            `json:"protocol"`
	Probe        string            `json:"probe"`
	State        string            `json:"state"`
	StartedAt    time.Time         `json:"started_at"`
	Duration     Duration          `json:"duration"`
	Error        string            `json:"error,omitempty"`
	Evidence     map[string]string `json:"evidence,omitempty"`
}

type Summary struct {
	Targets     int `json:"targets"`
	Reachable   int `json:"reachable"`
	Refused     int `json:"refused"`
	TimedOut    int `json:"timed_out"`
	Canceled    int `json:"canceled"`
	Blocked     int `json:"blocked"`
	Unsupported int `json:"unsupported"`
	Denied      int `json:"permission_denied"`
	Errors      int `json:"errors"`
}

const (
	StateReachable        = "reachable"
	StateRefused          = "refused"
	StateTimedOut         = "timed_out"
	StateCanceled         = "canceled"
	StateBlocked          = "blocked"
	StateUnsupported      = "unsupported"
	StatePermissionDenied = "permission_denied"
	StateError            = "error"
	ProbeTCPConnect       = "tcp_connect"
	ProtocolTCP           = "tcp"
	SourceManual          = "manual"
	SourceDiscovery       = "discovery"
	SourceNmapXML         = "nmap_xml"
	SourceNmapExecution   = "nmap_execution"
	DefaultLocalNodeID    = "node_local"
	DefaultLocalNodeName  = "local"
)
