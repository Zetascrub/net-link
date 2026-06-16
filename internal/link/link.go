package link

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Zetascrub/net-link/internal/ids"
	"github.com/Zetascrub/net-link/internal/model"
	"github.com/Zetascrub/net-link/internal/probes"
)

const (
	DefaultDiscoveryPort = 47888
	DefaultLinkPort      = 47889
	protocolVersion      = "net-link/peer/v1"
	probeMessageType     = "probe"
	helloMessageType     = "hello"
	linkCheckMessageType = "link_check"
	reverseMessageType   = "reverse_check"
	serviceMessageType   = "service_check"
	serviceResultType    = "service_result"
	legacyLinkProbeLine  = "NET-LINK HELLO/1\n"
)

type Peer struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Addresses     []string `json:"addresses"`
	DiscoveryPort int      `json:"discovery_port"`
	LinkPort      int      `json:"link_port"`
}

type Link struct {
	Peer          Peer         `json:"peer"`
	Address       string       `json:"address"`
	Duration      model.Duration `json:"duration"`
	Discovered    time.Time    `json:"discovered_at"`
	Linked        bool         `json:"linked"`
	ReverseLinked bool         `json:"reverse_linked"`
	Error         string       `json:"error,omitempty"`
	ReverseError  string       `json:"reverse_error,omitempty"`
}

type ServiceTarget struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ServiceResult struct {
	Source    string         `json:"source"`
	Target    ServiceTarget  `json:"target"`
	State     string         `json:"state"`
	Duration  model.Duration `json:"duration"`
	Error     string         `json:"error,omitempty"`
	Direction string         `json:"direction"`
}

type ServiceMatrix struct {
	Peer         Peer            `json:"peer"`
	LocalToPeer  []ServiceResult `json:"local_to_peer"`
	PeerToLocal  []ServiceResult `json:"peer_to_local"`
	RequestError string          `json:"request_error,omitempty"`
}

type DiscoveryRun struct {
	ID        string         `json:"id"`
	StartedAt time.Time      `json:"started_at"`
	EndedAt   time.Time      `json:"ended_at"`
	Duration  model.Duration `json:"duration"`
	Command   string         `json:"command"`
	Local     Peer           `json:"local"`
	Links     []Link         `json:"links"`
	Summary   LinkSummary    `json:"summary"`
}

type MatrixRun struct {
	ID        string          `json:"id"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   time.Time       `json:"ended_at"`
	Duration  model.Duration  `json:"duration"`
	Command   string          `json:"command"`
	Local     Peer            `json:"local"`
	Ports     []int           `json:"ports"`
	Matrices  []ServiceMatrix `json:"matrices"`
	Summary   MatrixSummary   `json:"summary"`
}

type LinkSummary struct {
	Peers         int `json:"peers"`
	Linked        int `json:"linked"`
	LinkedBothWay int `json:"linked_both_way"`
	Failed        int `json:"failed"`
}

type MatrixSummary struct {
	Peers                int `json:"peers"`
	LocalToPeerReachable int `json:"local_to_peer_reachable"`
	PeerToLocalReachable int `json:"peer_to_local_reachable"`
	Errors               int `json:"errors"`
}

type ListenOptions struct {
	Name          string
	DiscoveryPort int
	LinkPort      int
}

type DiscoverOptions struct {
	Name          string
	DiscoveryPort int
	LinkPort      int
	Timeout       time.Duration
}

type MatrixOptions struct {
	Name          string
	DiscoveryPort int
	LinkPort      int
	Timeout       time.Duration
	Ports         []int
}

type wireMessage struct {
	Type          string          `json:"type"`
	Protocol      string          `json:"protocol"`
	Peer          Peer            `json:"peer"`
	Targets       []ServiceTarget `json:"targets,omitempty"`
	Results       []ServiceResult `json:"results,omitempty"`
	ReverseLinked bool            `json:"reverse_linked,omitempty"`
	ReverseError  string          `json:"reverse_error,omitempty"`
	Error         string          `json:"error,omitempty"`
}

func Listen(ctx context.Context, opts ListenOptions, out io.Writer) error {
	if opts.DiscoveryPort <= 0 {
		opts.DiscoveryPort = DefaultDiscoveryPort
	}
	if opts.LinkPort <= 0 {
		opts.LinkPort = DefaultLinkPort
	}

	peer, err := LocalPeer(opts.Name, opts.DiscoveryPort, opts.LinkPort)
	if err != nil {
		return err
	}

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: opts.DiscoveryPort})
	if err != nil {
		return fmt.Errorf("listen discovery UDP: %w", err)
	}
	defer udpConn.Close()

	tcpListener, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(opts.LinkPort)))
	if err != nil {
		return fmt.Errorf("listen link TCP: %w", err)
	}
	defer tcpListener.Close()

	fmt.Fprintf(out, "Net-Link peer listening as %s\n", peer.Name)
	fmt.Fprintf(out, "Discovery UDP: %d  Link TCP: %d\n", opts.DiscoveryPort, opts.LinkPort)
	for _, addr := range peer.Addresses {
		fmt.Fprintf(out, "  %s\n", addr)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		serveDiscovery(ctx, udpConn, peer, out)
	}()
	go func() {
		defer wg.Done()
		serveLinks(ctx, tcpListener, peer, out)
	}()

	<-ctx.Done()
	udpConn.Close()
	tcpListener.Close()
	wg.Wait()
	return nil
}

func Discover(ctx context.Context, opts DiscoverOptions) ([]Link, error) {
	opts = normalizeDiscoverOptions(opts)
	peer, err := LocalPeer(opts.Name, opts.DiscoveryPort, opts.LinkPort)
	if err != nil {
		return nil, err
	}

	listener, listenerErr := startTemporaryResponder(ctx, peer)
	if listenerErr == nil {
		defer listener.Close()
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open discovery socket: %w", err)
	}
	defer conn.Close()

	message, err := json.Marshal(wireMessage{
		Type:     probeMessageType,
		Protocol: protocolVersion,
		Peer:     peer,
	})
	if err != nil {
		return nil, err
	}

	for _, addr := range broadcastAddresses(opts.DiscoveryPort) {
		_, _ = conn.WriteToUDP(message, addr)
	}

	_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
	seen := map[string]Link{}
	buffer := make([]byte, 8192)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return nil, err
		}

		var response wireMessage
		if err := json.Unmarshal(buffer[:n], &response); err != nil {
			continue
		}
		if response.Type != helloMessageType || response.Protocol != protocolVersion {
			continue
		}
		if response.Peer.ID == peer.ID {
			continue
		}

		address := remote.IP.String()
		key := response.Peer.ID + "@" + address
		if _, ok := seen[key]; ok {
			continue
		}

		linked, dur, linkErr, reverseLinked, reverseErr := verifyLink(ctx, peer, address, response.Peer.LinkPort, opts.Timeout)
		item := Link{
			Peer:          response.Peer,
			Address:       address,
			Discovered:    time.Now().UTC(),
			Linked:        linked,
			Duration:      model.Duration(dur),
			Error:         linkErr,
			ReverseLinked: reverseLinked,
			ReverseError:  reverseErr,
		}
		if listenerErr != nil && item.ReverseError == "" {
			item.ReverseError = listenerErr.Error()
		}
		seen[key] = item
	}

	links := make([]Link, 0, len(seen))
	for _, link := range seen {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].Peer.Name == links[j].Peer.Name {
			return links[i].Address < links[j].Address
		}
		return links[i].Peer.Name < links[j].Peer.Name
	})
	return links, nil
}

func Matrix(ctx context.Context, opts MatrixOptions) ([]ServiceMatrix, error) {
	if len(opts.Ports) == 0 {
		opts.Ports = []int{22, 80, 443, DefaultLinkPort}
	}
	discoverOpts := DiscoverOptions{
		Name:          opts.Name,
		DiscoveryPort: opts.DiscoveryPort,
		LinkPort:      opts.LinkPort,
		Timeout:       opts.Timeout,
	}
	links, err := Discover(ctx, discoverOpts)
	if err != nil {
		return nil, err
	}

	normalized := normalizeDiscoverOptions(discoverOpts)
	local, err := LocalPeer(opts.Name, normalized.DiscoveryPort, normalized.LinkPort)
	if err != nil {
		return nil, err
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var matrices []ServiceMatrix
	for _, item := range links {
		if !item.Linked {
			matrices = append(matrices, ServiceMatrix{Peer: item.Peer, RequestError: item.Error})
			continue
		}

		matrix := ServiceMatrix{Peer: item.Peer}
		matrix.LocalToPeer = checkServices(ctx, "local", targetsFor(item.Peer.Addresses, opts.Ports), timeout, "local_to_peer")
		results, err := requestPeerServiceCheck(ctx, item.Address, item.Peer.LinkPort, local, targetsFor(local.Addresses, opts.Ports), timeout)
		if err != nil {
			matrix.RequestError = err.Error()
		} else {
			matrix.PeerToLocal = results
		}
		matrices = append(matrices, matrix)
	}
	return matrices, nil
}

func NewDiscoveryRun(command string, local Peer, links []Link, started time.Time) DiscoveryRun {
	ended := time.Now().UTC()
	return DiscoveryRun{
		ID:        ids.New("linkrun"),
		StartedAt: started,
		EndedAt:   ended,
		Duration:  model.Duration(ended.Sub(started)),
		Command:   command,
		Local:     local,
		Links:     links,
		Summary:   summarizeLinks(links),
	}
}

func NewMatrixRun(command string, local Peer, ports []int, matrices []ServiceMatrix, started time.Time) MatrixRun {
	ended := time.Now().UTC()
	return MatrixRun{
		ID:        ids.New("matrixrun"),
		StartedAt: started,
		EndedAt:   ended,
		Duration:  model.Duration(ended.Sub(started)),
		Command:   command,
		Local:     local,
		Ports:     ports,
		Matrices:  matrices,
		Summary:   summarizeMatrices(matrices),
	}
}

func summarizeLinks(links []Link) LinkSummary {
	summary := LinkSummary{Peers: len(links)}
	for _, item := range links {
		if item.Linked {
			summary.Linked++
		}
		if item.Linked && item.ReverseLinked {
			summary.LinkedBothWay++
		}
		if !item.Linked {
			summary.Failed++
		}
	}
	return summary
}

func summarizeMatrices(matrices []ServiceMatrix) MatrixSummary {
	summary := MatrixSummary{Peers: len(matrices)}
	for _, matrix := range matrices {
		if matrix.RequestError != "" {
			summary.Errors++
		}
		for _, result := range matrix.LocalToPeer {
			if result.State == model.StateReachable {
				summary.LocalToPeerReachable++
			}
		}
		for _, result := range matrix.PeerToLocal {
			if result.State == model.StateReachable {
				summary.PeerToLocalReachable++
			}
		}
	}
	return summary
}

func LocalPeer(name string, discoveryPort int, linkPort int) (Peer, error) {
	if name == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			name = model.DefaultLocalNodeName
		} else {
			name = hostname
		}
	}

	addrs, err := localPrivateIPv4Addresses()
	if err != nil {
		addrs = nil
	}

	return Peer{
		ID:            loadOrCreatePeerID(),
		Name:          name,
		Version:       model.Version,
		Addresses:     addrs,
		DiscoveryPort: discoveryPort,
		LinkPort:      linkPort,
	}, nil
}

// loadOrCreatePeerID returns a persistent peer ID from disk, generating and
// saving one on first use. This keeps the ID stable across DHCP address changes
// and reboots, unlike a hash of hostname+IPs.
func loadOrCreatePeerID() string {
	path := peerIDPath()
	if data, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}
	id := ids.New("peer")
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = os.WriteFile(path, []byte(id+"\n"), 0600)
	return id
}

func peerIDPath() string {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "net-link", "peer-id")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".net-link", "peer-id")
	}
	return filepath.Join(home, ".config", "net-link", "peer-id")
}

func normalizeDiscoverOptions(opts DiscoverOptions) DiscoverOptions {
	if opts.DiscoveryPort <= 0 {
		opts.DiscoveryPort = DefaultDiscoveryPort
	}
	if opts.LinkPort <= 0 {
		opts.LinkPort = DefaultLinkPort
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	return opts
}

func startTemporaryResponder(ctx context.Context, peer Peer) (net.Listener, error) {
	listener, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(peer.LinkPort)))
	if err != nil {
		return nil, fmt.Errorf("reverse listener unavailable: %w", err)
	}
	go serveLinks(ctx, listener, peer, io.Discard)
	return listener, nil
}

func serveDiscovery(ctx context.Context, conn *net.UDPConn, peer Peer, out io.Writer) {
	response, _ := json.Marshal(wireMessage{
		Type:     helloMessageType,
		Protocol: protocolVersion,
		Peer:     peer,
	})

	buffer := make([]byte, 8192)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		var message wireMessage
		if err := json.Unmarshal(buffer[:n], &message); err != nil {
			continue
		}
		if message.Type != probeMessageType || message.Protocol != protocolVersion {
			continue
		}
		if message.Peer.ID == peer.ID {
			continue
		}

		_, _ = conn.WriteToUDP(response, remote)
		fmt.Fprintf(out, "Discovery probe from %s at %s\n", message.Peer.Name, remote.IP.String())
	}
}

func serveLinks(ctx context.Context, listener net.Listener, peer Peer, out io.Writer) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go handleLink(conn, peer, out)
	}
}

func handleLink(conn net.Conn, peer Peer, out io.Writer) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	if line == legacyLinkProbeLine {
		writeWire(conn, wireMessage{Type: helloMessageType, Protocol: protocolVersion, Peer: peer})
		fmt.Fprintf(out, "Link verified from %s\n", conn.RemoteAddr().String())
		return
	}

	var message wireMessage
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &message); err != nil {
		return
	}
	if message.Protocol != protocolVersion {
		return
	}

	switch message.Type {
	case linkCheckMessageType:
		reverseLinked, _, reverseErr := verifyReverse(conn.RemoteAddr(), message.Peer, 2*time.Second)
		response := wireMessage{
			Type:          helloMessageType,
			Protocol:      protocolVersion,
			Peer:          peer,
			ReverseLinked: reverseLinked,
		}
		if reverseErr != "" {
			response.ReverseError = reverseErr
		}
		writeWire(conn, response)
		fmt.Fprintf(out, "Link verified from %s reverse=%t\n", conn.RemoteAddr().String(), reverseLinked)

	case reverseMessageType:
		writeWire(conn, wireMessage{Type: helloMessageType, Protocol: protocolVersion, Peer: peer})

	case serviceMessageType:
		// Extend the deadline and create a matching context so the spawned
		// goroutines in checkServices are cancelled when the work is done
		// rather than running indefinitely on context.Background().
		svcTimeout := 2*time.Second + time.Duration(len(message.Targets))*250*time.Millisecond
		_ = conn.SetDeadline(time.Now().Add(svcTimeout))
		ctx, cancel := context.WithTimeout(context.Background(), svcTimeout)
		defer cancel()
		results := checkServices(ctx, peer.Name, message.Targets, 2*time.Second, "peer_to_local")
		writeWire(conn, wireMessage{
			Type:     serviceResultType,
			Protocol: protocolVersion,
			Peer:     peer,
			Results:  results,
		})
		fmt.Fprintf(out, "Service matrix request from %s targets=%d\n", conn.RemoteAddr().String(), len(message.Targets))
	}
}

func verifyLink(ctx context.Context, local Peer, address string, port int, timeout time.Duration) (bool, time.Duration, string, bool, string) {
	started := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address, strconv.Itoa(port)))
	duration := time.Since(started)
	if err != nil {
		return false, duration, err.Error(), false, ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := writeWire(conn, wireMessage{Type: linkCheckMessageType, Protocol: protocolVersion, Peer: local}); err != nil {
		return false, duration, err.Error(), false, ""
	}

	var msg wireMessage
	if err := readWire(conn, &msg); err != nil {
		return false, time.Since(started), err.Error(), false, ""
	}
	duration = time.Since(started)
	if msg.Type != helloMessageType || msg.Protocol != protocolVersion {
		return false, duration, "unexpected link response", false, ""
	}
	return true, duration, "", msg.ReverseLinked, msg.ReverseError
}

func verifyReverse(remote net.Addr, requester Peer, timeout time.Duration) (bool, time.Duration, string) {
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return false, 0, err.Error()
	}
	if requester.LinkPort <= 0 {
		return false, 0, "requester did not advertise a link port"
	}

	started := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp4", net.JoinHostPort(host, strconv.Itoa(requester.LinkPort)))
	duration := time.Since(started)
	if err != nil {
		return false, duration, err.Error()
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := writeWire(conn, wireMessage{Type: reverseMessageType, Protocol: protocolVersion}); err != nil {
		return false, duration, err.Error()
	}
	var msg wireMessage
	if err := readWire(conn, &msg); err != nil {
		return false, time.Since(started), err.Error()
	}
	if msg.Type != helloMessageType || msg.Protocol != protocolVersion {
		return false, time.Since(started), "unexpected reverse response"
	}
	return true, time.Since(started), ""
}

func requestPeerServiceCheck(ctx context.Context, address string, port int, local Peer, targets []ServiceTarget, timeout time.Duration) ([]ServiceResult, error) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout + time.Duration(len(targets))*250*time.Millisecond))
	if err := writeWire(conn, wireMessage{
		Type:     serviceMessageType,
		Protocol: protocolVersion,
		Peer:     local,
		Targets:  targets,
	}); err != nil {
		return nil, err
	}

	var response wireMessage
	if err := readWire(conn, &response); err != nil {
		return nil, err
	}
	if response.Type != serviceResultType || response.Protocol != protocolVersion {
		return nil, fmt.Errorf("unexpected service response")
	}
	return response.Results, nil
}

func checkServices(ctx context.Context, source string, targets []ServiceTarget, timeout time.Duration, direction string) []ServiceResult {
	results := make([]ServiceResult, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target ServiceTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = checkService(ctx, source, target, timeout, direction)
		}(i, target)
	}
	wg.Wait()
	return results
}

func checkService(ctx context.Context, source string, target ServiceTarget, timeout time.Duration, direction string) ServiceResult {
	started := time.Now()
	result := ServiceResult{Source: source, Target: target, Direction: direction}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	result.Duration = model.Duration(time.Since(started))
	if err != nil {
		result.State = probes.ClassifyConnectError(err)
		result.Error = err.Error()
		return result
	}
	conn.Close()
	result.State = model.StateReachable
	return result
}

func targetsFor(addresses []string, ports []int) []ServiceTarget {
	var targets []ServiceTarget
	for _, address := range addresses {
		for _, port := range ports {
			targets = append(targets, ServiceTarget{Host: address, Port: port})
		}
	}
	return targets
}

func writeWire(w io.Writer, message wireMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

func readWire(r io.Reader, message *wireMessage) error {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(strings.TrimSpace(line)), message)
}

func broadcastAddresses(port int) []*net.UDPAddr {
	seen := map[string]bool{}
	var out []*net.UDPAddr

	add := func(ip net.IP) {
		key := ip.String()
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, &net.UDPAddr{IP: ip, Port: port})
	}

	add(net.IPv4bcast)

	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			mask := net.IP(ipNet.Mask).To4()
			if ip == nil || mask == nil || !ip.IsPrivate() {
				continue
			}
			add(net.IPv4(ip[0]|^mask[0], ip[1]|^mask[1], ip[2]|^mask[2], ip[3]|^mask[3]))
		}
	}
	return out
}

func localPrivateIPv4Addresses() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil || !ip.IsPrivate() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out, nil
}
