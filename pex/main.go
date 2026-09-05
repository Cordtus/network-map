package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/conn"
	tmp2p "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

const (
	pexChannel      = byte(0x00)
	roundWait       = 6 * time.Second
	maxMsgSize      = 256 * 100
	roundAddrLimit  = 64
	maxPeerQueries  = 3               // re-request a peer up to 3 times, then stop it
	requestGap      = 3 * time.Second // space between re-requests to one peer
	maxDialAttempts = 2               // dial a candidate up to this many times before dropping it
	retryRounds     = 2               // rounds to wait before retrying a failed dial
)

type PeerInfo struct {
	ID   string `json:"id"`
	IP   string `json:"ip"`
	Port uint32 `json:"port"`
}

type options struct {
	seeds   string
	network string
	out     string
	jsonOut string
	verify  string
	time    int
	depth   int
	verbose bool
}

type state struct {
	mu        sync.Mutex
	attempts  map[string]int      // addr -> dial attempts so far
	connected map[string]bool     // addr that completed a handshake
	peers     map[string]PeerInfo // verified (answered a PEX request), keyed by IP
	queries   int
}

// pexClient is a minimal PEX reactor: request addrs from every outbound peer
// we dial, re-requesting each one up to maxPeerQueries times (spaced by
// requestGap so no single peer is hammered), and hand responses back to the
// crawl loop.
type pexClient struct {
	p2p.BaseReactor
	pexCh     chan []tmp2p.NetAddress
	sw        *p2p.Switch
	st        *state
	networks  map[string]string // peer ID -> observed network
	connected int
	mu        sync.Mutex
	reqs      map[string]int // peer ID -> PexRequests sent so far
}

func (r *pexClient) GetChannels() []*conn.ChannelDescriptor {
	return []*conn.ChannelDescriptor{
		{
			ID:                  pexChannel,
			Priority:            1,
			SendQueueCapacity:   10,
			RecvMessageCapacity: maxMsgSize,
			MessageType:         &tmp2p.Message{},
		},
	}
}

func (r *pexClient) AddPeer(p p2p.Peer) {
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Printf("    [addpeer recover] %v\n", rec)
		}
	}()
	r.mu.Lock()
	r.connected++
	net := ""
	if d, ok := p.NodeInfo().(p2p.DefaultNodeInfo); ok {
		net = d.Network
		r.networks[string(p.ID())] = net
	}
	r.mu.Unlock()
	fmt.Printf("    [dial] connected %s net=%q\n", p.RemoteAddr().String(), net)
	if p.IsOutbound() {
		// Record the dialed address as connected (handshake completed).
		if r.st != nil {
			if na := p.SocketAddr(); na != nil && isPublicIPv4(na.IP.String()) {
				r.st.markConnected(fmt.Sprintf("%s@%s:%d", p.ID(), na.IP.String(), na.Port))
			}
		}
		r.mu.Lock()
		r.reqs[string(p.ID())] = 1
		r.mu.Unlock()
		_ = p.Send(p2p.Envelope{ChannelID: pexChannel, Message: &tmp2p.PexRequest{}})
	}
}

func (r *pexClient) RemovePeer(p p2p.Peer, _ interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.reqs, string(p.ID()))
}

func (r *pexClient) Receive(e p2p.Envelope) {
	if e.ChannelID != pexChannel {
		return
	}
	addrs, ok := e.Message.(*tmp2p.PexAddrs)
	if !ok {
		return
	}
	// A PEX response proves this peer is live right now: record it as verified.
	if r.st != nil {
		if na := e.Src.SocketAddr(); na != nil {
			ip := na.IP.String()
			if isPublicIPv4(ip) {
				pi := PeerInfo{ID: string(e.Src.ID()), IP: ip, Port: uint32(na.Port)}
				r.st.mu.Lock()
				if _, exists := r.st.peers[ip]; !exists {
					r.st.peers[ip] = pi
				}
				r.st.mu.Unlock()
			}
		}
	}
	select {
	case r.pexCh <- addrs.Addrs:
	default:
	}
	id := string(e.Src.ID())
	r.mu.Lock()
	n := r.reqs[id]
	r.mu.Unlock()
	if n >= maxPeerQueries {
		// This peer has been fully queried; drop it so the slot frees up.
		if r.sw != nil {
			r.sw.StopPeerGracefully(e.Src)
		}
		return
	}
	// Re-request this peer after a gap, so its next address sample is drawn
	// from a different random subset of its address book.
	peer := e.Src
	go func(peer p2p.Peer, id string) {
		time.Sleep(requestGap)
		if !peer.IsRunning() {
			return
		}
		r.mu.Lock()
		if r.reqs[id] >= maxPeerQueries {
			r.mu.Unlock()
			return
		}
		r.reqs[id]++
		r.mu.Unlock()
		_ = peer.Send(p2p.Envelope{ChannelID: pexChannel, Message: &tmp2p.PexRequest{}})
	}(peer, id)
}

// hasActiveQueries reports whether any connected peer still has outstanding
// request budget (i.e. the crawl should keep collecting responses).
func (r *pexClient) hasActiveQueries() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.reqs {
		if n < maxPeerQueries {
			return true
		}
	}
	return false
}

func main() {
	o := parseFlags()
	os.Exit(run(o))
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.seeds, "seeds", "", "comma-separated P2P seeds (nodeID@host:port)")
	flag.StringVar(&o.network, "network", "", "chain-id sent in the node-info handshake (learned if empty)")
	flag.StringVar(&o.out, "out", "", "output peer_ips.json path ({ip: ts} of verified peers only)")
	flag.StringVar(&o.jsonOut, "json", "", "optional detailed peers JSON output path")
	flag.StringVar(&o.verify, "verify", "", "verify peers in a pex_peers.json file (dial each, report observed network)")
	flag.IntVar(&o.time, "time", 180, "max crawl time in seconds")
	flag.IntVar(&o.depth, "depth", 100, "max crawl rounds (safety cap; crawl normally ends when all peers are exhausted)")
	flag.BoolVar(&o.verbose, "verbose", false, "verbose logging")
	flag.Parse()
	return o
}

func run(o options) int {
	st := &state{
		attempts:  map[string]int{},
		connected: map[string]bool{},
		peers:     map[string]PeerInfo{},
	}
	start := time.Now()
	deadline := start.Add(time.Duration(o.time) * time.Second)

	sw, rc, network, err := buildSwitch(o.network)
	if err != nil {
		fmt.Fprintf(os.Stderr, "switch: %v\n", err)
		return 1
	}
	rc.st = st
	if err := sw.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "switch start: %v\n", err)
		return 1
	}
	defer sw.Stop()

	// Verification mode: dial every listed peer and record its actual network.
	if o.verify != "" {
		return verify(o, sw, rc, deadline)
	}

	// queue maps a candidate addr to the round it was last dialed (-1 = never).
	// Candidates are dialed, retried after failed dials (retryRounds apart, up
	// to maxDialAttempts times), and only ever counted as peers once they
	// connect and answer a PEX request. Unreachable/silent candidates drop out.
	queue := map[string]int{}
	if o.seeds != "" {
		for _, s := range strings.Split(o.seeds, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				queue[s] = -1
			}
		}
	}

	rounds := 0
	for time.Now().Before(deadline) && rounds < o.depth {
		if o.verbose {
			fmt.Printf("[%s] round %d: %d queued, %d queries\n",
				time.Now().Format("15:04:05"), rounds, len(queue), st.queries)
		}

		// Prune candidates that connected (now being queried) or gave up.
		for a := range queue {
			if st.isConnected(a) || st.attemptsOf(a) >= maxDialAttempts {
				delete(queue, a)
			}
		}
		if len(queue) == 0 && !rc.hasActiveQueries() {
			break
		}

		// Take up to roundAddrLimit candidates that are due for a dial attempt.
		batch := []string{}
		for a, dr := range queue {
			if dr >= 0 && rounds-dr < retryRounds {
				continue // waiting out the retry backoff
			}
			batch = append(batch, a)
			if len(batch) >= roundAddrLimit {
				break
			}
		}
		for _, a := range batch {
			st.markDialed(a)
			queue[a] = rounds
		}

		if len(batch) > 0 {
			valid := []string{}
			for _, a := range batch {
				if _, err := p2p.NewNetAddressString(a); err != nil {
					if o.verbose {
						fmt.Printf("  bad seed %q: %v\n", a, err)
					}
					delete(queue, a)
					continue
				}
				valid = append(valid, a)
			}
			if len(valid) > 0 {
				if err := sw.DialPeersAsync(valid); err != nil {
					fmt.Printf("  dial: %v\n", err)
				}
			}
		}

		// Collect responses until the round window elapses (or we already have
		// a full batch of fresh candidates to dial), expanding `queue`.
		roundEnd := time.Now().Add(roundWait)
		newQueued := 0
	collect:
		for time.Now().Before(roundEnd) {
			select {
			case addrsMsg := <-rc.pexCh:
				st.mu.Lock()
				st.queries++
				st.mu.Unlock()
				for _, a := range addrsMsg {
					if !isPublicIPv4(a.IP) {
						continue
					}
					addr := fmt.Sprintf("%s@%s:%d", a.ID, a.IP, a.Port)
					if !st.isConnected(addr) && st.attemptsOf(addr) < maxDialAttempts {
						if _, inQueue := queue[addr]; !inQueue {
							queue[addr] = -1
							newQueued++
						}
					}
				}
				if newQueued >= roundAddrLimit {
					break collect
				}
			case <-time.After(roundEnd.Sub(time.Now())):
				break collect
			}
		}
		rounds++
	}

	// Assemble outputs.
	st.mu.Lock()
	peers := make([]PeerInfo, 0, len(st.peers))
	for _, p := range st.peers {
		peers = append(peers, p)
	}
	st.mu.Unlock()
	sort.Slice(peers, func(i, j int) bool { return peers[i].IP < peers[j].IP })

	now := time.Now().Unix()
	verified := map[string]int64{}
	for _, p := range peers {
		verified[p.IP] = now
	}

	if o.out != "" {
		writeJSON(o.out, verified)
	}
	if o.jsonOut != "" {
		writeJSON(o.jsonOut, map[string]interface{}{
			"generatedAt": time.Now().UTC().Format(time.RFC3339),
			"network":     network,
			"queries":     st.queries,
			"peers":       peers,
		})
	}

	fmt.Printf("[%s] done: %d queries, %d verified peers, %ds\n",
		time.Now().Format("15:04:05"), st.queries, len(peers),
		int(time.Since(start).Seconds()))
	return 0
}

func verify(o options, sw *p2p.Switch, rc *pexClient, deadline time.Time) int {
	data, err := os.ReadFile(o.verify)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify file: %v\n", err)
		return 1
	}
	var doc struct {
		Peers []PeerInfo `json:"peers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "verify json: %v\n", err)
		return 1
	}

	addrs := make([]string, 0, len(doc.Peers))
	for _, p := range doc.Peers {
		if p.ID != "" && p.IP != "" && p.Port != 0 {
			addrs = append(addrs, fmt.Sprintf("%s@%s:%d", p.ID, p.IP, p.Port))
		}
	}

	// Dial in batches; AddPeer records each successful compatible handshake.
	for i := 0; i < len(addrs) && time.Now().Before(deadline); i += roundAddrLimit {
		batch := addrs[i : i+min(roundAddrLimit, len(addrs)-i)]
		if err := sw.DialPeersAsync(batch); err != nil {
			fmt.Printf("  dial: %v\n", err)
		}
		time.Sleep(2 * time.Second)
	}

	rc.mu.Lock()
	networks := map[string]int{}
	for _, n := range rc.networks {
		networks[n]++
	}
	connected := rc.connected
	rc.mu.Unlock()

	fmt.Printf("=== verification ===\n")
	fmt.Printf("addresses listed: %d\n", len(addrs))
	fmt.Printf("connected (handshake ok): %d (%.1f%%)\n",
		connected, 100*float64(connected)/float64(max(1, len(addrs))))
	fmt.Printf("by observed network: %v\n", networks)
	fmt.Printf("unreachable/rejected: %d\n", len(addrs)-connected)
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildSwitch(network string) (*p2p.Switch, *pexClient, string, error) {
	p2pCfg := config.DefaultP2PConfig()
	p2pCfg.ListenAddress = "tcp://127.0.0.1:0"
	p2pCfg.AllowDuplicateIP = true

	nodeKey := &p2p.NodeKey{PrivKey: ed25519.GenPrivKey()}
	ni := buildNodeInfo(network, nodeKey.PrivKey.PubKey())

	transport := p2p.NewMultiplexTransport(ni, *nodeKey, conn.DefaultMConnConfig())
	bumpTransportTimeouts(transport, 5*time.Second, 15*time.Second)
	if na, err := ni.NetAddress(); err == nil {
		_ = transport.Listen(*na)
	}
	sw := p2p.NewSwitch(p2pCfg, transport, p2p.WithMetrics(p2p.NopMetrics()))
	sw.SetLogger(log.NewTMLogger(log.NewSyncWriter(os.Stderr)))

	rc := &pexClient{pexCh: make(chan []tmp2p.NetAddress, 1024), networks: map[string]string{}, reqs: map[string]int{}}
	rc.BaseReactor = *p2p.NewBaseReactor("PEX", rc)
	rc.SetLogger(log.NewTMLogger(log.NewSyncWriter(os.Stderr)))
	sw.AddReactor("PEX", rc)
	sw.SetNodeInfo(ni)
	rc.sw = sw

	// Learn the real network from the first peer's node info if not given.
	if network == "" {
		network = "<learned>"
	}
	return sw, rc, network, nil
}

func (st *state) markDialed(key string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.attempts[key]++
}

func (st *state) attemptsOf(key string) int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.attempts[key]
}

func (st *state) markConnected(key string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.connected[key] = true
}

func (st *state) isConnected(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.connected[key]
}

func isPublicIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	nums := make([]int, 4)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		nums[i] = n
	}
	a, b := nums[0], nums[1]
	if a == 0 || a >= 224 || a == 127 || a == 10 {
		return false
	}
	if a == 172 && b >= 16 && b <= 31 {
		return false
	}
	if a == 192 && b == 168 {
		return false
	}
	if a == 169 && b == 254 {
		return false
	}
	return true
}

// bumpTransportTimeouts raises the multiplex transport's dial/handshake
// timeouts, which are hardcoded to a far-too-short 1s/3s (upstream config
// defaults are 3s/20s). Slow-but-live WAN peers otherwise fail the handshake.
// The fields are unexported, so this uses reflection+unsafe; it is a no-op if
// the field layout ever changes.
func bumpTransportTimeouts(t *p2p.MultiplexTransport, dial, handshake time.Duration) {
	refl := reflect.ValueOf(t).Elem()
	set := func(name string, d time.Duration) {
		f := refl.FieldByName(name)
		if !f.IsValid() {
			return
		}
		reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().SetInt(int64(d))
	}
	set("dialTimeout", dial)
	set("handshakeTimeout", handshake)
}

func buildNodeInfo(network string, pub crypto.PubKey) p2p.DefaultNodeInfo {
	return p2p.DefaultNodeInfo{
		ProtocolVersion: p2p.ProtocolVersion{P2P: 8, Block: 11, App: 0},
		DefaultNodeID:   p2p.ID(hex.EncodeToString(pub.Address())),
		ListenAddr:      "tcp://0.0.0.0:26656",
		Network:         network,
		Version:         "0.38.19",
		Channels:        []byte{0x00}, // advertise the PEX channel (channel ID list)
		Moniker:         "network-map-crawler",
		Other: p2p.DefaultNodeInfoOther{
			TxIndex:    "off",
			RPCAddress: "tcp://0.0.0.0:26657",
		},
	}
}

func writeJSON(path string, v interface{}) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		return
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "json: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
	}
}
