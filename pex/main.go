package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/p2p"
	"github.com/cometbft/cometbft/p2p/conn"
	tmp2p "github.com/cometbft/cometbft/proto/tendermint/p2p"
)

const (
	pexChannel     = byte(0x00)
	roundWait      = 6 * time.Second
	maxMsgSize     = 256 * 100
	roundAddrLimit = 64
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
	mu      sync.Mutex
	visited map[string]bool
	peers   map[string]PeerInfo
	queries int
}

// pexClient is a minimal PEX reactor: request addrs from every outbound peer
// we dial, and hand responses back to the crawl loop.
type pexClient struct {
	p2p.BaseReactor
	pexCh     chan []tmp2p.NetAddress
	sw        *p2p.Switch
	networks  map[string]string // peer ID -> observed network
	connected int
	mu        sync.Mutex
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
		_ = p.Send(p2p.Envelope{ChannelID: pexChannel, Message: &tmp2p.PexRequest{}})
	}
}

func (r *pexClient) Receive(e p2p.Envelope) {
	if e.ChannelID != pexChannel {
		return
	}
	addrs, ok := e.Message.(*tmp2p.PexAddrs)
	if !ok {
		return
	}
	select {
	case r.pexCh <- addrs.Addrs:
	default:
	}
	if r.sw != nil {
		r.sw.StopPeerGracefully(e.Src)
	}
}

func main() {
	o := parseFlags()
	os.Exit(run(o))
}

func parseFlags() options {
	var o options
	flag.StringVar(&o.seeds, "seeds", "", "comma-separated P2P seeds (nodeID@host:port)")
	flag.StringVar(&o.network, "network", "", "chain-id sent in the node-info handshake (learned if empty)")
	flag.StringVar(&o.out, "out", "", "output peer_ips.json path (merged {ip: ts})")
	flag.StringVar(&o.jsonOut, "json", "", "optional detailed peers JSON output path")
	flag.StringVar(&o.verify, "verify", "", "verify peers in a pex_peers.json file (dial each, report observed network)")
	flag.IntVar(&o.time, "time", 180, "max crawl time in seconds")
	flag.IntVar(&o.depth, "depth", 6, "max BFS depth")
	flag.BoolVar(&o.verbose, "verbose", false, "verbose logging")
	flag.Parse()
	return o
}

func run(o options) int {
	st := &state{
		visited: map[string]bool{},
		peers:   map[string]PeerInfo{},
	}
	start := time.Now()
	deadline := start.Add(time.Duration(o.time) * time.Second)

	existing := map[string]int64{}
	if o.out != "" {
		if data, err := os.ReadFile(o.out); err == nil {
			_ = json.Unmarshal(data, &existing)
		}
	}

	sw, rc, network, err := buildSwitch(o.network)
	if err != nil {
		fmt.Fprintf(os.Stderr, "switch: %v\n", err)
		return 1
	}
	if err := sw.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "switch start: %v\n", err)
		return 1
	}
	defer sw.Stop()

	// Verification mode: dial every listed peer and record its actual network.
	if o.verify != "" {
		return verify(o, sw, rc, deadline)
	}

	pending := []string{}
	if o.seeds != "" {
		for _, s := range strings.Split(o.seeds, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				pending = append(pending, s)
			}
		}
	}

	curDepth := 0
	for len(pending) > 0 && time.Now().Before(deadline) && curDepth <= o.depth {
		if o.verbose {
			fmt.Printf("[%s] depth %d: %d addresses in queue\n",
				time.Now().Format("15:04:05"), curDepth, len(pending))
		}

		// Split pending into this round's dial targets (up to roundAddrLimit
		// unvisited addresses) and the overflow to carry into the next round.
		// Only round members are marked visited, so overflow is not lost.
		round := []string{}
		overflow := []string{}
		for _, a := range pending {
			if st.isVisited(a) {
				continue
			}
			if len(round) >= roundAddrLimit {
				overflow = append(overflow, a)
			} else {
				round = append(round, a)
			}
		}
		if len(round) == 0 {
			break
		}
		for _, a := range round {
			st.markVisited(a)
		}

		// Dial all peers in this round (network validation inside the switch).
		valid := []string{}
		for _, a := range round {
			if _, err := p2p.NewNetAddressString(a); err != nil {
				if o.verbose {
					fmt.Printf("  bad seed %q: %v\n", a, err)
				}
				continue
			}
			valid = append(valid, a)
		}
		if len(valid) > 0 {
			if err := sw.DialPeersAsync(valid); err != nil {
				fmt.Printf("  dial: %v\n", err)
			}
		}

		// Collect responses until the round window elapses.
		roundEnd := time.Now().Add(roundWait)
		next := []string{}
		nextSeen := map[string]bool{}
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
					pi := PeerInfo{ID: a.ID, IP: a.IP, Port: a.Port}
					st.mu.Lock()
					if _, ok := st.peers[a.IP]; !ok {
						st.peers[a.IP] = pi
					}
					st.mu.Unlock()
					addr := fmt.Sprintf("%s@%s:%d", a.ID, a.IP, a.Port)
					if !nextSeen[addr] {
						nextSeen[addr] = true
						next = append(next, addr)
					}
				}
			case <-time.After(roundEnd.Sub(time.Now())):
				break collect
			}
		}

		pending = append(overflow, next...)
		curDepth++
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
	merged := map[string]int64{}
	for ip, ts := range existing {
		merged[ip] = ts
	}
	for _, p := range peers {
		merged[p.IP] = now
	}

	if o.out != "" {
		writeJSON(o.out, merged)
	}
	if o.jsonOut != "" {
		writeJSON(o.jsonOut, map[string]interface{}{
			"generatedAt": time.Now().UTC().Format(time.RFC3339),
			"network":     network,
			"queries":     st.queries,
			"peers":       peers,
		})
	}

	fmt.Printf("[%s] done: %d queries, %d unique peers, %d total ips, %ds\n",
		time.Now().Format("15:04:05"), st.queries, len(peers), len(merged),
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
	if na, err := ni.NetAddress(); err == nil {
		_ = transport.Listen(*na)
	}
	sw := p2p.NewSwitch(p2pCfg, transport, p2p.WithMetrics(p2p.NopMetrics()))
	sw.SetLogger(log.NewTMLogger(log.NewSyncWriter(os.Stderr)))

	rc := &pexClient{pexCh: make(chan []tmp2p.NetAddress, 256), networks: map[string]string{}}
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

func (st *state) isVisited(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.visited[key]
}

func (st *state) markVisited(key string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.visited[key] {
		return false
	}
	st.visited[key] = true
	return true
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
