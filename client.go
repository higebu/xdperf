package xdperf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
	"golang.org/x/text/message"

	"github.com/higebu/xdperf/xdp"
)

var defaultClientParams = ClientParams{
	SrcIP:      net.ParseIP("127.0.0.1"),
	DstIP:      net.ParseIP("127.0.0.1"),
	SrcPort:    12345,
	DstPort:    12345,
	SrcMac:     nil,
	DstMac:     net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	PacketSize: 64,
	Parallel:   1,
	PPS:        1000,
	BatchSize:  1,
	Tx:         false,
}

// ClientParams holds the parameters for the xdperf application.
type ClientParams struct {
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    int
	DstPort    int
	SrcMac     net.HardwareAddr
	DstMac     net.HardwareAddr
	PacketSize int
	Parallel   int
	PPS        uint64
	BatchSize  uint32
	Tx         bool
	Device     *net.Interface
}

// Client represents the Client.
type Client struct {
	Params ClientParams
	objs   *xdp.XdperfObjects
}

// NewClient creates a new Client instance with default parameters.
func NewClient(dev *net.Interface, opts ...ClientOption) (*Client, error) {
	c := &Client{
		Params: defaultClientParams,
	}
	c.Params.Device = dev

	for _, opt := range opts {
		opt(c)
	}

	if c.Params.SrcMac == nil {
		c.Params.SrcMac = dev.HardwareAddr
	}

	if c.Params.PacketSize < 64 {
		return nil, fmt.Errorf("packet size must be at least 64 bytes")
	}

	if c.Params.PPS == 0 {
		c.Params.BatchSize = 1 << 20
	}

	return c, nil
}

// ClientOption defines a function that modifies the Xdperf parameters.
type ClientOption func(*Client)

// WithSrcIP sets the source IP address.
func WithSrcIP(ip net.IP) ClientOption {
	return func(c *Client) {
		c.Params.SrcIP = ip
	}
}

// WithDstIP sets the destination IP address.
func WithDstIP(ip net.IP) ClientOption {
	return func(c *Client) {
		c.Params.DstIP = ip
	}
}

// WithSrcPort sets the source UDP port.
func WithSrcPort(port int) ClientOption {
	return func(c *Client) {
		c.Params.SrcPort = port
	}
}

// WithDstPort sets the destination UDP port.
func WithDstPort(port int) ClientOption {
	return func(c *Client) {
		c.Params.DstPort = port
	}
}

// WithSrcMac sets the source MAC address.
func WithSrcMac(mac net.HardwareAddr) ClientOption {
	return func(c *Client) {
		c.Params.SrcMac = mac
	}
}

// WithDstMac sets the destination MAC address.
func WithDstMac(mac net.HardwareAddr) ClientOption {
	return func(c *Client) {
		c.Params.DstMac = mac
	}
}

// WithPacketSize sets the size of the packets to send.
func WithPacketSize(size int) ClientOption {
	return func(c *Client) {
		c.Params.PacketSize = size
	}
}

// WithParallel sets the number of parallel threads to use.
func WithParallel(parallel int) ClientOption {
	return func(c *Client) {
		c.Params.Parallel = parallel
	}
}

// WithPPS sets the packets per second rate.
func WithPPS(pps uint64) ClientOption {
	return func(c *Client) {
		c.Params.PPS = pps
	}
}

// WithBatchSize sets the batch size for sending packets.
func WithBatchSize(batchSize uint32) ClientOption {
	return func(c *Client) {
		c.Params.BatchSize = batchSize
	}
}

// WithTx sets the client to use XDP_TX mode instead of XDP_REDIRECT.
func WithTx(tx bool) ClientOption {
	return func(c *Client) {
		c.Params.Tx = tx
	}
}

// Run starts the xdperf application with the provided parameters.
func (c *Client) Run() error {
	buf := gopacket.NewSerializeBuffer()

	var ethLayer gopacket.SerializableLayer
	var ipLayer gopacket.SerializableLayer
	var udpLayer *layers.UDP
	var payloadLen int

	if c.Params.SrcIP.To4() != nil && c.Params.DstIP.To4() != nil {
		// IPv4
		ethLayer = &layers.Ethernet{
			SrcMAC:       c.Params.SrcMac,
			DstMAC:       c.Params.DstMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    c.Params.SrcIP.To4(),
			DstIP:    c.Params.DstIP.To4(),
			Protocol: layers.IPProtocolUDP,
		}
		udpLayer = &layers.UDP{
			SrcPort: layers.UDPPort(c.Params.SrcPort),
			DstPort: layers.UDPPort(c.Params.DstPort),
		}
		udpLayer.SetNetworkLayerForChecksum(ip4)
		ipLayer = ip4
		payloadLen = c.Params.PacketSize - 14 - 20 - 8 // Ethernet(14) + IPv4(20) + UDP(8)
	} else if c.Params.SrcIP.To16() != nil && c.Params.DstIP.To16() != nil {
		// IPv6
		ethLayer = &layers.Ethernet{
			SrcMAC:       c.Params.SrcMac,
			DstMAC:       c.Params.DstMac,
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			Version:    6,
			HopLimit:   64,
			SrcIP:      c.Params.SrcIP.To16(),
			DstIP:      c.Params.DstIP.To16(),
			NextHeader: layers.IPProtocolUDP,
		}
		udpLayer = &layers.UDP{
			SrcPort: layers.UDPPort(c.Params.SrcPort),
			DstPort: layers.UDPPort(c.Params.DstPort),
		}
		udpLayer.SetNetworkLayerForChecksum(ip6)
		ipLayer = ip6
		payloadLen = c.Params.PacketSize - 14 - 40 - 8 // Ethernet(14) + IPv6(40) + UDP(8)
	} else {
		return fmt.Errorf("src-ip and dst-ip must be both IPv4 or both IPv6")
	}

	if payloadLen < 0 {
		return fmt.Errorf("size too small: must be at least %d bytes (Ethernet+IP+UDP header)", c.Params.PacketSize-payloadLen)
	}
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = []byte("a")[0]
	}
	err := gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethLayer, ipLayer, udpLayer, gopacket.Payload(payload))
	if err != nil {
		return fmt.Errorf("failed to serialize packet: %w", err)
	}
	in := buf.Bytes()

	c.objs = &xdp.XdperfObjects{}
	if err := xdp.LoadXdperfObjects(c.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier error: %w", ve)
		}
		return fmt.Errorf("loading objects: %w", err)
	}
	defer c.objs.Close()

	if c.objs.XdperfVariables.Ifidx == nil {
		return fmt.Errorf("ifidx variable not found in BPF object")
	}
	if err := c.objs.XdperfVariables.Ifidx.Set(uint32(c.Params.Device.Index)); err != nil {
		return fmt.Errorf("failed to set ifidx: %w", err)
	}

	var prog *ebpf.Program
	if c.Params.Tx {
		prog = c.objs.XdperfPrograms.XdpTx
	} else {
		prog = c.objs.XdperfPrograms.XdpRedirectNotouch
	}

	// Attach XDP program using cilium/ebpf/link
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: c.Params.Device.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %w", err)
	}
	defer l.Close()

	fmt.Printf("XDP client started on %s (idx: %d)\n",
		c.Params.Device.Name, c.Params.Device.Index)
	fmt.Printf("Sending to %s:%d from %s:%d\n",
		c.Params.DstIP, c.Params.DstPort, c.Params.SrcIP, c.Params.SrcPort)
	fmt.Println("Press Ctrl+C to stop")

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.printStats(ctx)

	runOpts := &ebpf.RunOptions{
		Data:   in,
		Repeat: c.Params.BatchSize,
		Flags:  unix.BPF_F_TEST_XDP_LIVE_FRAMES,
	}
	for i := range c.Params.Parallel {
		p, err := prog.Clone()
		if err != nil {
			return fmt.Errorf("failed to clone XDP program: %w", err)
		}
		wg.Add(1)
		go func(cpu int) {
			defer wg.Done()
			go func() {
				defer p.Close()
				if err := c.run(ctx, cpu, p, runOpts); err != nil {
					fmt.Printf("error in run: %v\n", err)
				}
			}()
			<-ctx.Done()
		}(i)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down client...")
	cancel()
	wg.Wait()
	return nil
}

func (c *Client) run(ctx context.Context, cpu int, xdpProg *ebpf.Program, runOpts *ebpf.RunOptions) error {
	runtime.LockOSThread()
	var cpuset unix.CPUSet
	cpuset.Set(cpu)
	if err := unix.SchedSetaffinity(unix.Gettid(), &cpuset); err != nil {
		return fmt.Errorf("failed to set CPU affinity: %v", err)
	}
	if c.Params.PPS == 0 {
		for {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			ret, err := xdpProg.Run(runOpts)
			if err != nil {
				return fmt.Errorf("bpf_prog_run failed: %w", err)
			}
			if ret != 0 {
				return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
			}
		}
	} else {
		interval := float64(float64(time.Second)*float64(c.Params.BatchSize)) / float64(c.Params.PPS)
		ticker := time.NewTicker(time.Duration(interval))
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				ret, err := xdpProg.Run(runOpts)
				if err != nil {
					return fmt.Errorf("bpf_prog_run failed: %w", err)
				}
				if ret != 0 {
					return fmt.Errorf("bpf_prog_run returned non-zero: %d", ret)
				}
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (c *Client) printStats(ctx context.Context) {
	var prevPackets uint64
	var prevBytes uint64
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]xdp.XdperfDatarec, possibleCPUs)
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var key uint32
			err := c.objs.StatsMap.Lookup(&key, &recs)
			if err != nil {
				fmt.Printf("failed to lookup stats_map: %v\n", err)
				continue
			}
			var sumPackets uint64
			var sumBytes uint64
			for _, rec := range recs {
				sumPackets += rec.RxPackets
				sumBytes += rec.RxBytes
			}
			deltaPackets := sumPackets - prevPackets
			deltaBytes := sumBytes - prevBytes
			prevPackets = sumPackets
			prevBytes = sumBytes
			p.Printf("%d xmit/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
		case <-ctx.Done():
			return
		}
	}
}
