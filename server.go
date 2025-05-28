package xdperf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/text/message"

	"github.com/higebu/xdperf/xdp"
)

// Server represents the server configuration for xdperf.
type Server struct {
	Port   int
	Device *net.Interface
	objs   *xdp.XdperfObjects
}

// NewServer creates a new Server instance with the specified attach device and port.
func NewServer(dev *net.Interface, port int) *Server {
	return &Server{
		Port:   port,
		Device: dev,
	}
}

// Run starts the xdperf server, attaching the XDP program to count packets.
func (s *Server) Run() error {
	// Load BPF objects
	s.objs = &xdp.XdperfObjects{}
	if err := xdp.LoadXdperfObjects(s.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier error: %w", ve)
		}
		return fmt.Errorf("loading objects: %v", err)
	}
	defer s.objs.Close()

	if err := s.objs.XdperfVariables.TargetPort.Set(uint16(s.Port)); err != nil {
		return fmt.Errorf("failed to set target port: %v", err)
	}

	// Attach XDP program to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   s.objs.XdperfPrograms.XdpCountPackets,
		Interface: s.Device.Index,
	})
	if err != nil {
		return fmt.Errorf("failed to attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("XDP server started on %s (idx: %d), port: %d\n",
		s.Device.Name, s.Device.Index, s.Port)
	fmt.Println("Press Ctrl+C to stop")

	// Start statistics display
	ctx, cancel := context.WithCancel(context.Background())
	go s.printStats(ctx)

	// Handle signals for graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	fmt.Println("\nShutting down server...")
	cancel()
	return nil
}

// printStats displays packet statistics every second
func (s *Server) printStats(ctx context.Context) {
	var prevPackets uint64
	var prevBytes uint64
	possibleCPUs := ebpf.MustPossibleCPU()
	recs := make([]xdp.XdperfDatarec, possibleCPUs) // Use XdperfDatarec type
	p := message.NewPrinter(message.MatchLanguage("en"))
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var key uint32
			err := s.objs.StatsMap.Lookup(&key, &recs)
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
			p.Printf("%d packets/s, %.2f Mbps\n", deltaPackets, float64(deltaBytes*8)/1024/1024)
		case <-ctx.Done():
			return
		}
	}
}
