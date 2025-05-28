package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf Xdperf src/xdperf.c -- -I /usr/include/x86_64-linux-gnu -I include

// BPF_F_TEST_XDP_LIVE_FRAMES is from linux/bpf.h
const BPF_F_TEST_XDP_LIVE_FRAMES = (1 << 1)
