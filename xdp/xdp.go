package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf Xdperf src/xdperf.c -- -I /usr/include/x86_64-linux-gnu -I include
