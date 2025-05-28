# xdperf

> **⚠️ This project is currently a Work In Progress (WIP) and may undergo significant changes. ⚠️**

## Overview

`xdperf` is a high-performance network traffic generation and analysis tool that utilizes XDP (eXpress Data Path). It can operate in both client and server modes to test network throughput and packet rates.

## Features

* **Client/Server Mode**: Can act as a traffic generator (client) or a packet counter (server).
* **XDP-based Packet Processing**: Leverages XDP for fast packet redirection and counting directly in the kernel.
* **Configurable Parameters**:
  * Source/Destination IP Addresses
  * Source/Destination MAC Addresses
  * Source/Destination UDP Ports
  * Packet Size
  * Number of Goroutines for Traffic Generation

## Requirements

* Linux Kernel with XDP and BPF_F_TEST_XDP_LIVE_FRAMES support (5.18 or newer)
* Go 1.24.2 or later (as specified in `go.mod`)
* clang
* libbpf-dev
* libxdp-dev

## Installation

To install `xdperf`, you need to have Go installed on your system. You can install it using the following command:

```bash
go install github.com/higebu/xdperf@latest
```

## Usage

### Server Mode

The server mode listens on a specified network interface and UDP port, counting incoming packets that match the port.

**Command:**

```bash
sudo xdperf --server --port <port> <device>
```

**Example:**

```bash
sudo xdperf --server --port 12345 eth0
```

This starts the server on interface `eth0`, listening for UDP packets on port `12345`.

### Client Mode

The client mode generates and sends UDP packets to a specified destination.

**Command:**

```bash
sudo xdperf [flags] <device>
```

**Flags:**

* `--src-ip <ip>`: Source IP address (default: 127.0.0.1)
* `--dst-ip <ip>`: Destination IP address (default: 127.0.0.1)
* `--src-port <port>`: Source UDP port (default: 12345)
* `--dst-port <port>`: Destination UDP port (default: 12345)
* `--src-mac <mac>`: Source MAC address (default: MAC of the redirect device)
* `--dst-mac <mac>`: Destination MAC address (default: 00:00:00:00:00:00)
* `-s, --size <bytes>`: Packet size in bytes (default: 64)
* `-p, --parallel <num>`: Number of goroutines for sending packets (default: 1)
* `--pps <num>`: Packets per second (default: 0, no rate limit)
* `--batch-size <num>`: Number of packets to send in a batch (default: 1 or 1048576 if no rate limit)

**Example:**

Sending traffic from `eth0` to `192.168.1.100:8080`:

```bash
sudo xdperf --dst-ip 192.168.1.100 --dst-mac 00:00:00:00:00:00 --dst-port 8080 eth0
```

Sending traffic with 100-byte packets using 4 goroutines:

```bash
sudo xdperf --dst-ip 192.168.1.100 --dst-mac 00:00:00:00:00:00 --dst-port 8080 -s 100 -p 4 eth0
```

## License

MIT License
