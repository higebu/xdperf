/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdperf.h"

volatile int ifidx;
volatile __u16 target_port;

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	int key = 0;
	struct datarec *rec = bpf_map_lookup_elem(&stats_map, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->rx_packets++;
	rec->rx_bytes += ctx->data_end - ctx->data;
	return bpf_redirect(ifidx, 0);
}

SEC("xdp")
int xdp_tx(struct xdp_md *ctx)
{
	int key = 0;
	struct datarec *rec = bpf_map_lookup_elem(&stats_map, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->rx_packets++;
	rec->rx_bytes += ctx->data_end - ctx->data;
	return XDP_TX;
}

SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct udphdr *udph;
	__u16 eth_proto;
	__u8 ip_proto;

	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth_proto = eth->h_proto;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		iph = data + sizeof(*eth);
		if ((void *)iph + sizeof(*iph) > data_end)
			return XDP_PASS;
		if (iph->protocol != IPPROTO_UDP)
			return XDP_PASS;

		udph = (void *)iph + (iph->ihl * 4);
		if ((void *)udph + sizeof(*udph) > data_end)
			return XDP_PASS;

		if (udph->dest == bpf_htons(target_port)) {
			int key = 0;
			struct datarec *rec = bpf_map_lookup_elem(&stats_map, &key);
			if (!rec)
				return XDP_ABORTED;
			rec->rx_packets++;
			rec->rx_bytes += (__u64)(data_end - data);
		}
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		ip6h = data + sizeof(*eth);
		if ((void *)ip6h + sizeof(*ip6h) > data_end)
			return XDP_PASS;
		if (ip6h->nexthdr != IPPROTO_UDP)
			return XDP_PASS;

		udph = (void *)ip6h + sizeof(*ip6h);
		if ((void *)udph + sizeof(*udph) > data_end)
			return XDP_PASS;

		if (udph->dest == bpf_htons(target_port)) {
			int key = 0;
			struct datarec *rec = bpf_map_lookup_elem(&stats_map, &key);
			if (!rec)
				return XDP_ABORTED;
			rec->rx_packets++;
			rec->rx_bytes += (__u64)(data_end - data);
		}
	} else {
		return XDP_PASS;
	}

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
