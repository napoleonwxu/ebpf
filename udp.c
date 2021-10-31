#define KBUILD_MODNAME "udp"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

static void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];
	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

// no need to recalculate checksum:
// reply packets failed if recalculate, set checksum to 0 is better
int udp_reverse(struct xdp_md *ctx) {
    //bpf_trace_printk("receive a packet\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }
    if (ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    //bpf_trace_printk("receive a udp packet\n");
    struct udphdr *udp = (void*)ip + sizeof(*ip);
    if ((void*)udp + sizeof(*udp) > data_end) {
        return XDP_PASS;
    }

    if (udp->dest != ntohs(55007)) {
        return XDP_PASS;
    }

    //bpf_trace_printk("receive a udp packet, dst port 55005\n");
    //return XDP_PASS; // for XDP_PASS test

    // update mac header
    swap_src_dst_mac(data);

    // update ip header
    __be32 raddr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = raddr;

    // update udp header
    __be16 rport = udp->source;
    udp->source = udp->dest;
    udp->dest = rport;

    // reply packet
    return XDP_TX;
}