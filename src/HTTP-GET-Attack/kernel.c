#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>


#define THRESHOLD 100


BPF_HASH(ipv4_table);
BPF_HASH(ipv4_blocked);

int xdp_http_get(struct xdp_md *ctx) {

    int zero = 0,one = 1, two = 2;
    __u32 ip4_address = 0 ;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {

        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end){
            return XDP_PASS;
        }
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (void *)((unsigned char *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) > data_end){
                return XDP_PASS;
            }
        }
        ip4_address = be32_to_cpu(ip->addrs.saddr);
        u64 uid1 = ip4_address;


        u64* valid = ipv4_blocked.lookup(&uid1);
        if (valid != 0) {
            bpf_trace_printk("passed");
            return XDP_PASS;
        }
        else {
            // check if ip is blocked
            if (*valid == 1) {
                bpf_trace_printk("dropped");
                return XDP_DROP;
            }
            else {
                return XDP_PASS;
            }
        }

    }
    else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {

        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end){
            return XDP_PASS;
        }
        if (ipv6->nexthdr == IPPROTO_TCP){
            tcp = (void *)((unsigned char *)ipv6 + 1);
            if ((void *)(tcp + 1) > data_end){
                return XDP_PASS;
            }
        }
    }
    else{
        return XDP_PASS;
    }

    //get the data offset header field
    __u32 doff = tcp->doff ;



    bpf_trace_printk("tcp data offset: %u", doff) ;


    //calculate the position of tcp payload start
    char* tcp_payload = (unsigned char*)tcp + 20;
    bpf_trace_printk("tcp payload1: %s", tcp_payload);

    //get first 3 characters of tcp payload
    __u32 c1 = *tcp_payload , c2 = *(tcp_payload+1) ,c3 = *(tcp_payload+2) ;

    //if it is a GET packet
    if ( c1== 'G' && c2 =='E' && c3 == 'T') {
    //if(1) {
        u64 uid = ip4_address, *p;

        bpf_trace_printk("ipv4 address: %u ", ip4_address ) ;

        u64 counter = 0;
        p = ipv4_table.lookup(&uid);
        if (p != 0) {
            counter = *p;
        }
        counter++;

        //if too many GET packets from same IP, permanently block that IP
        if (counter > THRESHOLD) {
            __u64 x = 1;
            ipv4_blocked.update(&uid, &x);
        }
        else {
            __u64 x = 2;
            ipv4_blocked.update(&uid, &x);
        }
        ipv4_table.update(&uid, &counter);

    }

    return XDP_PASS;
}
