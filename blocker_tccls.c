#include "../vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define TC_ACT_SHOT	2
#define TC_ACT_OK 0


struct Key {
	unsigned int src_ip;               //source ip
	unsigned int dst_ip;               //destination ip
	unsigned short src_port;  //source port
	unsigned short dst_port;  //destination port
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct Key);
	__type(value, int);
	__uint(max_entries, 1024);
} blockListMap SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("classifier")
int blocker(struct __sk_buff *skb) {

	void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *ethernet = data;
	if (data + ETH_HLEN>data_end){
		goto KEEP;
	}
	//filter IP packets (ethernet type = 0x0800)
	if (bpf_ntohs(BPF_CORE_READ(ethernet,h_proto)) != ETH_P_IP) {
		goto KEEP;
	}

	struct iphdr *ip = (void*) ethernet + ETH_HLEN;
	__u32 iphdr_siz = bpf_core_type_size(struct iphdr);
	if ((void*) ethernet + ETH_HLEN + iphdr_siz>data_end) goto KEEP;
	if (BPF_CORE_READ(ip,protocol) != IP_TCP) goto KEEP;
    if ((void*) ip + iphdr_siz > data_end) goto DROP;

	struct tcphdr *tcp = (void*) ip + iphdr_siz;
	__u32 tcphdr_siz = bpf_core_type_size(struct tcphdr);
	if ((void*) ip + iphdr_siz + tcphdr_siz>data_end){
		goto KEEP;
	}

	__u32 ipdst= bpf_htonl(BPF_CORE_READ(ip,daddr));
	__u32 ipsrc = bpf_htonl(BPF_CORE_READ(ip,saddr));
	__u16 tcpdst = bpf_htons(BPF_CORE_READ(tcp,dest));
	__u16 tcpsrc = bpf_htons(BPF_CORE_READ(tcp,source));

	struct Key pckInfoFrw = { .dst_ip = ipdst,
                           .src_ip = ipsrc,
                           .dst_port = tcpdst,
                           .src_port = tcpsrc };
	
	struct Key pckInfoInv = { .dst_ip = ipsrc,
                           .src_ip = ipdst,
                           .dst_port = tcpsrc,
                           .src_port = tcpdst };

    int* match = bpf_map_lookup_elem(&blockListMap, &pckInfoFrw);
    if (match != NULL) {
		goto DROP;
	}
	match = bpf_map_lookup_elem(&blockListMap, &pckInfoInv);
	if (match != NULL) {
		goto DROP;
	} 
	else {
		goto KEEP;
	}
	//keep the packet and send it to userspace
	KEEP:
	return TC_ACT_OK;

	//drop the packet
	DROP:
	return TC_ACT_SHOT;

}