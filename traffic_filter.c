#include "../vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define IP_TCP 	6
#define ETH_HLEN 14
#define UDP_HLEN 8
#define ETH_P_IP 0x0800
#define BPF_NOEXIST 1

struct Key {
	__u32 src_ip;               //source ip
	__u32 dst_ip;               //destination ip
	__u16 src_port;  //source port
	__u16 dst_port; //destination port
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct Key);
    __type(value, __u32);
    __uint(max_entries, 1024);
} connections SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("socket")
int filter(struct __sk_buff *skb) {	
	
	if (skb->protocol != bpf_htons(ETH_P_IP)) {
		bpf_printk("%d prt",skb->protocol);
		goto DROP;
	}

	__u8 buff[4];

	__u32 iphdr_siz = bpf_core_type_size(struct iphdr);
	if (iphdr_siz == 0) goto DROP;
	if (skb->len < ETH_HLEN + iphdr_siz) goto DROP;
	if (bpf_skb_load_bytes_relative(skb, bpf_core_field_offset(struct iphdr, protocol), buff, 1, BPF_HDR_START_NET )!=0)
		goto DROP;
	if (buff[0] != IP_TCP) {
		goto DROP;
	}

	__u32  tcp_header_length = 0;
	__u32  ip_header_length = 0;
	__u32  payload_offset = 0;
	__u32  payload_length = 0;
	
	
	if (bpf_skb_load_bytes_relative(skb, bpf_core_field_offset(struct iphdr, ihl), buff, 1, BPF_HDR_START_NET )!=0)
		goto DROP;
	
	buff[0] = buff[0] & 0x0F;
	ip_header_length = buff[0] << 2;    

	if (ip_header_length < iphdr_siz) {
		goto DROP;
	}
	
	__u32 tcphdr_siz = bpf_core_type_size(struct tcphdr);
	if (skb->len < ETH_HLEN + ip_header_length + tcphdr_siz) goto DROP;
	if (bpf_skb_load_bytes_relative(skb, ip_header_length + bpf_core_field_offset(struct tcphdr, doff), buff, 1, BPF_HDR_START_NET )!=0)
		goto DROP;
	
	__u16 tcphl = buff[0] & 0xF0; 
	
	tcp_header_length = tcphl >> 2;

	if (bpf_skb_load_bytes_relative(skb, ip_header_length + bpf_core_field_offset(struct tcphdr, dest), buff, 2, BPF_HDR_START_NET )!=0)
		goto DROP;
	__u16 portdst = (buff[0]<<8) | buff[1];
	if (bpf_skb_load_bytes_relative(skb, ip_header_length + bpf_core_field_offset(struct tcphdr, source), buff, 2, BPF_HDR_START_NET )!=0)
		goto DROP;
	__u16 portsrc = (buff[0]<<8) | buff[1];

	if (!( portsrc == 80 || portsrc == 443 || portdst == 80 || portdst == 443 )) goto DROP;

	if (bpf_skb_load_bytes_relative(skb, bpf_core_field_offset(struct iphdr, tot_len), buff, 2, BPF_HDR_START_NET )!=0)
		goto DROP;
	__u16 totlen = (buff[0]<<8) | buff[1]; 

	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = totlen - ip_header_length - tcp_header_length;

	if(payload_length < 7) {
		goto DROP;
	}

	if (bpf_skb_load_bytes_relative(skb, bpf_core_field_offset(struct iphdr, daddr), buff, 4, BPF_HDR_START_NET )!=0)
		goto DROP;
	__u32 ipdst = (buff[0]<<24) | (buff[1]<<16) | (buff[2]<<8) | buff[3];  
	
	if (bpf_skb_load_bytes_relative(skb, bpf_core_field_offset(struct iphdr, saddr), buff, 4, BPF_HDR_START_NET )!=0)
		goto DROP;
	__u32 ipsrc = (buff[0]<<24) | (buff[1]<<16) | (buff[2]<<8) | buff[3];
	
	struct Key key = { .dst_ip= ipdst, .src_ip = ipsrc, .dst_port=portdst, .src_port=portsrc};
	
	__u32 timestamp = 0;

	char p[7];
	__u32 err = bpf_skb_load_bytes(skb, payload_offset, p, 7);
	if (err!=0) {
		goto DROP;
	}

	//find a match with an HTTP request
	
	//GET
	else if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//POST
	else if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		goto HTTP_MATCH;
	}
	//PUT
	else if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//DELETE
	else if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		goto HTTP_MATCH;
	}
	//HEAD
	else if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		goto HTTP_MATCH;
	}
	//TLS match
	else if ((p[0] == 0x16) && (p[2] == 1) && (p[1] == 3)) {
		goto TLS_MATCH;
	} 
	//no HTTP match
	//check if packet belong to an existing connection
	__u32 * lookup_timestamp= bpf_map_lookup_elem(&connections, &key);
	if(lookup_timestamp!=NULL) {
		//send packet to userspace
		goto KEEP;
	}
	goto DROP;

	TLS_MATCH:
	bpf_printk("Tls match");
	err = bpf_map_update_elem(&connections, &key, &timestamp, BPF_NOEXIST);
	bpf_printk("%d %d %d ", err, key.dst_port, key.src_port);
	goto KEEP;

	HTTP_MATCH:
	bpf_printk("Http match");
	err = bpf_map_update_elem(&connections, &key, &timestamp, BPF_NOEXIST);
	bpf_printk("%d %d %d ", err, key.dst_port, key.src_port);
	goto KEEP;

	KEEP:
	return -1;

	DROP:
	return 0;

}