#include "libtrace.h"
#include <stdio.h>
#include "includes/plugin.h"
#include <string.h>

int simple_remove;
int enc_source;
int enc_dest;
int prefix_replace;
const char *prefix_replacement4;
const char *prefix_replacement6;

void init(config_setting_t *setting)
{
	if(!setting) { fprintf(stderr, "Setting is null"); return; }
	if(!config_setting_lookup_bool(setting, "remove", &simple_remove)) simple_remove = false;
	if(!config_setting_lookup_bool(setting, "enc_source", &enc_source)) enc_source = false;
	if(!config_setting_lookup_bool(setting, "enc_dest", &enc_dest)) enc_dest = false;
	if(!config_setting_lookup_bool(setting, "prefix_replace", &prefix_replace)) prefix_replace = false;;
	if(!config_setting_lookup_string(setting, "prefix_replacement4", &prefix_replacement4));
	if(!config_setting_lookup_string(setting, "prefix_replacement6", &prefix_replacement6));
}

static void update_in_cksum(uint16_t *csum, uint16_t old, uint16_t new)
{
	uint32_t sum = (~htons(*csum) & 0xFFFF)
			+ (~htons(old) & 0xFFFF)
			+ htons(new);
	sum = (sum & 0xFFFF) + (sum >> 16);
	*csum = htons(~(sum + (sum >> 16)));
}

static void update_in_cksum32(uint16_t *csum, uint32_t old, uint32_t new)
{
	update_in_cksum(csum, (uint16_t)(old>>16),(uint16_t)(new>>16));
	update_in_cksum(csum, (uint16_t)(old&0xFFFF), (uint16_t)(new&0xFFFF));
}

uint32_t enc_ip4(uint32_t old_ip)
{
	if(simple_remove)
	{
		return 0;
	}
}

void enc_ip6(uint8_t old_ip[], void **new_ip)
{
	if(simple_remove)
	{
		uint8_t tmp_new_ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		memcpy(new_ip, tmp_new_ip, sizeof(tmp_new_ip));
	}
}

void replace_ip6(struct libtrace_ip6 *ip6, libtrace_packet_t *p, int enc_src, int enc_dst)
{

	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	struct libtrace_icmp *icmp;

	tcp = trace_get_tcp(p);
	udp = trace_get_udp(p);
	icmp = trace_get_icmp(p);

	int i;
	uint8_t new_src_ip[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	enc_ip6(ip6->ip_src.s6_addr,(void*)&new_src_ip);
	uint8_t new_dst_ip[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	enc_ip6(ip6->ip_dst.s6_addr,(void*)&new_dst_ip);
	for(i = 0; i < 16; i++)
	{
		if(enc_src)
		{
			ip6->ip_src.s6_addr[i] = new_src_ip[i];
		}
		if(enc_dst)
		{
			ip6->ip_dst.s6_addr[i] = new_dst_ip[i];
		}
	}
	if(tcp) tcp->check = 0;
	if(udp) udp->check = 0;

	if(icmp)
	{
		icmp->checksum = 0;
		char *tmp = (char *)icmp;
		tmp = tmp + sizeof(struct libtrace_icmp);
		if(icmp->type == 1 || icmp->type == 3)
		{
			replace_ip6((struct libtrace_ip6 *)tmp, NULL, enc_dst, enc_src);
		}
	}

}

void replace_ip4(struct libtrace_ip *ip, int enc_src, int enc_dst)
{
	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	struct libtrace_icmp *icmp;
	tcp = trace_get_tcp_from_ip(ip, NULL);
	udp = trace_get_udp_from_ip(ip, NULL);
	icmp = trace_get_icmp_from_ip(ip, NULL);

	if(enc_src)
	{
		uint32_t old_ip = ip->ip_src.s_addr;
		uint32_t new_ip = htonl(enc_ip4(htonl(old_ip)));
		update_in_cksum32(&ip->ip_sum, old_ip, new_ip);
		if(tcp)	update_in_cksum32(&tcp->check, old_ip, new_ip);
		if(udp) update_in_cksum32(&udp->check, old_ip, new_ip);
		ip->ip_src.s_addr = new_ip;
	}
	if(enc_dst)
	{
		uint32_t old_ip = ip->ip_dst.s_addr;
		uint32_t new_ip = htonl(enc_ip4(htonl(old_ip)));
		update_in_cksum32(&ip->ip_sum, old_ip, new_ip);
		if(tcp) update_in_cksum32(&tcp->check, old_ip, new_ip);
		if(udp) update_in_cksum32(&udp->check, old_ip, new_ip);
		ip->ip_dst.s_addr = new_ip;
	}

	if(icmp)
	{
		char *tmp = (char *)icmp;
		tmp = tmp + sizeof(struct libtrace_icmp);
		if(icmp->type == 3 || icmp->type == 5 || icmp->type == 11)
		{
			replace_ip((struct libtrace_ip *)tmp, enc_dst, enc_src);
		}
	}

}

enum packetret parse_packet(libtrace_packet_t *pkt)
{
	struct libtrace_ip *ip;
	ip = trace_get_ip(pkt);

	struct libtrace_ip6 *ip6;
	ip6 = trace_get_ip6(pkt);

	if(!ip) return ACCEPTED;

	if(ip) replace_ip(ip, enc_source, enc_dest);
	if(ip6) replace_ip6(ip6, pkt, enc_source, enc_dest);
	return ACCEPTED;
}

void cleanup()
{
}
