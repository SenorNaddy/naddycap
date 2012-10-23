#include "libtrace.h"
#include <stdio.h>
#include "includes/plugin.h"
#include <string.h>
#include <arpa/inet.h>

int simple_remove;
int enc_source;
int enc_dest;
int prefix_replace;
int prefix_preserve;
uint32_t prefix4;
uint32_t netmask4;
uint32_t netmask6[4];
uint8_t prefix6[16];

uint32_t masks[33] = {
	0x00000000, 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
	0xf8000000, 0xfc000000, 0xfe000000, 0xff000000, 0xff800000,
	0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000,
	0xfffe0000, 0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000,
	0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
	0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8,
	0xfffffffc, 0xfffffffe, 0xffffffff,
};

void init(config_setting_t *setting)
{
	const char *prefix_replacement6;
	const char *prefix_replacement4;
	if(!setting) { fprintf(stderr, "Setting is null"); return; }
	if(!config_setting_lookup_bool(setting, "remove", &simple_remove)) simple_remove = false;
	if(!config_setting_lookup_bool(setting, "enc_source", &enc_source)) enc_source = false;
	if(!config_setting_lookup_bool(setting, "enc_dest", &enc_dest)) enc_dest = false;
	if(!config_setting_lookup_bool(setting, "prefix_replace", &prefix_replace)) prefix_replace = false;;
	if(!config_setting_lookup_bool(setting, "prefix_preserve", &prefix_preserve)) prefix_preserve = false;
	if(config_setting_lookup_string(setting, "prefix_replacement4", &prefix_replacement4))
	{
		int a,b,c,d,bits;
		sscanf(prefix_replacement4,"%i.%i.%i.%i/%i",
			&a, &b, &c, &d, &bits);
		prefix4 = (a<<24)+(b<<16)+(c<<8)+d;
		netmask4 = masks[bits];
	}
	if(config_setting_lookup_string(setting, "prefix_replacement6", &prefix_replacement6))
	{
		char tmp_address[INET6_ADDRSTRLEN];
		int bits;
		sscanf(prefix_replacement6, "%[0-9a-fA-F:]/%i",tmp_address, &bits);

		struct in6_addr tmp_addr;
		inet_pton(AF_INET6, tmp_address, &tmp_addr);

		char address[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &tmp_addr, address, INET6_ADDRSTRLEN);
		memcpy(prefix6, tmp_addr.s6_addr, sizeof(prefix6));

		int i;
		for(i = 0; i < 4; i++)
		{
			if(bits < 0) bits = 0;
			if(bits > 32) netmask6[i] = masks[32];
			else netmask6[i] = masks[bits];
			bits = bits - 32;
		}
	}
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
	if(prefix_preserve)
	{
		return ((prefix4 & old_ip) & netmask4) | (old_ip & ~netmask4);
	}
	if(prefix_replace)
	{
		return (prefix4 & netmask4) | (old_ip & ~netmask4);
	}
}

void enc_ip6(uint8_t old_ip[], void **new_ip)
{
	if(simple_remove)
	{
		uint8_t tmp_new_ip[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		memcpy(new_ip, tmp_new_ip, sizeof(tmp_new_ip));
	}
	if(prefix_replace || prefix_preserve)
	{
		uint8_t tmp_new_ip[16];
		int i,k,m;
		uint8_t tmp_netmask;
		m = 0;
		for(i = 0; i < 4; i++)
		{
			for(k = 0; k < 4; k++)
			{
				switch(k)
				{
					case 0:
						tmp_netmask = (netmask6[i] >> 24) & 0xFF;
						break;
					case 1:
						tmp_netmask = (netmask6[i] >> 16) & 0xFF;
						break;
					case 2:
						tmp_netmask = (netmask6[i] >> 8) & 0xFF;
						break;
					case 3:
						tmp_netmask = netmask6[i] & 0xFF;
						break;
				}
				if(prefix_replace) tmp_new_ip[m] =  (prefix6[m] & tmp_netmask) | (old_ip[m] & ~tmp_netmask);
				if(prefix_preserve) tmp_new_ip[m] = ((prefix6[m] & old_ip[m]) & tmp_netmask) | (old_ip[m] & ~tmp_netmask);
				m++;
			}
		}
		memcpy(new_ip, tmp_new_ip, sizeof(tmp_new_ip));
	}
}

void replace_ip6(struct libtrace_ip6 *ip6, libtrace_packet_t *p, int enc_src, int enc_dst)
{

	struct libtrace_tcp *tcp;
	struct libtrace_udp *udp;
	struct libtrace_icmp *icmp;
	void *payload;
	tcp = NULL;
	udp = NULL;
	icmp = NULL;
	uint32_t remaining;
	uint16_t proto;
	uint8_t payload_proto;
	if(p)
	{
		trace_get_layer3(p, &proto, &remaining);
		if(proto != TRACE_ETHERTYPE_IPV6 || remaining <= 0) return; //we should never execute this
		void *tmp;
		tmp = trace_get_payload_from_ip6(ip6, &payload_proto, &remaining); 
		if(remaining <= 0) return;
		switch (payload_proto)
		{
			case TRACE_IPPROTO_ICMPV6:
				icmp = (struct libtrace_icmp *)tmp;
				break;
			case TRACE_IPPROTO_UDP:
				udp = (struct libtrace_udp *)tmp;
				break;
			case TRACE_IPPROTO_TCP:
				tcp = (struct libtrace_tcp *)tmp;
				break;
		}
	}

	int i;
	uint8_t new_src_ip[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	if(enc_src) enc_ip6(ip6->ip_src.s6_addr,(void*)&new_src_ip);
/*	printf("%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i:%i\n",
		new_src_ip[0], new_src_ip[1], new_src_ip[2], new_src_ip[3],
		new_src_ip[4], new_src_ip[5], new_src_ip[6], new_src_ip[7],
		new_src_ip[8], new_src_ip[9], new_src_ip[10], new_src_ip[11],
		new_src_ip[12], new_src_ip[13], new_src_ip[14], new_src_ip[15]);*/
	uint8_t new_dst_ip[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	if(enc_dst) enc_ip6(ip6->ip_dst.s6_addr,(void*)&new_dst_ip);
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
			replace_ip4((struct libtrace_ip *)tmp, enc_dst, enc_src);
		}
	}

}

enum packetret parse_packet(libtrace_packet_t *pkt)
{
	struct libtrace_ip *ip;
	ip = trace_get_ip(pkt);

	struct libtrace_ip6 *ip6;
	ip6 = trace_get_ip6(pkt);

	if(ip) replace_ip4(ip, enc_source, enc_dest);
	if(ip6) replace_ip6(ip6, pkt, enc_source, enc_dest);
	return ACCEPTED;
}

void cleanup()
{
}
