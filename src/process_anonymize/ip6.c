/*
* naddycap - Extensible Network Capture
* Copyright (C) 2013 Simon Wadsworth
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes/process_anonymize.h"

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
