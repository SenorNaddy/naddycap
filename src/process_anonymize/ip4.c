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
