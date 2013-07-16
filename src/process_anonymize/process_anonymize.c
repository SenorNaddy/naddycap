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

int simple_remove;
int enc_source;
int enc_dest;
int prefix_replace;
int prefix_preserve;
int cryptopan;
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
	if(!config_setting_lookup_bool(setting, "prefix_replace", &prefix_replace)) prefix_replace = false;
	if(!config_setting_lookup_bool(setting, "prefix_preserve", &prefix_preserve)) prefix_preserve = false;
	if(!config_setting_lookup_bool(setting, "cryptopan", &cryptopan)) cryptopan = false;
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
