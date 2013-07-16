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

#include "libtrace.h"
#include <stdio.h>
#include "includes/plugin.h"

libtrace_filter_t *filter;

void init(config_setting_t *setting)
{
	const char *filter_str;
	config_setting_lookup_string(setting, "filter", &filter_str);
	filter = trace_create_filter(filter_str);
}
enum packetret parse_packet(libtrace_packet_t *pkt)
{
	if(trace_apply_filter(filter, pkt) == 0)
		return DROPPED;
	else return ACCEPTED;
}
void cleanup()
{
	trace_destroy_filter(filter);
}
