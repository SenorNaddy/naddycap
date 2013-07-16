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

libtrace_out_t *output;

void init(config_setting_t *setting)
{
	const char *str;
	config_setting_lookup_string(setting, "filename", &str);
	char file[256];
	sprintf(file, "erf:%s",str);
	output = trace_create_output(file);
	trace_start_output(output);
}
enum packetret parse_packet(libtrace_packet_t *pkt)
{
	trace_write_packet(output, pkt);
	return OUTPUTTED;
}
void cleanup()
{
	trace_destroy_output(output);
}
