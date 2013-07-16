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

#include "includes/naddycap.h"

int execute_pipeline(libtrace_packet_t *packet)
{
	if(args.num_packets->count == 0 || args.num_packets->ival[0] > 0)
	{
		path_curr = path_head;
		enum packetret p;
		while(path_curr != NULL)
		{
			p = (*(path_curr->m->parse_packet))(packet);
			if (p == DROPPED) break;
			path_curr = path_curr->next;
		}
		if (p != DROPPED) args.num_packets->ival[0]--;
		return 0;
	}
	else
	{
		return -1;
	}
}
