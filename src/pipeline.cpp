#include "naddycap.h"

int execute_pipeline(libtrace_packet_t *packet)
{
	if(args.num_packets->count <= 0 || args.num_packets->ival[0] > 0)
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
