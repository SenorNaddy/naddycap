#include "libtrace.h"
#include <stdio.h>
#include "includes/plugin.h"

libtrace_filter_t *filter;

void init(char *args)
{
	char tmp[256] = "";
	sprintf(tmp, "icmp");
	filter = trace_create_filter(tmp);
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
