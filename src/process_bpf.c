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
