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
