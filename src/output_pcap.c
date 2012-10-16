#include "libtrace.h"
#include <stdio.h>
#include "plugin.h"

libtrace_out_t *output;

void init(char *args)
{
	char file[256];
	sprintf(file, "pcapfile:%s",args);
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
