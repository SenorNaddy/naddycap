#include "libtrace.h"
#include <stdio.h>
#include "includes/plugin.h"


void init(char *args)
{
}
enum packetret parse_packet(libtrace_packet_t *pkt)
{
	return DROPPED;
}
void cleanup()
{
}
