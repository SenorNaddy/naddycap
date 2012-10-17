#ifndef PLUGIN_H
#define PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

enum packetret { DROPPED, ACCEPTED, ERROR, OUTPUTTED };

void init(char *args);
enum packetret parse_packet(libtrace_packet_t *pkt);
void cleanup();

#ifdef __cplusplus
}
#endif

#endif
