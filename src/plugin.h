#ifndef PLUGIN_H
#define PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

void init(char *args);
void parse_packet(libtrace_packet_t *pkt);
void cleanup();

#ifdef __cplusplus
}
#endif

#endif
