#ifndef PLUGIN_H
#define PLUGIN_H

#include "libconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

enum packetret { DROPPED, ACCEPTED, ERROR, OUTPUTTED };

void init(config_setting_t *settings);
enum packetret parse_packet(libtrace_packet_t *pkt);
void cleanup();

#ifdef __cplusplus
}
#endif

#endif
