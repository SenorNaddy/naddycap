#ifndef naddycap_H_
#define naddycap_H_

#include <signal.h>
#include <stdlib.h>
void naddycap_cleanup(libtrace_packet_t *packet, libtrace_t *trace, module m);
void naddycap_exit(int sig);

#endif
