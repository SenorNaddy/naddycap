#ifndef naddycap_H_
#define naddycap_H_

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "libtrace.h"
#include "libwandevent.h"
#include "plugin.h"
#include "structs.h"
#include "args.h"
#include "event.h"

int execute_pipeline(libtrace_packet_t *pkt);
void naddycap_cleanup(libtrace_packet_t *packet, libtrace_t *trace, module m);
void naddycap_exit(int sig);

extern process_path *path_head, *path_curr;

#endif
