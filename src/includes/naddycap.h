/*
* naddycap - Extensible Network Capture
* Copyright (C) 2013 Simon Wadsworth
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef naddycap_H_
#define naddycap_H_

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "libconfig.h"
#include "argtable2.h"
#include "libtrace.h"
#include "libwandevent.h"
#include "plugin.h"
#include "structs.h"
#include "args.h"
#include "event.h"

int execute_pipeline(libtrace_packet_t *pkt);
void naddycap_cleanup(libtrace_packet_t *packet, libtrace_t *trace, module m);
void naddycap_exit(int sig);
void parse_config(const char *config_file);

extern process_path *path_head, *path_curr;
extern config_t config;
#endif
