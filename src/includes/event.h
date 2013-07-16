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

#ifndef _event_H
#define _event_H

typedef struct mon_environment {
	wand_event_handler_t *wand_ev_hdl;
	struct wand_fdcb_t fd_cb;
	struct wand_timer_t timer;
	libtrace_t *trace;
	libtrace_packet_t *packet;
} mon_env_t;

void mon_event(mon_env_t *env);
void fd_read_event(struct wand_fdcb_t *evcb, enum wand_eventtype_t ev);
void timer_event(struct wand_timer_t *timer);
int process_mon_event(mon_env_t *env, libtrace_eventobj_t event);

#endif
