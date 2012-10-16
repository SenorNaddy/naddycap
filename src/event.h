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
