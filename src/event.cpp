#include "includes/naddycap.h"

void mon_event(mon_env_t *env_tmp)
{
	struct libtrace_eventobj_t event;
	libtrace_t *trace = env_tmp->trace;
	int poll_again = 1;

	do
	{
		if(!env_tmp->packet)
		{
			env_tmp->packet = trace_create_packet();
		}
		event = trace_event(trace, env_tmp->packet);
		poll_again = process_mon_event(env_tmp,event);
	} while (poll_again);
}

void fd_read_event(struct wand_fdcb_t *evcb, enum wand_eventtype_t ev)
{
	mon_env_t *env_tmp = (mon_env_t *)evcb->data;
	wand_del_event(env_tmp->wand_ev_hdl, evcb);
	mon_event(env_tmp);
}

void timer_event(struct wand_timer_t *timer)
{
	mon_event((mon_env_t *)timer->data);
}

int process_mon_event(mon_env_t *env_tmp, libtrace_eventobj_t event)
{
	wand_event_handler_t *ev_hdl_tmp = env_tmp->wand_ev_hdl;
	int micros;
	switch(event.type)
	{
		case TRACE_EVENT_IOWAIT:
			env_tmp->fd_cb.fd = event.fd;
			env_tmp->fd_cb.flags = EV_READ;
			env_tmp->fd_cb.data = env_tmp;
			env_tmp->fd_cb.callback = fd_read_event;
			wand_add_event(ev_hdl_tmp, &env_tmp->fd_cb);
			return 0;
		case TRACE_EVENT_SLEEP:
			micros = (int)((event.seconds - (int)event.seconds)*1000000.0);
			env_tmp->timer.expire = wand_calc_expire(ev_hdl_tmp, (int)event.seconds, micros);
			env_tmp->timer.callback = timer_event;
			env_tmp->timer.data = env_tmp;
			env_tmp->timer.prev = env_tmp->timer.next = NULL;
			wand_add_timer(ev_hdl_tmp, &env_tmp->timer);
			return 0;
		case TRACE_EVENT_PACKET:
			if(event.size == -1)
			{
				ev_hdl_tmp->running = false;
				return 0;
			}
			int res;
			res = execute_pipeline(env_tmp->packet);
			if(res == -1)
			{
				ev_hdl_tmp->running = false;
				return 0;
			}
			if(!env_tmp->packet)
			{
				env_tmp->packet = trace_create_packet();
			}
			return 1;
		case TRACE_EVENT_TERMINATE:
			ev_hdl_tmp->running = false;
			return 0;

		default:
			return 0;
	}
}
