#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "libtrace.h"
#include "plugin.h"
#include "structs.h"
#include "args.h"
#include "naddycap.h"

char trace_file[25];
module m;
libtrace_t *trace = NULL;
libtrace_packet_t *packet;
arguments args;

process_path *path_head, *path_curr;

int main(int argc, char *argv[])
{
	signal(SIGABRT, &naddycap_exit);
	signal(SIGKILL, &naddycap_exit);
	signal(SIGINT, &naddycap_exit);
	signal(SIGTERM, &naddycap_exit);

	char *error;

	initialize_clargs(&args);
	void *argtable[] = {args.help, args.version, args.modules, args.interface, args.module_path, args.num_packets, args.end};

	int nerrors;
	if(arg_nullcheck(argtable) != 0)
	{
		printf("%s: insufficient memory\n", argv[0]);
		naddycap_exit(1);
	}

	nerrors = arg_parse(argc, argv, argtable);

	if ( (args.help)->count > 0)
	{
		arg_print_syntaxv(stdout, argtable, "\n");
		arg_print_glossary(stdout, argtable, "	%-25s %s\n");
		naddycap_exit(2);
	}

	sprintf(trace_file, "pcapint:%s",args.interface->sval[0]);

	int i;
	for(i = 0; i < args.modules->count; i++)
	{
		process_path *p = (process_path *)malloc(sizeof(process_path));
		p->m = (module *)malloc(sizeof(module));
		printf("Loading %s\n", args.modules->sval[i]);
		char module_path_name[256];
		sprintf(module_path_name, "%s%s", args.module_path->sval[0], args.modules->sval[i]);
		p->m->lib_handle = dlopen(module_path_name, RTLD_LAZY);
		if(!p->m->lib_handle)
		{
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}

		p->m->init = (InitFunc)dlsym(p->m->lib_handle, "init");

		if ((error = dlerror()) != NULL)
		{
			fprintf(stderr, "%s\n", error);
			return -1;
		}

		p->m->parse_packet = (ParseFunc)dlsym(p->m->lib_handle, "parse_packet");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	return -1;
        	}
		p->m->cleanup = (CleanupFunc)dlsym(p->m->lib_handle,"cleanup");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	return -1;
        	}
		(*(p->m->init))(argv[argc-1]);
		p->next = NULL;
		if(i == 0)
		{
			path_head = path_curr =  p;
		}
		if(i > 0)
		{
			path_curr->next = p;
		}
		path_curr = p;
	}
	packet = trace_create_packet();

	trace = trace_create(trace_file);

	if (trace_is_err(trace))
	{
		trace_perror(trace, "Opening trace file");
		return 1;
	}

	if (trace_start(trace) == -1)
	{
		trace_perror(trace,"starting trace");
		return 1;
	}
	int read = 0;

	while (trace_read_packet(trace, packet) > 0 && (args.num_packets->count <= 0 || read < args.num_packets->ival[0]))
	{
		path_curr = path_head;
		while(path_curr != NULL)
		{
			enum packetret p = (*(path_curr->m->parse_packet))(packet);
			if(p == DROPPED) break;
			path_curr = path_curr->next;
		}
		read++;
	}
	naddycap_exit(0);
}

void naddycap_exit(int sig)
{
	naddycap_cleanup(packet, trace, m);
	exit(0);
}

void naddycap_cleanup(libtrace_packet_t *packet, libtrace_t *trace, module m)
{
	if(trace)
		trace_destroy(trace);
	if(packet)
		trace_destroy_packet(packet);
	free(args.help);
	free(args.version);
	free(args.modules);
	free(args.interface);
	free(args.module_path);
	free(args.num_packets);
	free(args.end);
	path_curr = path_head;
	process_path *p2free;
	while(path_curr != NULL)
	{
		if(path_curr->m->lib_handle)
		{
			(*(path_curr->m->cleanup))();
			dlclose(path_curr->m->lib_handle);
		}
		free(path_curr->m);
		p2free = path_curr;
		path_curr = path_curr->next;
		free(p2free);
	}
}
