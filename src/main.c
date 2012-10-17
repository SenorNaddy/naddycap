#include "includes/naddycap.h"

char trace_file[25];
module m;
libtrace_t *trace = NULL;
//libtrace_packet_t *packet;
arguments args;

process_path *path_head, *path_curr;

wand_event_handler_t *ev_hdl;
mon_env_t env;

unsigned char* process_path_memory;


int main(int argc, char *argv[])
{
	ev_hdl = NULL;
	signal(SIGABRT, &naddycap_exit);
	signal(SIGKILL, &naddycap_exit);
	signal(SIGINT, &naddycap_exit);
	signal(SIGTERM, &naddycap_exit);

	char *error;

	initialize_clargs(&args);
	void *argtable[] = {args.help, args.version, args.modules, args.interface, args.module_path, args.num_packets, args.output_file, args.end};

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

	if( nerrors > 0)
	{
		arg_print_errors(stdout, args.end, argv[0]);
		fprintf(stdout, "\n");
		arg_print_syntaxv(stdout, argtable, "\n");
		arg_print_glossary(stdout, argtable, "	%-25s %s\n");
		naddycap_exit(-1);
	}

	sprintf(trace_file, "pcapint:%s",args.interface->sval[0]);

	int i;
	process_path_memory = (unsigned char*)malloc((sizeof(process_path)+sizeof(module))*args.modules->count);

	int index = 0;
	for(i = 0; i < args.modules->count; i++)
	{
		process_path *p = (process_path *)(process_path_memory+index);
		index += sizeof(process_path);
		//process_path *p = (process_path *)malloc(sizeof(process_path));
		p->m = (module *)(process_path_memory+index);
		index += sizeof(module);
		//p->m = (module *)malloc(sizeof(module));
		printf("Loading %s\n", args.modules->sval[i]);
		char module_path_name[256];
		sprintf(module_path_name, "%s%s", args.module_path->sval[0], args.modules->sval[i]);
		p->m->lib_handle = dlopen(module_path_name, RTLD_LAZY);
		if(!p->m->lib_handle)
		{
			fprintf(stderr, "%s\n", dlerror());
			naddycap_exit(-1);
		}

		p->m->init = (InitFunc)dlsym(p->m->lib_handle, "init");

		if ((error = dlerror()) != NULL)
		{
			fprintf(stderr, "%s\n", error);
			naddycap_exit(-1);
		}

		p->m->parse_packet = (ParseFunc)dlsym(p->m->lib_handle, "parse_packet");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	naddycap_exit(-1);
        	}
		p->m->cleanup = (CleanupFunc)dlsym(p->m->lib_handle,"cleanup");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	naddycap_exit(-1);
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
	env.packet = NULL;
	if(wand_event_init() == -1) {
		naddycap_exit(-1);
	}

	ev_hdl = wand_create_event_handler();
	if(ev_hdl == NULL)
	{
		naddycap_exit(-1);
	}

	env.wand_ev_hdl = ev_hdl;


	//packet = trace_create_packet();

	trace = trace_create(trace_file);

	if (trace_is_err(trace))
	{
		trace_perror(trace, "Opening trace file");
		naddycap_exit(1);
	}

	if (trace_start(trace) == 0)
	{
		env.trace = trace;
		ev_hdl->running = true;
		mon_event(&env);
		wand_event_run(ev_hdl);
	}
	/*int read = 0;

	while (trace_read_packet(trace, packet) > 0 && (args.num_packets->count <= 0 || read < args.num_packets->ival[0]))
	{
		execute_pipeline(packet);
		read++;
	}*/
	naddycap_exit(0);
}

void naddycap_exit(int sig)
{
	naddycap_cleanup(env.packet, trace, m);
	exit(sig);
}

void naddycap_cleanup(libtrace_packet_t *packet, libtrace_t *trace, module m)
{
	if(trace)
		trace_destroy(trace);
	if(packet)
		trace_destroy_packet(packet);
	if(env.wand_ev_hdl)
		wand_destroy_event_handler(env.wand_ev_hdl);
	free(args.help);
	free(args.version);
	free(args.modules);
	free(args.interface);
	free(args.module_path);
	free(args.num_packets);
	free(args.output_file);
	free(args.end);
	if(config)
		config_destroy(config);
	path_curr = path_head;
	//process_path *p2free;
	while(path_curr != NULL)
	{
		if(path_curr->m->lib_handle)
		{
			(*(path_curr->m->cleanup))();
			dlclose(path_curr->m->lib_handle);
		}
		//free(path_curr->m);
		//p2free = path_curr;
		path_curr = path_curr->next;
		//free(p2free);
	}
	free(process_path_memory);
}
