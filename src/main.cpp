#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include "libtrace.h"
#include "plugin.h"
#include "structs.h"
#include "args.h"

char trace_file[25];
module m;
libtrace_t *trace = NULL;
libtrace_packet_t *packet;
arguments args;

int main(int argc, char *argv[])
{
	char *error;
	args.help = arg_lit0("h","help",	"display this help message");
	args.version = arg_lit0(NULL,"version",	"version information");
	args.modules = arg_strn(NULL,"module",	"<lib file>", 0, 15, "packet processing modules");
	args.interface = arg_str0("i","interface", "<interface>", "interface to capture on. any requires pcap output module");
	args.module_path = arg_str0(NULL,"module-path", "<path>","path to the modules directory");
	args.num_packets = arg_int0("n",NULL,"<NUM>","number of packets to capture. 0 is unlimited");
	args.end = arg_end(20);
	void *argtable[] = {args.help, args.version, args.modules, args.interface, args.module_path, args.num_packets, args.end};
	int nerrors;
	if(arg_nullcheck(argtable) != 0)
	{
		printf("%s: insufficient memory\n", argv[0]);
		return -1;
	}

	args.interface->sval[0] = "any";
	args.module_path->sval[0] = "./";
	args.num_packets->ival[0] = 0;
	nerrors = arg_parse(argc, argv, argtable);

	if ( (args.help)->count > 0)
	{
		arg_print_syntaxv(stdout, argtable, "\n");
		arg_print_glossary(stdout, argtable, "	%-25s %s\n");
		return -1;
	}

	sprintf(trace_file, "pcapint:%s",args.interface->sval[0]);

	int i;
	for(i = 0; i < args.modules->count; i++)
	{
		printf("Loading %s\n", args.modules->sval[i]);
		char module_path_name[256];
		sprintf(module_path_name, "%s%s", args.module_path->sval[0], args.modules->sval[i]);
		m.lib_handle = dlopen(module_path_name, RTLD_LAZY);
		if(!m.lib_handle)
		{
			fprintf(stderr, "%s\n", dlerror());
			return -1;
		}

		m.init = (InitFunc)dlsym(m.lib_handle, "init");

		if ((error = dlerror()) != NULL)
		{
			fprintf(stderr, "%s\n", error);
			return -1;
		}

		m.parse_packet = (ParseFunc)dlsym(m.lib_handle, "parse_packet");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	return -1;
        	}
		m.cleanup = (CleanupFunc)dlsym(m.lib_handle,"cleanup");
        	if ((error = dlerror()) != NULL)
        	{
                	fprintf(stderr, "%s\n", error);
                	return -1;
        	}
	}
	(*(m.init))(argv[argc-1]);

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
		(*(m.parse_packet))(packet);
		read++;
	}
	(*(m.cleanup))();
	trace_destroy(trace);
	trace_destroy_packet(packet);
}

