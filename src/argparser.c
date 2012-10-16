#include "naddycap.h"

void initialize_clargs(arguments *args)
{
	args->help = arg_lit0("h","help",	"display this help message");
	args->version = arg_lit0(NULL,"version",	"version information");
	args->modules = arg_strn(NULL,"module",	"<lib file>", 0, 15, "packet processing modules");
	args->interface = arg_str0("i","interface", "<interface>", "interface to capture on. any requires pcap output module");
	args->module_path = arg_str0(NULL,"module-path", "<path>","path to the modules directory");
	args->num_packets = arg_int0("n",NULL,"<NUM>","number of packets to capture. 0 is unlimited");
	args->end = arg_end(20); 

	args->interface->sval[0] = "any";
	args->module_path->sval[0] = "./";
	args->num_packets->ival[0] = 0;

}
