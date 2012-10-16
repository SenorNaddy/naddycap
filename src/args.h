#ifndef ARGS_H
#define ARGS_H

#ifndef ARGT_H
#define ARGT_H

#include <argtable2.h>
#endif

typedef struct arguments {
	struct arg_lit *help;
	struct arg_lit *version;
	struct arg_str *modules;
	struct arg_str *interface;
	struct arg_int *num_packets;
	struct arg_str *module_path;
	struct arg_end *end;
} arguments;

extern arguments args;
void initialize_clargs(arguments *args);

#endif
