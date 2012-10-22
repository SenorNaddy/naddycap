#ifndef ARGS_H
#define ARGS_H

typedef struct arguments {
	struct arg_lit *help;
	struct arg_lit *version;
	struct arg_str *modules;
	struct arg_str *interface;
	struct arg_int *num_packets;
	struct arg_str *module_path;
	struct arg_file *config_file;
	struct arg_end *end;
} arguments;

extern arguments args;
void initialize_clargs(arguments *args);

#endif
