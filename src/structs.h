typedef void (*InitFunc)(char *);
typedef void (*ParseFunc)(libtrace_packet_t *);
typedef void (*CleanupFunc)();

typedef struct module {
	void *lib_handle;
	InitFunc init;
	ParseFunc parse_packet;
	CleanupFunc cleanup;
} module;

typedef struct process_path {
	module *m;
	struct process_path *next;
} process_path;