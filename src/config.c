#include "includes/naddycap.h"

config_t *config;

void parse_config(char *config_file)
{
	config_init(config);
	config_read_file(config, config_file);
}
