/*
* naddycap - Extensible Network Capture
* Copyright (C) 2013 Simon Wadsworth
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
