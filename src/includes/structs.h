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

typedef void (*InitFunc)(config_setting_t *);
typedef enum packetret (*ParseFunc)(libtrace_packet_t *);
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
