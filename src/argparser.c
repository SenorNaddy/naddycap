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

#include "includes/naddycap.h"

void initialize_clargs(arguments *args)
{
	args->help = arg_lit0("h","help",	"display this help message");
	args->version = arg_lit0(NULL,"version",	"version information");
	args->modules = arg_strn(NULL,"module",	"<lib file>", 0, 15, "packet processing modules");
	args->interface = arg_str0("i","interface", "<interface>", "interface to capture on. any requires pcap output module");
	args->module_path = arg_str0(NULL,"module-path", "<path>","path to the modules directory");
	args->num_packets = arg_int0("n",NULL,"<NUM>","number of packets to capture. omit argument for unlimited");
	args->config_file = arg_file1(NULL,NULL,NULL, "config file ");
	args->end = arg_end(20); 

	args->interface->sval[0] = "any";
	args->module_path->sval[0] = "./";
	args->num_packets->ival[0] = 0;

}
