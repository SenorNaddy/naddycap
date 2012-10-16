all: naddycap output_erf output_pcap process_dropall

naddycap: main.o argparser.o pipeline.o event.o
	g++ -rdynamic -o naddycap main.o pipeline.o argparser.o event.o -ldl -ltrace -largtable2 -lwandevent

argparser.o: argparser.c naddycap.h args.h
	g++ -c -Wall -g argparser.c

event.o: event.c naddycap.h
	g++ -c -Wall -g event.c

pipeline.o: pipeline.cpp naddycap.h
	g++ -c -Wall -g pipeline.cpp

main.o:	main.cpp naddycap.h args.h structs.h event.h
	g++ -c -Wall -g main.cpp

output_erf: output_erf.c
	gcc -Wall -fPIC -c output_erf.c
	gcc -shared -Wl,-soname,output_erf.so -o output_erf.so output_erf.o

output_pcap: output_pcap.c
	gcc -Wall -fPIC -c output_pcap.c
	gcc -shared -Wl,-soname,output_pcap.so -o output_pcap.so output_pcap.o

process_dropall: process_dropall.c
	gcc -Wall -fPIC -c process_dropall.c
	gcc -shared -Wl,-soname,process_dropall.so -o process_dropall.so process_dropall.o

clean:
	rm -rf *o
	rm -rf *~
