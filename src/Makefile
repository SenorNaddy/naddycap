all: naddycap output_erf output_pcap

naddycap: main.cpp
	g++ -rdynamic -o naddycap main.cpp -ldl -ltrace -largtable2

output_erf: output_erf.c
	gcc -Wall -fPIC -c output_erf.c
	gcc -shared -Wl,-soname,output_erf.so -o output_erf.so output_erf.o

output_pcap: output_pcap.c
	gcc -Wall -fPIC -c output_pcap.c
	gcc -shared -Wl,-soname,output_pcap.so -o output_pcap.so output_pcap.o

clean:
	rm -rf *o
	rm -rf *~
