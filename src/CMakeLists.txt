CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

PROJECT( naddycap )

INCLUDE_DIRECTORIES( $(naddycap_SOURCE_DIR)/includes )

SET ( naddycap_SRCS main.cpp event.cpp pipeline.cpp argparser.cpp includes/naddycap.h )
ADD_EXECUTABLE ( naddycap ${naddycap_SRCS} )
TARGET_LINK_LIBRARIES (naddycap dl trace wandevent argtable2)

ADD_LIBRARY(output_erf SHARED output_erf.c)
ADD_LIBRARY(output_pcap SHARED output_pcap.c)
ADD_LIBRARY(process_dropall SHARED process_dropall.c)
ADD_LIBRARY(process_bpf SHARED process_bpf.c)

