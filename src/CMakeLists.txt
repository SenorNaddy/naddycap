CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

PROJECT( naddycap )

INCLUDE_DIRECTORIES( $(naddycap_SOURCE_DIR)/includes )

SET ( naddycap_SRCS main.c event.c pipeline.c argparser.c config.c includes/naddycap.h )
SET ( naddycap_LIBS dl trace wandevent argtable2 config )
ADD_EXECUTABLE ( naddycap ${naddycap_SRCS} )
TARGET_LINK_LIBRARIES (naddycap ${naddycap_LIBS} )

ADD_LIBRARY(output_erf SHARED output_erf.c)
ADD_LIBRARY(output_pcap SHARED output_pcap.c)
ADD_LIBRARY(process_dropall SHARED process_dropall.c)
ADD_LIBRARY(process_bpf SHARED process_bpf.c)
ADD_LIBRARY(process_anonymize SHARED process_anonymize.c)
