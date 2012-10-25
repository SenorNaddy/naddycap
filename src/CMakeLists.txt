CMAKE_MINIMUM_REQUIRED( VERSION 2.6 )

PROJECT( naddycap )

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeScripts)

INCLUDE_DIRECTORIES( $(naddycap_SOURCE_DIR)/includes )

FIND_PACKAGE(Libtrace REQUIRED)
FIND_PACKAGE(Argtable REQUIRED)
FIND_PACKAGE(Libconfig REQUIRED)
FIND_PACKAGE(Libwandevent REQUIRED)

SET ( naddycap_SRCS main.c event.c pipeline.c argparser.c config.c includes/naddycap.h )
SET ( naddycap_LIBS dl trace wandevent argtable2 config )
ADD_EXECUTABLE ( naddycap ${naddycap_SRCS} )
TARGET_LINK_LIBRARIES (naddycap ${naddycap_LIBS} )

ADD_LIBRARY(output_erf SHARED output_erf.c)
ADD_LIBRARY(output_pcap SHARED output_pcap.c)
ADD_LIBRARY(process_dropall SHARED process_dropall.c)
ADD_LIBRARY(process_bpf SHARED process_bpf.c)

ADD_SUBDIRECTORY(process_anonymize)
