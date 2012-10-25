INCLUDE_DIRECTORIES( $(naddycap_SOURCE_DIR)/process_anonymize/includes )

ADD_LIBRARY(process_anonymize SHARED process_anonymize.c ip6.c ip4.c)
