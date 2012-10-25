# - Try to find Argtable
# Once done this will define
#
#  Libtrace_FOUND - system has Argtable
#  Libtrace_INCLUDES - the Argtable include directory
#  Libtrace_LIBRARY - Link these to use Argtable

FIND_LIBRARY (Libtrace_LIBRARY NAMES trace
    PATHS
    ENV LD_LIBRARY_PATH
    ENV LIBRARY_PATH
    /usr/lib64
    /usr/lib
    /usr/local/lib64
    /usr/local/lib
    /opt/local/lib
	 ${LIBTRACE_ROOT}/lib
    )

FIND_PATH (Libtrace_INCLUDES libtrace.h
    ENV CPATH
	${LIBTRACE_ROOT}/include
    /usr/include
    /usr/local/include
    /opt/local/include
    )

IF(Libtrace_INCLUDES AND Libtrace_LIBRARY)
    SET(Libtrace_FOUND TRUE)
ENDIF(Libtrace_INCLUDES AND Libtrace_LIBRARY)

IF(Libtrace_FOUND)
  IF(NOT Libtrace_FIND_QUIETLY)
    MESSAGE(STATUS "Found Libtrace: ${Libtrace_LIBRARY}")
  ENDIF(NOT Libtrace_FIND_QUIETLY)
ELSE(Libtrace_FOUND)
  IF(Libtrace_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find Libtrace. Download from http://research.wand.net.nz/software/libtrace/libtrace-latest.tar.bz2")
  ENDIF(Libtrace_FIND_REQUIRED)
ENDIF(Libtrace_FOUND)
