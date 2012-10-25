# - Try to find Argtable
# Once done this will define
#
#  Libwandevent_FOUND - system has Argtable
#  Libwandevent_INCLUDES - the Argtable include directory
#  Libwandevent_LIBRARY - Link these to use Argtable

FIND_LIBRARY (Libwandevent_LIBRARY NAMES wandevent
    PATHS
    ENV LD_LIBRARY_PATH
    ENV LIBRARY_PATH
    /usr/lib64
    /usr/lib
    /usr/local/lib64
    /usr/local/lib
    /opt/local/lib
	 ${LIBwandevent_ROOT}/lib
    )

FIND_PATH (Libwandevent_INCLUDES libwandevent.h
    ENV CPATH
	${LIBwandevent_ROOT}/include
    /usr/include
    /usr/local/include
    /opt/local/include
    )

IF(Libwandevent_INCLUDES AND Libwandevent_LIBRARY)
    SET(Libwandevent_FOUND TRUE)
ENDIF(Libwandevent_INCLUDES AND Libwandevent_LIBRARY)

IF(Libwandevent_FOUND)
  IF(NOT Libwandevent_FIND_QUIETLY)
    MESSAGE(STATUS "Found Libwandevent: ${Libwandevent_LIBRARY}")
  ENDIF(NOT Libwandevent_FIND_QUIETLY)
ELSE(Libwandevent_FOUND)
  IF(Libwandevent_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find Libwandevent")
  ENDIF(Libwandevent_FIND_REQUIRED)
ENDIF(Libwandevent_FOUND)
