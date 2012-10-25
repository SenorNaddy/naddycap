# - Try to find Argtable
# Once done this will define
#
#  Libconfig_FOUND - system has Argtable
#  Libconfig_INCLUDES - the Argtable include directory
#  Libconfig_LIBRARY - Link these to use Argtable

FIND_LIBRARY (Libconfig_LIBRARY NAMES config
    PATHS
    ENV LD_LIBRARY_PATH
    ENV LIBRARY_PATH
    /usr/lib64
    /usr/lib
    /usr/local/lib64
    /usr/local/lib
    /opt/local/lib
	 ${LIBconfig_ROOT}/lib
    )

FIND_PATH (Libconfig_INCLUDES libconfig.h
    ENV CPATH
	${LIBconfig_ROOT}/include
    /usr/include
    /usr/local/include
    /opt/local/include
    )

IF(Libconfig_INCLUDES AND Libconfig_LIBRARY)
    SET(Libconfig_FOUND TRUE)
ENDIF(Libconfig_INCLUDES AND Libconfig_LIBRARY)

IF(Libconfig_FOUND)
  IF(NOT Libconfig_FIND_QUIETLY)
    MESSAGE(STATUS "Found Libconfig: ${Libconfig_LIBRARY}")
  ENDIF(NOT Libconfig_FIND_QUIETLY)
ELSE(Libconfig_FOUND)
  IF(Libconfig_FIND_REQUIRED)
    MESSAGE(FATAL_ERROR "Could not find Libconfig")
  ENDIF(Libconfig_FIND_REQUIRED)
ENDIF(Libconfig_FOUND)
