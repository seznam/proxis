if(NOT CMAKE_BUILD_TYPE)
	message(STATUS "No build type specified, using default CMAKE_BUILD_TYPE=Release.")
	message(STATUS "Build type options are: None Debug Release RelWithDebInfo MinSizeRel.")
	set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Debug)
	set(CMAKE_C_FLAGS "-O0")
endif()

find_package(OpenSSL REQUIRED 1.1.0)

find_library(libconfig_location NAMES libconfig.so)
message(STATUS ${libconfig_location})

add_library(libconfig SHARED IMPORTED)
set_target_properties(libconfig PROPERTIES IMPORTED_LOCATION ${libconfig_location})

find_library(libevent_location NAMES libevent.so libevent_openssl.so)
message(STATUS ${libevent_location})

add_library(libevent SHARED IMPORTED)
set_target_properties(libevent PROPERTIES IMPORTED_LOCATION ${libevent_location})

set(SOURCE_FILES acl.c log.c main.c proxy.c resp.c session.c worker.c)

add_definitions(-DPROJECT_NAME="${PROJECT_NAME}")
add_definitions(-DPROJECT_VERSION="${PROJECT_VERSION}")

if(CMAKE_SYSTEM_NAME STREQUAL Linux)
	add_definitions(-DLINUX)
endif()

add_executable(proxis ${SOURCE_FILES})

target_link_libraries (proxis event event_openssl pthread ssl crypto config)
