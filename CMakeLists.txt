cmake_minimum_required(VERSION 3.1.0)
project(libcareswrap)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckLibraryExists)

if(${UNIX})
  set(LIBCARESWRAP_FLAGS "-Wall -Wextra -Werror -pedantic")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBCARESWRAP_FLAGS} -Wmissing-prototypes")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LIBCARESWRAP_FLAGS}")
  if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # for GCC, -Wmissing-prototypes only works for C/ObjC.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-prototypes")
  endif()
endif()

set(CARESWRAP_ARES_INCLUDE_DIR "" CACHE PATH "Directory containing ares.h")
if(${CARESWRAP_ARES_INCLUDE_DIR})
  check_include_file("${CARESWRAP_ARES_INCLUDE_DIR}/ares.h" HAVE_ARES_H)
else()
  check_include_file(ares.h HAVE_ARES_H)
endif()
if(NOT (${HAVE_ARES_H}))
  message(FATAL_ERROR "Can't find ares.h; Try using -DCARESWRAP_ARES_INCLUDE_DIR=PATH")
endif()
set(CARESWRAP_ARES_LIBRARY "" CACHE FILEPATH "C-ares library filepath")
if(${CARESWRAP_ARES_LIBRARY})
  set(CMAKE_REQUIRED_LIBRARIES ${CARES_WRAP_ARES_LIBRARY})
else()
  set(CMAKE_REQUIRED_LIBRARIES cares)
endif()
check_function_exists(ares_library_init HAVE_ARES_LIBRARY_INIT)
if(NOT (${HAVE_ARES_LIBRARY_INIT}))
  message(FATAL_ERROR "Can't find -lcares; Try using -DCARESWRAP_ARES_LIBRARY=FILEPATH")
endif()

add_library(
  careswrap
  STATIC
  libcareswrap.cpp
  libcareswrap.hpp
)
target_include_directories(
  careswrap
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)
install(
  FILES
  libcareswrap.hpp
  DESTINATION
  include/measurement_kit/libcareswrap
)
install(
  TARGETS
  careswrap
  DESTINATION
  lib
)
target_link_libraries(careswrap ${CMAKE_REQUIRED_LIBRARIES})
if(WIN32)
  target_link_libraries(careswrap ws2_32)
endif()

set(LIBCARESWRAP_BUILD_EXAMPLES ON CACHE BOOL "Whether to build examples")
if(LIBCARESWRAP_BUILD_EXAMPLES)
  add_executable(
    client
    client.cpp
    argh.h
  )
  target_link_libraries(client careswrap)
endif()

enable_testing()
