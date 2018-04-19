cmake_minimum_required(VERSION 3.1.0)
project(libcareswrap LANGUAGES CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIncludeFiles)
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
target_link_libraries(careswrap cares)
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
