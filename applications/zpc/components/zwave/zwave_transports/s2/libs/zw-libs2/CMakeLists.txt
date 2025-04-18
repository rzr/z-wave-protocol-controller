# Libs2 is designed to be used included as a subproject, but this part allows to
# build libs2 standalone (here for x86)
if("${PROJECT_NAME}" STREQUAL "")
  cmake_minimum_required(VERSION 3.5)
  project(libs2 C ASM)

  set(CMAKE_BUILD_TYPE debug)
  add_definitions(-Dx86)

  if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
    # For gov/cobertura: do not use .c.o on the object files, only .o
    set(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  endif()
  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS} -Wno-self-assign -Wno-error=unused-command-line-argument"
    )
  endif()

  find_path(
    ZWAVE_CLASSCMD_DIR ZW_classcmd.h
    HINTS ENV ZWLIBROOT ${PROJECT_SOURCE_DIR}/..
          ${PROJECT_SOURCE_DIR}/../../ThirdParty/generated/
    PATH_SUFFIXES include)
  find_path(
    ZWAVE_INCLUDE_DIR ZW.h
    HINTS ENV ZWLIBROOT ${PROJECT_SOURCE_DIR}/..
          ${PROJECT_SOURCE_DIR}/../../ZWave/API/
    PATH_SUFFIXES include)
  SET(MEMORYCHECK_COMMAND_OPTIONS "${MEMORYCHECK_COMMAND_OPTIONS} --verbose --errors-for-leak-kinds=all --show-leak-kinds=all --leak-check=full --error-exitcode=1 --track-origins=yes")
  include(CTest)
  add_compile_definitions(NDEBUG)
  enable_testing()
endif("${PROJECT_NAME}" STREQUAL "")

if(WIN32 AND NOT CMAKE_BUILD_TYPE MATCHES Test)
  add_definitions(-DDllExport=__declspec\(dllexport\))
else()
  add_definitions(-DDllExport=extern)
endif()

set(CROSS_SYSTEM_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/include" PARENT_SCOPE)
# Setting -DOPTIONAL_SYSTEM_INCLUDE=<optional_include_path> allows to specify
# addional include path(s) when building libs2.
include_directories(include ${ZWAVE_INCLUDE_DIR} ${CROSS_SYSTEM_INCLUDE}
                    ${OPTIONAL_SYSTEM_INCLUDE} ${ZWAVE_CLASSCMD_DIR})

if("${CMAKE_PROJECT_NAME}" STREQUAL "SDK")
  set(SKIP_TESTING true)
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g3")
if(NOT DEFINED SKIP_TESTING OR CMAKE_BUILD_TYPE STREQUAL Test)
  enable_testing()
  add_subdirectory(test)
  message(STATUS "Adding unit test for libs2")
else()
  # Use the SKIP_TESTING variable to prevent warning when running cmake
  set(ignoreMe "${SKIP_TESTING}")
  set(DISABLE_MOCK true)
endif()

add_subdirectory(crypto)
add_subdirectory(protocol)
add_subdirectory(inclusion)
if(NOT DEFINED DISABLE_MOCK)
  add_subdirectory(include/mock)
  add_subdirectory(inclusion/mock)
  add_subdirectory(crypto/mock)
endif()

set(s2_slave_source protocol/S2.c inclusion/s2_inclusion.c)

# Library for slaves
if(NOT "${CMAKE_PROJECT_NAME}" STREQUAL "SDK") # not built againt zw-protocol
  add_library(s2_slave ${s2_slave_source})
  target_link_libraries(s2_slave s2crypto aes)
else(NOT "${CMAKE_PROJECT_NAME}" STREQUAL "SDK") # built against zw-protocol
  add_library(s2_slave OBJECT ${s2_slave_source})
  target_include_directories(s2_slave PRIVATE crypto/curve25519) # just for api.h which contains ifndef ZWAVE_PSA_SECURE_VAULT specific stuff
endif(NOT "${CMAKE_PROJECT_NAME}" STREQUAL "SDK")

target_include_directories(s2_slave
                           PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
