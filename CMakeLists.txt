cmake_minimum_required(VERSION 3.21)

project(sniffer LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "Sniffer requires Windows and the Win32 process APIs.")
endif()

include(CTest)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

add_library(libsniffer STATIC
    src/libsniffer/Params.h
    src/libsniffer/Utils.h
    src/libsniffer/framework.h
    src/libsniffer/pch.h
    src/libsniffer/profile_timer.h
    src/libsniffer/sniffer.cpp
    src/libsniffer/sniffer.h
    src/libsniffer/sniffer_cmds.h
    src/libsniffer/w32_api.cpp
    src/libsniffer/w32_api.h
)

target_compile_features(libsniffer PUBLIC cxx_std_14)
target_compile_definitions(libsniffer PUBLIC UNICODE _UNICODE)
target_include_directories(libsniffer PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(libsniffer PRIVATE Advapi32)

add_executable(sniffer src/sniffer/main.cpp)
target_link_libraries(sniffer PRIVATE libsniffer)

add_executable(test-target src/test-target/main.cpp)
target_compile_features(test-target PRIVATE cxx_std_14)
target_compile_definitions(test-target PRIVATE UNICODE _UNICODE)

if(BUILD_TESTING)
    add_executable(tests tests/main.cpp)
    target_link_libraries(tests PRIVATE libsniffer)
    add_test(NAME sniffer.tests COMMAND tests)
endif()

if(MSVC)
    foreach(target IN ITEMS libsniffer sniffer test-target)
        target_compile_options(${target} PRIVATE /W3 /sdl /permissive-)
    endforeach()

    if(BUILD_TESTING)
        target_compile_options(tests PRIVATE /W3 /sdl /permissive-)
    endif()
endif()
