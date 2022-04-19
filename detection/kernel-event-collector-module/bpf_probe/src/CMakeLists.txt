# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0
cmake_minimum_required(VERSION 2.8.7)

project(bpf_probe)

if(NOT DEFINED LOCAL_BUILD)
    set(LOCAL_BUILD no)
endif()

if (NOT ${LOCAL_BUILD})
    message("Project will be built using CB build utility")
    FIND_PACKAGE(CbUtil REQUIRED)
    cb_configure_flags()
    cb_conan_setup(TARGETS)
else()
    message("Project will be built using local system libraries")
    add_definitions(-DLOCAL_BUILD)
endif()

set(CMAKE_CXX_STANDARD 11)

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")

include_directories(${PROJECT_SOURCE_DIR}/../include)

set(EPBF_PROG_CPP ${CMAKE_CURRENT_BINARY_DIR}/cb_ebpfprog.cpp)
set(EBPF_PPRG_SRC ${PROJECT_SOURCE_DIR}/bcc_sensor.c)
set(GENERATE_SH   ${PROJECT_SOURCE_DIR}/generate.sh)

add_custom_command(
        OUTPUT ${EPBF_PROG_CPP}
        COMMAND chmod a+x ${GENERATE_SH}
        COMMAND ${GENERATE_SH} ${EBPF_PPRG_SRC} ${EPBF_PROG_CPP}
        DEPENDS ${GENERATE_SH} ${EBPF_PPRG_SRC}
        COMMENT "Generating BPF Program ${EPBF_PROG_CPP}"
)

add_custom_target(bcc_prog ALL DEPENDS ${EPBF_PROG_CPP})

add_library(bpf-probe STATIC
        BpfApi.cpp
        BpfProgram.cpp
        ${EPBF_PROG_CPP})
add_dependencies(bpf-probe bcc_prog)
set_property(TARGET bpf-probe PROPERTY POSITION_INDEPENDENT_CODE 1)

if (NOT ${LOCAL_BUILD})
    target_link_libraries(bpf-probe
            CONAN_PKG::bcc

            -Wl,--whole-archive
            CONAN_PKG::llvm
            CONAN_LIB::elfutils_elf
            -Wl,--no-whole-archive

            z rt dl pthread m
            )
else()
    target_link_libraries(bpf-probe
        bcc
        z
        rt
        dl
        pthread
        m
    )
endif()

add_executable(check_probe check_probe.cpp)
target_link_libraries(check_probe
        bpf-probe
        z rt dl pthread m)

add_subdirectory(tests)

include(constants.cmake)

install(TARGETS check_probe PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE DESTINATION .)


set(CPACK_OUTPUT_FILE_PREFIX $ENV{BUILD_DIR}/install-packages)
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME ${CHECK_PROBE_KIT_FILE})
set(CPACK_PACKAGE_DIRECTORY ${PROJECT_BINARY_DIR})

include(CPack)
