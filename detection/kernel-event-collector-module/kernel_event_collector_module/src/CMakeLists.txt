# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.12)
project (KernelEventCollectorModule)

# LOCAL_BUILD defines if the build will be performed with configuration options
# provided directly in this CMake file, or if the CB build utility will \
# substitute values in.
if(NOT DEFINED LOCAL_BUILD)
    set(LOCAL_BUILD no)
    include(cb-build.cmake)
else()
    include(local-build.cmake)
endif()

include(constants.cmake)

# Check for values from the ENV
if(DEFINED ENV{OPTION_MODULE_NAME})
    set(MODULE_NAME $ENV{OPTION_MODULE_NAME})
else()
    set(MODULE_NAME event_collector)
endif()
string(TOUPPER "${MODULE_NAME}" UPPER_MODULE_NAME)

if(DEFINED ENV{PROJECT_VERSION})
    set(VERSION_STRING $ENV{PROJECT_VERSION})
else()
    set(VERSION_STRING "0.0.0")
endif()


#############################################################################################
# Builds the module version suffix, from the VERSION_STRING.
#  This version suffix becomes a part of the ".ko" filename, also is compiled into code and
#  becomes a part of the device name created by the module.
#  Doing this should allow for more than one kernel-modules to be installed on the system
#  (since each will have its own unique device-node.)
#  example:
#    VERSION_STRING would be 1.6.12349
#    MODULE_VERSION_SUFFIX would be 1_6_12349
#
# Converting dots to underscore just because insmod does not like dots.
#############################################################################################
string(REPLACE "." "_" MODULE_VERSION_SUFFIX ${VERSION_STRING})
set(MODULE_NAME ${MODULE_NAME}_${MODULE_VERSION_SUFFIX})

# These items are calculated based on the configured MODULE_NAME
set(PROC_DIR ${${UPPER_MODULE_NAME}_PROC_DIR})
set(DEBUG_PREFIX ${${UPPER_MODULE_NAME}_DEBUG_PREFIX})
set(MEM_CACHE_PREFIX ${${UPPER_MODULE_NAME}_MEM_CACHE_PREFIX})

string(TIMESTAMP BUILD_DATE "%Y-%m-%d - %H:%M:%S")
set(KERNEL_BUILD_PATH ${PLATFORM_BUILD_DIR}/kernel-builds)

set(CBSENSOR_AFLAGS "")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${PROJECT_SOURCE_DIR}")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${PROJECT_BINARY_DIR}")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${INCLUDE_DIR}")

set(CBSENSOR_FLAGS "")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wall")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wformat")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Werror")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${PROJECT_SOURCE_DIR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${PROJECT_SOURCE_DIR}/tests")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${PROJECT_BINARY_DIR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${INCLUDE_DIR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -include \"version.h\"")

# Prepare source files (and remove configured files from a previous build)
set(CONFIGURED_VERSION_FILE ${PROJECT_BINARY_DIR}/version.h)
file(REMOVE ${CONFIGURED_VERSION_FILE})
configure_file(${INCLUDE_DIR}/version.h.in ${CONFIGURED_VERSION_FILE})

set(SOURCE_FILES drvmain.c
        stall-event.c
        hook-tracking.c
        findsyms.c
        page-helpers.c
        path-buffers.c
        mem-cache.c
        rbtree-helper.c
        file-helper.c
        file-hooks.c
        logger.c
        lsm.c
        modules.c
        cb-spinlock.c
        net-helper.c
        net-hooks.c
        net-tracking.c
        process-hooks.c
        task-helper.c
        fops-comm.c
        process-tracking.c
        process-tracking-sorted.c
        process-tracking-discovery.c
        process-tracking-show.c
        process-tracking-helpers.c
        cb-isolation.c
        cb-banning.c
        netfilter.c
        hash-table-generic.c
        file-process-tracking.c
        syscall_init.c
        cb-stats.c
        module-hooks.c
        event-factory.c
        cb-module-state-export.c
        dns-parser.c
        tests/run-tests.c
        tests/hashtabl-tests.c
        tests/process-tracking-tests.c
        tests/module-state-tests.c
        tests/stall-tests.c)

file(GLOB HEADER_FILES *.h ../include/*.h tests/*.h)

do_build_kernel_module()
do_post_build_kernel_module()
