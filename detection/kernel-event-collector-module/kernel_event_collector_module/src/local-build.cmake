

# Configure Paths
get_filename_component(ROOT_DIR "${PROJECT_SOURCE_DIR}/.." ABSOLUTE)
set(PLATFORM_BUILD_DIR "${CMAKE_BINARY_DIR}")
get_filename_component(ROOT_SOURCE_DIR "${PROJECT_SOURCE_DIR}" ABSOLUTE)
set(INCLUDE_DIR ${ROOT_DIR}/include)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${ROOT_DIR}/cmake")

# Include the CbKernelUtil helpers (after module path has been configured)
find_package(CbKernelUtil REQUIRED)

message("Building using variables defined locally in this CMake")
if(NOT KERNEL_NAME)
    message(FATAL_ERROR "You must specify the kernel version to build for with:\n"
            "    -DKERNEL_NAME=<version>.\n"
            "See the README for officially supported kernel versions.\n"
            "To build for the current distribution, use:\n"
            "    -DKERNEL_NAME=$(uname -r)\n")
endif()

function(do_build_kernel_module)
    set(KERNEL_VERSION "${KERNEL_NAME}")
    set(KERNEL_BUILD_DIR "/lib/modules/${KERNEL_NAME}/build")
    message(MODULE_NAME=${MODULE_NAME}, KERNEL_NAME=${KERNEL_NAME})
    message(KERNEL_VERSION=${KERNEL_VERSION})
    message(KERNEL_BUILD_PATH=${KERNEL_BUILD_PATH})
    message(PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR})
    message(PROJECT_BINARY_DIR=${PROJECT_BINARY_DIR})
    message(KERNEL_BUILD_DIR=${KERNEL_BUILD_DIR})
    message(SOURCE_FILES=${SOURCE_FILES})
    build_kernel_module(
            NAME                ${MODULE_NAME}
            KERNEL_NAME         ${KERNEL_NAME}
            KERNEL_VERSION      ${KERNEL_VERSION}
            OUTPUT_PATH         ${KERNEL_BUILD_PATH}
            MODULE_SOURCE_DIR   ${PROJECT_SOURCE_DIR}
            MODULE_BUILD_DIR    ${PROJECT_BINARY_DIR}
            KERNEL_BUILD_DIR    ${KERNEL_BUILD_DIR}
            FLAGS               ${CBSENSOR_FLAGS}
            AFLAGS              ${CBSENSOR_AFLAGS}
            SOURCE_FILES        ${SOURCE_FILES}
            USE_NATIVE_COMPILER
    )
endfunction()

function(do_post_build_kernel_module)
endfunction()