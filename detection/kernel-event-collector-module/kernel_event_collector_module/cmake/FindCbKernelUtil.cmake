# Copyright 2021 Carbon Black Inc.  All rights reserved.

function(build_kernel_module)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "You could only build linux kernel module on a linux system. Current system: ${CMAKE_SYSTEM_NAME}")
    endif()

    set(options           USE_NATIVE_COMPILER)
    set(oneValueArgs      NAME KERNEL_NAME KERNEL_VERSION MODULE_SOURCE_DIR MODULE_BUILD_DIR KERNEL_BUILD_DIR OUTPUT_PATH EXTRA_SYMBOLS)
    set(multiValueArgs    SOURCE_FILES FLAGS AFLAGS)
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_NAME)
        message(FATAL_ERROR "You must give a name to the module")
    else()
        string(TOLOWER ${ARG_NAME} MODULE_NAME)
    endif()

    if(NOT ARG_MODULE_SOURCE_DIR)
        set(MODULE_SOURCE_DIR ${CMAKE_PROJECT_SOURCE_DIR})
    else()
        set(MODULE_SOURCE_DIR ${ARG_MODULE_SOURCE_DIR})
    endif()

    if(NOT ARG_MODULE_BUILD_DIR)
        set(MODULE_BUILD_DIR ${CMAKE_PROJECT_BINARY_DIR})
    else()
        set(MODULE_BUILD_DIR ${ARG_MODULE_BUILD_DIR})
    endif()

    if(NOT ARG_KERNEL_NAME)
        message(FATAL_ERROR "You must give a kernel version")
    else()
        set(CURRENT_KERNEL_NAME ${ARG_KERNEL_NAME})
    endif()

    if(ARG_OUTPUT_PATH)
        set(OUTPUT_PATH ${ARG_OUTPUT_PATH})
    endif()

    set(KBUILD_DIR ${MODULE_BUILD_DIR})

    if(ARG_KERNEL_VERSION)
        set(OUTPUT_SUFFIX .${ARG_KERNEL_VERSION})
        set(TARGET_SUFFIX -${ARG_KERNEL_VERSION})
        set(KBUILD_DIR ${KBUILD_DIR}/${ARG_KERNEL_VERSION})
    endif()

    set(KBUILD_FILE ${KBUILD_DIR}/Kbuild)

    if(NOT "$ENV{VERBOSE}" STREQUAL "")
        set(_VERBOSE "V=1")
    endif()

    if(ARG_SOURCE_FILES)
        # First remove all links so that we make sure we don't leave any deleted files
        list(APPEND SRC_LINK_COMMANDS COMMAND find ${KBUILD_DIR} -type l | xargs rm -f)

        foreach(f ${ARG_SOURCE_FILES})
            string(REGEX MATCH "^[^ ]+\\.[cS]$" MATCHES ${f})
            if(MATCHES)
                list(APPEND MODULE_SOURCE_FILES ${f})
                if("${MODULE_NAME}.c" STREQUAL "${f}")
                    message(FATAL_ERROR "${f}: when there are multiple source modules a source file cannot have the same name as the module")
                endif()
                string(REGEX REPLACE "\\.[cS]" ".o" fo ${f})
                set(MODULE_OBJECT_FILES "${MODULE_OBJECT_FILES} ${fo}")
                list(APPEND OUTPUT_OBJS ${fo})
                string(REGEX MATCH "^.+/" subdir ${f})
                list(APPEND SUBDIRS ${subdir})

                # We need to create a hardlink to all source files so that the kernel build will work
                list(APPEND SRC_LINK_COMMANDS COMMAND ln -f ${MODULE_SOURCE_DIR}/${f} ${KBUILD_DIR}/${f})
            endif()
        endforeach()
    endif()
    list(APPEND OUTPUT_OBJS ${MODULE_NAME}.mod.c
            ${MODULE_NAME}.mod.o
            ${MODULE_NAME}.o
            modules.order
            Module.symvers)

    list(LENGTH SUBDIRS SUBDIRS_LEN)
    if (${SUBDIRS_LEN} GREATER 0)
        list(REMOVE_DUPLICATES SUBDIRS)
        foreach(subdir ${SUBDIRS})
            list(APPEND MKSUBDIRS_COMMANDS COMMAND mkdir -p ${subdir})
        endforeach()
    endif()

    if(ARG_FLAGS)
        foreach(f ${ARG_FLAGS})
            set(MODULE_FLAGS "${MODULE_FLAGS} ${f}")
        endforeach()
    endif()

    if(ARG_AFLAGS)
        foreach(f ${ARG_AFLAGS})
            set(ASM_FLAGS "${ASM_FLAGS} ${f}")
        endforeach()
    endif()

    if(ARG_KERNEL_BUILD_DIR)
        set(KERNEL_BUILD_DIR ${ARG_KERNEL_BUILD_DIR})
    else()
        set(KERNEL_BUILD_DIR "/lib/modules/${CURRENT_KERNEL_NAME}/build")
    endif()

    file(WRITE ${KBUILD_FILE} "obj-m := ${MODULE_NAME}.o\n")

    set(MODULE_FLAGS "${MODULE_FLAGS} -I${MODULE_SOURCE_DIR}")
    if(MODULE_FLAGS)
        file(APPEND ${KBUILD_FILE}
                "ccflags-y := ${MODULE_FLAGS}\n")
    endif()

    if(ASM_FLAGS)
        file(APPEND ${KBUILD_FILE}
                "asflags-y := ${ASM_FLAGS}\n")
    endif()

    if(MODULE_OBJECT_FILES)
        file(APPEND ${KBUILD_FILE}
                "${MODULE_NAME}-objs := ${MODULE_OBJECT_FILES}\n")
    endif()

    # If there are any symvers files added from another module, include it now
    if(ARG_EXTRA_SYMBOLS)
        file(APPEND ${KBUILD_FILE}
                "KBUILD_EXTRA_SYMBOLS = ${ARG_EXTRA_SYMBOLS}\n")
    endif()

    # Decide on what compiler to use.
    #  We may want to use the default system toolchain and not the one provided
    #  in the profile.  This is by design since it needs to use the same compiler
    #  as the running kernel.
    if(ARG_USE_NATIVE_COMPILER)
        set(_CC gcc)
    else()
        set(_CC ${CMAKE_C_COMPILER})
    endif()

    # Override CC in the Kbuild file
    string(REPLACE ";" " " _LNCH "${CMAKE_C_COMPILER_LAUNCHER}")
    file(APPEND ${KBUILD_FILE}
            "CC=${_LNCH} ${_CC}\n")


    set(MODULE_BIN_NAME ${MODULE_NAME}.ko)
    set(MODULE_SYMVER_NAME Module.symvers)

    set(OUTPUT_BIN_NAME    ${MODULE_BIN_NAME}${OUTPUT_SUFFIX})
    set(OUTPUT_SYMVER_NAME ${MODULE_NAME}.symvers${OUTPUT_SUFFIX})

    # Empty `MAKEFLAGS` erases Cmake's implied "--silent", in order to see the build output from KBUILD_COMMAND.
    #  This causes us to "loose" parallel builds if it is configured.
    set(KBUILD_COMMAND ${CMD_PREFIX} $(MAKE) MAKEFLAGS='' --no-print-directory -C ${KERNEL_BUILD_DIR} M=${KBUILD_DIR} ${_VERBOSE})

    if(OUTPUT_PATH)
        set(OUTPUT_BIN_FILE    "${OUTPUT_PATH}/${OUTPUT_BIN_NAME}")
        set(OUTPUT_SYMVER_FILE "${OUTPUT_PATH}/${OUTPUT_SYMVER_NAME}")
        set(MODULE_INSTALL_COMMAND cp ${MODULE_BIN_NAME} ${OUTPUT_BIN_FILE} && cp ${MODULE_SYMVER_NAME} ${OUTPUT_SYMVER_FILE})
        file(MAKE_DIRECTORY ${OUTPUT_PATH})
    else()
        set(OUTPUT_BIN_FILE    ${OUTPUT_BIN_NAME})
        set(OUTPUT_SYMVER_FILE ${OUTPUT_SYMVER_NAME})
    endif()


    add_custom_command(OUTPUT ${OUTPUT_BIN_FILE} ${OUTPUT_SYMVER_FILE}
            ${MKSUBDIRS_COMMANDS}
            ${SRC_LINK_COMMANDS}
            COMMAND ${KBUILD_COMMAND} modules
            COMMAND ${MODULE_INSTALL_COMMAND}
            VERBATIM
            WORKING_DIRECTORY ${KBUILD_DIR}
            BYPRODUCTS ${OUTPUT_BIN_NAME} ${OUTPUT_SYMVER_NAME}
            COMMENT "Generating ${OUTPUT_BIN_NAME}, ${OUTPUT_SYMVER_NAME}")

    set(TARGET_NAME modules-${MODULE_NAME}${TARGET_SUFFIX})

    # This target prints output in a way that can be colorized, and enforces the module build order
    add_custom_target(print-${TARGET_NAME}
            COMMAND echo "--- Building ${OUTPUT_BIN_NAME}"
            DEPENDS ${MODULE_TARGETS})

    # This target is added to ALL, and triggers the print target and the module to be built
    add_custom_target(${TARGET_NAME} ALL
            DEPENDS print-${TARGET_NAME} ${OUTPUT_BIN_FILE} ${OUTPUT_SYMVER_FILE})

    set(MODULE_TARGETS ${MODULE_TARGETS} ${TARGET_NAME} PARENT_SCOPE)
endfunction()
