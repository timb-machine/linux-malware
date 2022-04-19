if(DEFINED ENV{CONTAINER_TOP_DIR})
    set(ROOT_DIR $ENV{CONTAINER_TOP_DIR})
else()
    get_filename_component(ROOT_DIR "${PROJECT_SOURCE_DIR}/../.." ABSOLUTE)
endif()

if(DEFINED ENV{PLATFORM_BUILD})
    set(PLATFORM_BUILD_DIR $ENV{PLATFORM_BUILD})
else()
    set(PLATFORM_BUILD_DIR "${CMAKE_BINARY_DIR}")
endif()

if(DEFINED ENV{ORIGINAL_SOURCE})
    set(ROOT_SOURCE_DIR $ENV{ORIGINAL_SOURCE})
else()
    get_filename_component(ROOT_SOURCE_DIR "${PROJECT_SOURCE_DIR}/.." ABSOLUTE)
endif()

message("Building using variables provided by CB build utility")
find_package(CbUtil REQUIRED)
find_package(CbKernelUtil REQUIRED)
cb_conan_setup(TARGETS
        CONAN_INCLUDE ${PLATFORM_BUILD_DIR}/conanbuildinfo.cmake)

# Loop over the conan dependencies and add all the kernels that we find.
#  Note: I am trusting that conan gives them to me sorted.  I insert each new kernel at the beginning of the list.
#        This causes the "newest" kernel to be built first.
foreach(ITEM ${CONAN_DEPENDENCIES})
    if(ITEM MATCHES "Kernel_*")
        list(INSERT KERNEL_LIST 0 "${ITEM}")
    endif()
endforeach()

set(INCLUDE_DIR $ENV{ORIGINAL_SOURCE}/include)

function(do_build_kernel_module)
    foreach(KERNEL_NAME ${KERNEL_LIST})
        string(TOUPPER "${KERNEL_NAME}" UPPER_KERNEL_NAME)
        set(KERNEL_VERSION "${CONAN_USER_${UPPER_KERNEL_NAME}_version}")
        set(KERNEL_BUILD_DIR "${CONAN_RES_DIRS_${UPPER_KERNEL_NAME}}")
        cb_add_kernel_module(
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
                DEPENDS             ${HEADER_FILES}
                USE_NATIVE_COMPILER)
    endforeach()
endfunction()

function(do_post_build_kernel_module)
    file (GLOB SRC_FILES
            RELATIVE $ENV{ORIGINAL_SOURCE}
            *.h
            *.c
            )

    cb_check_kernel_files(
            SOURCE_DIR          $ENV{ORIGINAL_SOURCE}
            IGNORE_TAGS         CODE_INDENT
            CONSTANT_COMPARISON
            LEADING_SPACE
            LINUX_VERSION_CODE
            NEW_TYPEDEFS
            OPEN_BRACE
            SUSPECT_CODE_INDENT
            TRAILING_STATEMENTS
            AVOID_EXTERNS
            # checkpatch.pl does not like new typedefs.  We possibly should list all the typedefs we add here, but for now
            #  I am only listing the ones that are giving me issues.
            #  If you get the error `need consistent spacing around "*"` then add the type here.
            NEW_TYPES           CB_FILE_TYPE
            ProcessContext
            CB_EVENT_DNS_RESPONSE
            SOURCE_FILES        ${SRC_FILES}
    )
endfunction()