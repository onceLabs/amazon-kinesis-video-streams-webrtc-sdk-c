cmake_minimum_required(VERSION 3.6.3)

project(3rdLib VERSION 1.0)

# Macro utility to clone a library and source-related submodules.
macro( clone_path path )
    # Attempt to clone submodules.
    if( ${BUILD_CLONE_SUBMODULES} )
        find_package( Git REQUIRED )
        execute_process( COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive ${ARGV1} -- ${path}
                         WORKING_DIRECTORY ${ROOT_DIR}
                         RESULT_VARIABLE LIB_CLONE_RESULT )
        if( NOT ${LIB_CLONE_RESULT} STREQUAL "0" )
            message( FATAL_ERROR "Failed to clone submodules." )
        endif()
    endif()
endmacro()

# Clone the submodules only if this is a Git repo.
if( EXISTS ${ROOT_DIR}/.git )
    clone_path( ${CMAKE_CURRENT_LIST_DIR} )
    clone_path( ${CMAKE_CURRENT_LIST_DIR}/standard/corePKCS11 "--checkout" )
endif()

# 3rdparty/tinycbor
add_library(tinycbor SHARED
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborpretty.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborpretty_stdio.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborencoder.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborencoder_close_container_checked.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborerrorstrings.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborparser.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborparser_dup_string.c"
)

set_target_properties(tinycbor PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
)

file(GLOB TINYCBOR_HEADERS "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/*.h")
file(COPY ${TINYCBOR_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

if(CMAKE_C_STANDARD LESS 99)
    set_target_properties(tinycbor PROPERTIES C_STANDARD 99)
endif()

target_include_directories(tinycbor PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/tinycbor/src
)

# standard/
# Creates an install target to allow users to include CSDK as a set of shared libraries
set(FILEPATH_LOCATIONS
        ${CMAKE_CURRENT_LIST_DIR}/standard/backoffAlgorithm/backoffAlgorithmFilePaths.cmake
        ${CMAKE_CURRENT_LIST_DIR}/standard/coreMQTT/mqttFilePaths.cmake
        ${CMAKE_CURRENT_LIST_DIR}/standard/corePKCS11/pkcsFilePaths.cmake
    )

# Include filePaths of all libraries
foreach(filepath ${FILEPATH_LOCATIONS})
    include(${filepath})
endforeach()

# Each filePath defines a set of variables that are prefixed with the name of the
# library and end with the type of source or include directory e.g. MQTT_SERIALIZER_SOURCES.
set(LIBRARY_PREFIXES
        "BACKOFF_ALGORITHM"
        "MQTT"
        "PKCS"
    )

set(COREPKCS11_LOCATION "${CMAKE_CURRENT_LIST_DIR}/standard/corePKCS11")
set(CORE_PKCS11_3RDPARTY_LOCATION "${COREPKCS11_LOCATION}/source/dependency/3rdparty")

# Define any extra sources or includes outside the standard, making sure to use the same prefix.
set(MQTT_EXTRA_SOURCES
        ${MQTT_SERIALIZER_SOURCES})
set(PKCS_EXTRA_SOURCES
        "${COREPKCS11_LOCATION}/source/portable/os/posix/core_pkcs11_pal.c"
        "${COREPKCS11_LOCATION}/source/portable/os/core_pkcs11_pal_utils.c"
        "${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils/mbedtls_utils.c")
set(PKCS_EXTRA_INCLUDE_PRIVATE_DIRS
    PRIVATE
        "${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils"
        "${COREPKCS11_LOCATION}/source/portable/os")

if(NOT DEFINED INSTALL_LIBS)
    set(INSTALL_LIBS ${LIBRARY_PREFIXES})
endif()

foreach(library_prefix ${LIBRARY_PREFIXES})
    # Check if prefix is in list of libraries to be installed.
    list (FIND INSTALL_LIBS ${library_prefix} _index)
    # Create the library target.
    if(DEFINED "${library_prefix}_SOURCES" AND ${_index} GREATER -1)
        string(TOLOWER "aws_iot_${library_prefix}" library_name)
		message(STATUS "library_name = ${library_name}")
        add_library("${library_name}" SHARED
        ${${library_prefix}_EXTRA_SOURCES}
        ${${library_prefix}_SOURCES})
    else()
        continue()
    endif()

    # Add any extra includes defined for the library.
    if(DEFINED "${library_prefix}_EXTRA_INCLUDE_PUBLIC_DIRS")
        target_include_directories("${library_name}"
                        PUBLIC ${${library_prefix}_EXTRA_INCLUDE_PUBLIC_DIRS}
                        ${OPEN_SRC_INSTALL_PREFIX}/include)
    endif()

    if(DEFINED "${library_prefix}_EXTRA_INCLUDE_PRIVATE_DIRS")
        target_include_directories("${library_name}"
                        PRIVATE ${${library_prefix}_EXTRA_INCLUDE_PRIVATE_DIRS})
    endif()

    # Link library dependencies
    if(DEFINED "${library_prefix}_LIBRARY_DEPENDENCIES")
        message( STATUS "Linking libraries for ${library_prefix}: ${${library_prefix}_LIBRARY_DEPENDENCIES}" )
        target_link_libraries("${library_name}" PRIVATE "${${library_prefix}_LIBRARY_DEPENDENCIES}" )
    endif()

    # Allow a path to a custom config header to be passed through a CMake flag.
    set(config_prefix "${library_prefix}")
    if(";${OTA_BACKENDS};" MATCHES ";${library_prefix};")
        set(config_prefix "OTA")
    endif()
    if(DEFINED "${config_prefix}_CUSTOM_CONFIG_DIR")
        target_include_directories("${library_name}"
                                    PRIVATE ${${config_prefix}_CUSTOM_CONFIG_DIR})
    else()
        target_compile_definitions("${library_name}" PRIVATE -D${config_prefix}_DO_NOT_USE_CUSTOM_CONFIG)
        # PKCS11 requires a config so include the one from the demos by default.
        if(${config_prefix} STREQUAL "PKCS")
            target_include_directories("${library_name}" PRIVATE
                                        ${CMAKE_CURRENT_LIST_DIR}/config
                                        ${CMAKE_CURRENT_LIST_DIR}/standard/corePKCS11/source/dependency/3rdparty/mbedtls/include
                                        ${CMAKE_CURRENT_LIST_DIR}/logging-stack
                                        ${OPEN_SRC_INSTALL_PREFIX}/include
                                        ${OPEN_SRC_INSTALL_PREFIX}/include/mbedtls)
            target_link_directories("${library_name}" PUBLIC ${OPEN_SRC_INSTALL_PREFIX}/lib)
            target_link_libraries("${library_name}" PRIVATE mbedtls )
        endif()
    endif()

    # Add public include directories to library target.
    if(DEFINED "${library_prefix}_INCLUDE_PUBLIC_DIRS")
        target_include_directories("${library_name}"
                                    PUBLIC ${${library_prefix}_INCLUDE_PUBLIC_DIRS})
        foreach(library_public_dir ${${library_prefix}_INCLUDE_PUBLIC_DIRS})
            install(DIRECTORY ${library_public_dir}/ DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/include"
                    FILES_MATCHING PATTERN "*.h"
                    PATTERN "*private*" EXCLUDE)
        endforeach()
    endif()

    # Add private include directories to library target.
    if(DEFINED "${library_prefix}_INCLUDE_PRIVATE_DIRS")
        target_include_directories("${library_name}"
                                    PRIVATE ${${library_prefix}_INCLUDE_PRIVATE_DIRS})
    endif()

    set_target_properties("${library_name}" PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    )

    # Install the library target and support both static archive and shared library builds.
    install(TARGETS "${library_name}"
            LIBRARY DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
            ARCHIVE DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib")
endforeach()

# posix/
add_library( clock_posix
               "${CMAKE_CURRENT_LIST_DIR}/posix/clock_posix.c" )

target_include_directories( clock_posix
                              PUBLIC
                              ${CMAKE_CURRENT_LIST_DIR}/posix/ )

set_target_properties(clock_posix PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
)

# Install clock abstraction as library of both static archive and shared type.
if(INSTALL_PLATFORM_ABSTRACTIONS)
    install(TARGETS
      clock_posix
      LIBRARY DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
      ARCHIVE DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
      )
endif()
