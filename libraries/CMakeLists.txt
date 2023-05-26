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

include(
    ${CMAKE_CURRENT_LIST_DIR}/logging-stack/logging.cmake )

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
if(USE_OPENSSL)
    set(LIBRARY_PREFIXES
        "BACKOFF_ALGORITHM"
        "MQTT"
    )
elseif(USE_MBEDTLS)
    set(LIBRARY_PREFIXES
        "BACKOFF_ALGORITHM"
        "MQTT"
        "PKCS"
    )
endif()

if(USE_MBEDTLS)
    set(COREPKCS11_LOCATION "${CMAKE_CURRENT_LIST_DIR}/standard/corePKCS11")
    set(CORE_PKCS11_3RDPARTY_LOCATION "${COREPKCS11_LOCATION}/source/dependency/3rdparty")
endif()

# Define any extra sources or includes outside the standard, making sure to use the same prefix.
set(MQTT_EXTRA_SOURCES
    ${MQTT_SERIALIZER_SOURCES}
)

if(USE_MBEDTLS)
    set(PKCS_EXTRA_SOURCES
        "${COREPKCS11_LOCATION}/source/portable/os/posix/core_pkcs11_pal.c"
        "${COREPKCS11_LOCATION}/source/portable/os/core_pkcs11_pal_utils.c"
        "${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils/mbedtls_utils.c")
    set(PKCS_EXTRA_INCLUDE_PRIVATE_DIRS
        PRIVATE
        "${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils"
        "${COREPKCS11_LOCATION}/source/portable/os")
endif()

if(NOT DEFINED INSTALL_LIBS)
    set(INSTALL_LIBS ${LIBRARY_PREFIXES})
endif()

foreach(library_prefix ${LIBRARY_PREFIXES})
    # Check if prefix is in list of libraries to be installed.
    list (FIND INSTALL_LIBS ${library_prefix} _index)
    # Create the library target.
    if(DEFINED "${library_prefix}_SOURCES" AND ${_index} GREATER -1)
        string(TOLOWER "aws_iot_${library_prefix}" library_name)
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
                                        ${LOGGING_INCLUDE_DIRS}
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
        ARCHIVE DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
    )
endforeach()

# 3rdparty/tinycbor
add_library(tinycbor
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborpretty.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborpretty_stdio.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborencoder.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborencoder_close_container_checked.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborerrorstrings.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborparser.c"
    "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/cborparser_dup_string.c"
)

file(GLOB TINYCBOR_HEADERS "${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src/*.h")
file(COPY ${TINYCBOR_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

if(CMAKE_C_STANDARD LESS 99)
    set_target_properties(tinycbor PROPERTIES C_STANDARD 99)
endif()

target_include_directories(tinycbor PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/3rdparty/tinycbor/src
)

# posix/
add_library( clock_posix
               "${CMAKE_CURRENT_LIST_DIR}/posix/clock_posix.c" )

target_include_directories( clock_posix
                              PUBLIC
                              ${CMAKE_CURRENT_LIST_DIR}/posix )

set( TRANSPORT_INTERFACE_INCLUDE_DIR
     ${CMAKE_CURRENT_LIST_DIR}/standard/coreMQTT/source/interface )

# Create target for sockets utility.
add_library( sockets_posix
                "${CMAKE_CURRENT_LIST_DIR}/posix/sockets_posix.c" )

target_include_directories( sockets_posix
                            PUBLIC
                                ${LOGGING_INCLUDE_DIRS}
                                ${TRANSPORT_INTERFACE_INCLUDE_DIR}
)

set_target_properties(tinycbor clock_posix sockets_posix PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
)

if(USE_OPENSSL)
    # Create target for POSIX implementation of OpenSSL.
    add_library( openssl_posix
                    ${CMAKE_CURRENT_LIST_DIR}/posix/openssl_posix.c )

    target_link_libraries( openssl_posix
                        PUBLIC
                            sockets_posix
			    crypto
                            ssl
    )
    set_target_properties(openssl_posix PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    )
endif()

if(USE_MBEDTLS)
# Create target for mbedtls utility.
    add_library( mbedtls_posix
                    "${CMAKE_CURRENT_LIST_DIR}/posix/mbedtls_posix.c")

    target_link_libraries( mbedtls_posix
                           PRIVATE
                           mbedtls )
    target_include_directories(
        mbedtls_posix
        PUBLIC
            ${LOGGING_INCLUDE_DIRS}
            ${TRANSPORT_INTERFACE_INCLUDE_DIR}
            ${OPEN_SRC_INSTALL_PREFIX}/include
    )

    # Create target for POSIX implementation of MbedTLS transport with PKCS #11.
    add_library( mbedtls_pkcs11_posix
                    "${CMAKE_CURRENT_LIST_DIR}/posix/mbedtls_pkcs11_posix.c"
    )

    target_link_libraries( mbedtls_pkcs11_posix
                            mbedcrypto
                            mbedx509
                            mbedtls
                            aws_iot_pkcs )

    target_include_directories(
        mbedtls_pkcs11_posix
        PUBLIC
            ${LOGGING_INCLUDE_DIRS}
            ${TRANSPORT_INTERFACE_INCLUDE_DIR}
            ${PKCS_INCLUDE_PUBLIC_DIRS}
            ${COREPKCS11_LOCATION}/source/portable/os
            ${CORE_PKCS11_3RDPARTY_LOCATION}/pkcs11
            ${OPEN_SRC_INSTALL_PREFIX}/include
        PRIVATE
            ${CORE_PKCS11_3RDPARTY_LOCATION}/mbedtls_utils
    )

    set_target_properties(mbedtls_posix mbedtls_pkcs11_posix PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX}/lib
    )
endif()

# Install socket abstraction as library of both static archive and shared type.
if(INSTALL_PLATFORM_ABSTRACTIONS)
    install(TARGETS
        sockets_posix
        tinycbor
        clock_posix
        if(USE_OPENSSL)
            openssl_posix
        endif()
        if(USE_MBEDTLS)
            mbedtls_posix 
            mbedtls_pkcs11_posix
        endif()
        LIBRARY DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
        ARCHIVE DESTINATION "${OPEN_SRC_INSTALL_PREFIX}/lib"
    )
endif()