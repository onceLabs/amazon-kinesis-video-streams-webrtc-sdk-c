cmake_minimum_required(VERSION 2.8)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake;${CMAKE_MODULE_PATH}")
include(Utilities)
include(CheckIncludeFiles)
include(CheckFunctionExists)

project(KinesisVideoWebRTCClient LANGUAGES C)

# User Flags
option(ADD_MUCLIBC "Add -muclibc c flag" OFF)
option(BUILD_DEPENDENCIES "Whether or not to build depending libraries from source" ON)
option(USE_OPENSSL "Use openssl as crypto library" OFF)
option(USE_MBEDTLS "Use mbedtls as crypto library" ON)
option(BUILD_STATIC_LIBS "Build all libraries statically. (This includes third-party libraries.)" OFF)
option(BUILD_OPENSSL_PLATFORM "If buildng OpenSSL what is the target platform" OFF)
option(BUILD_LIBSRTP_HOST_PLATFORM "If buildng LibSRTP what is the current platform" OFF)
option(BUILD_LIBSRTP_DESTINATION_PLATFORM "If buildng LibSRTP what is the destination platform" OFF)
option(BUILD_SAMPLE "Build available samples" ON)
option(ENABLE_DATA_CHANNEL "Enable support for data channel" ON)## withhout sample code. experimental option.
option(ENABLE_STREAMING "Enable support for streaming" ON)## withhout sample code. experimental option.
option(BUILD_CLIENT "Build client." ON)## withhout sample code. experimental option.

# Developer Flags
option(BUILD_TEST "Build the testing tree." OFF)
option(CODE_COVERAGE "Enable coverage reporting" OFF)
option(COMPILER_WARNINGS "Enable all compiler warnings." OFF)
option(ADDRESS_SANITIZER "Build with AddressSanitizer." OFF)
option(MEMORY_SANITIZER "Build with MemorySanitizer." OFF)
option(THREAD_SANITIZER "Build with ThreadSanitizer." OFF)
option(UNDEFINED_BEHAVIOR_SANITIZER "Build with UndefinedBehaviorSanitizer." OFF)

option(KVS_PLAT_ESP_FREERTOS "Build for ESP FreeRTOS" OFF)

if(KVS_PLAT_ESP_FREERTOS)
  add_definitions(-DKVS_PLAT_ESP_FREERTOS)
endif()

if(NOT WIN32)

CHECK_INCLUDE_FILES(ifaddrs.h KVSWEBRTC_HAVE_IFADDRS_H)
if(KVSWEBRTC_HAVE_IFADDRS_H)
  add_definitions(-DKVSWEBRTC_HAVE_IFADDRS_H)
endif()

CHECK_FUNCTION_EXISTS(getifaddrs KVSWEBRTC_HAVE_GETIFADDRS)
if(KVSWEBRTC_HAVE_GETIFADDRS)
  add_definitions(-DKVSWEBRTC_HAVE_GETIFADDRS)
endif()

CHECK_FUNCTION_EXISTS(getenv KVSWEBRTC_HAVE_GETENV)
if(KVSWEBRTC_HAVE_GETENV)
  add_definitions(-DKVSWEBRTC_HAVE_GETENV)
endif()

CHECK_INCLUDE_FILES(netinet/tcp.h   KVSWEBRTC_HAVE_NETINET_TCP_H)
if(KVSWEBRTC_HAVE_NETINET_TCP_H)
  add_definitions(-DKVSWEBRTC_HAVE_NETINET_TCP_H)
endif()
endif()

set(CMAKE_MACOSX_RPATH TRUE)
get_filename_component(ROOT "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)

# static settings
if(BUILD_STATIC_LIBS OR WIN32)
  set(LINKAGE STATIC)
  # Force CMake to find static libs
  if(WIN32)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  else()
    SET(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  endif()
else()
  set(LINKAGE SHARED)
endif()

set(KINESIS_VIDEO_WEBRTC_CLIENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}")


message(STATUS "Kinesis Video WebRTC Client path is ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}")
message(STATUS "dependencies install path is ${OPEN_SRC_INSTALL_PREFIX}")

# pass ca cert location to sdk
add_definitions(-DKVS_CA_CERT_PATH="${CMAKE_SOURCE_DIR}/certs/cert.pem")
add_definitions(-DCMAKE_DETECTED_CACERT_PATH)

if(USE_OPENSSL)
  add_definitions(-DKVS_USE_OPENSSL)
elseif(USE_MBEDTLS)
  add_definitions(-DKVS_USE_MBEDTLS)
endif()

if(BUILD_DEPENDENCIES)
  set(OPEN_SRC_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/open-source)
  if(NOT EXISTS ${OPEN_SRC_INSTALL_PREFIX})
    file(MAKE_DIRECTORY ${OPEN_SRC_INSTALL_PREFIX})
  endif()

  set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${OPEN_SRC_INSTALL_PREFIX}/lib/pkgconfig")
  set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${OPEN_SRC_INSTALL_PREFIX})

  message(STATUS "Begin building dependencies.")

  set(SSL_OPTIONS USE_OPENSSL USE_MBEDTLS)
  count_true(ENABLED_SSL_OPTION_COUNT ${SSL_OPTIONS})

  if(ENABLED_SSL_OPTION_COUNT GREATER "1")
    message(FATAL_ERROR "Only one of ${SSL_OPTIONS} can be enabled")
  endif()

  if (USE_OPENSSL)
    set(BUILD_ARGS -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS}
                   -DBUILD_OPENSSL_PLATFORM=${BUILD_OPENSSL_PLATFORM}
                   -DOPENSSL_EXTRA=${OPENSSL_EXTRA})
    build_dependency(openssl ${BUILD_ARGS})
    set(OPENSSL_ROOT_DIR ${OPEN_SRC_INSTALL_PREFIX})
  elseif(USE_MBEDTLS)
    set(BUILD_ARGS -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS})
    build_dependency(mbedtls ${BUILD_ARGS})
  endif()

  set(BUILD_ARGS -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS}
                 -DOPENSSL_DIR=${OPEN_SRC_INSTALL_PREFIX}
                 -DUSE_OPENSSL=${USE_OPENSSL}
                 -DUSE_MBEDTLS=${USE_MBEDTLS})
  build_dependency(websockets ${BUILD_ARGS})
  if(ENABLE_STREAMING)
    set(BUILD_ARGS
        -DBUILD_STATIC_LIBS=${BUILD_STATIC_LIBS}
        -DOPENSSL_DIR=${OPEN_SRC_INSTALL_PREFIX}
        -DBUILD_LIBSRTP_HOST_PLATFORM=${BUILD_LIBSRTP_HOST_PLATFORM}
        -DBUILD_LIBSRTP_DESTINATION_PLATFORM=${BUILD_LIBSRTP_DESTINATION_PLATFORM}
        -DUSE_OPENSSL=${USE_OPENSSL}
        -DUSE_MBEDTLS=${USE_MBEDTLS}
    )
    build_dependency(srtp ${BUILD_ARGS})
  endif()
  if(ENABLE_DATA_CHANNEL)
    build_dependency(usrsctp)
  endif()

  if(BUILD_TEST)
    build_dependency(gtest)
  endif()

  message(STATUS "Finished building dependencies.")
endif()

############# find dependent libraries ############

find_package(Threads)
find_package(PkgConfig REQUIRED)
if (USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  set(OPEN_SRC_INCLUDE_DIRS ${OPEN_SRC_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
else()
  if(NOT KVS_PLAT_ESP_FREERTOS)
    find_package(MbedTLS REQUIRED)
    set(OPEN_SRC_INCLUDE_DIRS ${OPEN_SRC_INCLUDE_DIRS} ${MBEDTLS_INCLUDE_DIRS})
  endif()
endif()

if (ENABLE_STREAMING AND NOT KVS_PLAT_ESP_FREERTOS)
  if (OPEN_SRC_INSTALL_PREFIX)
    find_library(LLHTTP_LIBRARIES llhttp REQUIRED PATHS ${OPEN_SRC_INSTALL_PREFIX})
  else()
    find_library(LLHTTP_LIBRARIES llhttp REQUIRED )
  endif()
endif()

if (ENABLE_STREAMING AND NOT KVS_PLAT_ESP_FREERTOS)
  if (OPEN_SRC_INSTALL_PREFIX)
    find_library(WSLAY_LIBRARIES wslay REQUIRED PATHS ${OPEN_SRC_INSTALL_PREFIX})
  else()
    find_library(WSLAY_LIBRARIES wslay REQUIRED )
  endif()
endif()

if (ENABLE_STREAMING AND NOT KVS_PLAT_ESP_FREERTOS)
  if (OPEN_SRC_INSTALL_PREFIX)
    find_library(SRTP_LIBRARIES srtp2 REQUIRED PATHS ${OPEN_SRC_INSTALL_PREFIX})
  else()
    find_library(SRTP_LIBRARIES srtp2 REQUIRED )
  endif()
endif()

if(ENABLE_DATA_CHANNEL)
  # usrsctp dont support pkgconfig yet
  if(NOT KVS_PLAT_ESP_FREERTOS)
    find_library(
      Usrsctp
      NAMES ${USRSCTP_LIBNAME} usrsctp REQUIRED
      PATHS ${OPEN_SRC_INSTALL_PREFIX}/lib)
    endif()
endif()

set(OPEN_SRC_INCLUDE_DIRS ${OPEN_SRC_INCLUDE_DIRS} ${LIBSRTP_INCLUDE_DIRS}
                          ${CURL_INCLUDE_DIRS} ${LIBWEBSOCKETS_INCLUDE_DIRS})

link_directories(${LIBSRTP_LIBRARY_DIRS})
link_directories(${LIBWEBSOCKETS_LIBRARY_DIRS})
link_directories(${OPEN_SRC_INSTALL_PREFIX}/lib)

pkg_check_modules(GST gstreamer-1.0)
if(GST_FOUND)

  if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:/usr/local/opt/libffi/lib/pkgconfig")
    find_library(Intl "intl" REQUIRED PATHS "/usr/local/opt/gettext/lib")
    link_directories("/usr/local/opt/gettext/lib")
  endif()

  pkg_check_modules(GLIB2 REQUIRED glib-2.0)
  pkg_check_modules(GST_APP REQUIRED gstreamer-app-1.0)
  pkg_check_modules(GOBJ2 REQUIRED gobject-2.0)
  message("gstreamer found. Will build gstreamer samples")

  set(OPEN_SRC_INCLUDE_DIRS
      ${OPEN_SRC_INCLUDE_DIRS} ${GLIB2_INCLUDE_DIRS} ${GST_INCLUDE_DIRS}
      ${GST_APP_INCLUDE_DIRS} ${GOBJ2_INCLUDE_DIRS})

  set(GST_SAMPLE_LIBRARIES ${GLIB2_LIBRARIES} ${GST_LIBRARIES}
                           ${GST_APP_LIBRARIES} ${GOBJ2_LIBRARIES} ${Intl})

  link_directories(${GLIB2_LIBRARY_DIRS})
  link_directories(${GST_LIBRARY_DIRS})
  link_directories(${GST_APP_LIBRARY_DIRS})
  link_directories(${GOBJ2_LIBRARY_DIRS})
else()
  message("gstreamer not found. Will not build gstreamer samples")
endif()

############# find dependent libraries end ############

if("${CMAKE_C_COMPILER_ID}" MATCHES "GNU|Clang")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

  if(ADD_MUCLIBC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -muclibc")
  endif()

  if(CODE_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g -fprofile-arcs -ftest-coverage")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
  endif()

  if(ADDRESS_SANITIZER)
    enableSanitizer("address")
  endif()
  if(MEMORY_SANITIZER)
    enableSanitizer("memory")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-memory-track-origins")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize-memory-track-origins")
  endif()
  if(THREAD_SANITIZER)
    enableSanitizer("thread")
  endif()
  if(UNDEFINED_BEHAVIOR_SANITIZER)
    enableSanitizer("undefined")
  endif()
endif()

# Uncomment below line for debug heap
# add_definitions(-DHEAP_DEBUG)

# Uncomment below to add thread id in log
# add_definitions(-DENABLE_LOG_THREAD_ID)

# Uncomment below line for very verbose logging
# add_definitions(-DLOG_STREAMING)

if(BUILD_CLIENT)
  add_definitions(-DBUILD_CLIENT)
endif()
if (ENABLE_STREAMING)
  add_definitions(-DENABLE_STREAMING)
endif()
if (ENABLE_DATA_CHANNEL)
  add_definitions(-DENABLE_DATA_CHANNEL)
endif()

file(GLOB WEBRTC_STATE_MACHINE_SOURCE_FILES "src/source/state_machine/*.c")
file(GLOB WEBRTC_UTILS_SOURCE_FILES "src/source/utils/*.c")

file(
  GLOB
  WEBRTC_CLIENT_SOURCE_FILES
  "src/source/crypto/*.c"
  "src/source/ice/*.c"
  "src/source/Json/*.c"
  "src/source/net/*.c"
  "src/source/PeerConnection/*.c"
  "src/source/Rtcp/*.c"
  "src/source/Rtp/*.c"
  "src/source/Rtp/Codecs/*.c"
  "src/source/Sdp/*.c"
  "src/source/srtp/*.c"
  "src/source/stun/*.c"
  "src/source/sctp/*.c"
  "src/source/Metrics/*.c")

if (USE_OPENSSL)
  list(FILTER WEBRTC_CLIENT_SOURCE_FILES EXCLUDE REGEX ".*_mbedtls\\.c")
elseif (USE_MBEDTLS)
  list(FILTER WEBRTC_CLIENT_SOURCE_FILES EXCLUDE REGEX ".*_openssl\\.c")
endif()

file(
  GLOB
  WEBRTC_SIGNALING_CLIENT_SOURCE_FILES
  "src/source/credential/*.c"
  "src/source/api_call/*.c"
  "src/source/signaling/*.c"
  )

include_directories(${OPEN_SRC_INCLUDE_DIRS})
include_directories(${OPEN_SRC_INSTALL_PREFIX}/include)
include_directories(${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/src/include)

add_library(kvsWebrtcStateMachine STATIC ${WEBRTC_STATE_MACHINE_SOURCE_FILES})
target_link_libraries(kvsWebrtcStateMachine)

add_library(kvsWebrtcUtils STATIC ${WEBRTC_UTILS_SOURCE_FILES})

target_link_libraries(kvsWebrtcUtils ${CMAKE_THREAD_LIBS_INIT})

if(UNIX AND NOT APPLE)
  # rt needed for clock_gettime
  target_link_libraries(kvsWebrtcUtils rt)
endif()

if(BUILD_CLIENT)
  add_library(kvsWebrtcClient ${LINKAGE} ${WEBRTC_CLIENT_SOURCE_FILES})

  target_link_libraries(
    kvsWebrtcClient
    PRIVATE kvsWebrtcUtils
            kvsWebrtcStateMachine
            ${CMAKE_THREAD_LIBS_INIT}
            ${OPENSSL_SSL_LIBRARY}
            ${OPENSSL_CRYPTO_LIBRARY}
            ${SRTP_LIBRARIES}
            ${MBEDTLS_LIBRARIES}
            ${EXTRA_DEPS})

  if(ENABLE_STREAMING)
    target_link_libraries(
      kvsWebrtcClient
      PRIVATE ${SRTP_LIBRARIES})
  endif()

  if(ENABLE_DATA_CHANNEL)
    target_link_libraries(
      kvsWebrtcClient
      PRIVATE ${Usrsctp})
  endif()
endif()

set(CPRODUCER_COMMON_TLS_OPTION KVS_USE_OPENSSL)
if (USE_MBEDTLS)
    set(CPRODUCER_COMMON_TLS_OPTION KVS_USE_MBEDTLS)
endif()

add_library(kvsWebrtcSignalingClient ${LINKAGE} ${WEBRTC_SIGNALING_CLIENT_SOURCE_FILES})
target_compile_options(kvsWebrtcSignalingClient PUBLIC -Wno-format-truncation)
target_compile_definitions(kvsWebrtcSignalingClient PRIVATE KVS_BUILD_WITH_LWS ${CPRODUCER_COMMON_TLS_OPTION})

target_link_libraries(
  kvsWebrtcSignalingClient
  PRIVATE kvsWebrtcUtils
         kvsWebrtcStateMachine
         ${CMAKE_THREAD_LIBS_INIT}
         ${EXTRA_DEPS}
         ${OPENSSL_SSL_LIBRARY}
         ${OPENSSL_CRYPTO_LIBRARY}
         ${MBEDTLS_LIBRARIES}
         ${LLHTTP_LIBRARIES}
         ${WSLAY_LIBRARIES})

if (WIN32)
  target_link_libraries(kvsWebrtcClient PRIVATE "Ws2_32" "iphlpapi")
endif()

if(COMPILER_WARNINGS)
  target_compile_options(kvsWebrtcClient PUBLIC -Wall -Werror -pedantic -Wextra -Wno-unknown-warning-option)
  target_compile_options(kvsWebrtcSignalingClient PUBLIC -Wall -Werror -pedantic -Wextra -Wno-unknown-warning-option)
endif()

if(BUILD_CLIENT)
install(TARGETS kvsWebrtcClient
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
endif()

install(TARGETS kvsWebrtcSignalingClient
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(DIRECTORY ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/src/include/
  DESTINATION include
)

if (BUILD_SAMPLE)
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/samples/opusSampleFrames" DESTINATION .)
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/samples/h264SampleFrames" DESTINATION .)

  add_executable(
    kvsWebrtcClientMaster
    ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/Common.c
    ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/kvsWebRTCClientMaster.c)
  target_link_libraries(kvsWebrtcClientMaster kvsWebrtcClient kvsWebrtcSignalingClient kvsWebrtcUtils)

  add_executable(
    kvsWebrtcClientViewer
    ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/Common.c
    ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/kvsWebRTCClientViewer.c)
  target_link_libraries(kvsWebrtcClientViewer kvsWebrtcClient kvsWebrtcSignalingClient kvsWebrtcUtils)

  add_executable(
          discoverNatBehavior
          ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/discoverNatBehavior.c)
  target_link_libraries(discoverNatBehavior kvsWebrtcClient)

  if(GST_FOUND AND ENABLE_STREAMING)
    add_executable(
      kvsWebrtcClientMasterGstSample
      ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/Common.c
      ${KINESIS_VIDEO_WEBRTC_CLIENT_SRC}/samples/kvsWebRTCClientMasterGstreamerSample.c
    )
    target_link_libraries(kvsWebrtcClientMasterGstSample kvsWebrtcClient kvsWebrtcSignalingClient ${GST_SAMPLE_LIBRARIES} kvsWebrtcUtils)

    install(TARGETS kvsWebrtcClientMasterGstSample
      RUNTIME DESTINATION bin
    )
  endif()

  install(TARGETS kvsWebrtcClientMaster kvsWebrtcClientViewer discoverNatBehavior
    RUNTIME DESTINATION bin
  )
endif()

if(BUILD_TEST)
  add_subdirectory(tst)
endif()
