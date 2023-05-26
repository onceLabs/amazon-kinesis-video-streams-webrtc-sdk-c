cmake_minimum_required(VERSION 3.6.3)

project(KinesisVideoWebRTCClientSamples LANGUAGES C)

#set(OPEN_SRC_INSTALL_PREFIX "${CMAKE_CURRENT_SOURCE_DIR}/open-source" CACHE PATH "Libraries will be downloaded and build in this directory.")

message("OPEN_SRC_INSTALL_PREFIX=${OPEN_SRC_INSTALL_PREFIX}")

find_package(PkgConfig REQUIRED)

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

include_directories(${OPEN_SRC_INSTALL_PREFIX}/include)
include_directories(${OPEN_SRC_INCLUDE_DIRS})
link_directories(${OPEN_SRC_INSTALL_PREFIX}/lib)

# copy sample frames to this subproject build folder, in case developer runs sample program with command `kvsWebrtcClientMaster` from `build/samples` dir.
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/opusSampleFrames" DESTINATION .)
file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/h264SampleFrames" DESTINATION .)

add_executable(
  kvsWebrtcClientMaster
  Common.c
  kvsWebRTCClientMaster.c)
target_link_libraries(kvsWebrtcClientMaster kvsWebrtcClient kvsWebrtcSignalingClient kvsCommonLws kvspicUtils websockets)

add_executable(
  kvsWebrtcClientViewer
  Common.c
  kvsWebRTCClientViewer.c)
target_link_libraries(kvsWebrtcClientViewer kvsWebrtcClient kvsWebrtcSignalingClient kvsCommonLws kvspicUtils websockets)

add_executable(
        discoverNatBehavior
        discoverNatBehavior.c)
target_link_libraries(discoverNatBehavior kvsWebrtcClient)

if(GST_FOUND)
  add_executable(
    kvsWebrtcClientMasterGstSample
    Common.c
    kvsWebRTCClientMasterGstreamerSample.c
  )
  target_link_libraries(kvsWebrtcClientMasterGstSample kvsWebrtcClient kvsWebrtcSignalingClient ${GST_SAMPLE_LIBRARIES} kvsCommonLws kvspicUtils websockets)

  install(TARGETS kvsWebrtcClientMasterGstSample
    RUNTIME DESTINATION bin
  )
endif()

# Include Fleet Provisioning library's source and header path variables.
set(LIBRARIES_PATH ${CMAKE_SOURCE_DIR}/libraries)

include(
    ${LIBRARIES_PATH}/aws/fleet-provisioning-for-aws-iot-embedded-sdk/fleetprovisioningFilePaths.cmake )

# logging
file(GLOB LOGGING_HEADERS "${LIBRARIES_PATH}/logging-stack/*.h")
file(COPY ${LOGGING_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

if(USE_OPENSSL)
  list(APPEND INCLUDE_DIR
      "./"
      "./fleetProvisioning/"
      "${CMAKE_CURRENT_LIST_DIR}"
      "${OPEN_SRC_INSTALL_PREFIX}/include/"
      "${FLEET_PROVISIONING_INCLUDE_PUBLIC_DIRS}"
  )

  include_directories(${INCLUDE_DIR})

  add_executable(
    kvsWebRTCClientMasterWithProvisioning
    Common.c
    ${FLEET_PROVISIONING_SOURCES}
    ./fleetProvisioning/fleet_provisioning_serializer.c
    ./fleetProvisioning/fleet_provisioning_with_crt.c
    ./fleetProvisioning/mqtt_operations.c
    kvsWebRTCClientMasterWithProvisioning.c)

  target_link_libraries(kvsWebRTCClientMasterWithProvisioning kvsWebrtcClient kvsWebrtcSignalingClient kvsCommonLws kvspicUtils websockets
                        tinycbor
                        ${OPENSSL_SSL_LIBRARY}
                        ${OPENSSL_CRYPTO_LIBRARY}
                        sockets_posix
                        clock_posix
			openssl_posix
                        aws_iot_mqtt
                        aws_iot_backoff_algorithm)

elseif(USE_MBEDTLS)

# mbedtls
file(GLOB MBEDTLS_HEADERS
        "${LIBRARIES_PATH}/standard/corePKCS11/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.h")
file(COPY ${MBEDTLS_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

# Set path to corePKCS11 and it's third party libraries.
set(COREPKCS11_LOCATION "${LIBRARIES_PATH}/standard/corePKCS11")
set(CORE_PKCS11_3RDPARTY_LOCATION "${COREPKCS11_LOCATION}/source/dependency/3rdparty")

include( ${COREPKCS11_LOCATION}/pkcsFilePaths.cmake )

file(GLOB COREPKCS11_HEADERS 
          "${LIBRARIES_PATH}/config/core_pkcs11_config.h"
          "${LIBRARIES_PATH}/standard/corePKCS11/source/include/*.h"
          "${LIBRARIES_PATH}/standard/corePKCS11/source/dependency/3rdparty/pkcs11/*.h"
)
file(COPY ${COREPKCS11_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

list(APPEND INCLUDE_DIR
    "./"
    "./fleetProvisioning/"
    "${CMAKE_CURRENT_LIST_DIR}"
    "${OPEN_SRC_INSTALL_PREFIX}/include/"
    "${OPEN_SRC_INSTALL_PREFIX}/include/mbedtls/"
    "${OPEN_SRC_INSTALL_PREFIX}/include/pkcs11/"
    "${FLEET_PROVISIONING_INCLUDE_PUBLIC_DIRS}"
    "${COREPKCS11_LOCATION}"
    "${CORE_PKCS11_3RDPARTY_LOCATION}"
    "${COREPKCS11_LOCATION}/source/portable/os/"
)

include_directories(${INCLUDE_DIR})


add_executable(
  kvsWebRTCClientMasterWithProvisioning
  Common.c
  ${FLEET_PROVISIONING_SOURCES}
  ./fleetProvisioning/fleet_provisioning_serializer.c
  ./fleetProvisioning/fleet_provisioning_with_crt.c
  ./fleetProvisioning/mqtt_operations.c
  ./fleetProvisioning/pkcs11_operations.c
  kvsWebRTCClientMasterWithProvisioning.c)

target_link_libraries(kvsWebRTCClientMasterWithProvisioning kvsWebrtcClient kvsWebrtcSignalingClient kvsCommonLws kvspicUtils websockets
                       tinycbor
                       mbedcrypto
                       mbedx509
                       mbedtls
                       mbedtls_posix
                       mbedtls_pkcs11_posix
                       clock_posix
                       aws_iot_pkcs
                       aws_iot_mqtt
                       aws_iot_backoff_algorithm)
endif()

install(TARGETS kvsWebrtcClientMaster kvsWebrtcClientViewer discoverNatBehavior kvsWebRTCClientMasterWithProvisioning
  RUNTIME DESTINATION bin
)