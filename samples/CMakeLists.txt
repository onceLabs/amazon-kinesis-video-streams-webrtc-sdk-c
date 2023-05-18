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

set(FLEET_PROVISION_PATH ${OPEN_SRC_INSTALL_PREFIX}/libprovision/build/src) 

file(GLOB TINYCBOR_HEADERS "${FLEET_PROVISION_PATH}/project_libprovision/libraries/3rdparty/tinycbor/src/*.h")
file(COPY ${TINYCBOR_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

# corePKCS11 config
file(GLOB COREPKCS11_HEADERS "${FLEET_PROVISION_PATH}/project_libprovision/demos/pkcs11/common/include/core_pkcs11_config.h")
file(COPY ${COREPKCS11_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

# logging
file(GLOB LOGGING_HEADERS "${FLEET_PROVISION_PATH}/project_libprovision/demos/logging-stack/*.h")
file(COPY ${LOGGING_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)

# mbedtls
file(GLOB MBEDTLS_HEADERS
        "${FLEET_PROVISION_PATH}/project_libprovision/libraries/3rdparty/mbedtls/include/mbedtls"
        "${FLEET_PROVISION_PATH}/project_libprovision/libraries/standard/corePKCS11/source/dependency/3rdparty/mbedtls_utils/mbedtls_utils.h")
file(COPY ${MBEDTLS_HEADERS} DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/include)


include(
    ${FLEET_PROVISION_PATH}/project_libprovision/libraries/aws/fleet-provisioning-for-aws-iot-embedded-sdk/fleetprovisioningFilePaths.cmake )

include_directories(./)
include_directories(./fleetProvisioning/)
include_directories(${OPEN_SRC_INSTALL_PREFIX}/include/build/src/project_libprovision/libraries/3rdparty/tinycbor/src/)
include_directories(${FLEET_PROVISIONING_INCLUDE_PUBLIC_DIRS})

#file(COPY ${FLEET_PROVISION_PATH}/project_libprovision-build/lib/libmbedtls.so DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/lib)
file(COPY ${FLEET_PROVISION_PATH}/project_libprovision-build/lib/libtinycbor.so DESTINATION ${OPEN_SRC_INSTALL_PREFIX}/lib)

add_executable(
  kvsWebRTCClientMasterWithProvisioning
  Common.c
  ${FLEET_PROVISIONING_SOURCES}
  ./fleetProvisioning/fleet_provisioning_serializer.c
  ./fleetProvisioning/fleet_provisioning_with_crt.c
  ./fleetProvisioning/mqtt_operations.c
#  ./fleetProvisioning/pkcs11_operations.c
  ./fleetProvisioning/mbedtls_posix.c
  kvsWebRTCClientMasterWithProvisioning.c)
target_link_libraries(kvsWebRTCClientMasterWithProvisioning kvsWebrtcClient kvsWebrtcSignalingClient kvsCommonLws kvspicUtils websockets
                       tinycbor
                       mbedcrypto
                       mbedx509
                       mbedtls
                       clock_posix
#                       transport_mbedtls_pkcs11_posix
                       aws_iot_mqtt
                       aws_iot_backoff_algorithm)

install(TARGETS kvsWebrtcClientMaster kvsWebrtcClientViewer discoverNatBehavior kvsWebRTCClientMasterWithProvisioning
  RUNTIME DESTINATION bin
)