/*******************************************
Shared include file for the samples
*******************************************/
#ifndef __KINESIS_VIDEO_SAMPLE_INCLUDE__
#define __KINESIS_VIDEO_SAMPLE_INCLUDE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <com/amazonaws/kinesis/video/webrtcclient/Include.h>

#define NUMBER_OF_H264_FRAME_FILES               1500
#define NUMBER_OF_OPUS_FRAME_FILES               618
#define DEFAULT_FPS_VALUE                        25
#define DEFAULT_MAX_CONCURRENT_STREAMING_SESSION 10

#define SAMPLE_MASTER_CLIENT_ID "ProducerMaster"
#define SAMPLE_VIEWER_CLIENT_ID "ConsumerViewer"
#define SAMPLE_CHANNEL_NAME     (PCHAR) "ScaryTestChannel"

#define SAMPLE_AUDIO_FRAME_DURATION (20 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
#define SAMPLE_STATS_DURATION       (60 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define SAMPLE_VIDEO_FRAME_DURATION (HUNDREDS_OF_NANOS_IN_A_SECOND / DEFAULT_FPS_VALUE)

#define SAMPLE_PRE_GENERATE_CERT        TRUE
#define SAMPLE_PRE_GENERATE_CERT_PERIOD (1000 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)

#define SAMPLE_SESSION_CLEANUP_WAIT_PERIOD (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define SAMPLE_PENDING_MESSAGE_CLEANUP_DURATION (20 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define CA_CERT_PEM_FILE_EXTENSION ".pem"

#define FILE_LOGGING_BUFFER_SIZE (100 * 1024)
#define MAX_NUMBER_OF_LOG_FILES  5

#define SAMPLE_HASH_TABLE_BUCKET_COUNT  50
#define SAMPLE_HASH_TABLE_BUCKET_LENGTH 2

#define IOT_CORE_CREDENTIAL_ENDPOINT ((PCHAR) "AWS_IOT_CORE_CREDENTIAL_ENDPOINT")
#define IOT_CORE_CERT                ((PCHAR) "AWS_IOT_CORE_CERT")
#define IOT_CORE_PRIVATE_KEY         ((PCHAR) "AWS_IOT_CORE_PRIVATE_KEY")
#define IOT_CORE_ROLE_ALIAS          ((PCHAR) "AWS_IOT_CORE_ROLE_ALIAS")
#define IOT_CORE_THING_NAME          ((PCHAR) "AWS_IOT_CORE_THING_NAME")

#define AWS_IOT_ENDPOINT             ((PCHAR) "AWS_IOT_ENDPOINT")
#define IOT_CORE_CLAIM_CERT          ((PCHAR) "AWS_IOT_CLAIM_CERT_PATH")
#define IOT_CORE_CLAIM_PRIVATE_KEY   ((PCHAR) "AWS_IOT_CLAIM_PRIVATE_KEY_PATH")
#define IOT_CORE_PROVISIONING_TEMPLATE_NAME   ((PCHAR) "AWS_IOT_CORE_PROVISIONING_TEMPLATE_NAME")
#define IOT_CORE_ROOT_CA_CERT        ((PCHAR) "AWS_IOT_CORE_ROOT_CA_CERT")

/**
 * @brief AWS IoT MQTT broker port number.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 */
#define AWS_MQTT_PORT    ( 8883 )

/**
 * @brief Size of the network buffer for MQTT packets. Must be large enough to
 * hold the GetCertificateFromCsr response, which, among other things, includes
 * a PEM encoded certificate.
 */
#define NETWORK_BUFFER_SIZE       ( 4096U )

/**
 * @brief The name of the operating system that the application is running on.
 * The current value is given as an example. Please update for your specific
 * operating system.
 */
#define OS_NAME                   "Ubuntu"

/**
 * @brief The version of the operating system that the application is running
 * on. The current value is given as an example. Please update for your specific
 * operating system version.
 */
#define OS_VERSION                "18.04 LTS"

/**
 * @brief The name of the hardware platform the application is running on. The
 * current value is given as an example. Please update for your specific
 * hardware platform.
 */
#define HARDWARE_PLATFORM_NAME    "PC"

/**
 * @brief The name of the MQTT library used and its version, following an "@"
 * symbol.
 */
//#include "core_mqtt.h"
#define MQTT_LIB    "core-mqtt@" MQTT_LIBRARY_VERSION

/*
 * AWS IoT Core allows the use of HTTP or MQTT over TCP port 443. Connections
 * to IoT Core endpoints on port 443 default to the HTTP protocol.
 *
 * Clients must use the TLS Application-Layer Protocol Negotiation extension
 * to notify the service of it's desired protocol or authentication mode.
 *
 * For more information, please reference the following URL:
 * https://docs.aws.amazon.com/iot/latest/developerguide/protocols.html
 */

#define AWS_IOT_ALPN_MQTT_CUSTOM_AUTH                "mqtt"
#define AWS_IOT_ALPN_MQTT_CA_AUTH                    "x-amzn-mqtt-ca"
#define AWS_IOT_ALPN_HTTP_CA_AUTH                    "x-amzn-http-ca"
#define AWS_IOT_ALPN_MQTT_CUSTOM_AUTH_MBEDTLS        { AWS_IOT_ALPN_MQTT_CUSTOM_AUTH, NULL }
#define AWS_IOT_ALPN_MQTT_CA_AUTH_MBEDTLS            { AWS_IOT_ALPN_MQTT_CA_AUTH, NULL }
#define AWS_IOT_ALPN_HTTP_CA_AUTH_MBEDTLS            { AWS_IOT_ALPN_HTTP_CA_AUTH, NULL }

/*
 * @note OpenSSL requires that ALPN identifiers be provided in protocol form.
 *       This means that each alpn string be prepended with its length.
 *       When multiple concurrent alpn identifiers are necessary,
 *       each identifier should be prepended with it's respective length and
 *       then concatenated together.
 */
#define AWS_IOT_ALPN_MQTT_CUSTOM_AUTH_OPENSSL        "\x04mqtt"
#define AWS_IOT_ALPN_MQTT_CUSTOM_AUTH_OPENSSL_LEN    ( sizeof( AWS_IOT_ALPN_MQTT_CUSTOM_AUTH_OPENSSL ) - 1U )
#define AWS_IOT_ALPN_MQTT_CA_AUTH_OPENSSL            "\x0ex-amzn-mqtt-ca"
#define AWS_IOT_ALPN_MQTT_CA_AUTH_OPENSSL_LEN        ( sizeof( AWS_IOT_ALPN_MQTT_CA_AUTH_OPENSSL ) - 1U )
#define AWS_IOT_ALPN_HTTP_CA_AUTH_OPENSSL            "\x0ex-amzn-http-ca"
#define AWS_IOT_ALPN_HTTP_CA_AUTH_OPENSSL_LEN        ( sizeof( AWS_IOT_ALPN_HTTP_CA_AUTH_OPENSSL ) - 1U )

#define MASTER_DATA_CHANNEL_MESSAGE "This message is from the KVS Master"
#define VIEWER_DATA_CHANNEL_MESSAGE "This message is from the KVS Viewer"

/* Uncomment the following line in order to enable IoT credentials checks in the provided samples */
#define IOT_CORE_ENABLE_CREDENTIALS  1

/* when define IOT_CORE_ENABLE_CREDENTIALS, if use PKCS11 then set, else not set */
#ifdef KVS_USE_MBEDTLS
#define ENABLE_PKCS11 1
#endif

typedef enum {
    SAMPLE_STREAMING_VIDEO_ONLY,
    SAMPLE_STREAMING_AUDIO_VIDEO,
} SampleStreamingMediaType;

typedef struct __SampleStreamingSession SampleStreamingSession;
typedef struct __SampleStreamingSession* PSampleStreamingSession;

typedef struct {
    UINT64 prevNumberOfPacketsSent;
    UINT64 prevNumberOfPacketsReceived;
    UINT64 prevNumberOfBytesSent;
    UINT64 prevNumberOfBytesReceived;
    UINT64 prevPacketsDiscardedOnSend;
    UINT64 prevTs;
} RtcMetricsHistory, *PRtcMetricsHistory;

typedef struct {
    volatile ATOMIC_BOOL appTerminateFlag;
    volatile ATOMIC_BOOL interrupted;
    volatile ATOMIC_BOOL mediaThreadStarted;
    volatile ATOMIC_BOOL recreateSignalingClient;
    volatile ATOMIC_BOOL connected;
    BOOL useTestSrc;
    ChannelInfo channelInfo;
    PCHAR pCaCertPath;
    PAwsCredentialProvider pCredentialProvider;
    SIGNALING_CLIENT_HANDLE signalingClientHandle;
    PBYTE pAudioFrameBuffer;
    UINT32 audioBufferSize;
    PBYTE pVideoFrameBuffer;
    UINT32 videoBufferSize;
    TID mediaSenderTid;
    TIMER_QUEUE_HANDLE timerQueueHandle;
    UINT32 iceCandidatePairStatsTimerId;
    SampleStreamingMediaType mediaType;
    startRoutine audioSource;
    startRoutine videoSource;
    startRoutine receiveAudioVideoSource;
    RtcOnDataChannel onDataChannel;

    PStackQueue pPendingSignalingMessageForRemoteClient;
    PHashTable pRtcPeerConnectionForRemoteClient;

    MUTEX sampleConfigurationObjLock;
    CVAR cvar;
    BOOL trickleIce;
    BOOL useTurn;
    BOOL enableFileLogging;
    UINT64 customData;
    PSampleStreamingSession sampleStreamingSessionList[DEFAULT_MAX_CONCURRENT_STREAMING_SESSION];
    UINT32 streamingSessionCount;
    MUTEX streamingSessionListReadLock;
    UINT32 iceUriCount;
    SignalingClientCallbacks signalingClientCallbacks;
    SignalingClientInfo clientInfo;
    RtcStats rtcIceCandidatePairMetrics;

    MUTEX signalingSendMessageLock;

    UINT32 pregenerateCertTimerId;
    PStackQueue pregeneratedCertificates; // Max MAX_RTCCONFIGURATION_CERTIFICATES certificates
} SampleConfiguration, *PSampleConfiguration;

typedef struct {
    UINT64 hashValue;
    UINT64 createTime;
    PStackQueue messageQueue;
} PendingMessageQueue, *PPendingMessageQueue;

typedef VOID (*StreamSessionShutdownCallback)(UINT64, PSampleStreamingSession);

struct __SampleStreamingSession {
    volatile ATOMIC_BOOL terminateFlag;
    volatile ATOMIC_BOOL candidateGatheringDone;
    volatile ATOMIC_BOOL peerIdReceived;
    volatile SIZE_T frameIndex;
    PRtcPeerConnection pPeerConnection;
    PRtcRtpTransceiver pVideoRtcRtpTransceiver;
    PRtcRtpTransceiver pAudioRtcRtpTransceiver;
    RtcSessionDescriptionInit answerSessionDescriptionInit;
    PSampleConfiguration pSampleConfiguration;
    UINT64 audioTimestamp;
    UINT64 videoTimestamp;
    CHAR peerId[MAX_SIGNALING_CLIENT_ID_LEN + 1];
    TID receiveAudioVideoSenderTid;
    UINT64 offerReceiveTime;
    UINT64 startUpLatency;
    BOOL firstFrame;
    RtcMetricsHistory rtcMetricsHistory;
    BOOL remoteCanTrickleIce;

    // this is called when the SampleStreamingSession is being freed
    StreamSessionShutdownCallback shutdownCallback;
    UINT64 shutdownCallbackCustomData;
};

VOID sigintHandler(INT32);
STATUS readFrameFromDisk(PBYTE, PUINT32, PCHAR);
PVOID sendVideoPackets(PVOID);
PVOID sendAudioPackets(PVOID);
PVOID sendGstreamerAudioVideo(PVOID);
PVOID sampleReceiveVideoFrame(PVOID args);
PVOID getPeriodicIceCandidatePairStats(PVOID);
STATUS getIceCandidatePairStatsCallback(UINT32, UINT64, UINT64);
STATUS pregenerateCertTimerCallback(UINT32, UINT64, UINT64);
STATUS createSampleConfiguration(PCHAR, SIGNALING_CHANNEL_ROLE_TYPE, BOOL, BOOL, PSampleConfiguration*);
STATUS freeSampleConfiguration(PSampleConfiguration*);
STATUS signalingClientStateChanged(UINT64, SIGNALING_CLIENT_STATE);
STATUS signalingMessageReceived(UINT64, PReceivedSignalingMessage);
STATUS handleAnswer(PSampleConfiguration, PSampleStreamingSession, PSignalingMessage);
STATUS handleOffer(PSampleConfiguration, PSampleStreamingSession, PSignalingMessage);
STATUS handleRemoteCandidate(PSampleStreamingSession, PSignalingMessage);
STATUS initializePeerConnection(PSampleConfiguration, PRtcPeerConnection*);
STATUS lookForSslCert(PSampleConfiguration*);
STATUS createSampleStreamingSession(PSampleConfiguration, PCHAR, BOOL, PSampleStreamingSession*);
STATUS freeSampleStreamingSession(PSampleStreamingSession*);
STATUS streamingSessionOnShutdown(PSampleStreamingSession, UINT64, StreamSessionShutdownCallback);
STATUS sendSignalingMessage(PSampleStreamingSession, PSignalingMessage);
STATUS respondWithAnswer(PSampleStreamingSession);
STATUS resetSampleConfigurationState(PSampleConfiguration);
VOID sampleFrameHandler(UINT64, PFrame);
VOID sampleBandwidthEstimationHandler(UINT64, DOUBLE);
VOID sampleSenderBandwidthEstimationHandler(UINT64, UINT32, UINT32, UINT32, UINT32, UINT64);
VOID onDataChannel(UINT64, PRtcDataChannel);
VOID onConnectionStateChange(UINT64, RTC_PEER_CONNECTION_STATE);
STATUS sessionCleanupWait(PSampleConfiguration);
STATUS logSignalingClientStats(PSignalingClientMetrics);
STATUS logSelectedIceCandidatesInformation(PSampleStreamingSession);
STATUS logStartUpLatency(PSampleConfiguration);
STATUS createMessageQueue(UINT64, PPendingMessageQueue*);
STATUS freeMessageQueue(PPendingMessageQueue);
STATUS submitPendingIceCandidate(PPendingMessageQueue, PSampleStreamingSession);
STATUS removeExpiredMessageQueues(PStackQueue);
STATUS getPendingMessageQueueForHash(PStackQueue, UINT64, BOOL, PPendingMessageQueue*);
BOOL sampleFilterNetworkInterfaces(UINT64, PCHAR);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_SAMPLE_INCLUDE__ */
