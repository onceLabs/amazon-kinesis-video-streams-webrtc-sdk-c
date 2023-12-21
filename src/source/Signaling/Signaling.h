/*******************************************
Signaling internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_SIGNALING_CLIENT__
#define __KINESIS_VIDEO_WEBRTC_SIGNALING_CLIENT__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/socket.h> //!< #TBD, for freertos message queue.
#include "kvs/webrtc_client.h"
#include "ChannelInfo.h"
#include "TimerQueue.h"

/**
 * Default connect sync API timeout
 */
#define SIGNALING_CONNECT_STATE_TIMEOUT (15 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// Request id header name
#define SIGNALING_REQUEST_ID_HEADER_NAME KVS_REQUEST_ID_HEADER_NAME ":"

// Signaling client from custom data conversion
#define SIGNALING_CLIENT_FROM_CUSTOM_DATA(h) ((PSignalingClient) (h))

// Grace period for refreshing the ICE configuration
#define ICE_CONFIGURATION_REFRESH_GRACE_PERIOD (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// Termination timeout
#define SIGNALING_CLIENT_SHUTDOWN_TIMEOUT ((2 + SIGNALING_SERVICE_API_CALL_TIMEOUT_IN_SECONDS) * HUNDREDS_OF_NANOS_IN_A_SECOND)

// Signaling client state literal definitions
#define SIGNALING_CLIENT_STATE_UNKNOWN_STR         "Unknown"
#define SIGNALING_CLIENT_STATE_NEW_STR             "New"
#define SIGNALING_CLIENT_STATE_GET_CREDENTIALS_STR "Get Security Credentials"
#define SIGNALING_CLIENT_STATE_DESCRIBE_STR        "Describe Channel"
#define SIGNALING_CLIENT_STATE_CREATE_STR          "Create Channel"
#define SIGNALING_CLIENT_STATE_GET_ENDPOINT_STR    "Get Channel Endpoint"
#define SIGNALING_CLIENT_STATE_GET_ICE_CONFIG_STR  "Get ICE Server Configuration"
#define SIGNALING_CLIENT_STATE_READY_STR           "Ready"
#define SIGNALING_CLIENT_STATE_CONNECTING_STR      "Connecting"
#define SIGNALING_CLIENT_STATE_CONNECTED_STR       "Connected"
#define SIGNALING_CLIENT_STATE_DISCONNECTED_STR    "Disconnected"
#define SIGNALING_CLIENT_STATE_DELETE_STR          "Delete"
#define SIGNALING_CLIENT_STATE_DELETED_STR         "Deleted"

// Error refreshing ICE server configuration string
#define SIGNALING_ICE_CONFIG_REFRESH_ERROR_MSG "Failed refreshing ICE server configuration with status code 0x%08x."

// Error reconnecting to the signaling service
#define SIGNALING_RECONNECT_ERROR_MSG "Failed to reconnect with status code 0x%08x."

// Max error string length
#define SIGNALING_MAX_ERROR_MESSAGE_LEN 512

// Async ICE config refresh delay in case if the signaling is not yet in READY state
#define SIGNALING_ASYNC_ICE_CONFIG_REFRESH_DELAY (50 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)

// API call latency calculation
#define SIGNALING_API_LATENCY_CALCULATION(pClient, time, isCpApi)                                                                                    \
    MUTEX_LOCK((pClient)->diagnosticsLock);                                                                                                          \
    if (isCpApi) {                                                                                                                                   \
        (pClient)->diagnostics.cpApiLatency =                                                                                                        \
            EMA_ACCUMULATOR_GET_NEXT((pClient)->diagnostics.cpApiLatency, GETTIME() - (time));                                                       \
    } else {                                                                                                                                         \
        (pClient)->diagnostics.dpApiLatency =                                                                                                        \
            EMA_ACCUMULATOR_GET_NEXT((pClient)->diagnostics.dpApiLatency, GETTIME() - (time));                                                       \
    }                                                                                                                                                \
    MUTEX_UNLOCK((pClient)->diagnosticsLock);

#define SIGNALING_UPDATE_ERROR_COUNT(pClient, status)                                                                                                \
    if ((pClient) != NULL && STATUS_FAILED(status)) {                                                                                                \
        ATOMIC_INCREMENT(&(pClient)->diagnostics.numberOfErrors);                                                                                    \
    }

#define SIGNALING_SDP_TYPE_OFFER       "SDP_OFFER"
#define SIGNALING_SDP_TYPE_ANSWER      "SDP_ANSWER"
#define SIGNALING_ICE_CANDIDATE        "ICE_CANDIDATE"
#define SIGNALING_GO_AWAY              "GO_AWAY"
#define SIGNALING_RECONNECT_ICE_SERVER "RECONNECT_ICE_SERVER"
#define SIGNALING_STATUS_RESPONSE      "STATUS_RESPONSE"
// Max length of the signaling message type string length
#define SIGNALING_MESSAGE_TYPE_MAX_LEN ARRAY_SIZE(SIGNALING_RECONNECT_ICE_SERVER)

// Check for the stale credentials
#define CHECK_SIGNALING_CREDENTIALS_EXPIRATION(p)                                                                                                    \
    do {                                                                                                                                             \
        if (GETTIME() >= (p)->pAwsCredentials->expiration) {                                                                                         \
            DLOGD("Credential is expired.");                                                                                                         \
            ATOMIC_STORE(&(p)->apiCallStatus, (SIZE_T) HTTP_STATUS_UNAUTHORIZED);                                                                    \
            CHK(FALSE, retStatus);                                                                                                                   \
        }                                                                                                                                            \
    } while (FALSE)

// Send message JSON template
#define WSS_MESSAGE_TEMPLATE                                                                                                                         \
    "{\n"                                                                                                                                            \
    "\t\"action\": \"%s\",\n"                                                                                                                        \
    "\t\"RecipientClientId\": \"%.*s\",\n"                                                                                                           \
    "\t\"MessagePayload\": \"%s\"\n"                                                                                                                 \
    "}"

// Send message JSON template with correlation id
#define WSS_MESSAGE_TEMPLATE_WITH_CORRELATION_ID                                                                                                     \
    "{\n"                                                                                                                                            \
    "\t\"action\": \"%s\",\n"                                                                                                                        \
    "\t\"RecipientClientId\": \"%.*s\",\n"                                                                                                           \
    "\t\"MessagePayload\": \"%s\",\n"                                                                                                                \
    "\t\"CorrelationId\": \"%.*s\"\n"                                                                                                                \
    "}"

/** #TBD, need to add the code of initialization. */
#define WSS_INBOUND_MSGQ_LENGTH 64

#define IS_CURRENT_TIME_CALLBACK_SET(pClient) ((pClient) != NULL && ((pClient)->signalingClientCallbacks.getCurrentTimeFn != NULL))

#define SIGNALING_GET_CURRENT_TIME(pClient)                                                                                                          \
    (IS_CURRENT_TIME_CALLBACK_SET((pClient))                                                                                                         \
         ? ((pClient)->signalingClientCallbacks.getCurrentTimeFn((pClient)->signalingClientCallbacks.customData))                                    \
         : GETTIME())

// Testability hooks functions
typedef STATUS (*SignalingApiCallHookFunc)(UINT64);
typedef STATUS (*DispatchMsgHandlerFunc)(PVOID pMessage);
/**
 * @brief Signaling channel description returned from the service
 */
typedef struct {
    UINT32 version; //!< Version of the SignalingChannelDescription struct
    // #http_api_rsp_describeChannel
    CHAR channelArn[MAX_ARN_LEN + 1]; //!< Channel Amazon Resource Name (ARN)
    // #http_api_rsp_createChannel
    // #http_api_rsp_describeChannel
    // #http_api_getChannelEndpoint
    // #http_api_getIceConfig
    CHAR channelName[MAX_CHANNEL_NAME_LEN + 1]; //!< Signaling channel name. Should be unique per AWS account
    //!< #describe_channel_rsp
    SIGNALING_CHANNEL_STATUS channelStatus; //!< Current channel status as reported by the service
    //!< #describe_channel_rsp
    SIGNALING_CHANNEL_TYPE channelType; //!< Channel type as reported by the service
    //!< #describe_channel_rsp
    CHAR updateVersion[MAX_UPDATE_VERSION_LEN + 1]; //!< A random number generated on every update while describing
                                                    //!< signaling channel
    //!< #describe_channel_rsp
    //!< #describe_channel_rsp
    UINT64 messageTtl; //!< The period of time a signaling channel retains underlived messages before they are discarded
                       //!< The values are in the range of 5 and 120 seconds
    //!< #describe_channel_rsp
    UINT64 creationTime; //!< Timestamp of when the channel gets created
    /**
     * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_ResourceEndpointListItem.html
     */
    // Signaling endpoint
    CHAR channelEndpointWss[MAX_SIGNALING_ENDPOINT_URI_LEN + 1];
    //!< http_api_rsp_getChannelEndpoint
    // Signaling endpoint
    CHAR channelEndpointHttps[MAX_SIGNALING_ENDPOINT_URI_LEN + 1];
    //!< http_api_rsp_getChannelEndpoint
    // #http_api_getIceConfig
    IceConfigInfo iceConfigs[MAX_ICE_CONFIG_COUNT];
} SignalingChannelDescription, *PSignalingChannelDescription;
/**
 * Internal client info object
 */
typedef struct {
    // Public client info structure
    SignalingClientInfo signalingClientInfo;

    //
    // Below members will be used for direct injection for tests hooks
    //
    // Injected connect timeout

    // Custom data to be passed to the hooks
    UINT64 hookCustomData;

    // API pre and post ingestion points
    SignalingApiCallHookFunc describePreHookFn;
    SignalingApiCallHookFunc describePostHookFn;
    SignalingApiCallHookFunc createPreHookFn;
    SignalingApiCallHookFunc createPostHookFn;
    SignalingApiCallHookFunc getEndpointPreHookFn;
    SignalingApiCallHookFunc getEndpointPostHookFn;
    SignalingApiCallHookFunc getIceConfigPreHookFn;
    SignalingApiCallHookFunc getIceConfigPostHookFn;
    SignalingApiCallHookFunc connectPreHookFn;
    SignalingApiCallHookFunc connectPostHookFn;
    SignalingApiCallHookFunc deletePreHookFn;
    SignalingApiCallHookFunc deletePostHookFn;
} SignalingClientInfoInternal, *PSignalingClientInfoInternal;

/**
 * Internal structure tracking various parameters for diagnostics and metrics/stats
 */
typedef struct {
    volatile SIZE_T numberOfMessagesSent;
    volatile SIZE_T numberOfMessagesReceived;
    volatile SIZE_T iceRefreshCount;
    volatile SIZE_T numberOfErrors;
    volatile SIZE_T numberOfRuntimeErrors;
    volatile SIZE_T numberOfReconnects;
    UINT64 createTime;
    UINT64 connectTime;
    UINT64 cpApiLatency;
    UINT64 dpApiLatency;
} SignalingDiagnostics, PSignalingDiagnostics;

typedef struct {
    // Tracking when was the Last time the APIs were called
    UINT64 describeTime; //!< the time of describing the channel.
    UINT64 createTime;
    UINT64 getEndpointTime;
    UINT64 getIceConfigTime;
    UINT64 deleteTime;
    UINT64 connectTime;
} ApiCallHistory, *PApiCallHistory;

/**
 * Internal representation of the Signaling client.
 */
typedef struct {

    // Current service call result
    volatile SIZE_T apiCallStatus;

    // Shutting down the entire client
    volatile ATOMIC_BOOL shutdown;

    // Wss is connected
    volatile ATOMIC_BOOL connected;

    // Having state machine logic rely on call result of HTTP_STATUS_SIGNALING_RECONNECT_ICE
    // to transition to ICE config state is not enough in Async update mode when
    // connect is in progress as the result of connect will override the result
    // of HTTP_STATUS_SIGNALING_RECONNECT_ICE indicating state transition
    // if it comes first forcing the state machine to loop back to connected state.
    volatile ATOMIC_BOOL refreshIceConfig;

    // Indicates that there is another thread attempting to grab the service lock
    volatile ATOMIC_BOOL shutdownWssDispatch;

    BOOL connecting; //!< Indicates whether to self-prime on Ready or not
    BOOL reconnect;  //!< Flag determines if reconnection should be attempted on connection drop

    UINT64 iceConfigTime;       //!< Indicates when the ICE configuration has been retrieved
    UINT64 iceConfigExpiration; //!< Indicates when the ICE configuration is considered expired

    // Current version of the structure
    UINT32 version;

    // Stored Client info
    SignalingClientInfoInternal clientInfo;

    // Stored callbacks
    SignalingClientCallbacks signalingClientCallbacks;

    // Channel info
    PChannelInfo pChannelInfo;

    // Returned signaling channel description
    SignalingChannelDescription channelDescription;

    // Number of Ice Server objects
    UINT32 iceConfigCount;

    // Returned Ice configurations
    IceConfigInfo iceConfigs[MAX_ICE_CONFIG_COUNT];

    // The state machine
    PVOID pStateMachine;

    // Interlocking the state transitions
    MUTEX nestedFsmLock;

	 // AWS credentials provider
    PAwsCredentialProvider pCredentialProvider;

    // Current AWS credentials
    PAwsCredentials pAwsCredentials;

    // List of the ongoing messages
    PStackQueue pMessageQueue;

    // Message queue lock
    MUTEX messageQueueLock;

    // Re-entrant lock for diagnostics/stats
    MUTEX diagnosticsLock;

    // Internal diagnostics object
    SignalingDiagnostics diagnostics;

    // Tracking when was the Last time the APIs were called
    ApiCallHistory apiCallHistory;
    MUTEX wssContextLock;
	// wss context to use
    PVOID pWssContext;
    DispatchMsgHandlerFunc pDispatchMsgHandler;
    TID dispatchMsgTid;
    QueueHandle_t inboundMsqQ; //!< the inbound message queue is used to store the messages from the wss connection.
} SignalingClient, *PSignalingClient;

typedef struct {
    // The first member is the public signaling message structure
    ReceivedSignalingMessage receivedSignalingMessage;

    // The messaging client object
    PSignalingClient pSignalingClient;
} SignalingMessageWrapper, *PSignalingMessageWrapper;

// Public handle to and from object converters
#define TO_SIGNALING_CLIENT_HANDLE(p)   ((SIGNALING_CLIENT_HANDLE) (p))
#define FROM_SIGNALING_CLIENT_HANDLE(h) (IS_VALID_SIGNALING_CLIENT_HANDLE(h) ? (PSignalingClient) (h) : NULL)

/******************************************************************************
 * FUNCTION PROTOTYPE
 ******************************************************************************/
/**
 * @brief get the corrsponding message type from the string.
 *
 * @param[in] typeStr the string.
 * @param[in] typeLen the leng of string.
 * @param[in] pMessageType the corresponding message type.
 *
 * @return STATUS status of execution.
 */
STATUS getMessageTypeFromString(PCHAR typeStr, UINT32 typeLen, SIGNALING_MESSAGE_TYPE* pMessageType);
 
/**
 * @brief create the context of signaling client and its fsm.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS createSignalingSync(PSignalingClientInfoInternal, PChannelInfo, PSignalingClientCallbacks, PAwsCredentialProvider, PSignalingClient*);

/**
 * @brief free the context of signaling client and its fsm.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS freeSignaling(PSignalingClient*);

/**
 * @brief send the message through the signaling channel when the signaling client is connected to the signaling channel.
 *
 *          https://docs.aws.amazon.com/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis3.html
 *          https://docs.aws.amazon.com/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis4.html
 *          https://docs.aws.amazon.com/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis5.html
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] pSignalingMessage the buffer of the signaling message.
 *
 * @return STATUS status of execution.
 */
STATUS signalingSendMessageSync(PSignalingClient, PSignalingMessage);

/**
 * @brief get the count of ice servers.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in, out] pIceConfigCount
 *
 * @return STATUS status of execution.
 */
STATUS signalingGetIceConfigInfoCount(PSignalingClient, PUINT32);

/**
 * @brief get the information of the ice server.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] index
 * @param[in, out] ppIceConfigInfo
 *
 * @return STATUS status of execution.
 */
STATUS signalingGetIceConfigInfo(PSignalingClient, UINT32, PIceConfigInfo*);

/**
 * @brief bring signaling client state to READY.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS signalingFetchSync(PSignalingClient);

/**
 * @brief connect signaling client with the specific signaling channel.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS signalingConnectSync(PSignalingClient);

/**
 * @brief disconnect signaling client from the specific signaling channel.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS signalingDisconnectSync(PSignalingClient);

/**
 * @brief
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return STATUS status of execution.
 */
STATUS signalingDeleteSync(PSignalingClient);

/**
 * @brief return the state of the signaling client.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 *
 * @return SIGNALING_CLIENT_STATE state of signaling.
 */
SIGNALING_CLIENT_STATE signalingGetCurrentState(PSignalingClient);

STATUS signalingRemoveOngoingMessage(PSignalingClient, PCHAR);
STATUS signalingGetOngoingMessage(PSignalingClient, PCHAR, PCHAR, PSignalingMessage*);

UINT64 signalingGetCurrentTime(UINT64);

/**
 * @brief describe the signaling channel.
 *
 * @param[in] PSignalingClient the context of the signaling client.
 * @param[in] UINT64 the current time.
 *
 * @return STATUS status of execution.
 */
STATUS describeChannel(PSignalingClient, UINT64);

/**
 * @brief create the signaling channel.
 *
 * @param[in] PSignalingClient the context of the signaling client.
 * @param[in] UINT64 the current time.
 *
 * @return STATUS status of execution.
 */
STATUS createChannel(PSignalingClient, UINT64);

/**
 * @brief get the end-point of the signaling channel.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] time the current time.
 *
 * @return STATUS status of execution.
 */
STATUS getChannelEndpoint(PSignalingClient, UINT64);

/**
 * @brief get the information of ice servers.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] time the current time.
 *
 * @return STATUS status of execution.
 */
STATUS getIceConfig(PSignalingClient, UINT64);

/**
 * @brief connect to the signaling channel.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in] time the current time.
 *
 * @return STATUS status of execution.
 */
STATUS connectSignalingChannel(PSignalingClient, UINT64);

/**
 * @brief delete the signaling channel. if signaling client is connected to the signaling channel, you need to terminate the connection first.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] time the current time.
 *
 * @return STATUS status of execution.
 */
STATUS deleteChannel(PSignalingClient, UINT64);

STATUS signalingGetMetrics(PSignalingClient, PSignalingClientMetrics);

STATUS validateIceConfiguration(PSignalingClient);
#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_SIGNALING_CLIENT__ */
