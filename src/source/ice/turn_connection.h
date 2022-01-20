/*
 * Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "stun.h"
#include "network.h"
#include "timer_queue.h"
#include "socket_connection.h"
#include "connection_listener.h"
#include "ice_utils.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
#define TURN_REQUEST_TRANSPORT_UDP               17
#define TURN_REQUEST_TRANSPORT_TCP               6
#define DEFAULT_TURN_ALLOCATION_LIFETIME_SECONDS 600
// required by rfc5766 to be 300s
// The Permission Lifetime MUST be 300 seconds (= 5 minutes).
// https://tools.ietf.org/html/rfc5766#section-8
#define TURN_PERMISSION_LIFETIME                 (300 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_TIMER_INTERVAL_BEFORE_READY (50 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND) //!< 150ms
#define DEFAULT_TURN_TIMER_INTERVAL_AFTER_READY  (1 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_SEND_REFRESH_INVERVAL       (1 * HUNDREDS_OF_NANOS_IN_A_SECOND)

// turn state timeouts
#define DEFAULT_TURN_SOCKET_CONNECT_TIMEOUT    (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_GET_CREDENTIAL_TIMEOUT    (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_ALLOCATION_TIMEOUT        (5 * HUNDREDS_OF_NANOS_IN_A_SECOND)  //!< 5 sec
#define DEFAULT_TURN_CREATE_PERMISSION_TIMEOUT (2 * HUNDREDS_OF_NANOS_IN_A_SECOND)  //!< 2 sec
#define DEFAULT_TURN_BIND_CHANNEL_TIMEOUT      (3 * HUNDREDS_OF_NANOS_IN_A_SECOND)  //!< 3 sec
#define DEFAULT_TURN_CLEAN_UP_TIMEOUT          (10 * HUNDREDS_OF_NANOS_IN_A_SECOND) //!< 10 sec

// #TBD, It is suggested that the client refresh the allocation roughly 1 minute before it expires.
// https://tools.ietf.org/html/rfc5766#section-7
#define DEFAULT_TURN_ALLOCATION_REFRESH_GRACE_PERIOD (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)
#define DEFAULT_TURN_PERMISSION_REFRESH_GRACE_PERIOD (30 * HUNDREDS_OF_NANOS_IN_A_SECOND)

#define MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE                4 + 65536 /* header + data */
#define DEFAULT_TURN_MESSAGE_SEND_CHANNEL_DATA_BUFFER_LEN MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE
#define DEFAULT_TURN_MESSAGE_RECV_CHANNEL_DATA_BUFFER_LEN MAX_TURN_CHANNEL_DATA_MESSAGE_SIZE
#define DEFAULT_TURN_CHANNEL_DATA_BUFFER_SIZE             512
#define DEFAULT_TURN_MAX_PEER_COUNT                       32 //!<

// all turn channel numbers must be greater than 0x4000 and less than 0x7FFF
// 0x0000 through 0x3FFF: These values can never be used for channel numbers.
// 0x4000 through 0x7FFF: These values are the allowed channel numbers (16,383 possible values).
// 0x8000 through 0xFFFF: These values are reserved for future use.
// https://tools.ietf.org/html/rfc5766#section-11
#define TURN_CHANNEL_BIND_CHANNEL_NUMBER_BASE (UINT16) 0x4000

// 2 byte channel number 2 data byte size
#define TURN_DATA_CHANNEL_SEND_OVERHEAD  4
#define TURN_DATA_CHANNEL_MSG_FIRST_BYTE 0x40

#define TURN_STATE_NEW_STR                     (PCHAR) "TURN_STATE_NEW"
#define TURN_STATE_CHECK_SOCKET_CONNECTION_STR (PCHAR) "TURN_STATE_CHECK_SOCKET_CONNECTION"
#define TURN_STATE_GET_CREDENTIALS_STR         (PCHAR) "TURN_STATE_GET_CREDENTIALS"
#define TURN_STATE_ALLOCATION_STR              (PCHAR) "TURN_STATE_ALLOCATION"
#define TURN_STATE_CREATE_PERMISSION_STR       (PCHAR) "TURN_STATE_CREATE_PERMISSION"
#define TURN_STATE_BIND_CHANNEL_STR            (PCHAR) "TURN_STATE_BIND_CHANNEL"
#define TURN_STATE_READY_STR                   (PCHAR) "TURN_STATE_READY"
#define TURN_STATE_CLEAN_UP_STR                (PCHAR) "TURN_STATE_CLEAN_UP"
#define TURN_STATE_FAILED_STR                  (PCHAR) "TURN_STATE_FAILED"
#define TURN_STATE_UNKNOWN_STR                 (PCHAR) "TURN_STATE_UNKNOWN"

typedef STATUS (*RelayAddressAvailableFunc)(UINT64, PKvsIpAddress, PSocketConnection);
/**
 * @brief   the state of local turn connection.
 */
typedef enum {
    TURN_STATE_NEW,
    TURN_STATE_CHECK_SOCKET_CONNECTION,
    TURN_STATE_GET_CREDENTIALS,
    TURN_STATE_ALLOCATION, //!< https://tools.ietf.org/html/rfc5766#section-5
    TURN_STATE_CREATE_PERMISSION,
    TURN_STATE_BIND_CHANNEL,
    TURN_STATE_READY,
    TURN_STATE_CLEAN_UP,
    TURN_STATE_FAILED,
} TURN_CONNECTION_STATE;

/**
 * @brief   the state of remote candidates.
 */
typedef enum {
    TURN_PEER_CONN_STATE_CREATE_PERMISSION,
    TURN_PEER_CONN_STATE_BIND_CHANNEL,
    TURN_PEER_CONN_STATE_READY,
    TURN_PEER_CONN_STATE_FAILED,
} TURN_PEER_CONNECTION_STATE;

typedef enum {
    TURN_CONNECTION_DATA_TRANSFER_MODE_SEND_INDIDATION, //!< https://tools.ietf.org/html/rfc5766#section-2.4
    TURN_CONNECTION_DATA_TRANSFER_MODE_DATA_CHANNEL,    //!< https://tools.ietf.org/html/rfc5766#section-2.5
} TURN_CONNECTION_DATA_TRANSFER_MODE;
// 4+4+24=32
typedef struct {
    PBYTE data;  //!< the pointer of the buffer.
    UINT32 size; //!<
    KvsIpAddress senderAddr;
} TurnChannelData, *PTurnChannelData;

typedef struct {
    UINT64 customData;
    RelayAddressAvailableFunc relayAddressAvailableFn;
} TurnConnectionCallbacks, *PTurnConnectionCallbacks;

typedef struct {
    KvsIpAddress address;
    KvsIpAddress xorAddress;
    /*
     * Steps to create a turn channel for a peer:
     *     - create permission
     *     - channel bind
     *     - ready to send data
     */
    TURN_PEER_CONNECTION_STATE connectionState;
    PTransactionIdStore pTransactionIdStore;
    UINT16 channelNumber;
    UINT64 permissionExpirationTime;
    BOOL ready;
} TurnPeer, *PTurnPeer;

typedef struct __TurnConnection TurnConnection;
struct __TurnConnection {
    volatile ATOMIC_BOOL stopTurnConnection;
    /* shutdown is complete when turn socket is closed */
    volatile ATOMIC_BOOL shutdownComplete;
    volatile ATOMIC_BOOL hasAllocation; //!< get the allocation response of turn connection. It means we have the turn relay address.
    volatile SIZE_T timerCallbackId;

    // realm attribute in Allocation response
    CHAR turnRealm[STUN_MAX_REALM_LEN + 1];
    BYTE turnNonce[STUN_MAX_NONCE_LEN];
    UINT16 nonceLen;
    BYTE longTermKey[KVS_MD5_DIGEST_LENGTH];
    BOOL credentialObtained;   //!< get the nonce and realm from 401 response. true: got the information.
    BOOL relayAddressReported; //!< get the xor relay address.

    PSocketConnection pControlChannel; //!< the socket hanlder of this turn connection.

    TurnPeer turnPeerList[DEFAULT_TURN_MAX_PEER_COUNT]; //!< #TBD, need to review this. it should be reduced.
    UINT32 turnPeerCount;                               //!< the number of remote candidates for this turn connection.

    TIMER_QUEUE_HANDLE timerQueueHandle;

    IceServer turnServer;

    MUTEX lock; //!< the lock of this context.
    MUTEX sendLock;
    CVAR freeAllocationCvar;

    TURN_CONNECTION_STATE state; //!< the state of turn fsm.

    UINT64 stateTimeoutTime;

    STATUS errorStatus;
    // #TBD, need to review this is necessary or not, since turn does not send this packet frequently.
    PStunPacket pTurnPacket;
    PStunPacket pTurnCreatePermissionPacket;  //!< the packet of turn create-permission.
    PStunPacket pTurnChannelBindPacket;       //!< the packet of turn bind-channel.
    PStunPacket pTurnAllocationRefreshPacket; //!< the packet of refresh-allocation.

    KvsIpAddress hostAddress; //!< the host address, but it seems to be null now. #TBD, need to check the spec.

    KvsIpAddress relayAddress;

    PConnectionListener pConnectionListener;

    TURN_CONNECTION_DATA_TRANSFER_MODE dataTransferMode;
    KVS_SOCKET_PROTOCOL protocol;

    TurnConnectionCallbacks turnConnectionCallbacks;

    PBYTE sendDataBuffer;
    UINT32 dataBufferSize;

    PBYTE recvDataBuffer;      //!<
    UINT32 recvDataBufferSize; //!<
    UINT32 currRecvDataLen;
    // when a complete channel data have been assembled in recvDataBuffer, move it to completeChannelDataBuffer
    // to make room for subsequent partial channel data.
    PBYTE completeChannelDataBuffer;

    UINT64 allocationExpirationTime; //!< the expiration time of this turn allocation. unit: nano.
    UINT64 nextAllocationRefreshTime;

    UINT64 currentTimerCallingPeriod;
    BOOL deallocatePacketSent;
};
typedef struct __TurnConnection* PTurnConnection;

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
/**
 * @brief create the context of the turn connection.
 *
 * @param[in] pTurnServer
 * @param[in] timerQueueHandle
 * @param[in] dataTransferMode unused.
 * @param[in] protocol
 * @param[in] pTurnConnectionCallbacks
 * @param[in] pTurnSocket
 * @param[in] pConnectionListener
 * @param[in, out] ppTurnConnection
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_create(PIceServer pTurnServer, TIMER_QUEUE_HANDLE timerQueueHandle, TURN_CONNECTION_DATA_TRANSFER_MODE dataTransferMode,
                              KVS_SOCKET_PROTOCOL protocol, PTurnConnectionCallbacks pTurnConnectionCallbacks, PSocketConnection pTurnSocket,
                              PConnectionListener pConnectionListener, PTurnConnection* ppTurnConnection);
/**
 * @brief free the context of the turn connection.
 *
 * @param[in, out] ppTurnConnection
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_free(PTurnConnection* ppTurnConnection);
/**
 * @brief add remote peer to the turn connection.
 *
 * @param[in] pTurnConnection the context of the turn connection.
 * @param[in] pPeerAddress the ip address of remote peer.
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_addPeer(PTurnConnection pTurnConnection, PKvsIpAddress pPeerAddress);
/**
 * @brief add remote peer to the turn connection.
 *
 * @param[in] pTurnConnection the context of the turn connection.
 * @param[in] pBuf
 * @param[in] bufLen
 * @param[in] pDestIp
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_send(PTurnConnection pTurnConnection, PBYTE pBuf, UINT32 bufLen, PKvsIpAddress pDestIp);
/**
 * @brief start the turn connection.
 *
 * @param[in] pTurnConnection the context of the turn connection.
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_start(PTurnConnection pTurnConnection);
STATUS turn_connection_shutdown(PTurnConnection, UINT64);
BOOL turn_connection_isShutdownCompleted(PTurnConnection);
BOOL turn_connection_getRelayAddress(PTurnConnection, PKvsIpAddress);
/**
 * @brief advance the fsm of the turn connection.
 *
 * @param[in] pTurnConnection the context of the turn connection.
 *
 * @return STATUS status of execution.
 */
STATUS turn_connection_fsm_step(PTurnConnection pTurnConnection);
/**
 * @brief parse the data from the socket connection, and split them into stun packets, and turn packets.
 *
 * @param[in] pTurnConnection the context of the turn connection.
 * @param[in] pBuffer the pointer of data from socket connection.
 * @param[in] bufferLen the lengthe of pBuffer
 * @param[in] pSrc
 * @param[in] pDest
 * @param[in, out] channelDataList
 * @param[in, out] pChannelDataCount
 *
 * @return STATUS status of execution
 */
STATUS turn_connection_handleInboundData(PTurnConnection pTurnConnection, PBYTE pBuffer, UINT32 bufferLen, PKvsIpAddress pSrc, PKvsIpAddress pDest,
                                         PTurnChannelData channelDataList, PUINT32 pChannelDataCount);
#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_TURN_CONNECTION__ */
