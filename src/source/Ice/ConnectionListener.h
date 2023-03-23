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
#ifndef __KINESIS_VIDEO_WEBRTC_CONNECTION_LISTENER__
#define __KINESIS_VIDEO_WEBRTC_CONNECTION_LISTENER__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "kvs/error.h"
#include "SocketConnection.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
#define CONNECTION_LISTENER_SOCKET_WAIT_FOR_DATA_TIMEOUT     (200 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
#define CONNECTION_LISTENER_SHUTDOWN_TIMEOUT                 (1000 * HUNDREDS_OF_NANOS_IN_A_MILLISECOND)
#define CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION 64

typedef struct {
    volatile ATOMIC_BOOL terminate;
    PSocketConnection sockets[CONNECTION_LISTENER_DEFAULT_MAX_LISTENING_CONNECTION];
    UINT64 socketCount;
    MUTEX lock;
    TID receiveDataRoutine;
    PBYTE pBuffer;
    UINT64 bufferLen;
} ConnectionListener, *PConnectionListener;

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
/**
 * allocate the ConnectionListener struct
 *
 * @param - PConnectionListener* - IN/OUT - pointer to PConnectionListener being allocated
 *
 * @return - STATUS status of execution
 */
STATUS createConnectionListener(PConnectionListener*);

/**
 * free the ConnectionListener struct and all its resources
 *
 * @param - PConnectionListener* - IN/OUT - pointer to PConnectionListener being freed
 *
 * @return - STATUS status of execution
 */
STATUS freeConnectionListener(PConnectionListener*);

/**
 * add a new PSocketConnection to listen for incoming data
 *
 * @param - PConnectionListener      - IN - the ConnectionListener struct to use
 * @param - PSocketConnection   - IN - new PSocketConnection to listen for incoming data
 *
 * @return - STATUS status of execution
 */
STATUS connectionListenerAddConnection(PConnectionListener, PSocketConnection);

/**
 * remove PSocketConnection from the list to listen for incoming data
 *
 * @param - PConnectionListener      - IN - the ConnectionListener struct to use
 * @param - PSocketConnection   - IN - PSocketConnection to be removed
 *
 * @return - STATUS status of execution
 */
STATUS connectionListenerRemoveConnection(PConnectionListener, PSocketConnection);

/**
 * remove all listening PSocketConnection
 *
 * @param - PConnectionListener      - IN - the ConnectionListener struct to use
 *
 * @return - STATUS status of execution
 */
STATUS connectionListenerRemoveAllConnection(PConnectionListener);

/**
 * Spin off a listener thread that listen for incoming traffic for all PSocketConnection stored in connectionList.
 * Whenever a PSocketConnection receives data, invoke ConnectionDataAvailableFunc passed in.
 *
 * @param - PConnectionListener      - IN - the ConnectionListener struct to use
 *
 * @return - STATUS status of execution
 */
STATUS connectionListenerStart(PConnectionListener);
/**
 * @brief
 *
 * @param[in] pConnectionListener the ConnectionListener struct to use
 *
 * @return STATUS status of execution
 */
PVOID connectionListenerReceiveDataRoutine(PVOID pArg);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CONNECTION_LISTENER__ */
