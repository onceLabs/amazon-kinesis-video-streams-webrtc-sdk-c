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
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#define LOG_CLASS "SignalingFsm"
#include "StateMachine.h"
#include "state_machine.h"

/******************************************************************************
 * DEFINITION
 ******************************************************************************/
#define SIGNALING_STATE_NEW_REQUIRED (SIGNALING_STATE_NONE | SIGNALING_STATE_NEW)
#define SIGNALING_STATE_GET_TOKEN_REQUIRED                                                                                                           \
    (SIGNALING_STATE_NEW | SIGNALING_STATE_DESCRIBE | SIGNALING_STATE_DESCRIBE_MEDIA | SIGNALING_STATE_CREATE | SIGNALING_STATE_GET_ENDPOINT | SIGNALING_STATE_GET_ICE_CONFIG |       \
     SIGNALING_STATE_READY | SIGNALING_STATE_CONNECT | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_GET_TOKEN)
#define SIGNALING_STATE_DESCRIBE_REQUIRED                                                                                                            \
    (SIGNALING_STATE_GET_TOKEN | SIGNALING_STATE_CREATE | SIGNALING_STATE_GET_ENDPOINT | SIGNALING_STATE_GET_ICE_CONFIG | SIGNALING_STATE_CONNECT |  \
     SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION | SIGNALING_STATE_DESCRIBE | SIGNALING_STATE_READY |  \
   SIGNALING_STATE_DISCONNECTED)
#define SIGNALING_STATE_CREATE_REQUIRED (SIGNALING_STATE_DESCRIBE | SIGNALING_STATE_DESCRIBE_MEDIA | SIGNALING_STATE_CREATE)
#define SIGNALING_STATE_GET_ENDPOINT_REQUIRED                                                                                                        \
    (SIGNALING_STATE_DESCRIBE | SIGNALING_STATE_DESCRIBE_MEDIA | SIGNALING_STATE_CREATE | SIGNALING_STATE_GET_TOKEN | SIGNALING_STATE_READY | SIGNALING_STATE_CONNECT |               \
     SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION | SIGNALING_STATE_GET_ENDPOINT)
#define SIGNALING_STATE_GET_ICE_CONFIG_REQUIRED                                                                                                      \
    (SIGNALING_STATE_DESCRIBE | SIGNALING_STATE_DESCRIBE_MEDIA | SIGNALING_STATE_CONNECT | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION | SIGNALING_STATE_GET_ENDPOINT | SIGNALING_STATE_READY |         \
     SIGNALING_STATE_GET_ICE_CONFIG)
#define SIGNALING_STATE_READY_REQUIRED        (SIGNALING_STATE_GET_ICE_CONFIG | SIGNALING_STATE_DISCONNECTED | SIGNALING_STATE_READY)
#define SIGNALING_STATE_CONNECT_REQUIRED      (SIGNALING_STATE_READY | SIGNALING_STATE_DISCONNECTED | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION | SIGNALING_STATE_CONNECT)
#define SIGNALING_STATE_CONNECTED_REQUIRED    (SIGNALING_STATE_CONNECT | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION)
#define SIGNALING_STATE_DISCONNECTED_REQUIRED (SIGNALING_STATE_CONNECT | SIGNALING_STATE_CONNECTED | SIGNALING_STATE_JOIN_SESSION)

/******************************************************************************
 * INTERNAL FUNCTION PROTOTYPE
 ******************************************************************************/
STATUS fromNewSignalingState(UINT64, PUINT64);
STATUS executeNewSignalingState(UINT64, UINT64);
STATUS fromGetTokenSignalingState(UINT64, PUINT64);
STATUS executeGetTokenSignalingState(UINT64, UINT64);
STATUS fromDescribeSignalingState(UINT64, PUINT64);
STATUS executeDescribeSignalingState(UINT64, UINT64);
STATUS fromCreateSignalingState(UINT64, PUINT64);
STATUS executeCreateSignalingState(UINT64, UINT64);
STATUS fromGetEndpointSignalingState(UINT64, PUINT64);
STATUS executeGetEndpointSignalingState(UINT64, UINT64);
STATUS fromGetIceConfigSignalingState(UINT64, PUINT64);
STATUS executeGetIceConfigSignalingState(UINT64, UINT64);
STATUS fromReadySignalingState(UINT64, PUINT64);
STATUS executeReadySignalingState(UINT64 customData, UINT64 time);
STATUS fromConnectSignalingState(UINT64, PUINT64);
STATUS executeConnectSignalingState(UINT64, UINT64);
STATUS fromConnectedSignalingState(UINT64, PUINT64);
STATUS executeConnectedSignalingState(UINT64, UINT64);
STATUS fromDisconnectedSignalingState(UINT64, PUINT64);
STATUS executeDisconnectedSignalingState(UINT64, UINT64);
STATUS fromDescribeMediaStorageConfState(UINT64, PUINT64);
STATUS executeDescribeMediaStorageConfState(UINT64, UINT64);
STATUS fromJoinStorageSessionState(UINT64, PUINT64);
STATUS executeJoinStorageSessionState(UINT64, UINT64);
/**
 * Static definitions of the states
 */
static StateMachineState SIGNALING_STATE_MACHINE_STATES[] = {
    // http connection.
    {SIGNALING_STATE_NEW, SIGNALING_STATE_NEW_REQUIRED, fromNewSignalingState, executeNewSignalingState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_INVALID_READY_STATE},
    {SIGNALING_STATE_GET_TOKEN, SIGNALING_STATE_GET_TOKEN_REQUIRED, fromGetTokenSignalingState, executeGetTokenSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_GET_TOKEN_CALL_FAILED},
    {SIGNALING_STATE_DESCRIBE, SIGNALING_STATE_DESCRIBE_REQUIRED, fromDescribeSignalingState, executeDescribeSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_DESCRIBE_CALL_FAILED},
    {SIGNALING_STATE_CREATE, SIGNALING_STATE_CREATE_REQUIRED, fromCreateSignalingState, executeCreateSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_CREATE_CALL_FAILED},
    {SIGNALING_STATE_GET_ENDPOINT, SIGNALING_STATE_GET_ENDPOINT_REQUIRED, fromGetEndpointSignalingState, executeGetEndpointSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_GET_ENDPOINT_CALL_FAILED},
    {SIGNALING_STATE_GET_ICE_CONFIG, SIGNALING_STATE_GET_ICE_CONFIG_REQUIRED, fromGetIceConfigSignalingState, executeGetIceConfigSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_GET_ICE_CONFIG_CALL_FAILED},
    {SIGNALING_STATE_READY, SIGNALING_STATE_READY_REQUIRED, fromReadySignalingState, executeReadySignalingState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_READY_CALLBACK_FAILED},
    // websocket connection.
    {SIGNALING_STATE_CONNECT, SIGNALING_STATE_CONNECT_REQUIRED, fromConnectSignalingState, executeConnectSignalingState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_CONNECT_CALL_FAILED},
    {SIGNALING_STATE_CONNECTED, SIGNALING_STATE_CONNECTED_REQUIRED, fromConnectedSignalingState, executeConnectedSignalingState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_CONNECTED_CALLBACK_FAILED},
    {SIGNALING_STATE_DISCONNECTED, SIGNALING_STATE_DISCONNECTED_REQUIRED, fromDisconnectedSignalingState, executeDisconnectedSignalingState,
     SIGNALING_STATES_DEFAULT_RETRY_COUNT, STATUS_SIGNALING_DISCONNECTED_CALLBACK_FAILED},
    {SIGNALING_STATE_JOIN_SESSION, SIGNALING_STATE_CONNECTED, fromJoinStorageSessionState, executeJoinStorageSessionState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_CONNECTED_CALLBACK_FAILED},
    {SIGNALING_STATE_DESCRIBE_MEDIA, SIGNALING_STATE_DESCRIBE, fromDescribeMediaStorageConfState, executeDescribeMediaStorageConfState,
     INFINITE_RETRY_COUNT_SENTINEL, STATUS_SIGNALING_CONNECTED_CALLBACK_FAILED},
};

static UINT32 SIGNALING_STATE_MACHINE_STATE_COUNT = ARRAY_SIZE(SIGNALING_STATE_MACHINE_STATES);
/******************************************************************************
 * FUNCTION
 ******************************************************************************/
/******************************************************************************
 * State machine callback functions
 ******************************************************************************/
STATUS fromNewSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Transition to auth state
    state = SIGNALING_STATE_GET_TOKEN;
    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeNewSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);
    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_NEW) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief   change the fsm from get token to describe if we do not have channal arn.
 *          change the fsm from get token to get endpoint if we have channal arn.
 *          change the fsm from get token to delete if we are deleting the channel.
 */
STATUS fromGetTokenSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_GET_TOKEN;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // get the iot credential successfully.
    if ((HTTP_STATUS_CODE) ATOMIC_LOAD(&pSignalingClient->apiCallStatus) == HTTP_STATUS_OK) {
        // do we have the channel endpoint.
        if (pSignalingClient->pChannelInfo->pChannelArn != NULL && pSignalingClient->pChannelInfo->pChannelArn[0] != '\0') {
            // If the client application has specified the Channel ARN then we will skip describe and create states
            // Store the ARN in the stream description object first
            STRNCPY(pSignalingClient->channelDescription.channelArn, pSignalingClient->pChannelInfo->pChannelArn, MAX_ARN_LEN);
            pSignalingClient->channelDescription.channelArn[MAX_ARN_LEN] = '\0';

            // Move to get endpoint state if the media storage is not enabled.
            state = SIGNALING_STATE_GET_ENDPOINT;

            if (ATOMIC_LOAD_BOOL(&pSignalingClient->describeMediaStorageConf)) {
                if (pSignalingClient->pChannelInfo->pStorageStreamArn == NULL || pSignalingClient->pChannelInfo->pStorageStreamArn[0] == '\0') {
                    state = SIGNALING_STATE_DESCRIBE_MEDIA;
                } else {
                    STRNCPY(pSignalingClient->mediaStorageConfig.storageStreamArn, pSignalingClient->pChannelInfo->pStorageStreamArn, MAX_ARN_LEN);
                    pSignalingClient->mediaStorageConfig.storageStreamArn[MAX_ARN_LEN] = '\0';
                }
            }
        } else {
            state = SIGNALING_STATE_DESCRIBE;
        }
    }

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}
/**
 * @brief   get the aws crendential, and validate the credential. step the fsm.
 */
STATUS executeGetTokenSignalingState(UINT64 customData, UINT64 time)
{
    UNUSED_PARAM(time);
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    HTTP_STATUS_CODE serviceCallResult;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    ATOMIC_STORE(&pSignalingClient->apiCallStatus, (SIZE_T) HTTP_STATUS_NONE);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_GET_CREDENTIALS) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Use the credential provider to get the token
    retStatus = pSignalingClient->pCredentialProvider->getCredentialsFn(pSignalingClient->pCredentialProvider, &pSignalingClient->pAwsCredentials);

    // Check the expiration
    if (NULL == pSignalingClient->pAwsCredentials || GETTIME() >= pSignalingClient->pAwsCredentials->expiration) {
        serviceCallResult = HTTP_STATUS_UNAUTHORIZED;
    } else {
        serviceCallResult = HTTP_STATUS_OK;
    }

    ATOMIC_STORE(&pSignalingClient->apiCallStatus, (SIZE_T) serviceCallResult);

    // Self-prime the next state
    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromDescribeSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_DESCRIBE;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            // If we are trying to delete the channel then move to delete state
            if (ATOMIC_LOAD_BOOL(&pSignalingClient->describeMediaStorageConf)) {
                state = SIGNALING_STATE_DESCRIBE_MEDIA;
            } else {
                state = SIGNALING_STATE_GET_ENDPOINT;
            }
            break;

        case HTTP_STATUS_NOT_FOUND:
            state = SIGNALING_STATE_CREATE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeDescribeSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);
    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_DESCRIBE) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Call the aggregate function
    retStatus = describeChannel(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));
    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromDescribeMediaStorageConfState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_DESCRIBE;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        case HTTP_STATUS_NOT_FOUND:
            state = SIGNALING_STATE_CREATE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeDescribeMediaStorageConfState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_NULL_ARG);
    ATOMIC_STORE(&pSignalingClient->apiCallStatus, (SIZE_T) HTTP_STATUS_NONE);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK_STATUS(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                            SIGNALING_CLIENT_STATE_DESCRIBE_MEDIA));
    }

    // Call the aggregate function
    retStatus = describeMediaStorageConf(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromCreateSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_CREATE;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            state = SIGNALING_STATE_DESCRIBE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeCreateSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);
    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_CREATE) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Call the aggregate function
    retStatus = createChannel(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromGetEndpointSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_GET_ENDPOINT;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }
    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeGetEndpointSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);
    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_GET_ENDPOINT) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Call the aggregate function
    retStatus = getChannelEndpoint(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromGetIceConfigSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_GET_ICE_CONFIG;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            state = SIGNALING_STATE_READY;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeGetIceConfigSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);
    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_GET_ICE_CONFIG) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Call the aggregate function
    retStatus = getIceConfig(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromReadySignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_READY;

    SIZE_T result;
    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            state = SIGNALING_STATE_CONNECT;
            break;

        case HTTP_STATUS_SIGNALING_RECONNECT_ICE:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            break;
    }

    // Overwrite the state if we are force refreshing
    state = ATOMIC_EXCHANGE_BOOL(&pSignalingClient->refreshIceConfig, FALSE) ? SIGNALING_STATE_GET_ICE_CONFIG : state;

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeReadySignalingState(UINT64 customData, UINT64 time)
{
    UNUSED_PARAM(time);
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_READY) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Ensure we won't async the GetIceConfig as we reach the ready state
    if (pSignalingClient->connecting) {
        // Self-prime the connect
        CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));
    } else {
        // Reset the timeout for the state machine
        pSignalingClient->stepUntil = 0;
    }

    // Reset the ret status
    retStatus = STATUS_SUCCESS;
CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromConnectSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_CONNECT;
    SIZE_T result;
    BOOL connected;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    connected = ATOMIC_LOAD_BOOL(&pSignalingClient->connected);
    switch (result) {
        case HTTP_STATUS_OK:
            // We also need to check whether we terminated OK and connected or
            // simply terminated without being connected
            if (connected) {
                state = SIGNALING_STATE_CONNECTED;
            }

            break;

        case HTTP_STATUS_NOT_FOUND:
            state = SIGNALING_STATE_DESCRIBE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        case HTTP_STATUS_INTERNAL_SERVER_ERROR:
        case HTTP_STATUS_BAD_REQUEST:
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        case HTTP_STATUS_SIGNALING_RECONNECT_ICE:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;

        case HTTP_STATUS_NETWORK_CONNECTION_TIMEOUT:
        case HTTP_STATUS_NETWORK_READ_TIMEOUT:
        case HTTP_STATUS_REQUEST_TIMEOUT:
        case HTTP_STATUS_GATEWAY_TIMEOUT:
            // Attempt to get a new endpoint
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        default:
            state = SIGNALING_STATE_GET_TOKEN;
            break;
    }

    // Overwrite the state if we are force refreshing
    state = ATOMIC_EXCHANGE_BOOL(&pSignalingClient->refreshIceConfig, FALSE) ? SIGNALING_STATE_GET_ICE_CONFIG : state;

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeConnectSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_CONNECTING) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    retStatus = connectSignalingChannel(pSignalingClient, time);

    CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));

    // Reset the ret status
    retStatus = STATUS_SUCCESS;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromConnectedSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_CONNECTED;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_OK:
            if (!ATOMIC_LOAD_BOOL(&pSignalingClient->connected)) {
                state = SIGNALING_STATE_DISCONNECTED;
            } else if (ATOMIC_LOAD_BOOL(&pSignalingClient->joinSession)) {
                state = SIGNALING_STATE_JOIN_SESSION;
            }
            break;

        case HTTP_STATUS_NOT_FOUND:
        case HTTP_STATUS_SIGNALING_GO_AWAY:
            state = SIGNALING_STATE_DESCRIBE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        case HTTP_STATUS_INTERNAL_SERVER_ERROR:
        case HTTP_STATUS_BAD_REQUEST:
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        case HTTP_STATUS_SIGNALING_RECONNECT_ICE:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;

        default:
            state = SIGNALING_STATE_GET_TOKEN;
            break;
    }

    // Overwrite the state if we are force refreshing
    state = ATOMIC_EXCHANGE_BOOL(&pSignalingClient->refreshIceConfig, FALSE) ? SIGNALING_STATE_GET_ICE_CONFIG : state;
    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeConnectedSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_CONNECTED) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Reset the timeout for the state machine
    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    pSignalingClient->stepUntil = 0;
    MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromJoinStorageSessionState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_CONNECT;
    SIZE_T result;
    BOOL connected;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_NULL_ARG);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);

    switch (result) {
        case HTTP_STATUS_OK:
            if (!ATOMIC_LOAD_BOOL(&pSignalingClient->connected)) {
                state = SIGNALING_STATE_DISCONNECTED;
            } else if (!ATOMIC_LOAD_BOOL(&pSignalingClient->joinSession)) {
                state = SIGNALING_STATE_CONNECTED;
            }
            break;

        case HTTP_STATUS_NOT_FOUND:
            state = SIGNALING_STATE_DESCRIBE;
            break;

        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        case HTTP_STATUS_INTERNAL_SERVER_ERROR:
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        case HTTP_STATUS_BAD_REQUEST:
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        case HTTP_STATUS_SIGNALING_RECONNECT_ICE:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;

        case HTTP_STATUS_NETWORK_CONNECTION_TIMEOUT:
        case HTTP_STATUS_NETWORK_READ_TIMEOUT:
        case HTTP_STATUS_REQUEST_TIMEOUT:
        case HTTP_STATUS_GATEWAY_TIMEOUT:
            // Attempt to get a new endpoint
            state = SIGNALING_STATE_GET_ENDPOINT;
            break;

        default:
            DLOGW("unknown response code(%d).", result);
            state = SIGNALING_STATE_GET_TOKEN;
            break;
    }

    // Overwrite the state if we are force refreshing
    state = ATOMIC_EXCHANGE_BOOL(&pSignalingClient->refreshIceConfig, FALSE) ? SIGNALING_STATE_GET_ICE_CONFIG : state;

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeJoinStorageSessionState(UINT64 customData, UINT64 time)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_JOIN_SESSION) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    retStatus = joinStorageSession(pSignalingClient, time);

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS fromDisconnectedSignalingState(UINT64 customData, PUINT64 pState)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);
    UINT64 state = SIGNALING_STATE_DISCONNECTED;
    SIZE_T result;

    CHK(pSignalingClient != NULL && pState != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // See if we need to retry first of all
    CHK(pSignalingClient->reconnect, STATUS_SUCCESS);

    result = ATOMIC_LOAD(&pSignalingClient->apiCallStatus);
    switch (result) {
        case HTTP_STATUS_FORBIDDEN:
        case HTTP_STATUS_UNAUTHORIZED:
            state = SIGNALING_STATE_GET_TOKEN;
            break;

        default:
            state = SIGNALING_STATE_GET_ICE_CONFIG;
            break;
    }

    // Overwrite the state if we are force refreshing
    state = ATOMIC_EXCHANGE_BOOL(&pSignalingClient->refreshIceConfig, FALSE) ? SIGNALING_STATE_GET_ICE_CONFIG : state;

    *pState = state;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS executeDisconnectedSignalingState(UINT64 customData, UINT64 time)
{
    ENTERS();
    UNUSED_PARAM(time);
    STATUS retStatus = STATUS_SUCCESS;
    PSignalingClient pSignalingClient = SIGNALING_CLIENT_FROM_CUSTOM_DATA(customData);

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Notify of the state change
    if (pSignalingClient->signalingClientCallbacks.stateChangeFn != NULL) {
        CHK(pSignalingClient->signalingClientCallbacks.stateChangeFn(pSignalingClient->signalingClientCallbacks.customData,
                                                                     SIGNALING_CLIENT_STATE_DISCONNECTED) == STATUS_SUCCESS,
            STATUS_SIGNALING_FSM_STATE_CHANGE_FAILED);
    }

    // Self-prime the next state
    if (pSignalingClient->reconnect == TRUE) {
        CHK_STATUS(signaling_fsm_step(pSignalingClient, retStatus));
    }

CleanUp:

    LEAVES();
    return retStatus;
}

UINT64 signaling_fsm_getCurrentTime(UINT64 customData)
{
    UNUSED_PARAM(customData);
    return GETTIME();
}

STATUS signaling_fsm_create(PSignalingClient pSignalingClient, PSignalingFsmHandle pSignalingFsmHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStateMachine pStateMachine = NULL;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    CHK_STATUS(createStateMachine(SIGNALING_STATE_MACHINE_STATES, SIGNALING_STATE_MACHINE_STATE_COUNT, pSignalingClient,
                                    signaling_fsm_getCurrentTime, pSignalingClient, &pStateMachine));

CleanUp:
    *pSignalingFsmHandle = pStateMachine;
    LEAVES();
    return retStatus;
}

STATUS signaling_fsm_free(SignalingFsmHandle signalingFsmHandle)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    freeStateMachine(signalingFsmHandle);

    LEAVES();
    return retStatus;
}

STATUS signaling_fsm_step(PSignalingClient pSignalingClient, STATUS status)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    BOOL locked = FALSE;
    UINT64 currentTime;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    // Check for a shutdown
    CHK(!ATOMIC_LOAD_BOOL(&pSignalingClient->shutdown), retStatus);

    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    locked = TRUE;

    // Check if an error and the retry is OK
    if (!pSignalingClient->pChannelInfo->retry && STATUS_FAILED(status)) {
        CHK(FALSE, status);
    }

    currentTime = GETTIME();

    CHK(pSignalingClient->stepUntil == 0 || currentTime <= pSignalingClient->stepUntil, STATUS_SIGNALING_FSM_TIMEOUT);

    // Check if the status is any of the retry/failed statuses
    if (STATUS_FAILED(status)) {
        for (i = 0; i < SIGNALING_STATE_MACHINE_STATE_COUNT; i++) {
            CHK(status != SIGNALING_STATE_MACHINE_STATES[i].status, SIGNALING_STATE_MACHINE_STATES[i].status);
        }
    }
    //#TBD.
    // Fix-up the expired credentials transition
    // NOTE: Api Gateway might not return an error that can be interpreted as unauthorized to
    // make the correct transition to auth integration state.

    if (pSignalingClient->pAwsCredentials != NULL && pSignalingClient->pAwsCredentials->expiration < currentTime) {
        // Set the call status as auth error
        ATOMIC_STORE(&pSignalingClient->apiCallStatus, (SIZE_T) HTTP_STATUS_UNAUTHORIZED);
    }

    // Step the state machine
    CHK_STATUS(stepStateMachine(pSignalingClient->signalingFsmHandle));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);
    }

    LEAVES();
    return retStatus;
}

STATUS signaling_fsm_resetRetryCount(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    locked = TRUE;

    resetStateMachineRetryCount(pSignalingClient->signalingFsmHandle);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);
    }
    LEAVES();
    return retStatus;
}

STATUS signaling_fsm_setCurrentState(PSignalingClient pSignalingClient, UINT64 state)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    locked = TRUE;

    setStateMachineCurrentState(pSignalingClient->signalingFsmHandle, state);

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);
    }
    LEAVES();
    return retStatus;
}

UINT64 signaling_fsm_getCurrentState(PSignalingClient pSignalingClient)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PStateMachineState pStateMachineState = NULL;
    UINT64 state = SIGNALING_STATE_NONE;
    BOOL locked = FALSE;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    locked = TRUE;

    CHK_STATUS(getStateMachineCurrentState(pSignalingClient->signalingFsmHandle, &pStateMachineState));
    state = pStateMachineState->state;

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);
    }
    LEAVES();
    return state;
}

STATUS signaling_fsm_accept(PSignalingClient pSignalingClient, UINT64 requiredStates)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pSignalingClient != NULL, STATUS_SIGNALING_FSM_NULL_ARG);

    MUTEX_LOCK(pSignalingClient->nestedFsmLock);
    locked = TRUE;

    // Step the state machine
    CHK_STATUS(acceptStateMachineState(pSignalingClient->signalingFsmHandle, requiredStates));

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pSignalingClient->nestedFsmLock);
    }
    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}
