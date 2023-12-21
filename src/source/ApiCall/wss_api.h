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
#ifndef __AWS_KVS_WEBRTC_WSS_API_INCLUDE__
#define __AWS_KVS_WEBRTC_WSS_API_INCLUDE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "kvs/error.h"
#include "kvs/common_defs.h"
#include "Signaling.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
/**
 * @brief connect to the wss server.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in, out] pHttpStatusCode the http status code of wss connection.
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_connect(PSignalingClient pSignalingClient, PUINT32 pHttpStatusCode);
/**
 * @brief the callback to handle received data messages.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in] pMessage the buffer of the message.
 * @param[in] messageLen the length of the message.
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_handleDataMsg(PVOID pUserData, PCHAR pMessage, UINT32 messageLen);
/**
 * @brief the callback to handle received ctrl messages.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in] pMessage the buffer of the message.
 * @param[in] messageLen the length of the message.
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_handleCtrlMsg(PVOID pUserData, UINT8 opcode, PCHAR pMessage, UINT32 messageLen);
/**
 * @brief send the data buffer out.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in] pSendBuf
 * @param[in] bufLen
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_send(PSignalingClient pSignalingClient, PBYTE pSendBuf, UINT32 bufLen);
/**
 * @brief terminate the websocket connection but will set the result of signaling client for the next step.
 *
 * @param[in] pSignalingClient the context of signaling client.
 * @param[in] callResult
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_disconnect(PSignalingClient pSignalingClient);

/**
 * @brief https://docs.aws.amazon.com/kinesisvideostreams-webrtc-dg/latest/devguide/kvswebrtc-websocket-apis-7.html
 *
 * @param[in] pResponseStr the context of signaling client.
 * @param[in] resultLen
 * @param[in] pSignalingMessageWrapper
 *
 * @return STATUS status of execution.
 */
STATUS wss_api_rsp_receivedMessage(const CHAR* pResponseStr, UINT32 resultLen, PSignalingMessageWrapper pSignalingMessageWrapper);

#ifdef __cplusplus
}
#endif
#endif /* __AWS_KVS_WEBRTC_WSS_API_INCLUDE__ */