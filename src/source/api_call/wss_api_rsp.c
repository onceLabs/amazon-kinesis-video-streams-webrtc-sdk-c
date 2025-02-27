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
#define LOG_CLASS "WssApiRsp"
#include "wss_api.h"
#include "base64.h"

/******************************************************************************
 * DEFINITION
 ******************************************************************************/
#define WSS_RSP_ENTER() // DLOGD("enter")
#define WSS_RSP_EXIT()  // DLOGD("exit")

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS wss_api_rsp_receivedMessage(const CHAR* pMessage, UINT32 messageLen, PSignalingMessageWrapper pSignalingMessageWrapper)
{
    WSS_RSP_ENTER();
    STATUS retStatus = STATUS_SUCCESS;
    jsmn_parser parser;
    jsmntok_t* pTokens = NULL;
    UINT32 tokenCount;
    UINT32 i, strLen, outLen = MAX_SIGNALING_MESSAGE_LEN;
    BOOL parsedMessageType = FALSE, parsedStatusResponse = FALSE;

    CHK(NULL != (pTokens = (jsmntok_t*) MEMALLOC(MAX_JSON_TOKEN_COUNT * SIZEOF(jsmntok_t))), STATUS_NOT_ENOUGH_MEMORY);
    jsmn_init(&parser);
    tokenCount = jsmn_parse(&parser, pMessage, messageLen, pTokens, MAX_JSON_TOKEN_COUNT);
    CHK(tokenCount > 1, STATUS_JSON_API_CALL_INVALID_RETURN);
    CHK(pTokens[0].type == JSMN_OBJECT, STATUS_JSON_API_CALL_INVALID_RETURN);

    pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.version = SIGNALING_MESSAGE_CURRENT_VERSION;

    // Loop through the tokens and extract the stream description
    for (i = 1; i < tokenCount; i++) {
        if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "senderClientId")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= MAX_SIGNALING_CLIENT_ID_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);
            STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.peerClientId, pMessage + pTokens[i + 1].start, strLen);
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.peerClientId[MAX_SIGNALING_CLIENT_ID_LEN] = '\0';
            i++;
        } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "messageType")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= SIGNALING_MESSAGE_TYPE_MAX_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);
            CHK_STATUS(signaling_getMessageTypeFromString(pMessage + pTokens[i + 1].start, strLen,
                                                          &pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.messageType));

            parsedMessageType = TRUE;
            i++;
        } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "messagePayload")) {
            strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
            CHK(strLen <= MAX_SIGNALING_MESSAGE_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);

            // Base64 decode the message
            CHK_STATUS(base64Decode(pMessage + pTokens[i + 1].start, strLen,
                                    (PBYTE)(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload), &outLen));
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload[MAX_SIGNALING_MESSAGE_LEN] = '\0';
            pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payloadLen = outLen;
            // DLOGD("decoded payload:%s", pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.payload);
            i++;
        } else {
            if (!parsedStatusResponse) {
                if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "statusResponse")) {
                    parsedStatusResponse = TRUE;
                    i++;
                }
            } else {
                if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "correlationId")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_CORRELATION_ID_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.correlationId, pMessage + pTokens[i + 1].start,
                            strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.signalingMessage.correlationId[MAX_CORRELATION_ID_LEN] = '\0';

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "errorType")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_ERROR_TYPE_STRING_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.errorType, pMessage + pTokens[i + 1].start, strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.errorType[MAX_ERROR_TYPE_STRING_LEN] = '\0';

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "statusCode")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_STATUS_CODE_STRING_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);

                    // Parse the status code
                    CHK_STATUS(STRTOUI32(pMessage + pTokens[i + 1].start, pMessage + pTokens[i + 1].end, 10,
                                         (PUINT32) &pSignalingMessageWrapper->receivedSignalingMessage.statusCode));

                    i++;
                } else if (compareJsonString(pMessage, &pTokens[i], JSMN_STRING, (PCHAR) "description")) {
                    strLen = (UINT32)(pTokens[i + 1].end - pTokens[i + 1].start);
                    CHK(strLen <= MAX_MESSAGE_DESCRIPTION_LEN, STATUS_JSON_API_CALL_INVALID_RETURN);
                    STRNCPY(pSignalingMessageWrapper->receivedSignalingMessage.description, pMessage + pTokens[i + 1].start, strLen);
                    pSignalingMessageWrapper->receivedSignalingMessage.description[MAX_MESSAGE_DESCRIPTION_LEN] = '\0';

                    i++;
                }
            }
        }
    }
    // Message type is a mandatory field.
    CHK(parsedMessageType, STATUS_SIGNALING_INVALID_MESSAGE_TYPE);

CleanUp:
    SAFE_MEMFREE(pTokens);
    WSS_RSP_EXIT();
    return retStatus;
}
