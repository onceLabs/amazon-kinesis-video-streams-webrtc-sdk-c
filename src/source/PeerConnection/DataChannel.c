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
#ifdef ENABLE_DATA_CHANNEL

#define LOG_CLASS "DataChannel"
#include "../Include_i.h"
#include "PeerConnection.h"
#include "Sctp.h"
#include "DataChannel.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS createDataChannel(PRtcPeerConnection pPeerConnection, PCHAR pDataChannelName, PRtcDataChannelInit pRtcDataChannelInit,
                         PRtcDataChannel* ppRtcDataChannel)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsPeerConnection pKvsPeerConnection = (PKvsPeerConnection) pPeerConnection;
    UINT32 channelId = 0;
    PKvsDataChannel pKvsDataChannel = NULL;

    CHK(pKvsPeerConnection != NULL && pDataChannelName != NULL && ppRtcDataChannel != NULL, STATUS_NULL_ARG);

    // Only support creating DataChannels before signaling for now
    CHK(pKvsPeerConnection->pSctpSession == NULL, STATUS_PEER_CONN_NO_SCTP_SESSION);
    CHK((pKvsDataChannel = (PKvsDataChannel) MEMCALLOC(1, SIZEOF(KvsDataChannel))) != NULL, STATUS_NOT_ENOUGH_MEMORY);
    STRNCPY(pKvsDataChannel->dataChannel.name, pDataChannelName, MAX_DATA_CHANNEL_NAME_LEN);
    pKvsDataChannel->pRtcPeerConnection = (PRtcPeerConnection) pKvsPeerConnection;
    if (pRtcDataChannelInit != NULL) {
        // Setting negotiated to false. Not supporting at the moment
        pRtcDataChannelInit->negotiated = FALSE;
        pKvsDataChannel->rtcDataChannelInit = *pRtcDataChannelInit;
    } else {
        // If nothing is set, set default to ordered mode
        pKvsDataChannel->rtcDataChannelInit.ordered = FALSE;
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxPacketLifeTime);
        NULLABLE_SET_EMPTY(pKvsDataChannel->rtcDataChannelInit.maxRetransmits);
    }
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.label, pKvsDataChannel->dataChannel.name, STRLEN(pKvsDataChannel->dataChannel.name));
    pKvsDataChannel->rtcDataChannelDiagnostics.state = RTC_DATA_CHANNEL_STATE_CONNECTING;
    CHK_STATUS(hashTableGetCount(pKvsPeerConnection->pDataChannels, &channelId));
    pKvsDataChannel->rtcDataChannelDiagnostics.dataChannelIdentifier = channelId;
    pKvsDataChannel->dataChannel.id = channelId;
    STRNCPY(pKvsDataChannel->rtcDataChannelDiagnostics.protocol, DATA_CHANNEL_PROTOCOL_STR,
            ARRAY_SIZE(pKvsDataChannel->rtcDataChannelDiagnostics.protocol));
    CHK_STATUS(hashTablePut(pKvsPeerConnection->pDataChannels, channelId, (UINT64) pKvsDataChannel));

CleanUp:
    if (STATUS_SUCCEEDED(retStatus)) {
        *ppRtcDataChannel = (PRtcDataChannel) pKvsDataChannel;
    } else {
        SAFE_MEMFREE(pKvsDataChannel);
    }

    LEAVES();
    return retStatus;
}

STATUS dataChannelSend(PRtcDataChannel pRtcDataChannel, BOOL isBinary, PBYTE pMessage, UINT32 pMessageLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    PSctpSession pSctpSession = NULL;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && pMessage != NULL, STATUS_NULL_ARG);

    pSctpSession = ((PKvsPeerConnection) pKvsDataChannel->pRtcPeerConnection)->pSctpSession;

    CHK_STATUS(sctpSessionWriteMessage(pSctpSession, pKvsDataChannel->channelId, isBinary, pMessage, pMessageLen));
    pKvsDataChannel->rtcDataChannelDiagnostics.messagesSent++;
    pKvsDataChannel->rtcDataChannelDiagnostics.bytesSent += pMessageLen;
CleanUp:

    return retStatus;
}

STATUS dataChannelOnMessage(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnMessage rtcOnMessage)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnMessage != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onMessage = rtcOnMessage;
    pKvsDataChannel->onMessageCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS dataChannelOnOpen(PRtcDataChannel pRtcDataChannel, UINT64 customData, RtcOnOpen rtcOnOpen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PKvsDataChannel pKvsDataChannel = (PKvsDataChannel) pRtcDataChannel;

    CHK(pKvsDataChannel != NULL && rtcOnOpen != NULL, STATUS_NULL_ARG);

    pKvsDataChannel->onOpen = rtcOnOpen;
    pKvsDataChannel->onOpenCustomData = customData;

CleanUp:

    LEAVES();
    return retStatus;
}
#endif
