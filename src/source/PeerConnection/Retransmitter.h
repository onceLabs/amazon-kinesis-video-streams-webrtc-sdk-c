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
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RETRANSMITTER__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RETRANSMITTER__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "RtcpPacket.h"
#include "PeerConnection.h"
#include "Retransmitter.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
typedef struct {
    PUINT16 sequenceNumberList;
    UINT32 seqNumListLen;
    UINT32 validIndexListLen;
    PUINT64 validIndexList;
} Retransmitter, *PRetransmitter;

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS createRetransmitter(UINT32, UINT32, PRetransmitter*);
STATUS freeRetransmitter(PRetransmitter*);
STATUS resendPacketOnNack(PRtcpPacket, PKvsPeerConnection);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_PEERCONNECTION_RETRANSMITTER__ */
