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
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H
#define __KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
#include "kvs/error.h"
#include "kvs/common_defs.h"
#include "kvs/platform_utils.h"
/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
#define MIN_HEADER_LENGTH 12
#define VERSION_SHIFT     6
#define VERSION_MASK      0x3
#define PADDING_SHIFT     5
#define PADDING_MASK      0x1
#define EXTENSION_SHIFT   4
#define EXTENSION_MASK    0x1
#define CSRC_COUNT_MASK   0xF
#define MARKER_SHIFT      7
#define MARKER_MASK       0x1
#define PAYLOAD_TYPE_MASK 0x7F
#define SEQ_NUMBER_OFFSET 2
#define TIMESTAMP_OFFSET  4
#define SSRC_OFFSET       8
#define CSRC_OFFSET       12
#define CSRC_LENGTH       4

#define RTP_HEADER_LEN(pRtpPacket)                                                                                                                   \
    (12 + (pRtpPacket)->header.csrcCount * CSRC_LENGTH + ((pRtpPacket)->header.extension ? 4 + (pRtpPacket)->header.extensionLength : 0))

#define RTP_GET_RAW_PACKET_SIZE(pRtpPacket) (RTP_HEADER_LEN(pRtpPacket) + ((pRtpPacket)->payloadLength))

#define GET_UINT16_SEQ_NUM(seqIndex) ((UINT16) ((seqIndex) % (MAX_UINT16 + 1)))

typedef STATUS (*DepayRtpPayloadFunc)(PBYTE, UINT32, PBYTE, PUINT32, PBOOL);

/*
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           timestamp                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           synchronization source (SSRC) identifier            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       contributing source (CSRC[0..15]) identifiers           |
 * |                             ....                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

typedef struct __RtpPacketHeader {
    UINT8 version;
    BOOL padding;
    BOOL extension;
    BOOL marker;
    UINT8 csrcCount;
    UINT8 payloadType;
    UINT16 sequenceNumber;
    UINT32 timestamp;
    UINT32 ssrc;
    PUINT32 csrcArray;
    UINT16 extensionProfile;
    PBYTE extensionPayload;
    UINT32 extensionLength;
} RtpPacketHeader, *PRtpPacketHeader;

typedef struct __Payloads {
    PBYTE payloadBuffer;
    UINT32 payloadLength;
    UINT32 maxPayloadLength;
    PUINT32 payloadSubLength;
    UINT32 payloadSubLenSize;
    UINT32 maxPayloadSubLenSize;
} PayloadArray, *PPayloadArray;

typedef struct __RtpPacket {
    RtpPacketHeader header;
    PBYTE payload;
    UINT32 payloadLength;
    PBYTE pRawPacket;
    UINT32 rawPacketLength;
    // used for jitterBufferDelay calculation
    UINT64 receivedTime;
} RtpPacket, *PRtpPacket;

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS createRtpPacket(UINT8, BOOL, BOOL, UINT8, BOOL, UINT8, UINT16, UINT32, UINT32, PUINT32, UINT16, UINT32, PBYTE, PBYTE, UINT32, PRtpPacket*);
STATUS setRtpPacket(UINT8, BOOL, BOOL, UINT8, BOOL, UINT8, UINT16, UINT32, UINT32, PUINT32, UINT16, UINT32, PBYTE, PBYTE, UINT32, PRtpPacket);
STATUS freeRtpPacket(PRtpPacket*);
/**
 * @brief send packets to the corresponding rtp receiver.
 *
 * @param[in] pKvsPeerConnection the user context.
 * @param[in] pBuffer the address of packet.
 * @param[in, out] bufferLen the length of packet.
 *
 * @return STATUS status of execution
 */
STATUS createRtpPacketFromBytes(PBYTE, UINT32, PRtpPacket*);
STATUS constructRetransmitRtpPacketFromBytes(PBYTE, UINT32, UINT16, UINT8, UINT32, PRtpPacket*);
STATUS setRtpPacketFromBytes(PBYTE, UINT32, PRtpPacket);
STATUS createBytesFromRtpPacket(PRtpPacket, PBYTE, PUINT32);
STATUS setBytesFromRtpPacket(PRtpPacket, PBYTE, UINT32);
STATUS constructRtpPackets(PPayloadArray, UINT8, UINT16, UINT32, UINT32, PRtpPacket, UINT32);

#ifdef __cplusplus
}
#endif
#endif //__KINESIS_VIDEO_WEBRTC_CLIENT_RTP_RTPPACKET_H
