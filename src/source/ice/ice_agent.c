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
#define LOG_CLASS "IceAgent"
#include "../Include_i.h"
#include <arpa/inet.h>
#include <lwip/sockets.h>
#include "double_linked_list.h"
#include "hex.h"
#include "crc32.h"
#include "network.h"
#include "ice_agent.h"
#include "turn_connection.h"
#include "ice_agent_fsm.h"
#include "PeerConnection.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
#define ICE_AGENT_ENTRY() ENTERS()
#define ICE_AGENT_LEAVE() LEAVES()

// https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate/candidate
// https://tools.ietf.org/html/rfc5245#section-15.1
// a=candidate:4234997325 1 udp 2043278322 192.168.0.56 44323 typ host
typedef enum {
    SDP_ICE_CANDIDATE_PARSER_STATE_FOUNDATION = 0,
    SDP_ICE_CANDIDATE_PARSER_STATE_COMPONENT,
    SDP_ICE_CANDIDATE_PARSER_STATE_PROTOCOL,
    SDP_ICE_CANDIDATE_PARSER_STATE_PRIORITY,
    SDP_ICE_CANDIDATE_PARSER_STATE_IP,
    SDP_ICE_CANDIDATE_PARSER_STATE_PORT,
    SDP_ICE_CANDIDATE_PARSER_STATE_TYPE_ID,
    SDP_ICE_CANDIDATE_PARSER_STATE_TYPE_VAL,
    SDP_ICE_CANDIDATE_PARSER_STATE_OTHERS
} SDP_ICE_CANDIDATE_PARSER_STATE;

extern StateMachineState ICE_AGENT_STATE_MACHINE_STATES[];
extern UINT32 ICE_AGENT_STATE_MACHINE_STATE_COUNT;

/******************************************************************************
 * FUNCTIONS
 ******************************************************************************/
STATUS ice_candidate_updateAddress(PIceCandidate pIceCandidate, PKvsIpAddress pIpAddr)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pIceCandidate != NULL && pIpAddr != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(pIceCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_HOST, STATUS_ICE_AGENT_INVALID_ARG);
    CHK(pIceCandidate->state == ICE_CANDIDATE_STATE_NEW, retStatus);

    pIceCandidate->ipAddress = *pIpAddr;
    pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;

CleanUp:

    return retStatus;
}

UINT32 ice_candidate_computePriority(PIceCandidate pIceCandidate)
{
    UINT32 typePreference = 0, localPreference = 0;

    switch (pIceCandidate->iceCandidateType) {
        case ICE_CANDIDATE_TYPE_HOST:
            typePreference = ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            typePreference = ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            typePreference = ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_RELAYED:
            typePreference = ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE;
            break;
    }

    if (!pIceCandidate->ipAddress.isPointToPoint) {
        localPreference = ICE_PRIORITY_LOCAL_PREFERENCE;
    }

    // Reference: https://tools.ietf.org/html/rfc5245#section-4.1.2.1
    // priority = (2^24)*(type preference) +
    //   (2^8)*(local preference) +
    //   (2^0)*(256 - component ID)
    //
    // Since type preference <= 126 and local preference <= 65535, the maximum possible
    // priority is (2^24) * (126) + (2^8) * (65535) + 255 = 2130706431. So, it's safe
    // to use UINT32 since 2130706431 < 2 ^ 32.
    return (1 << 24) * (typePreference) + (1 << 8) * (localPreference) + 255;
}

UINT64 ice_candidate_pair_computePriority(PIceCandidatePair pIceCandidatePair, BOOL isLocalControlling)
{
    UINT64 controllingAgentCandidatePri = pIceCandidatePair->local->priority;
    UINT64 controlledAgentCandidatePri = pIceCandidatePair->remote->priority;

    if (!isLocalControlling) {
        controllingAgentCandidatePri = controlledAgentCandidatePri;
        controlledAgentCandidatePri = pIceCandidatePair->local->priority;
    }

    // https://tools.ietf.org/html/rfc5245#appendix-B.5
    return ((UINT64) 1 << 32) * MIN(controlledAgentCandidatePri, controllingAgentCandidatePri) +
        2 * MAX(controlledAgentCandidatePri, controllingAgentCandidatePri) + (controllingAgentCandidatePri > controlledAgentCandidatePri ? 1 : 0);
}

VOID ice_candidate_log(PIceCandidate pIceCandidate)
{
    CHAR ipAddr[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    PCHAR protocol = "UDP";

    if (pIceCandidate != NULL) {
        net_getIpAddrStr(&pIceCandidate->ipAddress, ipAddr, ARRAY_SIZE(ipAddr));
        if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
            if (pIceCandidate->pTurnConnection == NULL) {
                protocol = "NA";
            } else if (pIceCandidate->pTurnConnection->protocol == KVS_SOCKET_PROTOCOL_TCP) {
                protocol = "TCP";
            }
        }
        DLOGD("New %s ice candidate discovered. Id: %s. Ip: %s:%u. Type: %s. Protocol: %s. priority: %u",
              pIceCandidate->isRemote ? "remote" : "local", pIceCandidate->id, ipAddr, (UINT16) getInt16(pIceCandidate->ipAddress.port),
              iceAgentGetCandidateTypeStr(pIceCandidate->iceCandidateType), protocol, pIceCandidate->priority);
    }
}

PCHAR iceAgentGetCandidateTypeStr(ICE_CANDIDATE_TYPE candidateType)
{
    switch (candidateType) {
        case ICE_CANDIDATE_TYPE_HOST:
            return SDP_CANDIDATE_TYPE_HOST;
        case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            return SDP_CANDIDATE_TYPE_SERFLX;
        case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            return SDP_CANDIDATE_TYPE_PRFLX;
        case ICE_CANDIDATE_TYPE_RELAYED:
            return SDP_CANDIDATE_TYPE_RELAY;
    }
    return SDP_CANDIDATE_TYPE_UNKNOWN;
}

STATUS ice_agent_throwFatalError(PIceAgent pIceAgent, STATUS errorStatus)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    pIceAgent->iceAgentStatus = errorStatus;
    MUTEX_UNLOCK(pIceAgent->lock);

CleanUp:

    return retStatus;
}

UINT64 ice_agent_getCurrentTime(UINT64 customData)
{
    UNUSED_PARAM(customData);
    return GETTIME();
}

STATUS ice_agent_findCandidateByIp(PKvsIpAddress pIpAddress, PDoubleList pCandidateList, PIceCandidate* ppIceCandidate)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidate pIceCandidate = NULL, pTargetIceCandidate = NULL;
    UINT32 addrLen;

    CHK(pIpAddress != NULL && pCandidateList != NULL && ppIceCandidate != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pCandidateList, &pCurNode));
    while (pCurNode != NULL && pTargetIceCandidate == NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pIceCandidate = (PIceCandidate) data;
        pCurNode = pCurNode->pNext;

        addrLen = IS_IPV4_ADDR(pIpAddress) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH;
        if (pIpAddress->family == pIceCandidate->ipAddress.family && MEMCMP(pIceCandidate->ipAddress.address, pIpAddress->address, addrLen) == 0 &&
            pIpAddress->port == pIceCandidate->ipAddress.port) {
            pTargetIceCandidate = pIceCandidate;
        }
    }

CleanUp:

    if (ppIceCandidate != NULL) {
        *ppIceCandidate = pTargetIceCandidate;
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_findCandidateBySocketConnection(PSocketConnection pSocketConnection, PDoubleList pCandidateList, PIceCandidate* ppIceCandidate)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidate pIceCandidate = NULL, pTargetIceCandidate = NULL;

    CHK(pCandidateList != NULL && ppIceCandidate != NULL && pSocketConnection != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pCandidateList, &pCurNode));
    while (pCurNode != NULL && pTargetIceCandidate == NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pIceCandidate = (PIceCandidate) data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidate->pSocketConnection == pSocketConnection) {
            pTargetIceCandidate = pIceCandidate;
        }
    }

CleanUp:

    if (ppIceCandidate != NULL) {
        *ppIceCandidate = pTargetIceCandidate;
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_serialize(PIceCandidate pIceCandidate, PCHAR pOutputData, PUINT32 pOutputLength)
{
    STATUS retStatus = STATUS_SUCCESS;
    INT32 amountWritten = 0;

    CHK(pIceCandidate != NULL && pOutputLength != NULL, STATUS_ICE_AGENT_NULL_ARG);

    // TODO FIXME real source of randomness
    if (IS_IPV4_ADDR(&(pIceCandidate->ipAddress))) {
        amountWritten = SNPRINTF(pOutputData, pOutputData == NULL ? 0 : *pOutputLength,
                                 "%u 1 udp %u %d.%d.%d.%d %d typ %s raddr 0.0.0.0 rport 0 generation 0 network-cost 999", pIceCandidate->foundation,
                                 pIceCandidate->priority, pIceCandidate->ipAddress.address[0], pIceCandidate->ipAddress.address[1],
                                 pIceCandidate->ipAddress.address[2], pIceCandidate->ipAddress.address[3],
                                 (UINT16) getInt16(pIceCandidate->ipAddress.port), iceAgentGetCandidateTypeStr(pIceCandidate->iceCandidateType));
    } else {
        amountWritten = SNPRINTF(pOutputData, pOutputData == NULL ? 0 : *pOutputLength,
                                 "%u 1 udp %u %02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X "
                                 "%d typ %s raddr ::/0 rport 0 generation 0 network-cost 999",
                                 pIceCandidate->foundation, pIceCandidate->priority, pIceCandidate->ipAddress.address[0],
                                 pIceCandidate->ipAddress.address[1], pIceCandidate->ipAddress.address[2], pIceCandidate->ipAddress.address[3],
                                 pIceCandidate->ipAddress.address[4], pIceCandidate->ipAddress.address[5], pIceCandidate->ipAddress.address[6],
                                 pIceCandidate->ipAddress.address[7], pIceCandidate->ipAddress.address[8], pIceCandidate->ipAddress.address[9],
                                 pIceCandidate->ipAddress.address[10], pIceCandidate->ipAddress.address[11], pIceCandidate->ipAddress.address[12],
                                 pIceCandidate->ipAddress.address[13], pIceCandidate->ipAddress.address[14], pIceCandidate->ipAddress.address[15],
                                 (UINT16) getInt16(pIceCandidate->ipAddress.port), iceAgentGetCandidateTypeStr(pIceCandidate->iceCandidateType));
    }

    CHK_WARN(amountWritten > 0, STATUS_INTERNAL_ERROR, "SNPRINTF failed");

    if (pOutputData == NULL) {
        *pOutputLength = ((UINT32) amountWritten) + 1; // +1 for null terminator
    } else {
        // amountWritten doesnt account for null char
        CHK(amountWritten < (INT32) *pOutputLength, STATUS_BUFFER_TOO_SMALL);
    }

CleanUp:

    return retStatus;
}

STATUS ice_agent_populateSdpMediaDescriptionCandidates(PIceAgent pIceAgent, PSdpMediaDescription pSdpMediaDescription, UINT32 attrBufferLen,
                                                       PUINT32 pIndex)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT64 data;
    PDoubleListNode pCurNode = NULL;
    BOOL locked = FALSE;
    UINT32 attrIndex;

    CHK(pIceAgent != NULL && pSdpMediaDescription != NULL && pIndex != NULL, STATUS_ICE_AGENT_NULL_ARG);

    attrIndex = *pIndex;

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurNode = pCurNode->pNext;

        STRNCPY(pSdpMediaDescription->sdpAttributes[attrIndex].attributeName, "candidate", MAX_SDP_ATTRIBUTE_NAME_LENGTH);
        CHK_STATUS(ice_candidate_serialize((PIceCandidate) data, pSdpMediaDescription->sdpAttributes[attrIndex].attributeValue, &attrBufferLen));
        attrIndex++;
    }

    *pIndex = attrIndex;

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}

STATUS ice_agent_addRemoteCandidate(PIceAgent pIceAgent, PCHAR pIceCandidateString)
{
    ICE_AGENT_ENTRY();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    PIceCandidate pIceCandidate = NULL, pDuplicatedIceCandidate = NULL, pLocalIceCandidate = NULL;
    PCHAR curr, tail, next;
    UINT32 tokenLen = 0, portValue = 0, remoteCandidateCount = 0, len = 0, priority = 0;
    BOOL freeIceCandidateIfFail = TRUE;
    BOOL foundIp = FALSE;
    BOOL foundPort = FALSE;
    BOOL breakLoop = FALSE;
    CHAR ipBuf[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    KvsIpAddress candidateIpAddr;
    PDoubleListNode pCurNode = NULL;
    SDP_ICE_CANDIDATE_PARSER_STATE state;
    ICE_CANDIDATE_TYPE iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
    CHK(pIceAgent != NULL && pIceCandidateString != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(!IS_EMPTY_STRING(pIceCandidateString), STATUS_ICE_AGENT_INVALID_ARG);

    MEMSET(&candidateIpAddr, 0x00, SIZEOF(KvsIpAddress));

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(doubleListGetNodeCount(pIceAgent->remoteCandidates, &remoteCandidateCount));
    CHK(remoteCandidateCount < KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT, STATUS_ICE_MAX_REMOTE_CANDIDATE_COUNT_EXCEEDED);
    // a=candidate:4234997325 1 udp 2043278322 192.168.0.56 44323 typ host
    curr = pIceCandidateString;
    tail = pIceCandidateString + STRLEN(pIceCandidateString);
    state = SDP_ICE_CANDIDATE_PARSER_STATE_FOUNDATION;

    // parse the attribute of ice candidate.
    while ((next = STRNCHR(curr, tail - curr, ' ')) != NULL && !breakLoop) {
        tokenLen = (UINT32) (next - curr);

        switch (state) {
            case SDP_ICE_CANDIDATE_PARSER_STATE_FOUNDATION:
            case SDP_ICE_CANDIDATE_PARSER_STATE_COMPONENT:
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_PRIORITY:
                STRTOUI32(curr, next, 10, &priority);
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_PROTOCOL:
                CHK(STRNCMPI("tcp", curr, tokenLen) != 0, STATUS_ICE_CANDIDATE_STRING_IS_TCP);
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_IP:
                len = MIN(next - curr, KVS_IP_ADDRESS_STRING_BUFFER_LEN - 1);
                STRNCPY(ipBuf, curr, len);
                ipBuf[len] = '\0';
                if ((foundIp = inet_pton(AF_INET, ipBuf, candidateIpAddr.address) == 1 ? TRUE : FALSE)) {
                    candidateIpAddr.family = KVS_IP_FAMILY_TYPE_IPV4;
                } else if ((foundIp = inet_pton(AF_INET6, ipBuf, candidateIpAddr.address) == 1 ? TRUE : FALSE)) {
                    candidateIpAddr.family = KVS_IP_FAMILY_TYPE_IPV6;
                }
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_PORT:
                CHK_STATUS(STRTOUI32(curr, curr + tokenLen, 10, &portValue));
                candidateIpAddr.port = htons(portValue);
                foundPort = TRUE;
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_TYPE_ID:
                // DLOGD("%s", curr);
                if (STRNCMPI("typ", curr, tokenLen) != 0) {
                    DLOGE("can not find candidate typ");
                    CHK(FALSE, STATUS_ICE_CANDIDATE_STRING_MISSING_TYPE);
                }
                break;
            case SDP_ICE_CANDIDATE_PARSER_STATE_TYPE_VAL:
                // DLOGD("%s", curr);
                if (STRNCMPI("host", curr, tokenLen) == 0) {
                    iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
                } else if (STRNCMPI("srflx", curr, tokenLen) == 0) {
                    iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
                } else if (STRNCMPI("prflx", curr, tokenLen) == 0) {
                    iceCandidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
                } else if (STRNCMPI("relay", curr, tokenLen) == 0) {
                    iceCandidateType = ICE_CANDIDATE_TYPE_RELAYED;
                } else {
                    DLOGE("unknown candidate type");
                    CHK(FALSE, STATUS_ICE_CANDIDATE_STRING_MISSING_TYPE);
                }

                breakLoop = TRUE;
                break;
            default:
                DLOGW("supposedly does not happen.");
                break;
        }
        state++;
        curr = next + 1;
    }

    CHK(foundPort, STATUS_ICE_CANDIDATE_STRING_MISSING_PORT);
    CHK(foundIp, STATUS_ICE_CANDIDATE_STRING_MISSING_IP);
    // check the duplicated remote ice candidates.
    CHK_STATUS(ice_agent_findCandidateByIp(&candidateIpAddr, pIceAgent->remoteCandidates, &pDuplicatedIceCandidate));
    CHK(pDuplicatedIceCandidate == NULL, retStatus);

    CHK((pIceCandidate = MEMCALLOC(1, SIZEOF(IceCandidate))) != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);
    json_generateSafeString(pIceCandidate->id, ARRAY_SIZE(pIceCandidate->id));
    pIceCandidate->isRemote = TRUE;
    pIceCandidate->ipAddress = candidateIpAddr;
    pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
    pIceCandidate->iceCandidateType = iceCandidateType;
    pIceCandidate->priority = priority;
    CHK_STATUS(double_list_insertItemTail(pIceAgent->remoteCandidates, (UINT64) pIceCandidate));
    freeIceCandidateIfFail = FALSE;

    CHK_STATUS(ice_candidate_pair_create(pIceAgent, pIceCandidate, TRUE));

    // for the stat.
    ice_candidate_log(pIceCandidate);

    /* pass remote candidate to each turnConnection */
    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        pLocalIceCandidate = (PIceCandidate) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pLocalIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED && IS_IPV4_ADDR(&candidateIpAddr)) {
            CHK_STATUS(turn_connection_addPeer(pLocalIceCandidate->pTurnConnection, &pIceCandidate->ipAddress));
        }
    }

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus) && freeIceCandidateIfFail) {
        SAFE_MEMFREE(pIceCandidate);
    }

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_updateCandidateStats(PIceAgent pIceAgent, BOOL isRemote)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidate pIceCandidate = NULL;
    PRtcIceCandidateDiagnostics pRtcIceCandidateDiagnostics = NULL;

    CHK(pIceAgent != NULL && pIceAgent->pDataSendingIceCandidatePair != NULL, STATUS_ICE_AGENT_NULL_ARG);

    pIceCandidate = pIceAgent->pDataSendingIceCandidatePair->remote;
    pRtcIceCandidateDiagnostics = &pIceAgent->rtcSelectedRemoteIceCandidateDiagnostics;

    if (!isRemote) {
        pIceCandidate = pIceAgent->pDataSendingIceCandidatePair->local;
        pRtcIceCandidateDiagnostics = &pIceAgent->rtcSelectedLocalIceCandidateDiagnostics;
        STRNCPY(pRtcIceCandidateDiagnostics->url, STATS_NOT_APPLICABLE_STR, ARRAY_SIZE(pRtcIceCandidateDiagnostics->url));
        // URL and relay protocol are populated only for local candidate by spec.
        // If candidate type is host, there is no URL and is set to N/A
        if (pIceCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_HOST) {
            STRNCPY(pRtcIceCandidateDiagnostics->url, pIceAgent->iceServers[pIceCandidate->iceServerIndex].url,
                    ARRAY_SIZE(pRtcIceCandidateDiagnostics->url));
        }
        // Only if candidate is obtained from TURN server will relay protocol be populated. Else, relay protocol is
        // not applicable.
        STRNCPY(pRtcIceCandidateDiagnostics->relayProtocol, STATS_NOT_APPLICABLE_STR, ARRAY_SIZE(pRtcIceCandidateDiagnostics->relayProtocol));
        if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED && pIceCandidate->pTurnConnection != NULL) {
            switch (pIceCandidate->pTurnConnection->protocol) {
                case KVS_SOCKET_PROTOCOL_UDP:
                    STRNCPY(pRtcIceCandidateDiagnostics->relayProtocol, ICE_URL_TRANSPORT_UDP,
                            ARRAY_SIZE(pRtcIceCandidateDiagnostics->relayProtocol));
                    break;
                case KVS_SOCKET_PROTOCOL_TCP:
                    STRNCPY(pRtcIceCandidateDiagnostics->relayProtocol, ICE_URL_TRANSPORT_TCP,
                            ARRAY_SIZE(pIceAgent->rtcSelectedLocalIceCandidateDiagnostics.relayProtocol));
                    break;
                default:
                    MEMSET(pRtcIceCandidateDiagnostics->relayProtocol, 0, SIZEOF(pRtcIceCandidateDiagnostics->relayProtocol));
            }
        }
    }

    net_getIpAddrStr(&pIceCandidate->ipAddress, pRtcIceCandidateDiagnostics->address, ARRAY_SIZE(pRtcIceCandidateDiagnostics->address));
    pRtcIceCandidateDiagnostics->port = (UINT16) getInt16(pIceCandidate->ipAddress.port);
    pRtcIceCandidateDiagnostics->priority = pIceCandidate->priority;
    STRNCPY(pRtcIceCandidateDiagnostics->candidateType, iceAgentGetCandidateTypeStr(pIceCandidate->iceCandidateType),
            ARRAY_SIZE(pRtcIceCandidateDiagnostics->candidateType));

    STRNCPY(pRtcIceCandidateDiagnostics->protocol, ICE_URL_TRANSPORT_UDP, ARRAY_SIZE(pRtcIceCandidateDiagnostics->protocol));
    if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
        STRNCPY(pRtcIceCandidateDiagnostics->protocol, pIceAgent->rtcIceServerDiagnostics[pIceCandidate->iceServerIndex].protocol,
                ARRAY_SIZE(pRtcIceCandidateDiagnostics->protocol));
    }
CleanUp:
    return retStatus;
}
STATUS ice_agent_updateSelectedLocalRemoteCandidateStats(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // Update local candidate stats
    CHK_STATUS(ice_agent_updateCandidateStats(pIceAgent, FALSE));
    // Update remote candidate stats
    CHK_STATUS(ice_agent_updateCandidateStats(pIceAgent, TRUE));
CleanUp:
    return retStatus;
}

STATUS ice_agent_create(PCHAR username, PCHAR password, PIceAgentCallbacks pIceAgentCallbacks, PRtcConfiguration pRtcConfiguration,
                        TIMER_QUEUE_HANDLE timerQueueHandle, PConnectionListener pConnectionListener, PIceAgent* ppIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = NULL;
    UINT32 i;

    CHK(ppIceAgent != NULL && username != NULL && password != NULL && pConnectionListener != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(STRNLEN(username, MAX_ICE_CONFIG_USER_NAME_LEN + 1) <= MAX_ICE_CONFIG_USER_NAME_LEN &&
            STRNLEN(password, MAX_ICE_CONFIG_CREDENTIAL_LEN + 1) <= MAX_ICE_CONFIG_CREDENTIAL_LEN,
        STATUS_ICE_AGENT_INVALID_ARG);

    // allocate the entire struct
    pIceAgent = (PIceAgent) MEMCALLOC(1, SIZEOF(IceAgent));
    STRNCPY(pIceAgent->localUsername, username, MAX_ICE_CONFIG_USER_NAME_LEN);
    STRNCPY(pIceAgent->localPassword, password, MAX_ICE_CONFIG_CREDENTIAL_LEN);

    ATOMIC_STORE_BOOL(&pIceAgent->remoteCredentialReceived, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->agentStartGathering, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->candidateGatheringFinished, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->shutdown, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->restart, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->processStun, TRUE);
    pIceAgent->isControlling = FALSE;
    pIceAgent->tieBreaker = (UINT64) RAND();
    pIceAgent->iceTransportPolicy = pRtcConfiguration->iceTransportPolicy;
    pIceAgent->kvsRtcConfiguration = pRtcConfiguration->kvsRtcConfiguration;
    CHK_STATUS(ice_agent_validateKvsRtcConfig(&pIceAgent->kvsRtcConfiguration));

    if (pIceAgentCallbacks != NULL) {
        pIceAgent->iceAgentCallbacks = *pIceAgentCallbacks;
    }
    pIceAgent->fsmEndTime = 0;
    pIceAgent->foundationCounter = 0;
    pIceAgent->localNetworkInterfaceCount = ARRAY_SIZE(pIceAgent->localNetworkInterfaces);
    pIceAgent->candidateGatheringEndTime = INVALID_TIMESTAMP_VALUE;

    pIceAgent->lock = MUTEX_CREATE(FALSE);

    // Create the state machine
    // set the first state as the initial state which is new state.
    CHK_STATUS(state_machine_create(ICE_AGENT_STATE_MACHINE_STATES, ICE_AGENT_STATE_MACHINE_STATE_COUNT, (UINT64) pIceAgent, ice_agent_getCurrentTime,
                                    (UINT64) pIceAgent, &pIceAgent->pStateMachine));
    pIceAgent->iceAgentStatus = STATUS_SUCCESS;
    pIceAgent->iceAgentStateTimerTask = MAX_UINT32;
    pIceAgent->keepAliveTimerTask = MAX_UINT32;
    pIceAgent->iceCandidateGatheringTimerTask = MAX_UINT32;
    pIceAgent->timerQueueHandle = timerQueueHandle;
    pIceAgent->lastDataReceivedTime = INVALID_TIMESTAMP_VALUE;
    pIceAgent->detectedDisconnection = FALSE;
    pIceAgent->disconnectionGracePeriodEndTime = INVALID_TIMESTAMP_VALUE;
    pIceAgent->pConnectionListener = pConnectionListener;
    pIceAgent->pDataSendingIceCandidatePair = NULL;
    CHK_STATUS(transaction_id_store_create(DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT, &pIceAgent->pStunBindingRequestTransactionIdStore));

    pIceAgent->relayCandidateCount = 0;

    CHK_STATUS(double_list_create(&pIceAgent->localCandidates));
    CHK_STATUS(double_list_create(&pIceAgent->remoteCandidates));
    CHK_STATUS(double_list_create(&pIceAgent->pIceCandidatePairs));
    CHK_STATUS(stack_queue_create(&pIceAgent->pTriggeredCheckQueue));

    // Pre-allocate stun packets

    // no other attribtues needed: https://tools.ietf.org/html/rfc8445#section-11
    CHK_STATUS(stun_createPacket(STUN_PACKET_TYPE_BINDING_INDICATION, NULL, &pIceAgent->pBindingIndication));
    CHK_STATUS(hash_table_createWithParams(ICE_HASH_TABLE_BUCKET_COUNT, ICE_HASH_TABLE_BUCKET_LENGTH, &pIceAgent->requestTimestampDiagnostics));

    pIceAgent->iceServersCount = 0;
    for (i = 0; i < MAX_ICE_SERVERS_COUNT; i++) {
        if (pRtcConfiguration->iceServers[i].urls[0] != '\0' &&
            STATUS_SUCCEEDED(
                ice_utils_parseIceServer(&pIceAgent->iceServers[pIceAgent->iceServersCount], (PCHAR) pRtcConfiguration->iceServers[i].urls,
                                         (PCHAR) pRtcConfiguration->iceServers[i].username, (PCHAR) pRtcConfiguration->iceServers[i].credential))) {
            pIceAgent->rtcIceServerDiagnostics[i].port = (INT32) getInt16(pIceAgent->iceServers[i].ipAddress.port);
            switch (pIceAgent->iceServers[pIceAgent->iceServersCount].transport) {
                case KVS_SOCKET_PROTOCOL_UDP:
                    STRNCPY(pIceAgent->rtcIceServerDiagnostics[i].protocol, ICE_URL_TRANSPORT_UDP, MAX_STATS_STRING_LENGTH);
                    break;
                case KVS_SOCKET_PROTOCOL_TCP:
                    STRNCPY(pIceAgent->rtcIceServerDiagnostics[i].protocol, ICE_URL_TRANSPORT_TCP, MAX_STATS_STRING_LENGTH);
                    break;
                default:
                    MEMSET(pIceAgent->rtcIceServerDiagnostics[i].protocol, 0, SIZEOF(pIceAgent->rtcIceServerDiagnostics[i].protocol));
            }
            STRNCPY(pIceAgent->rtcIceServerDiagnostics[i].url, pRtcConfiguration->iceServers[i].urls, MAX_STATS_STRING_LENGTH);
            pIceAgent->iceServersCount++;
        }
    }

CleanUp:

    if (STATUS_FAILED(retStatus) && pIceAgent != NULL) {
        ice_agent_free(&pIceAgent);
        pIceAgent = NULL;
    }

    if (ppIceAgent != NULL) {
        *ppIceAgent = pIceAgent;
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_free(PIceAgent* ppIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = NULL;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidatePair pIceCandidatePair = NULL;
    PIceCandidate pIceCandidate = NULL;

    CHK(ppIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // ice_agent_free is idempotent
    CHK(*ppIceAgent != NULL, retStatus);

    pIceAgent = *ppIceAgent;

    hash_table_free(pIceAgent->requestTimestampDiagnostics);
    pIceAgent->requestTimestampDiagnostics = NULL;

    if (pIceAgent->localCandidates != NULL) {
        CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
        while (pCurNode != NULL) {
            pIceCandidate = (PIceCandidate) pCurNode->data;
            pCurNode = pCurNode->pNext;

            if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
                CHK_LOG_ERR(turn_connection_free(&pIceCandidate->pTurnConnection));
            }
        }
    }

    if (pIceAgent->pConnectionListener != NULL) {
        CHK_LOG_ERR(connection_listener_free(&pIceAgent->pConnectionListener));
    }

    if (pIceAgent->pIceCandidatePairs != NULL) {
        CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
        while (pCurNode != NULL) {
            CHK_STATUS(double_list_getNodeData(pCurNode, &data));
            pCurNode = pCurNode->pNext;
            pIceCandidatePair = (PIceCandidatePair) data;

            CHK_LOG_ERR(ice_candidate_pair_free(&pIceCandidatePair));
        }

        CHK_LOG_ERR(double_list_clear(pIceAgent->pIceCandidatePairs, FALSE));
        CHK_LOG_ERR(double_list_free(pIceAgent->pIceCandidatePairs));
    }

    if (pIceAgent->localCandidates != NULL) {
        CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
        while (pCurNode != NULL) {
            CHK_STATUS(double_list_getNodeData(pCurNode, &data));
            pCurNode = pCurNode->pNext;
            pIceCandidate = (PIceCandidate) data;

            /* turn sockets are freed by turn_connection_free */
            if (pIceCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_RELAYED) {
                CHK_LOG_ERR(socket_connection_free(&pIceCandidate->pSocketConnection));
            }
        }
        // free all stored candidates
        CHK_LOG_ERR(double_list_clear(pIceAgent->localCandidates, TRUE));
        CHK_LOG_ERR(double_list_free(pIceAgent->localCandidates));
    }

    /* In case we fail in the middle of a ICE restart */
    if (ATOMIC_LOAD_BOOL(&pIceAgent->restart) && pIceAgent->pDataSendingIceCandidatePair != NULL) {
        if (IS_CANN_PAIR_SENDING_FROM_RELAYED(pIceAgent->pDataSendingIceCandidatePair)) {
            CHK_LOG_ERR(turn_connection_free(&pIceAgent->pDataSendingIceCandidatePair->local->pTurnConnection));
        } else {
            CHK_LOG_ERR(socket_connection_free(&pIceAgent->pDataSendingIceCandidatePair->local->pSocketConnection));
        }

        MEMFREE(pIceAgent->pDataSendingIceCandidatePair->local);
        CHK_LOG_ERR(ice_candidate_pair_free(&pIceAgent->pDataSendingIceCandidatePair));

        pIceAgent->pDataSendingIceCandidatePair = NULL;
    }

    if (pIceAgent->remoteCandidates != NULL) {
        // remote candidates dont have socketConnection
        CHK_LOG_ERR(double_list_clear(pIceAgent->remoteCandidates, TRUE));
        CHK_LOG_ERR(double_list_free(pIceAgent->remoteCandidates));
    }

    if (pIceAgent->pTriggeredCheckQueue != NULL) {
        CHK_LOG_ERR(stack_queue_free(pIceAgent->pTriggeredCheckQueue));
    }

    if (IS_VALID_MUTEX_VALUE(pIceAgent->lock)) {
        MUTEX_FREE(pIceAgent->lock);
        pIceAgent->lock = INVALID_MUTEX_VALUE;
    }
    state_machine_free(pIceAgent->pStateMachine);

    if (pIceAgent->pBindingIndication != NULL) {
        stun_freePacket(&pIceAgent->pBindingIndication);
    }

    if (pIceAgent->pBindingRequest != NULL) {
        stun_freePacket(&pIceAgent->pBindingRequest);
    }

    if (pIceAgent->pStunBindingRequestTransactionIdStore != NULL) {
        transaction_id_store_free(&pIceAgent->pStunBindingRequestTransactionIdStore);
    }
    MEMFREE(pIceAgent);

    *ppIceAgent = NULL;

CleanUp:

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_validateKvsRtcConfig(PKvsRtcConfiguration pKvsRtcConfiguration)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pKvsRtcConfiguration != NULL, STATUS_ICE_AGENT_NULL_ARG);

    if (pKvsRtcConfiguration->iceLocalCandidateGatheringTimeout == 0) {
        pKvsRtcConfiguration->iceLocalCandidateGatheringTimeout = KVS_ICE_GATHER_REFLEXIVE_AND_RELAYED_CANDIDATE_TIMEOUT;
    }

    if (pKvsRtcConfiguration->iceConnectionCheckTimeout == 0) {
        pKvsRtcConfiguration->iceConnectionCheckTimeout = KVS_ICE_CONNECTIVITY_CHECK_TIMEOUT;
    }

    if (pKvsRtcConfiguration->iceCandidateNominationTimeout == 0) {
        pKvsRtcConfiguration->iceCandidateNominationTimeout = KVS_ICE_CANDIDATE_NOMINATION_TIMEOUT;
    }

    if (pKvsRtcConfiguration->iceConnectionCheckPollingInterval == 0) {
        pKvsRtcConfiguration->iceConnectionCheckPollingInterval = ICE_AGENT_TIMER_TA_DEFAULT;
    }

    DLOGD("\n\ticeLocalCandidateGatheringTimeout: %u ms"
          "\n\ticeConnectionCheckTimeout: %u ms"
          "\n\ticeCandidateNominationTimeout: %u ms"
          "\n\ticeConnectionCheckPollingInterval: %u ms",
          pKvsRtcConfiguration->iceLocalCandidateGatheringTimeout / HUNDREDS_OF_NANOS_IN_A_MILLISECOND,
          pKvsRtcConfiguration->iceConnectionCheckTimeout / HUNDREDS_OF_NANOS_IN_A_MILLISECOND,
          pKvsRtcConfiguration->iceCandidateNominationTimeout / HUNDREDS_OF_NANOS_IN_A_MILLISECOND,
          pKvsRtcConfiguration->iceConnectionCheckPollingInterval / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);

CleanUp:

    return retStatus;
}

STATUS ice_agent_reportNewLocalCandidate(PIceAgent pIceAgent, PIceCandidate pIceCandidate)
{
    ICE_AGENT_ENTRY();
    STATUS retStatus = STATUS_SUCCESS;
    CHAR serializedIceCandidateBuf[MAX_SDP_ATTRIBUTE_VALUE_LENGTH];
    UINT32 serializedIceCandidateBufLen = ARRAY_SIZE(serializedIceCandidateBuf);

    CHK(pIceAgent != NULL && pIceCandidate != NULL, STATUS_ICE_AGENT_NULL_ARG);

    ice_candidate_log(pIceCandidate);

    CHK_WARN(pIceAgent->iceAgentCallbacks.newLocalCandidateFn != NULL, retStatus, "newLocalCandidateFn callback not implemented");
    CHK_WARN(!ATOMIC_LOAD_BOOL(&pIceAgent->candidateGatheringFinished), retStatus,
             "Cannot report new ice candidate because candidate gathering is already finished");
    CHK_STATUS(ice_candidate_serialize(pIceCandidate, serializedIceCandidateBuf, &serializedIceCandidateBufLen));
    // callback for upper layer.
    pIceAgent->iceAgentCallbacks.newLocalCandidateFn(pIceAgent->iceAgentCallbacks.customData, serializedIceCandidateBuf);

CleanUp:

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}
/**
 * @brief gather local ip addresses and create a udp port. If port creation succeeded then create a new candidate
 * and store it in localCandidates. Ips that are already a local candidate will not be added again.
 *
 * @param[in] PIceAgent IceAgent object
 *
 * @return STATUS status of execution
 */
STATUS ice_agent_initHostCandidate(PIceAgent pIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PKvsIpAddress pIpAddress = NULL;
    PIceCandidate pTmpIceCandidate = NULL, pDuplicatedIceCandidate = NULL, pNewIceCandidate = NULL;
    UINT32 i, localCandidateCount = 0;
    PSocketConnection pSocketConnection = NULL;
    BOOL locked = FALSE;

    for (i = 0; i < pIceAgent->localNetworkInterfaceCount; ++i) {
        pIpAddress = &pIceAgent->localNetworkInterfaces[i];

        // make sure pIceAgent->localCandidates has no duplicates
        CHK_STATUS(ice_agent_findCandidateByIp(pIpAddress, pIceAgent->localCandidates, &pDuplicatedIceCandidate));
        // create the udp socket to
        if (pDuplicatedIceCandidate == NULL &&
            STATUS_SUCCEEDED(socket_connection_create(pIpAddress->family, KVS_SOCKET_PROTOCOL_UDP, pIpAddress, NULL, (UINT64) pIceAgent,
                                                      ice_agent_handleInboundData, pIceAgent->kvsRtcConfiguration.sendBufSize, &pSocketConnection))) {
            pTmpIceCandidate = MEMCALLOC(1, SIZEOF(IceCandidate));
            json_generateSafeString(pTmpIceCandidate->id, ARRAY_SIZE(pTmpIceCandidate->id));
            pTmpIceCandidate->isRemote = FALSE;
            pTmpIceCandidate->ipAddress = *pIpAddress;
            pTmpIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
            pTmpIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
            // we dont generate candidates that have the same foundation.
            pTmpIceCandidate->foundation = pIceAgent->foundationCounter++;
            pTmpIceCandidate->pSocketConnection = pSocketConnection;
            pTmpIceCandidate->priority = ice_candidate_computePriority(pTmpIceCandidate);

            /* Another thread could be calling ice_agent_addRemoteCandidate which triggers ice_candidate_pair_create.
             * ice_candidate_pair_create will read through localCandidates, since we are mutating localCandidates here,
             * need to acquire lock. */
            MUTEX_LOCK(pIceAgent->lock);
            locked = TRUE;

            CHK_STATUS(double_list_insertItemTail(pIceAgent->localCandidates, (UINT64) pTmpIceCandidate));
            CHK_STATUS(ice_candidate_pair_create(pIceAgent, pTmpIceCandidate, FALSE));

            MUTEX_UNLOCK(pIceAgent->lock);
            locked = FALSE;

            localCandidateCount++;
            // make a copy of pTmpIceCandidate so that if ice_agent_reportNewLocalCandidate fails pTmpIceCandidate wont get freed.
            pNewIceCandidate = pTmpIceCandidate;
            pTmpIceCandidate = NULL;

            ATOMIC_STORE_BOOL(&pSocketConnection->receiveData, TRUE);
            // connectionListener will free the pSocketConnection at the end.
            CHK_STATUS(connection_listener_add(pIceAgent->pConnectionListener, pNewIceCandidate->pSocketConnection));
        }
    }

    CHK(localCandidateCount != 0, STATUS_ICE_NO_LOCAL_HOST_CANDIDATE_AVAILABLE);

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    SAFE_MEMFREE(pTmpIceCandidate);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}
/**
 * @brief initialize the srflx candidates. create the socket connection of the local candidates with stun servers
 *
 * @param[in] pIceAgent the context of the ice agent.
 *
 * @return STATUS status of execution
 */
static STATUS ice_agent_initSrflxCandidate(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceServer pIceServer = NULL;
    PIceCandidate pCandidate = NULL, pNewCandidate = NULL;
    UINT32 j;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    /* There should be no other thread mutating localCandidates at this time, so safe to read without lock. */
    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurNode = pCurNode->pNext;
        pCandidate = (PIceCandidate) data;

        if (pCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_HOST) {
            for (j = 0; j < pIceAgent->iceServersCount; j++) {
                pIceServer = &pIceAgent->iceServers[j];
                // only stun.
                if (!pIceServer->isTurn && pIceServer->ipAddress.family == pCandidate->ipAddress.family) {
                    CHK((pNewCandidate = (PIceCandidate) MEMCALLOC(1, SIZEOF(IceCandidate))) != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);
                    json_generateSafeString(pNewCandidate->id, ARRAY_SIZE(pNewCandidate->id));
                    pNewCandidate->isRemote = FALSE;

                    // copy over host candidate's address to open up a new socket at that address.
                    pNewCandidate->ipAddress = pCandidate->ipAddress;
                    // open up a new socket at host candidate's ip address for server reflex candidate.
                    // the new port will be stored in pNewCandidate->ipAddress.port. And the Ip address will later be updated
                    // with the correct ip address once the STUN response is received.
                    CHK_STATUS(socket_connection_create(pCandidate->ipAddress.family, KVS_SOCKET_PROTOCOL_UDP, &pNewCandidate->ipAddress, NULL,
                                                        (UINT64) pIceAgent, ice_agent_handleInboundData, pIceAgent->kvsRtcConfiguration.sendBufSize,
                                                        &pNewCandidate->pSocketConnection));
                    ATOMIC_STORE_BOOL(&pNewCandidate->pSocketConnection->receiveData, TRUE);
                    // connectionListener will free the pSocketConnection at the end.
                    CHK_STATUS(connection_listener_add(pIceAgent->pConnectionListener, pNewCandidate->pSocketConnection));
                    pNewCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
                    pNewCandidate->state = ICE_CANDIDATE_STATE_NEW;
                    pNewCandidate->iceServerIndex = j;
                    pNewCandidate->foundation = pIceAgent->foundationCounter++; // we dont generate candidates that have the same foundation.
                    pNewCandidate->priority = ice_candidate_computePriority(pNewCandidate);

                    /* There could be another thread calling ice_agent_addRemoteCandidate which triggers ice_candidate_pair_create.
                     * ice_candidate_pair_create will read through localCandidates, since we are mutating localCandidates here,
                     * need to acquire lock. */
                    MUTEX_LOCK(pIceAgent->lock);
                    locked = TRUE;

                    CHK_STATUS(double_list_insertItemTail(pIceAgent->localCandidates, (UINT64) pNewCandidate));

                    MUTEX_UNLOCK(pIceAgent->lock);
                    locked = FALSE;

                    pNewCandidate = NULL;
                }
            }
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (pNewCandidate != NULL) {
        SAFE_MEMFREE(pNewCandidate);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}
/**
 * @brief initilize the relay candidate.
 *
 * @param[in] pIceAgent the context of the ice agent.
 * @param[in] iceServerIndex the index of ice servers.
 * @param[in] protocol the protocol which ice server uses.
 *
 * @return STATUS code of the execution
 */
static STATUS ice_agent_initRelayCandidate(PIceAgent pIceAgent, UINT32 iceServerIndex, KVS_SOCKET_PROTOCOL protocol)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidate pNewCandidate = NULL, pCandidate = NULL;
    BOOL locked = FALSE;
    PTurnConnection pTurnConnection = NULL;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    /* we dont support TURN on DTLS yet. */
    CHK(protocol != KVS_SOCKET_PROTOCOL_UDP || !pIceAgent->iceServers[iceServerIndex].isSecure, retStatus);
    CHK_WARN(pIceAgent->relayCandidateCount < KVS_ICE_MAX_RELAY_CANDIDATE_COUNT, retStatus,
             "Cannot create more relay candidate because max count of %u is reached", KVS_ICE_MAX_RELAY_CANDIDATE_COUNT);
    // #memory.
    CHK((pNewCandidate = (PIceCandidate) MEMCALLOC(1, SIZEOF(IceCandidate))) != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);

    json_generateSafeString(pNewCandidate->id, ARRAY_SIZE(pNewCandidate->id));
    pNewCandidate->isRemote = FALSE;

    // open up a new socket without binding to any host address. The candidate Ip address will later be updated
    // with the correct relay ip address once the Allocation success response is received. Relay candidate's socket is managed
    // by TurnConnection struct.
    CHK(socket_connection_create(KVS_IP_FAMILY_TYPE_IPV4, protocol, NULL, &pIceAgent->iceServers[iceServerIndex].ipAddress, (UINT64) pNewCandidate,
                                 ice_agent_handleInboundRelayedData, pIceAgent->kvsRtcConfiguration.sendBufSize,
                                 &pNewCandidate->pSocketConnection) == STATUS_SUCCESS,
        STATUS_ICE_AGENT_CREATE_TURN_SOCKET);
    // connectionListener will free the pSocketConnection at the end.
    CHK_STATUS(connection_listener_add(pIceAgent->pConnectionListener, pNewCandidate->pSocketConnection));

    pNewCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_RELAYED;
    pNewCandidate->state = ICE_CANDIDATE_STATE_NEW;
    pNewCandidate->iceServerIndex = iceServerIndex;
    pNewCandidate->foundation = pIceAgent->foundationCounter++; // we dont generate candidates that have the same foundation.
    pNewCandidate->priority = ice_candidate_computePriority(pNewCandidate);

    CHK_STATUS(turn_connection_create(&pIceAgent->iceServers[iceServerIndex], pIceAgent->timerQueueHandle,
                                      TURN_CONNECTION_DATA_TRANSFER_MODE_SEND_INDIDATION, protocol, NULL, pNewCandidate->pSocketConnection,
                                      pIceAgent->pConnectionListener, &pTurnConnection));

    pNewCandidate->pIceAgent = pIceAgent;
    pNewCandidate->pTurnConnection = pTurnConnection;

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(double_list_insertItemTail(pIceAgent->localCandidates, (UINT64) pNewCandidate));
    pNewCandidate = NULL;

    /* add existing remote candidates to turn. Need to acquire lock because remoteCandidates can be mutated by
     * ice_agent_addRemoteCandidate calls. */
    CHK_STATUS(double_list_getHeadNode(pIceAgent->remoteCandidates, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurNode = pCurNode->pNext;
        pCandidate = (PIceCandidate) data;

        // TODO: Stop skipping IPv6. Since we're allowing IPv6 remote candidates from ice_agent_addRemoteCandidate for host candidates,
        // it's possible to have a situation where the turn server uses IPv4 and the remote candidate uses IPv6.
        if (IS_IPV4_ADDR(&pCandidate->ipAddress)) {
            CHK_STATUS(turn_connection_addPeer(pTurnConnection, &pCandidate->ipAddress));
        }
    }

    pIceAgent->relayCandidateCount++;

    MUTEX_UNLOCK(pIceAgent->lock);
    locked = FALSE;

    CHK_STATUS(turn_connection_start(pTurnConnection));

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    SAFE_MEMFREE(pNewCandidate);

    return retStatus;
}
/**
 * @brief initialize the relay candidates.
 *
 * @param[in] pIceAgent the context of the ice agent.
 *
 * @return STATUS status of execution.
 */
static STATUS ice_agent_initRelayCandidates(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 j;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    for (j = 0; j < pIceAgent->iceServersCount; j++) {
        if (pIceAgent->iceServers[j].isTurn) {
            if (pIceAgent->iceServers[j].transport == KVS_SOCKET_PROTOCOL_UDP || pIceAgent->iceServers[j].transport == KVS_SOCKET_PROTOCOL_NONE) {
                CHK_STATUS(ice_agent_initRelayCandidate(pIceAgent, j, KVS_SOCKET_PROTOCOL_UDP));
            }

            if (pIceAgent->iceServers[j].transport == KVS_SOCKET_PROTOCOL_TCP || pIceAgent->iceServers[j].transport == KVS_SOCKET_PROTOCOL_NONE) {
                CHK_STATUS(ice_agent_initRelayCandidate(pIceAgent, j, KVS_SOCKET_PROTOCOL_TCP));
            }
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_fsmTimerCallback(UINT32 timerId, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerId);
    UNUSED_PARAM(currentTime);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    // Do not acquire lock because ice_agent_fsm_step acquires lock.
    // Drive the state machine
    CHK_STATUS(ice_agent_fsm_step(pIceAgent));

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_start(PIceAgent pIceAgent, PCHAR remoteUsername, PCHAR remotePassword, BOOL isControlling)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL && remoteUsername != NULL && remotePassword != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pIceAgent->remoteCredentialReceived), retStatus); // make ice_agent_start idempotent
    CHK(STRNLEN(remoteUsername, MAX_ICE_CONFIG_USER_NAME_LEN + 1) <= MAX_ICE_CONFIG_USER_NAME_LEN &&
            STRNLEN(remotePassword, MAX_ICE_CONFIG_CREDENTIAL_LEN + 1) <= MAX_ICE_CONFIG_CREDENTIAL_LEN,
        STATUS_ICE_AGENT_INVALID_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    ATOMIC_STORE_BOOL(&pIceAgent->remoteCredentialReceived, TRUE);
    /* role should not change during ice restart. */
    if (!ATOMIC_LOAD_BOOL(&pIceAgent->restart)) {
        pIceAgent->isControlling = isControlling;
    }

    STRNCPY(pIceAgent->remoteUsername, remoteUsername, MAX_ICE_CONFIG_USER_NAME_LEN);
    STRNCPY(pIceAgent->remotePassword, remotePassword, MAX_ICE_CONFIG_CREDENTIAL_LEN);
    if (STRLEN(pIceAgent->remoteUsername) + STRLEN(pIceAgent->localUsername) + 1 > MAX_ICE_CONFIG_USER_NAME_LEN) {
        DLOGW("remoteUsername:localUsername will be truncated to stay within %u char limit", MAX_ICE_CONFIG_USER_NAME_LEN);
    }
    SNPRINTF(pIceAgent->combinedUserName, ARRAY_SIZE(pIceAgent->combinedUserName), "%s:%s", pIceAgent->remoteUsername, pIceAgent->localUsername);

    MUTEX_UNLOCK(pIceAgent->lock);
    locked = FALSE;
    // try to advance the fsm of ice agent every 50ms.
    CHK_STATUS(timer_queue_addTimer(pIceAgent->timerQueueHandle, KVS_ICE_FSM_TIMER_START_DELAY,
                                    pIceAgent->kvsRtcConfiguration.iceConnectionCheckPollingInterval, ice_agent_fsmTimerCallback, (UINT64) pIceAgent,
                                    &pIceAgent->iceAgentStateTimerTask));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_gatherTimerCallback(UINT32 timerId, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerId);
    STATUS retStatus = STATUS_SUCCESS;
    // #memory. #heap. #TBD.
    IceCandidate newLocalCandidates[KVS_ICE_MAX_NEW_LOCAL_CANDIDATES_TO_REPORT_AT_ONCE];
    UINT32 newLocalCandidateCount = 0;
    PIceAgent pIceAgent = (PIceAgent) customData;
    BOOL locked = FALSE;
    BOOL stopScheduling = FALSE;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidate pIceCandidate = NULL;
    UINT32 pendingSrflxCandidateCount = 0;
    UINT32 pendingCandidateCount = 0;
    UINT32 i;
    UINT32 totalCandidateCount = 0;
    KvsIpAddress relayAddress;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    MEMSET(newLocalCandidates, 0x00, SIZEOF(newLocalCandidates));
    MEMSET(&relayAddress, 0x00, SIZEOF(KvsIpAddress));

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pIceCandidate = (PIceCandidate) data;
        pCurNode = pCurNode->pNext;

        totalCandidateCount++;
        // invalid candidates.
        if (pIceCandidate->state == ICE_CANDIDATE_STATE_NEW) {
            pendingCandidateCount++;
            // re-send the server-reflexive req.
            if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE) {
                pendingSrflxCandidateCount++;
                // the turn connection is ready.
            } else if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED && pIceCandidate->pTurnConnection != NULL &&
                       turn_connection_getRelayAddress(pIceCandidate->pTurnConnection, &relayAddress)) {
                /* Check if any relay address has been obtained. */
                // update the ip address of ice candidate and set the state of the ice candidate as valid.
                CHK_STATUS(ice_candidate_updateAddress(pIceCandidate, &relayAddress));
                CHK_STATUS(ice_candidate_pair_create(pIceAgent, pIceCandidate, FALSE));
            }
        }
    }

    /* keep sending binding request if there is still pending srflx candidate */
    if (pendingSrflxCandidateCount > 0) {
        CHK_STATUS(ice_agent_sendSrflxCandidateRequest(pIceAgent));
    }

    /* stop scheduling if there is no more pending candidate or if timeout is reached. */
    if ((totalCandidateCount > 0 && pendingCandidateCount == 0) || currentTime >= pIceAgent->candidateGatheringEndTime) {
        DLOGD("Candidate gathering completed.");
        stopScheduling = TRUE;
        pIceAgent->iceCandidateGatheringTimerTask = MAX_UINT32;
    }

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL && newLocalCandidateCount < ARRAY_SIZE(newLocalCandidates)) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurNode = pCurNode->pNext;
        pIceCandidate = (PIceCandidate) data;

        if (pIceCandidate->state == ICE_CANDIDATE_STATE_VALID && !pIceCandidate->reported) {
            newLocalCandidates[newLocalCandidateCount++] = *pIceCandidate;
            pIceCandidate->reported = TRUE;
        }
    }

    MUTEX_UNLOCK(pIceAgent->lock);
    locked = FALSE;

    /* newLocalCandidateCount is at most ARRAY_SIZE(newLocalCandidates). Candidates not reported in this invocation
     * will be reported in next invocation. */
    for (i = 0; i < newLocalCandidateCount; ++i) {
        CHK_STATUS(ice_agent_reportNewLocalCandidate(pIceAgent, &newLocalCandidates[i]));
    }
    // should send the null candidate to terminate the processing of gathering the ice candidate
    if (stopScheduling) {
        ATOMIC_STORE_BOOL(&pIceAgent->candidateGatheringFinished, TRUE);
        /* notify that candidate gathering is finished. */
        if (pIceAgent->iceAgentCallbacks.newLocalCandidateFn != NULL) {
            pIceAgent->iceAgentCallbacks.newLocalCandidateFn(pIceAgent->iceAgentCallbacks.customData, NULL);
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }
    if (stopScheduling) {
        retStatus = STATUS_TIMER_QUEUE_STOP_SCHEDULING;
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}

STATUS ice_agent_gather(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pIceAgent->agentStartGathering), retStatus);

    ATOMIC_STORE_BOOL(&pIceAgent->agentStartGathering, TRUE);
    // acquire the local ip address, this should be done once unless the network interface is changed.
    CHK_STATUS(net_getLocalhostIpAddresses(pIceAgent->localNetworkInterfaces, &pIceAgent->localNetworkInterfaceCount,
                                           pIceAgent->kvsRtcConfiguration.iceSetInterfaceFilterFunc,
                                           pIceAgent->kvsRtcConfiguration.filterCustomData));

    // skip gathering host candidate and srflx candidate if relay only
    if (pIceAgent->iceTransportPolicy != ICE_TRANSPORT_POLICY_RELAY) {
        // local candiates.
        CHK_STATUS(ice_agent_initHostCandidate(pIceAgent));
        CHK_STATUS(ice_agent_initSrflxCandidate(pIceAgent));
    }

    CHK_STATUS(ice_agent_initRelayCandidates(pIceAgent));

    // start listening for incoming data
    CHK_STATUS(connection_listener_start(pIceAgent->pConnectionListener));

    pIceAgent->candidateGatheringEndTime = GETTIME() + pIceAgent->kvsRtcConfiguration.iceLocalCandidateGatheringTimeout;

    CHK_STATUS(timer_queue_addTimer(pIceAgent->timerQueueHandle, KVS_ICE_GATHERING_TIMER_START_DELAY, KVS_ICE_GATHER_CANDIDATE_TIMER_POLLING_INTERVAL,
                                    ice_agent_gatherTimerCallback, (UINT64) pIceAgent, &pIceAgent->iceCandidateGatheringTimerTask));

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_shutdown(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, turnShutdownCompleted = FALSE;
    PDoubleListNode pCurNode = NULL;
    PIceCandidate pLocalCandidate = NULL;
    UINT32 i;
    UINT64 turnShutdownTimeout;
    PTurnConnection turnConnections[KVS_ICE_MAX_RELAY_CANDIDATE_COUNT];
    UINT32 turnConnectionCount = 0;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    DLOGD("Shutdown the ice agent(%s)", pIceAgent->combinedUserName);
    CHK(!ATOMIC_EXCHANGE_BOOL(&pIceAgent->shutdown, TRUE), retStatus);

    if (pIceAgent->iceAgentStateTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->iceAgentStateTimerTask, (UINT64) pIceAgent));
        pIceAgent->iceAgentStateTimerTask = MAX_UINT32;
    }

    if (pIceAgent->keepAliveTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->keepAliveTimerTask, (UINT64) pIceAgent));
        pIceAgent->keepAliveTimerTask = MAX_UINT32;
    }

    if (pIceAgent->iceCandidateGatheringTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->iceCandidateGatheringTimerTask, (UINT64) pIceAgent));
        pIceAgent->iceCandidateGatheringTimerTask = MAX_UINT32;
    }

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        pLocalCandidate = (PIceCandidate) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pLocalCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_RELAYED) {
            /* close socket so ice doesnt receive any more data */
            CHK_STATUS(socket_connection_close(pLocalCandidate->pSocketConnection));
        } else {
            CHK_STATUS(turn_connection_shutdown(pLocalCandidate->pTurnConnection, 0));
            turnConnections[turnConnectionCount++] = pLocalCandidate->pTurnConnection;
        }
    }

    MUTEX_UNLOCK(pIceAgent->lock);
    locked = FALSE;

    turnShutdownTimeout = GETTIME() + KVS_ICE_TURN_CONNECTION_SHUTDOWN_TIMEOUT;
    while (!turnShutdownCompleted && GETTIME() < turnShutdownTimeout) {
        for (i = 0, turnShutdownCompleted = TRUE; turnShutdownCompleted && i < turnConnectionCount; ++i) {
            if (!turn_connection_isShutdownCompleted(turnConnections[i])) {
                turnShutdownCompleted = FALSE;
            }
        }

        THREAD_SLEEP(KVS_ICE_SHORT_CHECK_DELAY);
    }

    if (!turnShutdownCompleted) {
        DLOGW("TurnConnection shutdown did not complete within %" PRIu64 " seconds",
              KVS_ICE_TURN_CONNECTION_SHUTDOWN_TIMEOUT / HUNDREDS_OF_NANOS_IN_A_SECOND);
    }

    /* remove connections last because still need to send data to deallocate turn */
    if (pIceAgent->pConnectionListener != NULL) {
        CHK_STATUS(connection_listener_removeAll(pIceAgent->pConnectionListener));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}

STATUS ice_agent_restart(PIceAgent pIceAgent, PCHAR localIceUfrag, PCHAR localIcePwd)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    PDoubleListNode pCurNode = NULL, pNextNode = NULL;
    PIceCandidate pLocalCandidate = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    UINT32 i;
    ATOMIC_BOOL alreadyRestarting;
    PIceCandidate localCandidates[KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT];
    UINT32 localCandidateCount = 0;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pIceAgent->shutdown), STATUS_INVALID_OPERATION);

    DLOGD("Restarting ICE");

    alreadyRestarting = ATOMIC_EXCHANGE_BOOL(&pIceAgent->restart, TRUE);
    CHK(!alreadyRestarting, retStatus);

    if (pIceAgent->iceAgentStateTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->iceAgentStateTimerTask, (UINT64) pIceAgent));
        pIceAgent->iceAgentStateTimerTask = MAX_UINT32;
    }

    if (pIceAgent->keepAliveTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->keepAliveTimerTask, (UINT64) pIceAgent));
        pIceAgent->keepAliveTimerTask = MAX_UINT32;
    }

    if (pIceAgent->iceCandidateGatheringTimerTask != MAX_UINT32) {
        CHK_STATUS(timer_queue_cancelTimer(pIceAgent->timerQueueHandle, pIceAgent->iceCandidateGatheringTimerTask, (UINT64) pIceAgent));
        pIceAgent->iceCandidateGatheringTimerTask = MAX_UINT32;
    }

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    /* do not process anymore stun messages because it may need to access resources like iceCandidiate which we are
     * about to free */
    ATOMIC_STORE_BOOL(&pIceAgent->processStun, FALSE);
    pIceAgent->iceAgentStatus = STATUS_SUCCESS;
    pIceAgent->lastDataReceivedTime = INVALID_TIMESTAMP_VALUE;

    pIceAgent->relayCandidateCount = 0;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        pLocalCandidate = (PIceCandidate) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pLocalCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
            CHK_STATUS(turn_connection_shutdown(pLocalCandidate->pTurnConnection, 0));
        }
        localCandidates[localCandidateCount++] = pLocalCandidate;
    }
    CHK_STATUS(double_list_clear(pIceAgent->localCandidates, FALSE));

    /* free all candidate pairs except the selected pair */
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pNextNode = pCurNode->pNext;

        if (pIceCandidatePair != pIceAgent->pDataSendingIceCandidatePair) {
            CHK_STATUS(ice_candidate_pair_free(&pIceCandidatePair));
        }

        pCurNode = pNextNode;
    }
    CHK_STATUS(double_list_clear(pIceAgent->pIceCandidatePairs, FALSE));

    MUTEX_UNLOCK(pIceAgent->lock);
    locked = FALSE;

    /* Time given for turn to free its allocation */
    THREAD_SLEEP(HUNDREDS_OF_NANOS_IN_A_SECOND);

    /* At this point there should be no thread accessing anything in iceAgent other than
     * pIceAgent->pDataSendingIceCandidatePair and its ice candidates. Therefore safe to proceed freeing resources */

    for (i = 0; i < localCandidateCount; ++i) {
        if (localCandidates[i] != pIceAgent->pDataSendingIceCandidatePair->local) {
            if (localCandidates[i]->iceCandidateType != ICE_CANDIDATE_TYPE_RELAYED) {
                CHK_STATUS(connection_listener_remove(pIceAgent->pConnectionListener, localCandidates[i]->pSocketConnection));
                CHK_STATUS(socket_connection_free(&localCandidates[i]->pSocketConnection));
            } else {
                CHK_STATUS(turn_connection_free(&localCandidates[i]->pTurnConnection));
            }
            MEMFREE(localCandidates[i]);
        }
    }

    /* Do not free remoteCandidates because new remote candidates could be added before or while restart happens.
     * There is no way to tell which session a remote candidate belongs to. Old ones will eventually fail the
     * connectivity test so it's ok. */

    CHK_STATUS(stack_queue_clear(pIceAgent->pTriggeredCheckQueue, FALSE));

    ATOMIC_STORE_BOOL(&pIceAgent->remoteCredentialReceived, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->agentStartGathering, FALSE);
    ATOMIC_STORE_BOOL(&pIceAgent->candidateGatheringFinished, FALSE);

    pIceAgent->fsmEndTime = 0;
    pIceAgent->foundationCounter = 0;
    pIceAgent->localNetworkInterfaceCount = ARRAY_SIZE(pIceAgent->localNetworkInterfaces);
    pIceAgent->candidateGatheringEndTime = INVALID_TIMESTAMP_VALUE;

    pIceAgent->iceAgentStateTimerTask = MAX_UINT32;
    pIceAgent->keepAliveTimerTask = MAX_UINT32;
    pIceAgent->iceCandidateGatheringTimerTask = MAX_UINT32;
    pIceAgent->detectedDisconnection = FALSE;
    pIceAgent->disconnectionGracePeriodEndTime = INVALID_TIMESTAMP_VALUE;

    transaction_id_store_reset(pIceAgent->pStunBindingRequestTransactionIdStore);

    STRNCPY(pIceAgent->localUsername, localIceUfrag, MAX_ICE_CONFIG_USER_NAME_LEN);
    STRNCPY(pIceAgent->localPassword, localIcePwd, MAX_ICE_CONFIG_CREDENTIAL_LEN);

    pIceAgent->iceAgentState = ICE_AGENT_STATE_NEW;
    CHK_STATUS(state_machine_setCurrentState(pIceAgent->pStateMachine, ICE_AGENT_STATE_NEW));

    ATOMIC_STORE_BOOL(&pIceAgent->processStun, TRUE);

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_setupFsmCheckConnection(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 iceCandidatePairCount = 0;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(doubleListGetNodeCount(pIceAgent->pIceCandidatePairs, &iceCandidatePairCount));

    DLOGD("ice candidate pair count %u", iceCandidatePairCount);

    // move all candidate pairs out of frozen state
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
    }

    if (pIceAgent->pBindingRequest != NULL) {
        CHK_STATUS(stun_freePacket(&pIceAgent->pBindingRequest));
    }
    CHK_STATUS(stun_createPacket(STUN_PACKET_TYPE_BINDING_REQUEST, NULL, &pIceAgent->pBindingRequest));
    CHK_STATUS(stun_attribute_appendUsername(pIceAgent->pBindingRequest, pIceAgent->combinedUserName));
    CHK_STATUS(stun_attribute_appendPriority(pIceAgent->pBindingRequest, 0));
    CHK_STATUS(stun_attribute_appendIceControlMode(
        pIceAgent->pBindingRequest, pIceAgent->isControlling ? STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING : STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
        pIceAgent->tieBreaker));

    pIceAgent->fsmEndTime = GETTIME() + pIceAgent->kvsRtcConfiguration.iceConnectionCheckTimeout;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_keepAliveTimerCallback(UINT32 timerId, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerId);
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    BOOL locked = FALSE;
    PIceCandidatePair pIceCandidatePair = NULL;
    PDoubleListNode pCurNode = NULL;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            pIceCandidatePair->lastDataSentTime = currentTime;
            DLOGV("send keep alive");
            CHK_STATUS(ice_agent_sendStunPacket(pIceAgent->pBindingIndication, NULL, 0, pIceAgent, pIceCandidatePair->local,
                                                &pIceCandidatePair->remote->ipAddress));
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}

STATUS ice_agent_setupFsmConnected(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL, pLastDataSendingIceCandidatePair = NULL;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    // clean the last pDataSendingIceCandidatePair
    if (pIceAgent->pDataSendingIceCandidatePair != NULL) {
        MUTEX_LOCK(pIceAgent->lock);
        locked = TRUE;

        /* at this point ice restart is complete */
        ATOMIC_STORE_BOOL(&pIceAgent->restart, FALSE);
        pLastDataSendingIceCandidatePair = pIceAgent->pDataSendingIceCandidatePair;
        pIceAgent->pDataSendingIceCandidatePair = NULL;

        MUTEX_UNLOCK(pIceAgent->lock);
        locked = FALSE;

        /* If pDataSendingIceCandidatePair is not NULL, then it must be the data sending pair before ice restart.
         * Free its resource here since not there is a new connected pair to replace it. */
        if (IS_CANN_PAIR_SENDING_FROM_RELAYED(pLastDataSendingIceCandidatePair)) {
            CHK_STATUS(turn_connection_shutdown(pLastDataSendingIceCandidatePair->local->pTurnConnection, KVS_ICE_TURN_CONNECTION_SHUTDOWN_TIMEOUT));
            CHK_STATUS(turn_connection_free(&pLastDataSendingIceCandidatePair->local->pTurnConnection));
        } else {
            CHK_STATUS(connection_listener_remove(pIceAgent->pConnectionListener, pLastDataSendingIceCandidatePair->local->pSocketConnection));
            CHK_STATUS(socket_connection_free(&pLastDataSendingIceCandidatePair->local->pSocketConnection));
        }
        MEMFREE(pLastDataSendingIceCandidatePair->local);
        CHK_STATUS(ice_candidate_pair_free(&pLastDataSendingIceCandidatePair));
    }

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // use the first connected pair as the data sending pair
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            pIceAgent->pDataSendingIceCandidatePair = pIceCandidatePair;
            retStatus = ice_agent_updateSelectedLocalRemoteCandidateStats(pIceAgent); //!< for the stat.
            if (STATUS_FAILED(retStatus)) {
                DLOGW("Failed to update candidate stats with status code 0x%08x", retStatus);
            }
            break;
        }
    }

    // schedule sending keep alive
    CHK_STATUS(timer_queue_addTimer(pIceAgent->timerQueueHandle, KVS_ICE_DEFAULT_TIMER_START_DELAY, KVS_ICE_SEND_KEEP_ALIVE_INTERVAL,
                                    ice_agent_keepAliveTimerCallback, (UINT64) pIceAgent, &pIceAgent->keepAliveTimerTask));

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_setupFsmNominating(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;
    // only controlling ice agent needs to send the "use-candidate" packet.
    //
    if (pIceAgent->isControlling) {
        CHK_STATUS(ice_agent_nominateCandidatePair(pIceAgent));

        if (pIceAgent->pBindingRequest != NULL) {
            CHK_STATUS(stun_freePacket(&pIceAgent->pBindingRequest));
        }
        CHK_STATUS(stun_createPacket(STUN_PACKET_TYPE_BINDING_REQUEST, NULL, &pIceAgent->pBindingRequest));
        CHK_STATUS(stun_attribute_appendUsername(pIceAgent->pBindingRequest, pIceAgent->combinedUserName));
        CHK_STATUS(stun_attribute_appendPriority(pIceAgent->pBindingRequest, 0));
        CHK_STATUS(stun_attribute_appendIceControlMode(pIceAgent->pBindingRequest, STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING, pIceAgent->tieBreaker));
        CHK_STATUS(stun_attribute_appendFlag(pIceAgent->pBindingRequest, STUN_ATTRIBUTE_TYPE_USE_CANDIDATE));
    }

    pIceAgent->fsmEndTime = GETTIME() + pIceAgent->kvsRtcConfiguration.iceCandidateNominationTimeout;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_setupFsmReady(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidatePair pNominatedAndValidCandidatePair = NULL;
    CHAR ipAddrStr[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    PDoubleListNode pCurNode = NULL, pNodeToDelete = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    BOOL locked = FALSE;
    PIceCandidate pIceCandidate = NULL;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // change the interval.
    CHK_STATUS(timer_queue_updateTimerPeriod(pIceAgent->timerQueueHandle, (UINT64) pIceAgent, pIceAgent->iceAgentStateTimerTask,
                                             KVS_ICE_STATE_READY_TIMER_POLLING_INTERVAL));

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // find nominated pair
    // #TBD, pDataSendingIceCandidatePair may be changed.
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));

    while (pCurNode != NULL && pNominatedAndValidCandidatePair == NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->nominated && pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            pNominatedAndValidCandidatePair = pIceCandidatePair;
            break;
        }
    }

    CHK(pNominatedAndValidCandidatePair != NULL, STATUS_ICE_NO_NOMINATED_VALID_CANDIDATE_PAIR_AVAILABLE);

    pIceAgent->pDataSendingIceCandidatePair = pNominatedAndValidCandidatePair;
    CHK_STATUS(net_getIpAddrStr(&pIceAgent->pDataSendingIceCandidatePair->local->ipAddress, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
    DLOGD("Selected pair %s_%s, local candidate type: %s. Round trip time %u ms", pIceAgent->pDataSendingIceCandidatePair->local->id,
          pIceAgent->pDataSendingIceCandidatePair->remote->id,
          iceAgentGetCandidateTypeStr(pIceAgent->pDataSendingIceCandidatePair->local->iceCandidateType),
          pIceAgent->pDataSendingIceCandidatePair->roundTripTime / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);

    /* no state timeout for ready state */
    pIceAgent->fsmEndTime = INVALID_TIMESTAMP_VALUE;

    /* shutdown turn allocations that are not needed. Invalidate not selected local ice candidates. */
    DLOGD("Freeing Turn allocations that are not selected. Total turn allocation count %u", pIceAgent->relayCandidateCount);

    // remove all the ice candidate pair except selected one.
    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidate = (PIceCandidate) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidate != pIceAgent->pDataSendingIceCandidatePair->local) {
            if (pIceCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
                CHK_STATUS(turn_connection_shutdown(pIceCandidate->pTurnConnection, 0));
            }
            pIceCandidate->state = ICE_CANDIDATE_STATE_INVALID;
        }
    }
    CHK_STATUS(ice_agent_invalidateCandidatePair(pIceAgent));

    /* Free not selected ice candidate pairs */
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pNodeToDelete = pCurNode;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_FAILED) {
            ice_candidate_pair_free(&pIceCandidatePair);
            doubleListDeleteNode(pIceAgent->pIceCandidatePairs, pNodeToDelete);
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_candidate_pair_calculateOrdinaryCheckRto(PIceAgent pIceAgent, PINT64 pRtoSlot)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    INT64 rtoSlot = 0;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        switch (pIceCandidatePair->state) {
            case ICE_CANDIDATE_PAIR_STATE_WAITING:
            case ICE_CANDIDATE_PAIR_STATE_IN_PROGRESS:
                rtoSlot++;
                break;
            default:
                break;
        }
    }
CleanUp:

    CHK_LOG_ERR(retStatus);
    *pRtoSlot = rtoSlot;
    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_create(PIceAgent pIceAgent, PIceCandidate pIceCandidate, BOOL isRemoteCandidate)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    UINT64 data;
    PDoubleListNode pCurNode = NULL;
    PDoubleList pDoubleList = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    BOOL freeObjOnFailure = TRUE;
    PIceCandidate pCurrentIceCandidate = NULL;

    CHK(pIceAgent != NULL && pIceCandidate != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK_WARN(pIceCandidate->state == ICE_CANDIDATE_STATE_VALID, retStatus, "New ice candidate need to be valid to form pairs");

    // if pIceCandidate is a remote candidate, then form pairs with every single valid local candidate. Otherwize,
    // form pairs with every single valid remote candidate
    pDoubleList = isRemoteCandidate ? pIceAgent->localCandidates : pIceAgent->remoteCandidates;

    CHK_STATUS(double_list_getHeadNode(pDoubleList, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurrentIceCandidate = (PIceCandidate) data;
        pCurNode = pCurNode->pNext;

        // https://tools.ietf.org/html/rfc8445#section-6.1.2.2
        // pair local and remote candidates with the same family
        if (pCurrentIceCandidate->state == ICE_CANDIDATE_STATE_VALID && pCurrentIceCandidate->ipAddress.family == pIceCandidate->ipAddress.family) {
            // allocate the memory of ice candidate pair.
            pIceCandidatePair = (PIceCandidatePair) MEMCALLOC(1, SIZEOF(IceCandidatePair));
            CHK(pIceCandidatePair != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);

            if (isRemoteCandidate) {
                pIceCandidatePair->local = (PIceCandidate) data;
                pIceCandidatePair->remote = pIceCandidate;
            } else {
                pIceCandidatePair->local = pIceCandidate;
                pIceCandidatePair->remote = (PIceCandidate) data;
            }
            pIceCandidatePair->nominated = FALSE;

            // ensure the new pair will go through connectivity check as soon as possible
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            CHK_STATUS(ice_candidate_pair_calculateOrdinaryCheckRto(pIceAgent, &pIceCandidatePair->rtoSlot));
            CHK_STATUS(transaction_id_store_create(DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT, &pIceCandidatePair->pTransactionIdStore));
            CHK_STATUS(hash_table_createWithParams(ICE_HASH_TABLE_BUCKET_COUNT, ICE_HASH_TABLE_BUCKET_LENGTH, &pIceCandidatePair->requestSentTime));

            pIceCandidatePair->lastDataSentTime = 0;
            STRNCPY(pIceCandidatePair->rtcIceCandidatePairDiagnostics.localCandidateId, pIceCandidatePair->local->id,
                    ARRAY_SIZE(pIceCandidatePair->rtcIceCandidatePairDiagnostics.localCandidateId));
            STRNCPY(pIceCandidatePair->rtcIceCandidatePairDiagnostics.remoteCandidateId, pIceCandidatePair->remote->id,
                    ARRAY_SIZE(pIceCandidatePair->rtcIceCandidatePairDiagnostics.remoteCandidateId));
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.state = pIceCandidatePair->state;
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.nominated = pIceCandidatePair->nominated;
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.lastPacketSentTimestamp = pIceCandidatePair->lastDataSentTime;
            pIceCandidatePair->firstStunRequest = TRUE;
            pIceCandidatePair->priority = ice_candidate_pair_computePriority(pIceCandidatePair, pIceAgent->isControlling);
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.totalRoundTripTime = 0.0;
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.currentRoundTripTime = 0.0;

            // Set data sending ICE candidate pair stats
            NULLABLE_SET_EMPTY(pIceCandidatePair->rtcIceCandidatePairDiagnostics.circuitBreakerTriggerCount);
            CHK_STATUS(ice_candidate_pair_insert(pIceAgent->pIceCandidatePairs, pIceCandidatePair));
            freeObjOnFailure = FALSE;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && freeObjOnFailure) {
        ice_candidate_pair_free(&pIceCandidatePair);
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_free(PIceCandidatePair* ppIceCandidatePair)
{
    ICE_AGENT_ENTRY();
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidatePair pIceCandidatePair = NULL;

    CHK(ppIceCandidatePair != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // free is idempotent
    CHK(*ppIceCandidatePair != NULL, retStatus);
    pIceCandidatePair = *ppIceCandidatePair;

    CHK_LOG_ERR(transaction_id_store_free(&pIceCandidatePair->pTransactionIdStore));
    CHK_LOG_ERR(hash_table_free(pIceCandidatePair->requestSentTime));
    pIceCandidatePair->requestSentTime = NULL;
    SAFE_MEMFREE(pIceCandidatePair);

CleanUp:

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_insert(PDoubleList pIceCandidatePairs, PIceCandidatePair pNewPair)
{
    ICE_AGENT_ENTRY();
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pCurIceCandidatePair = NULL;

    CHK(pIceCandidatePairs != NULL && pNewPair != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pIceCandidatePairs, &pCurNode));

    while (pCurNode != NULL) {
        pCurIceCandidatePair = (PIceCandidatePair) pCurNode->data;

        // insert new candidate pair ordered by priority from max to min.
        if (pCurIceCandidatePair->priority <= pNewPair->priority) {
            break;
        }
        pCurNode = pCurNode->pNext;
    }

    if (pCurNode != NULL) {
        CHK_STATUS(double_list_insertItemBefore(pIceCandidatePairs, pCurNode, (UINT64) pNewPair));
    } else {
        CHK_STATUS(double_list_insertItemTail(pIceCandidatePairs, (UINT64) pNewPair));
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_queryByLocalSocketConnectionAndRemoteAddr(PIceAgent pIceAgent, PSocketConnection pSocketConnection,
                                                                    PKvsIpAddress pRemoteAddr, BOOL checkPort, PIceCandidatePair* ppIceCandidatePair)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    UINT32 addrLen;
    PIceCandidatePair pTargetIceCandidatePair = NULL, pIceCandidatePair = NULL;
    PDoubleListNode pCurNode = NULL;

    CHK(pIceAgent != NULL && ppIceCandidatePair != NULL && pSocketConnection != NULL, STATUS_ICE_AGENT_NULL_ARG);

    addrLen = IS_IPV4_ADDR(pRemoteAddr) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH;

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));

    while (pCurNode != NULL && pTargetIceCandidatePair == NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;
        // check condition.
        if (pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_FAILED && pIceCandidatePair->local->pSocketConnection == pSocketConnection &&
            pIceCandidatePair->remote->ipAddress.family == pRemoteAddr->family &&
            MEMCMP(pIceCandidatePair->remote->ipAddress.address, pRemoteAddr->address, addrLen) == 0 &&
            (!checkPort || pIceCandidatePair->remote->ipAddress.port == pRemoteAddr->port)) {
            pTargetIceCandidatePair = pIceCandidatePair;
        }
    }

CleanUp:

    if (ppIceCandidatePair != NULL) {
        *ppIceCandidatePair = pTargetIceCandidatePair;
    }

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_pruneUnconnected(PIceAgent pIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL, pNextNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;

        if (pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            // backup next node as we will lose that after deleting pCurNode.
            pNextNode = pCurNode->pNext;
            CHK_STATUS(ice_candidate_pair_free(&pIceCandidatePair));
            CHK_STATUS(doubleListDeleteNode(pIceAgent->pIceCandidatePairs, pCurNode));
            pCurNode = pNextNode;
        } else {
            pCurNode = pCurNode->pNext;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_candidate_pair_checkConnection(PStunPacket pStunBindingRequest, PIceAgent pIceAgent, PIceCandidatePair pIceCandidatePair)
{
    STATUS retStatus = STATUS_SUCCESS;
    PStunAttributePriority pStunAttributePriority = NULL;
    UINT32 checkSum = 0;

    CHK(pStunBindingRequest != NULL && pIceAgent != NULL && pIceCandidatePair != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK_STATUS(stun_attribute_getByType(pStunBindingRequest, STUN_ATTRIBUTE_TYPE_PRIORITY, (PStunAttributeHeader*) &pStunAttributePriority));
    CHK(pStunAttributePriority != NULL, STATUS_ICE_AGENT_INVALID_ARG);

    // update priority and transaction id
    pStunAttributePriority->priority = pIceCandidatePair->local->priority;
    // generate the transacton id randomly.
    CHK_STATUS(ice_utils_generateTransactionId(pStunBindingRequest->header.transactionId, ARRAY_SIZE(pStunBindingRequest->header.transactionId)));
    CHK(pIceCandidatePair->pTransactionIdStore != NULL, STATUS_INVALID_OPERATION);
    // record the transaction id.
    transaction_id_store_insert(pIceCandidatePair->pTransactionIdStore, pStunBindingRequest->header.transactionId);

    // for the stat
    checkSum = COMPUTE_CRC32(pStunBindingRequest->header.transactionId, ARRAY_SIZE(pStunBindingRequest->header.transactionId));
    CHK_STATUS(hashTableUpsert(pIceCandidatePair->requestSentTime, checkSum, GETTIME()));

    if (pIceCandidatePair->local->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
        pIceAgent->rtcIceServerDiagnostics[pIceCandidatePair->local->iceServerIndex].totalRequestsSent++;
        CHK_STATUS(hashTableUpsert(pIceAgent->requestTimestampDiagnostics, checkSum, GETTIME()));
    }
    // send the stun packet.
    CHK_STATUS(ice_agent_sendStunPacket(pStunBindingRequest, (PBYTE) pIceAgent->remotePassword,
                                        (UINT32) STRLEN(pIceAgent->remotePassword) * SIZEOF(CHAR), pIceAgent, pIceCandidatePair->local,
                                        &pIceCandidatePair->remote->ipAddress));

    CHK_STATUS(ice_candidate_pair_calculateOrdinaryCheckRto(pIceAgent, &pIceCandidatePair->rtoSlot));
    pIceCandidatePair->rtoSlot = MAX(ICE_AGENT_TIMER_RTO_MAX, pIceCandidatePair->rtoSlot);
    pIceCandidatePair->rtcIceCandidatePairDiagnostics.lastRequestTimestamp = GETTIME();
    pIceCandidatePair->rtcIceCandidatePairDiagnostics.requestsSent++;
CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS ice_agent_checkCandidatePairConnection(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL triggeredCheckQueueEmpty;
    UINT64 data;
    PIceCandidatePair pIceCandidatePair = NULL;
    PDoubleListNode pCurNode = NULL;
    BOOL locked = FALSE;
    UINT64 startTime = 0;
    UINT64 endTime = 0;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    startTime = GETTIME();
    // Assuming pIceAgent->candidatePairs is sorted by priority
    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    CHK_STATUS(stack_queue_isEmpty(pIceAgent->pTriggeredCheckQueue, &triggeredCheckQueueEmpty));

    // The original desgin of linux based webrtc sdk does not control the throughput of the outbound packets, and does not follow the rfc8445 either.
    // triggered connectivity check.
    if (!triggeredCheckQueueEmpty) {
        // if pTriggeredCheckQueue is not empty, check its candidate pair first
        CHK_STATUS(stack_queue_dequeue(pIceAgent->pTriggeredCheckQueue, &data));
        pIceCandidatePair = (PIceCandidatePair) data;
        CHK_STATUS(ice_candidate_pair_checkConnection(pIceAgent->pBindingRequest, pIceAgent, pIceCandidatePair));
    } else {
        // ordinary connectivity check.
        // the triggered queue is empty.
        CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
        while (pCurNode != NULL) {
            pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
            pCurNode = pCurNode->pNext;
            pIceCandidatePair->rtoSlot--;
            if (pIceCandidatePair->rtoSlot < 0) {
                CHK_STATUS(ice_candidate_pair_checkConnection(pIceAgent->pBindingRequest, pIceAgent, pIceCandidatePair));
            }
        }
    }

CleanUp:

    endTime = GETTIME();
    if ((endTime - startTime) >= pIceAgent->kvsRtcConfiguration.iceConnectionCheckPollingInterval) {
        DLOGW("check candidate pair time: %" PRIu64 ". you need to check this interval setting.",
              (endTime - startTime) / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
    }

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_nominateCandidatePair(PIceAgent pIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidatePair pNominatedCandidatePair = NULL, pIceCandidatePair = NULL;
    UINT32 iceCandidatePairsCount = FALSE;
    PDoubleListNode pCurNode = NULL;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    // Assume holding pIceAgent->lock
    // do nothing if not controlling
    CHK(pIceAgent->isControlling, retStatus);

    DLOGD("Nominating candidate pair");

    CHK_STATUS(doubleListGetNodeCount(pIceAgent->pIceCandidatePairs, &iceCandidatePairsCount));
    CHK(iceCandidatePairsCount > 0, STATUS_ICE_CANDIDATE_PAIR_LIST_EMPTY);

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL && pNominatedCandidatePair == NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        // nominate first connected iceCandidatePair. it should have the highest priority since
        // pIceCandidatePairs is already sorted by priority.
        if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
            pNominatedCandidatePair = pIceCandidatePair;
        }
    }

    // should have a nominated pair.
    CHK(pNominatedCandidatePair != NULL, STATUS_ICE_FAILED_TO_NOMINATE_CANDIDATE_PAIR);

    pNominatedCandidatePair->nominated = TRUE;

    // reset transaction id list to ignore future connectivity check response.
    // #TBD,
    transaction_id_store_reset(pNominatedCandidatePair->pTransactionIdStore);

    // move not-nominated candidate pairs to frozen state so the second connectivity check only checks the nominated pair.
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (!pIceCandidatePair->nominated) {
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}

STATUS ice_agent_invalidateCandidatePair(PIceAgent pIceAgent)
{
    ICE_AGENT_ENTRY();

    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidatePair pIceCandidatePair = NULL;
    PDoubleListNode pCurNode = NULL;

    // Assume holding pIceAgent->lock
    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->local->state != ICE_CANDIDATE_STATE_VALID) {
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    ICE_AGENT_LEAVE();
    return retStatus;
}
/**
 * @brief receive one stun packet can not match the ip and port of local/remote, so it may be one reflexive candidate.
 */
static STATUS ice_agent_checkPeerReflexiveCandidate(PIceAgent pIceAgent, PKvsIpAddress pIpAddress, UINT32 priority, BOOL isRemote,
                                                    PSocketConnection pSocketConnection)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidate pIceCandidate = NULL, pLocalIceCandidate = NULL;
    BOOL freeIceCandidateOnError = TRUE;
    UINT32 candidateCount;

    // remote candidate dont have socketConnection
    CHK(pIceAgent != NULL && pIpAddress != NULL && (isRemote || pSocketConnection != NULL), STATUS_ICE_AGENT_NULL_ARG);
    //
    if (!isRemote) {
        // local peer reflexive candidate replaces existing local candidate because the peer sees different address
        // for this local candidate.
        CHK_STATUS(ice_agent_findCandidateByIp(pIpAddress, pIceAgent->localCandidates, &pIceCandidate));
        CHK(pIceCandidate == NULL, retStatus); // return early if duplicated

        ice_agent_findCandidateBySocketConnection(pSocketConnection, pIceAgent->localCandidates, &pLocalIceCandidate);
        pLocalIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
        pLocalIceCandidate->ipAddress = *pIpAddress;
        ice_candidate_log(pLocalIceCandidate);
        CHK(FALSE, retStatus);
    }

    CHK_STATUS(doubleListGetNodeCount(pIceAgent->remoteCandidates, &candidateCount));
    CHK_WARN(candidateCount < KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT, retStatus, "max remote candidate count exceeded"); // return early if limit exceeded
    CHK_STATUS(ice_agent_findCandidateByIp(pIpAddress, pIceAgent->remoteCandidates, &pIceCandidate));
    CHK(pIceCandidate == NULL, retStatus); // return early if duplicated
    DLOGD("New remote peer reflexive candidate found");

    CHK((pIceCandidate = MEMCALLOC(1, SIZEOF(IceCandidate))) != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);
    json_generateSafeString(pIceCandidate->id, ARRAY_SIZE(pIceCandidate->id));
    pIceCandidate->isRemote = TRUE;
    pIceCandidate->ipAddress = *pIpAddress;
    pIceCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
    pIceCandidate->priority = priority;
    pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;
    pIceCandidate->pSocketConnection = NULL; // remote candidate dont have PSocketConnection

    CHK_STATUS(double_list_insertItemHead(pIceAgent->remoteCandidates, (UINT64) pIceCandidate));
    freeIceCandidateOnError = FALSE;

    CHK_STATUS(ice_candidate_pair_create(pIceAgent, pIceCandidate, isRemote));

    ice_candidate_log(pIceCandidate);

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && freeIceCandidateOnError) {
        MEMFREE(pIceCandidate);
    }

    return retStatus;
}
/**
 * @brief handle the incoming stun packets.
 *
 * @param[in] pIceAgent
 * @param[in] pBuffer
 * @param[in] bufferLen
 * @param[in] pSocketConnection
 * @param[in] pSrcAddr
 * @param[in] pDestAddr
 *
 * @return STATUS status of execution.
 */
STATUS ice_agent_handleInboundStunPacket(PIceAgent pIceAgent, PBYTE pBuffer, UINT32 bufferLen, PSocketConnection pSocketConnection,
                                         PKvsIpAddress pSrcAddr, PKvsIpAddress pDestAddr)
{
    UNUSED_PARAM(pDestAddr);

    STATUS retStatus = STATUS_SUCCESS;
    PStunPacket pStunPacket = NULL, pStunResponse = NULL;
    PStunAttributeHeader pStunAttr = NULL;
    UINT16 stunPacketType = 0;
    PIceCandidatePair pIceCandidatePair = NULL;
    PStunAttributeAddress pStunAttributeAddress = NULL;
    PStunAttributePriority pStunAttributePriority = NULL;
    UINT32 priority = 0;
    PIceCandidate pIceCandidate = NULL;
    CHAR ipAddrStr[KVS_IP_ADDRESS_STRING_BUFFER_LEN], ipAddrStr2[KVS_IP_ADDRESS_STRING_BUFFER_LEN];
    PCHAR hexStr = NULL;
    UINT32 hexStrLen = 0, checkSum = 0;
    UINT64 requestSentTime = 0;
    UINT64 connectivityCheckRequestsReceived = 0;
    UINT64 connectivityCheckResponsesSent = 0;
    UINT64 connectivityCheckResponsesReceived = 0;

    // need to determine stunPacketType before deserializing because different password should be used depending on the packet type
    stunPacketType = (UINT16) getInt16(*((PUINT16) pBuffer));

    switch (stunPacketType) {
        case STUN_PACKET_TYPE_BINDING_REQUEST:
            connectivityCheckRequestsReceived++;
            // decode stun packet.
            CHK_STATUS(stun_deserializePacket(pBuffer, bufferLen, (PBYTE) pIceAgent->localPassword,
                                              (UINT32) STRLEN(pIceAgent->localPassword) * SIZEOF(CHAR), &pStunPacket));
            // create the response of this stun packet.
            CHK_STATUS(stun_createPacket(STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS, pStunPacket->header.transactionId, &pStunResponse));
            CHK_STATUS(stun_attribute_appendAddress(pStunResponse, STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS, pSrcAddr));
            CHK_STATUS(stun_attribute_appendIceControlMode(
                pStunResponse, pIceAgent->isControlling ? STUN_ATTRIBUTE_TYPE_ICE_CONTROLLING : STUN_ATTRIBUTE_TYPE_ICE_CONTROLLED,
                pIceAgent->tieBreaker));
            // decode this stun packet.
            CHK_STATUS(stun_attribute_getByType(pStunPacket, STUN_ATTRIBUTE_TYPE_PRIORITY, (PStunAttributeHeader*) &pStunAttributePriority));
            priority = pStunAttributePriority == NULL ? 0 : pStunAttributePriority->priority;
            // find the matched local ice canidate.
            CHK_STATUS(ice_agent_checkPeerReflexiveCandidate(pIceAgent, pSrcAddr, priority, TRUE, 0));

            CHK_STATUS(ice_agent_findCandidateBySocketConnection(pSocketConnection, pIceAgent->localCandidates, &pIceCandidate));
            CHK_WARN(pIceCandidate != NULL, STATUS_ICE_AGENT_MISSING_LOCAL_CANDIDATE, "Could not find local candidate to send STUN response");
            // send the response of this stun packet.
            CHK_STATUS(ice_agent_sendStunPacket(pStunResponse, (PBYTE) pIceAgent->localPassword,
                                                (UINT32) STRLEN(pIceAgent->localPassword) * SIZEOF(CHAR), pIceAgent, pIceCandidate, pSrcAddr));

            connectivityCheckResponsesSent++;
            // return early if there is no candidate pair. This can happen when we get connectivity check from the peer
            // before we receive the answer.
            CHK_STATUS(
                ice_candidate_pair_queryByLocalSocketConnectionAndRemoteAddr(pIceAgent, pSocketConnection, pSrcAddr, TRUE, &pIceCandidatePair));
            CHK(pIceCandidatePair != NULL, STATUS_ICE_AGENT_NO_MATCH_ICE_CANDIDATE_PAIR);

            if (!pIceCandidatePair->nominated) {
                CHK_STATUS(stun_attribute_getByType(pStunPacket, STUN_ATTRIBUTE_TYPE_USE_CANDIDATE, &pStunAttr));
                if (pStunAttr != NULL) {
                    DLOGD("received candidate with USE_CANDIDATE flag, local candidate type %s.",
                          iceAgentGetCandidateTypeStr(pIceCandidatePair->local->iceCandidateType));
                    pIceCandidatePair->nominated = TRUE;
                }
            }

            // schedule a connectivity check for the pair
            if (pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN || pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_WAITING ||
                pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_IN_PROGRESS) {
                PIceCandidatePair pHeadPair = NULL;
                // do not exit if there is an error.
                stackQueuePeek(pIceAgent->pTriggeredCheckQueue, (PUINT64) &pHeadPair);
                if (pHeadPair != NULL) {
                    if (pHeadPair->priority < pIceCandidatePair->priority) {
                        DLOGW("the priority of triggered check queue may be reverse.");
                    }
                }
                CHK_STATUS(stack_queue_enqueue(pIceAgent->pTriggeredCheckQueue, (UINT64) pIceCandidatePair));
            }

            if (pIceCandidatePair == pIceAgent->pDataSendingIceCandidatePair) {
                pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.requestsReceived += connectivityCheckRequestsReceived;
                pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.responsesSent += connectivityCheckResponsesSent;
                pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.nominated = pIceCandidatePair->nominated;
            }
            break;

        case STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS:
            connectivityCheckResponsesReceived++;
            checkSum = COMPUTE_CRC32(pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET, STUN_TRANSACTION_ID_LEN);
            // check if Binding Response is for finding srflx candidate
            // the response is for the stun req which we send.
            if (transaction_id_store_isExisted(pIceAgent->pStunBindingRequestTransactionIdStore, pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET)) {
                //
                CHK_STATUS(ice_agent_findCandidateBySocketConnection(pSocketConnection, pIceAgent->localCandidates, &pIceCandidate));
                CHK_WARN(pIceCandidate != NULL, STATUS_ICE_AGENT_MISSING_LOCAL_SOCKET,
                         "Local candidate with socket %d not found. Dropping STUN binding success response", pSocketConnection->localSocket);

                // Update round trip time for serial reflexive candidate
                pIceAgent->rtcIceServerDiagnostics[pIceCandidate->iceServerIndex].totalResponsesReceived++;
                retStatus = hash_table_get(pIceAgent->requestTimestampDiagnostics, checkSum, &requestSentTime);
                if (retStatus != STATUS_SUCCESS) {
                    DLOGW("Unable to fetch request Timestamp from the hash table. No update to totalRoundTripTime (error code: 0x%08x)", retStatus);
                } else {
                    pIceAgent->rtcIceServerDiagnostics[pIceCandidate->iceServerIndex].totalRoundTripTime += GETTIME() - requestSentTime;
                    CHK_STATUS(hash_table_remove(pIceAgent->requestTimestampDiagnostics, checkSum));
                }

                CHK_STATUS(stun_deserializePacket(pBuffer, bufferLen, NULL, 0, &pStunPacket));
                CHK_STATUS(stun_attribute_getByType(pStunPacket, STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS, &pStunAttr));
                CHK_WARN(pStunAttr != NULL, STATUS_ICE_AGENT_NO_MAPPED_ADDRESS,
                         "No mapped address attribute found in STUN binding response. Dropping Packet");

                pStunAttributeAddress = (PStunAttributeAddress) pStunAttr;
                // update the ip address of ice candidate and set the state of the ice candidate as valid.
                CHK_STATUS(ice_candidate_updateAddress(pIceCandidate, &pStunAttributeAddress->address));
                CHK(FALSE, retStatus);
            }

            // can not find the transaction id of binding req.
            CHK_STATUS(
                ice_candidate_pair_queryByLocalSocketConnectionAndRemoteAddr(pIceAgent, pSocketConnection, pSrcAddr, TRUE, &pIceCandidatePair));
            if (pIceCandidatePair == NULL) {
                // can not find the ice candidate pair under the current condition.
                CHK_STATUS(net_getIpAddrStr(pSrcAddr, ipAddrStr, ARRAY_SIZE(ipAddrStr)));
                CHK_STATUS(net_getIpAddrStr(&pSocketConnection->hostIpAddr, ipAddrStr2, ARRAY_SIZE(ipAddrStr2)));
                CHK_WARN(FALSE, STATUS_ICE_AGENT_NO_CANDIDATE_PAIR,
                         "Cannot find candidate pair with local candidate %s and remote candidate %s. Dropping STUN binding success response",
                         ipAddrStr2, ipAddrStr);
            }
            // check the transation id of stun packet.
            CHK_WARN(transaction_id_store_isExisted(pIceCandidatePair->pTransactionIdStore, pBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET),
                     STATUS_ICE_AGENT_NO_MATCH_TRANSACTION, "Dropping response packet because transaction id does not match");

            // Update round trip time and responses received only for relay candidates.
            if (pIceCandidatePair->local->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED) {
                pIceAgent->rtcIceServerDiagnostics[pIceCandidatePair->local->iceServerIndex].totalResponsesReceived++;
                retStatus = hash_table_get(pIceAgent->requestTimestampDiagnostics, checkSum, &requestSentTime);
                if (retStatus != STATUS_SUCCESS) {
                    DLOGW("Unable to fetch request Timestamp from the hash table. No update to totalRoundTripTime (error code: 0x%08x)", retStatus);
                } else {
                    pIceAgent->rtcIceServerDiagnostics[pIceCandidatePair->local->iceServerIndex].totalRoundTripTime += GETTIME() - requestSentTime;
                    CHK_STATUS(hash_table_remove(pIceAgent->requestTimestampDiagnostics, checkSum));
                }
            }
            CHK_STATUS(stun_deserializePacket(pBuffer, bufferLen, (PBYTE) pIceAgent->remotePassword,
                                              (UINT32) STRLEN(pIceAgent->remotePassword) * SIZEOF(CHAR), &pStunPacket));
            CHK_STATUS(stun_attribute_getByType(pStunPacket, STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS, &pStunAttr));
            CHK_WARN(pStunAttr != NULL, STATUS_ICE_AGENT_NO_MATCH_ATTR, "No mapped address attribute found in STUN response. Dropping Packet");

            pStunAttributeAddress = (PStunAttributeAddress) pStunAttr;

            if (!net_compareIpAddress(&pStunAttributeAddress->address, &pIceCandidatePair->local->ipAddress, FALSE)) {
                // this can happen for host and server reflexive candidates. If the peer
                // is in the same subnet, server reflexive candidate's binding response's xor mapped ip address will be
                // the host candidate ip address. In this case we will ignore the packet since the host candidate will
                // be getting its own response for the connection check.
                DLOGD("local candidate ip address does not match with xor mapped address in binding response");

                // we have a peer reflexive local candidate
                CHK_STATUS(ice_agent_checkPeerReflexiveCandidate(pIceAgent, &pStunAttributeAddress->address, pIceCandidatePair->local->priority,
                                                                 FALSE, pSocketConnection));

                CHK(FALSE, retStatus);
            }

            // this candidate pair is succeeded.
            // #TBD, can be used to notify the ice agent fsm of this change.
            if (pIceCandidatePair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                retStatus = hash_table_get(pIceCandidatePair->requestSentTime, checkSum, &requestSentTime);
                if (retStatus != STATUS_SUCCESS) {
                    DLOGW("Unable to fetch request Timestamp from the hash table. No update to totalRoundTripTime (error code: 0x%08x)", retStatus);
                } else {
                    pIceCandidatePair->roundTripTime = GETTIME() - requestSentTime;
                    DLOGD("Ice candidate pair %s_%s is connected. Round trip time: %" PRIu64 "ms", pIceCandidatePair->local->id,
                          pIceCandidatePair->remote->id, pIceCandidatePair->roundTripTime / HUNDREDS_OF_NANOS_IN_A_MILLISECOND);
                    pIceCandidatePair->rtcIceCandidatePairDiagnostics.currentRoundTripTime =
                        (DOUBLE) (pIceCandidatePair->roundTripTime) / HUNDREDS_OF_NANOS_IN_A_SECOND;
                    pIceCandidatePair->rtcIceCandidatePairDiagnostics.totalRoundTripTime +=
                        (DOUBLE) (pIceCandidatePair->roundTripTime) / HUNDREDS_OF_NANOS_IN_A_SECOND;

                    CHK_STATUS(hash_table_remove(pIceCandidatePair->requestSentTime, checkSum));
                }
            }

            pIceCandidatePair->rtcIceCandidatePairDiagnostics.responsesReceived += connectivityCheckResponsesReceived;
            pIceCandidatePair->rtcIceCandidatePairDiagnostics.lastResponseTimestamp = GETTIME();
            break;

        case STUN_PACKET_TYPE_BINDING_INDICATION:
            DLOGD("Received STUN binding indication");
            break;
        case STUN_PACKET_TYPE_BINDING_RESPONSE_ERROR:
            // STUN_PACKET_IS_TYPE_ERROR(pBuffer), retStatus)
            DLOGW("binding response error");
            break;
        default:
            CHK_STATUS(hexEncode(pBuffer, bufferLen, NULL, &hexStrLen));
            hexStr = MEMCALLOC(1, hexStrLen * SIZEOF(CHAR));
            CHK(hexStr != NULL, STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);
            CHK_STATUS(hexEncode(pBuffer, bufferLen, hexStr, &hexStrLen));
            DLOGW("Dropping unrecognized STUN packet. Packet type: 0x%02x. Packet content: \n\t%s", stunPacketType, hexStr);
            MEMFREE(hexStr);
            break;
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (pStunPacket != NULL) {
        stun_freePacket(&pStunPacket);
    }

    if (pStunResponse != NULL) {
        stun_freePacket(&pStunResponse);
    }

    // TODO send error packet

    return retStatus;
}
/**
 * @brief handle the incoming packets from the sockete of ice candidate.
 *
 * @param[in] customData the user data.
 * @param[in] pSocketConnection the context of the socket connection.
 * @param[in] pBuffer the buffer of the packet.
 * @param[in] bufferLen the length of the buffer.
 * @param[in] pSrc the source ip address.
 * @param[in] pDest the destination ip address.
 *
 * @return STATUS status of execution.
 */
STATUS ice_agent_handleInboundData(UINT64 customData, PSocketConnection pSocketConnection, PBYTE pBuffer, UINT32 bufferLen, PKvsIpAddress pSrc,
                                   PKvsIpAddress pDest)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceAgent pIceAgent = (PIceAgent) customData;
    BOOL locked = FALSE;
    UINT32 addrLen = 0;
    CHK(pIceAgent != NULL && pSocketConnection != NULL, STATUS_ICE_AGENT_NULL_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    pIceAgent->lastDataReceivedTime = GETTIME();

    // for stun packets, first 8 bytes are 4 byte type and length, then 4 byte magic byte
    if ((bufferLen < 8 || !IS_STUN_PACKET(pBuffer)) && pIceAgent->iceAgentCallbacks.inboundPacketFn != NULL) {
        // release lock early
        MUTEX_UNLOCK(pIceAgent->lock);
        locked = FALSE;
        // redirect packets to peer connection layer.
        pIceAgent->iceAgentCallbacks.inboundPacketFn(pIceAgent->iceAgentCallbacks.customData, pBuffer, bufferLen);

        MUTEX_LOCK(pIceAgent->lock);
        locked = TRUE;
        addrLen = IS_IPV4_ADDR(pSrc) ? IPV4_ADDRESS_LENGTH : IPV6_ADDRESS_LENGTH;
        if (pIceAgent->pDataSendingIceCandidatePair != NULL &&
            pIceAgent->pDataSendingIceCandidatePair->local->pSocketConnection == pSocketConnection &&
            pIceAgent->pDataSendingIceCandidatePair->remote->ipAddress.family == pSrc->family &&
            MEMCMP(pIceAgent->pDataSendingIceCandidatePair->remote->ipAddress.address, pSrc->address, addrLen) == 0 &&
            (pIceAgent->pDataSendingIceCandidatePair->remote->ipAddress.port == pSrc->port)) {
            pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.lastPacketReceivedTimestamp = GETTIME();
            pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.bytesReceived += bufferLen;
            pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics
                .packetsReceived++; // Since every byte buffer translates to a single RTP packet
        }
    } else {
        if (ATOMIC_LOAD_BOOL(&pIceAgent->processStun)) {
            CHK_STATUS(ice_agent_handleInboundStunPacket(pIceAgent, pBuffer, bufferLen, pSocketConnection, pSrc, pDest));
        }
    }

CleanUp:
    CHK_LOG_ERR(retStatus);
    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}
/**
 * @brief handle the inbound packets from the relay candidates.
 *
 * @param[in] customData the user data.
 * @param[in] pSocketConnection the context of the socket connection.
 * @param[in] pBuffer the buffer of the packet.
 * @param[in] bufferLen the length of the buffer.
 * @param[in] pSrc the source ip address.
 * @param[in] pDest the destination ip address.
 *
 * @return STATUS status of execution.
 */
STATUS ice_agent_handleInboundRelayedData(UINT64 customData, PSocketConnection pSocketConnection, PBYTE pBuffer, UINT32 bufferLen, PKvsIpAddress pSrc,
                                          PKvsIpAddress pDest)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidate pRelayedCandidate = (PIceCandidate) customData;
    // this should be more than enough. Usually the number of channel data in each tcp message is around 4
    // #memory, #heap.
    TurnChannelData* pTurnChannelData = NULL;
    UINT32 turnChannelDataCount = DEFAULT_TURN_CHANNEL_DATA_BUFFER_SIZE, i = 0;

    CHK(pRelayedCandidate != NULL && pSocketConnection != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // 32*512 = 16384. 16k.
    CHK(NULL != (pTurnChannelData = (TurnChannelData*) MEMALLOC(SIZEOF(TurnChannelData) * DEFAULT_TURN_CHANNEL_DATA_BUFFER_SIZE)),
        STATUS_ICE_AGENT_NOT_ENOUGH_MEMORY);

    CHK_STATUS(turn_connection_handleInboundData(pRelayedCandidate->pTurnConnection, pBuffer, bufferLen, pSrc, pDest, pTurnChannelData,
                                                 &turnChannelDataCount));

    for (i = 0; i < turnChannelDataCount; ++i) {
        ice_agent_handleInboundData((UINT64) pRelayedCandidate->pIceAgent, pSocketConnection, pTurnChannelData[i].data, pTurnChannelData[i].size,
                                    &pTurnChannelData[i].senderAddr, NULL);
    }

CleanUp:
    SAFE_MEMFREE(pTurnChannelData);
    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS ice_agent_sendStunPacket(PStunPacket pStunPacket, PBYTE password, UINT32 passwordLen, PIceAgent pIceAgent, PIceCandidate pLocalCandidate,
                                PKvsIpAddress pDestAddr)
{
    STATUS retStatus = STATUS_SUCCESS;
    PIceCandidatePair pIceCandidatePair = NULL;

    // Assuming holding pIceAgent->lock

    CHK(pStunPacket != NULL && pIceAgent != NULL && pLocalCandidate != NULL && pDestAddr != NULL, STATUS_ICE_AGENT_NULL_ARG);

    retStatus = ice_utils_sendStunPacket(pStunPacket, password, passwordLen, pDestAddr, pLocalCandidate->pSocketConnection,
                                         pLocalCandidate->pTurnConnection, pLocalCandidate->iceCandidateType == ICE_CANDIDATE_TYPE_RELAYED);

    if (STATUS_FAILED(retStatus)) {
        DLOGW("ice_utils_sendStunPacket failed with 0x%08x", retStatus);

        if (retStatus == STATUS_SOCKET_CONN_CLOSED_ALREADY) {
            pIceAgent->iceAgentStatus = STATUS_SOCKET_CONN_CLOSED_ALREADY;
            pLocalCandidate->state = ICE_CANDIDATE_STATE_INVALID;
            ice_agent_invalidateCandidatePair(pIceAgent);
        }

        retStatus = STATUS_SUCCESS;

        /* Update iceCandidatePair state to failed.
         * pIceCandidatePair could no longer exist. */
        CHK_STATUS(ice_candidate_pair_queryByLocalSocketConnectionAndRemoteAddr(pIceAgent, pLocalCandidate->pSocketConnection, pDestAddr, TRUE,
                                                                                &pIceCandidatePair));

        if (pIceCandidatePair != NULL) {
            DLOGD("mark candidate pair %s_%s as failed", pIceCandidatePair->local->id, pIceCandidatePair->remote->id);
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
        }
    } else {
        CHK_STATUS(ice_candidate_pair_queryByLocalSocketConnectionAndRemoteAddr(pIceAgent, pLocalCandidate->pSocketConnection, pDestAddr, TRUE,
                                                                                &pIceCandidatePair));
        if (pIceCandidatePair != NULL && pIceCandidatePair == pIceAgent->pDataSendingIceCandidatePair &&
            pIceAgent->pDataSendingIceCandidatePair->firstStunRequest) {
            pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.firstRequestTimestamp = GETTIME();
            pIceAgent->pDataSendingIceCandidatePair->firstStunRequest = FALSE;
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    return retStatus;
}

STATUS ice_agent_send(PIceAgent pIceAgent, PBYTE pBuffer, UINT32 bufferLen)
{
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE, isRelay = FALSE;
    PTurnConnection pTurnConnection = NULL;
    UINT32 packetsDiscarded = 0;
    UINT32 bytesDiscarded = 0;
    UINT32 bytesSent = 0;
    UINT32 packetsSent = 0;

    CHK(pIceAgent != NULL && pBuffer != NULL, STATUS_ICE_AGENT_NULL_ARG);
    CHK(bufferLen != 0, STATUS_ICE_AGENT_INVALID_ARG);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    /* Do not proceed if ice is shutting down */
    CHK(!ATOMIC_LOAD_BOOL(&pIceAgent->shutdown), retStatus);
    CHK(bufferLen != 0, STATUS_ICE_AGENT_INVALID_ARG);

    CHK_WARN(pIceAgent->pDataSendingIceCandidatePair != NULL, retStatus, "No valid ice candidate pair available to send data");
    CHK_WARN(pIceAgent->pDataSendingIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED, retStatus,
             "Invalid state for data sending candidate pair.");

    pIceAgent->pDataSendingIceCandidatePair->lastDataSentTime = GETTIME();

    isRelay = IS_CANN_PAIR_SENDING_FROM_RELAYED(pIceAgent->pDataSendingIceCandidatePair);
    if (isRelay) {
        CHK_ERR(pIceAgent->pDataSendingIceCandidatePair->local->pTurnConnection != NULL, STATUS_ICE_AGENT_NULL_ARG,
                "Candidate is relay but pTurnConnection is NULL");
        pTurnConnection = pIceAgent->pDataSendingIceCandidatePair->local->pTurnConnection;
    }

    retStatus = ice_utils_send(pBuffer, bufferLen, &pIceAgent->pDataSendingIceCandidatePair->remote->ipAddress,
                               pIceAgent->pDataSendingIceCandidatePair->local->pSocketConnection, pTurnConnection, isRelay);

    if (STATUS_FAILED(retStatus)) {
        DLOGW("ice_utils_send failed with 0x%08x", retStatus);
        packetsDiscarded++;
        bytesDiscarded = bufferLen; // This includes header and padding. TODO: update length to remove header and padding
        if (retStatus == STATUS_SOCKET_CONN_CLOSED_ALREADY) {
            DLOGW("IceAgent connection closed unexpectedly");
            pIceAgent->iceAgentStatus = STATUS_SOCKET_CONN_CLOSED_ALREADY;
            pIceAgent->pDataSendingIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
        }
        retStatus = STATUS_SUCCESS;
    } else {
        bytesSent = bufferLen;
        packetsSent++;
    }

CleanUp:

    if (STATUS_SUCCEEDED(retStatus) && pIceAgent->pDataSendingIceCandidatePair != NULL) {
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.packetsDiscardedOnSend += packetsDiscarded;
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.bytesDiscardedOnSend += bytesDiscarded;
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.state = pIceAgent->pDataSendingIceCandidatePair->state;
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.lastPacketSentTimestamp =
            pIceAgent->pDataSendingIceCandidatePair->lastDataSentTime;
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.bytesSent += bytesSent;
        pIceAgent->pDataSendingIceCandidatePair->rtcIceCandidatePairDiagnostics.packetsSent += packetsSent;
    }
    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    return retStatus;
}

STATUS ice_agent_sendCandidateNomination(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    PIceCandidatePair pIceCandidatePair = NULL;
    BOOL locked = FALSE;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);
    // do nothing if not controlling
    CHK(pIceAgent->isControlling, retStatus);

    MUTEX_LOCK(pIceAgent->lock);
    locked = TRUE;

    // send packet with USE_CANDIDATE flag if is controlling
    CHK_STATUS(double_list_getHeadNode(pIceAgent->pIceCandidatePairs, &pCurNode));
    while (pCurNode != NULL) {
        pIceCandidatePair = (PIceCandidatePair) pCurNode->data;
        pCurNode = pCurNode->pNext;

        if (pIceCandidatePair->nominated) {
            CHK_STATUS(ice_candidate_pair_checkConnection(pIceAgent->pBindingRequest, pIceAgent, pIceCandidatePair));
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (locked) {
        MUTEX_UNLOCK(pIceAgent->lock);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}

STATUS ice_agent_sendSrflxCandidateRequest(PIceAgent pIceAgent)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDoubleListNode pCurNode = NULL;
    UINT64 data;
    PIceCandidate pCandidate = NULL;
    PIceServer pIceServer = NULL;
    PStunPacket pBindingRequest = NULL;
    UINT64 checkSum = 0;

    CHK(pIceAgent != NULL, STATUS_ICE_AGENT_NULL_ARG);

    // Assume holding pIceAgent->lock
    /* Can't reuse pIceAgent->pBindingRequest because candidate gathering could be running in parallel with
     * connection check. */
    CHK_STATUS(stun_createPacket(STUN_PACKET_TYPE_BINDING_REQUEST, NULL, &pBindingRequest));

    CHK_STATUS(double_list_getHeadNode(pIceAgent->localCandidates, &pCurNode));
    while (pCurNode != NULL) {
        CHK_STATUS(double_list_getNodeData(pCurNode, &data));
        pCurNode = pCurNode->pNext;
        pCandidate = (PIceCandidate) data;

        if (pCandidate->state == ICE_CANDIDATE_STATE_NEW) {
            switch (pCandidate->iceCandidateType) {
                case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
                    pIceServer = &(pIceAgent->iceServers[pCandidate->iceServerIndex]);
                    if (pIceServer->ipAddress.family == pCandidate->ipAddress.family) {
                        transaction_id_store_insert(pIceAgent->pStunBindingRequestTransactionIdStore, pBindingRequest->header.transactionId);
                        checkSum = COMPUTE_CRC32(pBindingRequest->header.transactionId, ARRAY_SIZE(pBindingRequest->header.transactionId));
                        CHK_STATUS(ice_agent_sendStunPacket(pBindingRequest, NULL, 0, pIceAgent, pCandidate, &pIceServer->ipAddress));
                        pIceAgent->rtcIceServerDiagnostics[pCandidate->iceServerIndex].totalRequestsSent++;
                        CHK_STATUS(hashTableUpsert(pIceAgent->requestTimestampDiagnostics, checkSum, GETTIME()));
                    }
                    break;

                default:
                    break;
            }
        }
    }

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (pBindingRequest != NULL) {
        stun_freePacket(&pBindingRequest);
    }

    if (STATUS_FAILED(retStatus)) {
        ice_agent_throwFatalError(pIceAgent, retStatus);
    }

    return retStatus;
}
