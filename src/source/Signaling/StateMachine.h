/*******************************************
Signaling State Machine internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__
#define __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "Signaling.h"
/**
 * Signaling states definitions
 */
#define SIGNALING_STATE_NONE           ((UINT64) 0)
#define SIGNALING_STATE_NEW            ((UINT64) (1 << 0))
#define SIGNALING_STATE_GET_TOKEN      ((UINT64) (1 << 1))
#define SIGNALING_STATE_DESCRIBE       ((UINT64) (1 << 2))
#define SIGNALING_STATE_CREATE         ((UINT64) (1 << 3))
#define SIGNALING_STATE_GET_ENDPOINT   ((UINT64) (1 << 4))
#define SIGNALING_STATE_GET_ICE_CONFIG ((UINT64) (1 << 5))
#define SIGNALING_STATE_READY          ((UINT64) (1 << 6))
#define SIGNALING_STATE_CONNECT        ((UINT64) (1 << 7))
#define SIGNALING_STATE_CONNECTED      ((UINT64) (1 << 8))
#define SIGNALING_STATE_DISCONNECTED   ((UINT64) (1 << 9))

typedef PVOID SignalingFsmHandle;
typedef SignalingFsmHandle* PSignalingFsmHandle;

/**
 * @brief create the signaling fsm.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in, out] pSignalingFsmHandle the handle of the signaling fsm.
 *
 * @return STATUS status of execution.
 */
STATUS signaling_fsm_create(PSignalingClient pSignalingClient, PSignalingFsmHandle pSignalingFsmHandle);
/**
 * @brief free the signaling fsm.
 *
 * @param[in] pSignalingFsmHandle the handle of the signaling fsm.
 *
 * @return STATUS status of execution.
 */
STATUS signaling_fsm_free(SignalingFsmHandle pStateMachine);
/**
 * @brief step the state machine
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] expiration timeout
 * @param[in] finalState final signaling client state
 *
 * @return STATUS status of execution.
 */
STATUS signaling_fsm_step(PSignalingClient pSignalingClient, UINT64 expiration, UINT64 finalState);
/**
 * @brief check the current state is the required state or not.
 *
 * @param[in] pSignalingClient the context of the signaling client.
 * @param[in] requiredStates
 *
 * @return STATUS status of execution.
 */
STATUS signaling_fsm_accept(PSignalingClient pSignalingClient, UINT64 requiredStates);
STATUS signaling_fsm_resetRetryCount(PSignalingClient pSignalingClient);
STATUS signaling_fsm_setCurrentState(PSignalingClient pSignalingClient, UINT64 state);
UINT64 signaling_fsm_getCurrentState(PSignalingClient pSignalingClient);

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
STATUS executeReadySignalingState(UINT64, UINT64);
STATUS fromConnectSignalingState(UINT64, PUINT64);
STATUS executeConnectSignalingState(UINT64, UINT64);
STATUS fromConnectedSignalingState(UINT64, PUINT64);
STATUS executeConnectedSignalingState(UINT64, UINT64);
STATUS fromDisconnectedSignalingState(UINT64, PUINT64);
STATUS executeDisconnectedSignalingState(UINT64, UINT64);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_SIGNALING_STATE_MACHINE__ */
