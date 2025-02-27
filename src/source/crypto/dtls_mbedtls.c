#define LOG_CLASS "DTLS_mbedtls"

#include "time_port.h"
#include "dtls.h"
#include "Rtp.h"

/**  https://tools.ietf.org/html/rfc5764#section-4.1.2 */
mbedtls_ssl_srtp_profile DTLS_SRTP_SUPPORTED_PROFILES[] = {
    MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_80,
    MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_32,
};

STATUS dtls_session_create(PDtlsSessionCallbacks pDtlsSessionCallbacks, TIMER_QUEUE_HANDLE timerQueueHandle, INT32 certificateBits,
                           BOOL generateRSACertificate, PRtcCertificate pRtcCertificates, PDtlsSession* ppDtlsSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = NULL;
    PDtlsSessionCertificateInfo pCertInfo;
    UINT32 i, certCount;

    CHK(ppDtlsSession != NULL && pDtlsSessionCallbacks != NULL, STATUS_DTLS_NULL_ARG);
    CHK_STATUS(dtlsValidateRtcCertificates(pRtcCertificates, &certCount));

    pDtlsSession = (PDtlsSession) MEMCALLOC(SIZEOF(DtlsSession), 1);
    CHK(pDtlsSession != NULL, STATUS_NOT_ENOUGH_MEMORY);

    // initialize mbedtls stuff with sane values
    mbedtls_entropy_init(&pDtlsSession->entropy);
    mbedtls_ctr_drbg_init(&pDtlsSession->ctrDrbg);
    mbedtls_ssl_config_init(&pDtlsSession->sslCtxConfig);
    mbedtls_ssl_init(&pDtlsSession->sslCtx);
    CHK(mbedtls_ctr_drbg_seed(&pDtlsSession->ctrDrbg, mbedtls_entropy_func, &pDtlsSession->entropy, NULL, 0) == 0, STATUS_DTLS_CREATE_SSL_FAILED);

    CHK_STATUS(io_buffer_create(DEFAULT_MTU_SIZE, &pDtlsSession->pReadBuffer));
    pDtlsSession->timerQueueHandle = timerQueueHandle;
    pDtlsSession->timerId = MAX_UINT32;
    pDtlsSession->nestedDtlsLock = MUTEX_CREATE(TRUE);
    pDtlsSession->dtlsSessionCallbacks = *pDtlsSessionCallbacks;
    if (certificateBits == 0) {
        certificateBits = GENERATED_CERTIFICATE_BITS;
    }

    if (certCount == 0) {
        CHK_STATUS(certificate_key_create(certificateBits, generateRSACertificate, &pDtlsSession->certificates[0].cert,
                                          &pDtlsSession->certificates[0].privateKey));
        pDtlsSession->certificateCount = 1;
    } else {
        for (i = 0; i < certCount; i++) {
            CHK_STATUS(certificate_key_copy((mbedtls_x509_crt*) pRtcCertificates[i].pCertificate,
                                            (mbedtls_pk_context*) pRtcCertificates[i].pPrivateKey, &pDtlsSession->certificates[i]));
            // in case of a failure in between, we'll only free up to current position
            pDtlsSession->certificateCount++;
        }
    }

    // Generate and store the certificate fingerprints
    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        CHK_STATUS(dtls_session_calculateCertificateFingerprint(&pCertInfo->cert, pCertInfo->fingerprint));
    }
    *ppDtlsSession = pDtlsSession;

CleanUp:

    CHK_LOG_ERR(retStatus);

    if (STATUS_FAILED(retStatus) && pDtlsSession != NULL) {
        dtls_session_free(&pDtlsSession);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_free(PDtlsSession* ppDtlsSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    PDtlsSessionCertificateInfo pCertInfo;
    PDtlsSession pDtlsSession;

    CHK(ppDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    pDtlsSession = *ppDtlsSession;
    CHK(pDtlsSession != NULL, retStatus);

    if (pDtlsSession->timerId != MAX_UINT32) {
        timer_queue_cancelTimer(pDtlsSession->timerQueueHandle, pDtlsSession->timerId, (UINT64) pDtlsSession);
    }

    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        certificate_key_free(&pCertInfo->cert, &pCertInfo->privateKey);
    }
    mbedtls_entropy_free(&pDtlsSession->entropy);
    mbedtls_ctr_drbg_free(&pDtlsSession->ctrDrbg);
    mbedtls_ssl_config_free(&pDtlsSession->sslCtxConfig);
    mbedtls_ssl_free(&pDtlsSession->sslCtx);

    io_buffer_free(&pDtlsSession->pReadBuffer);
    if (IS_VALID_MUTEX_VALUE(pDtlsSession->nestedDtlsLock)) {
        MUTEX_FREE(pDtlsSession->nestedDtlsLock);
        pDtlsSession->nestedDtlsLock = INVALID_MUTEX_VALUE;
    }
    SAFE_MEMFREE(*ppDtlsSession);

CleanUp:
    LEAVES();
    return retStatus;
}

INT32 dtls_session_sendCallback(PVOID customData, const unsigned char* pBuf, ULONG len)
{
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = (PDtlsSession) customData;

    CHK(pDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    pDtlsSession->dtlsSessionCallbacks.outboundPacketFn(pDtlsSession->dtlsSessionCallbacks.outBoundPacketFnCustomData, (PBYTE) pBuf, len);

CleanUp:
    return STATUS_FAILED(retStatus) ? -retStatus : len;
}

INT32 dtls_session_receiveCallback(PVOID customData, unsigned char* pBuf, ULONG len)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = (PDtlsSession) customData;
    PIOBuffer pBuffer;
    UINT32 readBytes = MBEDTLS_ERR_SSL_WANT_READ;

    CHK(pDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    pBuffer = pDtlsSession->pReadBuffer;

    if (pBuffer->off < pBuffer->len) {
        CHK_STATUS(io_buffer_read(pBuffer, pBuf, len, &readBytes));
    }

CleanUp:
    LEAVES();
    return STATUS_FAILED(retStatus) ? -retStatus : readBytes;
}

// Provide mbedtls timer functionality for retransmission and timeout calculation
// Reference: https://tls.mbed.org/kb/how-to/dtls-tutorial
VOID dtls_session_setTimerCallback(PVOID customData, UINT32 intermediateDelayInMs, UINT32 finalDelayInMs)
{
    ENTERS();
    PDtlsSessionTimer pTimer = (PDtlsSessionTimer) customData;

    pTimer->intermediateDelay = intermediateDelayInMs * HUNDREDS_OF_NANOS_IN_A_MILLISECOND;
    pTimer->finalDelay = finalDelayInMs * HUNDREDS_OF_NANOS_IN_A_MILLISECOND;

    if (finalDelayInMs != 0) {
        pTimer->updatedTime = GETTIME();
    }
    LEAVES();
}

// Provide mbedtls timer functionality for retransmission and timeout calculation
// Reference: https://tls.mbed.org/kb/how-to/dtls-tutorial
//
// Returns:
//   -1: cancelled, set timer callback has been called with finalDelayInMs = 0;
//   0: no delays have passed
//   1: intermediate delay has passed
//   2: final delay has passed
INT32 dtls_session_getTimerCallback(PVOID customData)
{
    ENTERS();
    PDtlsSessionTimer pTimer = (PDtlsSessionTimer) customData;
    UINT64 elapsed = GETTIME() - pTimer->updatedTime;

    if (pTimer->finalDelay == 0) {
        return -1;
    } else if (elapsed >= pTimer->finalDelay) {
        return 2;
    } else if (elapsed >= pTimer->intermediateDelay) {
        return 1;
    } else {
        return 0;
    }
    LEAVES();
}

STATUS dtls_session_timerCallback(UINT32 timerID, UINT64 currentTime, UINT64 customData)
{
    UNUSED_PARAM(timerID);
    UNUSED_PARAM(currentTime);
    ENTERS();
    INT32 handshakeStatus;
    STATUS retStatus = STATUS_SUCCESS;
    PDtlsSession pDtlsSession = (PDtlsSession) customData;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;
    handshakeStatus = mbedtls_ssl_handshake(&pDtlsSession->sslCtx);
    switch (handshakeStatus) {
        case 0:
            // success.
            CHK_STATUS(dtls_session_changeState(pDtlsSession, RTC_DTLS_TRANSPORT_STATE_CONNECTED));
            CHK(FALSE, STATUS_TIMER_QUEUE_STOP_SCHEDULING);
            break;
        case MBEDTLS_ERR_SSL_WANT_READ:
        /* explicit fallthrough */
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            // No need to do anything when mbedtls needs more data. Another thread will provide the data.
            CHK(FALSE, STATUS_SUCCESS);
            break;
        default:
            LOG_MBEDTLS_ERROR("mbedtls_ssl_handshake", handshakeStatus);
            CHK_STATUS(dtls_session_changeState(pDtlsSession, RTC_DTLS_TRANSPORT_STATE_FAILED));
            CHK(FALSE, STATUS_TIMER_QUEUE_STOP_SCHEDULING);
            break;
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

INT32 dtls_session_deriveKeyCallback(PVOID customData, const unsigned char* pMasterSecret, const unsigned char* pKeyBlock, ULONG maclen, ULONG keylen,
                                     ULONG ivlen, const unsigned char clientRandom[MAX_DTLS_RANDOM_BYTES_LEN],
                                     const unsigned char serverRandom[MAX_DTLS_RANDOM_BYTES_LEN], mbedtls_tls_prf_types tlsProfile)
{
    ENTERS();
    UNUSED_PARAM(pKeyBlock);
    UNUSED_PARAM(maclen);
    UNUSED_PARAM(keylen);
    UNUSED_PARAM(ivlen);
    PDtlsSession pDtlsSession = (PDtlsSession) customData;
    PTlsKeys pKeys = &pDtlsSession->tlsKeys;
    MEMCPY(pKeys->masterSecret, pMasterSecret, SIZEOF(pKeys->masterSecret));
    MEMCPY(pKeys->randBytes, clientRandom, MAX_DTLS_RANDOM_BYTES_LEN);
    MEMCPY(pKeys->randBytes + MAX_DTLS_RANDOM_BYTES_LEN, serverRandom, MAX_DTLS_RANDOM_BYTES_LEN);
    pKeys->tlsProfile = tlsProfile;
    LEAVES();
    return 0;
}

STATUS dtls_session_start(PDtlsSession pDtlsSession, BOOL isServer)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 i;
    BOOL locked = FALSE;
    PDtlsSessionCertificateInfo pCertInfo;

    CHK(pDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->isStarted), retStatus);

    // Need to set isStarted to TRUE after acquiring the lock to make sure dtls_session_read
    // dont proceed before dtls_session_start finish
    ATOMIC_STORE_BOOL(&pDtlsSession->isStarted, TRUE);
    CHK_STATUS(dtls_session_changeState(pDtlsSession, RTC_DTLS_TRANSPORT_STATE_CONNECTING));

    // Initialize ssl config
    CHK(mbedtls_ssl_config_defaults(&pDtlsSession->sslCtxConfig, isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0,
        STATUS_DTLS_CREATE_SSL_FAILED);
    // no need to verify since the certificate will be verified through SDP later
    mbedtls_ssl_conf_authmode(&pDtlsSession->sslCtxConfig, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_rng(&pDtlsSession->sslCtxConfig, mbedtls_ctr_drbg_random, &pDtlsSession->ctrDrbg);

    for (i = 0; i < pDtlsSession->certificateCount; i++) {
        pCertInfo = pDtlsSession->certificates + i;
        CHK(mbedtls_ssl_conf_own_cert(&pDtlsSession->sslCtxConfig, &pCertInfo->cert, &pCertInfo->privateKey) == 0, STATUS_DTLS_CREATE_SSL_FAILED);
    }
    mbedtls_ssl_conf_dtls_cookies(&pDtlsSession->sslCtxConfig, NULL, NULL, NULL);
    CHK(mbedtls_ssl_conf_dtls_srtp_protection_profiles(&pDtlsSession->sslCtxConfig, DTLS_SRTP_SUPPORTED_PROFILES,
                                                       ARRAY_SIZE(DTLS_SRTP_SUPPORTED_PROFILES)) == 0,
        STATUS_DTLS_CREATE_SSL_FAILED);
    mbedtls_ssl_conf_export_keys_ext_cb(&pDtlsSession->sslCtxConfig, (mbedtls_ssl_export_keys_ext_t*) dtls_session_deriveKeyCallback, pDtlsSession);

    CHK(mbedtls_ssl_setup(&pDtlsSession->sslCtx, &pDtlsSession->sslCtxConfig) == 0, STATUS_DTLS_SSL_CTX_CREATION_FAILED);
    mbedtls_ssl_set_mtu(&pDtlsSession->sslCtx, DEFAULT_MTU_SIZE);
    mbedtls_ssl_set_bio(&pDtlsSession->sslCtx, pDtlsSession, (mbedtls_ssl_send_t*) dtls_session_sendCallback,
                        (mbedtls_ssl_recv_t*) dtls_session_receiveCallback, NULL);
    mbedtls_ssl_set_timer_cb(&pDtlsSession->sslCtx, &pDtlsSession->transmissionTimer, (mbedtls_ssl_set_timer_t*) dtls_session_setTimerCallback,
                             (mbedtls_ssl_get_timer_t*) dtls_session_getTimerCallback);

    // Start non-blocking handshaking
    pDtlsSession->dtlsSessionStartTime = GETTIME();
    CHK_STATUS(timer_queue_addTimer(pDtlsSession->timerQueueHandle, DTLS_SESSION_TIMER_START_DELAY, DTLS_TRANSMISSION_INTERVAL,
                                    dtls_session_timerCallback, (UINT64) pDtlsSession, &pDtlsSession->timerId));

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_isConnected(PDtlsSession pDtlsSession, PBOOL pIsConnected)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CHK(pDtlsSession != NULL && pIsConnected != NULL, STATUS_DTLS_NULL_ARG);
    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    *pIsConnected = pDtlsSession->state == RTC_DTLS_TRANSPORT_STATE_CONNECTED;
    MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);

CleanUp:
    LEAVES();
    return retStatus;
}

STATUS dtls_session_read(PDtlsSession pDtlsSession, PBYTE pData, PINT32 pDataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;
    INT32 sslRet, readBytes = 0;
    PIOBuffer pReadBuffer;
    BOOL iterate = TRUE;

    CHK(pDtlsSession != NULL && pData != NULL && pData != NULL, STATUS_DTLS_NULL_ARG);
    CHK(ATOMIC_LOAD_BOOL(&pDtlsSession->isStarted), STATUS_DTLS_PACKET_BEFORE_DTLS_READY);
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    pReadBuffer = pDtlsSession->pReadBuffer;
    CHK_STATUS(io_buffer_write(pReadBuffer, pData, *pDataLen));

    // read application data
    while (iterate && pReadBuffer->off < pReadBuffer->len) {
        sslRet = mbedtls_ssl_read(&pDtlsSession->sslCtx, pData + readBytes, pReadBuffer->len - pReadBuffer->off);
        if (sslRet > 0) {
            readBytes += sslRet;
        } else if (sslRet == 0 || sslRet == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            // if sslRet is 0, the connection is closed already.
            // if sslRet is MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, the client notified us that the connection is going to be closed.
            // In either case, we'll make sure that the state will change to CLOSED. If it's already closed, it'll be just a noop.
            DLOGI("Detected DTLS close_notify alert");
            CHK_STATUS(dtls_session_shutdown(pDtlsSession));
            iterate = FALSE;
        } else if (sslRet == MBEDTLS_ERR_SSL_WANT_READ || sslRet == MBEDTLS_ERR_SSL_WANT_WRITE) {
            iterate = FALSE;
        } else {
            LOG_MBEDTLS_ERROR("mbedtls_ssl_read", sslRet);
            readBytes = 0;
            retStatus = STATUS_INTERNAL_ERROR;
            iterate = FALSE;
        }
    }

    if (pDtlsSession->sslCtx.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        CHK_STATUS(dtls_session_changeState(pDtlsSession, RTC_DTLS_TRANSPORT_STATE_CONNECTED));
    }

CleanUp:
    if (pDataLen != NULL) {
        *pDataLen = readBytes;
    }

    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_send(PDtlsSession pDtlsSession, PBYTE pData, INT32 dataLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    INT32 writtenBytes = 0;
    BOOL locked = FALSE;
    INT32 sslRet;
    BOOL iterate = TRUE;

    CHK(pData != NULL, STATUS_DTLS_NULL_ARG);
    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    while (iterate && writtenBytes < dataLen) {
        sslRet = mbedtls_ssl_write(&pDtlsSession->sslCtx, pData + writtenBytes, dataLen - writtenBytes);
        if (sslRet > 0) {
            writtenBytes += sslRet;
        } else if (sslRet == MBEDTLS_ERR_SSL_WANT_READ || sslRet == MBEDTLS_ERR_SSL_WANT_WRITE) {
            iterate = FALSE;
        } else {
            LOG_MBEDTLS_ERROR("mbedtls_ssl_write", sslRet);
            writtenBytes = 0;
            retStatus = STATUS_INTERNAL_ERROR;
            iterate = FALSE;
        }
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return STATUS_SUCCESS;
}

STATUS dtls_session_getLocalCertificateFingerprint(PDtlsSession pDtlsSession, PCHAR pBuff, UINT32 buffLen)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL && pBuff != NULL, STATUS_DTLS_NULL_ARG);
    CHK(buffLen >= CERTIFICATE_FINGERPRINT_LENGTH, STATUS_INVALID_ARG_LEN);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    // TODO: Use the 0th certificate for now
    // #TBD. need to check the relationship of certificate.
    MEMCPY(pBuff, pDtlsSession->certificates[0].fingerprint, buffLen);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_verifyRemoteCertificateFingerprint(PDtlsSession pDtlsSession, PCHAR pExpectedFingerprint)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    CHAR actualFingerprint[CERTIFICATE_FINGERPRINT_LENGTH];
    mbedtls_x509_crt* pRemoteCertificate = NULL;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL && pExpectedFingerprint != NULL, STATUS_DTLS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    CHK((pRemoteCertificate = (mbedtls_x509_crt*) mbedtls_ssl_get_peer_cert(&pDtlsSession->sslCtx)) != NULL, STATUS_INTERNAL_ERROR);
    CHK_STATUS(dtls_session_calculateCertificateFingerprint(pRemoteCertificate, actualFingerprint));

    CHK(STRCMP(pExpectedFingerprint, actualFingerprint) == 0, STATUS_DTLS_REMOTE_CERTIFICATE_VERIFICATION_FAILED);

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_populateKeyingMaterial(PDtlsSession pDtlsSession, PDtlsKeyingMaterial pDtlsKeyingMaterial)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 offset = 0;
    BOOL locked = FALSE;
    PTlsKeys pKeys;
    BYTE keyingMaterialBuffer[MAX_SRTP_MASTER_KEY_LEN * 2 + MAX_SRTP_SALT_KEY_LEN * 2];
    mbedtls_ssl_srtp_profile negotiatedSRTPProfile;

    CHK(pDtlsSession != NULL && pDtlsKeyingMaterial != NULL, STATUS_DTLS_NULL_ARG);
    pKeys = &pDtlsSession->tlsKeys;

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    CHK(mbedtls_ssl_tls_prf(pKeys->tlsProfile, pKeys->masterSecret, ARRAY_SIZE(pKeys->masterSecret), KEYING_EXTRACTOR_LABEL, pKeys->randBytes,
                            ARRAY_SIZE(pKeys->randBytes), keyingMaterialBuffer, ARRAY_SIZE(keyingMaterialBuffer)) == 0,
        STATUS_INTERNAL_ERROR);

    pDtlsKeyingMaterial->key_length = MAX_SRTP_MASTER_KEY_LEN + MAX_SRTP_SALT_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->clientWriteKey, &keyingMaterialBuffer[offset], MAX_SRTP_MASTER_KEY_LEN);
    offset += MAX_SRTP_MASTER_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->serverWriteKey, &keyingMaterialBuffer[offset], MAX_SRTP_MASTER_KEY_LEN);
    offset += MAX_SRTP_MASTER_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->clientWriteKey + MAX_SRTP_MASTER_KEY_LEN, &keyingMaterialBuffer[offset], MAX_SRTP_SALT_KEY_LEN);
    offset += MAX_SRTP_SALT_KEY_LEN;

    MEMCPY(pDtlsKeyingMaterial->serverWriteKey + MAX_SRTP_MASTER_KEY_LEN, &keyingMaterialBuffer[offset], MAX_SRTP_SALT_KEY_LEN);

    negotiatedSRTPProfile = mbedtls_ssl_get_dtls_srtp_protection_profile(&pDtlsSession->sslCtx);
    switch (negotiatedSRTPProfile) {
        case MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_80:
            pDtlsKeyingMaterial->srtpProfile = KVS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80;
            break;
        case MBEDTLS_SRTP_AES128_CM_HMAC_SHA1_32:
            pDtlsKeyingMaterial->srtpProfile = KVS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_32;
            break;
        default:
            CHK(FALSE, STATUS_DTLS_UNKNOWN_SRTP_PROFILE);
    }

CleanUp:
    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }

    LEAVES();
    return retStatus;
}

STATUS dtls_session_shutdown(PDtlsSession pDtlsSession)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL locked = FALSE;

    CHK(pDtlsSession != NULL, STATUS_DTLS_NULL_ARG);

    MUTEX_LOCK(pDtlsSession->nestedDtlsLock);
    locked = TRUE;

    CHK(!ATOMIC_LOAD_BOOL(&pDtlsSession->shutdown), retStatus);

    while (mbedtls_ssl_close_notify(&pDtlsSession->sslCtx) == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // keep flushing outgoing buffer until nothing left
    }

    ATOMIC_STORE_BOOL(&pDtlsSession->shutdown, TRUE);
    CHK_STATUS(dtls_session_changeState(pDtlsSession, RTC_DTLS_TRANSPORT_STATE_CLOSED));

CleanUp:

    if (locked) {
        MUTEX_UNLOCK(pDtlsSession->nestedDtlsLock);
    }
    LEAVES();
    return retStatus;
}

STATUS certificate_key_copy(mbedtls_x509_crt* pCert, mbedtls_pk_context* pKey, PDtlsSessionCertificateInfo pDst)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL initialized = FALSE;
    mbedtls_ecp_keypair *pSrcECP, *pDstECP;

    CHK(pCert != NULL && pKey != NULL && pDst != NULL, STATUS_DTLS_NULL_ARG);
    CHK(mbedtls_pk_check_pair(&pCert->pk, pKey) == 0, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);

    mbedtls_x509_crt_init(&pDst->cert);
    mbedtls_pk_init(&pDst->privateKey);
    initialized = TRUE;

    CHK(mbedtls_x509_crt_parse_der(&pDst->cert, pCert->raw.p, pCert->raw.len) == 0, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);
    CHK(mbedtls_pk_setup(&pDst->privateKey, pKey->pk_info) == 0, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);

    switch (mbedtls_pk_get_type(pKey)) {
        case MBEDTLS_PK_RSA:
            CHK(mbedtls_rsa_copy(mbedtls_pk_rsa(pDst->privateKey), mbedtls_pk_rsa(*pKey)) == 0, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);
            break;
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECDSA:
            pSrcECP = mbedtls_pk_ec(*pKey);
            pDstECP = mbedtls_pk_ec(pDst->privateKey);
            CHK(mbedtls_ecp_group_copy(&pDstECP->grp, &pSrcECP->grp) == 0 && mbedtls_ecp_copy(&pDstECP->Q, &pSrcECP->Q) == 0 &&
                    mbedtls_mpi_copy(&pDstECP->d, &pSrcECP->d) == 0,
                STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);
            break;
        default:
            CHK(FALSE, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);
    }

CleanUp:

    if (STATUS_FAILED(retStatus) && initialized) {
        mbedtls_x509_crt_free(&pDst->cert);
        mbedtls_pk_free(&pDst->privateKey);
    }

    LEAVES();
    return retStatus;
}

/**
 * certificate_key_create generates a new certificate and a key
 * If generateRSACertificate is true, RSA is going to be used for the key generation. Otherwise, ECDSA is going to be used.
 * certificateBits is only being used when generateRSACertificate is true.
 */
STATUS certificate_key_create(INT32 certificateBits, BOOL generateRSACertificate, mbedtls_x509_crt* pCert, mbedtls_pk_context* pKey)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    BOOL initialized = FALSE;
    PCHAR pCertBuf = NULL;
    CHAR notBeforeBuf[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1], notAfterBuf[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    UINT64 now, notAfter;
    UINT32 written;
    INT32 len;
    mbedtls_entropy_context* pEntropy = NULL;
    mbedtls_ctr_drbg_context* pCtrDrbg = NULL;
    mbedtls_mpi serial;
    mbedtls_x509write_cert* pWriteCert = NULL;

    CHK(pCert != NULL && pKey != NULL, STATUS_DTLS_NULL_ARG);
    CHK(NULL != (pCertBuf = (PCHAR) MEMALLOC(GENERATED_CERTIFICATE_MAX_SIZE)), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pEntropy = (mbedtls_entropy_context*) MEMALLOC(SIZEOF(mbedtls_entropy_context))), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pCtrDrbg = (mbedtls_ctr_drbg_context*) MEMALLOC(SIZEOF(mbedtls_ctr_drbg_context))), STATUS_NOT_ENOUGH_MEMORY);
    CHK(NULL != (pWriteCert = (mbedtls_x509write_cert*) MEMALLOC(SIZEOF(mbedtls_x509write_cert))), STATUS_NOT_ENOUGH_MEMORY);

    // initialize to sane values
    mbedtls_entropy_init(pEntropy);
    mbedtls_ctr_drbg_init(pCtrDrbg);
    mbedtls_mpi_init(&serial);
    mbedtls_x509write_crt_init(pWriteCert);
    mbedtls_x509_crt_init(pCert);
    mbedtls_pk_init(pKey);
    initialized = TRUE;
    CHK(mbedtls_ctr_drbg_seed(pCtrDrbg, mbedtls_entropy_func, pEntropy, NULL, 0) == 0, STATUS_DTLS_DRBG_SEED_FAILED);

    // generate a key
    if (generateRSACertificate) {
        CHK(mbedtls_pk_setup(pKey, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == 0 &&
                mbedtls_rsa_gen_key(mbedtls_pk_rsa(*pKey), mbedtls_ctr_drbg_random, pCtrDrbg, certificateBits, KVS_RSA_F4) == 0,
            STATUS_DTLS_RSA_GEN_KEY_FAILED);
    } else {
        CHK(mbedtls_pk_setup(pKey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) == 0 &&
                mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*pKey), mbedtls_ctr_drbg_random, pCtrDrbg) == 0,
            STATUS_DTLS_ECP_GEN_KEY_FAILED);
    }

    // generate a new certificate
    CHK(mbedtls_mpi_read_string(&serial, 10, STR(GENERATED_CERTIFICATE_SERIAL)) == 0, STATUS_DTLS_MPI_READ_FAILED);

    now = GETTIME();
    CHK(generateTimestampStr(now, "%Y%m%d%H%M%S", notBeforeBuf, SIZEOF(notBeforeBuf), &written) == STATUS_SUCCESS, STATUS_DTLS_GEN_TIME_FAILED);

    notAfter = now + GENERATED_CERTIFICATE_DAYS * HUNDREDS_OF_NANOS_IN_A_DAY;
    CHK(generateTimestampStr(notAfter, "%Y%m%d%H%M%S", notAfterBuf, SIZEOF(notAfterBuf), &written) == STATUS_SUCCESS, STATUS_DTLS_GEN_TIME_FAILED);

    CHK(mbedtls_x509write_crt_set_serial(pWriteCert, &serial) == 0 &&
            mbedtls_x509write_crt_set_validity(pWriteCert, notBeforeBuf, notAfterBuf) == 0 &&
            mbedtls_x509write_crt_set_subject_name(pWriteCert, "O=" GENERATED_CERTIFICATE_NAME ",CN=" GENERATED_CERTIFICATE_NAME) == 0 &&
            mbedtls_x509write_crt_set_issuer_name(pWriteCert, "O=" GENERATED_CERTIFICATE_NAME ",CN=" GENERATED_CERTIFICATE_NAME) == 0,
        STATUS_DTLS_X509_SET_FAILED);
    // void functions, it must succeed
    mbedtls_x509write_crt_set_version(pWriteCert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_subject_key(pWriteCert, pKey);
    mbedtls_x509write_crt_set_issuer_key(pWriteCert, pKey);
    mbedtls_x509write_crt_set_md_alg(pWriteCert, MBEDTLS_MD_SHA1);

    MEMSET(pCertBuf, 0, GENERATED_CERTIFICATE_MAX_SIZE);
    len = mbedtls_x509write_crt_der(pWriteCert, (PVOID) pCertBuf, GENERATED_CERTIFICATE_MAX_SIZE, mbedtls_ctr_drbg_random, pCtrDrbg);
    CHK(len >= 0, STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);

    // mbedtls_x509write_crt_der starts writing from behind, so we need to use the return len
    // to figure out where the data actually starts:
    //
    //         -----------------------------------------
    //         |  padding      |       certificate     |
    //         -----------------------------------------
    //         ^               ^
    //       pCertBuf   pCertBuf + (SIZEOF(pCertBuf) - len)
    CHK(mbedtls_x509_crt_parse_der(pCert, (PVOID) (pCertBuf + GENERATED_CERTIFICATE_MAX_SIZE - len), len) == 0,
        STATUS_DTLS_CERTIFICATE_GENERATION_FAILED);

CleanUp:
    if (initialized) {
        mbedtls_x509write_crt_free(pWriteCert);
        mbedtls_mpi_free(&serial);
        mbedtls_ctr_drbg_free(pCtrDrbg);
        mbedtls_entropy_free(pEntropy);

        if (STATUS_FAILED(retStatus)) {
            certificate_key_free(pCert, pKey);
        }
    }
    SAFE_MEMFREE(pCertBuf);
    SAFE_MEMFREE(pEntropy);
    SAFE_MEMFREE(pCtrDrbg);
    SAFE_MEMFREE(pWriteCert);
    LEAVES();
    return retStatus;
}

STATUS certificate_key_free(mbedtls_x509_crt* pCert, mbedtls_pk_context* pKey)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;

    CHK(pCert != NULL && pKey != NULL, STATUS_DTLS_NULL_ARG);

    mbedtls_x509_crt_free(pCert);
    mbedtls_pk_free(pKey);

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS dtls_session_calculateCertificateFingerprint(mbedtls_x509_crt* pCert, PCHAR pBuff)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    UINT32 fingerprintSize = MBEDTLS_MD_MAX_SIZE;
    BYTE fingerprint[fingerprintSize];
    INT32 sslRet, i, size;
    // const is not pure C, but mbedtls_md_info_from_type requires the param to be const
    const mbedtls_md_info_t* pMdInfo;

    CHK(pBuff != NULL, STATUS_DTLS_NULL_ARG);

    pMdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    CHK(pMdInfo != NULL, STATUS_INTERNAL_ERROR);

    sslRet = mbedtls_sha256_ret(pCert->raw.p, pCert->raw.len, fingerprint, 0);
    CHK(sslRet == 0, STATUS_INTERNAL_ERROR);

    size = mbedtls_md_get_size(pMdInfo);

    for (i = 0; i < size; i++) {
        CHK(fingerprintSize >= 3, STATUS_DTLS_FINGERPRINT_OVERFLOW);
        SPRINTF(pBuff, "%.2X:", fingerprint[i]);
        pBuff += 3;
    }
    *(pBuff - 1) = '\0';

CleanUp:
    CHK_LOG_ERR(retStatus);
    LEAVES();
    return retStatus;
}
