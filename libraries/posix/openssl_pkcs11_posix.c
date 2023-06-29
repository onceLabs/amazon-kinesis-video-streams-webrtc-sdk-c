/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/bio.h>


#include <pkcs11.h>

#include "openssl_pkcs11_posix.h"
#include "Samples.h"

/* Standard includes. */
#include <assert.h>
#include <string.h>

/* POSIX socket includes. */
#include <unistd.h>
#include <poll.h>

/* Transport interface include. */
#include "transport_interface.h"

static ENGINE* p11Engine;

/*-----------------------------------------------------------*/

/**
 * @brief Label of root CA when calling @ref logPath.
 */
#define ROOT_CA_LABEL        "Root CA certificate"

/**
 * @brief Label of client certificate when calling @ref logPath.
 */
#define CLIENT_CERT_LABEL    "client's certificate"

/**
 * @brief Label of client key when calling @ref logPath.
 */
#define CLIENT_KEY_LABEL     "client's key"

/*-----------------------------------------------------------*/

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext {
    OpensslPkcs11Params_t * pParams;
};

/*-----------------------------------------------------------*/


/**
 * @brief Add X509 certificate to the trusted list of root certificates.
 *
 * OpenSSL does not provide a single function for reading and loading
 * certificates from files into stores, so the file API must be called. Start
 * with the root certificate.
 *
 * @param[out] pSslContext SSL context to which the trusted server root CA is to
 * be added.
 * @param[in] pRootCaPath Filepath string to the trusted server root CA.
 *
 * @return 1 on success; -1, 0 on failure.
 */
static int32_t setRootCa(OpensslPkcs11Params_t * pSslContext,
                         const char * pRootCaPath);

/**
 * @brief Set X509 certificate as client certificate for the server to
 * authenticate.
 *
 * @param[out] pSslContext SSL context to which the client certificate is to be
 * set.
 * @param[in] pClientCertPath Filepath string to the client certificate.
 *
 * @return 1 on success; 0 failure.
 */
static int32_t setClientCertificate(OpensslPkcs11Params_t * pContext,
                                    const OpensslPkcs11Credentials_t * pOpensslCredentials);


/**
 * @brief Set private key for the client's certificate.
 *
 * @param[out] pSslContext SSL context to which the private key is to be added.
 * @param[in] pPrivateKeyPath Filepath string to the client private key.
 *
 * @return 1 on success; 0 on failure.
 */
static int32_t setPrivateKey(OpensslPkcs11Params_t * pSslContext,
                             const OpensslPkcs11Credentials_t * pOpensslCredentials);

/**
 * @brief Passes TLS credentials to the OpenSSL library.
 *
 * Provides the root CA certificate, client certificate, and private key to the
 * OpenSSL library. If the client certificate or private key is not NULL, mutual
 * authentication is used when performing the TLS handshake.
 *
 * @param[out] pSslContext SSL context to which the credentials are to be
 * imported.
 * @param[in] pOpensslCredentials TLS credentials to be imported.
 *
 * @return 1 on success; -1, 0 on failure.
 */
static int32_t setCredentials(OpensslPkcs11Params_t * pSslContext,
                              const OpensslPkcs11Credentials_t * pOpensslCredentials);

/**
 * @brief Set optional configurations for the TLS connection.
 *
 * This function is used to set SNI, MFLN, and ALPN protocols.
 *
 * @param[in] pSsl SSL context to which the optional configurations are to be
 * set.
 * @param[in] pOpensslCredentials TLS credentials containing configurations.
 */
static void setOptionalConfigurations(SSL * pSsl,
                                      const OpensslPkcs11Credentials_t * pOpensslCredentials);

/**
 * @brief Converts the sockets wrapper status to openssl status.
 *
 * @param[in] socketStatus Sockets wrapper status.
 *
 * @return #OPENSSL_SUCCESS, #OPENSSL_INVALID_PARAMETER, #OPENSSL_DNS_FAILURE,
 * and #OPENSSL_CONNECT_FAILURE.
 */
static OpensslPkcs11Status_t convertToOpensslStatus(SocketStatus_t socketStatus);

/**
 * @brief Establish TLS session by performing handshake with the server.
 *
 * @param[in] pServerInfo Server connection info.
 * @param[in] pOpensslParams Parameters to perform the TLS handshake.
 * @param[in] pOpensslCredentials TLS credentials containing configurations.
 *
 * @return #OPENSSL_SUCCESS, #OPENSSL_API_ERROR, and #OPENSSL_HANDSHAKE_FAILED.
 */
static OpensslPkcs11Status_t tlsHandshake(const ServerInfo_t * pServerInfo,
        OpensslPkcs11Params_t * pOpensslParams,
        const OpensslPkcs11Credentials_t * pOpensslCredentials);

/**
 * @brief Check if the network context is valid.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 *
 * @return TRUE on success; FALSE on failure.
 */
static BOOL isValidNetworkContext(const NetworkContext_t * pNetworkContext);


/*-----------------------------------------------------------*/

static OpensslPkcs11Status_t convertToOpensslStatus(SocketStatus_t socketStatus)
{
    OpensslPkcs11Status_t opensslStatus = OPENSSL_PKCS11_INVALID_PARAMETER;

    switch (socketStatus) {
        case SOCKETS_SUCCESS:
            opensslStatus = OPENSSL_PKCS11_SUCCESS;
            break;

        case SOCKETS_INVALID_PARAMETER:
            opensslStatus = OPENSSL_PKCS11_INVALID_PARAMETER;
            break;

        case SOCKETS_DNS_FAILURE:
            opensslStatus = OPENSSL_PKCS11_DNS_FAILURE;
            break;

        case SOCKETS_CONNECT_FAILURE:
            opensslStatus = OPENSSL_PKCS11_CONNECT_FAILURE;
            break;

        default:
            DLOGE("Unexpected status received from socket wrapper: Socket status = %u", socketStatus);
            break;
    }

    return opensslStatus;
}
/*-----------------------------------------------------------*/

static void setOptionalConfigurations(SSL * pSsl, const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    int32_t sslStatus = -1;
    int16_t readBufferLength = 0;

    if (!pSsl || !pSsl) {
        DLOGE("Input paramters is invaliad, pSsl or pOpensslCredentials is NULL");
        return;
    }

    /* Set TLS ALPN if requested. */
    if ((pOpensslCredentials->pAlpnProtos != NULL) && (pOpensslCredentials->alpnProtosLen > 0U)) {
        DLOGD("Setting ALPN protos.");
        sslStatus = SSL_set_alpn_protos(
                        pSsl, (const uint8_t *) pOpensslCredentials->pAlpnProtos,
                        (uint32_t) pOpensslCredentials->alpnProtosLen);

        if (sslStatus != 0) {
            DLOGE("SSL_set_alpn_protos failed to set ALPN protos. %s", pOpensslCredentials->pAlpnProtos);
        }
    }

    /* Set TLS MFLN if requested. */
    if (pOpensslCredentials->maxFragmentLength > 0U) {
        DLOGD("Setting max send fragment length %u.", pOpensslCredentials->maxFragmentLength);

        /* Set the maximum send fragment length. */

        /* MISRA Directive 4.6 flags the following line for using basic
         * numerical type long. This directive is suppressed because openssl
         * function #SSL_set_max_send_fragment expects a length argument
         * type of long. */
        /* coverity[misra_c_2012_directive_4_6_violation] */
        sslStatus = (int32_t) SSL_set_max_send_fragment(
                        pSsl, (long) pOpensslCredentials->maxFragmentLength);

        if (sslStatus != 1) {
            DLOGE("Failed to set max send fragment length %u.",
                  pOpensslCredentials->maxFragmentLength);
        } else {
            readBufferLength = (int16_t) pOpensslCredentials->maxFragmentLength +
                               SSL3_RT_MAX_ENCRYPTED_OVERHEAD;

            /* Change the size of the read buffer to match the
             * maximum fragment length + some extra bytes for overhead. */
            SSL_set_default_read_buffer_len(pSsl, (size_t) readBufferLength);
        }
    }

    /* Enable SNI if requested. */
    if (pOpensslCredentials->sniHostName != NULL) {
        DLOGI("Setting server name %s for SNI.", pOpensslCredentials->sniHostName);

        /* MISRA Rule 11.8 flags the following line for removing the const
         * qualifier from the pointed to type. This rule is suppressed because
         * openssl implementation of #SSL_set_tlsext_host_name internally casts
         * the pointer to a string literal to a `void *` pointer. */
        /* coverity[misra_c_2012_rule_11_8_violation] */
        sslStatus = (int32_t) SSL_set_tlsext_host_name(pSsl, pOpensslCredentials->sniHostName);

        if (sslStatus != 1) {
            DLOGE("Failed to set server name %s for SNI.", pOpensslCredentials->sniHostName);
        }
    }
}

/*-----------------------------------------------------------*/

static OpensslPkcs11Status_t tlsHandshake(const ServerInfo_t * pServerInfo,
        OpensslPkcs11Params_t * pOpensslParams,
        const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    OpensslPkcs11Status_t returnStatus = OPENSSL_PKCS11_SUCCESS;
    int32_t sslStatus = -1, verifyPeerCertStatus = X509_V_OK;

    /* Validate the hostname against the server's certificate. */
    sslStatus = SSL_set1_host(pOpensslParams->pSsl, pServerInfo->pHostName);
    if (sslStatus != 1) {
        DLOGE("SSL_set1_host failed to set the hostname to validate.");
        returnStatus = OPENSSL_PKCS11_API_ERROR;
    }

    /* Enable SSL peer verification. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        SSL_set_verify(pOpensslParams->pSsl, SSL_VERIFY_PEER, NULL);

        /* Setup the socket to use for communication. */
        sslStatus = SSL_set_fd(pOpensslParams->pSsl, pOpensslParams->socketDescriptor);
        if (sslStatus != 1) {
            DLOGE("SSL_set_fd failed to set the socket fd to SSL context.");
            returnStatus = OPENSSL_PKCS11_API_ERROR;
        }
    }

    /* Perform the TLS handshake. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        setOptionalConfigurations(pOpensslParams->pSsl, pOpensslCredentials);

        sslStatus = SSL_connect(pOpensslParams->pSsl);
        if (sslStatus != 1) {
            DLOGE("SSL_connect failed to perform TLS handshake.");
            returnStatus = OPENSSL_PKCS11_HANDSHAKE_FAILED;
        }
    }

    /* Verify X509 certificate from peer. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        verifyPeerCertStatus = (int32_t) SSL_get_verify_result(pOpensslParams->pSsl);

        if (verifyPeerCertStatus != X509_V_OK) {
            DLOGE("SSL_get_verify_result failed to verify X509 certificate from peer.");
            returnStatus = OPENSSL_PKCS11_HANDSHAKE_FAILED;
        }
    }

    return returnStatus;
}

static int32_t setRootCa(OpensslPkcs11Params_t * pContext, const char * pRootCaPath)
{
    int32_t sslStatus = 1;
    FILE * pRootCaFile = NULL;
    X509 * pRootCa = NULL;
    X509_STORE *ctx = NULL;
    SSL_CTX * pSslContext = NULL;

    if (!pContext || !pRootCaPath) {
        DLOGE("Input paramters is invalid, pContext or pRootCaPath is NULL");
        sslStatus = -1;
    }

    if (sslStatus == 1) {
        pSslContext = SSL_get_SSL_CTX(pContext->pSsl);
        if (pSslContext == NULL) {
            DLOGE("SSL_get_SSL_CTX failed");
            sslStatus = -1;
        }
    }

    /* MISRA Rule 21.6 flags the following line for using the standard
     * library input/output function `fopen()`. This rule is suppressed because
     * openssl function #PEM_read_X509 takes an argument of type `FILE *` for
     * reading the root ca PEM file and `fopen()` needs to be used to get the
     * file pointer.  */
    /* coverity[misra_c_2012_rule_21_6_violation] */
    if (sslStatus == 1) {
        pRootCaFile = FOPEN(pRootCaPath, "r");

        if (pRootCaFile == NULL) {
            DLOGE("fopen failed to find the root CA certificate file: ROOT_CA_PATH=%s.", pRootCaPath);
            sslStatus = -1;
        }
    }

    if (sslStatus == 1) {
        /* Read the root CA into an X509 object. */
        pRootCa = PEM_read_X509(pRootCaFile, NULL, NULL, NULL);

        if (pRootCa == NULL) {
            DLOGE("PEM_read_X509 failed to parse root CA.");
            sslStatus = -1;
        }
    }

    if (sslStatus == 1) {
        /* Add the certificate to the context. */
        ctx = SSL_CTX_get_cert_store(pSslContext);
        if (ctx == NULL) {
            DLOGE("SSL_CTX_get_cert_store failed");
            sslStatus = -1;
        }
    }

    if (sslStatus == 1) {
        /* Add the certificate to the context. */
        sslStatus = X509_STORE_add_cert(ctx, pRootCa);

        if (sslStatus != 1) {
            DLOGE("X509_STORE_add_cert failed to add root CA to certificate store.");
            sslStatus = -1;
        }
    }

    /* Free the X509 object used to set the root CA. */
    if (pRootCa != NULL) {
        X509_free(pRootCa);
        pRootCa = NULL;
    }

    /* Close the file if it was successfully opened. */
    if (pRootCaFile != NULL) {
        if (FCLOSE(pRootCaFile) != 0) {
            DLOGW("fclose failed to close file %s", pRootCaPath);
        }
    }

    /* Log the success message if we successfully imported the root CA. */
    if (sslStatus == 1) {
        DLOGD("Successfully imported root CA.");
    }

    return sslStatus;
}
/*-----------------------------------------------------------*/

CK_RV findObjectWithLabelAndClass(CK_SESSION_HANDLE xSession,
                                  char * pcLabelName,
                                  CK_ULONG ulLabelNameLen,
                                  CK_OBJECT_CLASS xClass,
                                  CK_OBJECT_HANDLE_PTR pxHandle)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_ULONG ulCount = 0;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_ATTRIBUTE xTemplate[2] = { 0 };

    if ((pcLabelName == NULL) || (pxHandle == NULL)) {
        pkcs11Ret = CKR_ARGUMENTS_BAD;
    } else {
        xTemplate[0].type = CKA_LABEL;
        xTemplate[0].pValue = (CK_VOID_PTR) pcLabelName;
        xTemplate[0].ulValueLen = ulLabelNameLen;
        xTemplate[1].type = CKA_CLASS;
        xTemplate[1].pValue = &xClass;
        xTemplate[1].ulValueLen = sizeof(CK_OBJECT_CLASS);

        pkcs11Ret = C_GetFunctionList(&pxFunctionList);

        if ((pxFunctionList == NULL) || (pxFunctionList->C_FindObjectsInit == NULL) ||
            (pxFunctionList->C_FindObjects == NULL) || (pxFunctionList->C_FindObjectsFinal == NULL)) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    /* Initialize the FindObject state in the underlying PKCS #11 module based
     * on the search template provided by the caller. */
    if (CKR_OK == pkcs11Ret) {
        pkcs11Ret = pxFunctionList->C_FindObjectsInit(xSession, xTemplate, sizeof(xTemplate) / sizeof(CK_ATTRIBUTE));
    }

    if (CKR_OK == pkcs11Ret) {
        /* Find the first matching object, if any. */
        pkcs11Ret = pxFunctionList->C_FindObjects(xSession, pxHandle, 1UL, &ulCount);
    }

    if (CKR_OK == pkcs11Ret) {
        pkcs11Ret = pxFunctionList->C_FindObjectsFinal(xSession);
    }

    if ((NULL != pxHandle) && (ulCount == 0UL)) {
        *pxHandle = CK_INVALID_HANDLE;
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/

static CK_RV destroyProvidedObjects(CK_SESSION_HANDLE session,
                                    CK_BYTE_PTR * pkcsLabelsPtr,
                                    CK_OBJECT_CLASS * pClass,
                                    CK_ULONG count)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_OBJECT_HANDLE objectHandle;
    CK_BYTE * labelPtr;
    CK_ULONG index = 0;

    pkcs11Ret = C_GetFunctionList(&pxFunctionList);

    if ((pxFunctionList == NULL) || (pxFunctionList->C_DestroyObject == NULL)) {
        pkcs11Ret = CKR_FUNCTION_FAILED;
    }

    if (pkcs11Ret == CKR_OK) {
        for (index = 0; index < count; index++) {
            labelPtr = pkcsLabelsPtr[index];

            pkcs11Ret = findObjectWithLabelAndClass(session, (char *) labelPtr,
                                                    strlen((char *) labelPtr),
                                                    pClass[index], &objectHandle);

            while ((pkcs11Ret == CKR_OK) && (objectHandle != CK_INVALID_HANDLE)) {
                pkcs11Ret = pxFunctionList->C_DestroyObject(session, objectHandle);

                /* PKCS #11 allows a module to maintain multiple objects with the same
                 * label and type. The intent of this loop is to try to delete all of
                 * them. However, to avoid getting stuck, we won't try to find another
                 * object of the same label/type if the previous delete failed. */
                if (pkcs11Ret == CKR_OK) {
                    pkcs11Ret = findObjectWithLabelAndClass(session, (char *) labelPtr,
                                                            strlen((char *) labelPtr),
                                                            pClass[index], &objectHandle);
                } else {
                    break;
                }
            }
        }
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/
// 1 :success
static int32_t setClientCertificate(OpensslPkcs11Params_t * pContext,
                                    const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    int32_t sslStatus = -1;
    X509 *cert = NULL;
    unsigned char *certBuffer = NULL;
    size_t certSize = 0;
    int ret = -1;
    CK_RV pkcs11Ret = CKR_OK;
    CK_OBJECT_HANDLE certificateHandle = CK_INVALID_HANDLE;
    CK_ATTRIBUTE template = {CKA_VALUE, NULL, 0};
    CK_FUNCTION_LIST_PTR pxFunctionList;

    if (!pContext || !pContext->pSsl || !pOpensslCredentials || !pOpensslCredentials->pClientCertLabel || !pOpensslCredentials->p11Session) {
        return sslStatus;
    }

    /* Find certificate object handle with given label. */
    pkcs11Ret = findObjectWithLabelAndClass(pOpensslCredentials->p11Session,
                                            pOpensslCredentials->pClientCertLabel,
                                            strlen(pOpensslCredentials->pClientCertLabel),
                                            CKO_CERTIFICATE, &certificateHandle);
    if ((pkcs11Ret == CKR_OK) && (certificateHandle == CK_INVALID_HANDLE)) {
        pkcs11Ret = CKR_OBJECT_HANDLE_INVALID;
        DLOGE("findObjectWithLabelAndClass failed, certificateHandle is NULL ");
    }

    pkcs11Ret = C_GetFunctionList(&pxFunctionList);
    if ((pxFunctionList == NULL) || (pxFunctionList->C_GetAttributeValue == NULL)) {
        pkcs11Ret = CKR_FUNCTION_FAILED;
    }

    /* Get certificate size. */
    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = pxFunctionList->C_GetAttributeValue(pOpensslCredentials->p11Session, certificateHandle, &template, 1);
        if (pkcs11Ret != CKR_OK) {
            DLOGE("C_GetAttributeValue : Get certificate size failed");
        }
    }

    if (pkcs11Ret == CKR_OK) {
        certSize = template.ulValueLen;

        /* Allocate memory for certificate buffer. */
        template.pValue = (unsigned char *) malloc(certSize);
        if (template.pValue == NULL) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    /* Get certificate data. */
    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = pxFunctionList->C_GetAttributeValue(pOpensslCredentials->p11Session, certificateHandle, &template, 1);
        if (pkcs11Ret != CKR_OK) {
            MEMFREE(template.pValue);
        }
    }

    /* Convert certificate buffer to OpenSSL X509 object. */
    if (template.pValue != NULL && pkcs11Ret == CKR_OK) {
        cert = d2i_X509(NULL, (const unsigned char **) &template.pValue, certSize);
    }

    if (cert == NULL) {
        if (template.pValue != NULL) {
            MEMFREE(template.pValue);
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }


    /* Import the client certificate. */
    if (pkcs11Ret == CKR_OK) {
        ret = SSL_use_certificate(pContext->pSsl, cert);
    }

    if (ret != 1) {
        DLOGE("SSL_CTX_use_certificate failed to import client certificate at %s.",
              pOpensslCredentials->pClientCertLabel);
    } else {
        DLOGI("Successfully imported client certificate.");
    }

//    if (template.pValue != NULL) {
//        free(template.pValue);
//    }

    return ret;
}

/*-----------------------------------------------------------*/

static CK_RV getGetAttributeValueWithTemplate(CK_OBJECT_HANDLE objHandle,
        CK_ATTRIBUTE* template, CK_ULONG ulCount,
        const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList;

    if (!pOpensslCredentials || !template) {
        DLOGE("Input paramters is NULL");
        pkcs11Ret = CKR_ARGUMENTS_BAD;
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_GetFunctionList(&pxFunctionList);
        if ((pxFunctionList == NULL) || (pxFunctionList->C_GetAttributeValue == NULL)) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = pxFunctionList->C_GetAttributeValue(pOpensslCredentials->p11Session, objHandle, template, ulCount);
    }

    if (pkcs11Ret == CKR_OK) {
        for (int i = 0; i < ulCount; i++) {
            template[i].pValue = MEMALLOC(template[i].ulValueLen);
            if (template[i].pValue == NULL) {
                pkcs11Ret = CKR_FUNCTION_FAILED;
                DLOGE("content memory malloc failed");
                break;
            }
        }
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = pxFunctionList->C_GetAttributeValue(pOpensslCredentials->p11Session, objHandle, template, ulCount);
        if (pkcs11Ret != CKR_OK) {
            DLOGE("Get RSA private key paramters failed");
        }
    }

    return pkcs11Ret;
}


/*-----------------------------------------------------------*/

static EC_KEY* getPrivateECKey(CK_OBJECT_HANDLE privateKeyHandle,
                               const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_BYTE* ecParamsData = NULL; // CKA_EC_PARAMS值
    CK_BYTE* valueData = NULL;    // CKA_VALUE值
    CK_ULONG ecParamsLength = 0;
    CK_ULONG valueLength = 0;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ATTRIBUTE privateKeyTemplate[2] = {
        { CKA_EC_PARAMS,   NULL, 0 },
        { CKA_VALUE,       NULL, 0 },
    };
    BIGNUM* bnParams = NULL;
    BIGNUM* bnPrivateKey = NULL;
    EC_GROUP* group = NULL;
    EC_KEY* ecKey = NULL;

    pkcs11Ret = getGetAttributeValueWithTemplate(privateKeyHandle, privateKeyTemplate,
            sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE), pOpensslCredentials);

    if (pkcs11Ret == CKR_OK) {
        // Initialize BN parameters and private key from obtained ECC private key attributes
        bnParams = BN_bin2bn(privateKeyTemplate[0].pValue, privateKeyTemplate[0].ulValueLen, NULL);     // CKA_EC_PARAMS
        bnPrivateKey = BN_bin2bn(privateKeyTemplate[1].pValue, privateKeyTemplate[1].ulValueLen, NULL); // CKA_VALUE
    }

    if (bnParams && bnPrivateKey) {
        ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Use the appropriate curve name
    }

    if (ecKey) {
        BIGNUM* pKeyCopy = BN_dup(bnPrivateKey); // Create a copy of the private key
        if (BN_is_zero(pKeyCopy)) {
            BN_clear_free(pKeyCopy);
            ecKey = NULL;
            return ecKey;
        }
        if (EC_KEY_set_private_key(ecKey, pKeyCopy)) {
            EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // Use the appropriate curve name
            if (ecGroup) {
                EC_KEY_set_group(ecKey, ecGroup);
                EC_GROUP_free(ecGroup);
            }
        }
    }

    for (int i = 0; i < sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE); i++) {
        if (privateKeyTemplate[i].pValue != NULL) {
            MEMFREE(privateKeyTemplate[i].pValue);
        }
    }

    return ecKey;
}

static RSA* getPrivateRSAKey(CK_OBJECT_HANDLE privateKeyHandle,
                             const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    int ret = 0;
    RSA *rsa = NULL;
    CK_RV pkcs11Ret = CKR_OK;
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL;
    BIGNUM *bn_q = NULL, *bn_dmp1 = NULL, *bn_dmq1 = NULL, *bn_iqmp = NULL;
    CK_ATTRIBUTE privateKeyTemplate[8] = {
        { CKA_MODULUS,          NULL, 0 },
        { CKA_PRIVATE_EXPONENT, NULL, 0 },
        { CKA_PUBLIC_EXPONENT,  NULL, 0 },
        { CKA_PRIME_1,          NULL, 0 },
        { CKA_PRIME_2,          NULL, 0 },
        { CKA_EXPONENT_1,       NULL, 0 },
        { CKA_EXPONENT_2,       NULL, 0 },
        { CKA_COEFFICIENT,      NULL, 0 }
    };

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = getGetAttributeValueWithTemplate(privateKeyHandle, privateKeyTemplate,
                sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE), pOpensslCredentials);
    }

    if (pkcs11Ret == CKR_OK) {
        // 从获取的 RSA 私钥参数初始化 RSA 对象
        bn_n = BN_bin2bn(privateKeyTemplate[0].pValue, privateKeyTemplate[0].ulValueLen, NULL);    // CKA_MODULUS
        bn_d = BN_bin2bn(privateKeyTemplate[1].pValue, privateKeyTemplate[1].ulValueLen, NULL);    // CKA_PRIVATE_EXPONENT
        bn_e = BN_bin2bn(privateKeyTemplate[2].pValue, privateKeyTemplate[2].ulValueLen, NULL);    // CKA_PUBLIC_EXPONENT
        bn_p = BN_bin2bn(privateKeyTemplate[3].pValue, privateKeyTemplate[3].ulValueLen, NULL);    // CKA_PRIME_1
        bn_q = BN_bin2bn(privateKeyTemplate[4].pValue, privateKeyTemplate[4].ulValueLen, NULL);    // CKA_PRIME_2
        bn_dmp1 = BN_bin2bn(privateKeyTemplate[5].pValue, privateKeyTemplate[5].ulValueLen, NULL); // CKA_EXPONENT_1
        bn_dmq1 = BN_bin2bn(privateKeyTemplate[6].pValue, privateKeyTemplate[6].ulValueLen, NULL); // CKA_EXPONENT_2
        bn_iqmp = BN_bin2bn(privateKeyTemplate[7].pValue, privateKeyTemplate[7].ulValueLen, NULL); // CKA_COEFFICIENT
    }

    if (bn_n && bn_e && bn_d && bn_p && bn_q && bn_dmp1 && bn_dmq1 && bn_iqmp) {
        rsa = RSA_new();
        if (rsa) {
            ret = RSA_set0_key(rsa, bn_n, bn_e, bn_d);
            ret &= RSA_set0_factors(rsa, bn_p, bn_q);
            ret &= RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp);
        }
    }

    for (int i = 0; i < sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE); i++) {
        if (privateKeyTemplate[i].pValue != NULL) {
            MEMFREE(privateKeyTemplate[i].pValue);
        }
    }

    if (ret != 1 && rsa) {
        RSA_free(rsa);
        rsa = NULL;
    }

    return rsa;
}

/*-----------------------------------------------------------*/
static int32_t setPrivateKey(OpensslPkcs11Params_t * pContext,
                             const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    int32_t sslStatus = -1;
    CK_RV pkcs11Ret = CKR_OK;
    CK_ATTRIBUTE template = {0};
    EC_KEY* *ecKey = NULL;
    RSA *rsa = NULL;
    CK_OBJECT_HANDLE privateKeyHandle = CK_INVALID_HANDLE;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_BYTE_PTR pPrivateKeyContent = NULL;
    CK_ULONG ulPrivateKeyContentLen;
    CK_ATTRIBUTE prime1Attribute;
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_p = NULL, *bn_q = NULL, *bn_dmp1 = NULL, *bn_dmq1 = NULL, *bn_iqmp = NULL;
    CK_ATTRIBUTE privateKeyTemplate[8] = {
        { CKA_MODULUS,          NULL, 0 },
        { CKA_PRIVATE_EXPONENT, NULL, 0 },
        { CKA_PUBLIC_EXPONENT,  NULL, 0 },
        { CKA_PRIME_1,          NULL, 0 },
        { CKA_PRIME_2,          NULL, 0 },
        { CKA_EXPONENT_1,       NULL, 0 },
        { CKA_EXPONENT_2,       NULL, 0 },
        { CKA_COEFFICIENT,      NULL, 0 }
    };

    if (!pContext || !pContext->pSsl || !pOpensslCredentials || !pOpensslCredentials->pPrivateKeyLabel || !pOpensslCredentials->p11Session) {
        return sslStatus;
    }

    /* Get the handle of the device private key. */
    pkcs11Ret = findObjectWithLabelAndClass(pOpensslCredentials->p11Session,
                                            (char *) pOpensslCredentials->pPrivateKeyLabel,
                                            strlen(pOpensslCredentials->pPrivateKeyLabel),
                                            CKO_PRIVATE_KEY,
                                            &privateKeyHandle);
    pContext->p11PrivateKey = privateKeyHandle;

    if ((pkcs11Ret == CKR_OK) && (privateKeyHandle == CK_INVALID_HANDLE)) {
        pkcs11Ret = CK_INVALID_HANDLE;
        DLOGE("Could not find private key.");
    }

    pkcs11Ret = C_GetFunctionList(&pxFunctionList);
    if ((pxFunctionList == NULL) || (pxFunctionList->C_GetAttributeValue == NULL)) {
        pkcs11Ret = CKR_FUNCTION_FAILED;
    }

    /* Query the device private key type. */
    if (pkcs11Ret == CKR_OK) {
        template.type = CKA_KEY_TYPE;
        template.pValue = &pContext->keyType;
        template.ulValueLen = sizeof(&pContext->keyType);
        pkcs11Ret = pxFunctionList->C_GetAttributeValue(pOpensslCredentials->p11Session, privateKeyHandle, &template, 1);
    }

    if (pkcs11Ret == CKR_OK) {
        switch (pContext->keyType) {
            case CKK_RSA:
                rsa = getPrivateRSAKey(privateKeyHandle, pOpensslCredentials);
                // 将 RSA 私钥添加到 SSL_CTX 上下文中
                if (rsa) {
                    sslStatus = SSL_use_RSAPrivateKey(pContext->pSsl, rsa);
                    RSA_free(rsa);
                }
                break;

            case CKK_EC:
                DLOGW("Private key type is CKK_EC");
                ecKey = getPrivateECKey(privateKeyHandle, pOpensslCredentials);
                // 将 ECC 密钥对象添加到 SSL_CTX 上下文
                if (ecKey) {
                    sslStatus == SSL_use_PrivateKey(pContext->pSsl, ecKey);
                    EC_KEY_free(ecKey);
                }
                break;

            default:
                pkcs11Ret = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
        }
    }

    if (sslStatus != 1) {
        DLOGE("Add private key content into SSL content failed");
    }

    return sslStatus;
}

/*-----------------------------------------------------------*/

static int32_t setCredentials(OpensslPkcs11Params_t * pSslContext,
                              const OpensslPkcs11Credentials_t * pOpensslCredentials)
{
    int32_t sslStatus = 1;

    if (!pSslContext || !pOpensslCredentials) {
        sslStatus = 0;
        DLOGE("pSslContext  or pOpensslCredentials is NULL");
    }

    if ((sslStatus == 1) && (pOpensslCredentials->pRootCaPath != NULL)) {
        sslStatus = setRootCa(pSslContext, pOpensslCredentials->pRootCaPath);
    }

    if ((sslStatus == 1) && (pOpensslCredentials->pClientCertLabel != NULL)) {
        sslStatus =  setClientCertificate(pSslContext, pOpensslCredentials);
    }

    if ((sslStatus == 1) && (pOpensslCredentials->pPrivateKeyLabel != NULL)) {
        sslStatus =  setPrivateKey(pSslContext, pOpensslCredentials);
    }

    return sslStatus;
}

/*-----------------------------------------------------------*/

static BOOL isValidNetworkContext(const NetworkContext_t * pNetworkContext)
{
    BOOL isValid = FALSE;

    if ((pNetworkContext == NULL) || (pNetworkContext->pParams == NULL)) {
        DLOGE("Parameter check failed: pNetworkContext is NULL.");
    } else if (pNetworkContext->pParams->pSsl == NULL) {
        DLOGE("Failed to receive data over network: SSL object in network context is NULL.");
    } else {
        isValid = TRUE;
    }

    return isValid;
}

/*-----------------------------------------------------------*/

static CK_RV provisionPrivateECKey(CK_SESSION_HANDLE session, const char * label, EVP_PKEY* evpPkey)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_BYTE * DPtr = NULL;        /* Private value D. */
    CK_BYTE * ecParamsPtr = NULL; /* DER-encoding of an ANSI X9.62 Parameters value */
    CK_BBOOL trueObject = CK_TRUE;
    CK_BBOOL falseObject = CK_FALSE;
    CK_KEY_TYPE privateKeyType = CKK_EC;
    CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
    CK_OBJECT_HANDLE objectHandle = CK_INVALID_HANDLE;
    const BIGNUM* bn_d = NULL;
    EC_KEY* ecKey = NULL;
    CK_BYTE_PTR ecParams = NULL;
    CK_ULONG ecParamsLen = 0;
    CK_ULONG privLen;


    // Get the EC_PRIVATEKEY from the OpenSSL EVP_PKEY structure.
    ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
    if (ecKey == NULL) {
        DLOGE("Failed to get OpenSSL EC keypair from EVP_PKEY.\n");
        pkcs11Ret = CKR_GENERAL_ERROR;
    }

    if (pkcs11Ret == CKR_OK) {
        // Get the bytes of the private key.
        bn_d = EC_KEY_get0_private_key(ecKey);
        privLen = (CK_ULONG)((BN_num_bits(bn_d) + 7) / 8);
        DPtr = (CK_BYTE_PTR) OPENSSL_malloc(privLen);
        if (DPtr == NULL) {
            DLOGE("Failed to allocate memory for EC private key value.\n");
            pkcs11Ret =  CKR_HOST_MEMORY;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        if (EC_KEY_priv2oct(ecKey, DPtr, privLen) != privLen) {
            DLOGE("Failed to get EC private key value.\n");
            pkcs11Ret =  CKR_HOST_MEMORY;
        }
    }

    // Get the bytes of the EC curve OID.
    if (pkcs11Ret == CKR_OK) {
        ecParamsLen = (CK_ULONG) i2d_ECParameters(EC_KEY_get0_group(ecKey), &ecParams);
        if (ecParamsLen == 0 || ecParams == NULL) {
            DLOGE("Failed to get EC curve parameters.\n");
            pkcs11Ret =  CKR_HOST_MEMORY;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_GetFunctionList(&pxFunctionList);
        if ((pxFunctionList == NULL) || (pxFunctionList->C_CreateObject == NULL)) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        CK_ATTRIBUTE privateKeyTemplate[] = {
            { CKA_CLASS,     NULL /* &privateKeyClass*/, sizeof(CK_OBJECT_CLASS)  },
            { CKA_KEY_TYPE,  NULL /* &privateKeyType*/,  sizeof(CK_KEY_TYPE)      },
            { CKA_LABEL, (void *) label, (CK_ULONG) strlen(label) },
            { CKA_TOKEN,     NULL /* &trueObject*/,      sizeof(CK_BBOOL)         },
            { CKA_SIGN,      NULL /* &trueObject*/,      sizeof(CK_BBOOL)         },
            { CKA_SENSITIVE,        &falseObject,       sizeof(falseObject)     },
            { CKA_EXTRACTABLE,      &trueObject,        sizeof(trueObject)      },
            { CKA_EC_PARAMS, NULL /* ecParamsPtr*/,      ecParamsLen              },
            { CKA_VALUE,     NULL /* DPtr*/,             privLen                  }
        };

        /* Aggregate initializers must not use the address of an automatic variable. */
        privateKeyTemplate[ 0 ].pValue = &privateKeyClass;
        privateKeyTemplate[ 1 ].pValue = &privateKeyType;
        privateKeyTemplate[ 3 ].pValue = &trueObject;
        privateKeyTemplate[ 4 ].pValue = &trueObject;
        privateKeyTemplate[ 7 ].pValue = ecParamsPtr;
        privateKeyTemplate[ 8 ].pValue = DPtr;

        pkcs11Ret = pxFunctionList->C_CreateObject(session,
                (CK_ATTRIBUTE_PTR) &privateKeyTemplate,
                sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                &objectHandle);
    }

error:

    if (ecParams != NULL) {
        free(ecParams);
    }
    if (ecKey != NULL) {
        EC_KEY_free(ecKey);
    }

    if (DPtr != NULL) {
        OPENSSL_free(DPtr);
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/

static CK_RV provisionPrivateRSAKey(CK_SESSION_HANDLE session,
                                    const char * label,
                                    EVP_PKEY * evpPrivateKey)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_KEY_TYPE privateKeyType = CKK_RSA;
    CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
    CK_BBOOL trueObject = CK_TRUE;
    CK_BBOOL falseObject = CK_FALSE;
    CK_OBJECT_HANDLE objectHandle = CK_INVALID_HANDLE;
    unsigned char *n = NULL, *d = NULL, *e = NULL, *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    int nLen, dLen, eLen, pLen, qLen, dmp1Len, dmq1Len, iqmpLen;
    RSA *rsa = NULL;
    BIGNUM *rsa_n = NULL, *rsa_e = NULL, *rsa_d = NULL, *rsa_p = NULL, *rsa_q = NULL, *rsa_dmp1 = NULL, *rsa_dmq1 = NULL, *rsa_iqmp = NULL;

    rsa = EVP_PKEY_get1_RSA(evpPrivateKey);
    if (!rsa) {
        DLOGE("Failed to extract RSA key pair");
        pkcs11Ret = CKR_ATTRIBUTE_VALUE_INVALID;
    }

    RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
    RSA_get0_factors(rsa, &rsa_p, &rsa_q);
    RSA_get0_crt_params(rsa, &rsa_dmp1, &rsa_dmq1, &rsa_iqmp);

    if (pkcs11Ret == CKR_OK) {
        nLen = BN_num_bytes(rsa_n);
        n = (unsigned char *) OPENSSL_malloc(nLen);
        if (!n) {
            DLOGE("Failed to allocate memory for modulus");
            pkcs11Ret = CKR_HOST_MEMORY;
        }

        BN_bn2bin(rsa_n, n + nLen - BN_num_bytes(rsa_n));
    }

    if (pkcs11Ret == CKR_OK) {
        eLen = BN_num_bytes(rsa_e);
        e = (unsigned char *) OPENSSL_malloc(eLen);
        if (!e) {
            DLOGE("Failed to allocate memory for public exponent");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_e, e + eLen - BN_num_bytes(rsa_e));
    }

    if (pkcs11Ret == CKR_OK) {
        dLen = BN_num_bytes(rsa_d);
        d = (unsigned char *) OPENSSL_malloc(dLen);
        if (!d) {
            DLOGE("Failed to allocate memory for private exponent");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_d, d + dLen - BN_num_bytes(rsa_d));
    }

    if (pkcs11Ret == CKR_OK) {
        pLen = BN_num_bytes(rsa_p);
        p = (unsigned char *) OPENSSL_malloc(pLen);
        if (!p) {
            DLOGE("Failed to allocate memory for prime1");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_p, p + pLen - BN_num_bytes(rsa_p));
    }

    if (pkcs11Ret == CKR_OK) {
        qLen = BN_num_bytes(rsa_q);
        q = (unsigned char *) OPENSSL_malloc(qLen);
        if (!q) {
            DLOGE("Failed to allocate memory for prime2");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_q, q + qLen - BN_num_bytes(rsa_q));
    }

    if (pkcs11Ret == CKR_OK) {
        dmp1Len = BN_num_bytes(rsa_dmp1);
        dmp1 = (unsigned char *) OPENSSL_malloc(dmp1Len);
        if (!dmp1) {
            DLOGE("Failed to allocate memory for exponent1");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_dmp1, dmp1 + dmp1Len - BN_num_bytes(rsa_dmp1));
    }

    if (pkcs11Ret == CKR_OK) {
        dmq1Len = BN_num_bytes(rsa_dmq1);
        dmq1 = (unsigned char *) OPENSSL_malloc(dmq1Len);
        if (!dmq1) {
            DLOGE("Failed to allocate memory for exponent2");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_dmq1, dmq1 + dmq1Len - BN_num_bytes(rsa_dmq1));
    }

    if (pkcs11Ret == CKR_OK) {
        iqmpLen = BN_num_bytes(rsa_iqmp);
        iqmp = (unsigned char *) OPENSSL_malloc(iqmpLen);
        if (!iqmp) {
            DLOGE("Failed to allocate memory for coefficient");
            pkcs11Ret = CKR_HOST_MEMORY;
        }
        BN_bn2bin(rsa_iqmp, iqmp + iqmpLen - BN_num_bytes(rsa_iqmp));
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_GetFunctionList(&pxFunctionList);
        if ((pxFunctionList == NULL) || (pxFunctionList->C_CreateObject == NULL)) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        CK_ATTRIBUTE privateKeyTemplate[] = {
            { CKA_CLASS,            &privateKeyClass,   sizeof(privateKeyClass) },
            { CKA_KEY_TYPE,         &privateKeyType,    sizeof(privateKeyType)  },
            { CKA_LABEL, (void *) label,     strlen(label)           },
            { CKA_TOKEN,            &trueObject,        sizeof(trueObject)      },
            { CKA_SIGN,             &trueObject,        sizeof(trueObject)      },
            { CKA_SENSITIVE,        &falseObject,       sizeof(falseObject)     },
            { CKA_EXTRACTABLE,      &trueObject,        sizeof(trueObject)      },
            { CKA_MODULUS,          n,                  nLen                    },
            { CKA_PRIVATE_EXPONENT, d,                  dLen                    },
            { CKA_PUBLIC_EXPONENT,  e,                  eLen                    },
            { CKA_PRIME_1,          p,                  pLen                    },
            { CKA_PRIME_2,          q,                  qLen                    },
            { CKA_EXPONENT_1,       dmp1,               dmp1Len                 },
            { CKA_EXPONENT_2,       dmq1,               dmq1Len                 },
            { CKA_COEFFICIENT,      iqmp,               iqmpLen                 }
        };

        pkcs11Ret = pxFunctionList->C_CreateObject(session,
                (CK_ATTRIBUTE_PTR) &privateKeyTemplate,
                sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                &objectHandle);
    }

cleanup:
    if (n) {
        OPENSSL_free(n);
    }
    if (d) {
        OPENSSL_free(d);
    }
    if (e) {
        OPENSSL_free(e);
    }
    if (p) {
        OPENSSL_free(p);
    }
    if (q) {
        OPENSSL_free(q);
    }
    if (dmp1) {
        OPENSSL_free(dmp1);
    }
    if (dmq1) {
        OPENSSL_free(dmq1);
    }
    if (iqmp) {
        OPENSSL_free(iqmp);
    }
    if (rsa) {
        RSA_free(rsa);
    }
    EVP_cleanup();

    if (pkcs11Ret != CKR_OK) {
        DLOGE("Failed to create private key object on HSM");
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/
// CKR_OK
static CK_RV provisionPrivateKey(CK_SESSION_HANDLE session,
                                 const char * privateKey,
                                 size_t privateKeyLength,
                                 const char * label)
{
    CK_RV pkcs11Ret = CKR_OK;
    EVP_PKEY * pEvpKey = NULL;
    BIO* pBio = NULL;

    // 将PEM编码的数据读取到BIO中
    pBio = BIO_new_mem_buf((void*) privateKey, -1);
    if (!pBio) {
        DLOGE("BIO_new_mem_buf failed");
        pkcs11Ret = CKR_FUNCTION_FAILED;
    }

    // 从BIO中读取PEM格式的私钥信息
    if (pkcs11Ret == CKR_OK) {
        pEvpKey = PEM_read_bio_PrivateKey(pBio, NULL, NULL, NULL);
        if (pEvpKey == NULL) {
            DLOGE("Unable to parse private key.");
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    /* Determine whether the key to be imported is RSA or EC. */
    if (pkcs11Ret == CKR_OK) {
        if (EVP_PKEY_base_id(pEvpKey) == EVP_PKEY_RSA) {
            pkcs11Ret = provisionPrivateRSAKey(session, label, pEvpKey);
        } else if (EVP_PKEY_base_id(pEvpKey) == EVP_PKEY_EC) {
            pkcs11Ret = provisionPrivateECKey(session, label, pEvpKey);
        } else {
            DLOGE("Invalid private key type provided. Only RSA-2048 and "
                  "EC P-256 keys are supported.");
            pkcs11Ret = CKR_ARGUMENTS_BAD;
        }
    }

    if (pEvpKey) {
        EVP_PKEY_free(pEvpKey);
        pEvpKey = NULL;
    }
    // 释放BIO对象
    if (pBio) {
        BIO_free(pBio);
        pBio = NULL;
    }

    return pkcs11Ret;
}

/* CKR_OK(0) */
static CK_RV provisionCertificate(CK_SESSION_HANDLE session,
                                  const char * certificate,
                                  size_t certificateLength,
                                  const char * label)
{
    CK_RV pkcs11Ret = CKR_OK;
    CK_BBOOL tokenStorage = CK_TRUE;
    CK_OBJECT_HANDLE certHandle  = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS objectClass = CKO_CERTIFICATE;
    CK_FUNCTION_LIST_PTR pxFunctionList = NULL;
    CK_BBOOL trueValue = CK_TRUE;
    CK_BBOOL falseValue = CK_FALSE;
    CK_BYTE subject[] = "TestSubject";
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    X509* cert = NULL;
    BIO* pBio = NULL;
    unsigned char *cert_der = NULL;
    int len = 0;

    if (certificate == NULL) {
        DLOGE("Certificate file path cannot be null.");
        pkcs11Ret = CKR_ATTRIBUTE_VALUE_INVALID;
    }

    /* Read certificate from file and put into BIO */
    pBio = BIO_new_mem_buf((void*) certificate, -1);
    if (!pBio) {
        pkcs11Ret = CKR_HOST_MEMORY;
    }

    /* Get PEM formate certificate info from BIO */
    if (pkcs11Ret == CKR_OK) {
        cert = PEM_read_bio_X509(pBio, NULL, NULL, NULL);
        if (!cert) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    /* Convert OpenSSL certificate into PKCS11 format */
    if (pkcs11Ret == CKR_OK) {
        len = i2d_X509(cert, NULL);
        if (len < 0) {
            DLOGE("Error getting certificate length.\n");
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        cert_der = (unsigned char *)OPENSSL_malloc(len);
        unsigned char * buf = cert_der;
        if (i2d_X509(cert, &buf) < 0) {
            DLOGE("Error converting certificate to DER format.\n");
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_GetFunctionList(&pxFunctionList);
        if ((pxFunctionList == NULL) || (pxFunctionList->C_CreateObject == NULL)) {
            pkcs11Ret = CKR_FUNCTION_FAILED;
        }
    }

    if (pkcs11Ret == CKR_OK) {
        /* Prepare certificate object attributes */
        CK_ATTRIBUTE certTemplate[] = {
            {CKA_CLASS, &objectClass, sizeof(objectClass) },
            {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
            {CKA_TOKEN, &trueValue, sizeof(trueValue) },
            {CKA_PRIVATE, &falseValue, sizeof(falseValue) },
            {CKA_LABEL, label, strlen(label) },
            {CKA_END_DATE, NULL_PTR, 0},
            {CKA_ID, NULL_PTR, 0},
            {CKA_ISSUER, NULL_PTR, 0},
            {CKA_SERIAL_NUMBER, NULL_PTR, 0},
            {CKA_START_DATE, NULL_PTR, 0},
            {CKA_SUBJECT, subject, strlen((const char *) subject) },
            {CKA_VALUE, cert_der, len},
        };

        CK_ULONG certTemplateSize = sizeof(certTemplate) / sizeof(CK_ATTRIBUTE);

        /* Best effort clean-up of the existing object, if it exists. */
        (void)destroyProvidedObjects(session, (CK_BYTE_PTR *) &label, &objectClass, 1);

        /* Create certificate object in PKCS#11 device */
        pkcs11Ret = pxFunctionList->C_CreateObject(session, certTemplate, certTemplateSize, &certHandle);
    }

    if (cert_der) {
        OPENSSL_free(cert_der);
    }

    if (cert) {
        X509_free(cert);
    }

    if (pBio) {
        BIO_free(pBio);
    }

    if (pkcs11Ret != CKR_OK) {
        DLOGE("Error creating certificate object.\n");
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/

OpensslPkcs11Status_t Openssl_Pkcs11_Connect(NetworkContext_t * pNetworkContext,
        const ServerInfo_t * pServerInfo,
        const OpensslPkcs11Credentials_t * pOpensslPkcs11Credentials,
        uint32_t sendTimeoutMs,
        uint32_t recvTimeoutMs)
{
    OpensslPkcs11Params_t * pOpensslParams = NULL;
    SocketStatus_t socketStatus = SOCKETS_SUCCESS;
    OpensslPkcs11Status_t returnStatus = OPENSSL_PKCS11_SUCCESS;
    uint8_t sslObjectCreated = 0;
    SSL_CTX * pSslContext = NULL;
    X509_STORE *pCertStore = NULL;

    /* Validate parameters. */
    if ((pNetworkContext == NULL) || (pNetworkContext->pParams == NULL)) {
        DLOGE("Parameter check failed: pNetworkContext is NULL.");
        returnStatus = OPENSSL_PKCS11_INVALID_PARAMETER;
    } else if (pOpensslPkcs11Credentials == NULL) {
        DLOGE("Parameter check failed: pOpensslCredentials is NULL.");
        returnStatus = OPENSSL_PKCS11_INVALID_PARAMETER;
    } else {
        /* Empty else. */
    }

    /* Establish the TCP connection. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        pOpensslParams = pNetworkContext->pParams;
        pOpensslParams->p11Session = pOpensslPkcs11Credentials->p11Session;

        socketStatus = Sockets_Connect(&pOpensslParams->socketDescriptor,
                                       pServerInfo, sendTimeoutMs, recvTimeoutMs);

        /* Convert socket wrapper status to openssl status. */
        returnStatus = convertToOpensslStatus(socketStatus);
    }

    /* Create SSL context. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        pSslContext = SSL_CTX_new(TLS_client_method());

        if (pSslContext == NULL) {
            DLOGE("Creation of a new SSL_CTX object failed.");
            returnStatus = OPENSSL_PKCS11_API_ERROR;
        }
    }

    /* Create X.509 certificate store */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        pCertStore = X509_STORE_new();
        if (pCertStore == NULL) {
            DLOGE("Creation of a new X.509 certificate store object failed.");
            returnStatus = OPENSSL_PKCS11_API_ERROR;
        } else {
            SSL_CTX_set_cert_store(pSslContext, pCertStore);
        }
    }

    /* Setup credentials. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        /* Enable partial writes for blocking calls to SSL_write to allow a
         * payload larger than the maximum fragment length.
         * The mask returned by SSL_CTX_set_mode does not need to be checked. */

        /* MISRA Directive 4.6 flags the following line for using basic
        * numerical type long. This directive is suppressed because openssl
        * function #SSL_CTX_set_mode takes an argument of type long. */
        /* coverity[misra_c_2012_directive_4_6_violation] */
        (void) SSL_CTX_set_mode(pSslContext, (long) SSL_MODE_ENABLE_PARTIAL_WRITE);

        /* Create a new SSL session. */
        pOpensslParams->pSsl = SSL_new(pSslContext);
        if (pOpensslParams->pSsl == NULL) {
            returnStatus = OPENSSL_PKCS11_API_ERROR;
            DLOGE("SSL_new failed to create a new SSL context.");
        } else {
            sslObjectCreated = 1;
        }
    }

    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        if (!setCredentials(pOpensslParams, pOpensslPkcs11Credentials)) {
            returnStatus = OPENSSL_PKCS11_INVALID_CREDENTIALS;
            DLOGE("Setting up credentials failed.");
        }
    }

    /* Setup the socket to use for communication. */
    if (returnStatus == OPENSSL_PKCS11_SUCCESS) {
        returnStatus = tlsHandshake(pServerInfo, pOpensslParams, pOpensslPkcs11Credentials);
    }

    /* Free the SSL context. */
    if (pSslContext != NULL) {
        SSL_CTX_free(pSslContext);
        pSslContext = NULL;
    }

    /* Clean up on error. */
    if ((returnStatus != OPENSSL_PKCS11_SUCCESS) && (sslObjectCreated == 1)) {
        SSL_free(pOpensslParams->pSsl);
        pOpensslParams->pSsl = NULL;
    }

    /* Log failure or success depending on status. */
    if (returnStatus != OPENSSL_PKCS11_SUCCESS) {
        DLOGE("Failed to establish a TLS connection.");
    } else {
        DLOGI("Established a TLS connection.");
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

OpensslPkcs11Status_t Openssl_Pkcs11_Disconnect(const NetworkContext_t * pNetworkContext)
{
    OpensslPkcs11Params_t * pOpensslParams = NULL;
    SocketStatus_t socketStatus = SOCKETS_INVALID_PARAMETER;

    if (!isValidNetworkContext(pNetworkContext) || (pNetworkContext == NULL) || (pNetworkContext->pParams == NULL)) {
        /* No need to update the status here. The socket status
         * SOCKETS_INVALID_PARAMETER will be converted to openssl
         * status OPENSSL_INVALID_PARAMETER before returning from this
         * function. */
        DLOGE("Parameter check failed: pNetworkContext is NULL.");
    } else {
        pOpensslParams = pNetworkContext->pParams;

        if (pOpensslParams->pSsl != NULL) {
            /* SSL shutdown should be called twice: once to send "close notify" and
             * once more to receive the peer's "close notify". */
            if (SSL_shutdown(pOpensslParams->pSsl) == 0) {
                (void) SSL_shutdown(pOpensslParams->pSsl);
            }

            SSL_free(pOpensslParams->pSsl);
            pOpensslParams->pSsl = NULL;
        }

        /* Tear down the socket connection, pNetworkContext != NULL here. */
        socketStatus = Sockets_Disconnect(pOpensslParams->socketDescriptor);
    }

    return convertToOpensslStatus(socketStatus);
}
/*-----------------------------------------------------------*/

/* MISRA Rule 8.13 flags the following line for not using the const qualifier
 * on `pNetworkContext`. Indeed, the object pointed by it is not modified
 * by OpenSSL, but other implementations of `TransportRecv_t` may do so. */
int32_t Openssl_Pkcs11_Recv(NetworkContext_t * pNetworkContext, void * pBuffer, size_t bytesToRecv)
{
    OpensslPkcs11Params_t * pOpensslParams = NULL;
    int32_t bytesReceived = 0;

    if (!isValidNetworkContext(pNetworkContext) || (pBuffer == NULL) || (bytesToRecv == 0)) {
        DLOGE("Parameter check failed: invalid input, pBuffer = %p, bytesToRecv = %lu", pBuffer, bytesToRecv);
        bytesReceived = -1;
    } else {
        int32_t pollStatus = 1, readStatus = 1, sslError = 0;
        uint8_t shouldRead = 0U;
        struct pollfd pollFds;
        pOpensslParams = pNetworkContext->pParams;

        /* Initialize the file descriptor.
         * #POLLPRI corresponds to high-priority data while #POLLIN corresponds
         * to any other data that may be read. */
        pollFds.events = POLLIN | POLLPRI;
        pollFds.revents = 0;
        /* Set the file descriptor for poll. */
        pollFds.fd = pOpensslParams->socketDescriptor;

        /* #SSL_pending returns a value > 0 if application data
         * from the last processed TLS record remains to be read.
         * This implementation will ALWAYS block when the number of bytes
         * requested is greater than 1. Otherwise, poll the socket first
         * as blocking may negatively impact performance by waiting for the
         * entire duration of the socket timeout even when no data is available. */
        if ((bytesToRecv > 1) || (SSL_pending(pOpensslParams->pSsl) > 0)) {
            shouldRead = 1U;
        } else {
            /* Speculative read for the start of a payload.
             * Note: This is done to avoid blocking when no
             * data is available to be read from the socket. */
            pollStatus = poll(&pollFds, 1, 0);
        }

        if (pollStatus < 0) {
            bytesReceived = -1;
        } else if (pollStatus == 0) {
            /* No data available to be read from the socket. */
            bytesReceived = 0;
        } else {
            shouldRead = 1U;
        }

        if (shouldRead == 1U) {
            /* Blocking SSL read of data.
             * Note: The TLS record may only be partially received or unprocessed,
             * so it is possible that no processed application data is returned
             * even though the socket has data available to be read. */
            readStatus = (int32_t) SSL_read(pOpensslParams->pSsl, pBuffer, (int32_t) bytesToRecv);

            /* Successfully read of application data. */
            if (readStatus > 0) {
                bytesReceived = readStatus;
            }
        }

        /* Handle error return status if transport read did not succeed. */
        if (readStatus <= 0) {
            sslError = SSL_get_error(pOpensslParams->pSsl, readStatus);

            if (sslError == SSL_ERROR_WANT_READ) {
                /* The OpenSSL documentation mentions that SSL_Read can provide a
                 * return code of SSL_ERROR_WANT_READ in blocking mode, if the SSL
                 * context is not configured with with the SSL_MODE_AUTO_RETRY. This
                 * error code means that the SSL_read() operation needs to be retried
                 * to complete the read operation. Thus, setting the return value of
                 * this function as zero to represent that no data was received from
                 * the network. */
                bytesReceived = 0;
            } else {
                DLOGE("Failed to receive data over network: SSL_read failed: "
                      "ErrorStatus=%s.", ERR_reason_error_string(sslError));

                /* The transport interface requires zero return code only when the
                 * receive operation can be retried to achieve success. Thus, convert
                 * a zero error code to a negative return value as this cannot be
                 * retried. */
                bytesReceived = -1;
            }
        }
    }

    return bytesReceived;
}
/*-----------------------------------------------------------*/

/* MISRA Rule 8.13 flags the following line for not using the const qualifier
 * on `pNetworkContext`. Indeed, the object pointed by it is not modified
 * by OpenSSL, but other implementations of `TransportSend_t` may do so. */
int32_t Openssl_Pkcs11_Send(NetworkContext_t * pNetworkContext, const void * pBuffer, size_t bytesToSend)
{
    OpensslPkcs11Params_t * pOpensslParams = NULL;
    int32_t bytesSent = 0;

    if (!isValidNetworkContext(pNetworkContext) || (pBuffer == NULL) || (bytesToSend == 0)) {
        DLOGE("Parameter check failed: invalid input, pBuffer = %p, bytesToSend = %lu", pBuffer, bytesToSend);
        bytesSent = -1;
    } else {
        struct pollfd pollFds;
        int32_t pollStatus;

        pOpensslParams = pNetworkContext->pParams;

        /* Initialize the file descriptor. */
        pollFds.events = POLLOUT;
        pollFds.revents = 0;
        /* Set the file descriptor for poll. */
        pollFds.fd = pOpensslParams->socketDescriptor;

        /* `poll` checks if the socket is ready to send data.
         * Note: This is done to avoid blocking on SSL_write()
         * when TCP socket is not ready to accept more data for
         * network transmission (possibly due to a full TX buffer). */
        pollStatus = poll(&pollFds, 1, 0);

        if (pollStatus > 0) {
            /* SSL write of data. */
            bytesSent = (int32_t) SSL_write(pOpensslParams->pSsl, pBuffer, (int32_t) bytesToSend);

            if (bytesSent <= 0) {
                DLOGE("Failed to send data over network: SSL_write of OpenSSL failed: ErrorStatus=%s.",
                      ERR_reason_error_string(SSL_get_error(pOpensslParams->pSsl, bytesSent)));

                /* As the SSL context is configured for blocking mode, the SSL_write()
                 * function does not return an SSL_ERROR_WANT_READ or
                 * SSL_ERROR_WANT_WRITE error code. The SSL_ERROR_WANT_READ and
                 * SSL_ERROR_WANT_WRITE error codes signify that the write operation can
                 * be retried. However, in the blocking mode, as the SSL_write()
                 * function does not return either of the error codes, we cannot retry
                 * the operation on failure, and thus, this function will never return a
                 * zero error code.
                 */

                /* The transport interface requires zero return code only when the send
                 * operation can be retried to achieve success. Thus, convert a zero
                 * error code to a negative return value as this cannot be retried. */
                if (bytesSent == 0) {
                    bytesSent = -1;
                }
            }
        } else if (pollStatus < 0) {
            /* An error occurred while polling. */
            DLOGE("Unable to send TLS data on network: "
                  "An error occurred while checking availability of TCP socket %d.",
                  pOpensslParams->socketDescriptor);
            bytesSent = -1;
        } else {
            /* Socket is not available for sending data. Set return code for retrying send. */
            bytesSent = 0;
        }
    }

    return bytesSent;
}

/*-----------------------------------------------------------*/

CK_RV xInitializePkcs11Session(CK_SESSION_HANDLE * pxSession)
{
    int ret = 0;
    CK_RV pkcs11Ret = CKR_OK;
    CK_SLOT_ID *slotList = NULL;
    CK_FUNCTION_LIST_PTR pxFunctionList;
    CK_ULONG slotCount = 0;
    CK_C_INITIALIZE_ARGS xInitArgs = { 0 };
    const char *module = "/usr/lib/softhsm/libsofthsm2.so";

    if (SSL_library_init() != 1) {
        DLOGE("SSL_library_init failed");
        return CKR_FUNCTION_FAILED;
    }

    if (OpenSSL_add_all_algorithms() != 1) {
        DLOGE("OpenSSL_add_all_algorithms failed");
        return CKR_FUNCTION_FAILED;
    }
    if (OpenSSL_add_all_digests() != 1) {
        DLOGE("OpenSSL_add_all_digests failed");
        return CKR_FUNCTION_FAILED;
    }
    ERR_load_crypto_strings();
    ERR_clear_error();
    ENGINE_add_conf_module();
    ENGINE_load_builtin_engines();

    p11Engine = NULL;
    p11Engine = ENGINE_by_id("pkcs11");
    if (p11Engine == NULL) {
        DLOGE("Could not get engine\n");
        return CKR_FUNCTION_FAILED;
    }
    DLOGI("Engine id=%s, name=%s", ENGINE_get_id(p11Engine), ENGINE_get_name(p11Engine));

    pkcs11Ret = ENGINE_set_default(p11Engine, ENGINE_METHOD_ALL);
    if (!pkcs11Ret) {
        DLOGE("ENGINE_set_default - failed\n");
        return CKR_FUNCTION_FAILED;
    }


    pkcs11Ret = ENGINE_ctrl_cmd_string(p11Engine, "VERBOSE", NULL, 0);
    if (!pkcs11Ret) {
        DLOGE("ENGINE_ctrl_cmd_string - VERBOSE\n");
        return CKR_FUNCTION_FAILED;
    }

    pkcs11Ret = ENGINE_ctrl_cmd_string(p11Engine, "MODULE_PATH", module, 0);
    if (!pkcs11Ret) {
        DLOGE("ENGINE_ctrl_cmd_string  - MODULE_PATH\n");
        return CKR_FUNCTION_FAILED;
    }

    pkcs11Ret = ENGINE_init(p11Engine);
    if (!pkcs11Ret) {
        DLOGE("Could not initialize engine\n");
        return CKR_FUNCTION_FAILED;
    }

    pkcs11Ret = C_GetFunctionList(&pxFunctionList);
    if (pxFunctionList == NULL || pkcs11Ret != CKR_OK) {
        DLOGE("C_GetFunctionList failed");
    }

    if (pkcs11Ret == CKR_OK) {
        xInitArgs.CreateMutex = NULL;
        xInitArgs.DestroyMutex = NULL;
        xInitArgs.LockMutex = NULL;
        xInitArgs.UnlockMutex = NULL;
        xInitArgs.flags = CKF_OS_LOCKING_OK;
        xInitArgs.pReserved = NULL;
        pkcs11Ret = pxFunctionList->C_Initialize(&xInitArgs);
    }

    /* Get a list of slots available. */
    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = pxFunctionList->C_GetSlotList(CK_TRUE,   /* Token Present. */
                NULL,    /* We just want to know how many slots there are. */
                &slotCount);

        if (pkcs11Ret == CKR_OK) {
            if (slotCount == ((sizeof(CK_SLOT_ID) * (slotCount)) / (sizeof(CK_SLOT_ID)))) {
                slotList = MEMALLOC(sizeof(CK_SLOT_ID) * (slotCount));

                if (slotList == NULL) {
                    pkcs11Ret = CKR_HOST_MEMORY;
                }
            } else {
                pkcs11Ret = CKR_HOST_MEMORY;
            }
        } else {
            DLOGE("C_GetSlotList failed\n");
            pkcs11Ret = CKR_SLOT_ID_INVALID;
        }
    }

    // Call C_GetSlotList second times，get the slotID
    if ((pkcs11Ret == CKR_OK) && (slotList != NULL)) {
        pkcs11Ret = pxFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        if (pkcs11Ret != CKR_OK) {
            DLOGE("C_GetSlotList failed\n");
            pkcs11Ret = CKR_SLOT_ID_INVALID;
            MEMFREE(slotList);
        }
    }

    /* Open a PKCS #11 session. */
    if ((pkcs11Ret == CKR_OK) && (slotList != NULL) && (slotCount >= 1UL)) {
        /* We will take the first slot available.
         * If your application has multiple slots, insert logic
         * for selecting an appropriate slot here.
         */
        pkcs11Ret = pxFunctionList->C_OpenSession(slotList[0],
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                NULL, /* Application defined pointer. */
                NULL, /* Callback function. */
                pxSession);

        MEMFREE(slotList);
    }

    if ((pkcs11Ret == CKR_OK) && (pxFunctionList != NULL) && (pxFunctionList->C_Login != NULL)) {
        pkcs11Ret = pxFunctionList->C_Login(*pxSession,
                                            CKU_USER,
                                            (CK_UTF8CHAR_PTR) pkcs11configPKCS11_DEFAULT_USER_PIN,
                                            STRLEN(pkcs11configPKCS11_DEFAULT_USER_PIN));
    }

    return pkcs11Ret;
}

/*-----------------------------------------------------------*/

/* Return : TRUE, success */
BOOL loadClaimCredentialsAndKey(CK_SESSION_HANDLE p11Session,
                                const char * pClaimCertPath,
                                const char * pClaimCertLabel,
                                const char * pClaimPrivKeyPath,
                                const char * pClaimPrivKeyLabel)
{
    CK_RV ret = CKR_OK;
    BOOL status = FALSE;
    STATUS retStatus = STATUS_SUCCESS;
    char claimCert[ CLAIM_CERT_BUFFER_LENGTH ] = { 0 };
    char claimPrivateKey[ CLAIM_PRIVATE_KEY_BUFFER_LENGTH ] = { 0 };
    size_t claimCertLength = CLAIM_CERT_BUFFER_LENGTH;
    size_t claimPrivateKeyLength = CLAIM_PRIVATE_KEY_BUFFER_LENGTH;

    if (!pClaimCertPath || !pClaimCertLabel || !pClaimPrivKeyPath || !pClaimPrivKeyLabel) {
        DLOGE("The input parameter is NULL");
        retStatus = STATUS_NULL_ARG;
    }

    retStatus = readFile(pClaimCertPath, TRUE, claimCert, &claimCertLength);
    if (retStatus != STATUS_SUCCESS) {
        DLOGE("Read claimcert file returned status code: 0x%08x \n", retStatus);
    } else {
        retStatus = readFile(pClaimPrivKeyPath, TRUE, claimPrivateKey,
                             &claimPrivateKeyLength);
    }
    if (retStatus != STATUS_SUCCESS) {
        DLOGE("Read private key file returned status code: 0x%08x \n", retStatus);
    }

    if (retStatus == STATUS_SUCCESS) {
        ret = provisionPrivateKey(p11Session,
                                  claimPrivateKey,
                                  claimPrivateKeyLength,
                                  pClaimPrivKeyLabel);
        status = (ret == CKR_OK);
    }

    if (status == TRUE) {
        ret = provisionCertificate(p11Session,
                                   claimCert,
                                   claimCertLength,
                                   pClaimCertLabel);
        status = (ret == CKR_OK);
    }

    return status;
}

/*-----------------------------------------------------------*/

BOOL loadCertificateAndKey(CK_SESSION_HANDLE p11Session,
                           const char * pCertificate,
                           const char * pCertificateLabel,
                           size_t certificateLength,
                           const char * pPrivateKey,
                           const char * pPrivateKeyLabel,
                           size_t privateKeyLength)
{
    CK_RV ret;
    BOOL status = TRUE;

    if (!pCertificate || !pCertificateLabel || !pPrivateKey || !pPrivateKeyLabel) {
        DLOGE("The input parameter is NULL");
        status = FALSE;
    }

    if (status == TRUE) {
        ret = provisionCertificate(p11Session,
                                   pCertificate,
                                   certificateLength,
                                   pCertificateLabel);
        status = (ret == CKR_OK);
    }

    if (status == TRUE) {
        ret = provisionPrivateKey(p11Session,
                                  pPrivateKey,
                                  privateKeyLength,
                                  pPrivateKeyLabel);
        status = (ret == CKR_OK);
    }

    return status;
}

/*-----------------------------------------------------------*/

BOOL pkcs11CloseSession(CK_SESSION_HANDLE p11Session)
{
    CK_RV pkcs11Ret = CKR_OK;

    pkcs11Ret = C_Logout(p11Session);

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_CloseSession(p11Session);
    }

    if (pkcs11Ret == CKR_OK) {
        pkcs11Ret = C_Finalize(NULL);
    }

    if (!ENGINE_remove(p11Engine)) {
        DLOGE("Remove PKCS #11 engine failed");
    }

    ENGINE_free(p11Engine);

    return (pkcs11Ret == CKR_OK);
}


