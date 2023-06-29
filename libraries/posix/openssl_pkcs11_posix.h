/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef OPENSSL_PKCS11_POSIX_H_
#define OPENSSL_PKCS11_POSIX_H_

// SoftHSM library file path
#define SOFTHSM_LIB "/usr/lib/softhsm/libsofthsm2.so"
/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define CLAIM_CERT_BUFFER_LENGTH           2048

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define CLAIM_PRIVATE_KEY_BUFFER_LENGTH    2048

#define pkcs11configLABEL_CLAIM_CERTIFICATE                "Claim Cert"
#define pkcs11configLABEL_CLAIM_PRIVATE_KEY                "Claim Key"
#define pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS       "Device Cert"
#define pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS       "Device Priv TLS Key"
#define pkcs11configPKCS11_DEFAULT_USER_PIN                "1234"

/* *INDENT-OFF* */
#ifdef __cplusplus
    extern "C" {
#endif
/* *INDENT-ON* */

/* OpenSSL include. */
#include <openssl/ssl.h>

/* Transport includes. */
#include "transport_interface.h"
/* Socket include. */
#include "sockets_posix.h"

/**
 * @brief Parameters for the transport-interface
 * implementation that uses OpenSSL and POSIX sockets.
 *
 * @note For this transport implementation, the socket descriptor and
 * SSL context is used.
 */
typedef struct OpensslParams
{
    int32_t socketDescriptor;
    SSL * pSsl;

    /* PKCS #11. */
    CK_FUNCTION_LIST_PTR pP11FunctionList; /**< @brief PKCS #11 function list. */
    CK_SESSION_HANDLE p11Session;          /**< @brief PKCS #11 session. */
    CK_OBJECT_HANDLE p11PrivateKey;        /**< @brief PKCS #11 handle for the private key to use for client authentication. */
    CK_KEY_TYPE keyType;                   /**< @brief PKCS #11 key type corresponding to #p11PrivateKey. */
} OpensslPkcs11Params_t;

/**
 * @brief OpenSSL Connect / Disconnect return status.
 */
typedef enum OpensslStatus
{
    OPENSSL_PKCS11_SUCCESS = 0,         /**< Function successfully completed. */
    OPENSSL_PKCS11_INVALID_PARAMETER,   /**< At least one parameter was invalid. */
    OPENSSL_PKCS11_INSUFFICIENT_MEMORY, /**< Insufficient memory required to establish connection. */
    OPENSSL_PKCS11_INVALID_CREDENTIALS, /**< Provided credentials were invalid. */
    OPENSSL_PKCS11_HANDSHAKE_FAILED,    /**< Performing TLS handshake with server failed. */
    OPENSSL_PKCS11_API_ERROR,           /**< A call to a system API resulted in an internal error. */
    OPENSSL_PKCS11_DNS_FAILURE,         /**< Resolving hostname of the server failed. */
    OPENSSL_PKCS11_CONNECT_FAILURE      /**< Initial connection to the server failed. */
} OpensslPkcs11Status_t;

/**
 * @brief Contains the credentials to establish a TLS connection.
 */
typedef struct OpensslCredentials
{
    /**
     * @brief An array of ALPN protocols. Set to NULL to disable ALPN.
     *
     * See [this link]
     * (https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/)
     * for more information.
     */
    const char * pAlpnProtos;

    /**
     * @brief Length of the ALPN protocols array.
     */
    uint32_t alpnProtosLen;

    /**
     * @brief Set a host name to enable SNI. Set to NULL to disable SNI.
     *
     * @note This string must be NULL-terminated because the OpenSSL API requires it to be.
     */
    const char * sniHostName;

    /**
     * @brief Set the value for the TLS max fragment length (TLS MFLN)
     *
     * OpenSSL allows this value to be in the range of:
     * [512, 16384 (SSL3_RT_MAX_PLAIN_LENGTH)]
     *
     * @note By setting this to 0, OpenSSL uses the default value,
     * which is 16384 (SSL3_RT_MAX_PLAIN_LENGTH).
     */
    uint16_t maxFragmentLength;

    /**
     * @brief Filepaths to certificates and private key that are used when
     * performing the TLS handshake.
     *
     * @note These strings must be NULL-terminated because the OpenSSL API requires them to be.
     */
    const char * pRootCaPath;           /**< @brief Filepath string to the trusted server root CA. */
    const char * pClientCertLabel;      /**< @brief String representing the PKCS #11 label for the client certificate. */
    const char * pPrivateKeyLabel;      /**< @brief String representing the PKCS #11 label for the private key. */
    CK_SESSION_HANDLE p11Session;       /**< @brief PKCS #11 session handle. */
} OpensslPkcs11Credentials_t;

/**
 * @brief Sets up a TLS session on top of a TCP connection using the OpenSSL API.
 *
 * @param[out] pNetworkContext The output parameter to return the created network context.
 * @param[in] pServerInfo Server connection info.
 * @param[in] pOpensslPkcs11Credentials Credentials for the TLS connection.
 * @param[in] sendTimeoutMs Timeout for transport send.
 * @param[in] recvTimeoutMs Timeout for transport recv.
 *
 * @note A timeout of 0 means infinite timeout.
 *
 * @return #OPENSSL_SUCCESS on success;
 * #OPENSSL_INVALID_PARAMETER, #OPENSSL_INVALID_CREDENTIALS,
 * #OPENSSL_INVALID_CREDENTIALS, #OPENSSL_SYSTEM_ERROR on failure.
 */
OpensslPkcs11Status_t Openssl_Pkcs11_Connect( NetworkContext_t * pNetworkContext,
                                 const ServerInfo_t * pServerInfo,
                                 const OpensslPkcs11Credentials_t * pOpensslPkcs11Credentials,
                                 uint32_t sendTimeoutMs,
                                 uint32_t recvTimeoutMs );

/**
 * @brief Closes a TLS session on top of a TCP connection using the OpenSSL API.
 *
 * @param[out] pNetworkContext The output parameter to end the TLS session and
 * clean the created network context.
 *
 * @return #OPENSSL_SUCCESS on success; #OPENSSL_INVALID_PARAMETER on failure.
 */
OpensslPkcs11Status_t Openssl_Pkcs11_Disconnect( const NetworkContext_t * pNetworkContext );

/**
 * @brief Receives data over an established TLS session using the OpenSSL API.
 *
 * This can be used as #TransportInterface.recv function for receiving data
 * from the network.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 * @param[out] pBuffer Buffer to receive network data into.
 * @param[in] bytesToRecv Number of bytes requested from the network.
 *
 * @return Number of bytes received if successful; negative value to indicate failure.
 * A return value of zero represents that the receive operation can be retried.
 */
int32_t Openssl_Pkcs11_Recv( NetworkContext_t * pNetworkContext,
                      void * pBuffer,
                      size_t bytesToRecv );

/**
 * @brief Sends data over an established TLS session using the OpenSSL API.
 *
 * This can be used as the #TransportInterface.send function to send data
 * over the network.
 *
 * @param[in] pNetworkContext The network context created using Openssl_Connect API.
 * @param[in] pBuffer Buffer containing the bytes to send over the network stack.
 * @param[in] bytesToSend Number of bytes to send over the network.
 *
 * @return Number of bytes sent if successful; negative value on error.
 *
 * @note This function does not return zero value because it cannot be retried
 * on send operation failure.
 */
int32_t Openssl_Pkcs11_Send( NetworkContext_t * pNetworkContext,
                      const void * pBuffer,
                      size_t bytesToSend );

/* *INDENT-OFF* */
#ifdef __cplusplus
    }
#endif
/* *INDENT-ON* */

#endif /* ifndef OPENSSL_PKCS11_POSIX_H_ */
