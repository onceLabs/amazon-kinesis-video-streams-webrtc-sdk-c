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

/*
 * Demo for showing use of the Fleet Provisioning library to use the Fleet
 * Provisioning feature of AWS IoT Core for provisioning devices with
 * credentials. This demo shows how a device can be provisioned with AWS IoT
 * Core using the Certificate Signing Request workflow of the Fleet
 * Provisioning feature.
 *
 * The Fleet Provisioning library provides macros and helper functions for
 * assembling MQTT topics strings, and for determining whether an incoming MQTT
 * message is related to the Fleet Provisioning API of AWS IoT Core. The Fleet
 * Provisioning library does not depend on any particular MQTT library,
 * therefore the functionality for MQTT operations is placed in another file
 * (mqtt_operations.c). This demo uses the coreMQTT library. If needed,
 * mqtt_operations.c can be modified to replace coreMQTT with another MQTT
 * library. This demo requires using the AWS IoT Core broker as Fleet
 * Provisioning is an AWS IoT Core feature.
 *
 * This demo provisions a device certificate using the provisioning by claim
 * workflow with a Certificate Signing Request (CSR). The demo connects to AWS
 * IoT Core using provided claim credentials (whose certificate needs to be
 * registered with IoT Core before running this demo), subscribes to the
 * CreateCertificateFromCsr topics, and obtains a certificate. It then
 * subscribes to the RegisterThing topics and activates the certificate and
 * obtains a Thing using the provisioning template. Finally, it reconnects to
 * AWS IoT Core using the new credentials.
 */
#define LOG_CLASS "WebRtcSamples"

/* Standard includes. */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>


#include "Samples.h"

/* POSIX includes. */
#include <unistd.h>
#include <errno.h>

#ifdef ENABLE_PKCS11
/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"
#endif

/* AWS IoT Fleet Provisioning Library. */
#include "fleet_provisioning.h"

/* Demo includes. */
#include "mqtt_operations.h"
#ifdef ENABLE_PKCS11
#include "pkcs11_operations.h"
#endif
#include "fleet_provisioning_serializer.h"

/**
 * @brief Size of AWS IoT Thing name buffer.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_CreateThing.html#iot-CreateThing-request-thingName
 */
#define MAX_THING_NAME_LENGTH                128
/**
 * @brief Size of AWS IoT Template name buffer.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_CreateProvisioningTemplateVersion.html#API_CreateProvisioningTemplateVersion_RequestSyntax
*/
#define MAX_TEMPLATE_NAME_LENGTH             36
/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef FLEET_PROV_MAX_DEMO_LOOP_COUNT
#define FLEET_PROV_MAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS    ( 5 )

/**
 * @brief Size of buffer in which to hold the certificate signing request (CSR).
 */
#define CSR_BUFFER_LENGTH                              2048

/**
 * @brief Size of buffer in which to hold the certificate.
 */
#define CERT_BUFFER_LENGTH                             2048

/**
 * @brief Size of buffer in which to hold the certificate id.
 *
 * See https://docs.aws.amazon.com/iot/latest/apireference/API_Certificate.html#iot-Type-Certificate-certificateId
 */
#define CERT_ID_BUFFER_LENGTH                          64

/**
 * @brief Size of buffer in which to hold the certificate ownership token.
 */
#define OWNERSHIP_TOKEN_BUFFER_LENGTH                  512

/**
 * @brief Size of buffer in which to hold the certificate ownership token.
 */
#define PRIVATE_KEY_BUFFER_LENGTH                      2048

/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum {
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;

/*-----------------------------------------------------------*/

/**
 * @brief Status reported from the MQTT publish callback.
 */
static ResponseStatus_t responseStatus;

/**
 * @brief Buffer to hold the provisioned AWS IoT Thing name.
 */
static char thingName[ MAX_THING_NAME_LENGTH ];

/**
 * @brief Length of the AWS IoT Thing name.
 */
static size_t thingNameLength;

/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t payloadBuffer[ NETWORK_BUFFER_SIZE ];

/**
 * @brief Length of the payload stored in #payloadBuffer. This is set by the
 * MQTT publish callback when it copies a received payload into #payloadBuffer.
 */
static size_t payloadLength;

/**
 * @brief Buffer to hold the provisioned AWS IoT Template name.
 */
static char templateName[MAX_TEMPLATE_NAME_LENGTH];
/*-----------------------------------------------------------*/

/**
 * @brief Callback to receive the incoming publish messages from the MQTT
 * broker. Sets responseStatus if an expected CreateCertificateFromCsr or
 * RegisterThing response is received, and copies the response into
 * responseBuffer if the response is an accepted one.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] packetIdentifier Packet identifier of the incoming publish.
 */
static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
        uint16_t packetIdentifier );

/**
 * @brief Run the MQTT process loop to get a response.
 */
static bool waitForResponse( void );

/**
 * @brief Subscribe to the CreateKeysAndCertificate  accepted and rejected topics.
 */
static bool subscribeToKeysResponseTopics( void );

/**
 * @brief Unsubscribe from the CreateKeysAndCertificate  accepted and rejected topics.
 */
static bool unsubscribeFromKeysResponseTopics( void );

/**
 * @brief Subscribe to the RegisterThing accepted and rejected topics.
 */
static bool subscribeToRegisterThingResponseTopics( void );

/**
 * @brief Unsubscribe from the RegisterThing accepted and rejected topics.
 */
static bool unsubscribeFromRegisterThingResponseTopics( void );

/*-----------------------------------------------------------*/

static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
        uint16_t packetIdentifier )
{
    FleetProvisioningStatus_t status;
    FleetProvisioningTopic_t api;
    const char * cborDump;

    /* Silence compiler warnings about unused variables. */
    ( void ) packetIdentifier;

    status = FleetProvisioning_MatchTopic(pPublishInfo->pTopicName, pPublishInfo->topicNameLength, &api);

    if ( status != FleetProvisioningSuccess ) {
        DLOGW("Unexpected publish message received. Topic: %.*s.",
              ( int ) pPublishInfo->topicNameLength,
              ( const char * ) pPublishInfo->pTopicName);
    }


    if ( api == FleetProvCborCreateCertFromCsrAccepted ) {
        DLOGI("Received accepted response from Fleet Provisioning CreateCertificateFromCsr API.");

        cborDump = getStringFromCbor(( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength);
        DLOGD("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseAccepted;

        /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
        ( void ) memcpy( ( void * ) payloadBuffer,
                         ( const void * ) pPublishInfo->pPayload,
                         ( size_t ) pPublishInfo->payloadLength );

        payloadLength = pPublishInfo->payloadLength;
    } else if ( api == FleetProvCborCreateCertFromCsrRejected ) {
        DLOGE("Received rejected response from Fleet Provisioning CreateCertificateFromCsr API.");

        cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
        DLOGE("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseRejected;
    } else if ( api == FleetProvCborRegisterThingAccepted ) {
        DLOGI("Received accepted response from Fleet Provisioning RegisterThing API.");

        cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
        DLOGD("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseAccepted;

        /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
        ( void ) memcpy( ( void * ) payloadBuffer,
                         ( const void * ) pPublishInfo->pPayload,
                         ( size_t ) pPublishInfo->payloadLength );

        payloadLength = pPublishInfo->payloadLength;
    } else if ( api == FleetProvCborRegisterThingRejected ) {
        DLOGE("Received rejected response from Fleet Provisioning RegisterThing API.");

        cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
        DLOGD("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseRejected;
    } else if ( api == FleetProvCborCreateKeysAndCertAccepted ) {
        DLOGI("Received accepted response from Fleet Provisioning CreateKeysAndCertificate API.");

        cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
        DLOGD("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseAccepted;

        /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
        ( void ) memcpy( ( void * ) payloadBuffer,
                         ( const void * ) pPublishInfo->pPayload,
                         ( size_t ) pPublishInfo->payloadLength );

        payloadLength = pPublishInfo->payloadLength;
    } else if ( api == FleetProvCborCreateKeysAndCertRejected ) {
        DLOGE( "Received rejected response from Fleet Provisioning CreateKeysAndCertificate API.");

        cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
        DLOGD("Payload: %s", cborDump);
        free( ( void * ) cborDump );

        responseStatus = ResponseRejected;
    } else {
        DLOGE("Received message on unexpected Fleet Provisioning topic. Topic: %.*s.",
              ( int ) pPublishInfo->topicNameLength,
              ( const char * ) pPublishInfo->pTopicName);
    }
}
/*-----------------------------------------------------------*/

static bool waitForResponse( void )
{
    bool status = FALSE;

    responseStatus = ResponseNotReceived;

    /* responseStatus is updated from the MQTT publish callback. */
    ( void ) ProcessLoopWithTimeout();

    if ( responseStatus == ResponseNotReceived ) {
        DLOGE("Timed out waiting for response.");
    }

    if ( responseStatus == ResponseAccepted ) {
        status = TRUE;
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToKeysResponseTopics( void )
{
    bool status;

    status = SubscribeToTopic( FP_CBOR_CREATE_KEYS_ACCEPTED_TOPIC,
                               FP_CBOR_CREATE_KEYS_ACCEPTED_LENGTH );

    if ( status == FALSE ) {
        DLOGE("Failed to subscribe to fleet provisioning topic: %.*s.",
              FP_CBOR_CREATE_KEYS_ACCEPTED_LENGTH,
              FP_CBOR_CREATE_KEYS_ACCEPTED_TOPIC);
    }

    if ( status == TRUE ) {
        status = SubscribeToTopic( FP_CBOR_CREATE_KEYS_REJECTED_TOPIC,
                                   FP_CBOR_CREATE_KEYS_REJECTED_LENGTH );

        if ( status == FALSE ) {
            DLOGE("Failed to subscribe to fleet provisioning topic: %.*s.",
                  FP_CBOR_CREATE_KEYS_REJECTED_LENGTH,
                  FP_CBOR_CREATE_KEYS_REJECTED_TOPIC);
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromKeysResponseTopics( void )
{
    bool status;

    status = UnsubscribeFromTopic( FP_CBOR_CREATE_KEYS_ACCEPTED_TOPIC,
                                   FP_CBOR_CREATE_KEYS_ACCEPTED_LENGTH );

    if ( status == FALSE ) {
        DLOGE("Failed to unsubscribe from fleet provisioning topic: %.*s.",
              FP_CBOR_CREATE_KEYS_ACCEPTED_LENGTH,
              FP_CBOR_CREATE_KEYS_ACCEPTED_TOPIC);
    }

    if ( status == TRUE ) {
        status = UnsubscribeFromTopic( FP_CBOR_CREATE_KEYS_REJECTED_TOPIC,
                                       FP_CBOR_CREATE_KEYS_REJECTED_LENGTH );

        if ( status == FALSE ) {
            DLOGE("Failed to unsubscribe from fleet provisioning topic: %.*s.",
                  FP_CBOR_CREATE_KEYS_REJECTED_LENGTH,
                  FP_CBOR_CREATE_KEYS_REJECTED_TOPIC);
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToRegisterThingResponseTopics( void )
{
    bool status;
    char acceptedTopic[512];
    char rejectedTopic[512];

    SNPRINTF(acceptedTopic, SIZEOF(acceptedTopic),
             FP_REGISTER_API_PREFIX "%s" FP_REGISTER_API_BRIDGE FP_API_CBOR_FORMAT FP_API_ACCEPTED_SUFFIX, templateName);
    SNPRINTF(rejectedTopic, SIZEOF(rejectedTopic),
             FP_REGISTER_API_PREFIX "%s" FP_REGISTER_API_BRIDGE FP_API_CBOR_FORMAT FP_API_ACCEPTED_SUFFIX, templateName);

    status = SubscribeToTopic(acceptedTopic, STRLEN(acceptedTopic));

    if ( status == FALSE ) {
        DLOGE("Failed to subscribe to fleet provisioning topic: %.*s.",
              STRLEN(acceptedTopic), acceptedTopic);
    }

    if ( status == TRUE ) {
        status = SubscribeToTopic(rejectedTopic, STRLEN(rejectedTopic));

        if ( status == FALSE ) {
            DLOGE("Failed to subscribe to fleet provisioning topic: %.*s.",
                  STRLEN(rejectedTopic), rejectedTopic);
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromRegisterThingResponseTopics( void )
{
    bool status;
    char acceptedTopic[512];
    char rejectedTopic[512];

    SNPRINTF(acceptedTopic, SIZEOF(acceptedTopic),
             FP_REGISTER_API_PREFIX "%s" FP_REGISTER_API_BRIDGE FP_API_CBOR_FORMAT FP_API_ACCEPTED_SUFFIX, templateName);
    SNPRINTF(rejectedTopic, SIZEOF(rejectedTopic),
             FP_REGISTER_API_PREFIX "%s" FP_REGISTER_API_BRIDGE FP_API_CBOR_FORMAT FP_API_ACCEPTED_SUFFIX, templateName);

    status = UnsubscribeFromTopic(acceptedTopic, STRLEN(acceptedTopic));

    if ( status == FALSE ) {
        DLOGE("Failed to unsubscribe from fleet provisioning topic: %.*s.",
              STRLEN(acceptedTopic), acceptedTopic);
    }

    if ( status == TRUE ) {
        status = UnsubscribeFromTopic(rejectedTopic, STRLEN(rejectedTopic));

        if ( status == FALSE ) {
            DLOGE("Failed to unsubscribe from fleet provisioning topic: %.*s.",
                  STRLEN(rejectedTopic), rejectedTopic);
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool writeBufferToFile( char *pBuffer, size_t size, const char *pFileName )
{
    int i = 0;
    FILE *file = NULL;

    if ( pBuffer == NULL || pFileName == NULL ) {
        DLOGE("Invalid parameters to writecertificate...");
        return FALSE;
    }

    file = FOPEN( pFileName, "w" );
    if ( !file ) {
        DLOGE("Failed to open file %s for writing certificate...", pFileName);
        return FALSE;
    }

    FWRITE(pBuffer, size, 1, file);

    FCLOSE( file );

    return TRUE;
}
/*-----------------------------------------------------------*/


/* Uses the Fleet Provisioning library to generate and validate AWS IoT Fleet
 * Provisioning MQTT topics, and use the coreMQTT library to communicate with
 * the AWS IoT Fleet Provisioning APIs. */
STATUS createCredentialAndKey(PCHAR pClaimCertPath, PCHAR pClaimKeyPath, PCHAR pIotCoreCert,
                              PCHAR pIotCorePrivateKey, PCHAR pSerialNum, PCHAR pTemplate, PCHAR pEndpoint, PCHAR pRootCaCert)
{
    STATUS retStatus = STATUS_SUCCESS;
    bool status = FALSE;
    /* Buffer for holding the CSR. */
    char csr[ CSR_BUFFER_LENGTH ] = { 0 };
    size_t csrLength = 0;
    /* Buffer for holding received certificate until it is saved. */
    char certificate[ CERT_BUFFER_LENGTH ];
    size_t certificateLength;
    /* Buffer for holding the certificate ID. */
    char certificateId[ CERT_ID_BUFFER_LENGTH ];
    size_t certificateIdLength;
    /* Buffer for holding the certificate ownership token. */
    char ownershipToken[ OWNERSHIP_TOKEN_BUFFER_LENGTH ];
    size_t ownershipTokenLength;
    /* Buffer for holding the private key. */
    char privateKey[ PRIVATE_KEY_BUFFER_LENGTH ];
    size_t privateKeyLength;
    bool connectionEstablished = FALSE;
    int runCount = 0;

#ifdef ENABLE_PKCS11
    CK_RV pkcs11ret = CKR_OK;
    CK_SESSION_HANDLE p11Session;
    bool createPKCS11Session = FALSE;
#endif

    MEMCPY(templateName, pTemplate, STRLEN(pTemplate));
    DLOGV("claimCertPath:      %s\n", pClaimCertPath);
    DLOGV("claimKeyPath:       %s\n", pClaimKeyPath);
    DLOGV("pIotCoreCert:       %s\n", pIotCoreCert);
    DLOGV("pIotCorePrivateKey: %s\n", pIotCorePrivateKey);
    DLOGV("serialNum:          %s\n", pSerialNum);
    DLOGV("template:           %s\n", pTemplate);
    DLOGV("pEndpoint:          %s\n", pEndpoint);
    DLOGV("pRootCaCert:        %s\n", pRootCaCert);

    /* Initialize the buffer lengths to their max lengths. */
    certificateLength = CERT_BUFFER_LENGTH;
    certificateIdLength = CERT_ID_BUFFER_LENGTH;
    ownershipTokenLength = OWNERSHIP_TOKEN_BUFFER_LENGTH;
    privateKeyLength = PRIVATE_KEY_BUFFER_LENGTH;

#ifdef ENABLE_PKCS11
    /* Initialize the PKCS #11 module */
    pkcs11ret = xInitializePkcs11Session( &p11Session );
    CHK_ERR(pkcs11ret == CKR_OK, STATUS_INVALID_OPERATION, "Failed to initialize PKCS #11.");

    createPKCS11Session = TRUE;

    /* Insert the claim credentials into the PKCS #11 module */
    status = loadClaimCredentials( p11Session,
                                   pClaimCertPath,
                                   pkcs11configLABEL_CLAIM_CERTIFICATE,
                                   pClaimKeyPath,
                                   pkcs11configLABEL_CLAIM_PRIVATE_KEY );

    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to provision PKCS #11 with claim credentials.");

#endif
    /**** Connect to AWS IoT Core with provisioning claim credentials *****/

    /* We first use the claim credentials to connect to the broker.
     * These credentials should allow use of the RegisterThing API and one of the
     * CreateCertificatefromCsr or CreateKeysAndCertificate.
     * In this demo we use CreateKeysAndCertificate. */

    /* Attempts to connect to the AWS IoT MQTT broker.
     * If the connection fails, retries after a timeout.
     * Timeout value will exponentially increase until maximum attempts are reached. */

    DLOGI("Establishing MQTT session with claim certificate...");
#ifdef ENABLE_PKCS11
    status = EstablishMqttSession( provisioningPublishCallback,
                                   p11Session,
                                   pkcs11configLABEL_CLAIM_CERTIFICATE,
                                   pkcs11configLABEL_CLAIM_PRIVATE_KEY,
                                   pSerialNum,
                                   pEndpoint,
                                   pRootCaCert);
#else
    status = EstablishMqttSession( provisioningPublishCallback,
                                   pClaimCertPath,
                                   pClaimKeyPath,
                                   pSerialNum,
                                   pEndpoint,
                                   pRootCaCert);
#endif
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to establish MQTT session.");

    connectionEstablished = TRUE;

    /**** Call the CreateKeysAndCertificate API ***************************/

    /* We use the CreateKeysAndCertificate API to obtain a client certificate
     * for a key on the device by means of sending a certificate signing request (CSR). */

    /* Subscribe to the CreateKeysAndCertificate accepted and rejected topics.
     * In this demo we use CBOR encoding for the payloads,
     * so we use the CBOR variants of the topics. */
    status = subscribeToKeysResponseTopics();
    CHK_ERR(status, STATUS_INVALID_OPERATION, "subscribeToKeysResponseTopics failed.");

    /* Publish the CSR to the CreateKeysAndCertificates API. */
    status = PublishToTopic( FP_CBOR_CREATE_KEYS_PUBLISH_TOPIC,
                             FP_CBOR_CREATE_KEYS_PUBLISH_LENGTH,
                             NULL,
                             0 );
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to publish to fleet provisioning topic: %.*s.",
            FP_CBOR_CREATE_KEYS_PUBLISH_LENGTH, FP_CBOR_CREATE_KEYS_PUBLISH_TOPIC);

    /* Get the response to the CreateCertificatefromCsr request. */
    CHK_ERR(waitForResponse(), STATUS_INVALID_OPERATION, "Failed to Get the response to the CreateKeysAndCertificates request.");

    /* From the response, extract the certificate, certificate ID, privateKey, and
     * certificate ownership token. */
    status = parseKeysAndCertificateResponse( payloadBuffer,
             payloadLength,
             certificate,
             &certificateLength,
             certificateId,
             &certificateIdLength,
             ownershipToken,
             &ownershipTokenLength,
             privateKey,
             &privateKeyLength);
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to parseKeysAndCertificateResponse.");

    DLOGI("Received certificate with Id: %.*s", ( int ) certificateIdLength, certificateId);

    /* write certificate and key into file */
    status = writeBufferToFile(certificate, certificateLength, pIotCoreCert);
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to save certificate file.");
    status = writeBufferToFile(privateKey, privateKeyLength, pIotCorePrivateKey);
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to save privateKey file.");

#ifdef ENABLE_PKCS11
    /* Save the certificate into PKCS #11. */
    status = loadCertificateAndKey( p11Session,
                                    certificate,
                                    pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                    certificateLength,
                                    privateKey,
                                    pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                    privateKeyLength );
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to Save the certificate into PKCS #11.");
#endif

    /* Unsubscribe from the CreateCertificateFromCsr topics. */
    status = unsubscribeFromKeysResponseTopics();
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to unsubscribeFromKeysResponseTopics");

    /**** Call the RegisterThing API **************************************/

    /* We then use the RegisterThing API to activate the received certificate,
     * provision AWS IoT resources according to the provisioning template, and
     * receive device configuration. */
    /* Create the request payload to publish to the RegisterThing API. */
    status = generateRegisterThingRequest( payloadBuffer,
                                           NETWORK_BUFFER_SIZE,
                                           ownershipToken,
                                           ownershipTokenLength,
                                           pSerialNum,
                                           STRLEN(pSerialNum),
                                           &payloadLength );
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to Create the request payload to publish to the RegisterThing API.");

    /* Subscribe to the RegisterThing response topics. */
    status = subscribeToRegisterThingResponseTopics();
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to subscribeToRegisterThingResponseTopics.");


    /* Publish the RegisterThing request. */
    char topic[512] = {0};
    snprintf(topic, sizeof(topic), FP_REGISTER_API_PREFIX "%s" FP_REGISTER_API_BRIDGE FP_API_CBOR_FORMAT, pTemplate);

    status = PublishToTopic(topic , strlen(topic), (char *) payloadBuffer, payloadLength);

    if ( status == FALSE ) {
        DLOGE("Failed to publish to fleet provisioning topic: %.*s.", strlen(topic), topic);
    }

    /* Get the response to the RegisterThing request. */
    CHK_ERR(waitForResponse(), STATUS_INVALID_OPERATION, "Failed to  Get the response to the RegisterThing request.");


    /* Extract the Thing name from the response. */
    thingNameLength = MAX_THING_NAME_LENGTH;
    status = parseRegisterThingResponse( payloadBuffer,
                                         payloadLength,
                                         thingName,
                                         &thingNameLength );
    CHK_ERR(status, STATUS_INVALID_OPERATION, "Failed to extract the Thing name from the response.");

    DLOGI("Received AWS IoT Thing name: %.*s", ( int ) thingNameLength, thingName);

    /* Unsubscribe from the RegisterThing topics. */
    unsubscribeFromRegisterThingResponseTopics();

CleanUp:
    /**** Disconnect from AWS IoT Core ************************************/

    /* As we have completed the provisioning workflow, we disconnect from
     * the connection using the provisioning claim credentials. We will
     * establish a new MQTT connection with the newly provisioned
     * credentials. */
    if ( connectionEstablished == TRUE ) {
        DisconnectMqttSession();
        connectionEstablished = FALSE;
    }

#ifdef ENABLE_PKCS11
    if (createPKCS11Session == TRUE) {
        pkcs11CloseSession( p11Session );
    }
#endif

    return retStatus ;
}

/*-----------------------------------------------------------*/
