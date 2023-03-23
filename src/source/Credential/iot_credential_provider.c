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
#define LOG_CLASS "IotCredentialProvider"
#include "auth.h"
#include "iot_credential_provider.h"
#include "request_info.h"
#include "http_api.h"
#ifndef JSMN_HEADER
#define JSMN_HEADER
#endif
#include "jsmn.h"

////////////////////////////////////////////////////////////////////////
// Callback function implementations
////////////////////////////////////////////////////////////////////////
STATUS getIotCredentials(PAwsCredentialProvider, PAwsCredentials*);

STATUS createIotCredentialProviderWithTime(PCHAR iotGetCredentialEndpoint, PCHAR certPath, PCHAR privateKeyPath, PCHAR caCertPath, PCHAR roleAlias,
                                              PCHAR thingName, GetCurrentTimeFunc getCurrentTimeFn, UINT64 customData,
                                              BlockingServiceCallFunc serviceCallFn, PAwsCredentialProvider* ppCredentialProvider)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIotCredentialProvider pIotCredentialProvider = NULL;

    CHK(ppCredentialProvider != NULL && iotGetCredentialEndpoint != NULL && certPath != NULL && privateKeyPath != NULL && roleAlias != NULL &&
            thingName != NULL,
        // thingName != NULL && serviceCallFn != NULL,
        STATUS_NULL_ARG);

    pIotCredentialProvider = (PIotCredentialProvider) MEMCALLOC(1, SIZEOF(IotCredentialProvider));
    CHK(pIotCredentialProvider != NULL, STATUS_NOT_ENOUGH_MEMORY);

    pIotCredentialProvider->credentialProvider.getCredentialsFn = getIotCredentials;

    // Store the time functionality and specify default if NULL
    pIotCredentialProvider->getCurrentTimeFn = (getCurrentTimeFn == NULL) ? commonDefaultGetCurrentTimeFunc : getCurrentTimeFn;
    pIotCredentialProvider->customData = customData;

    CHK(STRNLEN(iotGetCredentialEndpoint, MAX_URI_CHAR_LEN + 1) <= MAX_URI_CHAR_LEN, MAX_URI_CHAR_LEN);
    STRNCPY(pIotCredentialProvider->iotGetCredentialEndpoint, iotGetCredentialEndpoint, MAX_URI_CHAR_LEN);

    CHK(STRNLEN(roleAlias, MAX_ROLE_ALIAS_LEN + 1) <= MAX_ROLE_ALIAS_LEN, STATUS_MAX_ROLE_ALIAS_LEN_EXCEEDED);
    STRNCPY(pIotCredentialProvider->roleAlias, roleAlias, MAX_ROLE_ALIAS_LEN);

    CHK(STRNLEN(privateKeyPath, MAX_PATH_LEN + 1) <= MAX_PATH_LEN, STATUS_PATH_TOO_LONG);
    STRNCPY(pIotCredentialProvider->privateKeyPath, privateKeyPath, MAX_PATH_LEN);

    if (caCertPath != NULL) {
        CHK(STRNLEN(caCertPath, MAX_PATH_LEN + 1) <= MAX_PATH_LEN, STATUS_PATH_TOO_LONG);
        STRNCPY(pIotCredentialProvider->caCertPath, caCertPath, MAX_PATH_LEN);
    }

    CHK(STRNLEN(certPath, MAX_PATH_LEN + 1) <= MAX_PATH_LEN, STATUS_PATH_TOO_LONG);
    STRNCPY(pIotCredentialProvider->certPath, certPath, MAX_PATH_LEN);

    CHK(STRNLEN(thingName, MAX_IOT_THING_NAME_LEN + 1) <= MAX_IOT_THING_NAME_LEN, STATUS_MAX_IOT_THING_NAME_LENGTH);
    STRNCPY(pIotCredentialProvider->thingName, thingName, MAX_IOT_THING_NAME_LEN);

    pIotCredentialProvider->serviceCallFn = serviceCallFn;

    CHK_STATUS(http_api_getIotCredential(pIotCredentialProvider));

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        freeIotCredentialProvider((PAwsCredentialProvider*) &pIotCredentialProvider);
        pIotCredentialProvider = NULL;
    }

    // Set the return value if it's not NULL
    if (ppCredentialProvider != NULL) {
        *ppCredentialProvider = (PAwsCredentialProvider) pIotCredentialProvider;
    }

    LEAVES();
    return retStatus;
}

STATUS freeIotCredentialProvider(PAwsCredentialProvider* ppCredentialProvider)
{
    ENTERS();
    STATUS retStatus = STATUS_SUCCESS;
    PIotCredentialProvider pIotCredentialProvider = NULL;

    CHK(ppCredentialProvider != NULL, STATUS_NULL_ARG);

    pIotCredentialProvider = (PIotCredentialProvider) *ppCredentialProvider;

    // Call is idempotent
    CHK(pIotCredentialProvider != NULL, retStatus);

    // Release the underlying AWS credentials object
    freeAwsCredentials(&pIotCredentialProvider->pAwsCredentials);

    // Release the object
    MEMFREE(pIotCredentialProvider);

    // Set the pointer to NULL
    *ppCredentialProvider = NULL;

CleanUp:

    LEAVES();
    return retStatus;
}

STATUS getIotCredentials(PAwsCredentialProvider pCredentialProvider, PAwsCredentials* ppAwsCredentials)
{
    ENTERS();

    STATUS retStatus = STATUS_SUCCESS;
    UINT64 currentTime;

    PIotCredentialProvider pIotCredentialProvider = (PIotCredentialProvider) pCredentialProvider;

    CHK(pIotCredentialProvider != NULL && ppAwsCredentials != NULL, STATUS_NULL_ARG);

    currentTime = pIotCredentialProvider->getCurrentTimeFn(pIotCredentialProvider->customData);

    CHK(pIotCredentialProvider->pAwsCredentials == NULL ||
            currentTime + IOT_CREDENTIAL_FETCH_GRACE_PERIOD > pIotCredentialProvider->pAwsCredentials->expiration,
        retStatus);

    // Fill the credentials
    CHK_STATUS(http_api_getIotCredential(pIotCredentialProvider));

CleanUp:

    if (STATUS_FAILED(retStatus)) {
        *ppAwsCredentials = NULL; //!< this can be removed.
    } else {
        *ppAwsCredentials = pIotCredentialProvider->pAwsCredentials;
    }
    LEAVES();
    return retStatus;
}

STATUS iot_credential_provider_create(PCHAR iotGetCredentialEndpoint, PCHAR certPath, PCHAR privateKeyPath, PCHAR caCertPath, PCHAR roleAlias,
                                      PCHAR thingName, PAwsCredentialProvider* ppCredentialProvider)
{
    return createIotCredentialProviderWithTime(iotGetCredentialEndpoint, certPath, privateKeyPath, caCertPath, roleAlias, thingName,
                                                  commonDefaultGetCurrentTimeFunc, NULL, NULL, ppCredentialProvider);
}
