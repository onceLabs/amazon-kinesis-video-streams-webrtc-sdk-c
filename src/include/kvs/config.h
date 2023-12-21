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
#ifndef __AWS_KVS_WEBRTC_CONFIG_INCLUDE__
#define __AWS_KVS_WEBRTC_CONFIG_INCLUDE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************
 * HEADERS
 ******************************************************************************/
 /* Config for Ameba-Pro */
#include "sample_config_webrtc.h"

/******************************************************************************
 * DEFINITIONS
 ******************************************************************************/
#define DEFAULT_SIGNALING_CACHE_FILE_PATH   KVS_WEBRTC_SIGNALING_CACHE_FILE_PATH

#ifdef __cplusplus
}
#endif
#endif /* __AWS_KVS_WEBRTC_CONFIG_INCLUDE__ */
