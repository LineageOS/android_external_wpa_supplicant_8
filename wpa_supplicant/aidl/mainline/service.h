/*
 * WPA Supplicant - Mainline supplicant service
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_SERVICE_H
#define MAINLINE_SUPPLICANT_SERVICE_H

#ifdef _cplusplus
extern "C"
{
#endif  // _cplusplus

struct wpas_aidl_priv;
struct wpa_global;

struct wpas_aidl_priv *mainline_aidl_init(struct wpa_global *global);
void mainline_aidl_deinit(struct wpas_aidl_priv *priv);

#ifdef _cplusplus
}
#endif  // _cplusplus

#endif  // MAINLINE_SUPPLICANT_SERVICE_H
