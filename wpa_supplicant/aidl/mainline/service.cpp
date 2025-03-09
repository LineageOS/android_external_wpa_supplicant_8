/*
 * WPA Supplicant - Mainline supplicant service
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <android/binder_manager.h>
#include <android/binder_process.h>

#include "mainline_supplicant.h"

extern "C"
{
#include "aidl_i.h"
#include "service.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/includes.h"
#include "utils/wpa_debug.h"
}

using ::ndk::SharedRefBase;

/* Handler for requests to the service */
void aidl_sock_handler(int /* sock */, void * /* eloop_ctx */, void * /* sock_ctx */) {
    // Suppress warning, since this service is only available after Android V
    if (__builtin_available(android __ANDROID_API_V__, *)) {
        ABinderProcess_handlePolledCommands();
    }
}

bool register_service(struct wpa_global *global) {
    wpa_printf(MSG_INFO, "Registering as a lazy service");
    std::string service_name = "wifi_mainline_supplicant";
    std::shared_ptr<MainlineSupplicant> service = SharedRefBase::make<MainlineSupplicant>(global);

    // Suppress warning, since this service is only available after Android V
    if (__builtin_available(android __ANDROID_API_V__, *)) {
        int status =
            AServiceManager_registerLazyService(service->asBinder().get(), service_name.c_str());
        if (status != EX_NONE) {
            wpa_printf(MSG_ERROR, "Registration failed with status %d", status);
        }
        return status == EX_NONE;
    }
    return false;
}

struct wpas_aidl_priv *mainline_aidl_init(struct wpa_global *global) {
    wpa_printf(MSG_INFO, "Initializing the mainline supplicant service");
    struct wpas_aidl_priv *priv = (wpas_aidl_priv *)os_zalloc(sizeof(*priv));
    if (!priv) {
        wpa_printf(MSG_ERROR, "Unable to allocate the global AIDL object");
        return NULL;
    }
    priv->global = global;

    // Suppress warning, since this service is only available after Android V
    if (__builtin_available(android __ANDROID_API_V__, *)) {
        ABinderProcess_setupPolling(&priv->aidl_fd);
    }
    if (priv->aidl_fd < 0) {
        wpa_printf(MSG_ERROR, "Unable to set up polling");
        mainline_aidl_deinit(priv);
        return NULL;
    }

    if (eloop_register_read_sock(priv->aidl_fd, aidl_sock_handler, global, priv) < 0) {
        wpa_printf(MSG_ERROR, "Unable to register eloop read socket");
        mainline_aidl_deinit(priv);
        return NULL;
    }

    if (!register_service(global)) {
        wpa_printf(MSG_ERROR, "Unable to register service");
        mainline_aidl_deinit(priv);
        return NULL;
    }

    wpa_printf(MSG_INFO, "AIDL setup is complete");
    return priv;
}

void mainline_aidl_deinit(struct wpas_aidl_priv *priv) {
    if (!priv) return;
    wpa_printf(MSG_INFO, "Deiniting the mainline supplicant service");
    eloop_unregister_read_sock(priv->aidl_fd);
    os_free(priv);
}
