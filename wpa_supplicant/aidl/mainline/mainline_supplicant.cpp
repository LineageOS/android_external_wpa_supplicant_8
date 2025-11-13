/*
 * WPA Supplicant - Mainline supplicant AIDL implementation
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "aidl/shared/shared_utils.h"
#include "callback_manager.h"
#include "mainline_supplicant.h"
#include "utils.h"

using ::ndk::ScopedAStatus;

const std::string kConfigFilePath = "/apex/com.android.wifi/etc/mainline_supplicant.conf";

MainlineSupplicant::MainlineSupplicant(struct wpa_global* global) {
    wpa_global_ = global;
}

ndk::ScopedAStatus MainlineSupplicant::addStaInterface(const std::string& ifaceName,
        std::shared_ptr<IStaInterface>* _aidl_return) {
    if (ifaceName.empty()) {
        wpa_printf(MSG_ERROR, "Empty iface name provided");
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }

    if (active_sta_ifaces_.find(ifaceName) != active_sta_ifaces_.end()) {
        wpa_printf(MSG_INFO, "Interface %s already exists", ifaceName.c_str());
        std::shared_ptr<IStaInterface> staIface = active_sta_ifaces_[ifaceName];
        _aidl_return = &staIface;
        return ndk::ScopedAStatus::ok();
    }

    if (ensureConfigFileExistsAtPath(kConfigFilePath) != 0) {
        wpa_printf(MSG_ERROR, "Unable to find config file at %s", kConfigFilePath.c_str());
        return createStatusWithMsg(
            SupplicantStatusCode::FAILURE_UNKNOWN, "Config file does not exist");
    }

    struct wpa_interface iface_params = {};
    iface_params.driver = kIfaceDriverName;
    iface_params.ifname = ifaceName.c_str();
    iface_params.confname = kConfigFilePath.c_str();

    struct wpa_supplicant* wpa_s = wpa_supplicant_add_iface(wpa_global_, &iface_params, NULL);
    if (!wpa_s) {
        wpa_printf(MSG_ERROR, "Unable to add interface %s", ifaceName.c_str());
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }

    std::shared_ptr<IStaInterface> staIface =
        ndk::SharedRefBase::make<StaIface>(wpa_global_, ifaceName);
    active_sta_ifaces_[ifaceName] = staIface;
    *_aidl_return = staIface;

    wpa_printf(MSG_INFO, "Interface %s was added successfully", ifaceName.c_str());
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus MainlineSupplicant::removeStaInterface(const std::string& ifaceName) {
    if (ifaceName.empty()) {
        wpa_printf(MSG_ERROR, "Empty iface name provided");
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }

    if (active_sta_ifaces_.find(ifaceName) == active_sta_ifaces_.end()) {
        wpa_printf(MSG_ERROR, "Interface %s does not exist", ifaceName.c_str());
        return createStatus(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN);
    }

    struct wpa_supplicant* wpa_s =
        wpa_supplicant_get_iface(wpa_global_, ifaceName.c_str());
    if (!wpa_s) {
        wpa_printf(MSG_ERROR, "Interface %s does not exist", ifaceName.c_str());
        return createStatus(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN);
    }
    if (wpa_supplicant_remove_iface(wpa_global_, wpa_s, 0)) {
        wpa_printf(MSG_ERROR, "Unable to remove interface %s", ifaceName.c_str());
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }

    // Remove interface and callback from the internal maps
    CallbackManager* callbackManager = CallbackManager::getInstance();
    WPA_ASSERT(callbackManager);
    callbackManager->unregisterStaIfaceCallback(ifaceName);
    active_sta_ifaces_.erase(ifaceName);

    wpa_printf(MSG_INFO, "Interface %s was removed successfully", ifaceName.c_str());
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus MainlineSupplicant::terminate() {
    wpa_printf(MSG_INFO, "Terminating...");
    wpa_supplicant_terminate_proc(wpa_global_);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus MainlineSupplicant::setDebugParams(
        IMainlineSupplicant::DebugLevel level, bool showKeys) {
    if (wpa_supplicant_set_debug_params(
            wpa_global_, static_cast<uint32_t>(level),
            false /* showTimestamp */, showKeys)) {
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
    return ndk::ScopedAStatus::ok();
}
