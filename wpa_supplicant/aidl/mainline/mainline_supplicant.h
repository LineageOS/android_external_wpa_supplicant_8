/*
 * WPA Supplicant - Mainline supplicant AIDL implementation
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_IMPL_H
#define MAINLINE_SUPPLICANT_IMPL_H

#include <map>

#include "sta_iface.h"

#include <aidl/android/system/wifi/mainline_supplicant/BnMainlineSupplicant.h>
#include <aidl/android/system/wifi/mainline_supplicant/IStaInterface.h>
#include <aidl/android/system/wifi/mainline_supplicant/SupplicantStatusCode.h>

extern "C"
{
#include "utils/common.h"
#include "utils/includes.h"
#include "utils/wpa_debug.h"
#include "wpa_supplicant_i.h"
#include "scan.h"
}

using ::aidl::android::system::wifi::mainline_supplicant::BnMainlineSupplicant;
using ::aidl::android::system::wifi::mainline_supplicant::IStaInterface;
using ::aidl::android::system::wifi::mainline_supplicant::SupplicantStatusCode;

class MainlineSupplicant : public BnMainlineSupplicant {
    public:
        MainlineSupplicant(struct wpa_global* global);
        ndk::ScopedAStatus addStaInterface(const std::string& ifaceName,
            std::shared_ptr<IStaInterface>* _aidl_return);
        ndk::ScopedAStatus removeStaInterface(const std::string& ifaceName);
        ndk::ScopedAStatus terminate();
        ndk::ScopedAStatus setDebugParams(IMainlineSupplicant::DebugLevel level, bool showKeys);

    private:
        // Raw pointer to the global structure maintained by the core
        struct wpa_global* wpa_global_;
        // Map containing all active STA interfaces, mapped by iface name -> object
        std::map<std::string, std::shared_ptr<IStaInterface>> active_sta_ifaces_;
};

#endif  // MAINLINE_SUPPLICANT_IMPL_H
