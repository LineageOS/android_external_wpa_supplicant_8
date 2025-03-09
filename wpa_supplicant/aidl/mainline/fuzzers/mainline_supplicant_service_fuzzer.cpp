/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android/binder_interface_utils.h>
#include <fuzzbinder/libbinder_ndk_driver.h>

#include "aidl/mainline/mainline_supplicant.h"

extern "C"
{
#include "utils/common.h"
#include "utils/includes.h"
#include "utils/wpa_debug.h"
#include "wpa_supplicant_i.h"
}

using namespace android;
using ndk::SharedRefBase;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    struct wpa_params params;
    os_memset(&params, 0, sizeof(params));
    params.wpa_debug_level = MSG_INFO;

    struct wpa_global *global = wpa_supplicant_init(&params);
    if (global == NULL) {
        return 1;
    }

    std::shared_ptr<MainlineSupplicant> service = SharedRefBase::make<MainlineSupplicant>(global);
    fuzzService(service->asBinder().get(), FuzzedDataProvider(data, size));
    return 0;
}
