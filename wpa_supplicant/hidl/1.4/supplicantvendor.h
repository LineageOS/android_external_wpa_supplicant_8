/* Copyright (c) 2018, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * vendor hidl interface for wpa_supplicant daemon
 *
 */

#ifndef WPA_SUPPLICANT_VENDOR_HIDL_SUPPLICANT_H
#define WPA_SUPPLICANT_VENDOR_HIDL_SUPPLICANT_H

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.1/ISupplicant.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicant.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantIface.h>
#include <vendor/qti/hardware/wifi/supplicant/2.2/ISupplicantVendor.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorIface.h>
#include <vendor/qti/hardware/wifi/supplicant/2.2/ISupplicantVendorStaIface.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "utils/wpa_debug.h"
#include "wpa_supplicant_i.h"
}

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor{
namespace V2_2 {
namespace Implementation {
using namespace android::hardware::wifi::supplicant::V1_0;
using namespace android::hardware;
using namespace vendor::qti::hardware::wifi::supplicant::V2_0;
/**
 * Implementation of the supplicantvendor hidl object. This hidl
 * object is used core for global control operations on
 * wpa_supplicant.
 */
class SupplicantVendor : public vendor::qti::hardware::wifi::supplicant::V2_2::ISupplicantVendor
{
public:
	SupplicantVendor(struct wpa_global* global);
	~SupplicantVendor() override = default;
	bool isValid();

	// Hidl methods exposed.
	Return<void> getVendorInterface(
	    const android::hardware::wifi::supplicant::V1_0::ISupplicant::IfaceInfo& iface_info, getVendorInterface_cb _hidl_cb) override;
	Return<void> listVendorInterfaces(listVendorInterfaces_cb _hidl_cb) override;
private:
	std::pair<SupplicantStatus, android::sp<ISupplicantVendorIface>> getVendorInterfaceInternal(
	    const android::hardware::wifi::supplicant::V1_0::ISupplicant::IfaceInfo& iface_info);
	std::pair<SupplicantStatus, std::vector<android::hardware::wifi::supplicant::V1_0::ISupplicant::IfaceInfo>>
	listVendorInterfacesInternal();
	// Raw pointer to the global structure maintained by the core.
	struct wpa_global* wpa_global_;
	// A macro to disallow the copy constructor and operator= functions
	// This must be placed in the private: declarations for a class.
	DISALLOW_COPY_AND_ASSIGN(SupplicantVendor);
};

}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicant
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor

#endif  // WPA_SUPPLICANT_VENDOR_HIDL_SUPPLICANT_H
