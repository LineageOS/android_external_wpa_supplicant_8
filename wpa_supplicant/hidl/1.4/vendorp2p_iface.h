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

#ifndef WPA_SUPPLICANT_VENDOR_HIDL_P2P_IFACE_H
#define WPA_SUPPLICANT_VENDOR_HIDL_P2P_IFACE_H

#include <array>
#include <vector>

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pIface.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantP2pIfaceCallback.h>
//#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaNetwork.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorNetwork.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorP2PIface.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorP2PIfaceCallback.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "p2p/p2p.h"
#include "p2p/p2p_i.h"
#include "p2p_supplicant.h"
#include "p2p_supplicant.h"
#include "config.h"
}

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor {
namespace V2_2 {
namespace Implementation {
using namespace android::hardware::wifi::supplicant::V1_0;
using namespace android::hardware::wifi::supplicant::V1_4::implementation;
using namespace vendor::qti::hardware::wifi::supplicant::V2_0;
using namespace android::hardware;

/**
 * Implementation of P2pIface hidl object. Each unique hidl
 * object is used for control operations on a specific interface
 * controlled by wpa_supplicant.
 */
class VendorP2pIface : public ISupplicantVendorP2PIface
{
public:
	VendorP2pIface(struct wpa_global* wpa_global, const char ifname[]);
	~VendorP2pIface() override = default;
	// Refer to |P2pIface::invalidate()|.
	void invalidate();
	bool isValid();

	Return<void> registerVendorCallback(
	    const android::sp<ISupplicantVendorP2PIfaceCallback>& callback,
	    registerVendorCallback_cb _hidl_cb) override;
	Return<void> setWfdR2DeviceInfo(
	    const hidl_array<uint8_t, 4>& info,
	    setWfdR2DeviceInfo_cb _hidl_cb) override;
	Return<void> getVendorNetwork(
	    SupplicantNetworkId id, getVendorNetwork_cb _hidl_cb) override;
    Return<void> setVendorInfoElement(
        const hidl_vec<uint8_t>& ie,
        hidl_bitfield<ISupplicantVendorP2PIfaceCallback::InfoElementType> type,
        setVendorInfoElement_cb _hidl_cb) override;

private:
	// Corresponding worker functions for the HIDL methods.
	SupplicantStatus registerCallbackInternal(
	    const android::sp<ISupplicantVendorP2PIfaceCallback>& callback);
	SupplicantStatus setWfdR2DeviceInfoInternal(
	    const std::array<uint8_t, 4>& info);
	SupplicantStatus setVendorInfoElementInternal(
        const hidl_vec<uint8_t>& ie,
        hidl_bitfield<ISupplicantVendorP2PIfaceCallback::InfoElementType> type);
	std::pair<SupplicantStatus, android::sp<ISupplicantVendorNetwork>> getNetworkInternal(
	    SupplicantNetworkId id);

	struct wpa_supplicant* retrieveIfacePtr();
	struct wpa_supplicant* retrieveGroupIfacePtr(
	    const std::string& group_ifname);

	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	struct wpa_global* wpa_global_;
	// Name of the iface this hidl object controls
	const std::string ifname_;
	bool is_valid_;

	DISALLOW_COPY_AND_ASSIGN(VendorP2pIface);
};

}  // namespace implementation
}  // namespace V2_2
}  // namespace wifi
}  // namespace supplicantvendor
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
#endif  // WPA_SUPPLICANT_VENDOR_HIDL_P2P_IFACE_H
