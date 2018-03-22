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

#ifndef WPA_SUPPLICANT_VENDOR_HIDL_STA_IFACE_H
#define WPA_SUPPLICANT_VENDOR_HIDL_STA_IFACE_H

#define DEVICE_CAPA_SIZE 200

#include <array>
#include <vector>

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaIface.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaIfaceCallback.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaNetwork.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorStaNetwork.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorStaIfaceCallback.h>
#include <vendor/qti/hardware/wifi/supplicant/2.1/types.h>
#include <vendor/qti/hardware/wifi/supplicant/2.2/ISupplicantVendorStaIface.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#include "driver_i.h"
#include "wpa.h"
#include "ctrl_iface.h"
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
using namespace vendor::qti::hardware::wifi::supplicant::V2_1;
using namespace vendor::qti::hardware::wifi::supplicant::V2_2;
using namespace android::hardware;
using supplicant::V2_0::ISupplicantVendorStaIfaceCallback;
using supplicant::V2_0::ISupplicantVendorNetwork;
using supplicant::V2_1::WifiGenerationStatus;

/**
 * Implementation of VendorStaIface hidl object. Each unique hidl
 * object is used for control operations on a specific interface
 * controlled by wpa_supplicant.
 */
class VendorStaIface : public vendor::qti::hardware::wifi::supplicant::V2_2::ISupplicantVendorStaIface
{
public:
	VendorStaIface(struct wpa_global* wpa_global, const char ifname[]);
	~VendorStaIface() override = default;
	// HIDL does not provide a built-in mechanism to let the server
	// invalidate a HIDL interface object after creation. If any client
	// process holds onto a reference to the object in their context,
	// any method calls on that reference will continue to be directed to
	// the server.
	// However Supplicant HAL needs to control the lifetime of these
	// objects. So, add a public |invalidate| method to all |IVendorface| and
	// |VendorNetwork| objects.
	// This will be used to mark an object invalid when the corresponding
	// iface or network is removed.
	// All HIDL method implementations should check if the object is still
	// marked valid before processing them.
	void invalidate();
	bool isValid();
	Return<void> registerVendorCallback(
	    const android::sp<ISupplicantVendorStaIfaceCallback>& callback,
	    registerVendorCallback_cb _hidl_cb) override;
        Return<void> filsHlpFlushRequest(
            filsHlpFlushRequest_cb _hidl_cb) override;
        Return<void> filsHlpAddRequest(
            const hidl_array<uint8_t, 6>& dst_mac, const hidl_vec<uint8_t>& pkt,
            filsHlpAddRequest_cb _hidl_cb) override;
        Return<void> getCapabilities(
            const hidl_string &capa_type,
                getCapabilities_cb _hidl_cb) override;
	Return<void> getVendorNetwork(
	    SupplicantNetworkId id, getVendorNetwork_cb _hidl_cb) override;
	/* DPP APIs */
	Return<void> dppAddBootstrapQrcode(
	    const hidl_string& uri, dppAddBootstrapQrcode_cb _hidl_cb) override;
	Return<void> dppBootstrapGenerate(
	    uint32_t type, const hidl_string& chan_list,
	    const hidl_array<uint8_t, 6>& mac_addr,
	    const hidl_string& info, const hidl_string& curve, const hidl_string& key,
	    dppBootstrapGenerate_cb _hidl_cb) override;
	Return<void> dppGetUri(uint32_t id, dppGetUri_cb _hidl_cb) override;
	Return<void> dppBootstrapRemove(
	    uint32_t id, dppBootstrapRemove_cb _hidl_cb) override;
	Return<void> dppStartListen(
	    const hidl_string& frequency, uint32_t dpp_role,
	    bool qr_mutual, bool netrole_ap,
	    dppStartListen_cb _hidl_cb) override;
	Return<void> dppStopListen(dppStopListen_cb _hidl_cb) override;
	Return<void> dppConfiguratorAdd(
	    const hidl_string& curve, const hidl_string& key, uint32_t expiry,
	    dppConfiguratorAdd_cb _hidl_cb) override;
	Return<void> dppConfiguratorRemove(
	    uint32_t id, dppConfiguratorRemove_cb _hidl_cb) override;
	Return<void> dppStartAuth(
	    int32_t peer_bootstrap_id, int32_t own_bootstrap_id, int32_t dpp_role,
	    const hidl_string& ssid, const hidl_string& password, bool isAp,
	    bool isDpp, int32_t conf_id, int32_t expiry, dppStartAuth_cb _hidl_cb) override;
	Return<void> dppConfiguratorGetKey(uint32_t id, dppConfiguratorGetKey_cb _hidl_cb) override;
	Return<void> getWifiGenerationStatus(
                getWifiGenerationStatus_cb _hidl_cb) override;
	Return<void> doDriverCmd(const hidl_string &command, doDriverCmd_cb _hidl_cb) override;

private:
	// Corresponding worker functions for the HIDL methods.
	SupplicantStatus registerCallbackInternal(
	    const android::sp<ISupplicantVendorStaIfaceCallback>& callback);
        SupplicantStatus filsHlpFlushRequestInternal();
        SupplicantStatus filsHlpAddRequestInternal(
            const std::array<uint8_t, 6>& dst_mac,
            const std::vector<uint8_t>& pkt);
	std::pair<SupplicantStatus, std::string> getCapabilitiesInternal(
	        const std::string &capa_type);
	std::pair<SupplicantStatus, android::sp<ISupplicantVendorNetwork>> getNetworkInternal(
	    SupplicantNetworkId id);
	struct wpa_supplicant* retrieveIfacePtr();
	/* DPP Internal APIs */
	std::pair<SupplicantStatus, int32_t> dppAddBootstrapQrcodeInternal(
	    const std::string &uri);
	std::pair<SupplicantStatus, int32_t> dppBootstrapGenerateInternal(
	    uint32_t type, const std::string &chan_list,
	    const std::array<uint8_t, 6>& bssid,
	    const std::string &info, const std::string &curve, const std::string &key);
	std::pair<SupplicantStatus, std::string> dppGetUriInternal(uint32_t id);
	std::pair<SupplicantStatus, int32_t> dppBootstrapRemoveInternal(
	    uint32_t id);
	std::pair<SupplicantStatus, int32_t> dppListenInternal(
	    const std::string &frequency, uint32_t dpp_role, bool qr_mutual, bool netrole_ap);
	SupplicantStatus dppStopListenInternal();
	std::pair<SupplicantStatus, int32_t> dppConfiguratorAddInternal(
	    const std::string &curve, const std::string &key, uint32_t expiry);
	std::pair<SupplicantStatus, int32_t> dppConfiguratorRemoveInternal(
	    uint32_t id);
	std::pair<SupplicantStatus, int32_t> dppStartAuthInternal(
	    int32_t peer_bootstrap_id, int32_t own_bootstrap_id, int32_t dpp_role,
	    const std::string &ssid, const std::string &password, bool isAp,
	    bool isDpp, int32_t conf_id, int32_t expiry);
	std::pair<SupplicantStatus, std::string> dppConfiguratorGetKeyInternal(uint32_t id);
	std::pair<SupplicantStatus, WifiGenerationStatus> getWifiGenerationStatusInternal();
	std::pair<SupplicantStatus, std::string> doDriverCmdInternal(const std::string &cmd);
	// Reference to the global wpa_struct. This is assumed to be valid for
	// the lifetime of the process.
	struct wpa_global* wpa_global_;
	// Name of the iface this hidl object controls
	const std::string ifname_;
	bool is_valid_;
	char device_capabilities[DEVICE_CAPA_SIZE];
	// A macro to disallow the copy constructor and operator= functions
	// This must be placed in the private: declarations for a class.
	DISALLOW_COPY_AND_ASSIGN(VendorStaIface);
};

}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicant
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
#endif  // WPA_SUPPLICANT_VENDOR_HIDL_STA_IFACE_H
