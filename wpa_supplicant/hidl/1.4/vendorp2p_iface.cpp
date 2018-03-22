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

#include "hidl_manager.h"
#include "hidl_return_util.h"
#include "iface_config_utils.h"
#include "misc_utils.h"
#include "vendorp2p_iface.h"

extern "C" {
#include "ap.h"
#include "wps_supplicant.h"
#include "wifi_display.h"
#include "common.h"
#include "wpabuf.h"
}

namespace {
constexpr uint8_t kWfdR2DeviceInfoSubelemId = 11;
} //namespace

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor {
namespace V2_2 {
namespace Implementation {
using android::hardware::wifi::supplicant::V1_4::implementation::hidl_return_util::validateAndCall;

VendorP2pIface::VendorP2pIface(struct wpa_global* wpa_global, const char ifname[])
    : wpa_global_(wpa_global), ifname_(ifname), is_valid_(true)
{
}

void VendorP2pIface::invalidate() { is_valid_ = false; }
bool VendorP2pIface::isValid()
{
	return (is_valid_ && (retrieveIfacePtr() != nullptr));
}

Return<void> VendorP2pIface::registerVendorCallback(
    const android::sp<ISupplicantVendorP2PIfaceCallback>& callback,
    registerVendorCallback_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &VendorP2pIface::registerCallbackInternal, _hidl_cb, callback);
}

Return<void> VendorP2pIface::getVendorNetwork(
    SupplicantNetworkId id, getVendorNetwork_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &VendorP2pIface::getNetworkInternal, _hidl_cb, id);
}

SupplicantStatus VendorP2pIface::registerCallbackInternal(
    const android::sp<ISupplicantVendorP2PIfaceCallback>& callback)
{
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (!hidl_manager ||
	    hidl_manager->addVendorP2pIfaceCallbackHidlObject(ifname_, callback)) {
		wpa_printf(MSG_INFO, "return failure vendor p2p iface callback");
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}


Return<void>  VendorP2pIface::setWfdR2DeviceInfo(
    const hidl_array<uint8_t, 4>& info, setWfdR2DeviceInfo_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &VendorP2pIface::setWfdR2DeviceInfoInternal, _hidl_cb, info);
}

SupplicantStatus VendorP2pIface::setWfdR2DeviceInfoInternal(
    const std::array<uint8_t, 4>& info)
{
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
	uint32_t wfd_r2_device_info_hex_len = info.size() * 2 + 1;
	std::vector<char> wfd_r2_device_info_hex(wfd_r2_device_info_hex_len);
	wpa_snprintf_hex(
	    wfd_r2_device_info_hex.data(), wfd_r2_device_info_hex.size(),
	    info.data(),info.size());
	std::string wfd_r2_device_info_set_cmd_str =
	     std::to_string(kWfdR2DeviceInfoSubelemId) + " " +
	     wfd_r2_device_info_hex.data();
	std::vector<char> wfd_r2_device_info_set_cmd(
	     wfd_r2_device_info_set_cmd_str.c_str(),
	     wfd_r2_device_info_set_cmd_str.c_str() +
	     wfd_r2_device_info_set_cmd_str.size() + 1);
	if (wifi_display_subelem_set(
		wpa_s->global, wfd_r2_device_info_set_cmd.data())) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorP2pIface::setVendorInfoElementInternal(
    const hidl_vec<uint8_t>& info,
    hidl_bitfield<ISupplicantVendorP2PIfaceCallback::InfoElementType> type)
{
	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
  struct wpabuf *vendor_info = wpabuf_alloc_copy(info.data(),info.size());

	if (p2p_add_wps_vendor_extension(
		wpa_s->global->p2p, vendor_info)) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}


std::pair<SupplicantStatus, android::sp<ISupplicantVendorNetwork>>
VendorP2pIface::getNetworkInternal(SupplicantNetworkId id)
{
        return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""},NULL};
}
/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this iface.
 * If the underlying iface is removed, then all RPC method calls on this object
 * will return failure.
 */
wpa_supplicant* VendorP2pIface::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(wpa_global_, ifname_.c_str());
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for this group iface.
 */
wpa_supplicant* VendorP2pIface::retrieveGroupIfacePtr(const std::string& group_ifname)
{
	return wpa_supplicant_get_iface(wpa_global_, group_ifname.c_str());
}

Return<void> VendorP2pIface::setVendorInfoElement(
    const hidl_vec<uint8_t>& info,
    hidl_bitfield<ISupplicantVendorP2PIfaceCallback::InfoElementType> type,
    setVendorInfoElement_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &VendorP2pIface::setVendorInfoElementInternal, _hidl_cb, info,type);
}

}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicantvendor
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
