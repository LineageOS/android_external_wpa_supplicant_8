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
#include "supplicantvendor.h"
#include "supplicant.h"

#include <android-base/file.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor{
namespace V2_2 {
namespace Implementation {
using android::hardware::wifi::supplicant::V1_4::implementation::hidl_return_util::validateAndCall;
using namespace android::hardware;
using namespace android::hardware::wifi::supplicant::V1_0;
using namespace android::hardware::wifi::supplicant::V1_4::implementation;
typedef android::hardware::wifi::supplicant::V1_1::ISupplicant ISupplicant;
using namespace vendor::qti::hardware::wifi::supplicant::V2_0;
using vendor::qti::hardware::wifi::supplicant::V2_2::ISupplicantVendorStaIface;

SupplicantVendor::SupplicantVendor(struct wpa_global* global) : wpa_global_(global) {}
bool SupplicantVendor::isValid()
{
	// This top level object cannot be invalidated.
	return true;
}

Return<void> SupplicantVendor::listVendorInterfaces(listVendorInterfaces_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &SupplicantVendor::listVendorInterfacesInternal, _hidl_cb);
}

Return<void> SupplicantVendor::getVendorInterface(
    const ISupplicant::IfaceInfo& iface_info, getVendorInterface_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
	    &SupplicantVendor::getVendorInterfaceInternal, _hidl_cb, iface_info);
}

std::pair<SupplicantStatus, android::sp<ISupplicantVendorIface>>
SupplicantVendor::getVendorInterfaceInternal(const ISupplicant::IfaceInfo& iface_info)
{
	struct wpa_supplicant* wpa_s =
	    wpa_supplicant_get_iface(wpa_global_, iface_info.name.c_str());
	if (!wpa_s) {
		return {{SupplicantStatusCode::FAILURE_IFACE_UNKNOWN, ""},
			nullptr};
	}
	HidlManager* hidl_manager = HidlManager::getInstance();
	if (iface_info.type == IfaceType::P2P) {
		wpa_printf(MSG_INFO, "get vendor p2p iface object");
		android::sp<ISupplicantVendorP2PIface> iface;
		if (!hidl_manager ||
		    hidl_manager->getVendorP2pIfaceHidlObjectByIfname(
			wpa_s->ifname, &iface)) {
			return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""},
				iface};
		}
		return {{SupplicantStatusCode::SUCCESS, ""}, iface};
	} else {
		wpa_printf(MSG_INFO, "get vendor sta iface object");
		android::sp<ISupplicantVendorStaIface> vendor_iface;
		if (!hidl_manager ||
		    hidl_manager->getVendorStaIfaceHidlObjectByIfname(
			wpa_s->ifname, &vendor_iface)) {
			return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""},
				vendor_iface};
		}
		return {{SupplicantStatusCode::SUCCESS, ""}, vendor_iface};
	}
}

std::pair<SupplicantStatus, std::vector<ISupplicant::IfaceInfo>>
SupplicantVendor::listVendorInterfacesInternal()
{
	std::vector<ISupplicant::IfaceInfo> ifaces;
	for (struct wpa_supplicant* wpa_s = wpa_global_->ifaces; wpa_s;
	     wpa_s = wpa_s->next) {
		if (wpa_s->global->p2p_init_wpa_s == wpa_s) {
			ifaces.emplace_back(ISupplicant::IfaceInfo{
			    IfaceType::P2P, wpa_s->ifname});
		} else {
			ifaces.emplace_back(ISupplicant::IfaceInfo{
			    IfaceType::STA, wpa_s->ifname});
		}
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, std::move(ifaces)};
}

}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicant
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
