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

#ifndef WPA_SUPPLICANT_HIDL_VENDOR_STA_NETWORK_H
#define WPA_SUPPLICANT_HIDL_VENDOR_STA_NETWORK_H

#include <array>
#include <vector>

#include <android-base/macros.h>

#include <android/hardware/wifi/supplicant/1.1/ISupplicantStaNetwork.h>
#include <android/hardware/wifi/supplicant/1.0/ISupplicantStaNetworkCallback.h>
#include <vendor/qti/hardware/wifi/supplicant/2.0/ISupplicantVendorStaNetwork.h>

extern "C" {
#include "utils/common.h"
#include "utils/includes.h"
#include "config.h"
#include "wpa_supplicant_i.h"
#include "notify.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "eap_peer/eap.h"
#include "rsn_supp/wpa.h"
}

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor {
namespace V2_2 {
namespace Implementation {
using namespace android::hardware::wifi::supplicant::V1_0;
using namespace vendor::qti::hardware::wifi::supplicant::V2_0;
using namespace android::hardware;

/**
 * Implementation of StaNetwork hidl object. Each unique hidl
 * object is used for control operations on a specific network
 * controlled by wpa_supplicant.
 */
class VendorStaNetwork : public ISupplicantVendorStaNetwork
{
public:
	VendorStaNetwork(
	    struct wpa_global* wpa_global, const char ifname[], int network_id);
	~VendorStaNetwork() override = default;
	// Refer to |StaIface::invalidate()|.
	void invalidate();
	bool isValid();

	// Hidl methods exposed.
	Return<void> setVendorKeyMgmt(
	    uint32_t key_mgmt_mask, setVendorKeyMgmt_cb _hidl_cb) override;
	Return<void> setVendorAuthAlg(
	    uint32_t auth_alg_mask, setVendorAuthAlg_cb _hidl_cb) override;
	Return<void> setVendorGroupCipher(
	    uint32_t group_cipher_mask, setVendorGroupCipher_cb _hidl_cb) override;
	Return<void> setVendorPairwiseCipher(
	    uint32_t pairwise_cipher_mask, setVendorPairwiseCipher_cb _hidl_cb) override;
	Return<void> getVendorKeyMgmt(getVendorKeyMgmt_cb _hidl_cb) override;
	Return<void> getVendorAuthAlg(getVendorAuthAlg_cb _hidl_cb) override;
	Return<void> getVendorGroupCipher(getVendorGroupCipher_cb _hidl_cb) override;
	Return<void> getVendorPairwiseCipher(getVendorPairwiseCipher_cb _hidl_cb) override;
	Return<void> setEapErp(bool enable, setEapErp_cb _hidl_cb) override;
	Return<void> setVendorProto(
	    uint32_t proto_mask, setVendorProto_cb _hidl_cb) override;
	Return<void> getVendorProto(getVendorProto_cb _hidl_cb) override;
	Return<void> setDppConnector(
	    const hidl_string& connector,
	    setDppConnector_cb _hidl_cb) override;
	Return<void> setDppNetAccessKey(
	    const hidl_vec<uint8_t>& net_access_key,
	    setDppNetAccessKey_cb _hidl_cb) override;
	Return<void> setDppNetAccessKeyExpiry(
	    uint32_t expiry, setDppNetAccessKeyExpiry_cb _hidl_cb) override;
	Return<void> setDppCsign(
	    const hidl_vec<uint8_t>& csign,
	    setDppCsign_cb _hidl_cb) override;
	Return<void> setVendorSimNumber(
	    uint32_t id, setVendorSimNumber_cb _hidl_cb) override;
	Return<void> setGroupMgmtCipher(
	    uint32_t group_mgmt_cipher, setGroupMgmtCipher_cb _hidl_cb) override;
	Return<void> setEapPhase1Params(
	    const hidl_string& phase1, setEapPhase1Params_cb _hidl_cb) override;
	Return<void> setEapOpensslCiphers(
	    const hidl_string& openssl_ciphers, setEapOpensslCiphers_cb _hidl_cb) override;
	Return<void> setWapiPskType(
	    uint32_t type, setWapiPskType_cb _hidl_cb) override;
	Return<void> setWapiPsk(
	    const hidl_string &psk, setWapiPsk_cb _hidl_cb) override;
	Return<void> setWapiCertSelMode(
	    uint32_t mode, setWapiCertSelMode_cb _hidl_cb) override;
	Return<void> setWapiCertSel(
	    const hidl_string &name, setWapiCertSel_cb _hidl_cb) override;
	Return<void> getWapiPskType(
	    getWapiPskType_cb _hidl_cb) override;
	Return<void> getWapiPsk(
	    getWapiPsk_cb _hidl_cb) override;
	Return<void> getWapiCertSelMode(
	    getWapiCertSelMode_cb _hidl_cb) override;
	Return<void> getWapiCertSel(
	    getWapiCertSel_cb _hidl_cb) override;

private:
	// Corresponding worker functions for the HIDL methods.
	SupplicantStatus setKeyMgmtInternal(uint32_t key_mgmt_mask);
	SupplicantStatus setAuthAlgInternal(uint32_t auth_alg_mask);
	SupplicantStatus setGroupCipherInternal(uint32_t group_cipher_mask);
	SupplicantStatus setPairwiseCipherInternal(uint32_t pairwise_cipher_mask);
	std::pair<SupplicantStatus, uint32_t> getKeyMgmtInternal();
	std::pair<SupplicantStatus, uint32_t> getAuthAlgInternal();
	std::pair<SupplicantStatus, uint32_t> getGroupCipherInternal();
	std::pair<SupplicantStatus, uint32_t> getPairwiseCipherInternal();
	SupplicantStatus setEapErpInternal(bool enable);
        SupplicantStatus setProtoInternal(uint32_t proto_mask);
        std::pair<SupplicantStatus, uint32_t> getProtoInternal();
        SupplicantStatus setDppConnectorInternal(const std::string& connector);
	SupplicantStatus setDppNetAccessKeyInternal(
	    const std::vector<uint8_t>& net_access_key);
	SupplicantStatus setDppNetAccessKeyExpiryInternal(uint32_t expiry);
	SupplicantStatus setDppCsignInternal(
	    const std::vector<uint8_t>& csign);

        SupplicantStatus setGroupMgmtCipherInternal(uint32_t grp_mgmt_cipher);
        SupplicantStatus setEapPhase1ParamsInternal(const std::string& phase1);
        SupplicantStatus setEapOpensslCiphersInternal(const std::string& openssl_ciphers);
	SupplicantStatus setVendorSimNumberInternal(uint32_t id);
	SupplicantStatus setWapiPskTypeInternal(uint32_t type);
	SupplicantStatus setWapiPskInternal(const std::string &psk);
	SupplicantStatus setWapiCertSelModeInternal(uint32_t mode);
	SupplicantStatus setWapiCertSelInternal(const std::string &name);
	std::pair<SupplicantStatus, uint32_t> getWapiPskTypeInternal();
	std::pair<SupplicantStatus, std::string> getWapiPskInternal();
	std::pair<SupplicantStatus, uint32_t> getWapiCertSelModeInternal();
	std::pair<SupplicantStatus, std::string> getWapiCertSelInternal();

	struct wpa_ssid* retrieveNetworkPtr();
	struct wpa_supplicant* retrieveIfacePtr();
	void resetInternalStateAfterParamsUpdate();
	// Reference to the global wpa_struct. This is assumed to be valid
	// for the lifetime of the process.
	struct wpa_global* wpa_global_;
	// Name of the iface this network belongs to.
	const std::string ifname_;
	// Id of the network this hidl object controls.
	const int network_id_;
	bool is_valid_;

	int setVendorStringFieldAndResetState(
	    const char* value, uint8_t** to_update_field,
	    const char* hexdump_prefix);
	int setVendorStringFieldAndResetState(
	    const char* value, char** to_update_field,
	    const char* hexdump_prefix);
	int setHexStr2bin(
	    const uint8_t* value, const size_t value_len,
	    uint8_t** to_update_field, size_t* to_update_field_len,
	    const char* hexdump_prefix);
	DISALLOW_COPY_AND_ASSIGN(VendorStaNetwork);
};

}  // namespace implementation
}  // namespace V2_2
}  // namespace supplicantvendor
}  // namespace wifi
}  // namespace hardware
}  // namespace qti
}  // namespace vendor

#endif  // WPA_SUPPLICANT_HIDL_VENDOR_STA_NETWORK_H

