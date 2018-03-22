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
#include "misc_utils.h"
#include "sta_network.h"
#include "vendorsta_network.h"

extern "C" {
#include "wps_supplicant.h"
}

namespace {
using android::hardware::wifi::supplicant::V1_0::ISupplicantStaNetwork;
using vendor::qti::hardware::wifi::supplicant::V2_0::ISupplicantVendorStaNetwork;
using android::hardware::wifi::supplicant::V1_0::SupplicantStatus;

constexpr uint32_t kAllowedVendorKeyMgmtMask =
    (static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::WAPI_PSK) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::WAPI_CERT) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::IEEE8021X_SUITEB) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::IEEE8021X_SUITEB_192) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::FILS_SHA256) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::FILS_SHA384) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::OWE) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::SAE) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorKeyMgmtMask::DPP));

constexpr uint32_t kAllowedVendorAuthAlgMask =
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorAuthAlgMask::FILS_SK);

constexpr uint32_t kAllowedVendorGroupCipherMask =
    (static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorGroupCipherMask::GCMP) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorGroupCipherMask::GCMP_256));

constexpr uint32_t kAllowedVendorPairwiseCipherMask =
    (static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorPairwiseCipherMask::GCMP) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorPairwiseCipherMask::GCMP_256));

constexpr uint32_t kAllowedVendorProtoMask =
    static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorProtoMask::WAPI);

constexpr uint32_t kAllowedVendorGroupMgmtCipherMask =
    (static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorGroupMgmtCipherMask::BIP_GMAC_128) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorGroupMgmtCipherMask::BIP_GMAC_256) |
     static_cast<uint32_t>(ISupplicantVendorStaNetwork::VendorGroupMgmtCipherMask::BIP_CMAC_256));
}  // namespace

namespace vendor {
namespace qti {
namespace hardware {
namespace wifi {
namespace supplicantvendor {
namespace V2_2 {
namespace Implementation {
using android::hardware::wifi::supplicant::V1_4::implementation::hidl_return_util::validateAndCall;

VendorStaNetwork::VendorStaNetwork(
    struct wpa_global *wpa_global, const char ifname[], int network_id)
    : wpa_global_(wpa_global),
      ifname_(ifname),
      network_id_(network_id),
      is_valid_(true)
{
}

void VendorStaNetwork::invalidate() { is_valid_ = false; }
bool VendorStaNetwork::isValid()
{
	return (is_valid_ && (retrieveNetworkPtr() != nullptr));
}

Return<void> VendorStaNetwork::setVendorKeyMgmt(
    uint32_t key_mgmt_mask, setVendorKeyMgmt_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setKeyMgmtInternal, _hidl_cb, key_mgmt_mask);
}

Return<void> VendorStaNetwork::setVendorAuthAlg(
    uint32_t auth_alg_mask,
    std::function<void(const SupplicantStatus &status)> _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setAuthAlgInternal, _hidl_cb, auth_alg_mask);
}

Return<void> VendorStaNetwork::setVendorGroupCipher(
    uint32_t group_cipher_mask, setVendorGroupCipher_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setGroupCipherInternal, _hidl_cb, group_cipher_mask);
}

Return<void> VendorStaNetwork::setVendorPairwiseCipher(
    uint32_t group_cipher_mask, setVendorPairwiseCipher_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setPairwiseCipherInternal, _hidl_cb, group_cipher_mask);
}

Return<void> VendorStaNetwork::getVendorKeyMgmt(getVendorKeyMgmt_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getKeyMgmtInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getVendorAuthAlg(getVendorAuthAlg_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getAuthAlgInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getVendorGroupCipher(getVendorGroupCipher_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getGroupCipherInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getVendorPairwiseCipher(getVendorPairwiseCipher_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getPairwiseCipherInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::setEapErp(bool enable, setEapErp_cb _hidl_cb)
{
        return validateAndCall(
            this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
            &VendorStaNetwork::setEapErpInternal, _hidl_cb, enable);
}

Return<void> VendorStaNetwork::setVendorProto(
    uint32_t proto_mask, setVendorProto_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setProtoInternal, _hidl_cb, proto_mask);
}

Return<void> VendorStaNetwork::getVendorProto(getVendorProto_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getProtoInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::setGroupMgmtCipher(
    uint32_t group_mgmt_cipher, setGroupMgmtCipher_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setGroupMgmtCipherInternal, _hidl_cb, group_mgmt_cipher);
}

Return<void> VendorStaNetwork::setEapPhase1Params(
    const hidl_string &phase1, setEapPhase1Params_cb _hidl_cb)
{
        return validateAndCall(
            this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
            &VendorStaNetwork::setEapPhase1ParamsInternal, _hidl_cb, phase1);
}

Return<void> VendorStaNetwork::setEapOpensslCiphers(
    const hidl_string &openssl_ciphers, setEapOpensslCiphers_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setEapOpensslCiphersInternal, _hidl_cb, openssl_ciphers);
}
Return<void> VendorStaNetwork::setDppConnector(
    const hidl_string &connector, setDppConnector_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setDppConnectorInternal, _hidl_cb, connector);
}

Return<void> VendorStaNetwork::setDppNetAccessKey(
    const hidl_vec<uint8_t>& net_access_key, setDppNetAccessKey_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setDppNetAccessKeyInternal, _hidl_cb, net_access_key);
}

Return<void> VendorStaNetwork::setDppNetAccessKeyExpiry(
    uint32_t expiry, setDppNetAccessKeyExpiry_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setDppNetAccessKeyExpiryInternal, _hidl_cb, expiry);
}

Return<void> VendorStaNetwork::setDppCsign(
    const hidl_vec<uint8_t>& csign, setDppCsign_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setDppCsignInternal, _hidl_cb, csign);
}

Return<void> VendorStaNetwork::setVendorSimNumber(
    uint32_t id, setVendorSimNumber_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setVendorSimNumberInternal, _hidl_cb, id);
}

Return<void> VendorStaNetwork::setWapiPskType(
    uint32_t type, setWapiPskType_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setWapiPskTypeInternal, _hidl_cb, type);
}

Return<void> VendorStaNetwork::setWapiPsk(
    const hidl_string &psk, setWapiPsk_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setWapiPskInternal, _hidl_cb, psk);
}

Return<void> VendorStaNetwork::setWapiCertSelMode(
    uint32_t mode, setWapiCertSelMode_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setWapiCertSelModeInternal, _hidl_cb, mode);
}

Return<void> VendorStaNetwork::setWapiCertSel(
    const hidl_string &name, setWapiCertSel_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::setWapiCertSelInternal, _hidl_cb, name);
}

Return<void> VendorStaNetwork::getWapiPskType(getWapiPskType_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getWapiPskTypeInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getWapiPsk(getWapiPsk_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getWapiPskInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getWapiCertSelMode(getWapiCertSelMode_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getWapiCertSelModeInternal, _hidl_cb);
}

Return<void> VendorStaNetwork::getWapiCertSel(getWapiCertSel_cb _hidl_cb)
{
	return validateAndCall(
	    this, SupplicantStatusCode::FAILURE_NETWORK_INVALID,
	    &VendorStaNetwork::getWapiCertSelInternal, _hidl_cb);
}

SupplicantStatus VendorStaNetwork::setKeyMgmtInternal(uint32_t key_mgmt_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (key_mgmt_mask & ~kAllowedVendorKeyMgmtMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->key_mgmt |= key_mgmt_mask;
	wpa_printf(MSG_INFO, "Vendor key_mgmt: 0x%x", wpa_ssid->key_mgmt);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setAuthAlgInternal(uint32_t auth_alg_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (auth_alg_mask & ~kAllowedVendorAuthAlgMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->auth_alg |= auth_alg_mask;
	wpa_printf(MSG_INFO, "vendor auth_alg: 0x%x", wpa_ssid->auth_alg);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setGroupCipherInternal(uint32_t group_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (group_cipher_mask & ~kAllowedVendorGroupCipherMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->group_cipher |= group_cipher_mask;
	wpa_printf(MSG_INFO, "vendor group_cipher: 0x%x", wpa_ssid->group_cipher);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setPairwiseCipherInternal(uint32_t pairwise_cipher_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (pairwise_cipher_mask & ~kAllowedVendorPairwiseCipherMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->pairwise_cipher |= pairwise_cipher_mask;
	wpa_printf(MSG_INFO, "vendor pairwise_cipher: 0x%x", wpa_ssid->pairwise_cipher);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getKeyMgmtInternal()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""},
		wpa_ssid->key_mgmt & kAllowedVendorKeyMgmtMask};
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getAuthAlgInternal()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""},
		wpa_ssid->auth_alg & kAllowedVendorAuthAlgMask};
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getGroupCipherInternal()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""},
		wpa_ssid->group_cipher & kAllowedVendorGroupCipherMask};
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getPairwiseCipherInternal()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""},
		wpa_ssid->pairwise_cipher & kAllowedVendorPairwiseCipherMask};
}

SupplicantStatus VendorStaNetwork::setEapErpInternal(bool enable)
{
#ifdef CONFIG_FILS
        struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
        wpa_ssid->eap.erp = enable ? 1 : 0;
        return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_FILS */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_FILS */
}

SupplicantStatus VendorStaNetwork::setProtoInternal(uint32_t proto_mask)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (proto_mask & ~kAllowedVendorProtoMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->proto |= proto_mask;
	wpa_printf(MSG_INFO, "Vendor Proto: 0x%x", wpa_ssid->proto);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getProtoInternal()
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""},
		wpa_ssid->proto & kAllowedVendorProtoMask};
}

SupplicantStatus VendorStaNetwork::setDppConnectorInternal(
    const std::string &connector)
{
#ifdef CONFIG_DPP
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (setVendorStringFieldAndResetState(
		connector.c_str(), &(wpa_ssid->dpp_connector),
		"dpp_connector")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_DPP */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_DPP */
}

SupplicantStatus VendorStaNetwork::setDppNetAccessKeyInternal(
    const std::vector<uint8_t> &net_access_key)
{
#ifdef CONFIG_DPP
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (setHexStr2bin(net_access_key.data(), net_access_key.size(),
			  &(wpa_ssid->dpp_netaccesskey),
			  &(wpa_ssid->dpp_netaccesskey_len), "dpp NetAccessKey")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_DPP */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_DPP */
}

SupplicantStatus VendorStaNetwork::setDppNetAccessKeyExpiryInternal(uint32_t expiry)
{
#ifdef CONFIG_DPP
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	wpa_ssid->dpp_netaccesskey_expiry = expiry;
	wpa_printf(MSG_MSGDUMP, "dpp_netaccesskey_expiry: %d",
		   wpa_ssid->dpp_netaccesskey_expiry);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_DPP */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_DPP */
}

SupplicantStatus VendorStaNetwork::setDppCsignInternal(
    const std::vector<uint8_t> &csign)
{
#ifdef CONFIG_DPP
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (setHexStr2bin(csign.data(), csign.size(), &(wpa_ssid->dpp_csign),
			  &(wpa_ssid->dpp_csign_len), "dpp C-Sign")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_DPP */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_DPP */
}

SupplicantStatus VendorStaNetwork::setGroupMgmtCipherInternal(uint32_t group_mgmt_cipher)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (group_mgmt_cipher & ~kAllowedVendorGroupMgmtCipherMask) {
		return {SupplicantStatusCode::FAILURE_ARGS_INVALID, ""};
	}
	wpa_ssid->group_mgmt_cipher = group_mgmt_cipher;
	wpa_printf(MSG_MSGDUMP, "group_mgmt_cipher: 0x%x", wpa_ssid->group_mgmt_cipher);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setEapPhase1ParamsInternal(const std::string &phase1)
{
        struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
        if (setVendorStringFieldAndResetState(
                phase1.c_str(), &(wpa_ssid->eap.phase1), "phase1")) {
                return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
        }
        return {SupplicantStatusCode::SUCCESS, ""};

}

SupplicantStatus VendorStaNetwork::setEapOpensslCiphersInternal(const std::string &openssl_ciphers)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
        if (setVendorStringFieldAndResetState(
		openssl_ciphers.c_str(), &(wpa_ssid->eap.openssl_ciphers), "openssl_ciphers")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setVendorSimNumberInternal(uint32_t id)
{
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	wpa_ssid->eap.sim_num = id;
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
}

SupplicantStatus VendorStaNetwork::setWapiPskTypeInternal(uint32_t type)
{

#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	wpa_ssid->psk_key_type = type;
	wpa_printf(MSG_DEBUG, "WapiPskType: 0x%x", wpa_ssid->psk_key_type);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_WAPI */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_WAPI */
}

SupplicantStatus VendorStaNetwork::setWapiPskInternal(const std::string &psk)
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	if (wpa_ssid->wapi_psk &&
	    os_strlen(wpa_ssid->wapi_psk) == psk.size() &&
	    os_memcmp(wpa_ssid->wapi_psk, psk.c_str(), psk.size()) == 0) {
		return {SupplicantStatusCode::SUCCESS, ""};
	}

	if (setVendorStringFieldAndResetState(
		psk.c_str(), &(wpa_ssid->wapi_psk), "wapi_psk")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}

	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_WAPI */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_WAPI */
}

SupplicantStatus VendorStaNetwork::setWapiCertSelModeInternal(uint32_t mode)
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	wpa_ssid->wapi_user_cert_mode = mode;
	wpa_printf(MSG_DEBUG, "WapiCertSelMode: 0x%x", wpa_ssid->wapi_user_cert_mode);
	resetInternalStateAfterParamsUpdate();
	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_WAPI */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_WAPI */
}

SupplicantStatus VendorStaNetwork::setWapiCertSelInternal(const std::string &name)
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	if (setVendorStringFieldAndResetState(
		name.c_str(), &(wpa_ssid->wapi_user_sel_cert), "wapi_user_sel_cert")) {
		return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
	}

	return {SupplicantStatusCode::SUCCESS, ""};
#else /* CONFIG_WAPI */
        return {SupplicantStatusCode::FAILURE_UNKNOWN, ""};
#endif /* CONFIG_WAPI */
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getWapiPskTypeInternal()
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""}, wpa_ssid->psk_key_type};
#else /* CONFIG_WAPI */
	return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
#endif /* CONFIG_WAPI */
}

std::pair<SupplicantStatus, std::string> VendorStaNetwork::getWapiPskInternal()
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (!wpa_ssid->wapi_psk) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, wpa_ssid->wapi_psk};
#else /* CONFIG_WAPI */
	return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
#endif /* CONFIG_WAPI */
}

std::pair<SupplicantStatus, uint32_t> VendorStaNetwork::getWapiCertSelModeInternal()
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	return {{SupplicantStatusCode::SUCCESS, ""}, wpa_ssid->wapi_user_cert_mode};
#else /* CONFIG_WAPI */
	return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
#endif /* CONFIG_WAPI */
}

std::pair<SupplicantStatus, std::string> VendorStaNetwork::getWapiCertSelInternal()
{
#ifdef CONFIG_WAPI
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();
	if (!wpa_ssid->wapi_user_sel_cert) {
		return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
	}
	return {{SupplicantStatusCode::SUCCESS, ""}, wpa_ssid->wapi_user_sel_cert};
#else /* CONFIG_WAPI */
	return {{SupplicantStatusCode::FAILURE_UNKNOWN, ""}, {}};
#endif /* CONFIG_WAPI */
}

/**
 * Retrieve the underlying |wpa_ssid| struct pointer for
 * this network.
 * If the underlying network is removed or the interface
 * this network belong to
 * is removed, all RPC method calls on this object will
 * return failure.
 */
struct wpa_ssid *VendorStaNetwork::retrieveNetworkPtr()
{
	wpa_supplicant *wpa_s = retrieveIfacePtr();
	if (!wpa_s)
		return nullptr;
	return wpa_config_get_network(wpa_s->conf, network_id_);
}

/**
 * Retrieve the underlying |wpa_supplicant| struct
 * pointer for
 * this network.
 */
struct wpa_supplicant *VendorStaNetwork::retrieveIfacePtr()
{
	return wpa_supplicant_get_iface(wpa_global_, ifname_.c_str());
}


/**
 * Helper function to set value in a string field in |wpa_ssid| structue
 * instance for this vendor network.
 * This function frees any existing data in these fields.
 */
int VendorStaNetwork::setVendorStringFieldAndResetState(
    const char *value, uint8_t **to_update_field, const char *hexdump_prefix)
{
	return setVendorStringFieldAndResetState(
	    value, (char **)to_update_field, hexdump_prefix);
}

/**
 * Helper function to set value in a string field in |wpa_ssid| structue
 * instance for this vendor network.
 * This function frees any existing data in these fields.
 */
int VendorStaNetwork::setVendorStringFieldAndResetState(
    const char *value, char **to_update_field, const char *hexdump_prefix)
{
	int value_len = strlen(value);
	if (*to_update_field) {
		os_free(*to_update_field);
	}
	*to_update_field = dup_binstr(value, value_len);
	if (!(*to_update_field)) {
		return 1;
	}
	wpa_hexdump_ascii(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field, value_len);
	resetInternalStateAfterParamsUpdate();
	return 0;
}

/**
 * Reset internal wpa_supplicant state machine state
 * after params update (except
 * bssid).
 */
void VendorStaNetwork::resetInternalStateAfterParamsUpdate()
{
	struct wpa_supplicant *wpa_s = retrieveIfacePtr();
	struct wpa_ssid *wpa_ssid = retrieveNetworkPtr();

	wpa_sm_pmksa_cache_flush(wpa_s->wpa, wpa_ssid);

	if (wpa_s->current_ssid == wpa_ssid || wpa_s->current_ssid == NULL) {
		/*
		 * Invalidate the EAP session cache if
		 * anything in the
		 * current or previously used
		 * configuration changes.
		 */
		eapol_sm_invalidate_cached_session(wpa_s->eapol);
	}
}

/**
 * Helper function to set Hex string value to a bin field with a corresponding length
 * field in |wpa_ssid| structue instance for this network.
 * This function frees any existing data in these fields.
 */
int VendorStaNetwork::setHexStr2bin(
    const uint8_t *value, const size_t value_len, uint8_t **to_update_field,
    size_t *to_update_field_len, const char *hexdump_prefix)
{
	size_t len;
	if (*to_update_field) {
		os_free(*to_update_field);
	}
	if (value_len & 1)
		return 1;

	len = value_len / 2;
	*to_update_field = (uint8_t *)os_malloc(len);
	if (!(*to_update_field) ||
	    hexstr2bin((const char *)value, *to_update_field, len)) {
		return 1;
	}
	*to_update_field_len = len;

	wpa_hexdump(
	    MSG_MSGDUMP, hexdump_prefix, *to_update_field,
	    *to_update_field_len);
	resetInternalStateAfterParamsUpdate();
	return 0;
}
}  // namespace implementation
}  // namespace V2_2
}  // namespace wifi
}  // namespace supplicantvendor
}  // namespace hardware
}  // namespace qti
}  // namespace vendor
