/*
 * aidl interface for wpa_hostapd daemon
 * Copyright (c) 2004-2018, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004-2018, Roshan Pius <rpius@google.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_bridge.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include "hostapd.h"
#include <aidl/android/hardware/wifi/hostapd/ApInfo.h>
#include <aidl/android/hardware/wifi/hostapd/BandMask.h>
#include <aidl/android/hardware/wifi/hostapd/ChannelParams.h>
#include <aidl/android/hardware/wifi/hostapd/ClientInfo.h>
#include <aidl/android/hardware/wifi/hostapd/EncryptionType.h>
#include <aidl/android/hardware/wifi/hostapd/HostapdStatusCode.h>
#include <aidl/android/hardware/wifi/hostapd/IfaceParams.h>
#include <aidl/android/hardware/wifi/hostapd/NetworkParams.h>
#include <aidl/android/hardware/wifi/hostapd/ParamSizeLimits.h>

extern "C"
{
#include "common/wpa_ctrl.h"
#include "drivers/linux_ioctl.h"
}


#ifdef ANDROID_HOSTAPD_UNITTEST
#include "tests/unittest_overrides.h"
#endif

// The AIDL implementation for hostapd creates a hostapd.conf dynamically for
// each interface. This file can then be used to hook onto the normal config
// file parsing logic in hostapd code.  Helps us to avoid duplication of code
// in the AIDL interface.
// TOOD(b/71872409): Add unit tests for this.
namespace {
constexpr char kConfFileNameFmt[] = "/data/vendor/wifi/hostapd/hostapd_%s.conf";

/**
 * To add an overlay file, add
 *
 * PRODUCT_COPY_FILES += \
 *   <your/path/here>/hostapd_unmetered_overlay.conf:/vendor/etc/wifi/hostapd_unmetered_overlay.conf
 *
 * to the build file for your device, with the <your/path/here> being the path to your overlay in
 * your repo. See the resolveVendorConfPath function in this file for more specifics on where this
 * overlay file will wind up on your device.
 *
 * This overlay may configure any of the parameters listed in kOverlayableKeys. The kOverlayableKeys
 * list is subject to change over time, as certain parameters may be added as APIs instead in the
 * future.
 *
 * Example of what an overlay file might look like:
 * $> cat hostapd_unmetered_overlay.conf
 * dtim_period=2
 * ap_max_inactivity=300
 *
 * Anything added to this overlay will be prepended to the hostapd.conf for unmetered (typically
 * local only hotspots) interfaces.
 */
constexpr char kUnmeteredIfaceOverlayPath[] = "/etc/wifi/hostapd_unmetered_overlay.conf";

/**
 * Allow-list of hostapd.conf parameters (keys) that can be set via overlay.
 *
 * If introducing new APIs, be sure to remove keys from this list that would otherwise be
 * controlled by the new API. This way we can avoid conflicting settings.
 * Please file an FR to add new keys to this list.
 */
static const std::set<std::string> kOverlayableKeys = {
	"ap_max_inactivity",
	"assocresp_elements"
	"beacon_int",
	"disassoc_low_ack",
	"dtim_period",
	"fragm_threshold",
	"max_listen_interval",
	"max_num_sta",
	"rts_threshold",
	"skip_inactivity_poll",
	"uapsd_advertisement_enabled",
	"wmm_enabled",
	"wmm_ac_vo_aifs",
	"wmm_ac_vo_cwmin",
	"wmm_ac_vo_cwmax",
	"wmm_ac_vo_txop_limit",
	"wmm_ac_vo_acm",
	"wmm_ac_vi_aifs",
	"wmm_ac_vi_cwmin",
	"wmm_ac_vi_cwmax",
	"wmm_ac_vi_txop_limit",
	"wmm_ac_vi_acm",
	"wmm_ac_bk_cwmin"
	"wmm_ac_bk_cwmax"
	"wmm_ac_bk_aifs",
	"wmm_ac_bk_txop_limit",
	"wmm_ac_bk_acm",
	"wmm_ac_be_aifs",
	"wmm_ac_be_cwmin",
	"wmm_ac_be_cwmax",
	"wmm_ac_be_txop_limit",
	"wmm_ac_be_acm",
};

using android::base::RemoveFileIfExists;
using android::base::StringPrintf;
#ifndef ANDROID_HOSTAPD_UNITTEST
using android::base::ReadFileToString;
using android::base::WriteStringToFile;
#endif
using aidl::android::hardware::wifi::hostapd::BandMask;
using aidl::android::hardware::wifi::hostapd::ChannelBandwidth;
using aidl::android::hardware::wifi::hostapd::ChannelParams;
using aidl::android::hardware::wifi::hostapd::EncryptionType;
using aidl::android::hardware::wifi::hostapd::Generation;
using aidl::android::hardware::wifi::hostapd::HostapdStatusCode;
using aidl::android::hardware::wifi::hostapd::IfaceParams;
using aidl::android::hardware::wifi::hostapd::NetworkParams;
using aidl::android::hardware::wifi::hostapd::ParamSizeLimits;

int band2Ghz = (int)BandMask::BAND_2_GHZ;
int band5Ghz = (int)BandMask::BAND_5_GHZ;
int band6Ghz = (int)BandMask::BAND_6_GHZ;
int band60Ghz = (int)BandMask::BAND_60_GHZ;

int32_t aidl_client_version = 0;
int32_t aidl_service_version = 0;

/**
 * Check that the AIDL service is running at least the expected version.
 * Use to avoid the case where the AIDL interface version
 * is greater than the version implemented by the service.
 */
inline int32_t isAidlServiceVersionAtLeast(int32_t expected_version)
{
	return expected_version <= aidl_service_version;
}

inline int32_t isAidlClientVersionAtLeast(int32_t expected_version)
{
	return expected_version <= aidl_client_version;
}

inline int32_t areAidlServiceAndClientAtLeastVersion(int32_t expected_version)
{
	return isAidlServiceVersionAtLeast(expected_version)
		&& isAidlClientVersionAtLeast(expected_version);
}

#define MAX_PORTS 1024
bool GetInterfacesInBridge(std::string br_name,
                           std::vector<std::string>* interfaces) {
	android::base::unique_fd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
	if (sock.get() < 0) {
		wpa_printf(MSG_ERROR, "Failed to create sock (%s) in %s",
			strerror(errno), __FUNCTION__);
		return false;
	}

	struct ifreq request;
	int i, ifindices[MAX_PORTS];
	char if_name[IFNAMSIZ];
	unsigned long args[3];

	memset(ifindices, 0, MAX_PORTS * sizeof(int));

	args[0] = BRCTL_GET_PORT_LIST;
	args[1] = (unsigned long) ifindices;
	args[2] = MAX_PORTS;

	strlcpy(request.ifr_name, br_name.c_str(), IFNAMSIZ);
	request.ifr_data = (char *)args;

	if (ioctl(sock.get(), SIOCDEVPRIVATE, &request) < 0) {
		wpa_printf(MSG_ERROR, "Failed to ioctl SIOCDEVPRIVATE in %s",
			__FUNCTION__);
		return false;
	}

	for (i = 0; i < MAX_PORTS; i ++) {
		memset(if_name, 0, IFNAMSIZ);
		if (ifindices[i] == 0 || !if_indextoname(ifindices[i], if_name)) {
			continue;
		}
		interfaces->push_back(if_name);
	}
	return true;
}

std::string resolveVendorConfPath(const std::string& conf_path)
{
#if defined(__ANDROID_APEX__)
	// returns "/apex/<apexname>" + conf_path
	std::string path = android::base::GetExecutablePath();
	return path.substr(0, path.find_first_of('/', strlen("/apex/"))) + conf_path;
#else
	return std::string("/vendor") + conf_path;
#endif
}

void logHostapdConfigError(int error, const std::string& file_path) {
	wpa_printf(MSG_ERROR, "Cannot read/write hostapd config %s, error: %s", file_path.c_str(),
			strerror(error));
	struct stat st;
	int result = stat(file_path.c_str(), &st);
	if (result == 0) {
		wpa_printf(MSG_ERROR, "hostapd config file uid: %d, gid: %d, mode: %d",st.st_uid,
				st.st_gid, st.st_mode);
	} else {
		wpa_printf(MSG_ERROR, "Error calling stat() on hostapd config file: %s",
				strerror(errno));
	}
}

std::string WriteHostapdConfig(
    const std::string& instance_name, const std::string& config,
    const std::string br_name, const bool usesMlo)
{
	std::string conf_name_as_string = instance_name;
	if (usesMlo) {
		conf_name_as_string = StringPrintf(
				"%s-%s", br_name.c_str(), instance_name.c_str());
	}
	const std::string file_path =
		StringPrintf(kConfFileNameFmt, conf_name_as_string.c_str());
	if (WriteStringToFile(
		config, file_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
		getuid(), getgid())) {
		return file_path;
	}
	// Diagnose failure
	int error = errno;
	logHostapdConfigError(errno, file_path);
	return "";
}

/*
 * Get the op_class for a channel/band
 * The logic here is based on Table E-4 in the 802.11 Specification
 */
int getOpClassForChannel(int channel, int band, bool support11n, bool support11ac) {
	// 2GHz Band
	if ((band & band2Ghz) != 0) {
		if (channel == 14) {
			return 82;
		}
		if (channel >= 1 && channel <= 13) {
			if (!support11n) {
				//20MHz channel
				return 81;
			}
			if (channel <= 9) {
				// HT40 with secondary channel above primary
				return 83;
			}
			// HT40 with secondary channel below primary
			return 84;
		}
		// Error
		return 0;
	}

	// 5GHz Band
	if ((band & band5Ghz) != 0) {
		if (support11ac) {
			switch (channel) {
				case 42:
				case 58:
				case 106:
				case 122:
				case 138:
				case 155:
					// 80MHz channel
					return 128;
				case 50:
				case 114:
					// 160MHz channel
					return 129;
			}
		}

		if (!support11n) {
			if (channel >= 36 && channel <= 48) {
				return 115;
			}
			if (channel >= 52 && channel <= 64) {
				return 118;
			}
			if (channel >= 100 && channel <= 144) {
				return 121;
			}
			if (channel >= 149 && channel <= 161) {
				return 124;
			}
			if (channel >= 165 && channel <= 169) {
				return 125;
			}
		} else {
			switch (channel) {
				case 36:
				case 44:
					// HT40 with secondary channel above primary
					return 116;
				case 40:
				case 48:
					// HT40 with secondary channel below primary
					return 117;
				case 52:
				case 60:
					// HT40 with secondary channel above primary
					return  119;
				case 56:
				case 64:
					// HT40 with secondary channel below primary
					return 120;
				case 100:
				case 108:
				case 116:
				case 124:
				case 132:
				case 140:
					// HT40 with secondary channel above primary
					return 122;
				case 104:
				case 112:
				case 120:
				case 128:
				case 136:
				case 144:
					// HT40 with secondary channel below primary
					return 123;
				case 149:
				case 157:
					// HT40 with secondary channel above primary
					return 126;
				case 153:
				case 161:
					// HT40 with secondary channel below primary
					return 127;
			}
		}
		// Error
		return 0;
	}

	// 6GHz Band
	if ((band & band6Ghz) != 0) {
		// Channels 1, 5. 9, 13, ...
		if ((channel & 0x03) == 0x01) {
			// 20MHz channel
			return 131;
		}
		// Channels 3, 11, 19, 27, ...
		if ((channel & 0x07) == 0x03) {
			// 40MHz channel
			return 132;
		}
		// Channels 7, 23, 39, 55, ...
		if ((channel & 0x0F) == 0x07) {
			// 80MHz channel
			return 133;
		}
		// Channels 15, 47, 69, ...
		if ((channel & 0x1F) == 0x0F) {
			// 160MHz channel
			return 134;
		}
		if (channel == 2) {
			// 20MHz channel
			return 136;
		}
		// Error
		return 0;
	}

	if ((band & band60Ghz) != 0) {
		if (1 <= channel && channel <= 8) {
			return 180;
		} else if (9 <= channel && channel <= 15) {
			return 181;
		} else if (17 <= channel && channel <= 22) {
			return 182;
		} else if (25 <= channel && channel <= 29) {
			return 183;
		}
		// Error
		return 0;
	}

	return 0;
}

bool validatePassphrase(int passphrase_len, int min_len, int max_len)
{
	if (min_len != -1 && passphrase_len < min_len) return false;
	if (max_len != -1 && passphrase_len > max_len) return false;
	return true;
}

std::string getInterfaceMacAddress(const std::string& if_name)
{
	u8 addr[ETH_ALEN] = {};
	struct ifreq ifr;
	std::string mac_addr;

	android::base::unique_fd sock(socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
	if (sock.get() < 0) {
		wpa_printf(MSG_ERROR, "Failed to create sock (%s) in %s",
			strerror(errno), __FUNCTION__);
		return "";
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);
	if (ioctl(sock.get(), SIOCGIFHWADDR, &ifr) < 0) {
		wpa_printf(MSG_ERROR, "Could not get interface %s hwaddr: %s",
			   if_name.c_str(), strerror(errno));
		return "";
	}

	memcpy(addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	mac_addr = StringPrintf("" MACSTR, MAC2STR(addr));

	return mac_addr;
}

std::string trimWhitespace(const std::string& str) {
	size_t pos = 0;
	size_t len = str.size();
	for (pos; pos < str.size() && std::isspace(str[pos]); ++pos){}
	for (len; len - 1 > 0 && std::isspace(str[len-1]); --len){}
	return str.substr(pos, len);
}

std::string CreateHostapdConfig(
	const IfaceParams& iface_params,
	const ChannelParams& channelParams,
	const NetworkParams& nw_params,
	const std::string br_name,
	const std::string owe_transition_ifname)
{
	if (nw_params.ssid.size() >
		static_cast<uint32_t>(
		ParamSizeLimits::SSID_MAX_LEN_IN_BYTES)) {
		wpa_printf(
			MSG_ERROR, "Invalid SSID size: %zu", nw_params.ssid.size());
		return "";
	}

	// SSID string
	std::stringstream ss;
	ss << std::hex;
	ss << std::setfill('0');
	for (uint8_t b : nw_params.ssid) {
		ss << std::setw(2) << static_cast<unsigned int>(b);
	}
	const std::string ssid_as_string = ss.str();

	// Encryption config string
	uint32_t band = 0;
	band |= static_cast<uint32_t>(channelParams.bandMask);
	bool is_2Ghz_band_only = band == static_cast<uint32_t>(band2Ghz);
	bool is_6Ghz_band_only = band == static_cast<uint32_t>(band6Ghz);
	bool is_60Ghz_band_only = band == static_cast<uint32_t>(band60Ghz);
	std::string encryption_config_as_string;
	switch (nw_params.encryptionType) {
	case EncryptionType::NONE:
		// no security params
		break;
	case EncryptionType::WPA:
		if (!validatePassphrase(
			nw_params.passphrase.size(),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MIN_LEN_IN_BYTES),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MAX_LEN_IN_BYTES))) {
			return "";
		}
		encryption_config_as_string = StringPrintf(
			"wpa=3\n"
			"wpa_pairwise=%s\n"
			"wpa_passphrase=%s",
			is_60Ghz_band_only ? "GCMP" : "TKIP CCMP",
			nw_params.passphrase.c_str());
		break;
	case EncryptionType::WPA2:
		if (!validatePassphrase(
			nw_params.passphrase.size(),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MIN_LEN_IN_BYTES),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MAX_LEN_IN_BYTES))) {
			return "";
		}
		encryption_config_as_string = StringPrintf(
			"wpa=2\n"
			"rsn_pairwise=%s\n"
#ifdef ENABLE_HOSTAPD_CONFIG_80211W_MFP_OPTIONAL
			"ieee80211w=1\n"
#endif
			"wpa_passphrase=%s",
			is_60Ghz_band_only ? "GCMP" : "CCMP",
			nw_params.passphrase.c_str());
		break;
	case EncryptionType::WPA3_SAE_TRANSITION:
		if (!validatePassphrase(
			nw_params.passphrase.size(),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MIN_LEN_IN_BYTES),
			static_cast<uint32_t>(ParamSizeLimits::
				WPA2_PSK_PASSPHRASE_MAX_LEN_IN_BYTES))) {
			return "";
		}
		// WPA3 transition mode or SAE+WPA_PSK key management(AKM) is not allowed in 6GHz.
		// Auto-convert any such configurations to SAE.
		if ((band & band6Ghz) != 0) {
			wpa_printf(MSG_INFO, "WPA3_SAE_TRANSITION configured in 6GHz band."
				   "Enable only SAE in key_mgmt");
			encryption_config_as_string = StringPrintf(
				"wpa=2\n"
				"rsn_pairwise=CCMP\n"
				"wpa_key_mgmt=%s\n"
				"ieee80211w=2\n"
				"sae_require_mfp=2\n"
				"sae_pwe=%d\n"
				"sae_password=%s",
#ifdef CONFIG_IEEE80211BE
				iface_params.hwModeParams.enable80211BE ?
					"SAE SAE-EXT-KEY" : "SAE",
#else
					"SAE",
#endif
				is_6Ghz_band_only ? 1 : 2,
				nw_params.passphrase.c_str());
		} else {
			encryption_config_as_string = StringPrintf(
				"wpa=2\n"
				"rsn_pairwise=%s\n"
				"wpa_key_mgmt=%s\n"
				"ieee80211w=1\n"
				"sae_require_mfp=1\n"
				"wpa_passphrase=%s\n"
				"sae_password=%s",
				is_60Ghz_band_only ? "GCMP" : "CCMP",
#ifdef CONFIG_IEEE80211BE
				iface_params.hwModeParams.enable80211BE ?
					"WPA-PSK SAE SAE-EXT-KEY" : "WPA-PSK SAE",
#else
					"WPA-PSK SAE",
#endif
				nw_params.passphrase.c_str(),
				nw_params.passphrase.c_str());
                }
		break;
	case EncryptionType::WPA3_SAE:
		if (!validatePassphrase(nw_params.passphrase.size(), 1, -1)) {
			return "";
		}
		encryption_config_as_string = StringPrintf(
			"wpa=2\n"
			"rsn_pairwise=%s\n"
			"wpa_key_mgmt=%s\n"
			"ieee80211w=2\n"
			"sae_require_mfp=2\n"
			"sae_pwe=%d\n"
			"sae_password=%s",
			is_60Ghz_band_only ? "GCMP" : "CCMP",
#ifdef CONFIG_IEEE80211BE
			iface_params.hwModeParams.enable80211BE ? "SAE SAE-EXT-KEY" : "SAE",
#else
			"SAE",
#endif
			is_6Ghz_band_only ? 1 : 2,
			nw_params.passphrase.c_str());
		break;
	case EncryptionType::WPA3_OWE_TRANSITION:
		encryption_config_as_string = StringPrintf(
			"wpa=2\n"
			"rsn_pairwise=%s\n"
			"wpa_key_mgmt=OWE\n"
			"ieee80211w=2",
			is_60Ghz_band_only ? "GCMP" : "CCMP");
		break;
	case EncryptionType::WPA3_OWE:
		encryption_config_as_string = StringPrintf(
			"wpa=2\n"
			"rsn_pairwise=%s\n"
			"wpa_key_mgmt=OWE\n"
			"ieee80211w=2",
			is_60Ghz_band_only ? "GCMP" : "CCMP");
		break;
	default:
		wpa_printf(MSG_ERROR, "Unknown encryption type");
		return "";
	}

	std::string channel_config_as_string;
	bool isFirst = true;
	if (channelParams.enableAcs) {
		std::string freqList_as_string;
		for (const auto &range :
			channelParams.acsChannelFreqRangesMhz) {
			if (!isFirst) {
				freqList_as_string += ",";
			}
			isFirst = false;

			if (range.startMhz != range.endMhz) {
				freqList_as_string +=
					StringPrintf("%d-%d", range.startMhz, range.endMhz);
			} else {
				freqList_as_string += StringPrintf("%d", range.startMhz);
			}
		}
		channel_config_as_string = StringPrintf(
			"channel=0\n"
			"acs_exclude_dfs=%d\n"
			"freqlist=%s",
			channelParams.acsShouldExcludeDfs,
			freqList_as_string.c_str());
	} else {
		int op_class = getOpClassForChannel(
			channelParams.channel,
			band,
			iface_params.hwModeParams.enable80211N,
			iface_params.hwModeParams.enable80211AC);
		channel_config_as_string = StringPrintf(
			"channel=%d\n"
			"op_class=%d",
			channelParams.channel, op_class);
	}

	std::string hw_mode_as_string;
	std::string enable_edmg_as_string;
	std::string edmg_channel_as_string;
	bool is_60Ghz_used = false;

	if (((band & band60Ghz) != 0)) {
		hw_mode_as_string = "hw_mode=ad";
		if (iface_params.hwModeParams.enableEdmg) {
			enable_edmg_as_string = "enable_edmg=1";
			edmg_channel_as_string = StringPrintf(
				"edmg_channel=%d",
				channelParams.channel);
		}
		is_60Ghz_used = true;
	} else if ((band & band2Ghz) != 0) {
		if (((band & band5Ghz) != 0)
		    || ((band & band6Ghz) != 0)) {
			hw_mode_as_string = "hw_mode=any";
		} else {
			hw_mode_as_string = "hw_mode=g";
		}
	} else if (((band & band5Ghz) != 0)
		    || ((band & band6Ghz) != 0)) {
			hw_mode_as_string = "hw_mode=a";
	} else {
		wpa_printf(MSG_ERROR, "Invalid band");
		return "";
	}

	std::string he_params_as_string;
#ifdef CONFIG_IEEE80211AX
	if (iface_params.hwModeParams.enable80211AX && !is_60Ghz_used) {
		he_params_as_string = StringPrintf(
			"ieee80211ax=1\n"
			"he_su_beamformer=%d\n"
			"he_su_beamformee=%d\n"
			"he_mu_beamformer=%d\n"
			"he_twt_required=%d\n",
			iface_params.hwModeParams.enableHeSingleUserBeamformer ? 1 : 0,
			iface_params.hwModeParams.enableHeSingleUserBeamformee ? 1 : 0,
			iface_params.hwModeParams.enableHeMultiUserBeamformer ? 1 : 0,
			iface_params.hwModeParams.enableHeTargetWakeTime ? 1 : 0);
	} else {
		he_params_as_string = "ieee80211ax=0";
	}
#endif /* CONFIG_IEEE80211AX */
	std::string eht_params_as_string;
#ifdef CONFIG_IEEE80211BE
	if (iface_params.hwModeParams.enable80211BE && !is_60Ghz_used) {
		eht_params_as_string = "ieee80211be=1\n";
		if (areAidlServiceAndClientAtLeastVersion(2)) {
			std::string interface_mac_addr = getInterfaceMacAddress(
					iface_params.usesMlo ? br_name : iface_params.name);
			if (interface_mac_addr.empty()) {
				wpa_printf(MSG_ERROR,
				    "Unable to set interface mac address as bssid for 11BE SAP");
				return "";
			}
            if (iface_params.usesMlo) {
                eht_params_as_string += StringPrintf(
                    "mld_addr=%s\n"
                    "mld_ap=1",
                    interface_mac_addr.c_str());
            } else {
                eht_params_as_string += StringPrintf(
                    "bssid=%s\n"
                    "mld_ap=1",
                    interface_mac_addr.c_str());
            }
		}
		/* TODO set eht_su_beamformer, eht_su_beamformee, eht_mu_beamformer */
	} else {
		eht_params_as_string = "ieee80211be=0";
	}
#endif /* CONFIG_IEEE80211BE */

	std::string ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string;
	switch (iface_params.hwModeParams.maximumChannelBandwidth) {
	case ChannelBandwidth::BANDWIDTH_20:
		ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string = StringPrintf(
#ifdef CONFIG_IEEE80211BE
			"eht_oper_chwidth=0\n"
#endif /* CONFIG_IEEE80211BE */
#ifdef CONFIG_IEEE80211AX
			"he_oper_chwidth=0\n"
#endif
			"vht_oper_chwidth=0\n"
			"%s", (band & band6Ghz) ? "op_class=131" : "");
		break;
	case ChannelBandwidth::BANDWIDTH_40:
		ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string = StringPrintf(
			"ht_capab=[HT40+]\n"
#ifdef CONFIG_IEEE80211BE
			"eht_oper_chwidth=0\n"
#endif /* CONFIG_IEEE80211BE */
#ifdef CONFIG_IEEE80211AX
			"he_oper_chwidth=0\n"
#endif
			"vht_oper_chwidth=0\n"
			"%s", (band & band6Ghz) ? "op_class=132" : "");
		break;
	case ChannelBandwidth::BANDWIDTH_80:
		ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string = StringPrintf(
			"ht_capab=[HT40+]\n"
#ifdef CONFIG_IEEE80211BE
			"eht_oper_chwidth=%d\n"
#endif /* CONFIG_IEEE80211BE */
#ifdef CONFIG_IEEE80211AX
			"he_oper_chwidth=%d\n"
#endif
			"vht_oper_chwidth=%d\n"
			"%s",
#ifdef CONFIG_IEEE80211BE
			(iface_params.hwModeParams.enable80211BE && !is_60Ghz_used) ? 1 : 0,
#endif
#ifdef CONFIG_IEEE80211AX
			(iface_params.hwModeParams.enable80211AX && !is_60Ghz_used) ? 1 : 0,
#endif
			iface_params.hwModeParams.enable80211AC ? 1 : 0,
			(band & band6Ghz) ? "op_class=133" : "");
		break;
	case ChannelBandwidth::BANDWIDTH_160:
		ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string = StringPrintf(
			"ht_capab=[HT40+]\n"
#ifdef CONFIG_IEEE80211BE
			"eht_oper_chwidth=%d\n"
#endif /* CONFIG_IEEE80211BE */
#ifdef CONFIG_IEEE80211AX
			"he_oper_chwidth=%d\n"
#endif
			"vht_oper_chwidth=%d\n"
			"%s",
#ifdef CONFIG_IEEE80211BE
			(iface_params.hwModeParams.enable80211BE && !is_60Ghz_used) ? 2 : 0,
#endif
#ifdef CONFIG_IEEE80211AX
			(iface_params.hwModeParams.enable80211AX && !is_60Ghz_used) ? 2 : 0,
#endif
			iface_params.hwModeParams.enable80211AC ? 2 : 0,
			(band & band6Ghz) ? "op_class=134" : "");
		break;
	default:
		if (!is_2Ghz_band_only && !is_60Ghz_used) {
			if (iface_params.hwModeParams.enable80211AC) {
				ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string =
					"ht_capab=[HT40+]\n"
					"vht_oper_chwidth=1\n";
			}
			if (band & band6Ghz) {
#ifdef CONFIG_IEEE80211BE
				if (iface_params.hwModeParams.enable80211BE)
					ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string += "op_class=137\n";
				else
					ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string += "op_class=134\n";
#else /* CONFIG_IEEE80211BE */
				ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string += "op_class=134\n";
#endif /* CONFIG_IEEE80211BE */
			}
#ifdef CONFIG_IEEE80211AX
			if (iface_params.hwModeParams.enable80211AX) {
				ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string += "he_oper_chwidth=1\n";
			}
#endif
#ifdef CONFIG_IEEE80211BE
			if (iface_params.hwModeParams.enable80211BE) {
				ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string += "eht_oper_chwidth=1";
			}
#endif
		}
		break;
	}

#ifdef CONFIG_INTERWORKING
	std::string access_network_params_as_string;
	if (nw_params.isMetered) {
		access_network_params_as_string = StringPrintf(
			"interworking=1\n"
			"access_network_type=2\n"); // CHARGEABLE_PUBLIC_NETWORK
	} else {
	    access_network_params_as_string = StringPrintf(
			"interworking=0\n");
	}
#endif /* CONFIG_INTERWORKING */

	std::string bridge_as_string;
	if (!br_name.empty() && !iface_params.usesMlo) {
		bridge_as_string = StringPrintf("bridge=%s", br_name.c_str());
	}

	// vendor_elements string
	std::string vendor_elements_as_string;
	if (nw_params.vendorElements.size() > 0) {
		std::stringstream ss;
		ss << std::hex;
		ss << std::setfill('0');
		for (uint8_t b : nw_params.vendorElements) {
			ss << std::setw(2) << static_cast<unsigned int>(b);
		}
		vendor_elements_as_string = StringPrintf("vendor_elements=%s", ss.str().c_str());
	}

	std::string owe_transition_ifname_as_string;
	if (!owe_transition_ifname.empty()) {
		owe_transition_ifname_as_string = StringPrintf(
			"owe_transition_ifname=%s", owe_transition_ifname.c_str());
	}

	std::string ap_isolation_as_string = StringPrintf("ap_isolate=%s",
			isAidlServiceVersionAtLeast(3) && nw_params.isClientIsolationEnabled ?
			"1" : "0");

	// Overlay for LOHS (unmetered SoftAP)
	std::string overlay_path = resolveVendorConfPath(kUnmeteredIfaceOverlayPath);
	std::string overlay_string;
	if (!nw_params.isMetered
			&& 0 == access(overlay_path.c_str(), R_OK)
			&& !ReadFileToString(overlay_path, &overlay_string)) {
		logHostapdConfigError(errno, overlay_path);
		return "";
	}
	std::string sanitized_overlay = "";
	std::istringstream overlay_stream(overlay_string);
	for (std::string line; std::getline(overlay_stream, line);) {
		std::string overlay_key = trimWhitespace(line.substr(0, line.find("=")));
		if (kOverlayableKeys.contains(overlay_key)) {
			sanitized_overlay.append(line + "\n");
		}
	}

	return StringPrintf(
		"%s\n"
		"interface=%s\n"
		"driver=nl80211\n"
		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_%s\n"
		// ssid2 signals to hostapd that the value is not a literal value
		// for use as a SSID.  In this case, we're giving it a hex
		// std::string and hostapd needs to expect that.
		"ssid2=%s\n"
		"%s\n"
		"ieee80211n=%d\n"
		"ieee80211ac=%d\n"
		"%s\n"
		"%s\n"
		"%s\n"
		"%s\n"
		"ignore_broadcast_ssid=%d\n"
		"wowlan_triggers=any\n"
#ifdef CONFIG_INTERWORKING
		"%s\n"
#endif /* CONFIG_INTERWORKING */
		"%s\n"
		"%s\n"
		"%s\n"
		"%s\n"
		"%s\n"
		"%s\n"
		"%s\n",
		sanitized_overlay.c_str(),
		iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str(),
		iface_params.name.c_str(),
		ssid_as_string.c_str(),
		channel_config_as_string.c_str(),
		iface_params.hwModeParams.enable80211N ? 1 : 0,
		iface_params.hwModeParams.enable80211AC ? 1 : 0,
		he_params_as_string.c_str(),
		eht_params_as_string.c_str(),
		hw_mode_as_string.c_str(), ht_cap_vht_oper_he_oper_eht_oper_chwidth_as_string.c_str(),
		nw_params.isHidden ? 1 : 0,
#ifdef CONFIG_INTERWORKING
		access_network_params_as_string.c_str(),
#endif /* CONFIG_INTERWORKING */
		encryption_config_as_string.c_str(),
		bridge_as_string.c_str(),
		owe_transition_ifname_as_string.c_str(),
		enable_edmg_as_string.c_str(),
		edmg_channel_as_string.c_str(),
		vendor_elements_as_string.c_str(),
		ap_isolation_as_string.c_str());
}

Generation getGeneration(hostapd_hw_modes *current_mode)
{
	wpa_printf(MSG_DEBUG, "getGeneration hwmode=%d, ht_enabled=%d,"
		   " vht_enabled=%d, he_supported=%d",
		   current_mode->mode, current_mode->ht_capab != 0,
		   current_mode->vht_capab != 0, current_mode->he_capab->he_supported);
	switch (current_mode->mode) {
	case HOSTAPD_MODE_IEEE80211B:
		return Generation::WIFI_STANDARD_LEGACY;
	case HOSTAPD_MODE_IEEE80211G:
		return current_mode->ht_capab == 0 ?
				Generation::WIFI_STANDARD_LEGACY : Generation::WIFI_STANDARD_11N;
	case HOSTAPD_MODE_IEEE80211A:
		if (current_mode->he_capab->he_supported) {
			return Generation::WIFI_STANDARD_11AX;
		}
		return current_mode->vht_capab == 0 ?
		       Generation::WIFI_STANDARD_11N : Generation::WIFI_STANDARD_11AC;
	case HOSTAPD_MODE_IEEE80211AD:
		return Generation::WIFI_STANDARD_11AD;
	default:
		return Generation::WIFI_STANDARD_UNKNOWN;
	}
}

ChannelBandwidth getChannelBandwidth(struct hostapd_config *iconf)
{
	wpa_printf(MSG_DEBUG, "getChannelBandwidth %d, isHT=%d, isHT40=%d",
		   iconf->vht_oper_chwidth, iconf->ieee80211n,
		   iconf->secondary_channel);
	switch (iconf->vht_oper_chwidth) {
	case CONF_OPER_CHWIDTH_80MHZ:
		return ChannelBandwidth::BANDWIDTH_80;
	case CONF_OPER_CHWIDTH_80P80MHZ:
		return ChannelBandwidth::BANDWIDTH_80P80;
		break;
	case CONF_OPER_CHWIDTH_160MHZ:
		return ChannelBandwidth::BANDWIDTH_160;
		break;
	case CONF_OPER_CHWIDTH_USE_HT:
		if (iconf->ieee80211n) {
			return iconf->secondary_channel != 0 ?
				ChannelBandwidth::BANDWIDTH_40 : ChannelBandwidth::BANDWIDTH_20;
		}
		return ChannelBandwidth::BANDWIDTH_20_NOHT;
	case CONF_OPER_CHWIDTH_2160MHZ:
		return ChannelBandwidth::BANDWIDTH_2160;
	case CONF_OPER_CHWIDTH_4320MHZ:
		return ChannelBandwidth::BANDWIDTH_4320;
	case CONF_OPER_CHWIDTH_6480MHZ:
		return ChannelBandwidth::BANDWIDTH_6480;
	case CONF_OPER_CHWIDTH_8640MHZ:
		return ChannelBandwidth::BANDWIDTH_8640;
	default:
		return ChannelBandwidth::BANDWIDTH_INVALID;
	}
}

std::optional<struct sta_info*> getStaInfoByMacAddr(const struct hostapd_data* iface_hapd,
		const u8 *mac_addr) {
	if (iface_hapd == nullptr || mac_addr == nullptr){
		wpa_printf(MSG_ERROR, "nullptr passsed to getStaInfoByMacAddr!");
		return std::nullopt;
	}

	for (struct sta_info* sta_ptr = iface_hapd->sta_list; sta_ptr; sta_ptr = sta_ptr->next) {
		int res;
		res = memcmp(sta_ptr->addr, mac_addr, ETH_ALEN);
		if (res == 0) {
			return sta_ptr;
		}
	}
	return std::nullopt;
}

bool forceStaDisconnection(struct hostapd_data* hapd,
			   const std::vector<uint8_t>& client_address,
			   const uint16_t reason_code) {
	if (client_address.size() != ETH_ALEN) {
		return false;
	}

	auto sta_ptr_optional = getStaInfoByMacAddr(hapd, client_address.data());
	if (sta_ptr_optional.has_value()) {
		wpa_printf(MSG_INFO, "Force client:" MACSTR " disconnect with reason: %d",
				MAC2STR(client_address.data()), reason_code);
		ap_sta_disconnect(hapd, sta_ptr_optional.value(), sta_ptr_optional.value()->addr,
				reason_code);
		return true;
	}

	return false;
}

// hostapd core functions accept "C" style function pointers, so use global
// functions to pass to the hostapd core function and store the corresponding
// std::function methods to be invoked.
//
// NOTE: Using the pattern from the vendor HAL (wifi_legacy_hal.cpp).
//
// Callback to be invoked once setup is complete
std::function<void(struct hostapd_data*)> on_setup_complete_internal_callback;
void onAsyncSetupCompleteCb(void* ctx)
{
	struct hostapd_data* iface_hapd = (struct hostapd_data*)ctx;
	if (on_setup_complete_internal_callback) {
		on_setup_complete_internal_callback(iface_hapd);
		// Invalidate this callback since we don't want this firing
		// again in single AP mode.
		if (strlen(iface_hapd->conf->bridge) > 0) {
			on_setup_complete_internal_callback = nullptr;
		}
	}
}

// Callback to be invoked on hotspot client connection/disconnection
std::function<void(struct hostapd_data*, const u8 *mac_addr, int authorized,
		const u8 *p2p_dev_addr)> on_sta_authorized_internal_callback;
void onAsyncStaAuthorizedCb(void* ctx, const u8 *mac_addr, int authorized,
		const u8 *p2p_dev_addr, const u8 *ip)
{
	struct hostapd_data* iface_hapd = (struct hostapd_data*)ctx;
	if (on_sta_authorized_internal_callback) {
		on_sta_authorized_internal_callback(iface_hapd, mac_addr,
			authorized, p2p_dev_addr);
	}
}

std::function<void(struct hostapd_data*, int level,
			enum wpa_msg_type type, const char *txt,
			size_t len)> on_wpa_msg_internal_callback;

void onAsyncWpaEventCb(void *ctx, int level,
			enum wpa_msg_type type, const char *txt,
			size_t len)
{
	struct hostapd_data* iface_hapd = (struct hostapd_data*)ctx;
	if (on_wpa_msg_internal_callback) {
		on_wpa_msg_internal_callback(iface_hapd, level,
					type, txt, len);
	}
}

inline ndk::ScopedAStatus createStatus(HostapdStatusCode status_code) {
	return ndk::ScopedAStatus::fromServiceSpecificError(
		static_cast<int32_t>(status_code));
}

inline ndk::ScopedAStatus createStatusWithMsg(
	HostapdStatusCode status_code, std::string msg)
{
	return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
		static_cast<int32_t>(status_code), msg.c_str());
}

// Method called by death_notifier_ on client death.
void onDeath(void* cookie) {
	wpa_printf(MSG_ERROR, "Client died. Terminating...");
	eloop_terminate();
}

}  // namespace

namespace aidl {
namespace android {
namespace hardware {
namespace wifi {
namespace hostapd {

Hostapd::Hostapd(struct hapd_interfaces* interfaces)
	: interfaces_(interfaces)
{
	death_notifier_ = AIBinder_DeathRecipient_new(onDeath);
}

::ndk::ScopedAStatus Hostapd::addAccessPoint(
	const IfaceParams& iface_params, const NetworkParams& nw_params)
{
	return addAccessPointInternal(iface_params, nw_params);
}

::ndk::ScopedAStatus Hostapd::removeAccessPoint(const std::string& iface_name)
{
	return removeAccessPointInternal(iface_name);
}

::ndk::ScopedAStatus Hostapd::terminate()
{
	wpa_printf(MSG_INFO, "Terminating...");
	// Clear the callback to avoid IPCThreadState shutdown during the
	// callback event.
	callbacks_.clear();
	eloop_terminate();
	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Hostapd::registerCallback(
	const std::shared_ptr<IHostapdCallback>& callback)
{
	return registerCallbackInternal(callback);
}

::ndk::ScopedAStatus Hostapd::forceClientDisconnect(
	const std::string& iface_name, const std::vector<uint8_t>& client_address,
	Ieee80211ReasonCode reason_code)
{
	return forceClientDisconnectInternal(iface_name, client_address, reason_code);
}

::ndk::ScopedAStatus Hostapd::setDebugParams(DebugLevel level)
{
	return setDebugParamsInternal(level);
}

::ndk::ScopedAStatus Hostapd::removeLinkFromMultipleLinkBridgedApIface(
        const std::string& iface_name, const std::string& linkIdentity)
{
	return removeLinkFromMultipleLinkBridgedApIfaceInternal(iface_name, linkIdentity);
}

::ndk::ScopedAStatus Hostapd::addAccessPointInternal(
	const IfaceParams& iface_params,
	const NetworkParams& nw_params)
{
	int channelParamsSize = iface_params.channelParams.size();
	if (channelParamsSize == 1) {
		// Single AP
		wpa_printf(MSG_INFO, "AddSingleAccessPoint, iface=%s",
			iface_params.name.c_str());
		return addSingleAccessPoint(iface_params, iface_params.channelParams[0],
		    nw_params, "", "");
	} else if (channelParamsSize == 2) {
		// Concurrent APs
		wpa_printf(MSG_INFO, "AddDualAccessPoint, iface=%s",
			iface_params.name.c_str());
		return addConcurrentAccessPoints(iface_params, nw_params);
	}
	return createStatus(HostapdStatusCode::FAILURE_ARGS_INVALID);
}

std::vector<uint8_t>  generateRandomOweSsid()
{
	u8 random[8] = {0};
	os_get_random(random, 8);

	std::string ssid = StringPrintf("Owe-%s", random);
	wpa_printf(MSG_INFO, "Generated OWE SSID: %s", ssid.c_str());
	std::vector<uint8_t> vssid(ssid.begin(), ssid.end());

	return vssid;
}


// Both of bridged dual APs and MLO AP will be treated as concurrenct APs.
// -----------------------------------------
//                  | br_name     |  instance#1 | instance#2 |
// ___________________________________________________________
// bridged dual APs | ap_br_wlanX |   wlan X    |   wlanY    |
// ___________________________________________________________
// MLO AP           | wlanX       |     0       |     1      |
// ___________________________________________________________
// Both will be added in br_interfaces_[$br_name] and use instance's name
// to be iface_params_new.name to create single Access point.
::ndk::ScopedAStatus Hostapd::addConcurrentAccessPoints(
	const IfaceParams& iface_params, const NetworkParams& nw_params)
{
	int channelParamsListSize = iface_params.channelParams.size();
	// Get available interfaces in bridge
	std::vector<std::string> managed_instances;
	std::string br_name = StringPrintf("%s", iface_params.name.c_str());
	if (iface_params.usesMlo) {
		// MLO AP is using link id as instance.
		for (std::size_t i = 0; i < iface_params.instanceIdentities->size(); i++) {
			managed_instances.push_back(iface_params.instanceIdentities->at(i)->c_str());
		}
	} else {
		if (!GetInterfacesInBridge(br_name, &managed_instances)) {
			return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
					"Get interfaces in bridge failed.");
		}
	}
	// Either bridged AP or MLO AP should have two instances.
	if (managed_instances.size() < channelParamsListSize) {
		return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
				"Available interfaces less than requested bands");
	}

	if (iface_params.usesMlo
				&& nw_params.encryptionType == EncryptionType::WPA3_OWE_TRANSITION) {
		return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
				"Invalid encryptionType (OWE transition) for MLO SAP.");
	}
	// start BSS on specified bands
	for (std::size_t i = 0; i < channelParamsListSize; i ++) {
		IfaceParams iface_params_new = iface_params;
		NetworkParams nw_params_new = nw_params;
		std::string owe_transition_ifname = "";
		iface_params_new.name = managed_instances[i];
		if (nw_params.encryptionType == EncryptionType::WPA3_OWE_TRANSITION) {
			if (i == 0 && i+1 < channelParamsListSize) {
				owe_transition_ifname = managed_instances[i+1];
				nw_params_new.encryptionType = EncryptionType::NONE;
			} else {
				owe_transition_ifname = managed_instances[0];
				nw_params_new.isHidden = true;
				nw_params_new.ssid = generateRandomOweSsid();
			}
		}

		ndk::ScopedAStatus status = addSingleAccessPoint(
		    iface_params_new, iface_params.channelParams[i], nw_params_new,
		    br_name, owe_transition_ifname);
		if (!status.isOk()) {
			wpa_printf(MSG_ERROR, "Failed to addAccessPoint %s",
				   managed_instances[i].c_str());
			return status;
		}
	}

	if (iface_params.usesMlo) {
		std::size_t i = 0;
		std::size_t j = 0;
		for (i = 0; i < interfaces_->count; i++) {
			struct hostapd_iface *iface = interfaces_->iface[i];

			for (j = 0; j < iface->num_bss; j++) {
				struct hostapd_data *iface_hapd = iface->bss[j];
				if (hostapd_enable_iface(iface_hapd->iface) < 0) {
					wpa_printf(
					MSG_ERROR, "Enabling interface %s failed on %zu",
						iface_params.name.c_str(), i);
					return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
				}
			}
		}
    }
	// Save bridge interface info
	br_interfaces_[br_name] = managed_instances;
	return ndk::ScopedAStatus::ok();
}

struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *interfaces,
					const size_t link_id)
{
#ifdef CONFIG_IEEE80211BE
	size_t i, j;

	for (i = 0; i < interfaces->count; i++) {
		struct hostapd_iface *iface = interfaces->iface[i];

		for (j = 0; j < iface->num_bss; j++) {
			struct hostapd_data *hapd = iface->bss[j];

			if (link_id == hapd->mld_link_id)
				return hapd;
		}
	}
#endif
	return NULL;
}

// Both of bridged dual APs and MLO AP will be treated as concurrenct APs.
// -----------------------------------------
//                  | br_name                 |  iface_params.name
// _______________________________________________________________
// bridged dual APs | bridged interface name  |  interface name
// _______________________________________________________________
// MLO AP           | AP interface name       |  mld link id as instance name
// _______________________________________________________________
::ndk::ScopedAStatus Hostapd::addSingleAccessPoint(
	const IfaceParams& iface_params,
	const ChannelParams& channelParams,
	const NetworkParams& nw_params,
	const std::string br_name,
	const std::string owe_transition_ifname)
{
	if (iface_params.usesMlo) { // the mlo case, iface name is instance name which is mld_link_id
		if (hostapd_get_iface_by_link_id(interfaces_, (size_t) iface_params.name.c_str())) {
			wpa_printf(
				MSG_ERROR, "Instance link id %s already present",
				iface_params.name.c_str());
			return createStatus(HostapdStatusCode::FAILURE_IFACE_EXISTS);
		}
	}
	if (hostapd_get_iface(interfaces_,
			iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str())) {
		wpa_printf(
			MSG_ERROR, "Instance interface %s already present",
			iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str());
		return createStatus(HostapdStatusCode::FAILURE_IFACE_EXISTS);
	}
	const auto conf_params = CreateHostapdConfig(iface_params, channelParams, nw_params,
					br_name, owe_transition_ifname);
	if (conf_params.empty()) {
		wpa_printf(MSG_ERROR, "Failed to create config params");
		return createStatus(HostapdStatusCode::FAILURE_ARGS_INVALID);
	}
	const auto conf_file_path =
		WriteHostapdConfig(iface_params.name, conf_params, br_name, iface_params.usesMlo);
	if (conf_file_path.empty()) {
		wpa_printf(MSG_ERROR, "Failed to write config file");
		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
	}
	std::string add_iface_param_str = StringPrintf(
		"%s config=%s", iface_params.usesMlo ? br_name.c_str(): iface_params.name.c_str(),
		conf_file_path.c_str());
	std::vector<char> add_iface_param_vec(
		add_iface_param_str.begin(), add_iface_param_str.end() + 1);
	if (hostapd_add_iface(interfaces_, add_iface_param_vec.data()) < 0) {
		wpa_printf(
			MSG_ERROR, "Adding hostapd iface %s failed",
			add_iface_param_str.c_str());
		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
	}

	// find the iface and set up callback.
	struct hostapd_data* iface_hapd = iface_params.usesMlo ?
		hostapd_get_iface_by_link_id(interfaces_, (size_t) iface_params.name.c_str()) :
		hostapd_get_iface(interfaces_, iface_params.name.c_str());
	WPA_ASSERT(iface_hapd != nullptr && iface_hapd->iface != nullptr);
	if (iface_params.usesMlo) {
		memcmp(iface_hapd->conf->iface, br_name.c_str(), br_name.size());
	}

	// Callback discrepancy between bridged dual APs and MLO AP
	// Note: Only bridged dual APs will have "iface_hapd->conf->bridge" and
	// Only MLO AP will have "iface_hapd->mld_link_id"
	// Register the setup complete callbacks
	// -----------------------------------------
	//                    |   bridged dual APs     | bridged single link MLO | MLO SAP
	// _________________________________________________________________________________________
	// hapd->conf->bridge | bridged interface name |  bridged interface nam  | N/A
	// _________________________________________________________________________________________
	// hapd->conf->iface  | AP interface name      |  AP interface name      | AP interface name
	// _________________________________________________________________________________________
	// hapd->mld_link_id  | 0 (default value)      |      link id (0)        | link id (0 or 1)
	// _________________________________________________________________________________________
	// hapd->mld_ap       |         0              |            1            |     1
	on_setup_complete_internal_callback =
		[this](struct hostapd_data* iface_hapd) {
			wpa_printf(
			MSG_INFO, "AP interface setup completed - state %s",
			hostapd_state_text(iface_hapd->iface->state));
			if (iface_hapd->iface->state == HAPD_IFACE_DISABLED) {
				// Invoke the failure callback on all registered
				// clients.
				std::string instanceName = iface_hapd->conf->iface;
#ifdef CONFIG_IEEE80211BE
				if (iface_hapd->conf->mld_ap
						&& strlen(iface_hapd->conf->bridge) == 0) {
					instanceName = std::to_string(iface_hapd->mld_link_id);
				}
#endif
				for (const auto& callback : callbacks_) {
					auto status = callback->onFailure(
						strlen(iface_hapd->conf->bridge) > 0 ?
						iface_hapd->conf->bridge : iface_hapd->conf->iface,
							    instanceName);
					if (!status.isOk()) {
						wpa_printf(MSG_ERROR, "Failed to invoke onFailure");
					}
				}
			}
		};

	// Register for new client connect/disconnect indication.
	on_sta_authorized_internal_callback =
		[this](struct hostapd_data* iface_hapd, const u8 *mac_addr,
			int authorized, const u8 *p2p_dev_addr) {
		wpa_printf(MSG_DEBUG, "notify client " MACSTR " %s",
				MAC2STR(mac_addr),
				(authorized) ? "Connected" : "Disconnected");
		ClientInfo info;
		info.ifaceName = strlen(iface_hapd->conf->bridge) > 0 ?
			iface_hapd->conf->bridge : iface_hapd->conf->iface;
		std::string instanceName = iface_hapd->conf->iface;
#ifdef CONFIG_IEEE80211BE
		if (iface_hapd->conf->mld_ap
				&& strlen(iface_hapd->conf->bridge) == 0) {
			instanceName = std::to_string(iface_hapd->mld_link_id);
		}
#endif
		info.apIfaceInstance = instanceName;
		info.clientAddress.assign(mac_addr, mac_addr + ETH_ALEN);
		info.isConnected = authorized;
		if(isAidlServiceVersionAtLeast(3) && !authorized) {
			u16 disconnect_reason_code = WLAN_REASON_UNSPECIFIED;
			auto sta_ptr_optional = getStaInfoByMacAddr(iface_hapd, mac_addr);
			if (sta_ptr_optional.has_value()){
				disconnect_reason_code = sta_ptr_optional.value()->deauth_reason;
			}
			info.disconnectReasonCode =
					static_cast<common::DeauthenticationReasonCode>(disconnect_reason_code);
		}
		for (const auto &callback : callbacks_) {
			auto status = callback->onConnectedClientsChanged(info);
			if (!status.isOk()) {
				wpa_printf(MSG_ERROR, "Failed to invoke onConnectedClientsChanged");
			}
		}
		};

	// Register for wpa_event which used to get channel switch event
	on_wpa_msg_internal_callback =
		[this](struct hostapd_data* iface_hapd, int level,
			enum wpa_msg_type type, const char *txt,
			size_t len) {
		wpa_printf(MSG_DEBUG, "Receive wpa msg : %s", txt);
		if (os_strncmp(txt, AP_EVENT_ENABLED,
					strlen(AP_EVENT_ENABLED)) == 0 ||
			os_strncmp(txt, WPA_EVENT_CHANNEL_SWITCH,
					strlen(WPA_EVENT_CHANNEL_SWITCH)) == 0) {
			std::string instanceName = iface_hapd->conf->iface;
#ifdef CONFIG_IEEE80211BE
			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
				instanceName = std::to_string(iface_hapd->mld_link_id);
			}
#endif
			ApInfo info;
			info.ifaceName = strlen(iface_hapd->conf->bridge) > 0 ?
				iface_hapd->conf->bridge : iface_hapd->conf->iface,
			info.apIfaceInstance = instanceName;
			info.freqMhz = iface_hapd->iface->freq;
			info.channelBandwidth = getChannelBandwidth(iface_hapd->iconf);
			info.generation = getGeneration(iface_hapd->iface->current_mode);
			info.apIfaceInstanceMacAddress.assign(iface_hapd->own_addr,
				iface_hapd->own_addr + ETH_ALEN);
			for (const auto &callback : callbacks_) {
				auto status = callback->onApInstanceInfoChanged(info);
				if (!status.isOk()) {
					wpa_printf(MSG_ERROR,
						   "Failed to invoke onApInstanceInfoChanged");
				}
			}
		} else if (os_strncmp(txt, AP_EVENT_DISABLED, strlen(AP_EVENT_DISABLED)) == 0
                           || os_strncmp(txt, INTERFACE_DISABLED, strlen(INTERFACE_DISABLED)) == 0)
		{
			std::string instanceName = iface_hapd->conf->iface;
#ifdef CONFIG_IEEE80211BE
			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
				instanceName = std::to_string(iface_hapd->mld_link_id);
			}
#endif
			// Invoke the failure callback on all registered clients.
			for (const auto& callback : callbacks_) {
				auto status =
					callback->onFailure(strlen(iface_hapd->conf->bridge) > 0 ?
					iface_hapd->conf->bridge : iface_hapd->conf->iface,
						instanceName);
				if (!status.isOk()) {
					wpa_printf(MSG_ERROR, "Failed to invoke onFailure");
				}
			}
		}
	};

	// Setup callback
	iface_hapd->setup_complete_cb = onAsyncSetupCompleteCb;
	iface_hapd->setup_complete_cb_ctx = iface_hapd;
	iface_hapd->sta_authorized_cb = onAsyncStaAuthorizedCb;
	iface_hapd->sta_authorized_cb_ctx = iface_hapd;
	wpa_msg_register_aidl_cb(onAsyncWpaEventCb);

	// Multi-link MLO should enable iface after both links have been set.
	if (!iface_params.usesMlo && hostapd_enable_iface(iface_hapd->iface) < 0) {
		wpa_printf(
			MSG_ERROR, "Enabling interface %s failed",
			iface_params.name.c_str());
		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
	}
	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Hostapd::removeAccessPointInternal(const std::string& iface_name)
{
	// interfaces to be removed
	std::vector<std::string> interfaces;
	bool is_error = false;

	const auto it = br_interfaces_.find(iface_name);
	if (it != br_interfaces_.end()) {
		// In case bridge, remove managed interfaces
		interfaces = it->second;
		br_interfaces_.erase(iface_name);
	} else {
		// else remove current interface
		interfaces.push_back(iface_name);
	}

	for (auto& iface : interfaces) {
		std::vector<char> remove_iface_param_vec(
		    iface.begin(), iface.end() + 1);
		if (hostapd_remove_iface(interfaces_, remove_iface_param_vec.data()) <  0) {
			wpa_printf(MSG_INFO, "Remove interface %s failed", iface.c_str());
			is_error = true;
		}
	}
	if (is_error) {
		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
	}
	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Hostapd::registerCallbackInternal(
	const std::shared_ptr<IHostapdCallback>& callback)
{
	binder_status_t status = AIBinder_linkToDeath(callback->asBinder().get(),
			death_notifier_, this /* cookie */);
	if (status != STATUS_OK) {
		wpa_printf(
			MSG_ERROR,
			"Error registering for death notification for "
			"hostapd callback object");
		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
	}
	callbacks_.push_back(callback);
	if (aidl_service_version == 0) {
	    aidl_service_version = Hostapd::version;
	    wpa_printf(MSG_INFO, "AIDL service version: %d", aidl_service_version);
	}
	if (aidl_client_version == 0) {
	    callback->getInterfaceVersion(&aidl_client_version);
	    wpa_printf(MSG_INFO, "AIDL client version: %d", aidl_client_version);
	}
	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Hostapd::forceClientDisconnectInternal(const std::string& iface_name,
	const std::vector<uint8_t>& client_address, Ieee80211ReasonCode reason_code)
{
	struct hostapd_data *hapd = hostapd_get_iface(interfaces_, iface_name.c_str());
	bool result;
	if (!hapd) {
		for (auto const& iface : br_interfaces_) {
			if (iface.first == iface_name) {
				for (auto const& instance : iface.second) {
					hapd = hostapd_get_iface(interfaces_, instance.c_str());
					if (hapd) {
						result = forceStaDisconnection(hapd, client_address,
								(uint16_t) reason_code);
						if (result) break;
					}
				}
			}
		}
	} else {
		result = forceStaDisconnection(hapd, client_address, (uint16_t) reason_code);
	}
	if (!hapd) {
		wpa_printf(MSG_ERROR, "Interface %s doesn't exist", iface_name.c_str());
		return createStatus(HostapdStatusCode::FAILURE_IFACE_UNKNOWN);
	}
	if (result) {
		return ndk::ScopedAStatus::ok();
	}
	return createStatus(HostapdStatusCode::FAILURE_CLIENT_UNKNOWN);
}

::ndk::ScopedAStatus Hostapd::setDebugParamsInternal(DebugLevel level)
{
	wpa_debug_level = static_cast<uint32_t>(level);
	return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus Hostapd::removeLinkFromMultipleLinkBridgedApIfaceInternal(
const std::string& iface_name, const std::string& linkIdentity)
{
	if (!hostapd_get_iface(interfaces_, iface_name.c_str())) {
		wpa_printf(MSG_ERROR, "Interface %s doesn't exist", iface_name.c_str());
		return createStatus(HostapdStatusCode::FAILURE_IFACE_UNKNOWN);
	}
	struct hostapd_data* iface_hapd =
		hostapd_get_iface_by_link_id(interfaces_, (size_t) linkIdentity.c_str());
	if (iface_hapd) {
		if (0 == hostapd_link_remove(iface_hapd, 1)) {
			return ndk::ScopedAStatus::ok();
		}
	}
	return createStatus(HostapdStatusCode::FAILURE_ARGS_INVALID);
}

}  // namespace hostapd
}  // namespace wifi
}  // namespace hardware
}  // namespace android
}  // namespace aidl
