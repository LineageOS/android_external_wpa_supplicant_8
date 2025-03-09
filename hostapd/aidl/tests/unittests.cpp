/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>

#include <gtest/gtest.h>
#include "../hostapd.cpp"

namespace aidl::android::hardware::wifi::hostapd {
unsigned char kTestSsid[] = {0x31, 0x32, 0x33, 0x61, 0x62, 0x63, 0x64};

class HostapdConfigTest : public testing::Test {
	protected:
	void SetUp() override {
		resetOverrides();

		mIface_params = {
			.name = "wlan42",
			.hwModeParams = {
				.enable80211N = true,
				.enable80211AC = false,
				.enable80211AX = false,
				.enable6GhzBand = false,
				.enableHeSingleUserBeamformer = false,
				.enableHeSingleUserBeamformee = false,
				.enableHeMultiUserBeamformer = false,
				.enableHeTargetWakeTime = false,
				.enableEdmg = false,
				.enable80211BE = false,
				.maximumChannelBandwidth = ChannelBandwidth::BANDWIDTH_AUTO,
			},
			.channelParams = {},  // not used in config creation
			.vendorData = {},  // not used in config creation
			.instanceIdentities = {},  // not used in config creation
			.usesMlo = false,
		};
		mChannel_params = {
			.bandMask = BandMask::BAND_2_GHZ,
			.acsChannelFreqRangesMhz = {},
			.enableAcs = false,
			.acsShouldExcludeDfs = false,
			.channel = 6,
		};
		mNetwork_params = {
			.ssid =  std::vector<uint8_t>(kTestSsid, kTestSsid + sizeof(kTestSsid)),
			.isHidden = false,
			.encryptionType = EncryptionType::WPA2,
			.passphrase = "verysecurewowe",
			.isMetered = true,  // default for tethered softap, change to false for lohs.
			.vendorElements = {},
		};
	}

	std::string mWlan42_tethered_config = "\ninterface=wlan42\n"
		"driver=nl80211\n"
		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
		"ssid2=31323361626364\n"
		"channel=6\n"
		"op_class=83\n"
		"ieee80211n=1\n"
		"ieee80211ac=0\n\n\n"
		"hw_mode=g\n\n"
		"ignore_broadcast_ssid=0\n"
		"wowlan_triggers=any\n"
		"interworking=1\n"
		"access_network_type=2\n\n"
		"wpa=2\n"
		"rsn_pairwise=CCMP\n"
		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
		"ap_isolate=0\n";

	std::string mWlan42_lohs_config = "dtim_period=2   \n"
		"   ap_max_inactivity=300\n"
		"skip_inactivity_poll = 1\n\n"
		"interface=wlan42\n"
		"driver=nl80211\n"
		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
		"ssid2=31323361626364\n"
		"channel=6\n"
		"op_class=83\n"
		"ieee80211n=1\n"
		"ieee80211ac=0\n\n\n"
		"hw_mode=g\n\n"
		"ignore_broadcast_ssid=0\n"
		"wowlan_triggers=any\n"
		"interworking=0\n\n"
		"wpa=2\n"
		"rsn_pairwise=CCMP\n"
		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
		"ap_isolate=0\n";

	std::string mWlan42_lohs_config_no_overlay = "\ninterface=wlan42\n"
		"driver=nl80211\n"
		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
		"ssid2=31323361626364\n"
		"channel=6\n"
		"op_class=83\n"
		"ieee80211n=1\n"
		"ieee80211ac=0\n\n\n"
		"hw_mode=g\n\n"
		"ignore_broadcast_ssid=0\n"
		"wowlan_triggers=any\n"
		"interworking=0\n\n"
		"wpa=2\n"
		"rsn_pairwise=CCMP\n"
		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
		"ap_isolate=0\n";

	IfaceParams mIface_params;
	ChannelParams mChannel_params;
	NetworkParams mNetwork_params;
	std::string mBr_name = "";
	std::string mOwe_transition_ifname = "";
};

/**
 * Null hostapd_data* and null mac address (u8*)
 * There's an || check on these that should return nullopt
 */
TEST(getStaInfoByMacAddrTest, NullArguments) {
	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(nullptr, nullptr));
}


/**
 * We pass valid arguments to get past the nullptr check, but hostapd_data->sta_list is nullptr.
 * Don't loop through the sta_info* list, just return nullopt.
 */
TEST(getStaInfoByMacAddrTest, NullStaList) {
	struct hostapd_data iface_hapd = {};
	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(&iface_hapd, mac_addr));
}

/**
 * Mac doesn't match, and we hit the end of the sta_info list.
 * Don't run over the end of the list and return nullopt.
 */
TEST(getStaInfoByMacAddrTest, NoMatchingMac) {
	struct hostapd_data iface_hapd = {};
	struct sta_info sta0 = {};
	struct sta_info sta1 = {};
	struct sta_info sta2 = {};
	iface_hapd.sta_list = &sta0;
	sta0.next = &sta1;
	sta1.next = &sta2;
	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(&iface_hapd, mac_addr));
}

/**
 * There is a matching address and we return it.
 */
TEST(getStaInfoByMacAddrTest, MatchingMac) {
	struct hostapd_data iface_hapd = {};
	struct sta_info sta0 = {};
	struct sta_info sta1 = {};
	struct sta_info sta2 = {};
	iface_hapd.sta_list = &sta0;
	sta0.next = &sta1;
	sta1.next = &sta2;
	u8 sta0_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0C};  // off by 1 bit
	std::memcpy(sta0.addr, sta0_addr, ETH_ALEN);
	u8 sta1_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
	std::memcpy(sta1.addr, sta1_addr, ETH_ALEN);
	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
	auto sta_ptr_optional = getStaInfoByMacAddr(&iface_hapd, mac_addr);
	EXPECT_TRUE(sta_ptr_optional.has_value());
	EXPECT_EQ(0, std::memcmp(sta_ptr_optional.value()->addr, sta1_addr, ETH_ALEN));
}


TEST_F(HostapdConfigTest, tetheredApConfig) {
	// instance name, config string, br_name, usesMlo
	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
	std::string expected_path = "/data/vendor/wifi/hostapd/hostapd_wlan42.conf";
	EXPECT_EQ(expected_path, config_path);
	EXPECT_EQ(mWlan42_tethered_config, hostapd_unittest_config_output);
}

TEST_F(HostapdConfigTest, tetheredApConfigStatFails) {
	hostapd_unittest_WriteStringToFileRet = false;
	hostapd_unittest_stat_ret = -1;
	// instance name, config string, br_name, usesMlo
	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
	std::string expected_path = "";
	EXPECT_EQ(expected_path, config_path);
}

TEST_F(HostapdConfigTest, tetheredApConfigWriteFails) {
	hostapd_unittest_WriteStringToFileRet = false;
	// instance name, config string, br_name, usesMlo
	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
	std::string expected_path = "";
	EXPECT_EQ(expected_path, config_path);
}

TEST_F(HostapdConfigTest, tetheredAp) {
	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
			mBr_name, mOwe_transition_ifname);
	EXPECT_EQ(mWlan42_tethered_config, config_string);
}

TEST_F(HostapdConfigTest, lohsAp) {
	mNetwork_params.isMetered = false;
	hostapd_unittest_overlay_content =
			"invalid_key=this_should_not_be_here\n"
			"dtim_period=2   \n"
			"   ap_max_inactivity=300\n"
			"another_invalid_key_dtim_period=-10000\n"
			"skip_inactivity_poll = 1";
	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
			mBr_name, mOwe_transition_ifname);
	EXPECT_EQ(mWlan42_lohs_config, config_string);
}

TEST_F(HostapdConfigTest, lohsApAccessFails) {
	mNetwork_params.isMetered = false;
	hostapd_unittest_accessRet = -1;
	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
			mBr_name, mOwe_transition_ifname);
	EXPECT_EQ(mWlan42_lohs_config_no_overlay, config_string);
}

TEST_F(HostapdConfigTest, lohsApReadFails) {
	mNetwork_params.isMetered = false;
	hostapd_unittest_ReadFileToStringRet = false;
	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
			mBr_name, mOwe_transition_ifname);
	EXPECT_EQ("", config_string);
}

}  // namespace aidl::android::hardware::wifi::hostapd
