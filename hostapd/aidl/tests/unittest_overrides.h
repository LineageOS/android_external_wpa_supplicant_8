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

#pragma once

#include <android-base/logging.h>

static ::android::base::LogSeverity wpa_to_android_level(int level)
{
	if (level == MSG_ERROR)
		return ::android::base::ERROR;
	if (level == MSG_WARNING)
		return ::android::base::WARNING;
	if (level == MSG_INFO)
		return ::android::base::INFO;
	return ::android::base::DEBUG;
}

// don't use hostapd's wpa_printf for unit testing. It won't compile otherwise
void wpa_printf(int level, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	LOG(wpa_to_android_level(level)) << ::android::base::StringPrintf(fmt, ap);
	va_end(ap);
}

static int hostapd_unittest_stat_ret = 0;
int stat(const char* pathname, struct stat* stabuf) {
	if (hostapd_unittest_stat_ret != 0) {
		errno = EINVAL;
	}
	return hostapd_unittest_stat_ret;
}

static int hostapd_unittest_accessRet = 0;
int access(const char* pathname, int mode) {
	if (hostapd_unittest_accessRet != 0) {
		errno = EINVAL;
	}
	return hostapd_unittest_accessRet;
}


// You can inspect the string here to see what we tried to write to a file
static std::string hostapd_unittest_config_output = "";
static bool hostapd_unittest_WriteStringToFileRet = true;
bool WriteStringToFile(const std::string& content, const std::string& path, mode_t mode,
		uid_t owner, gid_t group) {
	if (!hostapd_unittest_WriteStringToFileRet) {
		errno = EINVAL;
	} else {
		hostapd_unittest_config_output = content;
	}
	return hostapd_unittest_WriteStringToFileRet;
}

// You can simulate a file having content with this string
static std::string hostapd_unittest_overlay_content = "";
static bool hostapd_unittest_ReadFileToStringRet = true;
bool ReadFileToString(const std::string& path, std::string* content) {
	*content = hostapd_unittest_overlay_content;
	LOG(INFO) << "*content = " << *content;
	return hostapd_unittest_ReadFileToStringRet;
}

/**
 * We can simulate I/O operations failing by re-defining the calls.
 *
 * By default, all files are empty, and all calls succeed.
 */
void resetOverrides() {
	hostapd_unittest_stat_ret = 0;
	hostapd_unittest_WriteStringToFileRet = true;
	hostapd_unittest_config_output = "";
	hostapd_unittest_accessRet = 0;
	hostapd_unittest_overlay_content = "";
	hostapd_unittest_ReadFileToStringRet = true;
}
