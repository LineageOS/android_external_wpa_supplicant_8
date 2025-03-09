/*
 * WPA Supplicant - Utilities for the mainline supplicant
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_UTILS_H
#define MAINLINE_SUPPLICANT_UTILS_H

#include <aidl/android/system/wifi/mainline_supplicant/SupplicantStatusCode.h>

inline ndk::ScopedAStatus createStatus(SupplicantStatusCode statusCode) {
	return ndk::ScopedAStatus::fromServiceSpecificError(
		static_cast<int32_t>(statusCode));
}

inline ndk::ScopedAStatus createStatusWithMsg(
	    SupplicantStatusCode statusCode, std::string msg) {
	return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
		static_cast<int32_t>(statusCode), msg.c_str());
}

#endif // MAINLINE_SUPPLICANT_UTILS_H
