/*
* Copyright (c) 2012, 2013 Samsung Electronics Co., Ltd.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __NFC_LOG_H__
#define __NFC_LOG_H__

#include "nfc.h"
#include "nfc_internal.h"

#define COLOR_RED		"\033[0;31m"
#define COLOR_GREEN		"\033[0;32m"
#define COLOR_BROWN		"\033[0;33m"
#define COLOR_BLUE		"\033[0;34m"
#define COLOR_PURPLE		"\033[0;35m"
#define COLOR_CYAN		"\033[0;36m"
#define COLOR_LIGHTBLUE		"\033[0;37m"
#define COLOR_END		"\033[0;m"


#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "NFC_CAPI"

#define LOG_DEBUG(fmt, ...) \
	do { \
		LOGD(COLOR_BROWN" " fmt COLOR_END, ##__VA_ARGS__); \
	} while (0)
#define LOG_ERR(fmt, ...) \
	do { \
		LOGE(COLOR_RED" " fmt COLOR_END, ##__VA_ARGS__); \
	} while (0)
#define LOG_BEGIN() \
	do { \
		LOGD(COLOR_BLUE"BEGIN >>>>"COLOR_END); \
	} while (0)
#define LOG_END() \
	do { \
		LOGD(COLOR_BLUE"END <<<<"COLOR_END); \
	} while (0)

#define NFC_LOGD(format, arg...) LOG(LOG_DEBUG, LOG_TAG, format, ##arg)

#define DEBUG_NFC_CAPI_MSG(format, args...) \
	do {\
		NFC_LOGD(COLOR_GREEN format COLOR_END , ##args);\
	} while(0)

typedef struct
{
	bool				initialized;
	bool				on_activation_doing;

	net_nfc_target_info_h		current_tag;

	//net_nfc_target_handle_s	current_target;
	net_nfc_target_handle_h		current_target;

	nfc_tag_discovered_cb		on_tag_discovered_cb;
	void				*on_tag_discovered_user_data;

	nfc_ndef_discovered_cb		on_ndef_discovered_cb;
	void				*on_ndef_discovered_user_data;

	nfc_p2p_target_discovered_cb	on_p2p_target_discovered_cb;
	void				*on_p2p_target_discovered_user_data;

	nfc_p2p_data_received_cb		on_p2p_recv_cb;
	void				*on_p2p_recv_user_data;

	nfc_se_event_cb			on_se_event_cb;
	void				*on_se_event_user_data;

	nfc_se_transaction_event_cb	on_se_transaction_event_cb;
	void				*on_se_transaction_event_user_data;

	nfc_connection_handover_event_cb on_handover_event_cb;
	void				*on_handover_event_user_data;
}
_nfc_context_s;

#endif // __NFC_LOG_H__
