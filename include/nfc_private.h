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

#ifndef __NFC_PRIVATE_H__
#define __NFC_PRIVATE_H__
#include <net_nfc.h>
#include <net_nfc_typedef_private.h>

#include "nfc.h"


typedef enum {
	_NFC_CALLBACK_TYPE_RESULT=0,
	_NFC_CALLBACK_TYPE_DATA=1,
} _nfc_callback_type;


typedef struct {
	bool initialized;

	nfc_tag_discovered_cb 			on_tag_discovered_cb;
	void *						on_tag_discovered_user_data;
	nfc_ndef_discovered_cb 		on_ndef_discovered_cb;
	void * 						on_ndef_discovered_user_data;
	net_nfc_target_info_s 			*current_tag;

	//net_nfc_target_handle_s 		current_target;
	net_nfc_target_handle_h		current_target;

	nfc_p2p_target_discovered_cb	on_p2p_discovered_cb;
	void *						on_p2p_discovered_user_data;

	nfc_se_event_cb				on_se_event_cb;
	void *						on_se_event_user_data;

	nfc_p2p_send_completed_cb 	on_p2p_send_completed_cb;
	void *						on_p2p_send_completed_user_data;

	nfc_p2p_data_recived_cb		on_p2p_recv_cb;
	void * 						on_p2p_recv_user_data;

	nfc_p2p_connection_handover_completed_cb 		on_p2p_connection_handover_completed_cb;
	void *										on_p2p_connection_handover_completed_user_data;

	nfc_initialize_completed_cb	 	on_initialize_completed_cb;

	//nfc_se_transaction_event_cb		on_se_transaction_event_cb;
	//void *						on_se_transaction_event_user_data;

	nfc_se_transaction_event_cb		on_eSE_transaction_event_cb;
	void *						on_eSE_transaction_event_user_data;

	nfc_se_transaction_event_cb		on_UICC_transaction_event_cb;
	void *						on_UICC_transaction_event_user_data;

	net_nfc_se_type_e						on_se_type;

	nfc_activation_changed_cb	on_activation_changed_cb;
	void *						on_activation_changed_user_data;

	nfc_activation_completed_cb	on_activation_completed_cb;
	void *						on_activation_completed_user_data;
	bool                        on_activation_doing;

} _nfc_context_s;

typedef struct {
	void * callback;
	void * user_data;
	int callback_type;
} _async_callback_data;

#endif // __NFC_PRIVATE_H__
