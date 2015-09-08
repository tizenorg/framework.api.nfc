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

#include "nfc_common.h"

int nfc_se_open_secure_element_internal(
	nfc_se_type_e se_type,
	nfc_se_h *handle)
{
	net_nfc_error_e result;
	net_nfc_se_type_e type;
	net_nfc_target_handle_h temp = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(handle == NULL);

	switch (se_type)
	{
	case NFC_SE_TYPE_ESE :
		type = NET_NFC_SE_TYPE_ESE;
		break;

	case NFC_SE_TYPE_UICC :
		type = NET_NFC_SE_TYPE_UICC;
		break;

	default:
		return NFC_ERROR_INVALID_PARAMETER;
		break;
	}

	result = net_nfc_client_se_open_internal_secure_element_sync(
		type,
		&temp);
	if (result == NET_NFC_OK) {
		*handle = (nfc_se_h)temp;
	}

	return nfc_common_convert_error_code(__func__, result);
}


int nfc_se_send_apdu_internal(nfc_se_h handle,
	unsigned char *cmd,
	unsigned int cmd_len,
	unsigned char **resp,
	unsigned int *resp_len)
{
	net_nfc_error_e result;
	data_h command = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(handle == NULL);
	CHECK_INVALID(cmd == NULL);
	CHECK_INVALID(cmd_len == 0);
	CHECK_INVALID(resp == NULL);
	CHECK_INVALID(resp_len == NULL);

	if (cmd_len == 3 && cmd[0] == 'A' && cmd[1] == 'T' && cmd[2] == 'R') {
		LOG_DEBUG("cheat... invoke get atr");
		return nfc_se_get_atr_internal(handle, resp, resp_len);
	}

	*resp = NULL;
	*resp_len = 0;

	result = net_nfc_create_data(&command, cmd, cmd_len);
	if (result == NET_NFC_OK) {
		data_h response = NULL;

		result = net_nfc_client_se_send_apdu_sync(
			(net_nfc_target_handle_h)handle,
			command,
			&response);
		if (result == NET_NFC_OK && response != NULL) {
			uint8_t *buffer;
			uint32_t length;

			buffer = net_nfc_get_data_buffer(response);
			length = net_nfc_get_data_length(response);

			if (buffer != NULL && length > 0) {
				*resp = calloc(1, length);
				if (*resp != NULL) {
					memcpy(*resp, buffer, length);
					*resp_len = length;
				} else {
					result = NET_NFC_ALLOC_FAIL;
				}
			} else {
				result = NET_NFC_NO_DATA_FOUND;
			}

			net_nfc_free_data(response);
		}

		net_nfc_free_data(command);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", result);
	}

	return nfc_common_convert_error_code(__func__, result);
}


int nfc_se_get_atr_internal(nfc_se_h handle, unsigned char **atr, unsigned int *atr_len)
{
	net_nfc_error_e result;
	data_h response = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(handle == NULL);
	CHECK_INVALID(atr == NULL);
	CHECK_INVALID(atr_len == NULL);

	*atr = NULL;
	*atr_len = 0;

	result = net_nfc_client_se_get_atr_sync(
		(net_nfc_target_handle_h)handle,
		&response);
	if (result == NET_NFC_OK && response != NULL) {
		uint8_t *buffer;
		uint32_t length;

		buffer = net_nfc_get_data_buffer(response);
		length = net_nfc_get_data_length(response);

		if (buffer != NULL && length > 0) {
			*atr = calloc(1, length);
			if (*atr != NULL) {
				memcpy(*atr, buffer, length);
				*atr_len = length;
			} else {
				result = NET_NFC_ALLOC_FAIL;
			}
		} else {
			result = NET_NFC_NO_DATA_FOUND;
		}

		net_nfc_free_data(response);
	}

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_close_secure_element_internal(nfc_se_h handle)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_close_internal_secure_element_sync(
		(net_nfc_target_handle_h)handle);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_enable_card_emulation()
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();

	result = net_nfc_set_card_emulation_mode_sync(NET_NFC_CARD_EMELATION_ENABLE);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_disable_card_emulation()
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();

	result = net_nfc_set_card_emulation_mode_sync(NET_NFC_CARD_EMULATION_DISABLE);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_get_card_emulation_mode(nfc_se_card_emulation_mode_type_e *mode)
{
	net_nfc_error_e result;
	net_nfc_card_emulation_mode_t se_mode;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(mode == NULL);

	result = net_nfc_get_card_emulation_mode_sync(&se_mode);

	switch(se_mode)
	{
	case NET_NFC_CARD_EMELATION_ENABLE :
		*mode = NFC_SE_CARD_EMULATION_MODE_ON;
		break;

	case NET_NFC_CARD_EMULATION_DISABLE :
		*mode = NFC_SE_CARD_EMULATION_MODE_OFF;
		break;
	}

	return nfc_common_convert_error_code(__func__, result);;
}

int nfc_hce_send_apdu_response(nfc_se_h handle, unsigned char *resp, unsigned int resp_len)
{
	net_nfc_error_e result;
	data_h data;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(resp == NULL);
	CHECK_INVALID(resp_len == 0);

	result = net_nfc_create_data(&data, resp, resp_len);
	if (result == NET_NFC_OK) {
		result = net_nfc_client_hce_response_apdu_sync(handle, data);
		net_nfc_free_data(data);
	}
	else {
		LOG_ERR("net_nfc_create_data failed, [%d]", result);
	}

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_set_default_route(nfc_se_type_e powered_on_status, nfc_se_type_e powered_off_status, nfc_se_type_e low_battery_status)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_set_default_route_sync(powered_on_status, powered_off_status, low_battery_status);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_is_activated_handler_for_aid(nfc_se_type_e se_type, const char *aid, bool *is_activated_handler)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(aid == NULL);
	CHECK_INVALID(is_activated_handler == NULL);

	result = net_nfc_client_se_is_activated_aid_handler_sync((net_nfc_se_type_e)se_type, aid, is_activated_handler);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_is_activated_handler_for_category(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, bool *is_activated_handler)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(is_activated_handler == NULL);

	result = net_nfc_client_se_is_activated_category_handler_sync((net_nfc_se_type_e)se_type, category, is_activated_handler);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_register_aid(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, const char *aid)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(aid == NULL);

	result = net_nfc_client_se_register_aids_sync((net_nfc_se_type_e)se_type, category, aid);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_unregister_aid(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, const char *aid)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(aid == NULL);

	result = net_nfc_client_se_unregister_aid_sync((net_nfc_se_type_e)se_type, category, aid);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_get_registered_aids_count(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, int *count)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(count == NULL);

	result = net_nfc_client_se_get_registered_aids_count_sync(
			(net_nfc_se_type_e)NFC_SE_TYPE_HCE,
			(net_nfc_card_emulation_category_t)category,
			(size_t *)count);

	return nfc_common_convert_error_code(__func__, result);
}

static void _se_registered_aid_event_cb(net_nfc_se_type_e se_type,
		const char *aid, bool readonly, void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_se_registered_aid_cb != NULL) {
		gdbus_nfc_context.on_se_registered_aid_cb(
			(nfc_se_type_e)se_type,
			aid,
			readonly,
			gdbus_nfc_context.on_se_registered_aid_cb_user_data);
	}
}

int nfc_se_foreach_registered_aids(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, nfc_se_registered_aid_cb callback, void *user_data)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	gdbus_nfc_context.on_se_registered_aid_cb = callback;
	gdbus_nfc_context.on_se_registered_aid_cb_user_data = user_data;

	result = net_nfc_client_se_foreach_registered_aids_sync((net_nfc_se_type_e)se_type,
		(net_nfc_card_emulation_category_t)category,
		(net_nfc_client_se_registered_aid_cb)_se_registered_aid_event_cb,
		user_data);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_add_route_for_aid_internal(const char *aid, nfc_se_type_e se_type, const char* pkg_name, bool unlock_required,
		nfc_se_power_type_e power, nfc_card_emulation_category_type_e category)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_add_route_aid_sync(pkg_name, se_type, category, aid, unlock_required, power);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_se_remove_route_for_aid_internal(const char* pkg_name, const char *aid)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_remove_route_aid_sync(pkg_name, aid);

	return nfc_common_convert_error_code(__func__, result);
}
