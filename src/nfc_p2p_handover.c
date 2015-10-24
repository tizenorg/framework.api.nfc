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

static void _p2p_handover_cb(net_nfc_error_e result,
	net_nfc_conn_handover_carrier_type_e carrier, data_h ac_data, void *user_data)
{
	nfc_p2p_connection_handover_completed_cb callback;
	void *user_param;

	LOG_BEGIN();

	if (user_data == NULL) {
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		nfc_ac_type_e carrior_type;
		char *buffer;
		int len = 0;

		switch (carrier) {
		case NET_NFC_CONN_HANDOVER_CARRIER_BT :
			carrior_type = NFC_AC_TYPE_BT;
			buffer = nfc_common_get_bt_address_string(ac_data);
			if(buffer != NULL)
				len = strlen(buffer);
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS :
			carrior_type = NFC_AC_TYPE_WIFI;
			buffer = nfc_common_get_bt_address_string(ac_data);
			if(buffer != NULL)
				len = strlen(buffer);
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P :
			carrior_type = NFC_AC_TYPE_WIFI_DIRECT;
			buffer = nfc_common_get_bt_address_string(ac_data);
			if(buffer != NULL)
				len = strlen(buffer);
			break;

		default :
			carrior_type = NFC_AC_TYPE_UNKNOWN;
			buffer = NULL;
			len = 0;
			break;
		}

		callback(nfc_common_convert_error_code(__func__, result),
			carrior_type, (void *)buffer,
			len, user_param);

		if (buffer != NULL) {
			g_free(buffer);
		}
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_p2p_connection_handover(nfc_p2p_target_h target,
	nfc_ac_type_e type,
	nfc_p2p_connection_handover_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_conn_handover_carrier_type_e net_ac_type =
		NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);
	CHECK_INVALID(type > NFC_AC_TYPE_UNKNOWN);
	CHECK_ACTIVATED();

	switch (type)
	{
	case NFC_AC_TYPE_BT :
		net_ac_type = NET_NFC_CONN_HANDOVER_CARRIER_BT;
		break;

	case NFC_AC_TYPE_WIFI :
		net_ac_type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS;
		break;

	case NFC_AC_TYPE_WIFI_DIRECT :
		net_ac_type = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P;
		break;

	case NFC_AC_TYPE_UNKNOWN :
		net_ac_type = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
		break;

	default:
		break;
	}

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		ret = net_nfc_client_p2p_connection_handover(
			(net_nfc_target_handle_h)target,
			net_ac_type,
			_p2p_handover_cb,
			parameter);
		if (ret != NET_NFC_OK) {
			g_variant_unref(parameter);
		}
	} else {
		ret = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _connection_handover_event_cb(
	net_nfc_handover_event_e event,
	net_nfc_error_e result,
	net_nfc_conn_handover_carrier_type_e carrier,
	data_h ac_data,
	data_h ndef_message,
	void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_handover_event_cb != NULL) {
		nfc_ndef_message_h message;
		nfc_ac_type_e type;
		char *address;

		net_nfc_create_ndef_message_from_rawdata(&message, ndef_message);

		if (event == NET_NFC_HANDOVER_START) {
			type = NFC_AC_TYPE_UNKNOWN;
			address = NULL;
		} else {
			switch (carrier) {
			case NET_NFC_CONN_HANDOVER_CARRIER_BT :
				type = NFC_AC_TYPE_BT;
				address = nfc_common_get_bt_address_string(ac_data);
				break;

			case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS :
				type = NFC_AC_TYPE_WIFI;
				address = nfc_common_get_bt_address_string(ac_data);
				break;

			case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P :
				type = NFC_AC_TYPE_WIFI_DIRECT;
				address = nfc_common_get_bt_address_string(ac_data);
				break;

			default :
				type = NFC_AC_TYPE_UNKNOWN;
				address = NULL;
				break;
			}
		}

		gdbus_nfc_context.on_handover_event_cb(
			nfc_common_convert_error_code(__func__, result),
			event,
			type,
			address,
			message,
			gdbus_nfc_context.on_handover_event_user_data);

		if (address != NULL) {
			g_free(address);
		}
		net_nfc_free_ndef_message(message);
	}

	LOG_END();
}

int nfc_connection_handover_set_event_cb(nfc_connection_handover_event_cb callback, void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	gdbus_nfc_context.on_handover_event_cb = callback;
	gdbus_nfc_context.on_handover_event_user_data = user_data;

	net_nfc_client_handover_set_handover_event_cb(_connection_handover_event_cb, NULL);

	return NFC_ERROR_NONE;
}

int nfc_connection_handover_unset_event_cb(void)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();

	net_nfc_client_handover_unset_handover_event_cb();

	gdbus_nfc_context.on_handover_event_cb = NULL;
	gdbus_nfc_context.on_handover_event_user_data = NULL;

	return NFC_ERROR_NONE;
}

bool nfc_p2p_is_supported_ac_type(nfc_ac_type_e carrier)
{
	bool _is_support_p2p = false;
	bool _is_support_ac_type = false;

        LOG_BEGIN();

        _is_support_p2p = nfc_common_is_supported(NFC_P2P_FEATURE);
	if (!_is_support_p2p) {
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return false;
	}

	if (carrier == NFC_AC_TYPE_BT)
		_is_support_ac_type = true;

	if (_is_support_ac_type) {
		set_last_result(NFC_ERROR_NONE);
	} else {
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
	}

	return _is_support_ac_type;
}

int nfc_handover_message_import_from_ndef_message(nfc_handover_message_h *result, nfc_ndef_message_h msg)
{
	net_nfc_error_e ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(msg == NULL);
	CHECK_INVALID(result == NULL);

	ret = net_nfc_import_handover_from_ndef_message(
		(ndef_message_h)msg, (net_nfc_ch_message_h *)result);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_handover_message_get_random_number(nfc_handover_message_h message, unsigned short *random_number)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);
	CHECK_INVALID(random_number == NULL);

	result = net_nfc_get_handover_random_number(
		(net_nfc_ch_message_h)message,
		random_number);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_message_get_carrier_count(nfc_handover_message_h message, unsigned int *count)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);
	CHECK_INVALID(count == NULL);

	result = net_nfc_get_handover_carrier_count(
		(net_nfc_ch_message_h)message,
		count);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_message_get_carrier(nfc_handover_message_h message, int index, nfc_handover_carrier_h *carrier)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);
	CHECK_INVALID(carrier == NULL);

	result = net_nfc_get_handover_carrier(
		(net_nfc_ch_message_h)message,
		index,
		(net_nfc_ch_carrier_h *)carrier);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_message_get_carrier_by_type(nfc_handover_message_h message, nfc_ac_type_e type, nfc_handover_carrier_h *carrier)
{
	net_nfc_error_e result;
	net_nfc_conn_handover_carrier_type_e temp;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);
	CHECK_INVALID(carrier == NULL);

	switch (type) {
	case NFC_AC_TYPE_BT :
		temp = NET_NFC_CONN_HANDOVER_CARRIER_BT;
		break;

	case NFC_AC_TYPE_WIFI :
		temp = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS;
		break;

	case NFC_AC_TYPE_WIFI_DIRECT :
		temp = NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P;
		break;

	default:
		temp = NET_NFC_CONN_HANDOVER_CARRIER_UNKNOWN;
		break;
	}
	result = net_nfc_get_handover_carrier_by_type(
		(net_nfc_ch_message_h)message,
		temp,
		(net_nfc_ch_carrier_h *)carrier);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_message_destroy(nfc_handover_message_h message)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);

	result = net_nfc_free_handover_message((net_nfc_ch_message_h)message);

	return nfc_common_convert_error_code(__func__, result);
}


int nfc_handover_carrier_get_cps(nfc_handover_carrier_h carrier, nfc_ac_state_e *cps)
{
	net_nfc_error_e result;
	net_nfc_conn_handover_carrier_state_e temp;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(cps == NULL);

	result = net_nfc_get_handover_carrier_cps(
		(net_nfc_ch_carrier_h)carrier, &temp);
	if (result == NET_NFC_OK) {
		switch (temp) {
		case NET_NFC_CONN_HANDOVER_CARRIER_INACTIVATE :
			*cps = NFC_AC_STATE_INACTIVATE;
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATE :
			*cps = NFC_AC_STATE_ACTIVATE;
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_ACTIVATING :
			*cps = NFC_AC_STATE_ACTIVATING;
			break;

		default :
			*cps = NFC_AC_STATE_UNKNOWN;
			break;
		}
	}

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_get_type(nfc_handover_carrier_h carrier, nfc_ac_type_e *type)
{
	net_nfc_error_e result;
	net_nfc_conn_handover_carrier_type_e temp;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(type == NULL);

	result = net_nfc_get_handover_carrier_type(
		(net_nfc_ch_carrier_h)carrier, &temp);
	if (result == NET_NFC_OK) {
		switch (temp) {
		case NET_NFC_CONN_HANDOVER_CARRIER_BT :
			*type = NFC_AC_TYPE_BT;
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_WPS :
			*type = NFC_AC_TYPE_WIFI;
			break;

		case NET_NFC_CONN_HANDOVER_CARRIER_WIFI_P2P :
			*type = NFC_AC_TYPE_WIFI_DIRECT;
			break;

		default :
			*type = NFC_AC_TYPE_UNKNOWN;
			break;
		}
	}

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_get_carrier_record(nfc_handover_carrier_h carrier, nfc_ndef_record_h *record)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(record == NULL);

	result = net_nfc_get_handover_carrier_record(
		(net_nfc_ch_carrier_h)carrier, (ndef_record_h *)record);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_get_auxiliary_record_count(nfc_handover_carrier_h carrier, unsigned int *count)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(count == NULL);

	result = net_nfc_get_handover_auxiliary_record_count(
		(net_nfc_ch_carrier_h)carrier, count);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_get_auxiliary_record(nfc_handover_carrier_h carrier, int index, nfc_ndef_record_h *record)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(record == NULL);

	result = net_nfc_get_handover_auxiliary_record(
		(net_nfc_ch_carrier_h)carrier,
		index, (ndef_record_h *)record);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_get_handover_config(nfc_handover_carrier_h carrier, nfc_handover_config_h *config)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);
	CHECK_INVALID(config == NULL);

	result = net_nfc_create_carrier_config_from_carrier(
		(net_nfc_carrier_config_h *)config,
		(net_nfc_ch_carrier_h)carrier);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_carrier_destroy(nfc_handover_carrier_h carrier)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(carrier == NULL);

	result = net_nfc_free_handover_carrier((net_nfc_ch_carrier_h)carrier);

	return nfc_common_convert_error_code(__func__, result);
}


int nfc_handover_config_get_property(nfc_handover_config_h config, unsigned short attribute, unsigned short *size, unsigned char **data)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(config == NULL);
	CHECK_INVALID(size == NULL);
	CHECK_INVALID(data == NULL);

	result = net_nfc_get_carrier_config_property(
		(net_nfc_carrier_config_h)config,
		attribute, size, data);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_handover_config_destroy(nfc_handover_config_h config)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(config == NULL);

	result = net_nfc_free_carrier_config((net_nfc_carrier_config_h)config);

	return nfc_common_convert_error_code(__func__, result);
}

