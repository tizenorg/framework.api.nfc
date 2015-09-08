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

static void _p2p_send_cb(net_nfc_error_e result, void *user_data)
{
	nfc_p2p_send_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_p2p_send(nfc_p2p_target_h target,
	nfc_ndef_message_h message,
	nfc_p2p_send_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h rawdata;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(message == NULL);
	CHECK_INVALID(target == NULL);
	CHECK_ACTIVATED();
	CHECK_APP_PERMISSION();

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		net_nfc_create_rawdata_from_ndef_message(message, &rawdata);
		ret = net_nfc_client_p2p_send((net_nfc_target_handle_h)target,
			rawdata,
			_p2p_send_cb,
			parameter);
		if (ret != NET_NFC_OK) {
			g_variant_unref(parameter);
		}

		net_nfc_free_data(rawdata);
	} else {
		ret = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_p2p_send_no_permission(
	nfc_p2p_target_h target,
	nfc_ndef_message_h message,
	nfc_p2p_send_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h rawdata;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);
	CHECK_INVALID(message == NULL);
	CHECK_ACTIVATED();

	/* skip check app permission */

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		net_nfc_create_rawdata_from_ndef_message(message, &rawdata);
		ret = net_nfc_client_p2p_send((net_nfc_target_handle_h)target,
			rawdata,
			_p2p_send_cb,
			parameter);
		if (ret != NET_NFC_OK) {
			g_variant_unref(parameter);
		}

		net_nfc_free_data(rawdata);
	} else {
		ret = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _p2p_set_data_received_cb(data_h data, void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_p2p_recv_cb != NULL)
	{
		ndef_message_h ndef_message;

		net_nfc_create_ndef_message_from_rawdata(&ndef_message, data);

		gdbus_nfc_context.on_p2p_recv_cb(
			(nfc_p2p_target_h)(gdbus_nfc_context.current_target),
			ndef_message,
			gdbus_nfc_context.on_p2p_recv_user_data);

		net_nfc_free_ndef_message(ndef_message);
	}
}

int nfc_p2p_set_data_received_cb(nfc_p2p_target_h target,
	nfc_p2p_data_received_cb callback,
	void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);
	CHECK_INVALID(callback == NULL);
	CHECK_INVALID(gdbus_nfc_context.current_target != target);

	gdbus_nfc_context.on_p2p_recv_cb = callback;
	gdbus_nfc_context.on_p2p_recv_user_data = user_data;

	net_nfc_client_p2p_set_data_received(_p2p_set_data_received_cb, NULL);

	return NFC_ERROR_NONE;
}

int nfc_p2p_unset_data_received_cb(nfc_p2p_target_h target)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);
	CHECK_INVALID(gdbus_nfc_context.current_target != target);

	net_nfc_client_p2p_unset_data_received();

	gdbus_nfc_context.on_p2p_recv_cb = NULL;
	gdbus_nfc_context.on_p2p_recv_user_data = NULL;

	return NFC_ERROR_NONE;
}

static void _snep_start_server_cb(
	net_nfc_snep_handle_h arg_handle,
	net_nfc_snep_type_t event,
	net_nfc_error_e result,
	nfc_ndef_message_h msg,
	void *user_data)
{
	nfc_snep_event_cb callback;
	void *user_param;

	LOG_BEGIN();

	if (user_data == NULL) {
		LOG_ERR("user_data is NULL");
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		nfc_snep_event_e snep_event;

		switch ((int)event) {
		case NET_NFC_SNEP_GET :
			snep_event = NFC_SNEP_EVENT_GET;
			break;

		case NET_NFC_SNEP_PUT :
			snep_event = NFC_SNEP_EVENT_PUT;
			break;

		case NET_NFC_LLCP_REGISTERED :
			snep_event = NFC_SNEP_EVENT_REGISTER;
			break;

		case NET_NFC_LLCP_UNREGISTERED :
			snep_event = NFC_SNEP_EVENT_UNREGISTER;
			break;

		case NET_NFC_LLCP_START :
			snep_event = NFC_SNEP_EVENT_START;
			break;

		case NET_NFC_LLCP_STOP :
		default :
			snep_event = NFC_SNEP_EVENT_STOP;
			break;
		}

		callback(arg_handle, snep_event,
			nfc_common_convert_error_code(__func__, result),
			msg, user_param);

		if (snep_event == NFC_SNEP_EVENT_STOP) {
			g_variant_unref(user_data);
		}
	}
}

int nfc_snep_start_server(nfc_p2p_target_h target,
	const char *san,
	int sap,
	nfc_snep_event_cb callback,
	void *user_data)
{
	net_nfc_error_e result;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		result = net_nfc_client_snep_start_server(
			(net_nfc_target_handle_h)target,
			san,
			(sap_t)sap,
			_snep_start_server_cb,
			parameter);
		if (result != NET_NFC_OK) {
			g_variant_unref(parameter);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, result);
}

static void _snep_start_client_cb(net_nfc_snep_handle_h arg_handle,
	net_nfc_snep_type_t event,
	net_nfc_error_e result,
	nfc_ndef_message_h msg,
	void *user_data)
{
	nfc_snep_event_cb callback;
	void *user_param;

	LOG_BEGIN();

	if (user_data == NULL) {
		LOG_ERR("user_data is NULL");
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		nfc_snep_event_e snep_event;

		switch ((int)event) {
		case NET_NFC_SNEP_GET :
			snep_event = NFC_SNEP_EVENT_GET;
			break;

		case NET_NFC_SNEP_PUT :
			snep_event = NFC_SNEP_EVENT_PUT;
			break;

		case NET_NFC_LLCP_REGISTERED :
			snep_event = NFC_SNEP_EVENT_REGISTER;
			break;

		case NET_NFC_LLCP_UNREGISTERED :
			snep_event = NFC_SNEP_EVENT_UNREGISTER;
			break;

		case NET_NFC_LLCP_START :
			snep_event = NFC_SNEP_EVENT_START;
			break;

		case NET_NFC_LLCP_STOP :
		default :
			snep_event = NFC_SNEP_EVENT_STOP;
			break;
		}

		callback(arg_handle, snep_event,
			nfc_common_convert_error_code(__func__, result),
			msg, user_param);

		if (snep_event == NFC_SNEP_EVENT_STOP) {
			g_variant_unref(user_data);
		}
	}
}

int nfc_snep_start_client(nfc_p2p_target_h target,
	const char *san,
	int sap,
	nfc_snep_event_cb callback,
	void *user_data)
{
	net_nfc_error_e result;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		result = net_nfc_client_snep_start_client(
			(net_nfc_target_handle_h)target,
			san,
			(sap_t)sap,
			_snep_start_client_cb,
			parameter);
		if (result != NET_NFC_OK) {
			g_variant_unref(parameter);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, result);
}

static void _snep_send_request_cb(net_nfc_snep_handle_h target,
	net_nfc_snep_type_t event, net_nfc_error_e result, ndef_message_h msg, void *user_data)
{
	nfc_snep_event_cb callback;
	void *user_param;

	LOG_BEGIN();

	if (user_data == NULL) {
		LOG_ERR("user_data is NULL");
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		callback((nfc_p2p_snep_h)target,
			event,
			nfc_common_convert_error_code(__func__, result),
			(nfc_ndef_message_h)msg,
			user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_snep_send_client_request(nfc_p2p_snep_h handle,
	nfc_snep_type_e type,
	nfc_ndef_message_h msg,
	nfc_snep_event_cb callback,
	void *user_data)
{
	net_nfc_error_e result;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(handle == NULL);
	CHECK_INVALID(msg == NULL);

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		result = net_nfc_client_snep_send_client_request(
			(net_nfc_target_handle_h)handle,
			type,
			msg,
			_snep_send_request_cb,
			parameter);
		if (result != NET_NFC_OK) {
			g_variant_unref(parameter);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, result);
}

static void _snep_event_cb(net_nfc_snep_handle_h target, net_nfc_snep_type_t event,
	net_nfc_error_e result, ndef_message_h msg, void *user_data)
{
	nfc_snep_event_cb callback;
	void *user_param;

	LOG_BEGIN();

	if (user_data == NULL) {
		LOG_ERR("user_data is NULL");
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		switch ((int)event) {
		case NET_NFC_SNEP_GET :
			event = NFC_SNEP_EVENT_GET;
			break;

		case NET_NFC_SNEP_PUT :
			event = NFC_SNEP_EVENT_PUT;
			break;

		case NET_NFC_LLCP_REGISTERED :
			event = NFC_SNEP_EVENT_REGISTER;
			break;

		case NET_NFC_LLCP_UNREGISTERED :
			event = NFC_SNEP_EVENT_UNREGISTER;
			break;

		case NET_NFC_LLCP_START :
			event = NFC_SNEP_EVENT_START;
			break;

		case NET_NFC_LLCP_STOP :
			event = NFC_SNEP_EVENT_STOP;
			break;
		}

		callback(target, event,
			nfc_common_convert_error_code(__func__, result),
			(ndef_message_h)msg, user_param);
	}
}

int nfc_snep_register_server(const char *san, int sap,
	nfc_snep_event_cb callback, void *user_data)
{
	net_nfc_error_e result;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(san == NULL);
	CHECK_INVALID(sap == 0);

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		result = net_nfc_client_snep_register_server(san, (sap_t)sap,
			_snep_event_cb, parameter);
		if (result != NET_NFC_OK) {
			g_variant_unref(parameter);
		}
	} else {
		result = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_snep_unregister_server(const char *san, int sap)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_snep_unregister_server(san, (sap_t)sap);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_snep_stop_service(nfc_p2p_target_h target, nfc_p2p_snep_h clients)
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_snep_stop_service_sync(target, clients);

	return nfc_common_convert_error_code(__func__, result);
}

