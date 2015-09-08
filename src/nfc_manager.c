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

bool nfc_manager_is_supported(void)
{
	bool nfc_supported = false;

	LOG_BEGIN();

	nfc_supported = nfc_common_is_supported(NFC_FEATURE);

	if(nfc_supported == true)
		set_last_result(NFC_ERROR_NONE);
	else
		set_last_result(NFC_ERROR_NOT_SUPPORTED);

	return nfc_supported;
}

static void _activation_changed_cb(net_nfc_error_e result, void *user_data)
{
	nfc_activation_completed_cb callback;
	void *user_param;

	LOG_BEGIN();

	if(user_data == NULL) {
		LOG_ERR("user_data is NULL");
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

int nfc_manager_set_activation(bool activation,
	nfc_activation_completed_cb callback,
	void *user_data)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();

	if(nfc_manager_is_activated() == activation)
	{
		if (activation)
		{
			ret = NFC_ERROR_ALREADY_ACTIVATED;
		}
		else
		{
			ret = NFC_ERROR_ALREADY_DEACTIVATED;
		}
	}
	else
	{
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			callback,
			user_data);
		if (parameter != NULL)
		{
			ret = net_nfc_client_manager_set_active(activation,
				_activation_changed_cb,
				parameter);
			if (ret != NET_NFC_OK)
			{
				LOG_ERR("net_nfc_client_manager_set_active fail");

				g_variant_unref(parameter);
			}
		}
		else
		{
			ret = NET_NFC_ALLOC_FAIL;
		}

		ret = nfc_common_convert_error_code(__func__, ret);
	}

	return ret;
}

bool nfc_manager_is_activated(void)
{
	int ret;
	int activated = 0;

	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_FEATURE) == false)
	{
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return false;
	}

	ret = net_nfc_client_get_nfc_state(&activated);

	set_last_result(nfc_common_convert_error_code(__func__,ret));

	return (!!activated);
}

int nfc_manager_set_activation_changed_cb(nfc_activation_changed_cb callback,
	void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	net_nfc_client_manager_set_activated(callback, user_data);

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_activation_changed_cb(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	net_nfc_client_manager_unset_activated();

	set_last_result(NFC_ERROR_NONE);
}

int nfc_manager_initialize(void)
{
	int ret = NET_NFC_OK;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);

	if(!nfc_common_is_initialized())
	{
		ret = net_nfc_client_initialize();
		if (ret != NET_NFC_OK)
			return nfc_common_convert_error_code(__func__, ret);

		memset(&gdbus_nfc_context, 0, sizeof(gdbus_nfc_context));

		gdbus_nfc_context.initialized = true;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_manager_deinitialize (void)
{
	int ret = NET_NFC_OK;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);

	if(nfc_common_is_initialized())
	{
		net_nfc_client_se_unset_event_cb();

		net_nfc_client_p2p_unset_device_discovered();
		net_nfc_client_p2p_unset_device_detached();

		net_nfc_client_tag_unset_tag_discovered();
		net_nfc_client_tag_unset_tag_detached();

		ret = net_nfc_client_deinitialize();

		gdbus_nfc_context.initialized = false;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _tag_discovered_cb(net_nfc_target_info_h info, void *user_data)
{
	LOG_BEGIN();

	gdbus_nfc_context.current_tag = info;

	if(gdbus_nfc_context.on_tag_discovered_cb != NULL) {
		gdbus_nfc_context.on_tag_discovered_cb(
			NFC_DISCOVERED_TYPE_ATTACHED,
			(nfc_tag_h)gdbus_nfc_context.current_tag,
			gdbus_nfc_context.on_tag_discovered_user_data);
	}

	/* ndef discovered cb */
	if(gdbus_nfc_context.on_ndef_discovered_cb)
	{
		ndef_message_h ndef_message = NULL;

		if (net_nfc_get_tag_ndef_message((net_nfc_target_info_h)info,
			&ndef_message) == NET_NFC_OK) {
			gdbus_nfc_context.on_ndef_discovered_cb(ndef_message,
				gdbus_nfc_context.on_ndef_discovered_user_data);

			net_nfc_free_ndef_message(ndef_message);
		}
	}
}

static void _tag_detached_cb(void *user_data)
{
	LOG_BEGIN();

	if(gdbus_nfc_context.on_tag_discovered_cb != NULL) {
		gdbus_nfc_context.on_tag_discovered_cb(
			NFC_DISCOVERED_TYPE_DETACHED,
			(nfc_tag_h)gdbus_nfc_context.current_tag,
			gdbus_nfc_context.on_tag_discovered_user_data);
	}

	gdbus_nfc_context.current_tag = NULL;
}

int nfc_manager_set_ndef_discovered_cb(
	nfc_ndef_discovered_cb callback,
	void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	net_nfc_client_tag_set_tag_discovered(_tag_discovered_cb, NULL);
	net_nfc_client_tag_set_tag_detached(_tag_detached_cb, NULL);

	gdbus_nfc_context.on_ndef_discovered_cb = callback;
	gdbus_nfc_context.on_ndef_discovered_user_data = user_data;

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_ndef_discovered_cb( void )
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	gdbus_nfc_context.on_ndef_discovered_cb = NULL;
	gdbus_nfc_context.on_ndef_discovered_user_data = NULL;

	set_last_result(NFC_ERROR_NONE);
}

void nfc_manager_set_tag_filter(int filter)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_TAG_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	if(filter < NET_NFC_ALL_DISABLE)
	{
		LOG_ERR("Invalid parameter");
		set_last_result(NFC_ERROR_INVALID_PARAMETER);
		return;
	}

	net_nfc_client_tag_set_filter(filter);

	set_last_result(NFC_ERROR_NONE);
}

int nfc_manager_get_tag_filter(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_TAG_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return 0;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return 0;
	}

	set_last_result(NFC_ERROR_NONE);

	return net_nfc_client_tag_get_filter();
}

int nfc_manager_get_connected_tag(nfc_tag_h *tag)
{
	int ret;
	net_nfc_target_info_h result = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);

	*tag = NULL;

	net_nfc_client_tag_set_tag_discovered(_tag_discovered_cb, NULL);
	net_nfc_client_tag_set_tag_detached(_tag_detached_cb, NULL);


	if(gdbus_nfc_context.current_tag == NULL) {
		ret = net_nfc_client_tag_get_current_tag_info_sync(&result);
		if (ret == NET_NFC_OK) {
			*tag = (nfc_tag_h)result;
		}
	} else {
		/* FIXME ??? */
		*tag = gdbus_nfc_context.current_tag;

		ret = NET_NFC_OK;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_manager_get_connected_target(nfc_p2p_target_h *target)
{
	int ret;
	net_nfc_target_handle_h result = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(target == NULL);

	*target = NULL;

	net_nfc_client_tag_set_tag_discovered(_tag_discovered_cb, NULL);
	net_nfc_client_tag_set_tag_detached(_tag_detached_cb, NULL);

	if(gdbus_nfc_context.current_target == NULL) {
		ret = net_nfc_client_tag_get_current_target_handle_sync(&result);
		if (ret == NET_NFC_OK) {
			gdbus_nfc_context.current_target = result;

			*target = gdbus_nfc_context.current_target;
		}
	} else {
		/* FIXME ??? */
		*target = gdbus_nfc_context.current_target;

		ret = NET_NFC_OK;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_manager_set_tag_discovered_cb(nfc_tag_discovered_cb callback,
	void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	net_nfc_client_tag_set_tag_discovered(_tag_discovered_cb, NULL);
	net_nfc_client_tag_set_tag_detached(_tag_detached_cb, NULL);

	gdbus_nfc_context.on_tag_discovered_cb = callback;
	gdbus_nfc_context.on_tag_discovered_user_data = user_data;

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_tag_discovered_cb(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_TAG_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	gdbus_nfc_context.on_tag_discovered_cb = NULL;
	gdbus_nfc_context.on_tag_discovered_user_data = NULL;

	set_last_result(NFC_ERROR_NONE);
}

static void _p2p_discovered_cb(
	net_nfc_target_handle_h handle_info,
	void *user_data)
{
	LOG_BEGIN();

	gdbus_nfc_context.current_target = handle_info;

	if(gdbus_nfc_context.on_p2p_target_discovered_cb != NULL) {
		gdbus_nfc_context.on_p2p_target_discovered_cb(
			NFC_DISCOVERED_TYPE_ATTACHED,
			(nfc_p2p_target_h)gdbus_nfc_context.current_target,
			gdbus_nfc_context.on_p2p_target_discovered_user_data);
	}
}

static void _p2p_detached_cb(void *user_data)
{
	nfc_p2p_target_h handle =
		(nfc_p2p_target_h)gdbus_nfc_context.current_target;

	LOG_BEGIN();

	if(gdbus_nfc_context.on_p2p_target_discovered_cb != NULL) {
		gdbus_nfc_context.on_p2p_target_discovered_cb(
			NFC_DISCOVERED_TYPE_DETACHED,
			handle,
			gdbus_nfc_context.on_p2p_target_discovered_user_data);
	}

	/* unset data_received callback */
	nfc_p2p_unset_data_received_cb(handle);

	gdbus_nfc_context.current_target = NULL;
}

int nfc_manager_set_p2p_target_discovered_cb(
	nfc_p2p_target_discovered_cb callback,
	void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_P2P_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	net_nfc_client_p2p_set_device_discovered(_p2p_discovered_cb, NULL);
	net_nfc_client_p2p_set_device_detached(_p2p_detached_cb, NULL);

	gdbus_nfc_context.on_p2p_target_discovered_cb = callback;
	gdbus_nfc_context.on_p2p_target_discovered_user_data = user_data;

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_p2p_target_discovered_cb(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_P2P_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	gdbus_nfc_context.on_p2p_target_discovered_cb = NULL;
	gdbus_nfc_context.on_p2p_target_discovered_user_data = NULL;

	set_last_result(NFC_ERROR_NONE);
}

int nfc_manager_set_system_handler_enable(bool enable)
{
	int ret;
	int state;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();

	if (enable == true) {
		state = 0;
	} else {
		state = 1;
	}

	ret = net_nfc_client_sys_handler_set_launch_popup_state(state);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_manager_set_system_handler_enable_force(bool enable)
{
	int ret;
	int state;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();

	if (enable == true) {
		state = 0;
	} else {
		state = 1;
	}

	ret = net_nfc_client_sys_handler_set_launch_popup_state_force(state);

	return nfc_common_convert_error_code(__func__, ret);
}

bool nfc_manager_is_system_handler_enabled(void)
{
	int ret;
	int state = 0;

	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return false;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return false;
	}

	ret = net_nfc_client_sys_handler_get_launch_popup_state(&state);

	set_last_result(nfc_common_convert_error_code(__func__,ret));

	return (state == 0);
}

int nfc_manager_get_cached_message(nfc_ndef_message_h *ndef_message)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);

	ret = net_nfc_retrieve_current_ndef_message(ndef_message);

	return nfc_common_convert_error_code(__func__, ret);
}

static void _se_event_cb(net_nfc_message_e message, void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_se_event_cb != NULL) {
		if(message == NET_NFC_MESSAGE_SE_CARD_EMULATION_CHANGED)
			gdbus_nfc_context.on_se_event_cb(
				NFC_SE_EVENT_CARD_EMULATION_CHANGED,
				gdbus_nfc_context.on_se_event_user_data);

		else if(message == NET_NFC_MESSAGE_SE_TYPE_CHANGED)
			gdbus_nfc_context.on_se_event_cb(
				NFC_SE_EVENT_SE_TYPE_CHANGED,
				gdbus_nfc_context.on_se_event_user_data);
		else if(message == NET_NFC_MESSAGE_SE_FIELD_ON)
			gdbus_nfc_context.on_se_event_cb(
				NFC_SE_EVENT_FIELD_ON,
				gdbus_nfc_context.on_se_event_user_data);
	}
}

int nfc_manager_set_se_event_cb(nfc_se_event_cb callback, void *user_data)
{
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	net_nfc_client_se_set_event_cb(_se_event_cb, NULL);

	gdbus_nfc_context.on_se_event_cb = callback;
	gdbus_nfc_context.on_se_event_user_data = user_data;

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_se_event_cb(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_CE_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	gdbus_nfc_context.on_se_event_cb = NULL;
	gdbus_nfc_context.on_se_event_user_data = NULL;

	set_last_result(NFC_ERROR_NONE);
}

static void _se_transaction_event_cb(net_nfc_se_type_e se_type, data_h aid,
	data_h param, void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_se_transaction_event_cb != NULL) {
		gdbus_nfc_context.on_se_transaction_event_cb(
			se_type,
			net_nfc_get_data_buffer(aid),
			net_nfc_get_data_length(aid),
			net_nfc_get_data_buffer(param),
			net_nfc_get_data_length(param),
			gdbus_nfc_context.on_se_transaction_event_user_data);
	}
}

int nfc_manager_set_se_transaction_event_cb(
	nfc_se_type_e se_type,
	nfc_se_transaction_event_cb callback,
	void *user_data)
{
	net_nfc_se_type_e type = NET_NFC_SE_TYPE_NONE;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	gdbus_nfc_context.on_se_transaction_event_cb = callback;
	gdbus_nfc_context.on_se_transaction_event_user_data = user_data;

	switch(se_type)
	{
		case NFC_SE_TYPE_ESE:
			type = NET_NFC_SE_TYPE_ESE;
			break;

		case NFC_SE_TYPE_UICC:
			type = NET_NFC_SE_TYPE_UICC;
			break;
		case NET_NFC_SE_TYPE_HCE:
			type = NET_NFC_SE_TYPE_HCE;
			break;
		default:
			return NFC_ERROR_INVALID_PARAMETER;
			break;

	}

	net_nfc_client_se_set_transaction_event_cb(type, _se_transaction_event_cb, user_data);

	return NFC_ERROR_NONE;
}

void nfc_manager_unset_se_transaction_event_cb(nfc_se_type_e se_type)
{
	net_nfc_se_type_e type = NET_NFC_SE_TYPE_NONE;

	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_CE_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	switch(se_type)
	{
		case NFC_SE_TYPE_ESE:
			type = NET_NFC_SE_TYPE_ESE;
			break;

		case NFC_SE_TYPE_UICC:
			type = NET_NFC_SE_TYPE_UICC;
			break;
		default:
			type = NET_NFC_SE_TYPE_NONE;
			break;
	}

	net_nfc_client_se_unset_transaction_event_cb(type);

	set_last_result(NFC_ERROR_NONE);
}

int nfc_manager_enable_transaction_fg_dispatch()
{
	net_nfc_error_e result;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_set_transaction_fg_dispatch(true);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_manager_disable_transaction_fg_dispatch()
{
	net_nfc_error_e result;

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();

	result = net_nfc_client_se_set_transaction_fg_dispatch(false);

	return nfc_common_convert_error_code(__func__, result);
}

int nfc_manager_set_se_type(nfc_se_type_e type)
{
	int ret;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_NONE;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(type < NFC_SE_TYPE_DISABLE);
	CHECK_INVALID(type > NFC_SE_TYPE_HCE);

	switch (type)
	{
	case NFC_SE_TYPE_ESE :
		se_type = NET_NFC_SE_TYPE_ESE;
		break;
	case NFC_SE_TYPE_UICC :
		se_type = NET_NFC_SE_TYPE_UICC;
		break;
	case NFC_SE_TYPE_HCE :
		se_type = NET_NFC_SE_TYPE_HCE;
		break;
	default :
		se_type = NET_NFC_SE_TYPE_NONE;
		break;
	}

	ret = net_nfc_client_se_set_secure_element_type_sync(se_type);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_manager_get_se_type(nfc_se_type_e *type)
{
	int ret;
	net_nfc_se_type_e se_type = NET_NFC_SE_TYPE_NONE;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(type == NULL);

	ret = net_nfc_client_se_get_secure_element_type_sync(&se_type);

	switch (se_type)
	{
		case NET_NFC_SE_TYPE_ESE :
			*type = NFC_SE_TYPE_ESE;
			break;
		case NET_NFC_SE_TYPE_UICC :
			*type = NFC_SE_TYPE_UICC;
			break;
		case NET_NFC_SE_TYPE_HCE :
			*type = NFC_SE_TYPE_HCE;
			break;
		default:
			*type = NFC_SE_TYPE_DISABLE;
			break;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _hce_event_cb(net_nfc_target_handle_h handle,
		net_nfc_hce_event_t event, data_h apdu, void *user_data)
{
	LOG_BEGIN();

	if (gdbus_nfc_context.on_hce_event_cb != NULL) {
		gdbus_nfc_context.on_hce_event_cb(
			(nfc_se_h)handle,
			(nfc_hce_event_type_e)event,
			net_nfc_get_data_buffer(apdu),
			net_nfc_get_data_length(apdu),
			gdbus_nfc_context.on_hce_event_user_data);
	}
}

int nfc_manager_set_hce_event_cb(nfc_hce_event_cb callback, void *user_data)
{
	net_nfc_error_e result;
	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_CE_HCE_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(callback == NULL);

	gdbus_nfc_context.on_hce_event_cb = callback;
	gdbus_nfc_context.on_hce_event_user_data = user_data;

	result = net_nfc_client_hce_set_event_received_cb(_hce_event_cb, user_data);

	return nfc_common_convert_error_code(__func__, result);
}

void nfc_manager_unset_hce_event_cb(void)
{
	LOG_BEGIN();

	if(nfc_common_is_supported(NFC_CE_HCE_FEATURE) == false)
	{
		LOG_ERR("NFC not supported");
		set_last_result(NFC_ERROR_NOT_SUPPORTED);
		return;
	}

	if(nfc_common_is_initialized() == false)
	{
		LOG_ERR("NFC not initialized");
		set_last_result(NFC_ERROR_NOT_INITIALIZED);
		return;
	}

	net_nfc_client_hce_unset_event_received_cb();

	set_last_result(NFC_ERROR_NONE);
}

