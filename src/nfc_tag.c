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

/**
 * @brief The default factory key.
 * @details The key is 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
const unsigned char NFC_TAG_MIFARE_KEY_DEFAULT[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * @brief The well-known key for tags formatted according to the MIFARE Application Directory (MAD) specification.
 * @details The key is 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
const unsigned char NFC_TAG_MIFARE_KEY_APPLICATION_DIRECTORY[6] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};

/**
 * @brief The well-known key for tags formatted according to the NDEF on Mifare Classic specification.
 * @details The key is 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
const unsigned char NFC_TAG_MIFARE_KEY_NFC_FORUM[6] = {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7};

static void _tag_format_ndef_cb(net_nfc_error_e result,
	void *user_data)
{
	nfc_tag_format_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result),
			user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_tag_format_ndef(nfc_tag_h tag,
	unsigned char *key,
	int key_size,
	nfc_tag_format_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h key_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();
	CHECK_APP_PERMISSION();

	ret = net_nfc_create_data(&key_data, key, key_size);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag,
			&handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_ndef_format(
					handle,
					key_data,
					_tag_format_ndef_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(key_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _tag_read_ndef_cb(net_nfc_error_e result, ndef_message_h message,
	void *user_data)
{
	nfc_tag_read_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result),
			(nfc_ndef_message_h)message,
			user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_tag_read_ndef(nfc_tag_h tag,
	nfc_tag_read_completed_cb callback,
	void * user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_ndef_read(
				handle,
				_tag_read_ndef_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _tag_write_ndef_cb(net_nfc_error_e result,
	void *user_data)
{
	nfc_tag_write_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_tag_write_ndef(nfc_tag_h tag,
	nfc_ndef_message_h msg,
	nfc_tag_write_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;
	unsigned int byte_size = 0;
	uint32_t max_len = 0;
	net_nfc_ndef_card_state_e state = NET_NFC_NDEF_CARD_INVALID;

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();
	CHECK_APP_PERMISSION();

	ret = net_nfc_get_tag_ndef_state((net_nfc_target_info_h)tag, &state);
	if (ret != NET_NFC_OK) {
		LOG_ERR("net_nfc_get_tag_ndef_state failed, [%d]", ret);
		return nfc_common_convert_error_code(__func__, ret);;
	}

	if (state == NET_NFC_NDEF_CARD_READ_ONLY) {
		return NFC_ERROR_READ_ONLY_NDEF;
	}

	ret = net_nfc_get_tag_max_data_size((net_nfc_target_info_h)tag, &max_len);
	if (ret != NET_NFC_OK) {
		LOG_ERR("net_nfc_get_tag_max_data_size failed, [%d]", ret);
		return nfc_common_convert_error_code(__func__, ret);;
	}

	ret = nfc_common_get_rawdata_size(msg, &byte_size);
	if (ret != NFC_ERROR_NONE) {
		LOG_ERR("nfc_ndef_message_get_rawdata_size failed, [%d]", ret);
		return nfc_common_convert_error_code(__func__, ret);;
	}

	if (max_len < byte_size) {
		return NFC_ERROR_NO_SPACE_ON_NDEF;
	}

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_ndef_write(
				handle,
				msg,
				_tag_write_ndef_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _tag_transceive_data_cb(net_nfc_error_e result, data_h arg_data,
	void *user_data)
{
	nfc_tag_transceive_completed_cb callback;
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
		uint8_t *buffer = NULL;
		uint32_t length = 0;

		if (result == NET_NFC_OK && arg_data != NULL) {
			buffer = net_nfc_get_data_buffer(arg_data);
			length = net_nfc_get_data_length(arg_data);
		}

		callback(nfc_common_convert_error_code(__func__, result),
			buffer,
			length,
			user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_tag_transceive(nfc_tag_h tag,
	unsigned char *buffer,
	int buffer_size,
	nfc_tag_transceive_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h rawdata = NULL;

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(buffer == NULL);
	CHECK_INVALID(buffer_size <= 0);
	CHECK_ACTIVATED();
	CHECK_APP_PERMISSION();

	ret = net_nfc_create_data(&rawdata, buffer, buffer_size);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_transceive_data(
					handle,
					rawdata,
					_tag_transceive_data_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(rawdata);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_tag_get_type(nfc_tag_h tag, nfc_tag_type_e *type)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(type == NULL);

	ret = net_nfc_get_tag_type(tag, (net_nfc_target_type_e *)type);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_tag_is_support_ndef(nfc_tag_h tag, bool *is_support)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(is_support == NULL);

	ret = net_nfc_get_tag_ndef_support(tag, is_support);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_tag_get_maximum_ndef_size(nfc_tag_h tag, unsigned int *max_size)
{
	int ret;

	LOG_BEGIN();
	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(max_size == NULL);

	ret = net_nfc_get_tag_max_data_size(tag, max_size);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_tag_get_ndef_size(nfc_tag_h tag, unsigned int *actual_data_size)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(actual_data_size == NULL);

	ret = net_nfc_get_tag_actual_data_size(tag, actual_data_size);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_tag_foreach_information(nfc_tag_h tag,
	nfc_tag_information_cb callback,
	void *user_data)
{
	int ret;
	int i, count = 0;
	char **keys = NULL;
	data_h value = NULL;

	bool cont;

	LOG_BEGIN();
	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(callback == NULL);

	ret = net_nfc_get_tag_info_keys((net_nfc_target_info_h)tag,
		&keys, &count);

	if(ret != NET_NFC_OK)
		return nfc_common_convert_error_code(__func__, ret);

	for (i = 0; i < count; i++) {
		net_nfc_get_tag_info_value((net_nfc_target_info_h)tag, keys[i],
			&value);

		cont = callback(keys[i],
			net_nfc_get_data_buffer(value),
			net_nfc_get_data_length(value),
			user_data);

		if (!cont)
			break;
	}

	return NFC_ERROR_NONE;
}

/* FIXME */
static void _mifare_authenticate_with_keyA_cb(net_nfc_error_e result,
	void *user_data)
{
	nfc_mifare_authenticate_with_keyA_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_authenticate_with_keyA(nfc_tag_h tag,
	int sector_index,
	unsigned char *auth_key,
	nfc_mifare_authenticate_with_keyA_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h auth_key_data = NULL;

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(auth_key == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_create_data(&auth_key_data, auth_key, 6);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_mifare_authenticate_with_keyA(
					handle,
					sector_index,
					auth_key_data,
					_mifare_authenticate_with_keyA_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(auth_key_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}


static void _mifare_authenticate_with_keyB_cb(net_nfc_error_e result,
	void *user_data)
{
	nfc_mifare_authenticate_with_keyB_completed_cb callback;
	void *user_param;

	if (user_data == NULL) {
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

int nfc_mifare_authenticate_with_keyB(nfc_tag_h tag,
	int sector_index,
	unsigned char *auth_key,
	nfc_mifare_authenticate_with_keyB_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h auth_key_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(auth_key == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_create_data(&auth_key_data, auth_key, 6);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_mifare_authenticate_with_keyB(
					handle,
					sector_index,
					auth_key_data,
					_mifare_authenticate_with_keyB_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(auth_key_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

/* FIXME */
static void _mifare_read_block_cb(net_nfc_error_e result, data_h data,
	void *user_data)
{
	nfc_mifare_read_block_completed_cb callback;
	void *user_param;

	if (user_data == NULL) {
		LOG_ERR("user_data is NULL");
		return;
	}

	g_variant_get((GVariant *)user_data,
		"(uu)",
		(guint *)&callback,
		(guint *)&user_param);

	if (callback != NULL) {
		uint8_t *buffer = NULL;
		int length = 0;

		if (result == NET_NFC_OK && data != NULL) {
			buffer = net_nfc_get_data_buffer(data);
			length = net_nfc_get_data_length(data);
		}

		callback(nfc_common_convert_error_code(__func__, result),
			buffer,
			length,
			user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_read_block(nfc_tag_h tag,
	int block_index,
	nfc_mifare_read_block_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_mifare_read(
				handle,
				block_index,
				_mifare_read_block_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_mifare_read_page(nfc_tag_h tag,
	int page_index,
	nfc_mifare_read_page_completed_cb callback,
	void *user_data)
{
	int ret;
	GVariant *parameter;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);

	parameter = g_variant_new("(uu)",
		GPOINTER_TO_UINT(callback),
		GPOINTER_TO_UINT(user_data));
	if (parameter != NULL) {
		/* FIXME : not implemented */
//		ret = net_nfc_client_mifare_read_block(tag,
//			page_index,
//			_mifare_read_page_cb,
//			parameter);
//		if (ret != NET_NFC_OK) {
			g_variant_unref(parameter);
			ret = NET_NFC_OK;
//		}
	} else {
		ret = NET_NFC_ALLOC_FAIL;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_write_block_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_write_block_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_write_block(nfc_tag_h tag,
	int block_index,
	unsigned char *buffer,
	int buffer_size,
	nfc_mifare_write_block_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h block_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(buffer == NULL);
	CHECK_INVALID(buffer_size <= 0);
	CHECK_ACTIVATED();

	ret = net_nfc_create_data(&block_data, buffer, buffer_size);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag,
			&handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_mifare_write_block(
					handle,
					block_index,
					block_data,
					_mifare_write_block_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(block_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_write_page_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_write_page_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_write_page(nfc_tag_h tag,
	int page_index,
	unsigned char *buffer,
	int buffer_size,
	nfc_mifare_write_page_completed_cb callback,
	void *user_data)
{
	int ret;
	data_h block_data = NULL;

	LOG_BEGIN();
	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_INVALID(buffer == NULL);
	CHECK_INVALID(buffer_size <= 0);
	CHECK_ACTIVATED();

	ret = net_nfc_create_data(&block_data, buffer, buffer_size);
	if (ret == NET_NFC_OK) {
		net_nfc_target_handle_h handle = NULL;

		ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag,
			&handle);
		if (ret == NET_NFC_OK) {
			GVariant *parameter;

			parameter = g_variant_new("(uu)",
				GPOINTER_TO_UINT(callback),
				GPOINTER_TO_UINT(user_data));
			if (parameter != NULL) {
				ret = net_nfc_client_mifare_write_page(
					handle,
					page_index,
					block_data,
					_mifare_write_page_cb,
					parameter);
				if (ret != NET_NFC_OK) {
					g_variant_unref(parameter);
				}
			} else {
				ret = NET_NFC_ALLOC_FAIL;
			}
		} else {
			LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
		}

		net_nfc_free_data(block_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_increment_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_increment_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_increment(nfc_tag_h tag,
	int block_index,
	int value,
	nfc_mifare_increment_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_mifare_increment(
				handle,
				block_index,
				value,
				_mifare_increment_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_decrement_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_decrement_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_decrement(nfc_tag_h tag,
	int block_index,
	int value,
	nfc_mifare_decrement_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_mifare_decrement(
				handle,
				block_index,
				value,
				_mifare_decrement_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_transfer_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_transfer_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_transfer(nfc_tag_h tag,
	int block_index,
	nfc_mifare_transfer_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_mifare_transfer(
				handle,
				block_index,
				_mifare_transfer_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

static void _mifare_restore_cb(net_nfc_error_e result, void *user_data)
{
	nfc_mifare_restore_completed_cb callback;
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
		callback(nfc_common_convert_error_code(__func__, result), user_param);
	}

	g_variant_unref((GVariant *)user_data);
}

int nfc_mifare_restore(nfc_tag_h tag,
	int block_index,
	nfc_mifare_restore_completed_cb callback,
	void *user_data)
{
	int ret;
	net_nfc_target_handle_h handle = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(tag == NULL);
	CHECK_ACTIVATED();

	ret = net_nfc_get_tag_handle((net_nfc_target_info_h)tag, &handle);
	if (ret == NET_NFC_OK) {
		GVariant *parameter;

		parameter = g_variant_new("(uu)",
			GPOINTER_TO_UINT(callback),
			GPOINTER_TO_UINT(user_data));
		if (parameter != NULL) {
			ret = net_nfc_client_mifare_restore(
				handle,
				block_index,
				_mifare_restore_cb,
				parameter);
			if (ret != NET_NFC_OK) {
				g_variant_unref(parameter);
			}
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	} else {
		LOG_ERR("net_nfc_get_tag_handle failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_barcode_get_barcode(unsigned char **barcode, int *barcode_len)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_TAG_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(barcode == NULL);
	CHECK_INVALID(barcode_len == NULL);

	*barcode_len = 0;

	ret = net_nfc_client_barcode_get_barcode_sync(barcode, barcode_len);

	return nfc_common_convert_error_code(__func__, ret);
}
