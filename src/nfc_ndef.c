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
 * @brief RTD(Record type definition) Type - Smart Poster type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_SMART_POSTER_TYPE[2] = { 'S', 'p' };

/**
 * @brief  RTD(Record type definition) Type - Text type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_TEXT_TYPE[1] = { 'T' };
/**
 * @brief  RTD(Record type definition) Type - URI type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_URI_TYPE[1] = { 'U' };
/**
 * @brief  RTD(Record type definition) Type - Alternative Carrier type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_ALTERNATIVE_CARRIER_TYPE[2] = { 'a','c' };
/**
 * @brief  RTD(Record type definition) Type - Handover Carrier type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_HANDOVER_CARRIER_TYPE[2] = { 'H','c' };
/**
 * @brief  RTD(Record type definition) Type - Handover Request type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_HANDOVER_REQUEST_TYPE[2] = { 'H','r' };
/**
 * @brief  RTD(Record type definition) Type - Handover Select type.
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
const unsigned char NFC_RECORD_HANDOVER_SELECT_TYPE[2] = { 'H','s' };

int nfc_ndef_record_create(nfc_ndef_record_h *record,
	nfc_record_tnf_e tnf,
	const unsigned char *type,
	int type_size,
	const unsigned char *id,
	int id_size,
	const unsigned char *payload,
	unsigned int payload_size)
{
	int ret;
	data_h type_data = NULL;
	data_h id_data = NULL;
	data_h payload_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);

	net_nfc_create_data(&type_data, type, type_size);

	if (id != NULL && id_size > 0) {
		net_nfc_create_data(&id_data, id, id_size);
	}

	if (payload != NULL && payload_size > 0) {
		net_nfc_create_data(&payload_data, payload, payload_size);
	}

	ret = net_nfc_create_record(
		(ndef_record_h *)record,
		tnf,
		type_data,
		id_data,
		payload_data);

	if (payload_data != NULL) {
		net_nfc_free_data(payload_data);
	}

	if (id_data != NULL) {
		net_nfc_free_data(id_data);
	}

	net_nfc_free_data(type_data);

	return nfc_common_convert_error_code(__func__, ret);
}


int nfc_ndef_record_create_text(nfc_ndef_record_h *record,
	const char *text,
	const char *lang_code,
	nfc_encode_type_e encode)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(text == NULL);
	CHECK_INVALID(lang_code == NULL);

	ret = net_nfc_create_text_type_record(
		(ndef_record_h *)record,
		text,
		lang_code,
		encode);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_create_uri(nfc_ndef_record_h *record,
	const char *uri)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(uri == NULL);

	ret = net_nfc_create_uri_type_record(
		(ndef_record_h *)record,
		uri,
		NET_NFC_SCHEMA_FULL_URI);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_create_mime(nfc_ndef_record_h *record,
	const char *mime_type,
	const unsigned char *data,
	unsigned int data_size)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(mime_type == NULL);
	CHECK_INVALID(data == NULL);
	CHECK_INVALID(data_size <= 0);

	ret = nfc_ndef_record_create(record,
		NFC_RECORD_TNF_MIME_MEDIA,
		(unsigned char *)mime_type,
		strlen(mime_type),
		NULL,
		0,
		data,
		data_size);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_mime_type(nfc_ndef_record_h record,
	char **mime_type)
{
	int ret;
	nfc_record_tnf_e tnf;
	unsigned char *typename;
	int length;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(mime_type == NULL);

	if (nfc_ndef_record_get_tnf(record, &tnf) != NET_NFC_OK ||
		tnf != NFC_RECORD_TNF_MIME_MEDIA)
			{
		return NFC_ERROR_INVALID_RECORD_TYPE;
	}

	ret = nfc_ndef_record_get_type(record, &typename, &length);
	if (ret == NET_NFC_OK) {
		*mime_type = calloc(1, length + 1);
		if (*mime_type != NULL) {
			memcpy(*mime_type, typename, length);
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_destroy(nfc_ndef_record_h record)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);

	ret = net_nfc_free_record(record);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_set_id(nfc_ndef_record_h record,
	unsigned char *id,
	int id_size)
{
	int ret;
	data_h id_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(id == NULL);

	ret = net_nfc_create_data(&id_data, id, id_size);
	if (ret == NET_NFC_OK) {
		ret = net_nfc_set_record_id(record, id_data);

		net_nfc_free_data(id_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_payload(nfc_ndef_record_h record,
	unsigned char **payload,
	unsigned int *size)
{
	int ret;
	data_h payload_data;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(payload == NULL);
	CHECK_INVALID(size == NULL);

	*payload = NULL;
	*size = 0;

	ret = net_nfc_get_record_payload(record, &payload_data);
	if (ret == NET_NFC_OK) {
		*payload = net_nfc_get_data_buffer(payload_data);
		*size = net_nfc_get_data_length(payload_data);
	} else {
		*payload = NULL;
		*size = 0;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_type(nfc_ndef_record_h record,
	unsigned char **type,
	int *size)
{
	int ret;
	data_h type_data;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(type == NULL);
	CHECK_INVALID(size == NULL);

	*type = NULL;
	*size = 0;

	ret = net_nfc_get_record_type(record, &type_data);
	if (ret == NET_NFC_OK) {
		*type = net_nfc_get_data_buffer(type_data);
		*size = net_nfc_get_data_length(type_data);
	} else {
		*type = NULL;
		*size = 0;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_id(nfc_ndef_record_h record,
	unsigned char **id,
	int *size)
{
	int ret;
	data_h id_data;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(id == NULL);
	CHECK_INVALID(size == NULL);

	*id = NULL;
	*size = 0;

	ret = net_nfc_get_record_id(record, &id_data);
	if (ret == NET_NFC_OK) {
		*id = net_nfc_get_data_buffer(id_data);
		*size = net_nfc_get_data_length(id_data);
	} else {
		*id = NULL;
		*size = 0;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_tnf(nfc_ndef_record_h record, nfc_record_tnf_e *tnf)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(tnf == NULL);

	ret = net_nfc_get_record_tnf(record, (net_nfc_record_tnf_e *)tnf);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_text(nfc_ndef_record_h record, char **buffer)
{
	int ret;
	unsigned char* record_type = NULL;
	int type_size = 0;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(buffer == NULL);

	ret = nfc_ndef_record_get_type(record, &record_type, &type_size);

	if (ret == NFC_ERROR_NONE && record_type != NULL && type_size != 0 &&
				!strcmp((char*)record_type, "T"))
	{
		LOG_ERR("record type is T");
		ret = net_nfc_create_text_string_from_text_record(record, buffer);
	}
	else
	{
		LOG_ERR("record type is not T");
		return NFC_ERROR_INVALID_RECORD_TYPE;
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_langcode(nfc_ndef_record_h record, char **lang_code)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(lang_code == NULL);

	ret = net_nfc_get_languange_code_string_from_text_record(record, lang_code);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_encode_type(
	nfc_ndef_record_h record,
	nfc_encode_type_e *encode)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(encode == NULL);

	ret = net_nfc_get_encoding_type_from_text_record(
		record,
		(net_nfc_encode_type_e *)encode);

	/*	if( ret == NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE)
	 LOGE("%s reord type is not text type");*/

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_record_get_uri(nfc_ndef_record_h record, char **uri)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(record == NULL);
	CHECK_INVALID(uri == NULL);

	ret = net_nfc_create_uri_string_from_uri_record(record, uri);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_create(nfc_ndef_message_h *ndef_message)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);

	ret = net_nfc_create_ndef_message(ndef_message);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_create_from_rawdata(
	nfc_ndef_message_h *ndef_message,
	const unsigned char *rawdata,
	unsigned int rawdata_size)
{
	int ret;
	data_h rawdata_data = NULL;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(rawdata == NULL);
	CHECK_INVALID(rawdata_size <= 0);

	ret = net_nfc_create_data(&rawdata_data, rawdata, rawdata_size);
	if (ret == NET_NFC_OK) {
		ret = net_nfc_create_ndef_message_from_rawdata(
			(ndef_message_h *)ndef_message,
			rawdata_data);

		net_nfc_free_data(rawdata_data);
	} else {
		LOG_ERR("net_nfc_create_data failed, [%d]", ret);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_destroy(nfc_ndef_message_h ndef_message)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);

	ret = net_nfc_free_ndef_message(ndef_message);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_get_record_count(nfc_ndef_message_h ndef_message,
	int *count)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(count == NULL);

	ret = net_nfc_get_ndef_message_record_count(ndef_message, count);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_get_rawdata(nfc_ndef_message_h ndef_message,
	unsigned char **rawdata,
	unsigned int *rawdata_size)
{
	int ret;
	data_h rawdata_data;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(rawdata == NULL);
	CHECK_INVALID(rawdata_size == NULL);

	*rawdata = NULL;
	*rawdata_size = 0;

	ret = net_nfc_create_rawdata_from_ndef_message(ndef_message,
		&rawdata_data);
	if (ret == NET_NFC_OK) {
		uint8_t *buffer;
		uint32_t length;

		buffer = net_nfc_get_data_buffer(rawdata_data);
		length = net_nfc_get_data_length(rawdata_data);

		*rawdata = calloc(1, length);
		if (*rawdata != NULL) {
			memcpy(*rawdata, buffer, length);
			*rawdata_size = length;
		} else {
			ret = NET_NFC_ALLOC_FAIL;
		}

		net_nfc_free_data(rawdata_data);
	}

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_append_record(nfc_ndef_message_h ndef_message,
	nfc_ndef_record_h record)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(record == NULL);

	ret = net_nfc_append_record_to_ndef_message(ndef_message, record);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_insert_record(nfc_ndef_message_h ndef_message,
	int index,
	nfc_ndef_record_h record)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(record == NULL);

	ret = net_nfc_append_record_by_index(ndef_message, index, record);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_remove_record(nfc_ndef_message_h ndef_message,
	int index)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);

	ret = net_nfc_remove_record_by_index(ndef_message, index);

	return nfc_common_convert_error_code(__func__, ret);
}

int nfc_ndef_message_get_record(nfc_ndef_message_h ndef_message,
	int index,
	nfc_ndef_record_h *record)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(record == NULL);

	ret = net_nfc_get_record_by_index(ndef_message,
		index,
		(ndef_record_h*)record);

	return nfc_common_convert_error_code(__func__, ret);
}

