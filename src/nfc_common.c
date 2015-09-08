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

pid_t nfc_common_get_focus_app_pid()
{
	Ecore_X_Window focus;
	pid_t pid;

	ecore_x_init(NULL);

	focus = ecore_x_window_focus_get();
	if (ecore_x_netwm_pid_get(focus, &pid))
		return pid;

	return -1;
}

char * nfc_common_get_bt_address_string(data_h data)
{
	uint8_t *buffer;
	uint32_t length;

	if (data == NULL) {
		return NULL;
	}

	buffer = net_nfc_get_data_buffer(data);
	length = net_nfc_get_data_length(data);

	if (buffer == NULL || length < 6) {
		return NULL;
	}

	return g_strdup_printf("%02X:%02X:%02X:%02X:%02X:%02X",
		buffer[0],
		buffer[1],
		buffer[2],
		buffer[3],
		buffer[4],
		buffer[5]);
}

bool nfc_common_check_app_permission()
{
	pid_t focus_app_pid, current_app_pid;

	focus_app_pid = nfc_common_get_focus_app_pid();
	current_app_pid = getpgid(getpid());

	LOGD("[check app permission] focus_app_pid [%d], current_app_pid [%d]", focus_app_pid,
		current_app_pid);

	return (focus_app_pid == current_app_pid) ? true : false;
}

int nfc_common_convert_error_code(const char *func, int native_error_code)
{
	int error_code = NFC_ERROR_NONE;
	char *errorstr = NULL;

	switch (native_error_code)
	{
		case NET_NFC_OK:
			error_code = NFC_ERROR_NONE;
			errorstr = "ERROR_NONE";
			break;

		case NET_NFC_ALLOC_FAIL:
			error_code = NFC_ERROR_OUT_OF_MEMORY;
			errorstr = "OUT_OF_MEMORY";
			break;

		case NET_NFC_NOT_CONNECTED:
			error_code = NFC_ERROR_NO_DEVICE;
			errorstr = "NO_DEVICE";
			break;

		case NET_NFC_UNKNOWN_ERROR:
		case NET_NFC_THREAD_CREATE_FAIL:
		case NET_NFC_IPC_FAIL:
		case NET_NFC_BUFFER_TOO_SMALL:
		case NET_NFC_COMMUNICATE_WITH_CONTROLLER_FAILED:
		case NET_NFC_RF_ERROR:
		case NET_NFC_NOT_SUPPORTED:
		case NET_NFC_TAG_READ_FAILED:
		case NET_NFC_TAG_WRITE_FAILED:
		case NET_NFC_OPERATION_FAIL:
		case NET_NFC_INSUFFICIENT_STORAGE:
		case NET_NFC_NOT_INITIALIZED:
		case NET_NFC_NOT_REGISTERED:
			error_code = NFC_ERROR_OPERATION_FAILED;
			errorstr = "OPERATION_FAILED";
			break;

		case NET_NFC_SECURITY_FAIL:
			error_code = NFC_ERROR_SECURITY_RESTRICTED;
			errorstr = "SECURITY_RESTRICTED";
			break;

		case NET_NFC_INVALID_STATE:
			error_code = NFC_ERROR_ILLEGAL_STATE;
			errorstr = "ILLEGAL_STATE";
			break;

		case NET_NFC_OUT_OF_BOUND:
		case NET_NFC_NULL_PARAMETER:
		case NET_NFC_NOT_ALLOWED_OPERATION:
		case NET_NFC_LLCP_INVALID_SOCKET:
		case NET_NFC_NO_DATA_FOUND:
			error_code = NFC_ERROR_INVALID_PARAMETER;
			errorstr = "INVALID_PARAMETER";
			break;
		case NET_NFC_NDEF_RECORD_IS_NOT_EXPECTED_TYPE:
			error_code = NFC_ERROR_INVALID_RECORD_TYPE;
			errorstr = "INVALID_RECORD_TYPE";
			break;

		case NET_NFC_ALREADY_INITIALIZED:
		case NET_NFC_ALREADY_REGISTERED:
			error_code = NFC_ERROR_NONE;
			errorstr = "ERROR_NONE";
			break;

		case NET_NFC_RF_TIMEOUT:
			error_code = NFC_ERROR_TIMED_OUT;
			errorstr = "TIMED_OUT";
			break;
		case NET_NFC_INVALID_FORMAT:
		case NET_NFC_NDEF_TYPE_LENGTH_IS_NOT_OK:
		case NET_NFC_NDEF_ID_LENGTH_IS_NOT_OK:
		case NET_NFC_NDEF_BUF_END_WITHOUT_ME:
			error_code = NFC_ERROR_INVALID_NDEF_MESSAGE;
			errorstr = "INVALID_NDEF_MESSAGE";
			break;
		case NET_NFC_NO_NDEF_MESSAGE:
			error_code = NFC_ERROR_NO_NDEF_MESSAGE;
			errorstr = "NO_NDEF_MESSAGE";
			break;
		case NET_NFC_BUSY :
			error_code = NFC_ERROR_DEVICE_BUSY;
			errorstr = "DEVICE_BUSY";
			break;
		case NET_NFC_NO_NDEF_SUPPORT:
			error_code = NFC_ERROR_NOT_NDEF_FORMAT;
			errorstr = "NOT_SUPPORTED";
			break;
		case NET_NFC_PERMISSION_DENIED:
			error_code = NFC_ERROR_PERMISSION_DENIED;
			errorstr = "PERMISSION_DENIED";
			break;
		case NET_NFC_NOT_ACTIVATED:
			error_code = NFC_ERROR_NOT_ACTIVATED;
			errorstr = "NOT_ACTIVATED";
			break;
		default :
			error_code = NFC_ERROR_OPERATION_FAILED;
			errorstr = "OPERATION_FAILED";
	}

	if ( error_code != NFC_ERROR_NONE )
		LOGE("NFC func : %s, %s(0x%08x)", func, errorstr, error_code);

	return error_code;
}

bool nfc_common_is_initialized()
{
	return gdbus_nfc_context.initialized;
}

bool nfc_common_is_supported(char *str)
{
	int ret;
	bool is_supported;

	ret = system_info_get_platform_bool(str, &is_supported);

	if(ret != 0)
		return false;

	return is_supported;
}

int nfc_common_get_rawdata_size(nfc_ndef_message_h ndef_message,
	unsigned int *byte_size)
{
	int ret;

	LOG_BEGIN();

	CHECK_SUPPORTED(NFC_FEATURE);
	CHECK_INIT();
	CHECK_INVALID(ndef_message == NULL);
	CHECK_INVALID(byte_size == NULL);

	ret = net_nfc_get_ndef_message_byte_length(ndef_message,
		(unsigned int *)byte_size);

	return nfc_common_convert_error_code(__func__, ret);
}

