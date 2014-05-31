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

#include <tet_api.h>
#include <nfc.h>

enum {
	POSITIVE_TC_IDX = 0x01,
	NEGATIVE_TC_IDX,
};

#define MY_ASSERT( fun , test , msg ) \
{\
	if( !test ) \
		dts_fail(fun , msg ); \
}


static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void nfc_manager_set_activation_changed_cb_p(void);
static void nfc_manager_set_activation_changed_cb_n(void);
static void nfc_manager_set_activation_p(void);
static void nfc_manager_set_activation_n(void);
static void nfc_manager_initialize_p(void);
static void nfc_manager_initialize_n(void);
static void nfc_manager_deinitialize_p(void);
static void nfc_manager_deinitialize_n(void);
static void nfc_manager_set_tag_discovered_cb_p(void);
static void nfc_manager_set_tag_discovered_cb_n(void);
static void nfc_manager_set_ndef_discovered_cb_p(void);
static void nfc_manager_set_ndef_discovered_cb_n(void);
static void nfc_manager_set_p2p_target_discovered_cb_p(void);
static void nfc_manager_set_p2p_target_discovered_cb_n(void);
static void nfc_manager_set_se_event_cb_p(void);
static void nfc_manager_set_se_event_cb_n(void);
static void nfc_manager_set_se_transaction_event_cb_p(void);
static void nfc_manager_set_se_transaction_event_cb_n(void);
static void nfc_manager_set_system_handler_enable_p(void);
static void nfc_manager_set_system_handler_enable_n(void);


void _activation_changed_cb(bool activated , void *user_data);
void _activation_completed_cb(int error, void *user_data);
void utc_test_cb(void * user_data);





struct tet_testlist tet_testlist[] = {
	{ nfc_manager_set_activation_changed_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_activation_changed_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_activation_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_activation_n , NEGATIVE_TC_IDX },
	{ nfc_manager_initialize_p , POSITIVE_TC_IDX },
	{ nfc_manager_initialize_n , NEGATIVE_TC_IDX },
	{ nfc_manager_deinitialize_p , POSITIVE_TC_IDX },
	{ nfc_manager_deinitialize_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_tag_discovered_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_tag_discovered_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_ndef_discovered_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_ndef_discovered_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_p2p_target_discovered_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_p2p_target_discovered_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_se_event_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_se_event_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_se_transaction_event_cb_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_se_transaction_event_cb_n , NEGATIVE_TC_IDX },
	{ nfc_manager_set_system_handler_enable_p , POSITIVE_TC_IDX },
	{ nfc_manager_set_system_handler_enable_n , NEGATIVE_TC_IDX },

	{ NULL, 0 },
};

//this method is called only once in start
static void startup(void)
{
	/* start of TC */
}

static void cleanup(void)
{
	/* end of TC */
}

void _activation_changed_cb(bool activated , void *user_data)
{
	if( activated == true)
	{
	}
	else if( activated == false)
	{
	}
}

void  _activation_completed_cb(int error, void *user_data)
{
	error = 0;
	return error;
}

void utc_test_cb(void *user_data)
{
	return true;
}


static void nfc_manager_set_activation_changed_cb_p(void)
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_activation_changed_cb(_activation_changed_cb , NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_activation_changed_cb_p is faild");
}

static void nfc_manager_set_activation_changed_cb_n(void)
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_activation_changed_cb(NULL , NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_activation_changed_cb_n not allow null");
}

static void nfc_manager_set_activation_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_activation(1, _activation_completed_cb, NULL);

	dts_pass(__func__, "PASS");
}

static void nfc_manager_set_activation_n()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_activation(1, NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void nfc_manager_initialize_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_initialize(NULL, NULL);

	nfc_manager_deinitialize();

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_initialize_p is faild");
}

static void nfc_manager_initialize_n()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_initialize(NULL, NULL);

	dts_pass(__func__, "PASS");
}

static void nfc_manager_deinitialize_p()
{
	int ret = NFC_ERROR_NONE;

	nfc_manager_initialize(NULL, NULL);

	ret = nfc_manager_deinitialize();

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_initialize_p is faild");
}

static void nfc_manager_deinitialize_n()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_deinitialize();

	dts_pass(__func__, "PASS");
}

static void nfc_manager_set_tag_discovered_cb_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_tag_discovered_cb(utc_test_cb, NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_tag_discovered_cb_p is faild");
}

static void nfc_manager_set_tag_discovered_cb_n()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_tag_discovered_cb(NULL, NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_tag_discovered_cb_n not allow null");
}

static void nfc_manager_set_ndef_discovered_cb_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_ndef_discovered_cb(utc_test_cb , NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_ndef_discovered_cb_p is faild");
}

static void nfc_manager_set_ndef_discovered_cb_n()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_ndef_discovered_cb(NULL, NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_ndef_discovered_cb_n not allow null");
}

static void nfc_manager_set_p2p_target_discovered_cb_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_p2p_target_discovered_cb(utc_test_cb , NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_p2p_target_discovered_cb_p is faild");
}

static void nfc_manager_set_p2p_target_discovered_cb_n()
{
	int ret;

	ret = nfc_manager_set_p2p_target_discovered_cb(NULL, NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_p2p_target_discovered_cb_n not allow null");
}

static void nfc_manager_set_se_event_cb_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_se_event_cb(utc_test_cb , NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_se_event_cb_p is faild");
}

static void nfc_manager_set_se_event_cb_n ()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_se_event_cb(NULL, NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_se_event_cb_n not allow null");
}

static void nfc_manager_set_se_transaction_event_cb_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_se_transaction_event_cb(utc_test_cb , NULL);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_se_transaction_event_cb_p is faild");
}

static void nfc_manager_set_se_transaction_event_cb_n ()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_se_transaction_event_cb(NULL, NULL);

	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_manager_set_se_transaction_event_cb_n not allow null");
}

static void nfc_manager_set_system_handler_enable_p()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_system_handler_enable(true);

	dts_pass(__func__, "PASS");

}

static void nfc_manager_set_system_handler_enable_n ()
{
	int ret = NFC_ERROR_NONE;

	ret = nfc_manager_set_system_handler_enable(NULL);

	dts_pass(__func__, "PASS");
}
