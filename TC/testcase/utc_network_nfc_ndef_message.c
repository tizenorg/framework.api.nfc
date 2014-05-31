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

static void utc_nfc_ndef_message_create_p(void);
static void utc_nfc_ndef_message_create_n(void);
static void utc_nfc_ndef_message_create_from_rawdata_p(void);
static void utc_nfc_ndef_message_create_from_rawdata_n(void);
static void utc_nfc_ndef_message_destroy_p(void);
static void utc_nfc_ndef_message_destroy_n(void);
static void utc_nfc_ndef_message_get_record_count_p(void);
static void utc_nfc_ndef_message_get_record_count_n(void);
static void utc_nfc_ndef_message_get_rawdata_p(void);
static void utc_nfc_ndef_message_get_rawdata_n(void);
static void utc_nfc_ndef_message_append_record_p(void);
static void utc_nfc_ndef_message_append_record_n(void);
static void utc_nfc_ndef_message_insert_record_p(void);
static void utc_nfc_ndef_message_insert_record_n(void);
static void utc_nfc_ndef_message_remove_record_p(void);
static void utc_nfc_ndef_message_remove_record_n(void);
static void utc_nfc_ndef_message_get_record_p(void);
static void utc_nfc_ndef_message_get_record_n(void);


struct tet_testlist tet_testlist[] = {
	{ utc_nfc_ndef_message_create_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_create_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_create_from_rawdata_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_create_from_rawdata_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_destroy_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_destroy_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_record_count_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_record_count_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_rawdata_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_rawdata_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_append_record_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_append_record_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_insert_record_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_insert_record_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_remove_record_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_remove_record_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_record_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_message_get_record_n , NEGATIVE_TC_IDX },

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


static void utc_nfc_ndef_message_create_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	ret = nfc_ndef_message_create(&message);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_create_n(void)
{
	int ret ;
	ret = nfc_ndef_message_create(NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_create_from_rawdata_p(void)
{
	int ret ;
	unsigned char *buffer;
	uint32_t size;
	nfc_ndef_message_h message;
	nfc_ndef_message_h message2;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	nfc_ndef_message_append_record(message, record1);
	nfc_ndef_message_get_rawdata(message, &buffer, &size);
	ret = nfc_ndef_message_create_from_rawdata(&message2, buffer,size);

	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message2);
	nfc_ndef_message_destroy(message);
	free(buffer);
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_create_from_rawdata_n(void)
{
	int ret ;
	ret = nfc_ndef_message_create_from_rawdata(NULL, NULL, 0);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_destroy_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	ret = nfc_ndef_message_create(&message);
	ret = nfc_ndef_message_destroy(message);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_destroy_n(void)
{
	int ret ;
	ret = nfc_ndef_message_destroy(NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_get_record_count_p(void)
{
	int ret ;
	int count;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	nfc_ndef_message_append_record(message, record1);
	ret = nfc_ndef_message_get_record_count(message, &count);

	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_get_record_count_n(void)
{
	int ret ;
	ret = nfc_ndef_message_get_record_count(NULL, NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_get_rawdata_p(void)
{
	int ret ;
	unsigned char *buffer;
	uint32_t size;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	nfc_ndef_message_append_record(message, record1);
	ret= nfc_ndef_message_get_rawdata(message, &buffer, &size);

	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	free(buffer);
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_get_rawdata_n(void)
{
	int ret ;
	ret = nfc_ndef_message_get_rawdata(NULL, NULL, NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_append_record_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	ret = nfc_ndef_message_append_record(message, record1);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_append_record_n(void)
{
	int ret ;
	ret = nfc_ndef_message_append_record(NULL, NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_insert_record_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	ret = nfc_ndef_message_insert_record(message,0, record1);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_insert_record_n(void)
{
	int ret ;
	ret = nfc_ndef_message_insert_record(NULL, 0 , NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_remove_record_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	ret = nfc_ndef_message_insert_record(message,0, record1);
	ret = nfc_ndef_message_remove_record(message, 0);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_remove_record_n(void)
{
	int ret ;
	ret = nfc_ndef_message_remove_record(NULL, 0);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}
static void utc_nfc_ndef_message_get_record_p(void)
{
	int ret ;
	nfc_ndef_message_h message;
	nfc_ndef_record_h record1, record2;
	ret = nfc_ndef_message_create(&message);
	nfc_ndef_record_create_text(&record1, "test", "en-US", NFC_ENCODE_UTF_8);
	ret = nfc_ndef_message_insert_record(message,0, record1);
	ret = nfc_ndef_message_get_record(message, 0, &record2);
	MY_ASSERT(__func__ , ret == NFC_ERROR_NONE , "FAIL");
	nfc_ndef_message_destroy(message);
	dts_pass(__func__, "PASS");

}
static void utc_nfc_ndef_message_get_record_n(void)
{
	int ret ;
	ret = nfc_ndef_message_get_record(NULL, 0 , NULL);
	MY_ASSERT(__func__,  ret != NFC_ERROR_NONE , "FAIL");
	dts_pass(__func__, "PASS");
}

