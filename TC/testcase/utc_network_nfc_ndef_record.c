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
static void startup(void);
static void cleanup(void);

void (*tet_startup)(void) = startup;
void (*tet_cleanup)(void) = cleanup;

static void utc_nfc_ndef_record_create_p(void);
static void utc_nfc_ndef_record_create_n(void);
static void utc_nfc_ndef_record_create_text_p(void);
static void utc_nfc_ndef_record_create_text_n(void);
static void utc_nfc_ndef_record_create_uri_p(void);
static void utc_nfc_ndef_record_create_uri_n(void);
static void utc_nfc_ndef_record_create_mime_p(void);
static void utc_nfc_ndef_record_create_mime_n_1(void);
static void utc_nfc_ndef_record_create_mime_n_2(void);
static void utc_nfc_ndef_record_create_mime_n_3(void);
static void utc_nfc_ndef_record_destroy_p(void);
static void utc_nfc_ndef_record_destroy_n(void);
static void utc_nfc_ndef_record_set_id_p(void);
static void utc_nfc_ndef_record_set_id_n(void);
static void utc_nfc_ndef_record_get_id_p(void);
static void utc_nfc_ndef_record_get_id_n(void);
static void utc_nfc_ndef_record_get_payload_p(void);
static void utc_nfc_ndef_record_get_payload_n(void);
static void utc_nfc_ndef_record_get_type_p(void);
static void utc_nfc_ndef_record_get_type_n(void);
static void utc_nfc_ndef_record_get_tnf_p(void);
static void utc_nfc_ndef_record_get_tnf_n(void);
static void utc_nfc_ndef_record_get_text_p(void);
static void utc_nfc_ndef_record_get_text_n(void);
static void utc_nfc_ndef_record_get_langcode_p(void);
static void utc_nfc_ndef_record_get_langcode_n(void);
static void utc_nfc_ndef_record_get_encode_type_p(void);
static void utc_nfc_ndef_record_get_encode_type_n(void);
static void utc_nfc_ndef_record_get_uri_p(void);
static void utc_nfc_ndef_record_get_uri_n(void);
static void utc_nfc_ndef_record_get_mime_type_p(void);
static void utc_nfc_ndef_record_get_mime_type_n(void);

struct tet_testlist tet_testlist[] = {
	{ utc_nfc_ndef_record_create_p , POSITIVE_TC_IDX },
	{ utc_nfc_ndef_record_create_n , NEGATIVE_TC_IDX },
	{ utc_nfc_ndef_record_create_text_p, POSITIVE_TC_IDX },
	{ utc_nfc_ndef_record_create_text_n , NEGATIVE_TC_IDX},
	{ utc_nfc_ndef_record_create_uri_p, 1},
	{ utc_nfc_ndef_record_create_uri_n, 2 },
	{ utc_nfc_ndef_record_create_mime_p, 1},
	{ utc_nfc_ndef_record_create_mime_n_1, 2 },
	{ utc_nfc_ndef_record_create_mime_n_2, 2 },
	{ utc_nfc_ndef_record_create_mime_n_3, 2 },
	{ utc_nfc_ndef_record_destroy_p, 1},
	{ utc_nfc_ndef_record_destroy_n, 2},
	{ utc_nfc_ndef_record_set_id_p, 1 },
	{ utc_nfc_ndef_record_set_id_n, 2 },
	{ utc_nfc_ndef_record_get_id_p, 1 },
	{ utc_nfc_ndef_record_get_id_n, 2 },
	{ utc_nfc_ndef_record_get_payload_p, 1},
	{ utc_nfc_ndef_record_get_payload_n, 2},
	{ utc_nfc_ndef_record_get_type_p, 1},
	{ utc_nfc_ndef_record_get_type_n, 2},
	{ utc_nfc_ndef_record_get_tnf_p, 1},
	{ utc_nfc_ndef_record_get_tnf_n, 2},
	{ utc_nfc_ndef_record_get_text_p, 1},
	{ utc_nfc_ndef_record_get_text_n, 2},
	{ utc_nfc_ndef_record_get_langcode_p, 1},
	{ utc_nfc_ndef_record_get_langcode_n, 2},
	{ utc_nfc_ndef_record_get_encode_type_p, 1},
	{ utc_nfc_ndef_record_get_encode_type_n, 2},
	{ utc_nfc_ndef_record_get_uri_p, 1},
	{ utc_nfc_ndef_record_get_uri_n, 2},
	{ utc_nfc_ndef_record_get_mime_type_p, 1},
	{ utc_nfc_ndef_record_get_mime_type_n, 2},
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
static void utc_nfc_ndef_record_create_p(void)
{
	int ret=0;
	nfc_ndef_record_h record;
	unsigned char testbuffer[]  = "TEST";

	ret = nfc_ndef_record_create(&record, NFC_RECORD_TNF_WELL_KNOWN, testbuffer,1, testbuffer, 4, testbuffer, 4);
	if( ret == 0 )
		nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_create is faild");
}

static void utc_nfc_ndef_record_create_n(void)
{
	int ret=0;
	unsigned char testbuffer[]  = "TEST";

	ret = nfc_ndef_record_create(NULL, NFC_RECORD_TNF_WELL_KNOWN, testbuffer,1, testbuffer, 4, testbuffer, 4);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");
}
static void utc_nfc_ndef_record_create_text_p(void)
{
	int ret = 0;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	if( ret == 0 )
		nfc_ndef_record_destroy(record);

	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_create_text is faild");
}
static void utc_nfc_ndef_record_create_text_n(void)
{
	int ret = 0;
	ret = nfc_ndef_record_create_text(NULL, "test", "en-US", NFC_ENCODE_UTF_8 );
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_create_uri_p(void)
{
	int ret = 0;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_uri(&record , "http://test.com");
	if( ret == 0)
		nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_create_uri is faild");
}
static void utc_nfc_ndef_record_create_uri_n(void)
{
	int ret = 0;
	ret = nfc_ndef_record_create_uri(NULL , "http://test.com");
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}

static void utc_nfc_ndef_record_create_mime_p(void)
{
    int ret = NFC_ERROR_NONE;
    nfc_ndef_record_h record;

    ret = nfc_ndef_record_create_mime(&record, "text/plain", (unsigned char*)"the text record", sizeof("the text record"));
    if( ret == NFC_ERROR_NONE)
        nfc_ndef_record_destroy(record);
    dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_create_mime is faild");
}

static void utc_nfc_ndef_record_create_mime_n_1(void)
{
    int ret = NFC_ERROR_NONE;

    ret = nfc_ndef_record_create_mime(NULL, "text/plain", (unsigned char*)"the text record", sizeof("the text record"));
    dts_check_eq(__func__, ret, NFC_ERROR_INVALID_PARAMETER, "nfc_ndef_record_h null not allowed");
}

static void utc_nfc_ndef_record_create_mime_n_2(void)
{
    int ret = NFC_ERROR_NONE;
    nfc_ndef_record_h record;

    ret = nfc_ndef_record_create_mime(&record, NULL, (unsigned char*)"the text record", sizeof("the text record"));
    if( ret == NFC_ERROR_NONE)
        nfc_ndef_record_destroy(record);

    dts_check_eq(__func__, ret, NFC_ERROR_INVALID_PARAMETER, "mime_type null not allowed");
}

static void utc_nfc_ndef_record_create_mime_n_3(void)
{
    int ret = NFC_ERROR_NONE;
    nfc_ndef_record_h record;

    ret = nfc_ndef_record_create_mime(&record, "text/plain", NULL, sizeof("the text record"));
    if( ret == NFC_ERROR_NONE)
        nfc_ndef_record_destroy(record);

    dts_check_eq(__func__, ret, NFC_ERROR_INVALID_PARAMETER, "data null not allowed");
}

static void utc_nfc_ndef_record_destroy_p(void)
{
	int ret = 0;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	if( ret != 0){
			dts_fail(__func__, "can't create record\n");
	}
	ret = nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_destroy is faild");
}
static void utc_nfc_ndef_record_destroy_n(void)
{
	int ret = 0;
	ret = nfc_ndef_record_destroy(NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");
}
static void utc_nfc_ndef_record_set_id_p(void)
{
	int ret = 0;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_set_id(record, (unsigned char *)"test", 4);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_set_id is faild");
}
static void utc_nfc_ndef_record_set_id_n(void)
{
	int ret;
	ret = nfc_ndef_record_set_id(NULL, (unsigned char *)"test", 4);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");
}
static void utc_nfc_ndef_record_get_id_p(void)
{
	int ret = 0;
	int size;
	nfc_ndef_record_h record;
	unsigned char *id;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_set_id(record, (unsigned char *)"test", 4);
	ret = nfc_ndef_record_get_id(record, &id, &size);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_id is faild");

}
static void utc_nfc_ndef_record_get_id_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_id(NULL,NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");
}
static void utc_nfc_ndef_record_get_payload_p(void)
{
	int ret = 0;
	uint32_t size;
	nfc_ndef_record_h record;
	unsigned char *payload;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_payload(record, &payload, &size);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_payload is faild");
}
static void utc_nfc_ndef_record_get_payload_n(void)
{
	int ret;
	ret = nfc_ndef_record_set_id(NULL, (unsigned char *)"test", 4);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_type_p(void)
{
	int ret = 0;
	int size;
	nfc_ndef_record_h record;
	unsigned char *data;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_type(record, &data, &size);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_type is faild");
}
static void utc_nfc_ndef_record_get_type_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_type(NULL, NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_tnf_p(void)
{
	int ret = 0;

	nfc_ndef_record_h record;
	nfc_record_tnf_e tnf;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_tnf(record, &tnf);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_tnf is faild");
}
static void utc_nfc_ndef_record_get_tnf_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_tnf(NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_text_p(void)
{
	int ret = 0;
	char *text;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_text(record, &text);
	free(text);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_tnf is faild");

}
static void utc_nfc_ndef_record_get_text_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_text(NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_langcode_p(void)
{
	int ret = 0;
	char *text;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_langcode(record, &text);
	free(text);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_tnf is faild");

}
static void utc_nfc_ndef_record_get_langcode_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_langcode(NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_encode_type_p(void)
{
	int ret = 0;
	nfc_encode_type_e type;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_text(&record, "test", "en-US", NFC_ENCODE_UTF_8 );
	ret = nfc_ndef_record_get_encode_type(record, &type);
	nfc_ndef_record_destroy(record);
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_encode_type is faild");

}
static void utc_nfc_ndef_record_get_encode_type_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_encode_type(NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}
static void utc_nfc_ndef_record_get_uri_p(void)
{
	int ret = 0;
	char *uri;
	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_uri(&record, "http://test.com");
	ret = nfc_ndef_record_get_uri(record, &uri);
	if(ret == 0 ){
		free(uri);
		nfc_ndef_record_destroy(record);
	}
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_uri is faild");
}
static void utc_nfc_ndef_record_get_uri_n(void)
{
	int ret;
	ret = nfc_ndef_record_get_uri(NULL, NULL);
	dts_check_ne(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_h not allow null");

}

static void utc_nfc_ndef_record_get_mime_type_p(void)
{
	int ret = NFC_ERROR_NONE;
	char *mime_type;

	nfc_ndef_record_h record;
	ret = nfc_ndef_record_create_mime(&record, "text/plain", (unsigned char*)"the text record", sizeof("the text record"));
	ret = nfc_ndef_record_get_mime_type(record, &mime_type);
	if(ret == NFC_ERROR_NONE ){
		free(mime_type);
		nfc_ndef_record_destroy(record);
	}
	dts_check_eq(__func__, ret, NFC_ERROR_NONE, "nfc_ndef_record_get_mime_type is faild");
}
static void utc_nfc_ndef_record_get_mime_type_n(void)
{
    int ret;

    ret = nfc_ndef_record_get_mime_type(NULL, NULL);
    dts_check_eq(__func__, ret, NFC_ERROR_INVALID_PARAMETER, "nfc_ndef_record_h not allow null");
}
