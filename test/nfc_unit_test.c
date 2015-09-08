#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <nfc.h>

#define BUFFER_LEN 10
#define PRT(format, args...) printf("%s:%d() "format, __FUNCTION__, __LINE__, ##args)
#define TC_PRT(format, args...) PRT(format"\n", ##args)


GMainLoop *main_loop = NULL;

typedef struct {
	const char *tc_name;
	int tc_code;
} tc_table_t;

tc_table_t tc_table[] = {
	/* manage api*/
	{"nfc_manager_initialize" ,1}, //OK
	{"nfc_snep_register_server", 2},

    /* -----------*/
    {"Finish"               , 0x00ff},
    {NULL                   , 0x0000},
};

void tc_usage_print(void)
{
	int i = 0;

	while (tc_table[i].tc_name)
	{
		if (tc_table[i].tc_code != 0x00ff)
		{
			TC_PRT("Key %d : usage %s", tc_table[i].tc_code, tc_table[i].tc_name);
		}
		else
		{
         TC_PRT("Key %d : usage %s\n\n", 0x00ff, tc_table[i].tc_name);
		}

		i++;
	}
}


void _nfc_snep_event_cb(nfc_p2p_snep_h handle, nfc_snep_event_e event, nfc_error_e result, nfc_ndef_message_h msg, void *user_data)
{
	TC_PRT("Inside _nfc_snep_event_cb");
	switch(event)
	{
		case NFC_SNEP_EVENT_STOP:
			TC_PRT("NFC_SNEP_EVENT_STOP");
			break;
		case NFC_SNEP_EVENT_START:
			TC_PRT("NFC_SNEP_EVENT_START");
			break;
		case NFC_SNEP_EVENT_GET:
			TC_PRT("NFC_SNEP_EVENT_GET");
			break;
		case NFC_SNEP_EVENT_PUT:
			TC_PRT("NFC_SNEP_EVENT_PUT");
			break;
		case NFC_SNEP_EVENT_REGISTER:
			TC_PRT("NFC_SNEP_EVENT_REGISTER");
			break;
		case NFC_SNEP_EVENT_UNREGISTER:
			TC_PRT("NFC_SNEP_EVENT_UNREGISTER");
			break;
	}
}

void _nfc_p2p_target_discovered_cb(nfc_discovered_type_e type, nfc_p2p_target_h target, void *user_data)
{
	int result;

	TC_PRT("Inside server");
	result = nfc_snep_register_server("default", 4, _nfc_snep_event_cb, NULL);
	TC_PRT("nfc_snep_register_server %d", result);

	result = nfc_snep_start_server(target, "default", 4, _nfc_snep_event_cb, NULL);
	TC_PRT("nfc_snep_start_server %d", result);
}

int test_input_callback(void *data)
{
	long test_id = (long)data;

	switch (test_id) {
	case 0x00ff:
		TC_PRT("Finished");
		g_main_loop_quit(main_loop);
		break;
	case 1: //nfc_manager_initialize
		{
			int ret;
			ret = nfc_manager_initialize();

			if(ret == NFC_ERROR_NONE)
				TC_PRT("nfc initialize success");
			else
				TC_PRT("nfc initialize failed");
		}
		break;
	case 2: //TBT - snep behavior
		{
			int ret;
			ret = nfc_manager_initialize();

			if(ret == NFC_ERROR_NONE)
			{
				TC_PRT("register cb");
				nfc_manager_set_p2p_target_discovered_cb(_nfc_p2p_target_discovered_cb, NULL);
			}
		}
	case 3: //nfc_snep_register_server
		{
			int ret;
			ret = nfc_snep_register_server("default", 4, NULL, NULL);

			if(ret == NFC_ERROR_NONE)
				TC_PRT("success");
			else
				TC_PRT("failed");
		}
	default:
		break;
	}

    return 0;
}

static gboolean key_event_cb(GIOChannel *chan,
                GIOCondition cond,
                gpointer data)
{
	char buf[BUFFER_LEN] = { 0 };

	gsize len = 0;
	long test_id;

	memset(buf, 0, sizeof(buf));

	if (g_io_channel_read_chars(chan, buf, sizeof(buf), &len, NULL) == G_IO_STATUS_ERROR)
		return FALSE;

	tc_usage_print();
	test_id = atoi(buf);

	if (test_id)
		g_idle_add(test_input_callback, (void *)test_id);

	return TRUE;
}


int main(int argc, char ** argv)
{
	GIOChannel *key_io;

//#if !GLIB_CHECK_VERSION(2,35,0)
//   g_type_init();
//#endif

	key_io = g_io_channel_unix_new(fileno(stdin));

	g_io_channel_set_encoding(key_io, NULL, NULL);
	g_io_channel_set_flags(key_io, G_IO_FLAG_NONBLOCK, NULL);

	g_io_add_watch(key_io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
		key_event_cb, NULL);

	g_io_channel_unref(key_io);

	main_loop = g_main_loop_new(NULL, FALSE);

	g_main_loop_run(main_loop);

	return 0;
}
