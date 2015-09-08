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


#ifndef __NFC_H__
#define __NFC_H__

#include <tizen.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file nfc.h
 * @brief This file contains the NFC API.
 */

#define NFC_ERROR_CLASS TIZEN_ERROR_NFC

/**
 * @brief Error codes reported by the NFC API.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum {
	NFC_ERROR_NONE = TIZEN_ERROR_NONE,	/**< Successful	*/
	NFC_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,	/**< Out of memory */
	NFC_ERROR_OPERATION_FAILED = NFC_ERROR_CLASS | 0x01,	/**< Operation failed*/
	NFC_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,	/**< Invalid parameter */
	NFC_ERROR_INVALID_NDEF_MESSAGE = NFC_ERROR_CLASS | 0x02,	/**< Invalid NDEF message */
	NFC_ERROR_INVALID_RECORD_TYPE  = NFC_ERROR_CLASS | 0x03,	/**< Invalid record type*/
	NFC_ERROR_TIMED_OUT = TIZEN_ERROR_TIMED_OUT,	/**< Timeout error, no answer */
	NFC_ERROR_DEVICE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,	/**< Previous operation is not finished still busy */
	NFC_ERROR_NO_DEVICE = NFC_ERROR_CLASS | 0x04, /**< no device */
	NFC_ERROR_NOT_ACTIVATED = NFC_ERROR_CLASS | 0x05, /**< NFC is not activated */
	NFC_ERROR_NOT_SUPPORTED = TIZEN_ERROR_NOT_SUPPORTED, /**< Not supported */
	NFC_ERROR_ALREADY_ACTIVATED = NFC_ERROR_CLASS | 0x06, /**< Already activated */
	NFC_ERROR_ALREADY_DEACTIVATED = NFC_ERROR_CLASS | 0x07, /**< Already deactivated */
	NFC_ERROR_READ_ONLY_NDEF = NFC_ERROR_CLASS | 0x08, /**< Read only tag */
	NFC_ERROR_NO_SPACE_ON_NDEF = NFC_ERROR_CLASS | 0x09, /**< No enough space on tag */
	NFC_ERROR_NO_NDEF_MESSAGE = NFC_ERROR_CLASS | 0x0a, /**< No NDEF Message on Tag */
	NFC_ERROR_NOT_NDEF_FORMAT = NFC_ERROR_CLASS | 0x0b, /**< Not NDEF format Tag */
	NFC_ERROR_SECURITY_RESTRICTED = NFC_ERROR_CLASS | 0x0c, /**<  Restricted by access control */
	NFC_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED, /**< Restricted by Smack */
	NFC_ERROR_ILLEGAL_STATE = NFC_ERROR_CLASS | 0x0d, /**<  The state is wrong */
	NFC_ERROR_NOT_INITIALIZED = NFC_ERROR_CLASS | 0x0e, /**< NFC is not initialized */
	NFC_ERROR_TAG_NOT_SUPPORTED = NFC_ERROR_CLASS | 0x0f, /**< Tag is not supported */
	NFC_ERROR_AID_ALREADY_REGISTERED = NFC_ERROR_CLASS | 0x10 /**< AID already registered (@b Since: 2.3.1) */
} nfc_error_e;

/**
 * @brief Enumerations for record TNF (Type Name Format)
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @details It is indicate format of type field
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
typedef enum {
	NFC_RECORD_TNF_EMPTY = 0x00,	/**< Empty */
	NFC_RECORD_TNF_WELL_KNOWN = 0x01,	/**< RTD(Record Type Definition) type format [NFC RTD] */
	NFC_RECORD_TNF_MIME_MEDIA= 0x02,	/**< MIME Media types in RFC 2046 [RFC 2046] */
	NFC_RECORD_TNF_URI = 0x03,	/**< Absolute URI as defined in RFC 3986 [RFC 3986] */
	NFC_RECORD_TNF_EXTERNAL_RTD = 0x04,	/**< NFC Forum external type [NFC RTD] */
	NFC_RECORD_TNF_UNKNOWN = 0x05,	/**< Unknown\n The payload type is unknown */
	NFC_RECORD_TNF_UNCHAGNED = 0x06,	/**< It means the payload is an intermediate or final chunk of a chunked NDEF Record */
} nfc_record_tnf_e;


/**
 * @brief Enumerations for NFC encode types
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
typedef enum {
	NFC_ENCODE_UTF_8 = 0x00,	/**< UTF-8 */
	NFC_ENCODE_UTF_16,	/**< UTF-16 */
} nfc_encode_type_e;

/**
 * @brief Enumerations for NFC tag types
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 */
typedef enum {
	NFC_UNKNOWN_TARGET = 0x00U,	/**< Unknown target */
	NFC_GENERIC_PICC,	/**< GENERIC PICC*/
	NFC_ISO14443_A_PICC,	/**< ISO14443_A PICC */
	NFC_ISO14443_4A_PICC,	/**< ISO14443_4A PICC */
	NFC_ISO14443_3A_PICC,	/**< ISO14443_3A PICC */
	NFC_MIFARE_MINI_PICC,	/**< MIFARE_MINI_PICC */
	NFC_MIFARE_1K_PICC,	/**< MIFARE_1K_PICC */
	NFC_MIFARE_4K_PICC,	/**< MIFARE_4K_PICC */
	NFC_MIFARE_ULTRA_PICC,	/**< MIFARE_ULTRA_PICC */
	NFC_MIFARE_DESFIRE_PICC,	/**< MIFARE_DESFIRE_PICC */
	NFC_ISO14443_B_PICC,	/**< ISO14443_B PICC */
	NFC_ISO14443_4B_PICC,	/**< ISO14443_4B PICC */
	NFC_ISO14443_BPRIME_PICC,	/**< ISO14443_BPRIME PICC */
	NFC_FELICA_PICC,	/**< FELICA PICC */
	NFC_JEWEL_PICC,	/**< JEWEL PICC */
	NFC_ISO15693_PICC,	/**< ISO15693 PICC */
	NFC_BARCODE_128_PICC, /**< BARCODE_128 PICC */
	NFC_BARCODE_256_PICC, /**< BARCODE_256 PICC */

	NFC_NFCIP1_TARGET,	/**< NFCIP1_TARGET */
	NFC_NFCIP1_INITIATOR,	/**< NFCIP1_INITIATOR */
} nfc_tag_type_e;

/**
 * @brief Enumerations for NFC Tag filter
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum {
	NFC_TAG_FILTER_ALL_DISABLE = 0x0000,	/**< All disable */
	NFC_TAG_FILTER_ISO14443A_ENABLE = 0x0001,	/**< ISO14443A enable */
	NFC_TAG_FILTER_ISO14443B_ENABLE = 0x0002,	/**< ISO14443B enable */
	NFC_TAG_FILTER_ISO15693_ENABLE = 0x0004,	/**< ISO15693 enable */
	NFC_TAG_FILTER_FELICA_ENABLE = 0x0008,	/**< FELICA enable */
	NFC_TAG_FILTER_JEWEL_ENABLE = 0x0010,	/**< JEWEL enable */
	NFC_TAG_FILTER_IP_ENABLE = 0x0020,	/**< IP enable */
	NFC_TAG_FILTER_ALL_ENABLE= ~0,	/**< All enable */
} nfc_tag_filter_e;

/**
 * @brief Enumerations for NFC discovered type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum {
	NFC_DISCOVERED_TYPE_ATTACHED,	/**< Attached, discovered, activated event*/
	NFC_DISCOVERED_TYPE_DETACHED,	/**< detached, disappeared, deactivated event*/
} nfc_discovered_type_e;

/**
 * @brief Enumerations for NFC Secure Element (SIM/UICC(Universal Integrated Circuit Card)) event
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum{
	NFC_SE_EVENT_START_TRANSACTION, /**< This event notifies the terminal host that it shall launch an application associated to an NFC application in a UICC(Universal Integrated Circuit Card) host. */
	NFC_SE_EVENT_END_TRANSACTION,	/**< This event notifies the terminal host that current transaction in process was ended. */
	NFC_SE_EVENT_CONNECTIVITY, /**< It's ready signal to communicate UICC(Universal Integrated Circuit Card) with terminal host. UICC(Universal Integrated Circuit Card) create pipe and open the pipe chanel. Then it sends the signal to terminal host or host controller. */
	NFC_SE_EVENT_FIELD_ON, /**< When the CLF(Contactless Front-end) detects a RF field, the card RF gate sends the event #NFC_SE_EVENT_FIELD_ON to the card application gate. When there are multiple open card RF gates the CLF shall send the #NFC_SE_EVENT_FIELD_ON on all open pipes to these gates.Next the CLF starts the initialization and anti-collision process as defined in ISO/IEC 14443-3 [6]*/
	NFC_SE_EVENT_FIELD_OFF,	/**< When the CLF(Contactless Front-end) detects that the RF field is off, the card RF gate shall send #NFC_SE_EVENT_FIELD_OFF to the card application gate. When there are multiple open card RF gates the CLF shall send the #NFC_SE_EVENT_FIELD_OFF to one gate only.*/
	NFC_SE_EVENT_TRANSACTION, /**< This event  notifies , external reader trys to access secure element */
	NFC_SE_EVENT_SE_TYPE_CHANGED, /**< This event notifies, changing the emulated secure element type */
	NFC_SE_EVENT_CARD_EMULATION_CHANGED, /**< This event notifies, changing the card emulation mode */
} nfc_se_event_e;

/**
 * @brief Enumerations for NFC Secure Element (SIM/UICC(Universal Integrated Circuit Card)) type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum{
	NFC_SE_TYPE_DISABLE = 0x00, /**< Disable card emulation */
	NFC_SE_TYPE_ESE = 0x01, /**< SmartMX type card emulation */
	NFC_SE_TYPE_UICC = 0x02, /**< UICC type card emulation */
	NFC_SE_TYPE_SDCARD = 0x03, /**< SDCARD card emulation (Not yet supported on Tizen) (@b Since: 2.3.1)  */
	NFC_SE_TYPE_HCE = 0x04 /**< Host based card emulation (@b Since: 2.3.1) */
} nfc_se_type_e;

/**
 * @brief Enumerations for NFC Card Emulation Mode type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 */
typedef enum{
	NFC_SE_CARD_EMULATION_MODE_OFF = 0x00, /**< Card Emulation mode OFF */
	NFC_SE_CARD_EMULATION_MODE_ON = 0x01, /**< Card Emulation mode ON */
} nfc_se_card_emulation_mode_type_e;

/**
 * @brief Enumerations for SNEP event
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 */
typedef enum {
	NFC_SNEP_EVENT_STOP = 0x00, /**< server or client stopped */
	NFC_SNEP_EVENT_START = 0x01, /**< server started or client connected */
	NFC_SNEP_EVENT_GET = 0x02, /**< server received get request */
	NFC_SNEP_EVENT_PUT = 0x03, /**< server received put request */
	NFC_SNEP_EVENT_REGISTER = 0x04, /**< service registered */
	NFC_SNEP_EVENT_UNREGISTER = 0x05, /**< service unregistered */
} nfc_snep_event_e;

/**
 * @brief Enumerations for SNEP request type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 */
typedef enum {
	NFC_SNEP_GET = 0x01, /**< get request */
	NFC_SNEP_PUT = 0x02, /**< put request */
} nfc_snep_type_e;

/**
 * @brief Enumerations for NFC Card Emulation Category type
 * @since_tizen 2.3.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 */
typedef enum{
	NFC_CARD_EMULATION_CATEGORY_PAYMENT = 0x01, /**< Category used for NFC payment services */
	NFC_CARD_EMULATION_CATEGORY_OTHER = 0x02, /**< Category that can be used for all other card emulation services */
} nfc_card_emulation_category_type_e;

/**
 * @brief Enumerations for NFC Card Emulation HCE event type
 * @since_tizen 2.3.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 */
typedef enum{
	NFC_HCE_EVENT_DEACTIVATED = 0x00, /**< HCE Deactivated */
	NFC_HCE_EVENT_ACTIVATED = 0x01, /**< HCE Activated */
	NFC_HCE_EVENT_APDU_RECEIVED = 0x02, /**< HCE APDU Received */
} nfc_hce_event_type_e;

/**
 * @brief The handle to the NDEF record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
typedef struct _ndef_record_s *nfc_ndef_record_h;

/**
 * @brief The handle to the NDEF message
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 */
typedef struct _ndef_message_s *nfc_ndef_message_h;

/**
 * @brief The handle to the NFC tag
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 */
typedef struct _net_nfc_target_info_s *nfc_tag_h;

/**
 * @brief The handle to NFC p2p target
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 */
typedef void *nfc_p2p_target_h;

/**
 * @brief The handle to NFC p2p snep instance
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 */
typedef struct _nfc_p2p_snep_s *nfc_p2p_snep_h;

/**
 * @brief The handle to NFC secure element instance
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 */
typedef void *nfc_se_h;

/**
 * @brief The default factory key.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @details The key is 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
extern const unsigned char NFC_TAG_MIFARE_KEY_DEFAULT[6];

/**
 * @brief The well-known key for tags formatted according to the MIFARE Application Directory (MAD) specification.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @details The key is 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
extern const unsigned char NFC_TAG_MIFARE_KEY_APPLICATION_DIRECTORY[6];

/**
 * @brief The well-known key for tags formatted according to the NDEF on Mifare Classic specification.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @details The key is 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 */
extern const unsigned char NFC_TAG_MIFARE_KEY_NFC_FORUM[6];


/**
 * @brief RTD(Record type definition) Type - Smart Poster type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_SMART_POSTER_TYPE[2];

/**
 * @brief  RTD(Record type definition) Type - Text type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_TEXT_TYPE[1];
/**
 * @brief  RTD(Record type definition) Type - URI type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_URI_TYPE[1];
/**
 * @brief  RTD(Record type definition) Type - Alternative Carrier type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_ALTERNATIVE_CARRIER_TYPE[2];
/**
 * @brief  RTD(Record type definition) Type - Handover Carrier type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_HANDOVER_CARRIER_TYPE[2];
/**
 * @brief  RTD(Record type definition) Type - Handover Request type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_HANDOVER_REQUEST_TYPE[2];
/**
 * @brief  RTD(Record type definition) Type - Handover Select type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 */
extern const unsigned char NFC_RECORD_HANDOVER_SELECT_TYPE[2];

/**
 * @brief Called after nfc_manager_set_activation() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @internal
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] error The result
 * @param [in] user_data The user data passed from the callback registration function
 *
 * @see nfc_manager_set_activation()
 */
typedef void (* nfc_activation_completed_cb)(nfc_error_e error, void *user_data);

/**
 * @brief Called when nfc activation state is changed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] activated The activation state
 * @param [in] user_data The user data passed from the callback registration function
 *
 * @see nfc_manager_set_activation_changed_cb()
 */
typedef void (*nfc_activation_changed_cb)(bool activated , void *user_data);

/**
 * @brief Called when an NFC tag appears or disappears
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks  The tag handle does not have detail target info when an NFC tag disappeared.\n
 * 	So then do not use tag functions which use tag handle.
 *
 * @param [in] type The discovered type attached or detached
 * @param [in] tag The handle to NFC tag
 * @param [in] user_data The user data passed from the callback registration function
 *
 * @see nfc_manager_set_tag_discovered_cb()
 * @see nfc_manager_unset_tag_discovered_cb()
 * @see nfc_manager_set_tag_filter()
 */
typedef void (* nfc_tag_discovered_cb)(nfc_discovered_type_e type, nfc_tag_h tag, void *user_data);

/**
 * @brief Called when an NDEF Message is discovered
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks @a message will be automatically destroyed when the callback function returns. (Do not release @a message.)
 *
 * @param [in] message The handle to NDEF message
 * @param [in] user_data The user data passed from the callback registration function
 *
 * @see nfc_manager_set_ndef_discovered_cb()
 * @see nfc_manager_unset_ndef_discovered_cb()
 */
typedef void (* nfc_ndef_discovered_cb)(nfc_ndef_message_h message, void *user_data);


/**
 * @brief Called once for each tag information.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @remarks @a key and value will be automatically destroyed when the callback function returns. (Do not release @a key and value.)
 *
 * @param[in] key The key of information
 * @param[in] value The value of information
 * @param[in] value_size The data size in bytes
 * @param[in] user_data The user data passed from the foreach function
 *
 * @return @c true to continue with the next iteration of the loop, \n @c false to break out of the loop.
 * @pre nfc_tag_foreach_information() invokes this callback.
 *
 * @see	nfc_tag_foreach_information()
 */

typedef bool (*nfc_tag_information_cb)(const char *key, const unsigned char *value, int value_size, void *user_data);


/**
 * @brief Called after nfc_tag_transceive() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @remarks @a buffer will be automatically destroyed when the callback function returns. (Do not release @a buffer.)
 *
 * @param [in] result The result of function call
 * @param [in] buffer The result data
 * @param [in] buffer_size The size of buffer in bytes
 * @param [in] user_data The user data passed from nfc_tag_transceive()
 *
 * @see nfc_tag_transceive()
 */
typedef void (* nfc_tag_transceive_completed_cb)(nfc_error_e result, unsigned char *buffer, int buffer_size, void *user_data);

/**
 * @brief Called after the nfc_tag_write_ndef() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] result The result of function call
 * @param [in] user_data The user data passed from nfc_manager_initialize()
 *
 * @see nfc_tag_write_ndef()
 */
typedef void (* nfc_tag_write_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after the nfc_tag_read_ndef() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @remarks @a message will be automatically destroyed when the callback function returns. (Do not release @a message.)
 *
 * @param [in] result The result of function call
 * @param [in] message The NDEF message
 * @param [in] user_data The user data passed from nfc_tag_read_ndef()
 *
 * @see nfc_tag_read_ndef()
 */
typedef void (* nfc_tag_read_completed_cb)(nfc_error_e result, nfc_ndef_message_h message, void *user_data);

/**
 * @brief   Called after the nfc_tag_format_ndef() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] result The result of function call
 * @param [in] user_data The user data passed from nfc_tag_format_ndef()
 *
 * @see nfc_tag_format_ndef()
 */
typedef void (* nfc_tag_format_completed_cb)(nfc_error_e result, void *user_data);


/**
 * @brief Called after nfc_mifare_authenticate_with_keyA() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_authenticate_with_keyA()
 * @param [in] user_data The user data passed from nfc_mifare_authenticate_with_keyA()
 *
 * @see nfc_mifare_authenticate_with_keyA()
 */
typedef void (* nfc_mifare_authenticate_with_keyA_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_authenticate_with_keyB() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of function call
 * @param [in] user_data The user data passed from nfc_mifare_authenticate_with_keyB()
 *
 * @see nfc_mifare_authenticate_with_keyB()
 */
typedef void (* nfc_mifare_authenticate_with_keyB_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_write_block() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_write_block()
 * @param [in] user_data The user data passed from nfc_mifare_write_block()
 *
 * @see nfc_mifare_write_block()
 */
typedef void (* nfc_mifare_write_block_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_write_page() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of function call
 * @param [in] user_data The user data passed from nfc_mifare_write_page()
 *
 * @see nfc_mifare_write_page()
 */
typedef void (* nfc_mifare_write_page_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_read_block() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @remarks @a buffer will be automatically destroyed when the callback function returns. (Do not release @a buffer.)
 *
 * @param [in] result The result of function call
 * @param [in] buffer The read buffer
 * @param [in] size The size of buffer in bytes
 * @param [in] user_data The user data passed from nfc_mifare_read_block()
 *
 * @see nfc_mifare_read_block()
 */
typedef void (* nfc_mifare_read_block_completed_cb)(nfc_error_e result, unsigned char *buffer, int bufer_size, void *user_data);

/**
 * @brief Called after nfc_mifare_read_page() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @remarks @a buffer will be automatically destroyed when the callback function returns. (Do not release @a buffer.)
 *
 * @param [in] result The result of nfc_mifare_read_page()
 * @param [in] buffer The read buffer
 * @param [in] size The size of read buffer in bytes
 * @param [in] user_data The user data passed from nfc_mifare_read_page()
 *
 * @see nfc_mifare_read_page()
 */
typedef void (* nfc_mifare_read_page_completed_cb)(nfc_error_e result, unsigned char *buffer, int bufer_size, void *user_data);

/**
 * @brief Called after nfc_mifare_increment() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_increment()
 * @param [in] user_data The user data passed from nfc_mifare_increment()
 *
 * @see nfc_mifare_increment()
 */
typedef void (* nfc_mifare_increment_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_decrement() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_decrement()
 * @param [in] user_data The user data passed from nfc_mifare_decrement()
 *
 * @see nfc_mifare_decrement()
 */
typedef void (* nfc_mifare_decrement_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_transfer() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_transfer()
 * @param [in] user_data The user data passed from nfc_mifare_transfer()
 *
 * @see nfc_mifare_transfer()
 */
typedef void (* nfc_mifare_transfer_completed_cb)(nfc_error_e result, void *user_data);

/**
 * @brief Called after nfc_mifare_restore() has completed
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 *
 * @param [in] result The result of nfc_mifare_restore()
 * @param [in] user_data The user data passed from nfc_mifare_restore()
 *
 * @see nfc_mifare_restore()
 */
typedef void (* nfc_mifare_restore_completed_cb)(nfc_error_e result, void *user_data);



/**
 * @brief Called when NFC peer-to-peer target appeared or disappeared
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] type The discovered type attached or detached
 * @param [in] target The handle to p2p target
 * @param [in] user_data The user data passed from nfc_manager_set_p2p_target_discovered_cb()
 *
 * @see nfc_manager_set_p2p_target_discovered_cb()
 * @see nfc_manager_unset_p2p_target_discovered_cb()
 */
typedef void (*nfc_p2p_target_discovered_cb)(nfc_discovered_type_e type, nfc_p2p_target_h target, void *user_data);

/**
 * @brief Called when receiving  Secure Element (SIM/UICC(Universal Integrated Circuit Card)) event.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] event The Secure Element event
 * @param [in] user_data The user data passed from nfc_manager_set_se_event_cb()
 *
 * @see nfc_manager_set_se_event_cb()
 * @see nfc_manager_unset_se_event_cb()
 */
typedef void (*nfc_se_event_cb)(nfc_se_event_e event , void *user_data);


/**
 * @brief Called when receiving Secure Element(SIM/UICC(Universal Integrated Circuit Card)) transaction event data
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @remarks This event  notifies , external reader trys to access secure element.
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] se type
 * @param [in] aid Application Id, specified in ISO/IEC 7816-4
 * @param [in] aid_size The size of aid (5~16)
 * @param [in] param The parameter list, specified in ISO/IEC 8825-1
 * @param [in] param The size of param (0~65535)
 * @param [in] user_data The user data passed from nfc_manager_set_se_transaction_event_cb()
 *
 * @see nfc_manager_set_se_transaction_event_cb()
 * @see nfc_manager_unset_se_transaction_event_cb()
 */
typedef void (*nfc_se_transaction_event_cb)(nfc_se_type_e se_type, unsigned char* aid, int aid_size , unsigned char* param, int param_size,  void *user_data);



/**
 * @brief Called after nfc_p2p_send() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] result The result of function call
 * @param [in] user_data The user data passed from nfc_p2p_send()
 *
 * @see nfc_p2p_send()
 */
typedef void (*nfc_p2p_send_completed_cb)(nfc_error_e result, void *user_data);


/**
 * @brief Called after nfc_p2p_send() has completed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @remarks @a message will be automatically destroyed when the callback function returns. (Do not release @a message.)
 *
 * @param [in] target The handle to p2p target
 * @param [in] message The received message
 * @param [in] user_data The user data passed from nfc_p2p_set_recv_cb()
 *
 * @see nfc_p2p_set_data_received_cb()
 * @see nfc_p2p_unset_data_received_cb()
 */
typedef void (*nfc_p2p_data_received_cb)(nfc_p2p_target_h target, nfc_ndef_message_h message, void *user_data);

/**
 * @brief Called when SNEP event is raised
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] handle The handle of current snep instance
 * @param [in] event The kind of snep event
 * @param [in] result The result of snep event
 * @param [in] msg The ndef message which received from client or result of get request
 * @param [in] user_data The user data passed from snep apis.
 *
 * @see nfc_snep_start_server()
 * @see nfc_snep_send_client_request()
 */
typedef void (*nfc_snep_event_cb)(nfc_p2p_snep_h handle,
	nfc_snep_event_e event, nfc_error_e result,
	nfc_ndef_message_h msg, void *user_data);

/**
 * @brief Called when receiving HCE(Host Card Emulation) event.
 * @since_tizen 2.3.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 * @remarks If the event type is NFC_HCE_EVENT_DEACTIVATED or NFC_HCE_EVENT_ACTIVATED, then apdu and apdu_len is NULL and 0.
 *
 * @param [in] handle The handle of connected secure element
 * @param [in] event The HCE event type
 * @param [in] apdu The bytes array of apdu command data
 * @param [in] apdu_len The size of apdu command bytes array
 * @param [in] user_data The user data passed from nfc_manager_set_hce_event_cb()
 *
 * @see nfc_manager_set_hce_event_cb()
 * @see nfc_manager_unset_hce_event_cb()
 */
typedef void (*nfc_hce_event_cb)(nfc_se_h handle, nfc_hce_event_type_e event, unsigned char *apdu, unsigned int apdu_len, void *user_data);

/**
 * @brief Called once for each registered AID.
 * @since_tizen 2.3.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] aid Application Id, specified in ISO/IEC 7816-4
 * @param [in] read_only @c true an aid is on read only mode, otherwise @c false
 * @param [in] user_data The user data passed from the foreach function
 *
 * @see nfc_se_foreach_registered_aids()
 */
typedef void (*nfc_se_registered_aid_cb)(nfc_se_type_e se_type,	const char *aid, bool read_only, void *user_data);

/**
 * @brief Gets the value that indicates whether NFC is supported.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @remarks This function can executed Regardless of nfc_manager_initialize state.
 *
 * @return true on NFC supported,  otherwise false
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @exception #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @exception #NFC_ERROR_OPERATION_FAILED Operation fail
 */
bool nfc_manager_is_supported(void);

/**
 * @brief Set NFC Activation state changed callback
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function to invoke when activation state is changed.
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_activation_changed_cb()
 * @see nfc_manager_unset_activation_changed_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_activation_changed_cb(nfc_activation_changed_cb callback , void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_manager_set_activation_changed_cb()
 * @see nfc_activation_changed_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_activation_changed_cb(void);

/**
 * @brief Sets NFC Activation
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel platform
 * @privilege %http://tizen.org/privilege/nfc.admin
 * @internal
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE

 * @param [in] activation The NFC state for setting
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @post It invokes nfc_activation_completed_cb() when it has completed to set activation.\n
 * The Callback can receive error code when process is done.
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_ALREADY_ACTIVATED Already activated
 * @retval #NFC_ERROR_ALREADY_DEACTIVATED Already deactivated
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation fail
 *
 * @see nfc_manager_is_activated()
 * @see nfc_activation_completed_cb()
 * @see nfc_manager_initialize()
*/
int nfc_manager_set_activation(bool activation, nfc_activation_completed_cb callback, void *user_data);

/**
 * @brief Gets NFC Activation state
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 * @remarks This function can executed Regardless of nfc_manager_initialize state.
 *
 * @return true on NFC activated,  otherwise false
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @exception #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @exception #NFC_ERROR_OPERATION_FAILED Operation fail
 */
bool nfc_manager_is_activated(void);

/**
 * @brief Initializes NFC Manager.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks This function must be called before proceeding any other nfc functions\n
 *	When an application crashes or exits without the deinitialization. NFC manager automatically deinitializes the process itself.\n
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_OPERATION_FAILED Operation fail
 *
 * @see nfc_manager_deinitialize()
 */
int nfc_manager_initialize(void);

/**
 * @brief Releases all the resource of the NFC Manager and disconnect the session between an application and NFC Manager.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_OPERATION_FAILED Operation fail
 *
 * @see nfc_manager_initialize()
 */
int nfc_manager_deinitialize(void);

/**
 * @brief Registers a callback function for receiving tag discovered notification.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function called when a tag is appeared or disappeared
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_unset_tag_discovered_cb()
 * @see nfc_tag_discovered_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_tag_discovered_cb(nfc_tag_discovered_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_manager_set_tag_discovered_cb()
 * @see nfc_tag_discovered_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_tag_discovered_cb(void);

/**
 * @brief Registers a callback function for receiving NDEF Message discovered notification
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function called when NDEF Message is discovered
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_unset_ndef_discovered_cb()
 * @see nfc_ndef_discovered_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_ndef_discovered_cb(nfc_ndef_discovered_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_manager_set_ndef_discovered_cb()
 * @see nfc_ndef_discovered_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_ndef_discovered_cb(void);

/**
 * @brief Registers a callback function for receiving NFC peer-to-peer target discovered notification.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function called when NFC peer-to-peer target is discovered
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_unset_ndef_discovered_cb()
 * @see nfc_p2p_target_discovered_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_p2p_target_discovered_cb(nfc_p2p_target_discovered_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_manager_set_p2p_target_discovered_cb()
 * @see nfc_p2p_target_discovered_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_p2p_target_discovered_cb(void);


/**
 * @brief Registers a callback function for receiving  Secure Element (SIM/UICC(Universal Integrated Circuit Card)) event.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function called when occurred Secure Element (SIM/UICC(Universal Integrated Circuit Card)) event.
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_se_event_cb()
 * @see nfc_manager_unset_se_event_cb()
 * @see nfc_manager_initialize()
 */

int nfc_manager_set_se_event_cb(nfc_se_event_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_se_event_cb()
 * @see nfc_manager_set_se_event_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_se_event_cb(void);

/**
 * @brief Registers a callback function for receiving  Secure Element (SIM/UICC(Universal Integrated Circuit Card)) transaction event(#NFC_SE_EVENT_TRANSACTION) data.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] se_type The type of secure element.
 * @param [in] callback The callback function called when occurred SE transaction event.
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_se_transaction_event_cb()
 * @see nfc_manager_unset_se_transaction_event_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_se_transaction_event_cb(nfc_se_type_e se_type, nfc_se_transaction_event_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] se_type The type of secure element.
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_se_transaction_event_cb()
 * @see nfc_manager_set_se_transaction_event_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_se_transaction_event_cb(nfc_se_type_e se_type);

/**
 * @brief Registers a callback function for receiving HCE(Host Card Emulation) event.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [in] callback The callback function called when HCE(Host Card Emulation) event occurred.
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_hce_event_cb()
 * @see nfc_manager_unset_hce_event_cb()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_hce_event_cb(nfc_hce_event_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @exception #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_hce_event_cb()
 * @see nfc_manager_set_hce_event_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_unset_hce_event_cb(void);

/**
 * @brief give the priority to the foreground application when dispatching transaction event.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks This function must be called only when the application is in the foreground. \n
 *	If the application go out from foreground, application must call "nfc_manager_disable_transaction_fg_dispatch" to disable foreground dispatch \n\n
 * @remarks Security level can be determined by the manufacturer usage.\n
 * If a security issue is occurred, contact with the manufacturer of the product.\n
 * If you want to know about security level in detail, See the GSMA specification.\n
 * (http://www.gsma.com/digitalcommerce/wp-content/uploads/2013/12/GSMA-NFC05-NFC-Handset-APIs-Requirement-Specification-version-4-1.pdf)
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_SECURITY_RESTRICTED Security restricted by Access Control
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_OPERATION_FAILED	IPC fail
 *
 * @see nfc_manager_disable_transaction_fg_dispatch()
 * @see nfc_manager_initialize()
 */
int nfc_manager_enable_transaction_fg_dispatch(void);

/**
 * @brief disable foreground dispatch for "EVT_TRANSACTION" to the givin application.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks After calling "nfc_manager_enable_transaction_fg_dispatch", an application must call this api when it go out from foureground.  \n\n
 * @remarks Security level can be determined by the manufacturer usage.\n
 * If a security issue is occurred, contact with the manufacturer of the product.\n
 * If you want to know about security level in detail, See the GSMA specification.\n
 * (http://www.gsma.com/digitalcommerce/wp-content/uploads/2013/12/GSMA-NFC05-NFC-Handset-APIs-Requirement-Specification-version-4-1.pdf)
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_SECURITY_RESTRICTED Security restricted by Access Control
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_OPERATION_FAILED	IPC fail
 *
 * @see nfc_manager_enable_transaction_fg_dispatch()
 * @see nfc_manager_initialize()
 */
int nfc_manager_disable_transaction_fg_dispatch(void);

/**
 * @brief Gets NDEF message cached when the tag is detected or when data received from NFC peer-to-peer target.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks This function is used to get the ndef message that was read before launched your application.
 * @param [out] ndef_message The cached NDEF message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NO_NDEF_MESSAGE The cached message does not exist
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 *
 */
int nfc_manager_get_cached_message(nfc_ndef_message_h *ndef_message);

/**
 * @brief Sets filter of target types.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks Bit operator OR(|) can be used in the configure parameter (like  NFC_TAG_FILTER_ISO14443A_ENABLE | NFC_TAG_FILTER_ISO14443B_ENABLE)
 *	or you may choose "NFC_TAG_ALL_ENABLE" enum value to get all result.
 *	It prevent getting tag types from RF level.
 *	If the client api does call this function, default is always NFC_TAG_ALL_ENABLE.
 *
 * @param [in] filter The filter value with bits operation #nfc_tag_filter_e
 *
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @exception #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_manager_get_tag_filter()
 * @see nfc_tag_discovered_cb()
 * @see nfc_manager_initialize()
 */
void nfc_manager_set_tag_filter(int filter);

/**
 * @brief Gets the current filter status.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @remarks Bit operation OR(|) is used in return data\n
 * The default value is NFC_TAG_FILTER_ALL_ENABLE
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @return The filter which is set #nfc_tag_filter_e
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 *
 * @see nfc_manager_set_tag_filter()
 * @see nfc_manager_initialize()
 */
int nfc_manager_get_tag_filter(void);

/**
 * @brief Gets current connected tag.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [out] tag The connected tag
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_NO_DEVICE There is no connected target
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NO_DEVICE There is no connected tag
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 */
int nfc_manager_get_connected_tag(nfc_tag_h *tag);

/**
 * @brief Gets current connected p2p target
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [out] target The connected target
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_NO_DEVICE There is no connected target
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NO_DEVICE There is no connected tag
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 */
int nfc_manager_get_connected_target(nfc_p2p_target_h *target);


/**
 * @brief Enable or disable the system handling for tag and target discovered event
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks In default, The system handling is enabled.
 *
 * @param [in] enable The state of enable
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_is_system_handler_enabled()
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_system_handler_enable(bool enable);

/**
 * @brief Gets the state of the system handler
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks In default, The system handling is enabled.
 * @remarks The specific error code can be obtained using the get_last_result() method. Error codes are described in Exception section.
 *
 * @return true on enabled, otherwise false.
 *
 * @exception #NFC_ERROR_NONE Success
 * @exception #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @exception #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @exception #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @exception #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @exception #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @exception #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_set_system_handler_enable()
 * @see nfc_manager_initialize()
 */
bool nfc_manager_is_system_handler_enabled(void);

/**
 * @brief Sets the card emulation Secure Element type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks Security level can be determined by the manufacturer usage.\n
 * If a security issue is occurred, contact with the manufacturer of the product.\n
 * If you want to know about security level in detail, See the GSMA specification.\n
 * (http://www.gsma.com/digitalcommerce/wp-content/uploads/2013/12/GSMA-NFC05-NFC-Handset-APIs-Requirement-Specification-version-4-1.pdf)
 *
 * @param [in] type The type of Secure Element
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_SECURITY_RESTRICTED Security restricted by Access Control
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 */
int nfc_manager_set_se_type(nfc_se_type_e type);

/**
 * @brief Gets the card emulation Secure Element type
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 *
 * @param [out] type The type of Secure Element
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_PERMISSION_DENIED Security restricted by SMACK
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 */
int nfc_manager_get_se_type(nfc_se_type_e *type);

/**
 * @brief Creates a record with given parameter value.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks Every data buffer is deeply copied.\n
 * Every data is a byte array(binary data).
 *
 * @param [out] record A handle to record
 * @param [in] tnf The type name format
 * @param [in] type The specified type name
 * @param [in] type_size The byte size of type
 * @param [in] id The record ID
 * @param [in] id_size The byte size of ID
 * @param [in] payload The payload of this record
 * @param [in] payload_size The byte size of payload
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_record_create_text()
 * @see nfc_ndef_record_create_uri()
 * @see nfc_ndef_record_create_mime()
 * @see nfc_ndef_record_destroy()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_create(nfc_ndef_record_h *record, nfc_record_tnf_e tnf, const unsigned char *type, int type_size, const unsigned char *id, int id_size, const unsigned char *payload, unsigned int payload_size);


/**
 * @brief Creates a record with text type payload
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks This function does not encode the text. @a text will be assumed as that it is already encoded with encode type.\n
 * The text buffer will be deeply copied.\n
 * The record is created in this format\n
 * - TNF : NFC_RECORD_TNF_WELL_KNOWN\n
 * - type : "T"\n
 * - payload : encode and header information + language code + text \n
 * Defined in Record Type Definition Technical Specifications.
 *
 * @param [out] record A handle to record
 * @param [in] text The encoded text
 * @param [in] lang_code The language code string value followed by IANA[RFC 3066] (ex: en-US, ko-KR)
 * @param [in] encode The encoding type
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_record_create()
 * @see nfc_ndef_record_create_uri()
 * @see nfc_ndef_record_create_mime()
 * @see nfc_ndef_record_destroy()
 * @see nfc_ndef_record_get_text()
 * @see nfc_ndef_record_get_langcode()
 * @see nfc_ndef_record_get_encode_type()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_create_text(nfc_ndef_record_h *record, const char *text, const char *lang_code, nfc_encode_type_e encode);

/**
 * @brief Creates a record with URI type payload
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks The uri string will be deep copied.\n
 * The record is created in this format\n
 * - TNF : NFC_RECORD_TNF_WELL_KNOWN\n
 * - type : "U"\n
 * - payload : protocol scheme + uri\n
 * Defined in Record Type Definition Technical Specifications.
 *
 * @param [out] record A handle to record
 * @param [in] uri	The URI string that will be stored in the payload
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_record_create()
 * @see nfc_ndef_record_create_text()
 * @see nfc_ndef_record_create_mime()
 * @see nfc_ndef_record_destroy()
 * @see nfc_ndef_record_get_uri()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_create_uri(nfc_ndef_record_h* record, const char *uri);


/**
 * @brief Creates a record with MIME type payload
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks The data buffer will be deep copied.\n
 * The data are bytes array(binary data).\n
 * The mime_type string will deep copied.\n
 * The record is created in this format\n
 * - TNF : NFC_RECORD_TNF_MIME_MEDIA\n
 * - type : mime type\n
 * - payload : data\n
 * Defined in Record Type Definition Technical Specifications.
 *
 * @param [out] record A handle to record
 * @param [in] mime_type	The mime type [RFC 2046] (ex. text/plain, image/jpeg ) This value is stored in type field
 * @param [in] data	The pointer of data
 * @param [in] data_size	The size of data
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_record_create()
 * @see nfc_ndef_record_create_uri()
 * @see nfc_ndef_record_create_text()
 * @see nfc_ndef_record_destroy()
 * @see nfc_ndef_record_get_mime_type()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_create_mime(nfc_ndef_record_h* record, const char *mime_type, const unsigned char *data, unsigned int data_size);


/**
 * @brief Destroys the record handle
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @param [in] record The handle to record
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_ndef_record_create()
 * @see nfc_ndef_record_create_text()
 * @see nfc_ndef_record_create_uri()
 * @see nfc_ndef_record_create_mime()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_destroy(nfc_ndef_record_h record);

/**
 * @brief Sets record ID
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks The ID buffer are deep copied.
 *
 * @param [in] record The handle to record
 * @param [in] id The record ID
 * @param [in] id_size The size of ID in bytes
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_ndef_record_get_id()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_set_id(nfc_ndef_record_h record, unsigned char *id, int id_size);

/**
 * @brief Gets record ID
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks It may return NULL pointer if the ID is not exist\n
 *  This function gives you  the pointer of ID that is contained by record\n
 *  Do not free the ID. It will be released when @a record is destroyed by nfc_ndef_record_destroy().
 *
 * @param [in] record The handle to record
 * @param [out] id The record ID ( do not free )
 * @param [out] size The size of ID in bytes
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_ndef_record_set_id()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_id(nfc_ndef_record_h record, unsigned char **id, int *size);

/**
 * @brief Gets record payload.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks This function gives you  the pointer of payload that is contained by record\n
 * Do not free the payload. it will be freed when @a record is destroyed by nfc_ndef_record_destroy().
 *
 * @param [in] record The handle to record
 * @param [out] payload	The payload  ( do not free this pointer )
 * @param [out] size the size of payload in byte
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_payload(nfc_ndef_record_h record, unsigned char ** payload, unsigned int *size);

/**
 * @brief Gets record type.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks This function gives you  the pointer of type that is contained by record.\n
 * Do not free the type. it will be freed when the record is freed.
 *
 * @param [in] record The handle to record
 * @param [out] type	The record type  ( do not free this pointer )
 * @param [out] size The size of type in byte
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_type(nfc_ndef_record_h record, unsigned char **type, int *size);

/**
 * @brief Gets record TNF(Type Name Format) value.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @param [in] record The handle to record
 * @param [out] tnf The TNF(Type Name Format) value
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_tnf(nfc_ndef_record_h record, nfc_record_tnf_e *tnf);

/**
 * @brief Gets text from text record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks This function returns newly allocated string, this value must be deallocated by caller.\n
 * This function is valid only for text type record.\n
 * The text type record 's tnf is NFC_RECORD_TNF_WELL_KNOWN and it's type is "T"
 *
 * @param [in] record The handle to record
 * @param [out] text The text in record payload ( should be freed by caller )
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_RECORD_TYPE Invalid record type
 *
 * @see nfc_ndef_record_create_text()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_text(nfc_ndef_record_h record, char **text);

/**
 * @brief Gets language code from text record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 * @remarks This function returns newly allocated string, this value must be deallocated by caller.\n
 * This function is valid only for text type record.\n
 * The text type record 's tnf is NFC_RECORD_TNF_WELL_KNOWN and it's type is "T"
 *
 * @param [in] record	The handle to record
 * @param [out] lang_code lang code ( should be freed by caller )
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_RECORD_TYPE Invalid record type
 *
 * @see nfc_ndef_record_create_text()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_langcode(nfc_ndef_record_h record, char **lang_code);

/**
 * @brief Gets encoding type from text record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks  This function is valid only for text type record.\n
 * The text type record 's tnf is NFC_RECORD_TNF_WELL_KNOWN and it's type is "T"
 *
 * @param [in] record	The handle to record
 * @param [out] encode encode type #nfc_encode_type_e
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_RECORD_TYPE Invalid record type
 *
 * @see nfc_ndef_record_create_text()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_encode_type(nfc_ndef_record_h record, nfc_encode_type_e *encode);

/**
 * @brief Gets URI from uri record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks The function returns newly allocated string, this value must be deallocated by caller.\n
 * This function is valid only for uri type record.
 * The uri type record 's tnf is NFC_RECORD_TNF_WELL_KNOWN and it's type is "U"
 *
 * @param [in] record	The handle to record
 * @param [out] uri	The uri in record payload ( should be freed by caller )
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_RECORD_TYPE Invalid record type
 *
 * @see nfc_ndef_record_create_uri()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_uri(nfc_ndef_record_h record, char **uri);


/**
 * @brief Gets mime type from mime type record
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE
 *
 * @remarks The function returns newly allocated string, this value must be deallocated by caller.\n
 * This function is valid only for mime type record.\n
 * The uri type record 's tnf is NFC_RECORD_TNF_MIME_MEDIA.
 *
 * @param [in] record	The handle to record
 * @param [out] mime_type	The mime type in record payload ( should be freed by caller )
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_RECORD_TYPE Invalid record type
 *
 * @see nfc_ndef_record_create_mime()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_record_get_mime_type(nfc_ndef_record_h record, char **mime_type);


/**
 * @brief Creates NDEF message handle
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @param [out] ndef_message A handle to NDEF message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_message_create_from_rawdata()
 * @see nfc_ndef_message_destroy()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_create(nfc_ndef_message_h *ndef_message);

/**
 * @brief Creates NDEF message handle from raw serial bytes.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks It consumes the bytes array until get the ME(Message End) flag*. It returns error if the bytes array does not have ME flag.\n
 * *The ME flag is a 1-bit field that when set indicates the end of an NDEF message.
 *
 * @param [out] ndef_message The handle to NDEF message
 * @param [in] rawdata The NDEF message in form of bytes array
 * @param [in] rawdata_size The size of bytes array
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_ndef_message_create()
 * @see nfc_ndef_message_destroy()
 * @see nfc_ndef_message_get_rawdata()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_create_from_rawdata(nfc_ndef_message_h *ndef_message, const unsigned char *rawdata, unsigned int rawdata_size);

/**
 * @brief Destroys NDEF message handle
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks This function will free all these memory including record handles.
 *
 * @param [in] ndef_message The handle to NDEF message to destroy
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_ndef_message_create()
 * @see nfc_ndef_message_create_from_rawdata()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_destroy(nfc_ndef_message_h ndef_message);

/**
 * @brief Gets the number of record in NDEF message
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [out] count The number of record
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_get_record_count(nfc_ndef_message_h ndef_message, int *count);

/**
 * @brief Gets serial bytes array of NDEF message.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks It gets copy of the bytes array from NDEF message. @a rawdata must be released with free() by you.
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [out] rawdata The bytes array of bytes array
 * @param [out] rawdata_size The size of bytes array in byte
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_NDEF_MESSAGE Invalid NDEF message
 *
 * @see nfc_ndef_message_create_from_rawdata()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_get_rawdata(nfc_ndef_message_h ndef_message, unsigned char **rawdata, unsigned int *rawdata_size);

/**
 * @brief Appends a record into NDEF message
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks Appended record is handled by frameworks. The record is released by frameworks when message is released.
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [in] record The record that will be appended into NDEF message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_ndef_message_insert_record()
 * @see nfc_ndef_message_remove_record()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_append_record(nfc_ndef_message_h ndef_message, nfc_ndef_record_h record);

/**
 * @brief Inserts a record at index into NDEF message
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks Appended record is handled by frameworks. The record is released by frameworks when message is released.\n
 * The index value should not bigger than nfc_ndef_message_get_record_count()
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [in] index The index of record ( starts from 0 )
 * @param [in] record The record that will be appended into NDEF message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_NDEF_MESSAGE	Invalid NDEF message
 *
 * @see nfc_ndef_message_append_record()
 * @see nfc_ndef_message_remove_record()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_insert_record(nfc_ndef_message_h ndef_message, int index, nfc_ndef_record_h record);

/**
 * @brief Removes the record that indicated by index number and this deleted record will be freed.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [in] index	The index of record ( starts from 0 )
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_INVALID_NDEF_MESSAGE	Invalid NDEF message
 *
 * @see nfc_ndef_message_append_record()
 * @see nfc_ndef_message_insert_record()
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_remove_record(nfc_ndef_message_h ndef_message, int index);

/**
 * @brief Gets record by index.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE
 *
 * @remarks This function just return the pointer of record. if you change the record value it directly affects the NDEF message
 *
 * @param [in] ndef_message The handle to NDEF message
 * @param [in] index The index of record ( starts from 0 )
 * @param [out] record The handle to record
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_ndef_message_get_record(nfc_ndef_message_h ndef_message, int index, nfc_ndef_record_h *record);

/**
 * @brief Gets the type of NFC tag
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [out] type The type of NFC tag
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_manager_initialize()
 */
int nfc_tag_get_type(nfc_tag_h tag, nfc_tag_type_e *type);

/**
 * @brief Checks whether the given NFC tag supports NDEF messages.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [out] is_supported @c true when NFC tag supports NDEF messages, otherwise @c false
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_tag_read_ndef()
 * @see nfc_manager_initialize()
 */
int nfc_tag_is_support_ndef(nfc_tag_h tag, bool *is_supported);

/**
 * @brief Gets the maximum NDEF message size that can be stored in NFC tag.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @remarks This max size indicates the maximum size of NDEF message that can be stored in this detected tag.
 *
 * @param [in] tag The handle to NFC tag
 * @param [out] maximum_ndef_bytes_size The maximum bytes size of NDEF message that can be stored in this detected tag.
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_tag_get_maximum_ndef_size(nfc_tag_h tag, unsigned int *maximum_ndef_bytes_size);

/**
 * @brief Gets size of NDEF message that stored in the tag
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [out] ndef_bytes_size The NDEF message bytes size that stored in the tag
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_manager_initialize()
 */
int nfc_tag_get_ndef_size(nfc_tag_h tag, unsigned int *ndef_bytes_size);


/**
 * @brief Retrieves all tag information
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param[in] tag The handle to NFC tag
 * @param[in] callback	The callback function to invoke
 * @param[in] user_data	The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_manager_initialize()
 */
int nfc_tag_foreach_information(nfc_tag_h tag, nfc_tag_information_cb callback, void *user_data);


/**
 * @brief Transceives the data of the raw format card.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @details This function is the only way to access the raw format card (not formated),
	each tag type requires own command to access tags. \n
	This function provides the low level access of tag operation and you require the knowledge of each tag technology.
* @ingroup CAPI_NETWORK_NFC_TAG_MODULE
*
* @param [in] tag The handle to NFC tag
* @param [in] buffer The binary data for parameter or additional commands
* @param [in] buffer_size The size of buffer in bytes
* @param [in] callback The callback function to invoke after this function has completed\n It can be null if a notification is not required
* @param [in] user_data	The user data to be passed to the callback function
*
* @return 0 on success, otherwise a negative error value.
* @retval #NFC_ERROR_NONE Successful
* @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
* @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
* @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
* @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
* @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
* @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
* @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
* @retval #NFC_ERROR_OPERATION_FAILED Operation failed
*
* @post It invokes nfc_tag_transceive_completed_cb() when it has completed to transceive data.\n
* The Callback can receive error code when process is done.
*
* @see nfc_tag_read_ndef()
* @see nfc_tag_is_support_ndef()
* @see nfc_manager_initialize()
*/
int nfc_tag_transceive(nfc_tag_h tag, unsigned char *buffer, int buffer_size, nfc_tag_transceive_completed_cb callback, void *user_data);

/**
 * @brief Reads NDEF formatted data from NFC tag.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_NOT_NDEF_FORMAT Not ndef format tag
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_tag_read_completed_cb() when it has completed to read NDEF formatted data.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_tag_transceive()
 * @see nfc_tag_is_support_ndef()
 * @see nfc_tag_write_ndef()
 * @see nfc_manager_initialize()
 */
int nfc_tag_read_ndef(nfc_tag_h tag, nfc_tag_read_completed_cb callback, void *user_data);

/**
 * @brief Writes NDEF formatted data.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] msg The message will be write to the tag
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_NOT_NDEF_FORMAT Not ndef format tag
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_tag_write_completed_cb() when it has completed to write NDEF data.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_tag_is_support_ndef()
 * @see nfc_tag_read_ndef()
 * @see nfc_manager_initialize()
 */
int nfc_tag_write_ndef(nfc_tag_h tag, nfc_ndef_message_h msg, nfc_tag_write_completed_cb callback, void *user_data);

/**
 * @brief Formats the detected tag that can store NDEF message.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @details Some tags are required authentication. If the detected target doesn't need authentication, @a key can be NULL.
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] key The key value that may need to format the tag
 * @param [in] key_size The size of key in byte
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_NOT_NDEF_FORMAT Not ndef format tag
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_tag_format_completed_cb() when it has completed to format the NFC tag.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_tag_is_support_ndef()
 * @see nfc_manager_initialize()
 */
int nfc_tag_format_ndef(nfc_tag_h tag, unsigned char *key, int key_size, nfc_tag_format_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Authenticates a sector with key A.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks I/O operations(read / write / increment / decrement / transfer / restore) will be available after successful authentication.\n
 * This function is only available for MIFARE classic.\n
 *	\n
 *	MIFARE CLASSIC MINI \n
 *		=> 0 ~ 4 : 5 sectors having 4 block each with block size of 16 bytes \n
 *	\n
 *	MIFARE CLASSIC 1K \n
 *		=> 0 ~ 15 : 16 sectors having 4 block each with block size of 16 bytes \n
 *	\n
 *	MIFARE CLASSIC 4K \n
 *		=> 0 ~ 31 : 32 sectors having 4 block each with block size of 16 bytes	\n
 *		=> 32 ~ 39 : 8 sectors having 16 block each with block size of 16 bytes
 *
 * @param[in] tag The handle to NFC tag
 * @param[in] sector_index The index of sector to authenticate with key A, starting from 0
 * @param[in] auth_key 6-byte authentication key
 * @param[in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param[in] user_data	The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_authenticate_with_keyA_completed_cb() when it has completed to authenticate the given sector with key A.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_authenticate_with_keyB()
 * @see nfc_mifare_read_block()
 * @see nfc_mifare_read_page()
 * @see nfc_mifare_write_block()
 * @see nfc_mifare_write_page()
 * @see nfc_mifare_increment()
 * @see nfc_mifare_decrement()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_authenticate_with_keyA(nfc_tag_h tag, int sector_index, unsigned char *auth_key, nfc_mifare_authenticate_with_keyA_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Authenticates a sector with key B.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks I/O operations(read / write / increment / decrement / transfer / restore) will be available after successful authentication.\n
 * This function is only available for MIFARE classic.\n
 * 	\n
 *	MIFARE CLASSIC MINI\n
 *		=> 0 ~ 4 : 5 sector and 4 block with 16 bytes\n
 *	\n
 *	MIFARE CLASSIC 1K \n
 *		=> 0 ~ 15 : 16 sector and 4 block with 16 bytes\n
 *	\n
 *	MIFARE CLASSIC 4K\n
 *		=> 0 ~ 31 : 32 sector and 4 block with 16 bytes \n
 *		=> 32 ~ 39 : 8 sector and 16 block with 16 bytes
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] sector_index The index of sector to authenticate with key B, starting from 0
 * @param [in] auth_key 6-byte authentication key
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_authenticate_with_keyB_completed_cb() when it has completed to authenticate the given sector with key B.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_authenticate_with_keyA()
 * @see nfc_mifare_read_block()
 * @see nfc_mifare_read_page()
 * @see nfc_mifare_write_block()
 * @see nfc_mifare_write_page()
 * @see nfc_mifare_increment()
 * @see nfc_mifare_decrement()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_authenticate_with_keyB(nfc_tag_h tag, int sector_index, unsigned char *auth_key, nfc_mifare_authenticate_with_keyB_completed_cb callback, void *user_data);


/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Reads a 16-byte block.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE classic.
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The block or starting page number
 * @param [in] callback	The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_read_block_completed_cb() when it has completed to read a block.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_read_page()
 * @see nfc_mifare_write_block()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_read_block(nfc_tag_h tag, int block_index, nfc_mifare_read_block_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Reads 4 pages(16 bytes).
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE Ultra light.\n
 * The MIFARE Ultralight protocol always reads 4 pages at a time, to reduce the number of commands required to read an entire tag.
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] page_index  The index of page to read, starting from 0
 * @param [in] callback	The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_read_page_completed_cb() when it has completed to read a page.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_read_block()
 * @see nfc_mifare_write_page()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_read_page(nfc_tag_h tag, int page_index, nfc_mifare_read_page_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Writes block (16 byte) of data to the tag at a given block index.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE classic.
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The index of block to read, starting from 0
 * @param [in] buffer 16 bytes of data to write
 * @param [in] buffer_size The size of buffer in bytes
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_write_block_completed_cb() when it has completed to write a block.\n The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_write_page()
 * @see nfc_mifare_read_block()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_write_block(nfc_tag_h tag, int block_index, unsigned char *buffer, int buffer_size, nfc_mifare_write_block_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Writes a page (4 bytes) of data to the tag at a given page index
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE Ultra light
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] page_index The index of page to write, starting from 0
 * @param [in] buffer 4 bytes of data to write
 * @param [in] buffer_size The size of buffer in bytes
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_write_page_completed_cb() when it has completed to write a page.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_write_block()
 * @see nfc_mifare_read_page()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_write_page(nfc_tag_h tag, int page_index, unsigned char *buffer, int buffer_size, nfc_mifare_write_page_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Increases a value block, storing the result in the temporary block on the tag.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE classic
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The index of block to increase, starting from 0
 * @param [in] value Non-negative to increment by
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_increment_completed_cb() when it has completed to increment.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_decrement()
 * @see nfc_mifare_write_block()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_increment(nfc_tag_h tag, int block_index, int value, nfc_mifare_increment_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Decreases a value block, storing the result in the temporary block on the tag.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks  This function is only available for MIFARE classic
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The index of block to decrease, starting from 0
 * @param [in] value non-negative to decrement by
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_decrement_completed_cb() when it has completed to decrement.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_increment()
 * @see nfc_mifare_write_block()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_decrement(nfc_tag_h tag, int block_index, int value, nfc_mifare_decrement_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Copy from the temporary block to the specified block.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE classic
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The index of block to copy to, starting from 0
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_transfer_completed_cb() when it has completed to transfer.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_restore()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_transfer(nfc_tag_h tag, int block_index, nfc_mifare_transfer_completed_cb callback, void *user_data);

/**
 * @ingroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE
 * @brief Copy from a value block to the temporary block.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @remarks This function is only available for MIFARE classic
 *
 * @param [in] tag The handle to NFC tag
 * @param [in] block_index The index of block to copy from, starting from 0
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_TIMED_OUT Timeout is reached while communicating with tag
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @post It invokes nfc_mifare_restore_completed_cb() when it has completed to restore.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_mifare_transfer()
 * @see nfc_manager_initialize()
*/
int nfc_mifare_restore(nfc_tag_h tag, int block_index, nfc_mifare_restore_completed_cb callback, void *user_data);

/**
 * @brief Registers a callback function for receiving data from NFC peer-to-peer target.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 * @param [in] callback The callback function to invoke when an NDEF Message is discovered
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_p2p_set_data_received_cb()
 * @see nfc_p2p_unset_data_received_cb()
 * @see nfc_p2p_target_discovered_cb()
 * @see nfc_manager_initialize()
 */
int nfc_p2p_set_data_received_cb(nfc_p2p_target_h target, nfc_p2p_data_received_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 *
 * @see nfc_p2p_set_data_received_cb()
 * @see nfc_p2p_unset_data_received_cb()
 * @see nfc_p2p_target_discovered_cb()
 * @see nfc_manager_initialize()
 */
int nfc_p2p_unset_data_received_cb(nfc_p2p_target_h target);

/**
 * @brief Sends data to NFC peer-to-peer target
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 * @param [in] message The message to send
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @post It invokes nfc_p2p_send_completed_cb() when it has completed to p2p send.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_p2p_send_completed_cb()
 * @see nfc_p2p_target_discovered_cb()
 * @see nfc_manager_initialize()
*/
int nfc_p2p_send(nfc_p2p_target_h target, nfc_ndef_message_h message, nfc_p2p_send_completed_cb callback, void *user_data);

/**
 * @brief Start peer-to-peer server using SNEP protocol
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 * @param [in] san The name of service (service access name)
 * @param [in] sap The number of service (service access point)
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @post It invokes nfc_snep_event_cb() when snep event is occured.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_snep_event_cb()
 * @see nfc_manager_initialize()
*/
int nfc_snep_start_server(nfc_p2p_target_h target, const char *san, int sap, nfc_snep_event_cb callback, void *user_data);

/**
 * @brief Start peer-to-peer client using SNEP protocol
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 * @param [in] san The name of service (service access name)
 * @param [in] sap The number of service (service access point)
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @post It invokes nfc_snep_event_cb() when snep event is occured.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_snep_event_cb()
 * @see nfc_snep_send_client_request()
 * @see nfc_snep_stop_service()
 * @see nfc_manager_initialize()
*/
int nfc_snep_start_client(nfc_p2p_target_h target, const char *san, int sap, nfc_snep_event_cb callback, void *user_data);

/**
 * @brief Send request message to peer-to-peer client using SNEP protocol
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] handle The handle to connected snep instance
 * @param [in] type The request type of snep protocol
 * @param [in] msg The ndef message which will be sent
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @post It invokes nfc_snep_event_cb() when snep event is occured.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_snep_event_cb()
 * @see nfc_manager_initialize()
*/
int nfc_snep_send_client_request(nfc_p2p_snep_h handle, nfc_snep_type_e type, nfc_ndef_message_h msg, nfc_snep_event_cb callback, void *user_data);

/**
 * @brief Stop snep server or client
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] target The handle to peer target
 * @param [in] service The handle which will be stopped
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @see nfc_snep_event_cb()
 * @see nfc_manager_initialize()
*/
int nfc_snep_stop_service(nfc_p2p_target_h target, nfc_p2p_snep_h service);

/**
 * @brief Register peer-to-peer server using SNEP protocol
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] san The name of service (service access name)
 * @param [in] sap The number of service (service access point)
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @post It invokes nfc_snep_event_cb() when snep event is occured.\n
 * The Callback can receive error code when process is done.
 *
 * @see nfc_snep_event_cb()
 * @see nfc_manager_initialize()
*/
int nfc_snep_register_server(const char *san, int sap, nfc_snep_event_cb callback, void *user_data);

/**
 * @brief Unregister snep server or client
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc
 * @ingroup CAPI_NETWORK_NFC_P2P_MODULE
 *
 * @param [in] san The name of service (service access name)
 * @param [in] sap The number of service (service access point)
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @see nfc_snep_event_cb()
 * @see nfc_manager_initialize()
*/
int nfc_snep_unregister_server(const char *san, int sap);

/**
 * @brief Enable card emulation mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 * @remarks Security level can be determined by the manufacturer usage.\n
 * If a security issue is occurred, contact with the manufacturer of the product.\n
 * If you want to know about security level in detail, See the GSMA specification.\n
 * (http://www.gsma.com/digitalcommerce/wp-content/uploads/2013/12/GSMA-NFC05-NFC-Handset-APIs-Requirement-Specification-version-4-1.pdf)
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not intialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_PERMISSION_DENIED Security Restricted by SMACK
 * @retval #NFC_ERROR_SECURITY_RESTRICTED Security Restricted
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_se_disable_card_emulation()
 * @see nfc_manager_initialize()
 */
int nfc_se_enable_card_emulation(void);

/**
 * @brief Disable card emulation mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 * @remarks Security level can be determined by the manufacturer usage.\n
 * If a security issue is occurred, contact with the manufacturer of the product.\n
 * If you want to know about security level in detail, See the GSMA specification.\n
 * (http://www.gsma.com/digitalcommerce/wp-content/uploads/2013/12/GSMA-NFC05-NFC-Handset-APIs-Requirement-Specification-version-4-1.pdf)
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not intialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_PERMISSION_DENIED Security Restricted by SMACK
 * @retval #NFC_ERROR_SECURITY_RESTRICTED Security Restricted
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_se_enable_card_emulation()
 * @see nfc_manager_initialize()
 */
int nfc_se_disable_card_emulation(void);

/**
 * @brief Get the current card emulation mode.
 * @since_tizen @if MOBILE 2.3 @elseif WEARABLE 2.3.1 @endif
 * @privlevel public
 * @privilege %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [out]  type   The current card emulation mode type
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not intialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_PERMISSION_DENIED Security Restricted by SMACK
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_se_enable_card_emulation()
 * @see nfc_se_disable_card_emulation()
 * @see nfc_manager_initialize()
 */
int nfc_se_get_card_emulation_mode(nfc_se_card_emulation_mode_type_e *type);

/**
 * @brief Send APDU(Application Protocol Data Unit) response to CLF(Contactless Front-end).
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in]  handle   The handle of connected secure element
 * @param [in] resp     The bytes array of response data
 * @param [in] resp_len The size of response bytes array
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_manager_set_hce_event_cb()
 * @see nfc_manager_unset_hce_event_cb()
 * @see nfc_manager_initialize()
 */
int nfc_hce_send_apdu_response(nfc_se_h handle, unsigned char *resp, unsigned int resp_len);

/**
 * @brief Set the default route for each device status.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] powered_on_status The type of default Secure Element when device is powered on
 * @param [in] powered_off_status The type of default Secure Element when device is powered off
 * @param [in] low_battery_status The type of default Secure Element when battery is low
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_manager_initialize()
 */
int nfc_se_set_default_route(nfc_se_type_e powered_on_status, nfc_se_type_e powered_off_status, nfc_se_type_e low_battery_status);

/**
 * @brief Gets the state whether an application to call this api is currently the activated handler for specific AID.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] aid Application Id, specified in ISO/IEC 7816-4
 * @param [out] is_activated_handler @c true when application is currently the activated handler, otherwise @c false
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_manager_initialize()
 */
int nfc_se_is_activated_handler_for_aid(nfc_se_type_e se_type, const char *aid, bool *is_activated_handler);

/**
 * @brief Gets the state whether an application to call this api is currently the activated handler for category.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] category The category
 * @param [out] is_activated_handler @c true when application is currently the activated handler, otherwise @c false
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_manager_initialize()
 */
int nfc_se_is_activated_handler_for_category(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, bool *is_activated_handler);

/**
 * @brief Registers a AID for a specific category.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] category The category
 * @param [in] aid Application Id, specified in ISO/IEC 7816-4
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_AID_ALREADY_REGISTERED AID is already registered
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_se_unregister_aid()
 * @see nfc_manager_initialize()
 */
int nfc_se_register_aid(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, const char *aid);

/**
 * @brief Unregisters a previously registered AID for the specified category.
 * @details You can unregister aid only you registered. If you try to release the aid what you are not registered, then the api return error.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] category The category
 * @param [in] aid Application Id, specified in ISO/IEC 7816-4
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_se_register_aid()
 * @see nfc_manager_initialize()
 */
int nfc_se_unregister_aid(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, const char *aid);

/**
 * @brief Retrieves all registered AID.
 * @details You can retrives aid only you registered. If you try to retrives the aid what you are not registered, then the api return error.
 * @since_tizen 2.3.1
 * @privlevel   public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] category The category
 * @param [in] callback	The callback function to invoke
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_manager_initialize()
 *
 */
int nfc_se_foreach_registered_aids(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, nfc_se_registered_aid_cb callback, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* __NFC_H__ */
