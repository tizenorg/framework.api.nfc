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


#ifndef __NFC_INTERNAL_H__
#define __NFC_INTERNAL_H__

#include "nfc.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enumerations for Handover event
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef enum {
    NFC_HANDOVER_EVENT_START = 0x00, /**< handover started */
    NFC_HANDOVER_EVENT_FINISH = 0x01, /**< handover finished */
} nfc_handover_event_e;

/**
 * @brief Enumerations for NFC AC(Alternative Carrier)
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef enum {
	NFC_AC_TYPE_BT = 0x00, /**< Bluetooth AC*/
	NFC_AC_TYPE_WIFI, /**<Wifi AC*/
	NFC_AC_TYPE_WIFI_DIRECT,/**<Wifi-direct AC*/
	NFC_AC_TYPE_UNKNOWN, /* No selected preferred AC */
} nfc_ac_type_e ;

/**
 * @brief Enumerations for NFC AC(Alternative Carrier) state
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef enum {
	NFC_AC_STATE_INACTIVATE = 0x00, /**< inactivate */
	NFC_AC_STATE_ACTIVATE, /**<  activated */
	NFC_AC_STATE_ACTIVATING,/**< now activating */
	NFC_AC_STATE_UNKNOWN, /**< unknown */
} nfc_ac_state_e ;

typedef enum{
	NFC_SE_POWER_MODE_SLEEP = 0x00, /**< sleep mode */
	NFC_SE_POWER_MODE_ON = 0x01, /**< Power On */
	NFC_SE_POWER_MODE_OFF = 0x02, /**< Power Off */
} nfc_se_power_type_e;

/**
 * @brief The handle to the Connection Handover message
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef struct _net_nfc_ch_message_s *nfc_handover_message_h;

/**
 * @brief The handle to the Connection Handover carrier
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef struct _net_nfc_ch_carrier_s *nfc_handover_carrier_h;

/**
 * @brief The handle to the Connection Handover carrier configuration
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 */
typedef struct _net_nfc_carrier_config_s *nfc_handover_config_h;

/**
 * @brief Called after nfc_p2p_connection_handover() has completed.
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remark To use the @a ac_data outside this function, copy the @a ac_data.
 * @remark @a ac_data could be NULL, if nfc_p2p_connection_handover failed.
 * @remark If @a carrier is #NFC_AC_TYPE_BT, @ac_data should be converted to 'char *' type. This is bluetooth address information.
 *
 * @param [in] result The result of function call
 * @param [in] carrier The type of Alternative Carrier
 * @param [in] ac_data The connected remote device AC(Alternative Carrier) information data
 * @param [in] ac_data_size The connected remote device AC(Alternative Carrier) information data size
 * @param [in] user_data The user data passed from nfc_p2p_connection_handover()
 *
 * @see nfc_p2p_connection_handover()
 */
typedef void (*nfc_p2p_connection_handover_completed_cb)(nfc_error_e result, nfc_ac_type_e carrier, void *ac_data, int ac_data_size, void *user_data);


/**
 * @brief Called when connection handover is started or finished.
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remark To use the @a address outside this function, copy the @a address.
 * @remark @a address is NULL when is called by start event
 *
 * @param [in] result  The result of function call
 * @param [in] event   The event type of current invocation
 * @param [in] carrier The type of Alternative Carrier
 * @param [in] address The unique id of connected remote device
 * @param [in] msg     The original ndef message of current handover operation
 * @param [in] user_data The user data passed from nfc_connection_handover_set_event_cb()
 *
 * @see nfc_connection_handover_set_event_cb()
 * @see nfc_connection_handover_unset_event_cb()
 */
typedef void (*nfc_connection_handover_event_cb)(nfc_error_e result, nfc_handover_event_e event, nfc_ac_type_e carrier, char *address, nfc_ndef_message_h msg, void *user_data);


/**
 * @brief NFC Connection handover between NFC peer-to-peer target
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in] target The handle to NFC device
 * @param [in] type Preferred Alternative Carrier
 * @param [in] callback The callback function to invoke after this function has completed\n It can be null if notification is not required
 * @param [in] user_data The user data to be passed to the callback function *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NFC_ERROR_DEVICE_BUSY Device is too busy to handle your request
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 *
 * @see nfc_p2p_connection_handover_completed_cb()
*/
int nfc_p2p_connection_handover(nfc_p2p_target_h target , nfc_ac_type_e type, nfc_p2p_connection_handover_completed_cb callback, void *user_data);

/**
 * @brief Check available Alternative Carrier(AC) for NFC handover
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in] carrier Alternative Carrier when to be checked whether supported or not
 *
 * @retval #true Supported
 * @retval #false Not Supported
 *
 * @see nfc_p2p_is_supported_ac_type()
*/
bool nfc_p2p_is_supported_ac_type(nfc_ac_type_e carrier);

/**
 * @brief Registers a callback function for receiving event of connection handover.
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in] callback The callback function to invoke when handover event occurs
 * @param [in] user_data The user data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_connection_handover_unset_event_cb()
 * @see nfc_connection_handover_event_cb()
 */
int nfc_connection_handover_set_event_cb(nfc_connection_handover_event_cb callback, void *user_data);


/**
 * @brief Unregisters the callback function
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 *
 * @see nfc_connection_handover_set_event_cb()
 * @see nfc_connection_handover_event_cb()
 */
int nfc_connection_handover_unset_event_cb(void);

/**
 * @brief create handover message instance from ndef message
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks There is no relation or memory share between @a msg and @a result.
 * @remarks After using handover message, @a result must be destroyed by nfc_handover_message_destroy()
 *
 * @param [out] result The instance of created handover message
 * @param [in]  msg    The instance of source ndef message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_random_number()
 * @see nfc_handover_message_get_carrier_count()
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 * @see nfc_handover_message_destroy()
 */
int nfc_handover_message_import_from_ndef_message(nfc_handover_message_h *result, nfc_ndef_message_h msg);

/**
 * @brief extract random number of handover message
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  message The instance of handover message
 * @param [out] random_number The random number of current message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_import_from_ndef_message()
 * @see nfc_handover_message_destroy()
 */
int nfc_handover_message_get_random_number(nfc_handover_message_h message, unsigned short *random_number);

/**
 * @brief get number of carriers in handover message
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  message The instance of handover message
 * @param [out] count The number of carriers in handover message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_import_from_ndef_message()
 * @see nfc_handover_message_destroy()
 */
int nfc_handover_message_get_carrier_count(nfc_handover_message_h message, unsigned int *count);

/**
 * @brief get instance of specific carrier in handover message by index
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks Do not destroy carrier instance returned from this function. (It managed by handover message)

 * @param [in]  message The instance of handover message
 * @param [in]  index The index of specific carrier
 * @param [out] carrier The instance of indexed carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_import_from_ndef_message()
 * @see nfc_handover_message_destroy()
 */
int nfc_handover_message_get_carrier(nfc_handover_message_h message, int index, nfc_handover_carrier_h *carrier);

/**
 * @brief get instance of specific carrier in handover message by carrier type
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks Do not destroy carrier instance returned from this function. (It managed by handover message)
 *
 * @param [in]  message The instance of handover message
 * @param [in]  type The type of specific carrier
 * @param [out] carrier The instance of indexed carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_import_from_ndef_message()
 * @see nfc_handover_message_destroy()
 */
int nfc_handover_message_get_carrier_by_type(nfc_handover_message_h message, nfc_ac_type_e type, nfc_handover_carrier_h *carrier);

/**
 * @brief destroy handover message instance
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  message The instance of handover message
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_import_from_ndef_message()
 */
int nfc_handover_message_destroy(nfc_handover_message_h message);

/**
 * @brief get CPS(Carrier Power Status) value of handover carrier
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [out] cps The CPS of handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */
int nfc_handover_carrier_get_cps(nfc_handover_carrier_h carrier, nfc_ac_state_e *cps);

/**
 * @brief get type of handover carrier
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [out] type The type of handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */

int nfc_handover_carrier_get_type(nfc_handover_carrier_h carrier, nfc_ac_type_e *type);
/**
 * @brief get carrier record of handover carrier
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks Do not destroy ndef record instance returned from this function. (It managed by handover carrier)
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [out] record The ndef record of current handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */
int nfc_handover_carrier_get_carrier_record(nfc_handover_carrier_h carrier, nfc_ndef_record_h *record);

/**
 * @brief get number of auxiliary records in handover carrier
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [out] count The number of auxiliary records in handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */
int nfc_handover_carrier_get_auxiliary_record_count(nfc_handover_carrier_h carrier, unsigned int *count);

/**
 * @brief get specific auxiliary record in handover carrier by index
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks Do not destroy ndef record instance returned from this function. (It managed by handover carrier)
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [in]  index The index of specific record
 * @param [out] record The ndef record of current handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */
int nfc_handover_carrier_get_auxiliary_record(nfc_handover_carrier_h carrier, int index, nfc_ndef_record_h *record);

/**
 * @brief get instance of handover configuration from handover carrier
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks There is no relation or memory share between @a carrier and @a config.
 * @remarks After using handover config, @a config must be destroyed by nfc_handover_config_destroy()
 *
 * @param [in]  carrier The instance of handover carrier
 * @param [out] config The instance of handover config
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 * @see nfc_handover_config_destroy()
 */
int nfc_handover_carrier_get_handover_config(nfc_handover_carrier_h carrier, nfc_handover_config_h *config);

/**
 * @brief destroy handover carrier instance
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  carrier The instance of handover carrier
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_carrier_duplicate()
 */
int nfc_handover_carrier_destroy(nfc_handover_carrier_h carrier);

/**
 * @brief get attribute property from handover configuration
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @remarks Do not destroy @a data returned from this function. (It managed by handover config)
 *
 * @param [in]  config The instance of handover config
 * @param [in]  attribute The id of specific attribute
 * @param [out] size The length of returned buffer
 * @param [out] data The data buffer of specific attribute
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_message_get_carrier()
 * @see nfc_handover_message_get_carrier_by_type()
 */
int nfc_handover_config_get_property(nfc_handover_config_h config, unsigned short attribute, unsigned short *size, unsigned char **data);

/**
 * @brief destroy handover config instance
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_HANDOVER_MODULE
 *
 * @param [in]  config The instance of handover config
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 *
 * @see nfc_handover_carrier_get_handover_config()
 */
int nfc_handover_config_destroy(nfc_handover_config_h config);

int nfc_manager_set_system_handler_enable_force(bool enable);
int nfc_p2p_send_no_permission(nfc_p2p_target_h target, nfc_ndef_message_h message, nfc_p2p_send_completed_cb callback, void *user_data);

int nfc_se_open_secure_element_internal(nfc_se_type_e se_type, nfc_se_h *handle);
int nfc_se_send_apdu_internal(nfc_se_h handle, unsigned char *cmd, unsigned int cmd_len, unsigned char **resp, unsigned int *resp_len);
int nfc_se_close_secure_element_internal(nfc_se_h handle);
int nfc_se_get_atr_internal(nfc_se_h handle, unsigned char **atr, unsigned int *atr_len);

/**
 * @brief Add a route for the specific AID.
 * @since_tizen 2.3.0.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] aid The AID
 * @param [in] se_type The type of Secure Element
 * @param [in] pkg_name The package name
 * @param [in] unlock_required @c true when enabling routing only in device unlock state, otherwise @c false
 * @param [in] power The device power state
 * @param [in] category The category which the AID associated with
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 *
 * @see nfc_se_remove_route_for_aid()
 */
int nfc_se_add_route_for_aid_internal(const char *aid, nfc_se_type_e se_type, const char* pkg_name, bool unlock_required, nfc_se_power_type_e power, nfc_card_emulation_category_type_e category);

/**
 * @brief Remove a route for the specific AID.
 * @since_tizen 2.3.0.1
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @param [in] pkg_name The package name
 * @param [in] aid The AID
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_INVALID_PARAMETER	Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 * @retval #NFC_ERROR_PERMISSION_DENIED	Permission denied
 * @retval #NFC_ERROR_OPERATION_FAILED Operation failed
 *
 * @see nfc_se_add_route_for_aid()
 */
int nfc_se_remove_route_for_aid_internal(const char* pkg_name, const char *aid);

/**
 * @brief Initializes NFC Manager.
 * @since_tizen 2.3
 * @ingroup CAPI_NETWORK_NFC_MANAGER_MODULE
 * @remarks This function must be called before proceeding any other nfc functions\n
 *	When an application crashes or exits without the deinitialization. NFC manager automatically deinitializes the process itself.\n
 *	This function is synchronous.
 *
 * @return 0 on success, otherwise a negative error value.
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_OPERATION_FAILED Operation fail
 *
 * @see nfc_manager_deinitialize()
 */
int nfc_manager_initialize_sync(void);

/**
 * @brief Get number of all registered AID.
 * @since_tizen 2.4
 * @privlevel public
 * @privilege   %http://tizen.org/privilege/nfc.cardemulation
 * @ingroup CAPI_NETWORK_NFC_SE_MODULE
 *
 * @remarks You can get number of aids only you registered.
 *
 * @param [in] se_type The type of Secure Element
 * @param [in] category The category
 * @param [out] count Number of registered aids
 *
 * @retval #NFC_ERROR_NONE Successful
 * @retval #NFC_ERROR_NOT_SUPPORTED Not supported NFC
 * @retval #NFC_ERROR_NOT_INITIALIZED Not initialized NFC
 * @retval #NFC_ERROR_NOT_ACTIVATED NFC is not activated
 * @retval #NFC_ERROR_ILLEGAL_STATE Illegal state
 * @retval #NFC_ERROR_INVALID_PARAMETER Invalid parameter
 * @retval #NFC_ERROR_OUT_OF_MEMORY Out of memory
 *
 * @see nfc_se_register_aid()
 * @see nfc_se_unregister_aid()
 * @see nfc_se_foreach_registered_aids()
 *
 */
int nfc_se_get_registered_aids_count(nfc_se_type_e se_type, nfc_card_emulation_category_type_e category, int *count);


#ifdef __cplusplus
}
#endif

#endif /* __NFC_INTERNAL_H__ */
