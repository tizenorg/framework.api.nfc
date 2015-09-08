/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


 /**
 * @file nfc_doc.h
 * @brief  This file contains high level documentation the NFC API.
 */

/**
 * @defgroup CAPI_NETWORK_NFC_MODULE NFC
 * @brief The NFC API provides very short-range radio communication technology.
 * @ingroup CAPI_NETWORK_FRAMEWORK
 *
 * @par
 * @section CAPI_NETWORK_NFC_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_MODULE_OVERVIEW Overview
 * NFC Service enables applications to\n
 * - set up nfc manager\n
 * - read / write ndef message or raw data and get attribute of tag\n
 * - create NDEF(NFC Data Exchange Format) message or NDEF record\n
 * - receive/send ndef message to the peer target\n
 * - read / write data to the Secure Element for Card Emulation mode\n
 *
 * @subsection CAPI_NETWORK_NFC_MANAGER_MODULE_DESCRIPTION nfc-manager
 * The nfc manager api provides functions to connect nfc-server and register event listener\n
 * - control connection with nfc-server. \n
 * - register / deregister event listeners for detecting tag, ndef, llcp, secure element \n
 * - set / unset tag filter to be listened only in case of specific tag. \n
 *
 * @subsection CAPI_NETWORK_NFC_NDEF_MODULE_DESCRIPTION NDEF(NFC Data Exchange Format)
 *  The NDEF(NFC Data Exchange Format) api provides functions to make NDEF record and NDEF message.\n
 * - create NDEF record and retrieve specific field of NDEF record\n
 * - create NDEF message with NDEF records\n
 *
 * @subsection CAPI_NETWORK_NFC_TAG_MODULE_DESCRIPTION TAG
 * The TAG api provide functions to read or write NDEF(NFC Data Exchange Format) and also low level transaction API with Non NDEF tag. \n
 * - read NDEF from NDEF compatible TAG\n
 * - write NDEF to NDEF compatible TAG\n
 * - check whether tag has NDEF or not\n
 * - format NFC forum tag to be compatible with NDEF\n
 * - read specific attributes from tag by ISO14443\n
 * - low level api of MIFARE classic and MIFARE ultra light\n
 *
 * @subsection CAPI_NETWORK_NFC_P2P_MODULE_DESCRIPTION Peer to Peer
 * The Peer to Peer api provide functions to exchange NDEF data with peer target.
 * - send ndef message\n
 * - receive ndef message\n
 *
 * @subsection CAPI_NETWORK_NFC_SE_MODULE_DESCRIPTION Card Emulation
 * The Card Emulation api provide functions to exchange data with Secure Element.
 * - send apdu to secure element\n
 * - get atr from secure element\n
 */

/**
 * @defgroup CAPI_NETWORK_NFC_MANAGER_MODULE Manager
 * @brief NFC Manager API provides access to NFC Events.
 * @ingroup CAPI_NETWORK_NFC_MODULE
 *
 * @section CAPI_NETWORK_NFC_MANAGER_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_MANAGER_MODULE_OVERVIEW Overview
 * The nfc manager api provides functions to connect nfc-server and register event listener\n
 * - control connection with nfc-server. \n
 * - register / deregister event listeners for detecting tag, ndef, llcp, secure element \n
 * - set / unset tag filter to be listened only in case of specific tag. \n
 * @section CAPI_NETWORK_NFC_MANAGER_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 * - http://tizen.org/feature/network.nfc.tag\n
 * - http://tizen.org/feature/network.nfc.p2p\n
 * - http://tizen.org/feature/network.nfc.card_emulation\n
 * - http://tizen.org/feature/network.secure_element.uicc\n
 * - http://tizen.org/feature/network.secure_element.ese\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */


/**
 * @defgroup CAPI_NETWORK_NFC_NDEF_MODULE NDEF
 * @brief The NDEF api provides functions to make NDEF record and NDEF message.
 * @ingroup CAPI_NETWORK_NFC_MODULE
 * @section CAPI_NETWORK_NFC_NDEF_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_NDEF_MODULE_OVERVIEW Overview
 *  The NDEF api provides functions to make NDEF record and NDEF message.\n
 * - create NDEF record and retrieve specific field of NDEF record\n
 * - create NDEF message with NDEF records\n
 *
 * <table>
 * <tr>
 *  <th> APIs </th>
 *  <th> Description </th>
 * </tr>
 * <tr>
 *  <td> @ref CAPI_NETWORK_NFC_NDEF_RECORD_MODULE </td>
 *  <td> Record API provides NDEF record and retrieve specific field of NDEF record </td>
 * </tr>
 * <tr>
 *  <td>  @ref CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE  </td>
 *  <td>Message API provides functions to create NDEF message and insert/remove records in NDEF message</td>
 * </tr>
 * </table>
 *
 */

/**
 * @defgroup CAPI_NETWORK_NFC_NDEF_RECORD_MODULE Record
 * @ingroup CAPI_NETWORK_NFC_NDEF_MODULE
 * @brief Record API provides an NDEF record.
 * @section CAPI_NETWORK_NFC_NDEF_RECORD_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 *
 * @section CAPI_NETWORK_NFC_NDEF_RECORD_MODULE_OVERVIEW Overview
 * The NDEF record api provides functions to make NDEF record\n
 * - create / destroy NDEF record\n
 * - set / get elements from NDEF record\n
 *
 * @section CAPI_NETWORK_NFC_NDEF_RECORD_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE Message
 * @ingroup CAPI_NETWORK_NFC_NDEF_MODULE
 * @brief Message API provides functions to create NDEF message and insert/remove records in NDEF message
 * @section CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 *
 * @section CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE_OVERVIEW Overview
 * The NDEF message api provides functions to make NDEF message\n
 * - create / destroy NDEF message\n
 * - insert / remove NDEF record\n
 * - get NDEF record from NDEF message\n
 *
 * @section CAPI_NETWORK_NFC_NDEF_MESSAGE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_NFC_TAG_MODULE TAG
 * @ingroup CAPI_NETWORK_NFC_MODULE
 * @brief TAG API provide functions for read/write operation on NDEF and also provide low level API of Mifare
 * @section CAPI_NETWORK_NFC_TAG_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_TAG_MODULE_OVERVIEW Overview
 * The TAG api provides functions to read or write NDEF and low level transaction APIs with Non NDEF tag. \n
 * - read NDEF from NDEF compatible TAG\n
 * - write NDEF to NDEF compatible TAG\n
 * - check whether tag has NDEF or not\n
 * - format NFC forum tag to be compatible with NDEF\n
 * - read specific attributes from tag by ISO14443\n
 * - low level api of MIFARE classic and MIFARE ultra light\n
 * @section CAPI_NETWORK_NFC_TAG_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 * - http://tizen.org/feature/network.nfc.tag\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */

/**
 * @defgroup CAPI_NETWORK_NFC_TAG_MIFARE_MODULE Mifare
 * @ingroup CAPI_NETWORK_NFC_TAG_MODULE
 * @brief API provides access to MIFARE specific I/O operations on a Tag.
 * @section CAPI_NETWORK_NFC_TAG_MIFARE_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_TAG_MIFARE_MODULE_OVERVIEW Overview

	MIFARE Classic is also known as MIFARE Standard.\n
	MIFARE Classic tags are divided into sectors, and each sector is sub-divided into blocks. Block size is always 16 bytes.\n

	MIFARE Classic Mini are 320 bytes (SIZE_MINI), with 5 sectors each of 4 blocks.\n
	MIFARE Classic 1k are 1024 bytes (SIZE_1K), with 16 sectors each of 4 blocks.\n
	MIFARE Classic 2k are 2048 bytes (SIZE_2K), with 32 sectors each of 4 blocks.\n
	MIFARE Classic 4k are 4096 bytes (SIZE_4K). The first 32 sectors contain 4 blocks and the last 8 sectors contain 16 blocks.\n

	MIFARE Classic tags require authentication on a per-sector basis before any other I/O operations on that sector can be performed. \n
	There are two keys per sector, and ACL bits determine what I/O operations are allowed on that sector after authenticating with a key\n
 * @section CAPI_NETWORK_NFC_TAG_MIFARE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 * - http://tizen.org/feature/network.nfc.tag\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */


 /**
 * @defgroup CAPI_NETWORK_NFC_P2P_MODULE Peer to Peer
 * @ingroup CAPI_NETWORK_NFC_MODULE
 * @brief The peer to peer api provide functions to exchange NDEF data with peer target.
 * @section CAPI_NETWORK_NFC_P2P_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_P2P_MODULE_OVERVIEW Overview
 * The peer to peer api provides functions to exchange NDEF data with the peer target. \n
 * - send ndef message
 * - receive ndef message
 * @section CAPI_NETWORK_NFC_P2P_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 * - http://tizen.org/feature/network.nfc.p2p\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */

 /**
 * @defgroup CAPI_NETWORK_NFC_SE_MODULE Card Emulation
 * @ingroup CAPI_NETWORK_NFC_MODULE
 * @brief The Card Emulation api provide functions to exchange data with Secure Element.
 * @section CAPI_NETWORK_NFC_SE_MODULE_HEADER	Required Header
 * \#include <nfc.h>
 * @section CAPI_NETWORK_NFC_SE_MODULE_OVERVIEW Overview
 * The Card Emulation api provide functions to exchange data with Secure Element. \n
 * - send apdu to secure element
 * - get atr from secure element
 * @section CAPI_NETWORK_NFC_SE_MODULE_FEATURE Related Features
 * This API is related with the following features:\n
 * - http://tizen.org/feature/network.nfc\n
 * - http://tizen.org/feature/network.nfc.card_emulation\n
 * - http://tizen.org/feature/network.nfc.card_emulation.hce\n
 * - http://tizen.org/feature/network.secure_element.uicc\n
 * - http://tizen.org/feature/network.secure_element.ese\n
 *
 * It is recommended to design feature related codes in your application for reliability.\n
 *
 * You can check if a devrice supports the related features for this API by using @ref CAPI_SYSTEM_SYSTEM_INFO_MODULE, thereby controlling the procedure of your application.\n
 *
 * To ensure your application is only running on the device with specific features, please define the features in your manifest file using the manifest editor in the SDK.\n
 *
 * More details on featuring your application can be found from <a href="../org.tizen.mobile.native.appprogramming/html/ide_sdk_tools/feature_element.htm"><b>Feature Element</b>.</a>
 *
 */
