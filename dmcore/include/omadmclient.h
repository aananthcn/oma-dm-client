/*
 * libdmclient
 *
 * Copyright (C) 2012 Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * David Navarro <david.navarro@intel.com>
 *
 */

/*!
 * @file omadmclient.h
 *
 * @brief Interface to the dmclient library.
 *
 ******************************************************************************/

#ifndef OMADMCLIENT_H
#define OMADMCLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <omadmtree_mo.h>

#define DMCLT_FLAG_NONE         0x00
#define DMCLT_FLAG_UI_INFORM    0x04
#define DMCLT_FLAG_UI_ACCEPT    0x08

typedef enum {
	DMCLT_ERR_NONE = 0,
	DMCLT_ERR_END,
	DMCLT_ERR_INTERNAL,
	DMCLT_ERR_MEMORY,
	DMCLT_ERR_USAGE
} dmc_err_t;

typedef enum {
	DMCLT_AUTH_TYPE_UNKNOWN = 0,
	DMCLT_AUTH_TYPE_HTTP_BASIC,
	DMCLT_AUTH_TYPE_HTTP_DIGEST,
	DMCLT_AUTH_TYPE_BASIC,
	DMCLT_AUTH_TYPE_DIGEST,
	DMCLT_AUTH_TYPE_HMAC,
	DMCLT_AUTH_TYPE_X509,
	DMCLT_AUTH_TYPE_SECURID,
	DMCLT_AUTH_TYPE_SAFEWORD,
	DMCLT_AUTH_TYPE_DIGIPASS,
	DMCLT_AUTH_TYPE_TRANSPORT
} dmc_authType_t;

typedef struct {
	char *uri;
	dmc_authType_t auth_type;
	long auth_data_length;
	unsigned char *auth_data;
	long length;
	unsigned char *data;
} dmc_buffer_t;

typedef void *dmc_session;

typedef struct {
	char *source;
	char *target;
	char *type;
	char *format;
	char *data;
} dmc_item_t;

/** Definitions for User Interaction **/

typedef enum {
	DMCLT_UI_TYPE_UNDEFINED = 0,
	DMCLT_UI_TYPE_DISPLAY,
	DMCLT_UI_TYPE_CONFIRM,
	DMCLT_UI_TYPE_USER_INPUT,
	DMCLT_UI_TYPE_USER_CHOICE,
	DMCLT_UI_TYPE_USER_MULTICHOICE
} dmc_ui_type_t;

typedef enum {
	DMCLT_UI_INPUT_UNDEFINED = 0,
	DMCLT_UI_INPUT_ALPHA,
	DMCLT_UI_INPUT_NUM,
	DMCLT_UI_INPUT_DATE,
	DMCLT_UI_INPUT_TIME,
	DMCLT_UI_INPUT_PHONE,
	DMCLT_UI_INPUT_IP
} dmc_ui_input_t;

typedef enum {
	DMCLT_UI_ECHO_UNDEFINED = 0,
	DMCLT_UI_ECHO_TEXT,
	DMCLT_UI_ECHO_PASSWD
} dmc_ui_echo_t;

typedef struct {
	dmc_ui_type_t type;
	int min_disp;
	int max_disp;
	int max_resp_len;
	dmc_ui_input_t input_type;
	dmc_ui_echo_t echo_type;
	char *disp_msg;
	char *dflt_resp;
	char **choices;
} dmc_ui_t;

typedef int (*dmc_callback_t) (void *userData, const dmc_ui_t * uiData,
				 char *userReply);

/*----------------------------------------------------------------------------*/
/* data types and declarations to handle events from managment objects */
typedef unsigned long mo_event_t;

enum mo_events {
	EVENT_NONE = 0,
	FUMO_INSTALL_COMPLETE,
	SCOMO_INSTALL_COMPLETE,
	MAX_MO_EVENTS
};

typedef int (*mo_event_cb_t) (enum mo_events, int, int); /* 2nd arg - component ID,
							    3rd arg - optional argument */
int dmc_set_mo_event(enum mo_events event, int status); /* sets the flag */
int dmc_get_mo_event(enum mo_events event);		/* returns true if flag set */
int dmc_clr_mo_event(enum mo_events event);
int dmc_get_mo_status(enum mo_events event);

/*----------------------------------------------------------------------------*/

/*!
 * @brief Initializes an OMA DM session
 *
 * @param useWbxml if true, libdmclient will use WBXML to encode SyncML packets
 *
 * @returns a new session handle if successful or NULL in case of error
 */
dmc_session *omadmclient_session_init(bool useWbxml);

/*!
 * @brief Closes an initialized OMA DM session
 *
 * @param sessionH session handle
 */
void omadmclient_session_close(dmc_session sessionH);

/*!
 * @brief Sets the callback to use when OMA DM session requires UI
 *
 * @param UICallbacksP callback for user interaction. Can be nil.
 * @param userData past as parameter to UICallbacksP
  *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_set_UI_callback(dmc_session sessionH,
					dmc_callback_t UICallbacksP,
					void *userData);

/*!
 * @brief Adds an OMA Management Object to the DM tree used by the session
 *
 * @param sessionH session handle
 * @param moP interface of the MO to add. This will be freed by the lib on omadmclient_session_close().
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_session_add_mo(dmc_session sessionH,
				       omadm_mo_interface_t * moP);

/*!
 * @brief Retrieves the list of nodes URIs matching an URN
 *
 * @param sessionH session handle
 * @param urn URN to look for 
 * @param uriListP nil-terminated array of URI. To be freed by the caller.
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_getUriList(dmc_session sessionH, char *urn,
				   char ***uriListP);

/*!
 * @brief Starts an OMA DM session for the specified server
 *
 * @param sessionH session handle
 * @param serverID id of the DM server to connect to
 * @param sessionID id for the session
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_session_start(dmc_session sessionH, char *serverID,
				      int sessionID);

/*!
 * @brief Starts an OMA DM session in reply to an package #0
 *
 * @param sessionH session handle
 * @param pkg0 buffer containing the received package #0
 * @param pkg0_len length of the pkg0 buffer
 * @param flags (out) sessions flags. See DMCLT_FLAG_*. Can be nil.
 * @param body_offset (out) contains the offset to the start of the body. If there is no body, it will be
 * equal to pkg0_len. Can be nil.
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_session_start_on_alert(dmc_session sessionH,
					       uint8_t * pkg0, int pkg0_len,
					       char *flags, int *body_offset);

/*!
 * @brief Retrieves the next packet to be sent to the server
 *
 * @param sessionH session handle
 * @param packetP (out) storage for the packet must be freed by the caller
 *
 * @returns DMCLT_ERR_NONE if successful, DMCLT_ERR_END if the session is over
 *          or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_get_next_packet(dmc_session sessionH,
					dmc_buffer_t * packetP);

/*!
 * @brief Processes a packet received from the server
 *
 * @param sessionH session handle
 * @param packetP packet received from the server.
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_process_reply(dmc_session sessionH,
				      dmc_buffer_t * packetP);

/*!
 * @brief Add a generic alert to the next packet to be sent to the server
 *
 * @param sessionH session handle
 * @param correlator correlator for the generic alert. Ignored if NULL.
 * @param itemP item to add in the generic alert. NULL fields in itemP are ignored in the
 * <Item> element added to the <Alert>.
 *
 * @returns DMCLT_ERR_NONE if successful or one of DMCLT_ERR_*
 */
dmc_err_t omadmclient_add_generic_alert(dmc_session sessionH,
					  char *correlator,
					  dmc_item_t * itemP);

/*!
 * @brief Frees internal data of a dmc_buffer_t.
 *        The dmc_buffer_t remains untouched
 *
 * @param packetP
 */
void omadmclient_clean_buffer(dmc_buffer_t * packetP);

#endif				// OMADMCLIENT_H
