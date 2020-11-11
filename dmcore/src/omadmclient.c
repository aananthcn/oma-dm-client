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
 * @file omadmclient.c
 *
 * @brief Main file for the omadmclient library.  Contains code for APIs.
 *
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include "dmcore.h"

#define PRV_CHECK_SML_CALL(func)    if (SML_ERR_OK != (func)) \
						      return DMCLT_ERR_INTERNAL
#define PRV_MAX_MESSAGE_SIZE        "16384"



/* variables to manage events passed by management objects */
mo_event_t MoEvents;
pthread_mutex_t MoEventMutex = PTHREAD_MUTEX_INITIALIZER;
int MoEventStatus[MAX_MO_EVENTS];


static void prvCreatePacket1(dmcore_t * intp)
{
	// this is the beginning of the session
	SmlAlertPtr_t alertP;

	alertP = smlAllocAlert();
	if (alertP) {
		SmlReplacePtr_t replaceP;

		switch (intp->state) {
		case STATE_CLIENT_INIT:
			alertP->data = smlString2Pcdata("1201");
			break;
		case STATE_SERVER_INIT:
			alertP->data = smlString2Pcdata("1200");
			break;
		default:
			smlFreeProtoElement((basicElement_t *) alertP);
			return;
		}
		smlFreeItemList(alertP->itemList);
		alertP->itemList = NULL;

		replaceP = get_device_info(intp);
		if (replaceP) {
			add_element(intp, (basicElement_t *) alertP);
			add_element(intp, (basicElement_t *) replaceP);
			intp->state = STATE_IN_SESSION;
		} else {
			smlFreeProtoElement((basicElement_t *) alertP);
		}
	}
}

static SmlSyncHdrPtr_t prvGetHeader(dmcore_t * intp)
{
	SmlSyncHdrPtr_t headerP;

	headerP = smlAllocSyncHdr();
	if (headerP) {
		set_pcdata_string(headerP->version, "1.2");
		set_pcdata_string(headerP->proto, "DM/1.2");
		set_pcdata_hex(headerP->sessionID, intp->session_id);
		set_pcdata_int(headerP->msgID, intp->message_id);
		set_pcdata_string(headerP->target->locURI,
				  intp->account->server_uri);
		set_pcdata_string(headerP->source->locURI, intp->account->id);
		if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED !=
		    intp->clt_auth
		    && OMADM_SYNCML_ERROR_SUCCESS != intp->clt_auth) {
			headerP->cred =
			    get_credentials(intp->account->toServerCred);
		}
		headerP->meta = smlAllocPcdata();
		if (headerP->meta) {
			SmlMetInfMetInfPtr_t metInfP;

			metInfP = smlAllocMetInfMetInf();
			if (metInfP) {
				metInfP->maxmsgsize =
				    smlString2Pcdata(PRV_MAX_MESSAGE_SIZE);
				headerP->meta->contentType =
				    SML_PCDATA_EXTENSION;
				headerP->meta->extension = SML_EXT_METINF;
				headerP->meta->length = 0;
				headerP->meta->content = metInfP;
			} else {
				smlFreePcdata(headerP->meta);
				headerP->meta = NULL;
			}
		}

	}

	return headerP;
}

static int prvComposeMessage(dmcore_t * intp)
{
	int toSend = -1;
	Ret_t result;
	SmlSyncHdrPtr_t syncHdrP;
	elemCell_t *cell;

	intp->message_id++;
	intp->command_id = 1;

	syncHdrP = prvGetHeader(intp);

	result = smlStartMessageExt(intp->smlH, syncHdrP, SML_VERS_1_2);

	smlFreeSyncHdr(syncHdrP);

	cell = intp->elem_first;
	while (cell && result == SML_ERR_OK) {
		set_pcdata_int(cell->element->cmdID, intp->command_id++);
		cell->msg_id = intp->message_id;

		switch (cell->element->elementType) {
		case SML_PE_ALERT:
			result =
			    smlAlertCmd(intp->smlH,
					(SmlAlertPtr_t) (cell->element));
			toSend = 1;
			break;

		case SML_PE_REPLACE:
			result =
			    smlReplaceCmd(intp->smlH,
					  (SmlReplacePtr_t) (cell->element));
			toSend = 1;
			break;

		case SML_PE_RESULTS:
			result =
			    smlResultsCmd(intp->smlH,
					  (SmlResultsPtr_t) (cell->element));
			toSend = 1;
			break;

		case SML_PE_STATUS:
			result =
			    smlStatusCmd(intp->smlH,
					 (SmlStatusPtr_t) (cell->element));
			toSend++;
			break;

		default:
			// should not happen
			break;
		}

		cell = cell->next;
	}

	if (result != SML_ERR_OK) {
		return DMCLT_ERR_INTERNAL;
	}

	PRV_CHECK_SML_CALL(smlEndMessage(intp->smlH, SmlFinal_f));

	refresh_elements(intp);

	if (toSend <= 0) {
		return DMCLT_ERR_END;
	}

	return DMCLT_ERR_NONE;
}

static void prvFreeAuth(authDesc_t * authP)
{
	if (!authP)
		return;

	if (authP->name)
		free(authP->name);
	if (authP->secret)
		free(authP->secret);
	if (authP->data.buffer)
		free(authP->data.buffer);

	free(authP);
}

dmc_session *dmc_session_init(bool useWbxml)
{
	dmcore_t *intp;
	SmlInstanceOptions_t opts;
	Ret_t rc;

	intp = (dmcore_t *) malloc(sizeof(dmcore_t));
	if (!intp) {
		return NULL;
	}

	/* clear newly allocated memory */
	memset(intp, 0, sizeof(dmcore_t));
	memset(&opts, 0, sizeof(opts));

	if (useWbxml) {
		opts.encoding = SML_WBXML;
	} else {
		opts.encoding = SML_XML;
	}
	opts.workspaceSize = PRV_MAX_WORKSPACE_SIZE;
	intp->sml_callbacks = get_callbacks();

	rc = smlInitInstance(intp->sml_callbacks, &opts, NULL, &(intp->smlH));
	if (SML_ERR_OK != rc) {
		dmc_session_close((void **)intp);
		free(intp);
		intp = NULL;
	}

	if (OMADM_SYNCML_ERROR_NONE != dmtree_open(&(intp->dmtreeH))) {
		dmc_session_close((void **)intp);
		free(intp);
		intp = NULL;
	}

	return (dmc_session) intp;
}

dmc_err_t dmc_set_UI_callback(dmc_session dmcs,
			      dmc_callback_t UICallbacksP, void *userData)
{
	dmcore_t *intp = (dmcore_t *) dmcs;

	if (intp == NULL) {
		return DMCLT_ERR_USAGE;
	}

	intp->alert_cb = UICallbacksP;
	intp->cb_data = userData;

	return DMCLT_ERR_NONE;
}

dmc_err_t dmc_session_add_mo(dmc_session dmcs, omadm_mo_interface_t * moP)
{
	dmcore_t *intp = (dmcore_t *) dmcs;

	if (intp == NULL || moP == NULL) {
		return DMCLT_ERR_USAGE;
	}

	if (OMADM_SYNCML_ERROR_NONE !=
	    momgr_add_plugin(intp->dmtreeH->MOs, moP)) {
		return DMCLT_ERR_INTERNAL;
	}

	return DMCLT_ERR_NONE;
}

dmc_err_t dmc_getUriList(dmc_session dmcs, char *urn, char ***uriListP)
{
	dmcore_t *intp = (dmcore_t *) dmcs;

	if (intp == NULL || urn == NULL || uriListP == NULL) {
		return DMCLT_ERR_USAGE;
	}

	if (OMADM_SYNCML_ERROR_NONE !=
	    momgr_list_uri(intp->dmtreeH->MOs, urn, uriListP)) {
		return DMCLT_ERR_INTERNAL;
	}

	return DMCLT_ERR_NONE;
}

dmc_err_t dmc_session_start(dmc_session dmcs, char *serverID, int sessionID)
{
	int rc;
	dmcore_t *intp = (dmcore_t *) dmcs;

	if (intp == NULL || serverID == NULL) {
		return DMCLT_ERR_USAGE;
	}

	rc = dmtree_setServer(intp->dmtreeH, serverID);
	if (OMADM_SYNCML_ERROR_NONE != rc) {
		return DMCLT_ERR_INTERNAL;
	}

	rc = momgr_check_mandatory_mo(intp->dmtreeH->MOs);
	if (OMADM_SYNCML_ERROR_NONE != rc) {
		return DMCLT_ERR_USAGE;
	}

	rc = get_server_account(intp->dmtreeH->MOs, serverID, &(intp->account));
	if (OMADM_SYNCML_ERROR_NONE != rc) {
		return DMCLT_ERR_INTERNAL;
	}

	if (NULL == intp->account->toClientCred) {
		intp->srv_auth = OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED;
	}
	if (NULL == intp->account->toServerCred) {
		intp->clt_auth = OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED;
	}

	intp->session_id = sessionID;
	intp->message_id = 0;
	intp->state = STATE_CLIENT_INIT;

	return DMCLT_ERR_NONE;
}

dmc_err_t dmc_session_start_on_alert(dmc_session dmcs,
				     uint8_t * pkg0,
				     int pkg0_len,
				     char *flags, int *body_offset)
{
	dmcore_t *intp = (dmcore_t *) dmcs;
	char *serverID;
	int sessionID;
	dmc_err_t err;
	buffer_t package;

	if (intp == NULL || pkg0 == NULL || pkg0_len <= 0) {
		return DMCLT_ERR_USAGE;
	}

	package.buffer = pkg0;
	package.len = pkg0_len;

	if (OMADM_SYNCML_ERROR_NONE !=
	    decode_package_0(package, &serverID, &sessionID, flags,
			     body_offset)) {
		return DMCLT_ERR_USAGE;
	}
	// We start the session now since we need to access the DM tree to validate the received package0.
	err = dmc_session_start(dmcs, serverID, sessionID);

	if (DMCLT_ERR_NONE == err) {
		if (OMADM_SYNCML_ERROR_NONE !=
		    validate_package_0(intp, package)) {
			err = DMCLT_ERR_USAGE;
		}
	}

	intp->state = STATE_SERVER_INIT;

	return err;
}

void dmc_session_close(dmc_session dmcs)
{
	dmcore_t *intp = (dmcore_t *) dmcs;

	if (!intp) {
		return;
	}

	if (intp->dmtreeH) {
		dmtree_close(intp->dmtreeH);
	}
	if (intp->smlH) {
		smlTerminateInstance(intp->smlH);
	}
	if (intp->sml_callbacks) {
		free(intp->sml_callbacks);
	}
	if (intp->elem_first) {
		free_element_list(intp->elem_first);
	}
	if (intp->old_elem) {
		free_element_list(intp->old_elem);
	}
	if (intp->reply_ref) {
		free(intp->reply_ref);
	}
	if (intp->account) {
		if (intp->account->id)
			free(intp->account->id);
		if (intp->account->server_uri)
			free(intp->account->server_uri);
		if (intp->account->dmtree_uri)
			free(intp->account->dmtree_uri);
		prvFreeAuth(intp->account->toServerCred);
		prvFreeAuth(intp->account->toClientCred);
		free(intp->account);
	}
	memset(intp, 0, sizeof(dmcore_t));
}

static void prvCreatePacketFumoAlert(dmcore_t * intp, int ret)
{
	SmlAlertPtr_t alertP;

	alertP = smlAllocAlert();
	if (alertP) {
		SmlReplacePtr_t replaceP;
		switch (ret) {
		case REQ_STAT_UPDATE_DONE:
			alertP->data = smlString2Pcdata("200");
			break;
		case REQ_STAT_NA_INVALID:
		case REQ_STAT_PKG_ERROR:
			alertP->data = smlString2Pcdata("405");
			break;
		case REQ_STAT_UPDATER_ERROR:
		case REQ_STAT_UPDATE_ERROR:
		case REQ_STAT_REMOVE_ERROR:
			alertP->data = smlString2Pcdata("410");
			break;
		default:
			smlFreeProtoElement((basicElement_t *) alertP);
			return;
		}
		smlFreeItemList(alertP->itemList);
		alertP->itemList = NULL;
		replaceP = get_fumo_alert(intp);
		if (replaceP) {
			add_element(intp, (basicElement_t *) alertP);
			add_element(intp, (basicElement_t *) replaceP);
			intp->state = STATE_IN_SESSION;
		} else {
			smlFreeProtoElement((basicElement_t *) alertP);
		}
	}
}


/**********************************************************************************
 * Event Managment Functions
 * 
 * Caller: this and dm-client
 */
int dmc_set_mo_event(enum mo_events event, int status)
{
	if ((event >= MAX_MO_EVENTS) || ((int)event >= sizeof(mo_event_t)))
		return -1;

	pthread_mutex_lock(&MoEventMutex);
	MoEvents |= ((mo_event_t)1 << event);
	MoEventStatus[event] = status;
	pthread_mutex_unlock(&MoEventMutex);

	return 0;
}

int dmc_clr_mo_event(enum mo_events event)
{
	if ((event >= MAX_MO_EVENTS) || ((int)event >= sizeof(mo_event_t)))
		return -1;

	pthread_mutex_lock(&MoEventMutex);
	MoEvents &= ~((mo_event_t)1 << event);
	MoEventStatus[event] = 205; /* reset content */
	pthread_mutex_unlock(&MoEventMutex);

	return 0;
}

int dmc_get_mo_event(enum mo_events event)
{
	int test;

	if ((event >= MAX_MO_EVENTS) || ((int)event >= sizeof(mo_event_t)))
		return -1;

	pthread_mutex_lock(&MoEventMutex);
	test = MoEvents & ((mo_event_t)1 << event);
	pthread_mutex_unlock(&MoEventMutex);

	if (test)
		return TRUE;
	else
		return FALSE;
}


int dmc_get_mo_status(enum mo_events event)
{
	int status;

	if ((event >= MAX_MO_EVENTS) || ((int)event >= sizeof(mo_event_t)))
		return 416; /* Requested Range Not Satisfiable */

	pthread_mutex_lock(&MoEventMutex);
	status = MoEventStatus[event];
	pthread_mutex_unlock(&MoEventMutex);

	return status;
}

/**********************************************************************************
 */
dmc_err_t dmc_get_next_packet(dmc_session dmcs, dmc_buffer_t * pktp)
{
	dmcore_t *intp = (dmcore_t *) dmcs;
	dmc_err_t status;
	int mo_status;

	if (!intp || !pktp || !(intp->account)) {
		return DMCLT_ERR_USAGE;
	}

	if (STATE_IN_SESSION != intp->state) {
		prvCreatePacket1(intp);
	}

	if (TRUE == dmc_get_mo_event(FUMO_INSTALL_COMPLETE)) {
		mo_status = dmc_get_mo_status(FUMO_INSTALL_COMPLETE);
		prvCreatePacketFumoAlert(intp, mo_status);
		dmc_clr_mo_event(FUMO_INSTALL_COMPLETE);
	}

	status = prvComposeMessage(intp);

	memset(pktp, 0, sizeof(dmc_buffer_t));
	if (status == DMCLT_ERR_NONE) {
		MemPtr_t dataP;
		MemSize_t size;

		PRV_CHECK_SML_CALL(smlLockReadBuffer
				   (intp->smlH, &dataP, &size));

		pktp->data = (unsigned char *)malloc(size);
		if (!pktp->data)
			return DMCLT_ERR_MEMORY;
		memcpy(pktp->data, dataP, size);
		pktp->length = size;
		pktp->uri = strdup(intp->account->server_uri);
		PRV_CHECK_SML_CALL(smlUnlockReadBuffer(intp->smlH, size));

		// export authentication data for non OMA-DM level authentication types
		pktp->auth_type = intp->account->toServerCred->type;
		if (0 != intp->account->toServerCred->data.len) {
			switch (pktp->auth_type) {
			case DMCLT_AUTH_TYPE_BASIC:
			case DMCLT_AUTH_TYPE_DIGEST:
				// do nothing, authentication is handled in the DM packet
				break;
			default:
				pktp->auth_data =
				    (unsigned char *)malloc(intp->
							    account->toServerCred->data.
							    len);
				if (NULL == pktp->auth_data) {
					dmc_clean_buffer(pktp);
					status = DMCLT_ERR_MEMORY;
				} else {
					memcpy(pktp->auth_data,
					       intp->account->
					       toServerCred->data.buffer,
					       intp->account->
					       toServerCred->data.len);
					pktp->auth_data_length =
					    intp->account->toServerCred->data.
					    len;
				}
			}
		}
	}

	return status;
}

dmc_err_t dmc_process_reply(dmc_session dmcs, dmc_buffer_t * pktp)
{
	dmcore_t *intp = (dmcore_t *) dmcs;
	MemPtr_t dataP;
	MemSize_t size;

	if (!intp || !pktp) {
		return DMCLT_ERR_USAGE;
	}

	PRV_CHECK_SML_CALL(smlLockWriteBuffer(intp->smlH, &dataP, &size));
	if (size >= pktp->length) {
		memcpy(dataP, pktp->data, pktp->length);
	}
	PRV_CHECK_SML_CALL(smlUnlockWriteBuffer(intp->smlH, pktp->length));

	PRV_CHECK_SML_CALL(smlSetUserData(intp->smlH, intp));

	PRV_CHECK_SML_CALL(smlProcessData(intp->smlH, SML_ALL_COMMANDS));

	return DMCLT_ERR_NONE;
}

dmc_err_t dmc_add_generic_alert(dmc_session dmcs, char *c, dmc_item_t * itemP)
{
	SmlAlertPtr_t alertP;
	dmcore_t *intp = (dmcore_t *) dmcs;
	char *correlator = c;

	if (!intp || !itemP || !itemP->type || !itemP->format || !itemP->data) {
		return DMCLT_ERR_USAGE;
	}

	alertP = smlAllocAlert();
	if (NULL == alertP) {
		return DMCLT_ERR_MEMORY;
	}

	alertP->data = smlString2Pcdata("1226");
	if (NULL == alertP->data) {
		smlFreeAlert(alertP);
		return DMCLT_ERR_MEMORY;
	}

	if (correlator) {
		alertP->correlator = smlString2Pcdata(correlator);
		if (NULL == alertP->correlator) {
			smlFreeAlert(alertP);
			return DMCLT_ERR_MEMORY;
		}
	}

	if (itemP->source) {
		alertP->itemList->item->source = smlAllocSource();
		if (NULL == alertP->itemList->item->source) {
			smlFreeAlert(alertP);
			return DMCLT_ERR_MEMORY;
		}
		alertP->itemList->item->source->locURI =
		    smlString2Pcdata(itemP->source);
	}

	if (itemP->target) {
		alertP->itemList->item->target = smlAllocTarget();
		if (NULL == alertP->itemList->item->target) {
			smlFreeAlert(alertP);
			return DMCLT_ERR_MEMORY;
		}
		alertP->itemList->item->target->locURI =
		    smlString2Pcdata(itemP->target);
	}

	alertP->itemList->item->meta =
	    convert_to_meta(itemP->format, itemP->type);
	alertP->itemList->item->data = smlString2Pcdata(itemP->data);
	if (NULL == alertP->itemList->item->meta
	    || NULL == alertP->itemList->item->data) {
		smlFreeAlert(alertP);
		return DMCLT_ERR_MEMORY;
	}

	add_element(intp, (basicElement_t *) alertP);

	return DMCLT_ERR_NONE;
}

void dmc_clean_buffer(dmc_buffer_t * pktp)
{
	if (pktp) {
		if (pktp->uri) {
			free(pktp->uri);
		}
		if (pktp->data) {
			free(pktp->data);
		}
		if (pktp->auth_data) {
			free(pktp->auth_data);
		}
		memset(pktp, 0, sizeof(dmc_buffer_t));
	}
}
