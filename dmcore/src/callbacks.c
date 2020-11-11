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
 * @file callbacks.c
 *
 * @brief Callbacks for the SyncMLRTK.
 *
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>

#include "dmcore.h"

static Ret_t prv_do_generic_cmd_cb(InstanceID_t id,
				   VoidPtr_t userData, SmlGenericCmdPtr_t cmdP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;
	SmlItemListPtr_t itemCell;

	if (intp->sequence
	    && intp->seq_code != OMADM_SYNCML_ERROR_NOT_MODIFIED
	    && intp->seq_code != OMADM_SYNCML_ERROR_SUCCESS) {
		// do not treat this command
		smlFreeGeneric(cmdP);
		return SML_ERR_OK;
	}

	if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED != intp->srv_auth) {
		statusP = create_status(intp, intp->srv_auth, cmdP);

		add_element(intp, (basicElement_t *) statusP);
		smlFreeGeneric(cmdP);
		return SML_ERR_OK;
	}

	itemCell = cmdP->itemList;
	while (itemCell) {
		int code;

		if (intp->sequence
		    && intp->seq_code == OMADM_SYNCML_ERROR_NOT_MODIFIED) {
			code = OMADM_SYNCML_ERROR_NOT_EXECUTED;
		} else {
			switch (cmdP->elementType) {
			case SML_PE_ADD:
				code = add_node(intp, itemCell->item);
				break;
			case SML_PE_COPY:
				code = copy_node(intp, itemCell->item);
				break;
			case SML_PE_DELETE:
				code = delete_node(intp, itemCell->item);
				break;
			case SML_PE_REPLACE:
				code = replace_node(intp, itemCell->item);
				break;
			default:
				code =
				    OMADM_SYNCML_ERROR_COMMAND_NOT_IMPLEMENTED;
			}
		}
		statusP = create_status(intp, code, cmdP);
		add_target_ref(statusP, itemCell->item->target);
		add_element(intp, (basicElement_t *) statusP);

		itemCell = itemCell->next;
	}

	smlFreeGeneric(cmdP);
	return SML_ERR_OK;
}

static Ret_t prv_start_message_cb(InstanceID_t id,
				  VoidPtr_t userData, SmlSyncHdrPtr_t headerP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;
	SmlChalPtr_t challengeP = NULL;
	char *dataStr;

	if (intp->reply_ref) {
		free(intp->reply_ref);
	}
	intp->sequence = NULL;
	intp->seq_code = 0;

	intp->reply_ref = smlPcdata2String(headerP->msgID);

	if (headerP->cred) {
		intp->srv_auth =
		    check_credentials(headerP->cred,
				      intp->account->toClientCred);
		challengeP = get_challenge(intp->account->toClientCred);
		store_nonce(intp->dmtreeH->MOs, intp->account, false);
	}

	dataStr = smlPcdata2String(headerP->respURI);
	if (dataStr) {
		set_new_uri(intp, dataStr);
		free(dataStr);
	}

	statusP = create_status(intp, intp->srv_auth, NULL);
	statusP->chal = challengeP;
	add_target_ref(statusP, headerP->target);
	add_source_ref(statusP, headerP->source);

	add_element(intp, (basicElement_t *) statusP);

	smlFreeSyncHdr(headerP);
	return SML_ERR_OK;
}

static Ret_t prv_end_message_cb(InstanceID_t id,
				VoidPtr_t userData, Boolean_t final)
{
	return SML_ERR_OK;
}

static Ret_t prv_start_atomic_cb(InstanceID_t id,
				 VoidPtr_t userData, SmlAtomicPtr_t atomicP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;

	if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED != intp->srv_auth) {
		statusP =
		    create_status(intp, intp->srv_auth,
				  (SmlGenericCmdPtr_t) atomicP);

		add_element(intp, (basicElement_t *) statusP);
		smlFreeAtomic(atomicP);
		return SML_ERR_OK;
	}

	smlFreeAtomic(atomicP);
	return SML_ERR_OK;
}

static Ret_t prv_end_atomic_cb(InstanceID_t id, VoidPtr_t userData)
{
	return SML_ERR_OK;
}

static Ret_t prv_start_sequence_cb(InstanceID_t id,
				   VoidPtr_t userData,
				   SmlSequencePtr_t sequenceP)
{
	dmcore_t *intp = (dmcore_t *) userData;

	intp->sequence = sequenceP;
	if (intp->srv_auth == OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED) {
		intp->seq_code = OMADM_SYNCML_ERROR_SUCCESS;
	} else {
		intp->seq_code = intp->srv_auth;
	}

	smlFreeAtomic((SmlAtomicPtr_t) sequenceP);
	return SML_ERR_OK;
}

static Ret_t prv_end_sequence_cb(InstanceID_t id, VoidPtr_t userData)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;

	statusP =
	    create_status(intp, intp->seq_code,
			  (SmlGenericCmdPtr_t) (intp->sequence));
	add_element(intp, (basicElement_t *) statusP);

	intp->sequence = NULL;
	intp->seq_code = 0;

	return SML_ERR_OK;
}

static Ret_t prv_alert_cmd_cb(InstanceID_t id,
			      VoidPtr_t userData, SmlAlertPtr_t alertP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;
	int code;
	dmc_ui_t *dmcAlertP;
	char *answer;

	dmcAlertP = NULL;
	answer = NULL;

	if (intp->sequence) {
		switch (intp->seq_code) {
		case OMADM_SYNCML_ERROR_NOT_MODIFIED:
			// user aborted sequence
			code = OMADM_SYNCML_ERROR_NOT_EXECUTED;
			goto end;
		case OMADM_SYNCML_ERROR_SUCCESS:
			// everything is fine
			break;
		default:
			// do not treat this command
			smlFreeAlert(alertP);
			return SML_ERR_OK;
		}
	}

	if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED != intp->srv_auth) {
		code = intp->srv_auth;
		goto end;
	}

	if (NULL == intp->alert_cb) {
		code = OMADM_SYNCML_ERROR_OPTIONAL_FEATURE_NOT_SUPPORTED;
		goto end;
	}

	dmcAlertP = get_ui_from_sml(alertP);
	if (NULL == dmcAlertP) {
		code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
		goto end;
	}
//TODO: check for UTF8
	answer = (char *)malloc(dmcAlertP->max_resp_len + 1);
	if (NULL == answer) {
		code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
		goto end;
	}

	code = intp->alert_cb(intp->cb_data, dmcAlertP, answer);

	if (intp->sequence && dmcAlertP->type == DMCLT_UI_TYPE_CONFIRM) {
		intp->seq_code = code;
	}

 end:
	// the SmlAlertPtr_t can be cast as a SmlGenericCmdPtr_t since we only
	// need elementType and cmdID in prvCreateStatus()
	statusP = create_status(intp, code, (SmlGenericCmdPtr_t) alertP);

	if ((code == OMADM_SYNCML_ERROR_SUCCESS)
	    && (dmcAlertP->type >= DMCLT_UI_TYPE_USER_INPUT)) {
		statusP->itemList = smlAllocItemList();
		if (statusP->itemList) {
			statusP->itemList->item->data =
			    smlString2Pcdata(answer ? answer : "");
		}
	}

	add_element(intp, (basicElement_t *) statusP);

	if (answer)
		free(answer);
	if (dmcAlertP)
		free_dmc_alert(dmcAlertP);

	smlFreeAlert(alertP);
	return SML_ERR_OK;
}

static Ret_t prv_get_cmd_cb(InstanceID_t id,
			    VoidPtr_t userData, SmlGetPtr_t getP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;
	SmlItemListPtr_t itemCell;
	SmlItemListPtr_t resultLastCell;
	SmlResultsPtr_t resultP;

	if (intp->sequence
	    && intp->seq_code != OMADM_SYNCML_ERROR_NOT_MODIFIED
	    && intp->seq_code != OMADM_SYNCML_ERROR_SUCCESS) {
		// do not treat this command
		smlFreeGetPut((SmlPutPtr_t) getP);
		return SML_ERR_OK;
	}

	if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED != intp->srv_auth) {
		statusP =
		    create_status(intp, intp->srv_auth,
				  (SmlGenericCmdPtr_t) getP);

		add_element(intp, (basicElement_t *) statusP);
		smlFreeGetPut((SmlPutPtr_t) getP);
		return SML_ERR_OK;
	}

	resultP = smlAllocResults();
	if (!resultP)
		return SML_ERR_NOT_ENOUGH_SPACE;
	set_pcdata_pcdata(resultP->cmdRef, getP->cmdID);
	resultP->msgRef = smlString2Pcdata(intp->reply_ref);
	smlFreeItemList(resultP->itemList);
	resultP->itemList = NULL;

	resultLastCell = NULL;
	itemCell = getP->itemList;
	while (itemCell) {
		int code;

		if (intp->sequence
		    && intp->seq_code == OMADM_SYNCML_ERROR_NOT_MODIFIED) {
			code = OMADM_SYNCML_ERROR_NOT_EXECUTED;
		} else {
			SmlItemListPtr_t newCell;

			newCell = smlAllocItemList();
			if (!newCell) {
				code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
			} else {
				code =
				    get_node(intp, itemCell->item,
					     newCell->item);
			}
			if (code == OMADM_SYNCML_ERROR_SUCCESS) {
				if (resultLastCell) {
					resultLastCell->next = newCell;
				} else {
					resultP->itemList = newCell;
				}
				resultLastCell = newCell;
			} else {
				smlFreeItemList(newCell);
			}
		}
		statusP =
		    create_status(intp, code, (SmlGenericCmdPtr_t) getP);
		add_target_ref(statusP, itemCell->item->target);
		add_element(intp, (basicElement_t *) statusP);

		itemCell = itemCell->next;
	}

	if (resultP->itemList) {
		add_element(intp, (basicElement_t *) resultP);
	} else {
		smlFreeResults(resultP);
	}

	smlFreeGetPut((SmlPutPtr_t) getP);
	return SML_ERR_OK;
}

static Ret_t prv_exec_cmd_cb(InstanceID_t id,
			     VoidPtr_t userData, SmlExecPtr_t execP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	SmlStatusPtr_t statusP;
	SmlItemListPtr_t itemCell;

	if (intp->sequence
	    && intp->seq_code != OMADM_SYNCML_ERROR_NOT_MODIFIED
	    && intp->seq_code != OMADM_SYNCML_ERROR_SUCCESS) {
		// do not treat this command
		smlFreeExec(execP);
		return SML_ERR_OK;
	}

	if (OMADM_SYNCML_ERROR_AUTHENTICATION_ACCEPTED != intp->srv_auth) {
		statusP = create_status(intp, intp->srv_auth,
				  (SmlGenericCmdPtr_t) execP);

		add_element(intp, (basicElement_t *) statusP);
		smlFreeExec(execP);
		return SML_ERR_OK;
	}

	itemCell = execP->itemList;
	while (itemCell) {
		int code;

		if (intp->sequence
		    && intp->seq_code == OMADM_SYNCML_ERROR_NOT_MODIFIED) {
			code = OMADM_SYNCML_ERROR_NOT_EXECUTED;
		} else {
			code = exec_node(intp, itemCell->item,
					 execP->correlator);
		}
		statusP = create_status(intp, code, (SmlGenericCmdPtr_t) execP);
		add_target_ref(statusP, itemCell->item->target);
		add_element(intp, (basicElement_t *) statusP);

		itemCell = itemCell->next;
	}

	smlFreeExec(execP);
	return SML_ERR_OK;
}

static Ret_t prv_status_cmd_cb(InstanceID_t id,
			       VoidPtr_t userData, SmlStatusPtr_t statusP)
{
	dmcore_t *intp = (dmcore_t *) userData;
	int code;
	char *cmdRef;
	char *msgRef;

	cmdRef = smlPcdata2String(statusP->cmdRef);
	if (!cmdRef)
		return SML_ERR_WRONG_PARAM;

	msgRef = smlPcdata2String(statusP->msgRef);
	if (!msgRef) {
		free(cmdRef);
		smlFreeStatus(statusP);
		return SML_ERR_WRONG_PARAM;
	}

	code = pcdata_to_int(statusP->data);

	if (strcmp(cmdRef, "0")) {
		elemCell_t *cellP;

		cellP = retrieve_element(intp, cmdRef, msgRef);
		if (cellP) {
			switch (code) {
			case OMADM_SYNCML_ERROR_IN_PROGRESS:
				// put it back in the sent command list
				put_back_element(intp, cellP);
				break;
			case OMADM_SYNCML_ERROR_INVALID_CREDENTIALS:
			case OMADM_SYNCML_ERROR_MISSING_CREDENTIALS:
				// resend this with the new header
				add_element(intp, cellP->element);
				free(cellP);	// /!\ do not free the element
				break;
			default:
				// nothing more to do
				free_element_list(cellP);
				break;
			}
		}
	} else {
		// we are dealing with the header
		intp->clt_auth = code;
		if (statusP->chal) {
			dmc_authType_t type;
			buffer_t newNonce;

			type =
			    get_from_chal_meta(statusP->chal->meta, &newNonce);
			if (type != DMCLT_AUTH_TYPE_UNKNOWN) {
				intp->account->toServerCred->type = type;
				if (intp->account->toServerCred->data.buffer)
					free(intp->account->toServerCred->
					     data.buffer);
				intp->account->toServerCred->data.buffer =
				    newNonce.buffer;
				intp->account->toServerCred->data.len =
				    newNonce.len;
				store_nonce(intp->dmtreeH->MOs,
					    intp->account, true);
			}
		}
	}

	free(cmdRef);
	free(msgRef);
	smlFreeStatus(statusP);

	return SML_ERR_OK;
}

static Ret_t prv_handle_error_cb(InstanceID_t id, VoidPtr_t userData)
{
	return SML_ERR_OK;
}

static Ret_t prv_transmit_chunk_cb(InstanceID_t id, VoidPtr_t userData)
{
	return SML_ERR_OK;
}

SmlCallbacksPtr_t get_callbacks()
{
	SmlCallbacksPtr_t callbacksP;

	callbacksP = (SmlCallbacksPtr_t) malloc(sizeof(SmlCallbacks_t));
	if (callbacksP) {
		memset(callbacksP, 0, sizeof(SmlCallbacks_t));
		callbacksP->startMessageFunc = prv_start_message_cb;
		callbacksP->endMessageFunc = prv_end_message_cb;
		callbacksP->startAtomicFunc = prv_start_atomic_cb;
		callbacksP->endAtomicFunc = prv_end_atomic_cb;
		callbacksP->startSequenceFunc = prv_start_sequence_cb;
		callbacksP->endSequenceFunc = prv_end_sequence_cb;
		callbacksP->addCmdFunc = prv_do_generic_cmd_cb;
		callbacksP->alertCmdFunc = prv_alert_cmd_cb;
		callbacksP->deleteCmdFunc = prv_do_generic_cmd_cb;
		callbacksP->execCmdFunc = prv_exec_cmd_cb;
		callbacksP->getCmdFunc = prv_get_cmd_cb;
		callbacksP->statusCmdFunc = prv_status_cmd_cb;
		callbacksP->replaceCmdFunc = prv_do_generic_cmd_cb;
		callbacksP->copyCmdFunc = prv_do_generic_cmd_cb;
		callbacksP->handleErrorFunc = prv_handle_error_cb;
		callbacksP->transmitChunkFunc = prv_transmit_chunk_cb;

		// Commands ignored
		callbacksP->endSyncFunc = NULL;
	}

	return callbacksP;
}
