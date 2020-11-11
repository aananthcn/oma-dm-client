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
 * @file sml2tree.c
 *
 * @brief Interface between SyncMLRTK and internal dm tree.
 *
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "dmcore.h"

#define PRV_CONVERT_CODE(code) if ((code) == OMADM_SYNCML_ERROR_NONE) code = OMADM_SYNCML_ERROR_SUCCESS

int prv_fill_item(SmlItemPtr_t itemP, dmtree_node_t node)
{
	itemP->source = smlAllocSource();
	if (!itemP->source) {
		return OMADM_SYNCML_ERROR_COMMAND_FAILED;
	}
	smlFreePcdata(itemP->source->locURI);
	itemP->source->locURI = smlString2Pcdata(node.uri);
	if (node.data_buffer) {
		itemP->data = smlAllocPcdata();
		if (!itemP->data) {
			return OMADM_SYNCML_ERROR_COMMAND_FAILED;
		}
		itemP->data->content = malloc(node.data_size);
		if (!itemP->data->content) {
			return OMADM_SYNCML_ERROR_COMMAND_FAILED;
		}
		memcpy(itemP->data->content, node.data_buffer, node.data_size);
		itemP->data->contentType = SML_PCDATA_OPAQUE;
		itemP->data->length = node.data_size;
	}
	itemP->meta = convert_to_meta(node.format, node.type);

	return OMADM_SYNCML_ERROR_SUCCESS;
}

int prv_get(dmcore_t * intp, const char *uri, SmlItemPtr_t resultP)
{
	int code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
	dmtree_node_t node;

	memset(&node, 0, sizeof(dmtree_node_t));

	node.uri = strdup(uri);
	if (node.uri) {
		code = dmtree_get(intp->dmtreeH, &node);
		if (OMADM_SYNCML_ERROR_NONE == code) {
			code = prv_fill_item(resultP, node);
		}
		dmtree_node_clean(&node, true);
	}
	return code;
}

int prv_add_item_to_list(SmlItemPtr_t itemP, SmlItemListPtr_t * listP)
{
	SmlItemListPtr_t newListP;

	newListP = (SmlItemListPtr_t) malloc(sizeof(SmlItemList_t));
	if (NULL == newListP) {
		return OMADM_SYNCML_ERROR_DEVICE_FULL;
	}

	newListP->item = itemP;
	newListP->next = *listP;
	*listP = newListP;

	return OMADM_SYNCML_ERROR_SUCCESS;
}

int prv_get_to_list(dmcore_t * intp,
			   const char *uri, SmlItemListPtr_t * listP)
{
	int code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
	SmlItemPtr_t itemP = NULL;

	itemP = smlAllocItem();
	if (itemP) {
		code = prv_get(intp, uri, itemP);

		if (OMADM_SYNCML_ERROR_SUCCESS == code) {
			code = prv_add_item_to_list(itemP, listP);
		}
		if (OMADM_SYNCML_ERROR_SUCCESS != code) {
			smlFreeItemPtr(itemP);
		}
	}

	return code;
}

void prv_get_tree_to_list(dmcore_t * intp,
				 const char *uri, SmlItemListPtr_t * listP)
{
	int code = OMADM_SYNCML_ERROR_COMMAND_FAILED;
	dmtree_node_t node;

	memset(&node, 0, sizeof(dmtree_node_t));

	node.uri = strdup(uri);
	if (NULL == node.uri) {
		return;
	}
	if (OMADM_SYNCML_ERROR_NONE == dmtree_get(intp->dmtreeH, &node)) {
		SmlItemPtr_t itemP;

		itemP = smlAllocItem();
		if (itemP) {
			code = prv_fill_item(itemP, node);
			if (OMADM_SYNCML_ERROR_SUCCESS == code) {
				code = prv_add_item_to_list(itemP, listP);
			}
			if (OMADM_SYNCML_ERROR_SUCCESS != code) {
				smlFreeItemPtr(itemP);
			}
		}

		if (!strcmp(node.format, "node")
		    && 0 != node.data_size) {
			char **childList;
			int i = 0;

			childList =
			    strArray_buildChildList(uri, node.data_buffer,
						    node.data_size);
			if (NULL != childList) {
				while (NULL != childList[i]) {
					prv_get_tree_to_list(intp,
							     childList[i],
							     listP);
					i++;
				}
			}
			strArray_free(childList);
		}
	}

	dmtree_node_clean(&node, true);
}

int get_node(dmcore_t * intp, SmlItemPtr_t itemP, SmlItemPtr_t resultP)
{
	int code;
	char *uri;

	uri = smlPcdata2String(itemP->target->locURI);
	if (!uri)
		return OMADM_SYNCML_ERROR_NOT_FOUND;

	code = prv_get(intp, uri, resultP);

	free(uri);
	return code;
}

int add_node(dmcore_t * intp, SmlItemPtr_t itemP)
{
	int code;
	dmtree_node_t node;

	memset(&node, 0, sizeof(dmtree_node_t));
	node.uri = smlPcdata2String(itemP->target->locURI);
	extract_from_meta(itemP->meta, &(node.format), &(node.type));
	node.data_size = itemP->data->length;
	if (node.data_size) {
		node.data_buffer = itemP->data->content;
	}

	code = dmtree_add(intp->dmtreeH, &node);
	PRV_CONVERT_CODE(code);

	dmtree_node_clean(&node, false);

	return code;
}

int delete_node(dmcore_t * intp, SmlItemPtr_t itemP)
{
	int code;
	char *uri;

	uri = smlPcdata2String(itemP->target->locURI);
	if (!uri)
		return OMADM_SYNCML_ERROR_NOT_FOUND;

	code = dmtree_delete(intp->dmtreeH, uri);
	PRV_CONVERT_CODE(code);

	free(uri);
	return code;
}

int exec_node(dmcore_t * intp, SmlItemPtr_t itemP, SmlPcdataPtr_t correlatorP)
{
	int code;
	char *uri;
	char *data;
	char *correlator;

	uri = smlPcdata2String(itemP->target->locURI);
	if (!uri) {
		return OMADM_SYNCML_ERROR_NOT_FOUND;
	}

	data = smlPcdata2String(itemP->data);
	correlator = smlPcdata2String(correlatorP);

	code = dmtree_exec(intp->dmtreeH, uri, data, correlator);
	PRV_CONVERT_CODE(code);

	free(uri);
	if (data != NULL)
		free(data);
	if (correlator != NULL)
		free(correlator);
	return code;
}

int replace_node(dmcore_t * intp, SmlItemPtr_t itemP)
{
	int code;
	dmtree_node_t node;

	memset(&node, 0, sizeof(dmtree_node_t));
	node.uri = smlPcdata2String(itemP->target->locURI);
	extract_from_meta(itemP->meta, &(node.format), &(node.type));
	node.data_size = itemP->data->length;
	if (node.data_size) {
		node.data_buffer = itemP->data->content;
	}

	code = dmtree_replace(intp->dmtreeH, &node);
	PRV_CONVERT_CODE(code);

	dmtree_node_clean(&node, false);

	return code;
}

int copy_node(dmcore_t * intp, SmlItemPtr_t itemP)
{
	int code;
	char *src_uri;
	char *dst_uri;

	dst_uri = smlPcdata2String(itemP->target->locURI);
	if (!dst_uri)
		return OMADM_SYNCML_ERROR_NOT_FOUND;

	src_uri = smlPcdata2String(itemP->source->locURI);
	if (!src_uri) {
		free(dst_uri);
		return OMADM_SYNCML_ERROR_NOT_FOUND;
	}

	code = dmtree_copy(intp->dmtreeH, src_uri, dst_uri);
	PRV_CONVERT_CODE(code);

	free(dst_uri);
	free(src_uri);

	return code;
}
