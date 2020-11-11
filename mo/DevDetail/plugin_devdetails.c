/*
 * libdmclient test materials
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/md5.h>
#include "static_mo_util.h"

#include "syncml_error.h"

#define PRV_BASE_URI "./DevDetail"
#define PRV_URN      "urn:oma:mo:oma-dm-devdetail:1.0"

char DevTyp[64];
char OEM[64];
char FwV[64];
char SwV[64];
char HwV[64];
char BaseValidationResult[64];
char Group[64];
char Subgroup[64];


static static_node_t gDevDetailNodes[] = {
	{PRV_BASE_URI, PRV_URN, OMADM_NODE_IS_INTERIOR, "Get=*",
	 "URI/DevTyp/OEM/FwV/SwV/HwV/LrgObj"},
	{PRV_BASE_URI "/DevTyp", NULL, OMADM_NODE_IS_LEAF, NULL, DevTyp},
	{PRV_BASE_URI "/OEM", NULL, OMADM_NODE_IS_LEAF, NULL, OEM},
	{PRV_BASE_URI "/FwV", NULL, OMADM_NODE_IS_LEAF, NULL, FwV},
	{PRV_BASE_URI "/SwV", NULL, OMADM_NODE_IS_LEAF, NULL, SwV},
	{PRV_BASE_URI "/HwV", NULL, OMADM_NODE_IS_LEAF, NULL, HwV},
	{PRV_BASE_URI "/LrgObj", NULL, OMADM_NODE_IS_LEAF, NULL, "true"},
	{PRV_BASE_URI "/URI", NULL, OMADM_NODE_IS_INTERIOR, NULL,
	 "MaxDepth/MaxTotLen/MaxSegLen"},
	{PRV_BASE_URI "/URI/MaxDepth", NULL, OMADM_NODE_IS_LEAF, NULL, "0"},
	{PRV_BASE_URI "/URI/MaxTotLen", NULL, OMADM_NODE_IS_LEAF, NULL, "0"},
	{PRV_BASE_URI "/URI/MaxSegLen", NULL, OMADM_NODE_IS_LEAF, NULL, "0"},
	{PRV_BASE_URI "/Ext", NULL, OMADM_NODE_IS_INTERIOR, NULL, "Group/Subgroup"},
	{PRV_BASE_URI "/Ext/Group", NULL, OMADM_NODE_IS_LEAF, NULL, Group},
	{PRV_BASE_URI "/Ext/Subgroup", NULL, OMADM_NODE_IS_LEAF, NULL, Subgroup},
	{NULL, NULL, OMADM_NODE_NOT_EXIST, NULL},
};

static int prv_initFN(void **oData)
{
	*oData = gDevDetailNodes;
	return OMADM_SYNCML_ERROR_NONE;
}

static int get_params_from_db(void)
{
	int ret;

#if 0
	if (0 != db_init()) {
		printf("\nFILE: %s ## Database Init Failed!!!\n", __FILE__);
		return -1;
	}

	db_read_str("DevTyp", DevTyp);
	db_read_str("OEM", OEM);
	db_read_str("FwV", FwV);
	db_read_str("SwV", SwV);
	db_read_str("HwV", HwV);
	db_read_str("Group", Group);
	db_read_str("Subgroup", Subgroup);
	db_exit();
#endif

	return 0;
}


omadm_mo_interface_t *omadm_get_mo_interface(void *fptr)
{
	omadm_mo_interface_t *retVal = NULL;

	if (0 != get_params_from_db())
		return NULL;

	retVal = malloc(sizeof(*retVal));
	if (retVal) {
		memset(retVal, 0, sizeof(*retVal));
		retVal->base_uri = strdup(PRV_BASE_URI);
		retVal->initFunc = prv_initFN;
		retVal->isNodeFunc = static_mo_is_node;
		retVal->findURNFunc = static_mo_findURN;
		retVal->getFunc = static_mo_get;
		retVal->getACLFunc = static_mo_getACL;
	}

	return retVal;
}
