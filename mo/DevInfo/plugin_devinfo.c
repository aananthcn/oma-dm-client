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

#include "static_mo_util.h"

#include "syncml_error.h"

#define PRV_BASE_URI "./DevInfo"
#define PRV_URN      "urn:oma:mo:oma-dm-devinfo:1.0"

char DevId[64];
char Man[64];
char Mod[64];

static static_node_t gDevInfoNodes[] = {
	{PRV_BASE_URI, PRV_URN, OMADM_NODE_IS_INTERIOR, "Get=*", "DevId/Man/Mod/DmV/Lang/Bearer/Ext"},
	{PRV_BASE_URI "/DevId", NULL, OMADM_NODE_IS_LEAF, NULL,	DevId},
	{PRV_BASE_URI "/Man", NULL, OMADM_NODE_IS_LEAF, NULL, Man},
	{PRV_BASE_URI "/Mod", NULL, OMADM_NODE_IS_LEAF, NULL, Mod},
	{PRV_BASE_URI "/DmV", NULL, OMADM_NODE_IS_LEAF, NULL, "1.0"},
	{PRV_BASE_URI "/Lang", NULL, OMADM_NODE_IS_LEAF, NULL, "English"},
	{PRV_BASE_URI "/Ext", NULL, OMADM_NODE_IS_INTERIOR, NULL, "Intel/other"},
	{PRV_BASE_URI "/Ext/Intel", NULL, OMADM_NODE_IS_INTERIOR, NULL, "test1/test2"},
	{PRV_BASE_URI "/Ext/Intel/test1", NULL, OMADM_NODE_IS_LEAF, NULL, "data of test1"},
	{PRV_BASE_URI "/Ext/Intel/test2", NULL, OMADM_NODE_IS_LEAF, NULL, "data of test2"},
	{PRV_BASE_URI "/Ext/other", NULL, OMADM_NODE_IS_INTERIOR, NULL, "test3"},
	{PRV_BASE_URI "/Ext/other/test3", NULL, OMADM_NODE_IS_LEAF, NULL, "data of test3"},
	{PRV_BASE_URI "/Bearer", NULL, OMADM_NODE_IS_INTERIOR, NULL, "test"},
	{PRV_BASE_URI "/Bearer/test", NULL, OMADM_NODE_IS_LEAF, NULL, "test bearer"},
	{NULL, NULL, OMADM_NODE_NOT_EXIST, NULL},
};

static int prv_initFN(void **oData)
{
	*oData = gDevInfoNodes;
	return OMADM_SYNCML_ERROR_NONE;
}


static int get_params_from_db(void)
{
#if 0
	if (0 != db_init()) {
		printf("\nFILE: %s ## Database Init Failed!!!\n", __FILE__);
		return -1;
	}

	db_read_str("DevId", DevId);
	db_read_str("Man", Man);
	db_read_str("Mod", Mod);

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
