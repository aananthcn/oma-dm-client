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

#define PRV_BASE_URI "./DMAcc"
#define PRV_URN      "urn:oma:mo:oma-dm-dmacc:1.0"

char server_url[256];
char username_toclient[64];
char password_toclient[64];
char username_toserver[64];
char password_toserver[64];


static static_node_t gDmAccNodes[] = {
	{PRV_BASE_URI, NULL,						OMADM_NODE_IS_INTERIOR, "Get=*",	"test/secret"},
	{PRV_BASE_URI "/test", PRV_URN,					OMADM_NODE_IS_INTERIOR, "Get=aananth",	"AppID/ServerID/Name/AppAddr/AppAuth"},
	{PRV_BASE_URI "/test/AppID", NULL,				OMADM_NODE_IS_LEAF,	NULL,		"w7"},
	{PRV_BASE_URI "/test/ServerID", NULL,				OMADM_NODE_IS_LEAF,	NULL,		"aananth"},
	{PRV_BASE_URI "/test/Name", NULL,				OMADM_NODE_IS_LEAF,	NULL,		"Aananth DM Server"},
	{PRV_BASE_URI "/test/AppAddr", NULL,				OMADM_NODE_IS_INTERIOR, NULL,		"url"},
	{PRV_BASE_URI "/test/AppAddr/url", NULL,			OMADM_NODE_IS_INTERIOR, NULL,		"Addr/AddrType"},
	{PRV_BASE_URI "/test/AppAddr/url/Addr", NULL,			OMADM_NODE_IS_LEAF,	NULL,		server_url},
	{PRV_BASE_URI "/test/AppAddr/url/AddrType", NULL,		OMADM_NODE_IS_LEAF,	NULL,		"URI"},
	{PRV_BASE_URI "/test/AppAuth", NULL,				OMADM_NODE_IS_INTERIOR, NULL,		"toclient/toserver"},
	{PRV_BASE_URI "/test/AppAuth/toclient", NULL,			OMADM_NODE_IS_INTERIOR, NULL,		"AAuthLevel/AAuthType/AAuthName/AAuthSecret/AAuthData"},
	{PRV_BASE_URI "/test/AppAuth/toserver", NULL,			OMADM_NODE_IS_INTERIOR, NULL,		"AAuthLevel/AAuthType/AAuthName/AAuthSecret/AAuthData"},
	{PRV_BASE_URI "/test/AppAuth/toclient/AAuthLevel", NULL,	OMADM_NODE_IS_LEAF,	NULL,		"SRVCRED"},
	{PRV_BASE_URI "/test/AppAuth/toclient/AAuthType", NULL,		OMADM_NODE_IS_LEAF,	NULL,		"DIGEST"},
	{PRV_BASE_URI "/test/AppAuth/toclient/AAuthName", NULL,		OMADM_NODE_IS_LEAF,	NULL,		username_toclient},
	{PRV_BASE_URI "/test/AppAuth/toclient/AAuthSecret", NULL,	OMADM_NODE_IS_LEAF,	"",		password_toclient},
	{PRV_BASE_URI "/test/AppAuth/toclient/AAuthData", NULL,		OMADM_NODE_IS_LEAF,	"",		NULL},
	{PRV_BASE_URI "/test/AppAuth/toserver/AAuthLevel", NULL,	OMADM_NODE_IS_LEAF,	NULL,		"CLCRED"},
	{PRV_BASE_URI "/test/AppAuth/toserver/AAuthType", NULL,		OMADM_NODE_IS_LEAF,	NULL,		"BASIC"},
	{PRV_BASE_URI "/test/AppAuth/toserver/AAuthName", NULL,		OMADM_NODE_IS_LEAF,	NULL,		username_toserver},
	{PRV_BASE_URI "/test/AppAuth/toserver/AAuthSecret", NULL,	OMADM_NODE_IS_LEAF,	"",		password_toserver},
	{PRV_BASE_URI "/test/AppAuth/toserver/AAuthData", NULL,		OMADM_NODE_IS_LEAF,	"",		NULL},

	{PRV_BASE_URI "/secret", PRV_URN, OMADM_NODE_IS_INTERIOR, "Get=unused", "AppID/ServerID/Name/AppAddr/AppAuth"},
	{PRV_BASE_URI "/secret/AppID", NULL, OMADM_NODE_IS_LEAF, NULL, "w7"},
	{PRV_BASE_URI "/secret/ServerID", NULL, OMADM_NODE_IS_LEAF, NULL, "unused"},
	{PRV_BASE_URI "/secret/Name", NULL, OMADM_NODE_IS_LEAF, NULL, "ACL testing"},
	{PRV_BASE_URI "/secret/AppAddr", NULL, OMADM_NODE_IS_INTERIOR, NULL, "url"},
	{PRV_BASE_URI "/secret/AppAddr/url", NULL, OMADM_NODE_IS_INTERIOR, NULL, "Addr/AddrType"},
	{PRV_BASE_URI "/secret/AppAddr/url/Addr", NULL, OMADM_NODE_IS_LEAF, NULL, "http://127.0.0.1"},
	{PRV_BASE_URI "/secret/AppAddr/url/AddrType", NULL, OMADM_NODE_IS_LEAF, NULL, "URI"},
	{PRV_BASE_URI "/secret/AppAuth", NULL, OMADM_NODE_IS_INTERIOR, NULL, "toclient/toserver"},
	{PRV_BASE_URI "/secret/AppAuth/toclient", NULL, OMADM_NODE_IS_INTERIOR, NULL, "AAuthLevel/AAuthType/AAuthName/AAuthSecret/AAuthData"},
	{PRV_BASE_URI "/secret/AppAuth/toserver", NULL, OMADM_NODE_IS_INTERIOR, NULL, "AAuthLevel/AAuthType/AAuthName/AAuthSecret/AAuthData"},
	{PRV_BASE_URI "/secret/AppAuth/toclient/AAuthLevel", NULL, OMADM_NODE_IS_LEAF, NULL, "SRVCRED"},
	{PRV_BASE_URI "/secret/AppAuth/toclient/AAuthType", NULL, OMADM_NODE_IS_LEAF, NULL, "BASIC"},
	{PRV_BASE_URI "/secret/AppAuth/toclient/AAuthName", NULL, OMADM_NODE_IS_LEAF, NULL, "unused"},
	{PRV_BASE_URI "/secret/AppAuth/toclient/AAuthSecret", NULL, OMADM_NODE_IS_LEAF, "", "unused"},
	{PRV_BASE_URI "/secret/AppAuth/toclient/AAuthData", NULL, OMADM_NODE_IS_LEAF, "", NULL},
	{PRV_BASE_URI "/secret/AppAuth/toserver/AAuthLevel", NULL, OMADM_NODE_IS_LEAF, NULL, "CLCRED"},
	{PRV_BASE_URI "/secret/AppAuth/toserver/AAuthType", NULL, OMADM_NODE_IS_LEAF, NULL, "BASIC"},
	{PRV_BASE_URI "/secret/AppAuth/toserver/AAuthName", NULL, OMADM_NODE_IS_LEAF, NULL, "unused"},
	{PRV_BASE_URI "/secret/AppAuth/toserver/AAuthSecret", NULL, OMADM_NODE_IS_LEAF, "", "unused"},
	{PRV_BASE_URI "/secret/AppAuth/toserver/AAuthData", NULL, OMADM_NODE_IS_LEAF, "", NULL},

	{NULL, NULL, OMADM_NODE_NOT_EXIST, NULL},
};

static int prv_initFN(void **oData)
{
	*oData = gDmAccNodes;
	return OMADM_SYNCML_ERROR_NONE;
}


static int get_params_from_db(void)
{
#if 0
	if (0 != db_init()) {
		printf("\nFILE: %s ## Database Init Failed!!!\n", __FILE__);
		return -1;
	}

	db_read_str("url/Addr", server_url);
	db_read_str("toclient/AAuthName", username_toclient);
	db_read_str("toclient/AAuthSecret", password_toclient);
	db_read_str("toserver/AAuthName", username_toserver);
	db_read_str("toserver/AAuthSecret", password_toserver);

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
