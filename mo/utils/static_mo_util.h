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

#ifndef STATIC_MO_UTIL_H_
#define STATIC_MO_UTIL_H_

#include <omadmtree_mo.h>

typedef struct {
	char *uri;
	char *urn;
	omadmtree_node_kind_t type;
	char *acl;
	char *value;
} static_node_t;

int static_mo_is_node(const char *iURI, omadmtree_node_kind_t * oNodeType,
		      void *iData);
int static_mo_get(dmtree_node_t * nodeP, void *iData);
int static_mo_getACL(const char *iURI, char **oValue, void *iData);
int static_mo_findURN(const char *iURN, char ***oURL, void *iData);

#endif
