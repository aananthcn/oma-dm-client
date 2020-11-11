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
 * @file omadmtree_mo.h
 *
 * @brief Header file for the dmtree management objects
 *
 */

#ifndef OMADMTREE_MO_H_
#define OMADMTREE_MO_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OMADM_NODE_PROPERTY_VERSION     "VerNo"
#define OMADM_NODE_PROPERTY_TIMESTAMP   "TStamp"
#define OMADM_NODE_PROPERTY_FORMAT      "Format"
#define OMADM_NODE_PROPERTY_TYPE        "Type"
#define OMADM_NODE_PROPERTY_ACL         "ACL"
#define OMADM_NODE_PROPERTY_NAME        "Name"
#define OMADM_NODE_PROPERTY_SIZE        "Size"
#define OMADM_NODE_PROPERTY_TITLE       "Title"

	typedef enum {
		OMADM_NODE_NOT_EXIST,
		OMADM_NODE_IS_INTERIOR,
		OMADM_NODE_IS_LEAF
	} omadmtree_node_kind_t;

	typedef struct {
		char *uri;
		char *format;
		char *type;
		unsigned int data_size;
		char *data_buffer;
	} dmtree_node_t;

/* Utility functions to manipulate dmtree_node_t */

/*!
 * @brief Frees the dmtree_node_t and all its internal pointers INCLUDING the data_buffer.
 *        equivalent to: dmtree_node_clean(node, true); free(node);
 *
 * @param node the dmtree_node_t to be freed
 *
 */
	void dmtree_node_free(dmtree_node_t * node);

/*!
 * @brief Frees the internal pointers of dmtree_node_t and reset them to NULL.
 *        data_size is set to 0. data_buffer is always set to NULL.
 *        If full is false, data_buffer is not freed.
 *
 * @param node the dmtree_node_t to be cleaned.
 * @param full determines if the function frees the memory pointed by data_buffer or not.
 *
 */
	void dmtree_node_clean(dmtree_node_t * node, bool full);

/*!
 * @brief Duplicates a dmtree_node_t.
 *        All its internal pointers are also duplicated INCLUDING the data_buffer.
 *
 * @param node the dmtree_node_t to be duplicated.
 *
 * @returns a pointer to a new dmtree_node_t or NULL in case of error.
 */
	dmtree_node_t *dmtree_node_dup(const dmtree_node_t * src);

/*!
 * @brief Copies a dmtree_node_t to another dmtree_node_t.
 *        All the source's internal pointers are duplicated INCLUDING the data_buffer.
 *        If the destination's internal pointers are not NULL, they are not replaced.
 *        In case of error, function returns NULL and dest is not modified.
 *
 * @param dest the destination of the copy. The dmtree_node_t memory must be allocated prior to the call.
 * @param src the dmtree_node_t to be copied.
 *
 * @returns the orginal value of dest or NULL in case of error.
 */
	dmtree_node_t *dmtree_node_copy(dmtree_node_t * dest,
					const dmtree_node_t * src);

/*!
 * @brief Callback to initialize the MO (MANDATORY)
 *
 * @param dataP (out) opaque pointer to MO internal data
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_init_fn) (void **dataP);

/*!
 * @brief Callback to free the MO
 *
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 */
	typedef void (*omadm_mo_close_fn) (void *data);

/*!
 * @brief Callback to get the type of a node
 *
 * @param uri (in) URL of the node
 * @param type (out) type of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_is_node_fn) (const char *uri,
					    omadmtree_node_kind_t * type,
					    void *data);

/*!
 * @brief Callback to find the URLs associated to an URN
 *
 * @param urn (in) URN to find
 * @param urlsP (out) null-terminated array of urls, freed by the caller
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_find_urn_fn) (const char *urn, char ***urlsP,
					     void *data);

/*!
 * @brief Callback to set the value of a node
 *
 * result is stored in the nodeP parameter. If the targeted node is an
 * interior node, the nodeP->data_buffer must be a char * containing
 * the node's children's names separated by '/'.
 *
 * @param nodeP (in/out) the node to retrieve
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_get_fn) (dmtree_node_t * nodeP, void *data);

/*!
 * @brief Callback to get the value of a node
 *
 * The targeted node can already exist. This is used both for ADD
 * and REPLACE SyncML commands.
 * If nodeP-> type is "node", an interior node must be created.
 *
 * @param nodeP (in) the node to store
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_set_fn) (const dmtree_node_t * nodeP,
					void *data);

/*!
 * @brief Callback to get the ACL of a node
 *
 * The ACL string must be allocated by this function. It will be
 * freed by the caller.
 * If the node has no ACL, *aclP must be NULL.
 *
 * @param uri (in) URL of the node
 * @param aclP (out) ACL of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_get_ACL_fn) (const char *uri, char **aclP,
					    void *data);

/*!
 * @brief Callback to set the ACL of a node
 *
 * @param uri (in) URL of the node
 * @param acl (in) ACL of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_set_ACL_fn) (const char *uri, const char *acl,
					    void *data);

/*!
 * @brief Callback to rename a node
 *
 * The to parameter contains only the new name of the node, not the
 * complete new URL.
 *
 * @param from (in) URL of the node
 * @param to (in) new name of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_rename_fn) (const char *from, const char *to,
					   void *data);

/*!
 * @brief Callback to delete a node
 *
 * @param uri (in) URL of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_delete_fn) (const char *uri, void *data);

/*!
 * @brief Callback to execute the function associated to a node
 *
 * @param uri (in) URL of the node
 * @param cmdData (in) parameter past to the EXEC SyncML command
 * @param correlator (in) correlator associated to the EXEC SyncML command
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
	typedef int (*omadm_mo_exec_fn) (const char *uri, const char *cmdData,
					 const char *correlator, void *data);

/*!
 * @brief Callback to replace the function associated to a node
 *
 * @param uri (in) URL of the node
 * @param data (in) MO internal data as created by #omadm_mo_init_fn
 *
 * @returns a SyncML error code
 */
        typedef int (*omadm_mo_replace_fn) (const char *uri, char *data);
/*!
 * @brief Structure containing the interface of the MO
 *
 * base_uri and initFunc must be set. Other callbacks can be null.
 * The MO can not be root (i.e. base_uri must differ from ".").
 *
 */
	typedef struct {
		char *base_uri;	/*!< base URI of the MO */
		omadm_mo_init_fn initFunc;	/*!< initialization function */
		omadm_mo_close_fn closeFunc;
		omadm_mo_is_node_fn isNodeFunc;
		omadm_mo_find_urn_fn findURNFunc;
		omadm_mo_get_fn getFunc;
		omadm_mo_set_fn setFunc;
		omadm_mo_get_ACL_fn getACLFunc;
		omadm_mo_set_ACL_fn setACLFunc;
		omadm_mo_rename_fn renameFunc;
		omadm_mo_delete_fn deleteFunc;
		omadm_mo_exec_fn execFunc;
		omadm_mo_replace_fn replaceFunc;
	} omadm_mo_interface_t;

/*!
 * @brief Entry point of the shared lib
 *
 * The returned pointer ust be allocated by this function.
 * The caller will call closeFunc (if any) before freeing the pointer.
 * The caller will also free the uri string inside.
 *
 * @returns a pointer tothe MO interface
 */
	omadm_mo_interface_t *omadm_get_mo_interface(void *);

#ifdef __cplusplus
}
#endif
#endif
