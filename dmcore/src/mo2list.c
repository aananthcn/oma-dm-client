#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "dmcore.h"

SmlReplacePtr_t get_device_info(dmcore_t * intp)
{
	SmlReplacePtr_t replaceP = NULL;
	SmlItemListPtr_t listP = NULL;

	if (intp == NULL) {
		goto error;
	}
	// Mandatory nodes
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./DevInfo/Mod", &listP))
		goto error;
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./DevInfo/Man", &listP))
		goto error;
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./DevInfo/DevId", &listP))
		goto error;
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./DevInfo/Lang", &listP))
		goto error;
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./DevInfo/DmV", &listP))
		goto error;

	// Optional nodes
	prv_get_tree_to_list(intp, "./DevInfo/Bearer", &listP);
	prv_get_tree_to_list(intp, "./DevInfo/Ext", &listP);

	replaceP = smlAllocReplace();
	if (replaceP) {
		smlFreeItemList(replaceP->itemList);
		replaceP->itemList = listP;
		listP = NULL;
	}

 error:
	if (listP)
		smlFreeItemList(listP);
	return replaceP;
}

SmlReplacePtr_t get_fumo_alert(dmcore_t * intp)
{
	SmlReplacePtr_t replaceP = NULL;
	SmlItemListPtr_t listP = NULL;

	if (intp == NULL) {
		goto error;
	}
	// Mandatory nodes
	if (OMADM_SYNCML_ERROR_SUCCESS !=
	    prv_get_to_list(intp, "./Fumo/State", &listP))
		goto error;

	replaceP = smlAllocReplace();
	if (replaceP) {
		smlFreeItemList(replaceP->itemList);
		replaceP->itemList = listP;
		listP = NULL;
	}

 error:
	if (listP)
		smlFreeItemList(listP);
	return replaceP;
}

