#ifndef OMA_DM_CLIENT_H
#define OMA_DM_CLIENT_H

#include "omadmclient.h"

dmc_session get_dm_session(void);
dmc_err_t dmc_set_UI_callback(dmc_session dmcs, dmc_callback_t UICallbacksP,
						 void *userData);

#endif
