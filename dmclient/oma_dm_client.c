#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <dlfcn.h>
#include <dirent.h>
#include <stdbool.h>
#include <omadmclient.h>
#include <curl/curl.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include "dmcore.h"
#include "oma_dm_client.h"
#include "dm_register.h"

#define MAX_PLUGIN 16

/*****************************************************************************
 * Declarations								     
 *****************************************************************************/
// HACK
typedef struct {
	void *unused1;
	void *unused2;
	void *unused3;
	int unused4;
	int unused5;
	int unused6;
	void *unused7;
	void *unused8;
	void *unused9;
	char *unusedA;
	int srv_auth;
	int clt_auth;
} hack_internals_t;

/*****************************************************************************
 * Globals
 *****************************************************************************/
dmc_session Session = NULL;
char MgmtObjDir[512];

/*****************************************************************************
 * Functions
 *****************************************************************************/
#define CPL	32
void output_buffer(FILE * fd, bool is_wbxml, dmc_buffer_t buffer)
{
	int i;

	if (is_wbxml) {
		unsigned char array[CPL];

		i = 0;
		while (i < buffer.length) {
			int j;
			fprintf(fd, "  ");

			memcpy(array, buffer.data + i, CPL);

			for (j = 0; j < CPL && i + j < buffer.length; j++) {
				fprintf(fd, "%02X ", array[j]);
			}
			while (j < CPL) {
				fprintf(fd, "   ");
				j++;
			}
			fprintf(fd, "  ");
			for (j = 0; j < CPL && i + j < buffer.length; j++) {
				if (isprint(array[j]) || isspace(array[i]))
					fprintf(fd, "%c", array[j]);
				else
					fprintf(fd, ".");
			}
			fprintf(fd, "\n");

			i += CPL;
		}
	} else {
		int tab;

		tab = -2;
		for (i = 0; i < buffer.length; i++) {
			if (buffer.data[i] == '<') {
				int j;
				if (i + 1 < buffer.length
				    && buffer.data[i + 1] == '/') {
					tab--;
					if (i != 0 && buffer.data[i - 1] == '>') {
						fprintf(fd, "\n");
						for (j = 0; j < tab * 4; j++)
							fprintf(fd, " ");
					}
				} else {
					if (i != 0 && buffer.data[i - 1] == '>') {
						fprintf(fd, "\n");
						for (j = 0; j < tab * 4; j++)
							fprintf(fd, " ");
					}
					tab++;
				}
			}
			fprintf(fd, "%c", buffer.data[i]);
		}
	}
	fprintf(fd, "\n\n");
	fflush(fd);
}

int ui_callback(void *user_data, const dmc_ui_t * alert_data, char *user_reply)
{
	int code = 200;

	printf("\nAlert received:\n");
	printf("type: %d\n", alert_data->type);
	printf("min_disp: %d\n", alert_data->min_disp);
	printf("max_disp: %d\n", alert_data->max_disp);
	printf("max_resp_len: %d\n", alert_data->max_resp_len);
	printf("input_type: %d\n", alert_data->input_type);
	printf("echo_type: %d\n", alert_data->echo_type);
	printf("disp_msg: \"%s\"\n", alert_data->disp_msg);
	printf("dflt_resp: \"%s\"\n", alert_data->dflt_resp);

	printf("\n----------- UI -----------\n\n");
	printf("%s\n", alert_data->disp_msg);
	if (alert_data->type >= DMCLT_UI_TYPE_USER_CHOICE) {
		int i = 0;
		while (alert_data->choices[i]) {
			printf("%d: %s\n", i + 1, alert_data->choices[i]);
			i++;
		}
	}
	printf("\n--------------------------\n\n");

	if (alert_data->type >= DMCLT_UI_TYPE_CONFIRM) {
		char reply[256];

		printf("? ");
		fflush(stdout);
		memset(reply, 0, 256);
		fgets(reply, 256, stdin);

		if (reply[0] == 0)
			code = 214;

		if (alert_data->type == DMCLT_UI_TYPE_CONFIRM) {
			if (reply[0] == 'y')
				code = 200;
			else
				code = 304;
		} else {
			int s;
			for (s = 0; 0 != reply[s] && 0x0A != reply[s]; s++) ;
			reply[s] = 0;
			strncpy(user_reply, reply, alert_data->max_resp_len);
		}
	}

	return code;
}

static size_t store_reply_callback(void *contents, size_t size,
				   size_t nmemb, void *userp)
{
	dmc_buffer_t *reply = (dmc_buffer_t *) userp;
	size_t total = size * nmemb;

	reply->data = realloc(reply->data, reply->length + total);
	if (reply->data == NULL) {
		printf("Not enough memory\n");
		exit(EXIT_FAILURE);
	}

	memcpy(&(reply->data[reply->length]), contents, total);
	reply->length += total;

	return total;
}

long send_recv_pkg(CURL * curlh, char *type, dmc_buffer_t * packet,
		   dmc_buffer_t * reply)
{
	struct curl_slist *hdrlist = NULL;
	long stat = 503;
	CURLcode code;

	memset(reply, 0, sizeof(dmc_buffer_t));
	if (NULL == curlh) {
		return stat;
	}

	curl_easy_setopt(curlh, CURLOPT_URL, packet->uri);
	curl_easy_setopt(curlh, CURLOPT_POST, 1);
	hdrlist = curl_slist_append(hdrlist, type);

	curl_easy_setopt(curlh, CURLOPT_HTTPHEADER, hdrlist);
	curl_easy_setopt(curlh, CURLOPT_POSTFIELDSIZE_LARGE,
			 (curl_off_t) (packet->length));
	curl_easy_setopt(curlh, CURLOPT_COPYPOSTFIELDS, (void *)(packet->data));

	curl_easy_setopt(curlh, CURLOPT_WRITEFUNCTION, store_reply_callback);
	curl_easy_setopt(curlh, CURLOPT_WRITEDATA, (void *)reply);

	if (CURLE_OK == curl_easy_perform(curlh)) {
		code = curl_easy_getinfo(curlh, CURLINFO_RESPONSE_CODE, &stat);
		if (CURLE_OK != code) {
			stat = 503;
		}
	}
	curl_slist_free_all(hdrlist);

	return stat;
}

/*******************************************************************************
 * Function: process_packet_auth_type
 *
 * TBD
 */
void process_packet_auth_type(dmc_authType_t auth_type)
{
	switch (auth_type) {
	case DMCLT_AUTH_TYPE_HTTP_BASIC:
	case DMCLT_AUTH_TYPE_HTTP_DIGEST:
		// establish HTTPS session
		printf("WARNING! execution reached a portion of code that \
		      \nwasn't implemented!!. File: %s; Function: %s; Case: \
		      \n%s; Case ID: %d\n", __FILE__, __func__, "DMCLT_AUTH_TYPE_HTTP_BASIC", (int)auth_type);
		break;
	case DMCLT_AUTH_TYPE_BASIC:
	case DMCLT_AUTH_TYPE_DIGEST:
		// do nothing
		break;
	case DMCLT_AUTH_TYPE_HMAC:
		// compute HMAC of the message and add it to
		// the transport header
		printf("WARNING! execution reached a portion of code that \
		      \nwasn't implemented!!. File: %s; Function: %s; Case: \
		      \n%s; Case ID: %d\n", __FILE__, __func__, "DMCLT_AUTH_TYPE_HMAC:", (int)auth_type);
		break;
	case DMCLT_AUTH_TYPE_X509:
	case DMCLT_AUTH_TYPE_SECURID:
	case DMCLT_AUTH_TYPE_SAFEWORD:
	case DMCLT_AUTH_TYPE_DIGIPASS:
	case DMCLT_AUTH_TYPE_TRANSPORT:
	default:
		printf("WARNING! execution reached a portion of code that \
		      wasn't implemented!!. File: %s; Function: %s; Case: \
		      %s; Case ID: %d\n", __FILE__, __func__, "default", (int)auth_type);
		break;
	}
}

/*******************************************************************************
 * Function: dmc_do_session
 *
 * TBD
 */
long dmc_do_session(bool is_wbxml)
{
	CURL *curlh;
	char *ptype;
	dmc_buffer_t buffer;
	dmc_buffer_t reply;
	dmc_err_t err;

	long status = 200;

	curlh = curl_easy_init();
	do {
		/* fill 'buffer' with xml contents */
		err = dmc_get_next_packet(Session, &buffer);
		if (DMCLT_ERR_NONE != err) {
			continue;
		}
		printf("Processed packet:\n");
		output_buffer(stdout, is_wbxml, buffer);
		process_packet_auth_type(buffer.auth_type);

		/* send the 'buffer' contents to the server */
		if (is_wbxml)
			ptype = "Content-Type: application/vnd.syncml+wbxml";
		else
			ptype = "Content-Type: application/vnd.syncml+xml";
		status = send_recv_pkg(curlh, ptype, &buffer, &reply);
		printf("Reply from \"%s\": %ld\n\n", buffer.uri, status);
		dmc_clean_buffer(&buffer);

		/* check the status from server */
		if (200 == status) {
			if (is_wbxml) {
				output_buffer(stdout, is_wbxml, reply);
			} else {
				int i;
				for (i = 0; i < reply.length; i++)
					printf("%c", reply.data[i]);
				printf("\n\n");
				fflush(stdout);
			}
			err = dmc_process_reply(Session, &reply);
			dmc_clean_buffer(&reply);
		}
	} while (DMCLT_ERR_NONE == err && 200 == status);

	curl_easy_cleanup(curlh);

	return 0;
}




/**********************************************************************************
 * Callback from Managment Objects
 * 
 * Caller: will be called by plugins (Management Objects)
 */
int mo_event_callback(enum mo_events event, int id, int status)
{
	int ret;

	if ((id == C_LIBFUMO) && (event == FUMO_INSTALL_COMPLETE)) {
		ret = dmc_set_mo_event(FUMO_INSTALL_COMPLETE, status);
		if (ret < 0)
			printf("Error: can't set event - %s\n", __func__);
	}

	if ((id == C_LIBSCOMO) && (event == SCOMO_INSTALL_COMPLETE)) {
		ret = dmc_set_mo_event(SCOMO_INSTALL_COMPLETE, status);
		if (ret < 0)
			printf("Error: can't set event - %s\n", __func__);
	}

	return ret;
}

/*******************************************************************************
 * Function: scan_plugin
 *
 * This function searches the address to a specific function in the shared
 * object (dynamically linked file) and stores them in an array
 *
 * arg1: filename of the .so file
 * arg2: the directory entry under which the .so file is found
 * arg3: array of handle to store the result
 * arg4: current index of the above array
 */
int scan_plugin(char *fname, struct dirent *fe, void *hpn[MAX_PLUGIN], int i)
{
	void *handle;
	omadm_mo_interface_t *mo_if_ptr = NULL;
	void *fptr;
	omadm_mo_interface_t *(*get_moif_fnp) (void *);
	dmc_err_t err;

	if (fname == NULL)
		return -1;

	sprintf(fname, "%s", MgmtObjDir);
	strcat(fname, "/");
	strcat(fname, fe->d_name);
	fptr = (void*)&mo_event_callback;
	/* open the shared library */
	handle = dlopen(fname, RTLD_LAZY);
	if (handle) {
		/* resolve address of symbol */
		get_moif_fnp = dlsym(handle, "omadm_get_mo_interface");
		if (get_moif_fnp) {
			mo_if_ptr = get_moif_fnp(fptr);
			if (mo_if_ptr && (mo_if_ptr->base_uri)) {
				err = dmc_session_add_mo(Session, mo_if_ptr);
				if (DMCLT_ERR_NONE == err) {
					// store handle
					hpn[i] = handle;
					handle = NULL;
				} else {
					free(mo_if_ptr);
				}
			}
		}

		if (handle) {
			dlclose(handle);
		}
	} else {
		printf("%s(): Can't open plugin %s\n", __func__, fname);
		printf(" *** %s\n", dlerror());
		return -1;
	}

	return 0;
}

/*******************************************************************************
 * Function: load_plugins
 *
 * This function searches for .so files under MgmtObjDir (directory that
 * contains managment objects in form of .so files and extract addresses to
 * symbols
 *
 * arg1: array of handle to .so files
 *
 */
int load_plugins(void *hplugins[MAX_PLUGIN])
{
	DIR *pfolder;
	struct dirent *filep;
	int i, ret;
	char *fname;
	void *handle = NULL;

	i = ret = 0;

	/* load plugins from the plugins directory */
	pfolder = opendir(MgmtObjDir);
	if (pfolder != NULL) {
		while ((filep = readdir(pfolder)) && (i < MAX_PLUGIN)) {
			if (DT_REG == filep->d_type) {
				fname = (char *)malloc(strlen(MgmtObjDir) +
						       1 +
						       strlen(filep->d_name) +
						       1);
				ret = scan_plugin(fname, filep, hplugins, i);
				free(fname);
				if (ret < 0) {
					printf("%s(): scan_plugin failed!!\n",
					       __func__);
					break;
				}
				i++;
			}
		}
		closedir(pfolder);
	}

	return ret;
}

/*******************************************************************************
 * Function: get_dm_session
 *
 * This function returns the current session information.
 */
dmc_session get_dm_session(void)
{
	return Session;
}

/*******************************************************************************
 * Function: print_usage
 *
 * This function will help users on how to use our client
 */
void print_usage(void)
{
	printf("Usage: sota-oma-dm [-w] [-f FILE | -s SERVERID]\n");
	printf
	    ("\n  Launch a DM session with the virtualhost SERVERID. If SERVERID is not specified, \"aananth\" is used by default.\n\n");
	printf("  -w\tuse WBXML\n");
	printf("  -s\topen a DM session with virtualhost SERVERID\n");
	printf("  -p\tabsolute path to plugins directory\n\n");

}

void alarm_handler(int signo)
{
	printf("SIGALARM received\n This handler will replace the default action to avoid possible crashing of dm-client \n");
}

/*******************************************************************************
 * Function: main
 *
 * The entry point!!
 */
int main(int argc, char *argv[])
{
	long status;
	int c;
	char *virtualhost = NULL;
	char *file = NULL;
	omadm_mo_interface_t *sota_mo;
	void *hplugins[MAX_PLUGIN];
	int err;
	int s_ret;

	dmc_buffer_t buffer;
	dmc_buffer_t reply;
	char *proxyStr;

	bool is_wbxml = false;

	virtualhost = NULL;
	file = NULL;
	opterr = 0;
	memset(hplugins, 0, MAX_PLUGIN * sizeof(void *));

	while ((c = getopt(argc, argv, "ws:f:p:")) != -1) {
		switch (c) {
		case 'w':
			is_wbxml = true;
			break;
		case 's':
			virtualhost = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'p':
			strcpy(MgmtObjDir, optarg);
			break;
		case '?':
			print_usage();
			return 1;
		default:
			break;
		}
	}

	if (virtualhost && file) {
		print_usage();
		return 1;
	}

	if (access(MgmtObjDir, F_OK) != 0) {
		printf("%s couldn't access \"%s\"\n\n", argv[0], MgmtObjDir);
		print_usage();
		return -1;
	}

	Session = dmc_session_init(is_wbxml);
	if (Session == NULL) {
		printf("Initialization failed\n");
		return 1;
	}
	err = dmc_set_UI_callback(Session, ui_callback, NULL);
	if (err != DMCLT_ERR_NONE) {
		printf("Initialization failed: %d\n", err);
		return err;
	}

	if (0 != device_registration_check()) {
		goto close_session;
	}

	/* load all managment objects stored in a specified directory */
	if (0 > load_plugins(hplugins)) {	/* TODO: The directory of mo should go from here!! */
		goto close_session;
	}

	s_ret = signal(SIGALRM, alarm_handler);
	if (s_ret == SIG_ERR) {
		printf("Failed to register handler for SIGALRM\n");
	}
	printf("SIGALRM handler successfully registered \n");
	/* if -s option is not provided, then assume "aananth" as the virtualhost */
	if (virtualhost == NULL)
		virtualhost = "aananth";

	err = dmc_session_start(Session, virtualhost, 1);
	if (err != DMCLT_ERR_NONE) {
		printf("Session opening to \"*/%s\" failed: %d\n", virtualhost,
		       err);
		return err;
	}
	while (1) {
		status = dmc_do_session(is_wbxml);
		sleep(1);
	}
 close_session:
	dmc_session_close(Session);

	c = 0;
	while ((c < MAX_PLUGIN) && (hplugins[c] != 0)) {
		dlclose(hplugins[c]);
		c++;
	}

	// check that we return 0 in case of success
	if (DMCLT_ERR_END == err)
		err = 0;
	else if (status != 200)
		err = status;
	return err;
}
