#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <curl/curl.h>
#include <pthread.h>

#include "dm_register.h"

#define BUFF_SIZE	(1024)
#define PATH_SIZE	(256)

/* Globals */
static char RegResp[BUFF_SIZE];
static int RespReceived;
static char RegUrl[PATH_SIZE];
static pthread_mutex_t rxmutex = PTHREAD_MUTEX_INITIALIZER;


/* Function definitions */
static size_t server_reply_callback(void *contents, size_t size,
                                   size_t nmemb, void *userp)
{
        size_t total = size * nmemb;
        char *contp = (char *) contents;

	(void) pthread_mutex_lock(&rxmutex);
	strncpy(RegResp, contp, BUFF_SIZE);
	RespReceived = 1;
	(void) pthread_mutex_unlock(&rxmutex);

        printf("Rx <== %s\n", contp);
        return total;
}


int send_to_regmodule(CURL *curlh, char *buffer)
{
        CURLcode code;
        int log_len, stat, retc;

        stat = retc = 0;
        log_len = strlen(buffer);
        if (log_len > BUFF_SIZE)
                log_len = BUFF_SIZE;

        curl_easy_setopt(curlh, CURLOPT_URL, RegUrl);
        curl_easy_setopt(curlh, CURLOPT_POST, 1);

        curl_easy_setopt(curlh, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t) (log_len));
        curl_easy_setopt(curlh, CURLOPT_COPYPOSTFIELDS, (void *)(buffer));

        curl_easy_setopt(curlh, CURLOPT_WRITEFUNCTION, server_reply_callback);

        printf("%s(): Sending %s to %s ...\n", __func__, buffer, RegUrl);
        if (CURLE_OK == curl_easy_perform(curlh)) {
                code = curl_easy_getinfo(curlh, CURLINFO_RESPONSE_CODE, &stat);
                if (CURLE_OK != code) {
                        retc = -1;
                }
        }
	printf("%s(): Response code: %d\n", __func__, stat);

        return retc;
}



int get_registration_data(char *dev, char *usr, char *pwd)
{
#if 0
	json_t *jobj;

	if (0 != ej_load_buf(RegResp, &jobj)) {
		printf("%s(): can't load RegResp data\n", __func__);
		return -1;
	}

	if (0 != ej_get_string(jobj, "DevId", dev)) {
		printf("%s(): can't get DevId from RegResp\n", __func__);
		return -1;
	}

	if (0 != ej_get_string(jobj, "toserver/AAuthName", usr)) {
		printf("%s(): can't get AuthName from RegResp\n", __func__);
		return -1;
	}

	if (0 != ej_get_string(jobj, "toserver/AAuthSecret", pwd)) {
		printf("%s(): can't get AuthSecret from RegResp\n", __func__);
		return -1;
	}

	printf("%s(): registration response parsed!!\n", __func__);
	json_decref(jobj);
#endif
	return 0;
}


#define SECRET_STR	"aananth:aananth"
int register_device(char *dev, char *usr, char *pwd)
{
    CURL *curlh;
    char buf[BUFF_SIZE];
	int retc = 0;
	int i, x;

#if 0
	struct timespec ts;
	json_t *jobj;

	if ((jobj = json_object()) == NULL) {
                printf("%s(), json object is null\n", __func__);
		return -1;
	}

        curlh = curl_easy_init();
        if (NULL == curlh) {
                printf("%s(), curlh is null\n", __func__);
		json_decref(jobj);
                return -1;
        }

	/* send secret string and an unique id to registration module */
	ej_add_string(&jobj, "secret", SECRET_STR);
	ej_add_string(&jobj, "udid", get_unique_deviceid());
	ej_store_buf(jobj, buf, BUFF_SIZE);
        retc = send_to_regmodule(curlh, buf);

	/* wait for response */
	for (i=x=0; !x && i < 3000; i++) {
		(void) pthread_mutex_lock(&rxmutex);
		if (RespReceived)
			x = 1; /* exit */
		(void) pthread_mutex_unlock(&rxmutex);
		usleep(1000);
	}

	/* parse response string to get registration data */
	if (0 != get_registration_data(dev, usr, pwd)) {
		printf("%s(): Error parsing registration response\n", __func__);
		retc = -1;
	}

        curl_easy_cleanup(curlh);
	json_decref(jobj);
#endif
	return retc;
}


int device_registration_check(void)
{
	char devid[64], userid[64], passwd[64];
	int dstat, ustat, pstat;
	int retval = 0;

#if 0
	/* try to read DevId, server UserID and Password from database */
	if (0 != db_init()) {
		printf("\nFILE: %s ## Database Init Failed!!!\n", __FILE__);
		return -1;
	}
	if (0 != db_read_str("url/Register", RegUrl)) {
		printf("\nFILE: %s ## Database not configured!!!\n", __FILE__);
		return -1;
	}
	dstat = db_read_str("DevId", devid);
	ustat = db_read_str("toserver/AAuthName", userid);
	pstat = db_read_str("toserver/AAuthSecret", passwd);

	/* DevId, UserID, Password are configured during EOL manufacturing */
	if ((dstat != 0) || (ustat != 0) || (pstat != 0)) {

		/* The code will enter here only on first time power on */
		printf("%s(): The device is not registered, trying to register...\n", __func__);
		if (0 != register_device(devid, userid, passwd)) {
			printf("%s(): device registration failure!!\n", __func__);
			retval = -1;
			goto exit;
		}

		if (0 != db_add_str("DevId", devid)) {
			printf("%s(): Can't add DevId to db, attempting to write\n", __func__);
			db_write_str("DevId", devid);
		}

		if (0 != db_add_str("toserver/AAuthName", userid)) {
			printf("%s(): Can't add toserver/AAuthName to db, trying to write \n", __func__);
			db_write_str("toserver/AAuthName", userid);
		}

		if (0 != db_add_str("toserver/AAuthSecret", passwd)) {
			printf("%s(): Can't add toserver/AAuthSecret to db, trying to write \n", __func__);
			db_write_str("toserver/AAuthSecret", passwd);
		}
	}
exit:
	db_exit();
#endif
	return retval;
}
