#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>


#define CPU_ID_FILE0 "/sys/fsl_otp/HW_OCOTP_CFG0"
#define CPU_ID_FILE1 "/sys/fsl_otp/HW_OCOTP_CFG1"
#define MAC_ID_FILE  "/sys/class/net/mlan0/address"
#define HOSTNAME_ID "/etc/hostname"

#define MAX_UDID_LEN	128
#define UDID_LEN	64


static char udid[MAX_UDID_LEN];

void copy_udid(char *tmpid0, void *tmpid1)
{
	char *d, *s;
	if (tmpid1 == NULL)
		sprintf(udid, "%s", tmpid0);
	else
		sprintf(udid, "%s%s", tmpid0, tmpid1);


	for ( d = s = udid; *d; s++) {
		if (isspace(*s))
			continue;
		*d = *s;
		d++;
	}
}

int read_machine_id(void)
{
	FILE *fp, *fp0, *fp1;
	int ret;
	char hostname[UDID_LEN], tmpid0[UDID_LEN], tmpid1[UDID_LEN], *d, *s;

	fp = fopen(HOSTNAME_ID, "r");
	if (fp == NULL) {
		printf("Unable to read %s \n", HOSTNAME_ID);
		return -1;
	}

	ret = fread(hostname, 1, UDID_LEN, fp);
	hostname[ret-1]='\0';
	ret = strcmp(hostname, "mahindra");

	if ( 0 == ret) {
		fp0 = fopen(CPU_ID_FILE0, "r");
		fp1 = fopen(CPU_ID_FILE1, "r");
		if ( (fp0 == NULL) || (fp1 == NULL)) {
			printf("\n\n%s(): Can't read hardware register\n", __func__);
			return -1;
		}
		        /* read id from hardware register / sysfs */
		ret= fread(tmpid0, 1, UDID_LEN, fp0);
		printf("Read cfg0 as %s\n", tmpid0);
		tmpid0[ret-1]='\0';
		fclose(fp0);
		fread(tmpid1, 1, UDID_LEN, fp1);
		printf("Read cfg1 as %s\n", tmpid1);
		tmpid1[ret-1]='\0';
		fclose(fp1);

		/* cat and eliminate white space */
		copy_udid(tmpid0, tmpid1);
	}
	else {
		fp0 = fopen(MAC_ID_FILE, "r");
		if ( (fp0 == NULL) || (fp1 == NULL)) {
			printf("\n\n%s(): Can't read MAC register for Monarch \n", __func__);
			fclose(fp);
			return -1;
                }
		fread(tmpid0, 1, UDID_LEN, fp0);
		fclose(fp0);

		/* cat and eliminate white space */
		copy_udid(tmpid0, NULL);
	}
	fclose(fp);
	return 0;
}

char * get_unique_deviceid(void)
{
	int ret;

	/* following lines are specific to i.MX6 micro */
	ret = read_machine_id();
	if (ret == -1) {
		printf("\n\n%s(): Can't read hardware register or MAC register, unintended target \n", __func__);
		strcpy(udid, "PC-");
		if(getenv("USER"))
			strcat(udid, getenv("USER"));
		return udid;
	}
	else
		printf("Valid target found with udid %d \n", udid);
	return udid;
}
