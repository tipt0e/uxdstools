#include "uxds.h"
/* bastardized kinit - no keytab support
 * fetches a ticket with default context
 * enctype, etc 
 * takes min 1 & max 4 arguments
 * usage: k_init principal [service] [ccache] [password]
 * you can pick ccache and service desired
 * and put password on command line
 * otherwise getpwd() is called for creds
 * useful for php's ldap_sasl_bind() calls
 * able to ditch expect
 */
int main(int argc, char *argv[])
{
    static authzdata auth;

    char *user = NULL;
    char *svc = NULL;
    char *buf = NULL;

    if ((argv[1] == NULL) || (argc < 2) || (argc > 5)) {
	fprintf(stderr,
		"usage: %s principal [service] [ccache] [password]\n",
		argv[0]);
	fprintf(stderr,
		"                use \"NONE\" for defaults if password used\n");
	exit(1);
    }
    user = strdup(argv[1]);
    if (argv[2] == NULL) {
	auth.password = getpwd(user);
	goto tkt;
    }
    if ((argv[2] != NULL) && (strcmp(argv[2], "NONE") != 0)) {
	svc = strdup(argv[2]);
    }
    if ((argv[3] != NULL) && (strcmp(argv[3], "NONE") != 0)) {
	putenv(center(buf, "KRB5CCNAME=", argv[3]));
    }
    else if(argv[3] == NULL) {
        auth.password = getpwd(user);
	goto tkt;
    }
    if (argv[4] != NULL) {
	auth.password = strdup(argv[4]);
    }
    else {
        auth.password = getpwd(user);
    }
  tkt:
    if (get_tkts(user, svc, auth) != 0) {
	exit(1);
    }

    exit(0);
}
