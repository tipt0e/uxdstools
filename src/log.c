/* log functions */

#include "uxds.h"
#include "uxds_strings.h"
#include "uxds_log.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "uxds_krb5.h"
#endif

#ifdef TOOL_LOG

int log_event(char *acct, uxds_acct_t type, uxds_tool_t op, char *text)
{
    static uxds_authz_t auth;

    char *blurb = NULL;
    char *oper = NULL;
    char *admin = NULL;

    switch (type) {
    case USER:
	blurb = "POSIX USER";
	break;
    case GROUP:
	blurb = "POSIX GROUP";
	break;
    case SUDOER:
	blurb = "SUDOER";
	break;
    default:
	break;
    }
    switch (op) {
    case ADD:
	oper = "ADD";
	break;
    case DEL:
	oper = "DELETE";
	break;
    case MOD:
	oper = "MODIFY";
	break;
    default:
	break;
    }

#ifdef HAVE_LDAP_SASL_GSSAPI
    if (auth.username == NULL) 
	admin = strdup(get_krbname(auth, FALSE));
    else 
	admin = strdup(auth.username);
#else
    admin = strtok(auth.binddn, ",");
#endif				/* HAVE_LDAP_SASL_GSSAPI */

    FILE *fp;
    fp = fopen(UXDS_LOG, "a");
    file_chkerr(fp);
    fprintf(fp,
	    "%s - Change attempted by: ** %s **\n - %s Account %s of %s %s\n",
	    curdate(), admin, blurb, oper, acct, text);

    if (fflush(fp)) {
	fprintf(stderr, "log file was not properly fflush()d\n");
	return 1;
    }
    fclose(fp);
    if (admin)
	free(admin);

    return 0;
}
#endif				/* TOOL_LOG */
