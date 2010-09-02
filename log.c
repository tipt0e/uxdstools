/* log functions */

#include "uxds.h"
#include "strings.h"
#include "log.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "krb5.h"
#endif

#ifdef TOOL_LOG

int log_event(char *acct, usrt type, toolop op, char *text)
{
    static authzdata auth;

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
    if (auth.username == NULL) {
	admin = strdup(get_krbname(auth, 0));
    } else {
	admin = strdup(auth.username);
    }
#else
    admin = strtok(auth.binddn, ";");
#endif				/* HAVE_LDAP_SASL_GSSAPI */

    FILE *fp;
    fp = fopen(UXDS_LOG, "a");
#if 0
    if (fp == NULL) {
	switch (errno) {
	case EINVAL:
	    fprintf(stderr,
		    "EINVAL - invalid value passed to the function\n");
	    break;
	case EACCES:
	    fprintf(stderr, "EACCES - permission denied to open log %s\n",
		    UXDS_LOG);
	    break;
	case EDEADLK:
	    fprintf(stderr,
		    "EDEADLK - resource deadlock would occur opening %s\n",
		    UXDS_LOG);
	    break;
	case ENAMETOOLONG:
	    fprintf(stderr, "ENAMETOOLONG - file name too long\n");
	    break;
	case ENOLCK:
	    fprintf(stderr, "ENOLCK - no record locks available for %s\n",
		    UXDS_LOG);
	    break;
	case ENOSYS:
	    fprintf(stderr, "ENOSYS - function not implemented\n");
	    break;
	case ELOOP:
	    fprintf(stderr,
		    "ELOOP - too many symbolic links encountered opening %s\n",
		    UXDS_LOG);
	    break;
	default:
	    fprintf(stderr, "ERRNO is %i\n", errno);
	    break;
	}
	fprintf(stderr, "ditching on * %i *......\n", errno);
	exit(errno);
    }
#endif
    fprintf(fp,
	    "%s - Change attempted by: ** %s **\n - %s Account %s of %s %s\n",
	    curdate(), admin, blurb, oper, acct, text);

    fclose(fp);
    return 0;
}
#endif				/* TOOL_LOG */
