/* Command line parse functions */

#include "uxds.h"
#include "uxds_strings.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "uxds_krb5.h"
#endif

void optmask(char *label, uxds_acct_t type, struct cmdopts opts,
	     uxds_flag_t flag)
{
    switch (flag) {
	/* account with wrong args */
    case XACCT:
	fprintf(stderr, "option not relevant for account TYPE\n");
	usage(0, opts.binary, type, XBOTH);
	break;
	/* only one of user, group, or sudoer */
    case XBOTH:
	fprintf(stderr, "options (-U|-G|-S) CANNOT be concurrent\n\n");
	usage(0, opts.binary, type, XBOTH);
	break;
	/* message for options SASL!GSSAPI only */
    case XBIND:
	fprintf(stderr,
		"option -%c is unnecessary with GSSAPI or SIMPLE binds\n\n",
		(char) opts.letter);
	usage(0, opts.binary, type, XBOTH);
	break;
    default:
	break;
    }
    if (!(opts.chosen) || (opts.chosen[0] == '-')) {
	fprintf(stderr, "option -%c MUST have %s argument\n\n",
		(char) opts.letter, label);
	usage(0, opts.binary, type, XBOTH);
    }
}

void usage(uxds_usage_t mflag, char *binary, uxds_acct_t atype,
	   uxds_tool_t op)
{
    char *acct = NULL;
    char *oper = NULL;
    switch (atype) {
    case USER:
	acct = "POSIX User";
	break;
    case GROUP:
	acct = "POSIX Group";
	break;
    case SELF:
	acct = "POSIX & SUDOer";
	break;
    case SUDOER:
	acct = "SUDOer";
	break;
    default:
	break;
    }
    switch (op) {
    case ADD:
	oper = "Add";
	break;
    case DEL:
	oper = "Delete";
	break;
    case MOD:
	oper = "Modify";
	break;
    case EYE:
	oper = "Parse";
    default:
	break;
    }
    switch (mflag) {
    case UXDS_USAGE:
#ifdef HAVE_LDAP_SASL
	fprintf(stdout,
		"usage: %s -H <host URI> -b <baseDN> -m <SASL mech> [[-u <authcid>] [-D bind DN] [-p passwd] [-P]]\n",
		binary);
#else
	fprintf(stdout,
		"usage: %s -H <host URI> -b <baseDN> [[-D bind DN] [-p passwd] [-P]]\n",
		binary);
#endif				/* HAVE_LDAP_SASL */
	if (op != DEL) {
	    if (atype == GROUP) {
		fprintf(stdout,
			"             [-G <groupname> [-I <description>] [-M|-R <memberUid>] [-N gidNumber]]\n");
	    }
	    if (atype == USER) {
		fprintf(stdout,
			"             [-U <username> -G <primary group> -f <first name> -l <last name> [-N <uidNumber>]]\n");
#ifdef QMAIL
		fprintf(stdout,
			"             [[-S <shell>] [-X <homeDirectory>]] [[-W <email>] [-Q <fqdn>]]\n");
#else
		fprintf(stdout,
			"             [[-S <shell>] [-X <homeDirectory>]]\n");
#endif				/* QMAIL */
	    }
	} else {
	    if (atype == USER) {
		fprintf(stdout, "             [-U <username>]\n");
	    }
	    if (atype == GROUP) {
		fprintf(stdout, "             [-G <groupname>]\n");
	    }
	}
	if (atype == SELF) {
	    fprintf(stdout,
		    "             [-U <username> -G <groupname> [-S <sudoer>]] [-L <filename>]\n");
	}
	if (atype == SUDOER) {
	    switch (op) {
	    case ADD:
		fprintf(stdout,
			"             [-U <user> | -G <group>] [-C <cmd>,...] [-O <option>,...]\n");
		break;
	    case MOD:
		fprintf(stdout,
			"             [-A <sudoUser>] [-C <cmd>,...] [-O <option>,...] [-R]\n");
		break;
	    case DEL:
		fprintf(stdout, "             [-A <sudoUser>]\n");
		break;
	    default:
		break;
	    }
	}
#ifdef HAVE_LDAP_SASL
	fprintf(stdout, "SASL support available.\n");
#ifdef HAVE_LDAP_SASL_GSSAPI
	fprintf(stdout, "GSSAPI support available.\n");
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#endif				/* HAVE_LDAP_SASL */
	exit(EXIT_SUCCESS);
	break;
    case UXDS_HELP:
	fprintf(stdout, "%s - LDAP %s Account %s\n", binary, acct, oper);
	fprintf(stdout, "usage: %s [options]\n", binary);
	fprintf(stdout, "AUTH options:\n");
	fprintf(stdout,
		"   -H URI     LDAP resource URI e.g. ldap://server.example.com\n");
	fprintf(stdout,
		"   -b baseDN  LDAP base DN for searches, e.g. ou=unix,dc=foobar,dc=pvt\n");

#ifdef HAVE_LDAP_SASL_GSSAPI
	fprintf(stdout,
		"   -K cert    X.509 Certificate file to use for PK-INIT\n" \
                "              Requires -u <username|cn>\n");
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#ifdef HAVE_LDAP_SASL
	fprintf(stdout,
		"   -m mech    SASL mechanism e.g. GSSAPI, DIGEST-MD5, CRAM-MD5, etc.\n");
	fprintf(stdout,
		"              or NONE for simple bind operation\n");
	fprintf(stdout,
		"   -V         SASL INTERACTIVE mode - verbose info and used for some mechs\n");
	fprintf(stdout,
		"Options if NONE is chosen as SASL mech (SIMPLE bind):\n");
#endif				/* HAVE_LDAP_SASL */
	fprintf(stdout,
		"   -D DN      DN for simple bind or if enabled SASL authorization identity\n");
#ifdef HAVE_LDAP_SASL
	fprintf(stdout, "Options if GSSAPI is not chosen as SASL mech:\n");
	fprintf(stdout, "   -r realm   SASL realm (not mandatory)\n");
	fprintf(stdout, "   -u user    SASL authentication identity\n");
	fprintf(stdout, "   -p pass    SASL or simple bind password\n");
#endif				/* HAVE_LDAP_SASL */
	fprintf(stdout,
		"   -P         Enter password creds (with GSSAPI enabled obtain ticket)\n");
	fprintf(stdout,
		"              (-m GSSAPI argument NOT needed for above)\n");
	fprintf(stdout, "              must be LAST argument given\n");
#ifdef HAVE_LDAP_SASL_GSSAPI
	fprintf(stdout, "Options if GSSAPI is chosen as SASL mech:\n");
	fprintf(stdout,
		"   -c ccache  Kerberos credentials cache location\n");
	fprintf(stdout,
		"              can be a path, e.g. /tmp/krb5cc_100 or preceded by 'METHOD:'\n");
	fprintf(stdout,
		"              as in FILE:/tmp/krb5cc_100 or KCM:100\n");
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	fprintf(stdout, "Options for Target %s Account %s:\n", acct, oper);
	switch (atype) {
	case USER:
	    fprintf(stdout, "   -U user    Username: <user>\n");
	    if (op != DEL) {
		fprintf(stdout,
			"   -G group   Group to add member to: <gid>\n");
		fprintf(stdout, "   -f name    First name: <name>\n");
		fprintf(stdout, "   -l name    Last name: <name>\n");
		fprintf(stdout, "   -N uidN    UID Number: <uidN>\n");
		fprintf(stdout, "   -X path    Home Directory: <path>\n");
		fprintf(stdout, "   -S shell   Shell: <shell>\n");
#ifdef QMAIL
		fprintf(stdout,
			"   -W email   mailAlternateAddress for Qmail: <email>\n");
		fprintf(stdout,
			"   -Q fqdn    mailHost for Qmail: <server>\n");
#endif				/* QMAIL */
#ifdef HAVE_LDAP_SASL_GSSAPI
		fprintf(stdout,
			"   -y         reset password (krb5Key) to random string\n");
		fprintf(stdout,
			"   -z passwd  set password (krb5Key) to string (passwd)\n");
		fprintf(stdout,
			"   -e         expire account password (krb5PasswordEnd)\n");
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	    }
	    break;
	case GROUP:
	    fprintf(stdout, "   -G group   Groupname: <group>\n");
	    if (op != DEL) {
		fprintf(stdout, "   -N gidN    GID Number: <gidN>\n");
		fprintf(stdout,
			"   -I desc    Description (use quotes if spaces) \"<desc>\"\n");
		fprintf(stdout,
			"   -M name    Add user(s) as group memberUid - if multiple\n");
		fprintf(stdout,
			"              separate with commas: -M grp1,grp2\n");
		if (op == MOD) {
		    fprintf(stdout,
			    "   -R name    Delete user(s) as group memberUid - if multiple\n");
		    fprintf(stdout,
			    "              separate with commas: -R grp1,grp2\n");
		}
	    }
	    break;
	case SELF:
	    fprintf(stdout,
		    "   -U uid     Parse POSIX user account for <uid>\n");
	    fprintf(stdout,
		    "   -G group   Parse POSIX group account for <group>\n");
	    fprintf(stdout,
		    "   -S sudoer  Parse SUDOer account for <sudoer>\n");
	    fprintf(stdout, "   -L file    export ldif to <file>\n");
	    break;
	case SUDOER:
	    if (op != ADD) {
		fprintf(stdout, "   -A         LDAP sudoUser account\n");
	    } else {
		fprintf(stdout,
			"   -U user    LDAP POSIX user to add as sudoUser\n");
		fprintf(stdout,
			"   -G group   LDAP POSIX group to add as sudoUser\n");
		fprintf(stdout,
			"              (-U OR -G they are exclusive)\n");
	    }
	    if (op != DEL) {
		fprintf(stdout,
			"              for below if multiple arguments then\n");
		fprintf(stdout,
			"              separate with commas and single quotes\n");
		fprintf(stdout,
			"   -C cmd     sudoCommand(s) to add <cmdpath>\n");
		fprintf(stdout,
			"              e.g. -C '/bin/sh,!/bin/cat' etc.\n");
		fprintf(stdout,
			"   -O opt     sudoOption(s) to add <option>\n");
		fprintf(stdout,
			"              e.g. -O '!authenticate,env_reset' etc.\n");
	    }
	    break;
	default:
	    break;
	}
	fprintf(stdout, "misc options:\n");
	fprintf(stdout,
		"   -d         set debug bit for verbose output\n");
	fprintf(stdout, "   -v|--version\n");
	fprintf(stdout, "              show version info\n");
	fprintf(stdout, "   -h|--help  HELP! prints this message\n");
	exit(EXIT_FAILURE);
	break;
    case UXDS_VERSION:
	fprintf(stdout, "%s : LDAP %s Account %s - uxdstools v%s\n",
		binary, acct, oper, VERSION);
	exit(EXIT_SUCCESS);
	break;
    default:
	break;
    }
}


/* command line parser */
int parse_args(int argc, char **argv, uxds_acct_t atype, uxds_tool_t op,
		int numargs, uxds_authz_t * auth, uxds_data_t *mdata,
		char *binary)
{
    int i;
    int sflag;

    struct cmdopts opts;

#ifdef HAVE_LDAP_SASL_GSSAPI
    char *cbuf = NULL;
    auth->pkcert = NULL;
    auth->credcache = NULL;
    auth->saslmech = NULL;
#endif				/* HAVE_LDAP_SASL_GSSAPI */
    opts.binary = binary;
    auth->debug = 0;
    auth->verb = 0;
    auth->uri = NULL;
    auth->binddn = NULL;
    auth->username = NULL;
    auth->password = NULL;
    auth->pxacct = NULL;
    auth->basedn = NULL;
    auth->ldif = NULL;
    auth->password = calloc(1, sizeof(struct berval));
    auth->password->bv_val = NULL;
    auth->password->bv_len = 0;
    if ((atype == SELF) || (atype == SUDOER)) {
	goto parse;
    }
    mdata->exp = 0;
    mdata->cpw = 0;
    mdata->membit = 0;
    mdata->_entry = 0;
    mdata->ou = NULL;
    mdata->user = NULL;
    mdata->group = NULL;
    mdata->firstname = NULL;
    mdata->lastname = NULL;
    mdata->member = NULL;
    mdata->shell = NULL;
    mdata->comment = NULL;
    mdata->uidnum = NULL;
    mdata->gidnum = NULL;
    mdata->homes = NULL;
    mdata->setpass = NULL;
#ifdef QMAIL
    mdata->mhost = NULL;
    mdata->altaddr = NULL;
#endif				/* QMAIL */
  parse:
    if (argv[1] == NULL) {
	usage(UXDS_USAGE, argv[0], atype, op);
    }
    if (argc < (numargs)) {
	if ((strstr(argv[1], "-v")) || (strstr(argv[1], "--version"))) {
	    usage(UXDS_VERSION, argv[0], atype, op);
	    exit(EXIT_SUCCESS);
	}
	if ((strstr(argv[1], "-h")) || (strstr(argv[1], "--help"))) {
	    usage(UXDS_HELP, argv[0], atype, op);
	} else {
	    usage(UXDS_USAGE, argv[0], atype, op);
	}
    }
    if (atype == SUDOER) {
	mdata->su = calloc(1, sizeof(uxds_sudo_t));
	mdata->su->sudoer = NULL;
	mdata->su->cmd_s = NULL;
	mdata->su->opt_s = NULL;
	mdata->su->ou = NULL;
    }
    /* option arguments */
    sflag = 0;
    int c = 0;
    for (i = 1; i < argc; i++) {
	if (argv[i][0] == '-') {
	    if (!(argv[i][1])) {
		usage(UXDS_USAGE, argv[0], atype, op);
	    }
	    /* ugly hack */
	    opts.dash = argv[i][0];
	    opts.letter = argv[i][1];
	    i++;
	    opts.chosen = argv[i];
	    i--;
	    switch (argv[i][1]) {
	    case 'v':		/* Show version info */
		usage(UXDS_VERSION, argv[0], atype, op);
		break;
	    case 'h':		/* Verbose help message */
		usage(UXDS_HELP, argv[0], atype, op);
		break;
	    case 'd':		/* set debug bit */
		if (auth->debug == 0) {
		    auth->debug++;
		    fprintf(stderr, "DEBUG flag set.\n");
		} else {
		    fprintf(stderr,
			    "DEBUG flag ALREADY set, ignoring...\n");
		}
		break;
	    case 'V':
		if (auth->verb == 0) {
		    auth->verb++;
		}
		break;
		/* AUTHENTICATION options */
	    case 'H':		/* LDAP host URI */
		i++;
		optmask("<URI>", atype, opts, c);
		auth->uri = strdup(argv[i]);
		i--;
		break;
	    case 'b':
		i++;
		optmask("<base DN>", atype, opts, c);
		auth->basedn = strdup(argv[i]);
		i--;
		break;
#ifdef HAVE_LDAP_SASL
	    case 'm':		/* SASL mechanism  */
		optmask("<SASLMECH> or NONE for", atype, opts, c);
		auth->saslmech = argv[i + 1];
		if (!(strncasecmp("GSSAPI", argv[i + 1], 4))) {
		    sflag = 2;
		    auth->username = NULL;
		    auth->binddn = NULL;
		} else {
		    sflag = 1;
		}
		break;
#endif				/* HAVE_LDAP_SASL */
	    case 'D':		/* LDAP authorization DN */
		i++;
#ifdef HAVE_LDAP_SASL_GSSAPI
		if (sflag == 2) {
		    fprintf(stderr,
			    "option -D is unnecessary with GSSAPI\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		optmask("<DN>", atype, opts, c);
		auth->binddn = strdup(argv[i]);
		i--;
		break;
#ifdef HAVE_LDAP_SASL_GSSAPI
	    case 'c':		/* Krb5 credentials cache */
		i++;
		if (sflag < 2) {
		    fprintf(stderr,
			    "option -c is only available with GSSAPI mech\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		optmask("<ccache>", atype, opts, c);
		auth->credcache = strdup(argv[i]);
		if (sflag == 3) {
		    putenv(center(cbuf, "KRB5CCNAME=", auth->credcache));
		    printf("%s is var\n", getenv("KRB5CCNAME"));
		}
		i--;
		break;
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#ifdef HAVE_LDAP_SASL
	    case 'u':		/* SASL authentication identity */
		i++;
#ifdef HAVE_LDAP_SASL_GSSAPI
		if ((sflag != 2 && auth->saslmech == NULL)
		    || auth->pkcert != NULL) {
		    sflag = 3;
		}
#else
		c = XBIND;
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		optmask("<username>", atype, opts, c);
		auth->username = strdup(argv[i]);
		i--;
		break;
	    case 'r':		/* Realm NOT MANDATORY */
		i++;
		c = XBIND;
		optmask("<realm>", atype, opts, c);
		auth->realm = strdup(argv[i]);
		i--;
		break;
#endif				/* HAVE_LDAP_SASL */
		/* Switch depending on atype, op */
	    case 'L':		/* export LDIF */
		i++;
		optmask("<filename>", atype, opts, c);
		auth->ldif = strdup(argv[i]);
		i--;
		break;
#ifdef HAVE_LDAP_SASL_GSSAPI
	    case 'K':		/* PK-INIT */
		i++;
		optmask("<filename>", atype, opts, c);
		if (auth->username == NULL) {
		    fprintf(stderr, "MUST HAVE -u option for -K option\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		if ((sflag < 3) || (auth->saslmech) || (auth->binddn)) {
		    fprintf(stderr,
			    "-D|-P|-m options CONFLICT with -K option\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		if (strncmp(argv[i], "FILE:", 5) != 0) {
		    fprintf(stderr,
			    "with [-K] 'FILE:' must prepend the path to the certificate\n\n");
                    usage(UXDS_USAGE, argv[0], atype, op);
                }
                char *check = strdup(argv[i]);
                strtok(check, ":");
                if (strtok(NULL, ":") == NULL) {
                    fprintf(stderr,
                            "with [-K] there must be a certificate name after 'FILE:'\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
                free(check);
		auth->pkcert = strdup(argv[i]);
		fprintf(stdout, "Using PK-INIT with x509 cert: %s\n",
			auth->pkcert);
		i--;
		break;
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	    case 'U':		/* user account select */
		i++;
		switch (atype) {
		case GROUP:
		    fprintf(stderr,
			    "%s: -U not an option for POSIX GROUP OPS\n",
			    binary);
		    exit(EXIT_FAILURE);
		    break;
		case SELF:
		    if ((auth->acct == GROUP) || (auth->acct == SUDOER))
			c = XBOTH;
		    //optmask("<username>", atype, opts, c);
		    auth->acct = USER;
		    if ((argv[i] != NULL) && (argv[i][0] != '-')) {
			auth->pxacct = strdup(argv[i]);
		    }
		    break;
		case SUDOER:
		    if (op != ADD) {
			fprintf(stderr,
				"%s: -U is an option for SUDOER ADD ONLY\n",
				binary);
			exit(EXIT_FAILURE);
		    } else {
			optmask("<username>", atype, opts, c);
			mdata->su->type = USER;
			mdata->su->sudoer = strdup(argv[i]);
		    }
		    break;
		case USER:
		    optmask("<username>", atype, opts, c);
		    mdata->user = strdup(argv[i]);
		    break;
		default:
		    break;
		}
		i--;
		break;
	    case 'G':
		i++;
		int g = 7;
		if (auth->debug)
		    g++;
                if (auth->pkcert)
                    g = g + 2;
		if ((atype != GROUP) && (atype != SUDOER) && (op != ADD)) {
		    if ((op == MOD) && (argc > g)) {
			fprintf(stderr,
				"%s: %i is argc -G only good WITHOUT ANY OTHER modifications\n",
				binary, g);
			exit(EXIT_FAILURE);
		    }
		    if (atype == SELF) {
			if ((auth->acct == USER) || (auth->acct == SUDOER))
			    c = XBOTH;
			//optmask("<group>", atype, opts, c);
			auth->acct = GROUP;
			if ((argv[i] != NULL) && (argv[i][0] != '-')) {
			    auth->pxacct = strdup(argv[i]);
			}
			i--;
			break;
		    } else {
			mdata->modrdn = 1;
			goto modrdn;
		    }
		    fprintf(stderr,
			    "%s: -G not an option for existing POSIX USER DELETE\n",
			    binary);
		    exit(EXIT_FAILURE);
		}
		if (atype == SUDOER) {
		    if (op != ADD) {
			fprintf(stderr,
				"%s: -G is an option for SUDOER ADD ONLY\n",
				binary);
			exit(EXIT_FAILURE);
		    } else {
			mdata->su->type = GROUP;
			mdata->su->sudoer = strdup(argv[i]);
		    }
		    i--;
		    break;
		}
	      modrdn:;
		optmask("<group>", atype, opts, c);
		mdata->group = strdup(argv[i]);
		i--;
		break;
	    case 'A':
		i++;
		if (atype != SUDOER) {
		    optmask("<sudoer>", atype, opts, XACCT);
		    break;
		}
		if (op == ADD) {
		    fprintf(stderr,
			    "%s: [-A] Relevant for SUDOER ADD ONLY\n",
			    binary);
		    exit(EXIT_FAILURE);
		}
		optmask("<sudoer>", atype, opts, c);
		mdata->su->sudoer = strdup(argv[i]);
		i--;
		break;
	    case 'N':
		i++;
		if (atype == SELF) {
		    fprintf(stderr, "not a PARSING option\n");
		    exit(EXIT_FAILURE);
		}
		if ((strlen(argv[i]) != 5)) {
		    fprintf(stderr, "(u|g)idNumber MUST be 5 digits\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		if (atype == USER) {
		    optmask("<uidNumber>", atype, opts, c);
		    mdata->uidnum = strdup(argv[i]);
		    i--;
		    break;
		} else if (atype == GROUP) {
		    optmask("<gidNumber>", atype, opts, c);
		    mdata->gidnum = strdup(argv[i]);
		    i--;
		    break;
		}
		i--;
		break;
	    case 'f':
		i++;
		if (atype != USER) {
		    optmask("<first name>", atype, opts, XACCT);
		    break;
		}
		optmask("<first name>", atype, opts, c);
		mdata->firstname = strdup(argv[i]);
		i--;
		break;
	    case 'l':
		i++;
		if (atype != USER) {
		    optmask("<last name>", atype, opts, XACCT);
		    break;
		}
		optmask("<last name>", atype, opts, c);
		mdata->lastname = strdup(argv[i]);
		i--;
		break;
	    case 'I':
		i++;
		if (atype != USER) {
		    optmask("<\"description\">", atype, opts, c);
		    mdata->comment = strdup(argv[i]);
		    i--;
		    break;
		}
		i--;
		break;
	    case 'R':
		i++;
		if (atype == SUDOER) {
		    if (op != MOD) {
			fprintf(stderr,
				"%s: [-R] for SUDOer MODIFICATIONS ONLY\n",
				binary);
			exit(EXIT_FAILURE);
		    } else {
			mdata->su->tool = DEL;
			i--;
			break;
		    }
		}
		if ((atype != GROUP) || (op != MOD)) {
		    optmask("<memberUid>", atype, opts, XACCT);
		    break;
		}
		optmask("<memberUid>", atype, opts, c);
		mdata->membit = 1;
		mdata->member = strdup(argv[i]);
		i--;
		break;
	    case 'M':
		i++;
		if (atype != GROUP) {
		    optmask("<memberUid>", atype, opts, XACCT);
		}
		optmask("<memberUid>", atype, opts, c);
		mdata->membit = 0;
		mdata->member = strdup(argv[i]);
		i--;
		break;
	    case 'X':
		i++;
		if ((op == DEL) && (atype != USER)) {
		    optmask("<memberUid>", atype, opts, XACCT);
		}
		optmask("<homedir>", atype, opts, c);
		mdata->homes = strdup(argv[i]);
		i--;
		break;
	    case 'S':
		i++;
		if (atype == GROUP) {
		    fprintf(stderr,
			    "-S not compatible with POSIX GROUP OPS\n");
		    exit(EXIT_FAILURE);
		}
		if (atype == SELF) {
		    if ((auth->acct == USER) || (auth->acct == GROUP))
			c = XBOTH;
		    //optmask("<sudoer>", atype, opts, c);
		    auth->acct = SUDOER;
		    if (argv[i] != NULL) {
			auth->pxacct = strdup(argv[i]);
		    }
		    i--;
		    break;
		}
		if (op == DEL) {
		    optmask("<shell>", atype, opts, XACCT);
		    break;
		}
		optmask("<shell>", atype, opts, c);
		mdata->shell = (char *) malloc(strlen(argv[i] + 2));
		//snprintf(mdata->shell,strlen(argv[i] + 1),"%s",argv[i]);
		/* I know this is _bad_ but I don't get truncation */
		mdata->shell = strdup(argv[i]);
		i--;
		break;
#ifdef QMAIL
	    case 'W':
		i++;
		if ((atype != USER) || (op == DEL)) {
		    fprintf(stderr,
			    "-W only used with POSIX USER ADD or MODIFY\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		optmask("<email>", atype, opts, c);
		mdata->altaddr = strdup(argv[i]);
		i--;
		break;
	    case 'Q':
		i++;
		if ((atype != USER) || (op == DEL)) {
		    fprintf(stderr,
			    "-Q only used with POSIX USER ADD or MODIFY\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		optmask("<fqdn>", atype, opts, c);
		mdata->mhost = strdup(argv[i]);
		i--;
		break;
#endif				/* QMAIL */
		/* sudoer options */
	    case 'C':
		i++;
		if (atype != SUDOER) {
		    optmask("<sudoCommand>", atype, opts, XACCT);
		    break;
		}
		optmask("<sudoCommand>", atype, opts, c);
		mdata->su->cmd_s = strdup(argv[i]);
		i--;
		break;
	    case 'O':
		i++;
		if (atype != SUDOER) {
		    optmask("<sudoOption>", atype, opts, XACCT);
		    break;
		}
		optmask("<sudoOption>", atype, opts, c);
		mdata->su->opt_s = strdup(argv[i]);
		i--;
		break;
	    case 'y':		/* set flag for passwd resets */
		i++;
		if (mdata->setpass != NULL) {
		    fprintf(stderr,
			    "option -z cannot be used with option -y\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		}
		if ((op == DEL) || (atype != USER)) {
		    fprintf(stderr,
			    "option -y only used with USER ADD or MODIFY\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		}
		if (mdata->cpw == 0) {
		    mdata->cpw++;
		}
		i--;
		break;
	    case 'z':
		i++;
		if (mdata->cpw == 1) {
		    fprintf(stderr,
			    "option -z cannot be used with option -y\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		}
		if ((op == DEL) || (atype != USER)) {
		    fprintf(stderr,
			    "option -z only used with USER ADD or MODIFY\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		}
		optmask("<password>", atype, opts, c);
		mdata->setpass = (char *) malloc(sizeof(char));
		mdata->setpass = strdup(argv[i]);
		i--;
		break;
	    case 'e':		/* expire password - sets to 12/31/2007 */
		i++;
		if ((op == DEL) || (atype != USER)) {
		    fprintf(stderr,
			    "option -e only used with USER ADD or MODIFY\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		}
		if (mdata->exp == 0) {
		    mdata->exp++;
		}
		i--;
		break;
	    case 'p':		/* Password for SASL or SIMPLE bind */
		i++;
#ifdef HAVE_LDAP_SASL_GSSAPI
		if ((sflag == 2) || (auth->pkcert != NULL)) {
		    fprintf(stderr,
			    "option -p is unnecessary with GSSAPI or PKINIT\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		if (argv[i] == NULL) {
		    fprintf(stderr,
			    "option -p MUST have <password> argument\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		auth->password->bv_val = strdup(argv[i]);
		i--;
		break;
	    case 'P':		/* enter password on command line */
		i++;
#ifdef HAVE_LDAP_SASL_GSSAPI
		if ((sflag == 2) || (auth->pkcert != NULL)) {
		    fprintf(stderr,
			    "option -P is unnecessary with GSSAPI or PKINIT\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		if (argv[i] != NULL) {
		    fprintf(stderr,
			    "option -P must be the LAST argument\n\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		}
		switch (sflag) {
		case 0:
		    fprintf(stdout, "SIMPLE Bind selected.\n");
		    break;
#ifdef HAVE_LDAP_SASL
		case 1:
		    fprintf(stdout, "SASL Bind selected with %s mech.\n",
			    auth->saslmech);
		    break;
#ifdef HAVE_LDAP_SASL_GSSAPI
		case 2:
		    fprintf(stderr,
			    "[-P] incompatible with [-m] GSSAPI mech.\n");
		    usage(UXDS_USAGE, argv[0], atype, op);
		    break;
		case 3:
		    fprintf(stdout,
			    "KINIT with SASL/GSSAPI Bind selected.\n");
		    auth->password->bv_val =
			strdup(getpwd(auth->username));
		    auth->password->bv_len =
			strlen(auth->password->bv_val);
		    break;
#endif				/*HAVE_LDAP_SASL_GSSAPI */
#endif				/*HAVE_LDAP_SASL */
		default:
		    fprintf(stderr, "FATAL ERROR - no bind flag SET.\n");
		    exit(EXIT_FAILURE);
		    break;
		}

		if (auth->username == NULL) {
		    auth->password->bv_val = strdup(getpwd("Your DN"));
		    auth->password->bv_len =
			strlen(auth->password->bv_val);
		}
/* if GSSAPI enabled we let 
 * krb5_posix_prompter take care if it
 */
#ifndef HAVE_LDAP_SASL_GSSAPI
		else {
		    auth->password->bv_val =
			strdup(getpwd(auth->username));
		    auth->password->bv_len =
			strlen(auth->password->bv_val);
		}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		break;
	    default:		/* bucket for all other switches */
		fprintf(stderr, "-%c is NOT a recognized option\n\n",
			argv[i][1]);
		usage(UXDS_USAGE, argv[0], atype, op);
		break;
	    }
	}
	if ((atype == SELF) || (atype == SUDOER)) {
	    goto nextparse;
	}
	if (op != DEL) {
	    if (atype == USER) {
		if (mdata->firstname != NULL) {
		    mdata->_entry++;
		}
		if (mdata->lastname != NULL) {
		    mdata->_entry++;
		}
		if (mdata->uidnum != NULL) {
		    mdata->_entry++;
		}
		if (mdata->shell != NULL) {
		    mdata->_entry++;
		}
		if (mdata->homes != NULL) {
		    mdata->_entry++;
		}
		if ((mdata->firstname != NULL)
		    || (mdata->lastname != NULL)) {
		    mdata->_entry++;
		}
		if (mdata->cpw != 0) {
		    mdata->_entry++;
		}
#ifdef QMAIL
		if (mdata->mhost != NULL) {
		    mdata->_entry++;
		}
		if (mdata->altaddr != NULL) {
		    mdata->_entry++;
		}
#endif				/* QMAIL */
	    }
	    if (atype == GROUP) {
		if (mdata->gidnum != NULL) {
		    mdata->_entry = 1;
		}
		if (mdata->comment != NULL) {
		    mdata->_entry++;
		}
		if (mdata->member != NULL) {
		    mdata->_entry++;
		}
	    }
	}
      nextparse:;
    }
    if ((atype == SELF) || (atype == SUDOER)) {
	goto againparse;
    }
    /* this can be tweak to allow custom GECOS */
    if ((op == ADD) && (atype == USER)) {
	if ((mdata->firstname == NULL) || (mdata->lastname == NULL) ||
	    (mdata->group == NULL)) {
	    fprintf(stderr,
		    "%s: [-G <group>],[-f <first name>],[-l <last name>] all REQUIRED for USER ADD\n",
		    binary);
	    exit(EXIT_FAILURE);
	}
    }
    if ((op == ADD) && (atype == GROUP)) {
	if ((mdata->group == NULL) || (mdata->comment == NULL)) {
	    fprintf(stderr,
		    "%s: [-I] <description> is REQUIRED for POSIX GROUP ADD\n",
		    binary);
	    exit(EXIT_FAILURE);
	}
    }

    if ((op == ADD) && (atype == USER)) {
	if (mdata->user == NULL) {
	    fprintf(stderr,
		    "%s: [-U] <username> is REQUIRED for POSIX USER ADD\n",
		    binary);
	    exit(EXIT_FAILURE);
	}
    }

    if ((op != ADD)) {
	if ((atype == USER) && (mdata->user == NULL)) {
	    fprintf(stderr,
		    "%s: [-U] <username> REQUIRED for POSIX USER OPS\n",
		    binary);
	    exit(EXIT_FAILURE);
	}

	if ((atype == GROUP) && (mdata->group == NULL)) {
	    fprintf(stderr,
		    "%s: [-G] <group> REQUIRED for POSIX GROUP OPS\n",
		    binary);
	    exit(EXIT_FAILURE);
	}
    }
  againparse:;
    if (atype == SELF) {
	if (auth->pxacct == NULL) {
	    auth->pxacct = "*";
	    if ((auth->acct != USER) &&
		(auth->acct != GROUP) && (auth->acct != SUDOER)) {
		auth->acct = SELF;
	    }
	}
    }
    if (atype == SUDOER) {
	if ((op != DEL) && (mdata->su->cmd_s == NULL)) {
	    if (op == ADD) {
		fprintf(stderr,
			"%s: At least ONE [-C] <cmd> argument MUST be supplied for SUDOER ADD\n",
			binary);
		exit(EXIT_FAILURE);
	    } else if (mdata->su->opt_s == NULL) {
		fprintf(stderr,
			"%s: At least ONE [-C] <cmd> or [-O] <opt> MUST be supplied for SUDOER MODIFY\n",
			binary);
		exit(EXIT_FAILURE);
	    }
	}
	if (mdata->su->sudoer == NULL) {
	    if (op == ADD) {
		fprintf(stderr,
			"%s: A POSIX USER or GROUP account MUST be chosen for SUDOER OPS\n",
			binary);
	    } else {
		fprintf(stderr,
			"%s: A SUDOER Account MUST be chosen for SUDOER OPS\n",
			binary);
	    }
	    exit(EXIT_FAILURE);
	}

    }
#ifdef HAVE_LDAP_SASL_GSSAPI
    if ((auth->password != NULL) || (auth->pkcert != NULL)) {
	switch (sflag) {
	case 0:
	    if (auth->debug)
		fprintf(stderr, "SIMPLE BIND selected.\n");
	    break;
	case 1:
	    if (auth->debug)
		fprintf(stderr, "SASL - %s selected as mech.\n",
			auth->saslmech);
	    break;
	case 2:
	    if (auth->password->bv_val != NULL) {
		fprintf(stderr,
			"-m GSSAPI is INCOMPATIBLE with [-u] and [-p|-P]\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	case 3:
	    if (get_tkts(auth->username, NULL, *auth) == 0) {
		if ((atype == USER) && (op != DEL)) {
		    if ((mdata->cpw == 1) || (mdata->setpass != NULL)) {
			char *ccname = get_krbname(*auth, 1);
			char *ccbuf = NULL;
			putenv(center
			       (ccbuf, "KRB5CCNAME=/tmp/kacache_",
				auth->username));
			center_free(ccbuf);
			if (get_tkts
			    (auth->username, "kadmin/changepw",
			     *auth) != 0) {
			    fprintf(stderr,
				    "error in obtaining changepw ticket\n");
			}
			putenv(center(ccbuf, "KRB5CCNAME=", ccname));
			center_free(ccbuf);
		    }
		}
		auth->username = NULL;
		auth->saslmech = "GSSAPI";
		sflag = 2;
	    } else {
		fprintf(stderr, "error in obtaining krbtgt ticket\n");
		fprintf(stderr,
			"all subsequent operations will fail...\n");
	    }
	    break;
	default:
	    break;
	}
    }
#endif				/* HAVE_LDAP_SASL_GSSAPI */
    return sflag;
}
