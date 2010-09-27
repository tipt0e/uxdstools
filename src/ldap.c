/* LDAP functions */

#include "uxds.h"
#include "uxds_strings.h"
#ifdef HAVE_LDAP_SASL
#include "uxds_sasl.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "uxds_krb5.h"
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#endif				/* HAVE_LDAP_SASL */
#ifdef PTS
#include "uxds_afs.h"
#endif				/* PTS */
#ifdef TOOL_LOG
#include "uxds_log.h"
#endif				/* TOOL_LOG */

int rc;
char *cbuf = NULL;
char *res = "ERROR";
struct berval **vals;

int uxds_user_authz(int select, authzdata auth, LDAP * ld)
{
    int proto;
    int authmethod = 0;
#ifdef HAVE_LDAP_SASL
    char *sasl_mech = NULL;
    unsigned sasl_flags = 0;
#endif				/* HAVE_LDAP_SASL */

    char *ldapuri = ber_strdup(auth.l_uri);

    if (auth.debug) {
	fprintf(stderr, "sflag value is %i -> ", select);
	fprintf(stderr,
		"(0 = SIMPLE, 1 = SASL non GSSAPI, 2 = SASL/GSSAPI)\n");
	fprintf(stderr, "LDAP host URI is: %s\n", ldapuri);
    }
#ifdef HAVE_LDAP_SASL
/* SASL authentication chosen */
    if ((select > 0) || (auth.pkcert)) {
	authmethod = LDAP_AUTH_SASL;
	sasl_mech = ber_strdup(auth.s_mech);
	if (auth.verb == 1) {
	    sasl_flags = LDAP_SASL_INTERACTIVE;	/* [-V] some mechs need? */
	} else {
	    sasl_flags = LDAP_SASL_QUIET;	/* default */
	}
#ifdef HAVE_LDAP_SASL_GSSAPI
	if (select == 2) {
	    if (auth.debug)
		fprintf(stderr,
			"used GSSAPI -> credentials cache is: %s\n",
			auth.credcache);
	}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
    }
#endif				/* HAVE_LDAP_SASL */
    /* simple authentication chosen */
#ifdef HAVE_LDAP_SASL_GSSAPI
    if ((select == 0) && (!auth.pkcert))
#else
    if (select == 0)
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	authmethod = LDAP_AUTH_SIMPLE;

    proto = LDAP_VERSION3;

    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &proto) !=
	LDAP_OPT_SUCCESS) {
	fprintf(stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
		proto);
	return 1;
    }

    switch (authmethod) {
#ifdef HAVE_LDAP_SASL
    case LDAP_AUTH_SASL:
#ifdef HAVE_LDAP_SASL_GSSAPI
	if (select == 2) {
	    if (auth.credcache != NULL) {
		auth.credcache =
		    center(cbuf, "KRB5CCNAME=", auth.credcache);
		center_free(cbuf);
		if (auth.debug)
		    fprintf(stderr, "'%s' exported\n", auth.credcache);
		putenv(auth.credcache);
	    }
	}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	if (auth.binddn != NULL) {
	    if (auth.debug)
		fprintf(stderr, "selected dn: %s\n", auth.binddn);
	}
	rc = ldap_sasl_interactive_bind_s(ld, auth.binddn,
					  sasl_mech, NULL, NULL,
					  sasl_flags, uxds_sasl_interact,
					  &auth);
	break;
#endif				/* HAVE_LDAP_SASL */
    case LDAP_AUTH_SIMPLE:
    default:
	if (auth.password->bv_val != NULL) {
	    auth.password->bv_len = strlen(auth.password->bv_val);
	    rc = ldap_sasl_bind_s(ld, auth.binddn, NULL, auth.password,
				  NULL, NULL, NULL);
	} else {
	    /* XXX */
	    fprintf(stderr,
		    "FATAL: need to fix in args.c - exiting with no SIMPLE BIND passwd\n");
	    fprintf(stderr, "Need [-p <password>] or [-P] option\n");

	    return 1;
	}
	break;
    }

    if (rc != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	ldap_unbind_ext_s(ld, NULL, NULL);
	return 1;
    }
    if (auth.debug)
	fprintf(stdout, "SUCCESSFUL bind using URI %s\n", ldapuri);
#ifdef HAVE_LDAP_SASL
    /* get SASL SSF factor - debug */
    if (auth.debug) {
	sasl_ssf_t ssf;
	unsigned long val = 0;
	if (!ldap_get_option(ld, LDAP_OPT_X_SASL_SSF, &ssf)) {
	    val = (unsigned long) ssf;
	}
	fprintf(stderr, "SSF level is: %lu\n", val);
    }
#endif				/* HAVE_LDAP_SASL */
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
    }
    return 0;
}

/* unbind from directory service */
int uxds_ldap_unbind(LDAP * ld)
{
    rc = ldap_unbind_ext_s(ld, NULL, NULL);
#ifdef HAVE_LDAP_SASL
    sasl_done();
    sasl_client_init(NULL);
#endif				/* HAVE_LDAP_SASL */

    return rc;
}

/* perform search operation and parse - based on account type argument */
int uxds_acct_parse(int bindtype, authzdata auth, LDAP * ld)
{
    BerElement *ber;
    LDAPMessage *msg;
    LDAPMessage *entry;

    FILE *fp;

    int i;
    int all = 0;
    char *dn = NULL;
    char *base = NULL;
    char *attr = NULL;
    char *fbuf = NULL;
    char *filter = NULL;
    char *accttype = NULL;
    enum { s, S, G };
    /* only pull these values */
    char *attr_mask[] = { "cn",
	"sn",
	"givenName",
	"mail",
	"mailHost",
	"mailLocalAddress",
	"mailAlternateAddress",
	"mailMessageStore",
	"accountStatus",
	"gecos",
	"uid",
	"uidNumber",
	"gidNumber",
	"homeDirectory",
	"description",
	"memberUid",
	"loginShell",
	"krb5PrincipalName",
	"krb5PasswordEnd",
	"sshPublicKey",
	"sudoRole",
	"sudoCommand",
	"sudoOption",
	(char *) 0
    };

#ifdef HAVE_LDAP_SASL_GSSAPI
    char *kuser = NULL;
#endif				/* HAVE_LDAP_SASL_GSSAPI */

    base = NULL;
    if (auth.debug)
	fprintf(stderr, "account type vars: account = %i\n", auth.acct);
    if (strchr(auth.pxacct, '*') != NULL)
	all = 1;
    switch (auth.acct) {
	/* if user/group/sudoer argument not selected - then do who am i? */
    case SELF:
	switch (bindtype) {
	case s:
	    base = strdup(auth.binddn);
	    filter = "uid=*";
	    if (auth.debug)
		fprintf(stderr, "search filter string: %s\n", filter);
	    break;
#ifdef HAVE_LDAP_SASL
	case S:
	    filter = center(fbuf, "uid=", auth.username);
	    if (auth.debug)
		fprintf(stderr, "search filter string: %s\n", filter);
	    break;
#ifdef HAVE_LDAP_SASL_GSSAPI
	case G:
	    kuser = get_krbname(auth, FALSE);
	    if (auth.debug)
		fprintf(stderr,
			"user account filter half returned: %s, size %lu len %lu\n",
			kuser, sizeof(kuser), strlen(kuser));
	    filter = strdup(center(fbuf, "uid=", kuser));
	    center_free(fbuf);
	    if (auth.debug)
		fprintf(stderr, "search filter string: %s\n", filter);
	    break;
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#endif				/* HAVE_LDAP_SASL */
	default:
	    break;
	}
	break;
    case USER:
	filter =
	    strdup(center
		   (fbuf, center(fbuf, POSIXACCOUNT, auth.pxacct), "))"));
	accttype = "POSIX User";
	break;
    case GROUP:
	filter =
	    strdup(center
		   (fbuf, center(fbuf, POSIXGROUP, auth.pxacct), "))"));
	accttype = "POSIX Group";
	break;
    case SUDOER:
	filter =
	    strdup(center
		   (fbuf, center(fbuf, SUDOUSER, auth.pxacct), "))"));
	accttype = "SUDOer";
	break;
    }
    center_free(fbuf);
    if (auth.debug)
	fprintf(stderr, "using '%s' as selected account\n", auth.pxacct);
    if (auth.basedn != NULL) {
	base = strdup(auth.basedn);
    }
    /* perform search */
    if (auth.debug)
	fprintf(stderr, "final passed filter: %s\n", filter);
    if (auth.ldif != NULL) {
	attr_mask[0] = NULL;
    }
    if (ldap_search_ext_s
	(ld, base, LDAP_SCOPE_SUBTREE, filter, attr_mask, 0,
	 NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    if (accttype == NULL) {
	accttype = "Your";
    }
    if (all == 1) {
	fprintf(stdout, "------- %s Account Listing -------\n", accttype);
	for (entry = ldap_first_entry(ld, msg);
	     entry != NULL; entry = ldap_next_entry(ld, entry)) {
	    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
		fprintf(stdout, "DN: %s\n", dn);
		ldap_memfree(dn);
	    }

	}
	free(filter);

	return 0;
    } else {

	entry = ldap_first_entry(ld, msg);
	if (entry == NULL) {
	    fprintf(stderr, "account %s not matched to any DN\n",
		    auth.pxacct);
	    return 1;
	}
	if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	    if (accttype == NULL)
		accttype = "Your account";
	    fprintf(stderr, "%s matched DN: %s\n\n", accttype, dn);
	    if (auth.ldif != NULL) {
		fp = fopen(auth.ldif, "w");
		file_chkerr(fp);
		fprintf(fp, "# ------ uxdstools LDIF export -------\n");
		fprintf(fp, "# %s Account: %s\n", accttype, auth.pxacct);
		fprintf(fp, "dn: %s\n", dn);
		fclose(fp);
	    }
	    ldap_memfree(dn);
	    if (auth.acct == SELF) {
		free(filter);

		return 0;
	    }
	}
    }
    /* loop through account attributes and print values */
    fprintf(stdout, "------- %s Report: %s -------\n", accttype,
	    auth.pxacct);
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL;
	 attr = ldap_next_attribute(ld, entry, ber)) {
	if ((vals = ldap_get_values_len(ld, entry, attr)) != NULL) {
	    for (i = 0; vals[i] != NULL; i++) {
		if (auth.ldif == NULL) {
		    if (strstr(attr, "objectClass") == 0) {
			fprintf(stdout, "%s: %s\n", attr, vals[i]->bv_val);
		    }
		} else {
#ifdef HAVE_LDAP_SASL_GSSAPI
		    if (strcmp(attr, "krb5Key") == 0)
			vals[i]->bv_val =
			    base64(vals[i]->bv_val,
				   strlen(vals[i]->bv_val));
#endif				/* HAVE_LDAP_SASL_GSSAPI */
		    fprintf(stdout, "%s: %s\n", attr, vals[i]->bv_val);
		    fp = fopen(auth.ldif, "a");
		    fprintf(fp, "%s: %s\n", attr, vals[i]->bv_val);
		    fclose(fp);
		}
	    }
	    ldap_value_free_len(vals);
	}
	ldap_memfree(attr);
    }
    if (ber != NULL) {
	ber_free(ber, 0);
    }
    ldap_msgfree(msg);
    free(filter);

    return 0;
}

int uxds_acct_add(uxds_acct_t pxtype, struct mod_data mdata, LDAP * ld)
{
    BerElement *ber;
    LDAPMessage *msg;
    LDAPMessage *entry;

    static authzdata auth;

    int i;
    int a;
    char *cbuf = NULL;
    char *attr = NULL;
    char **mems = NULL;
    char *filter = NULL;
    char *dn = NULL;
    char *role = NULL;
    char *user_dn = NULL;
    char *group_dn = NULL;
    char *_g_cn[] = { mdata.group, NULL };
    char *_description[] = { mdata.comment, NULL };
    char *G_objectclass[] = { "top",
	"posixGroup",
	NULL
    };

    char *mask[] = { "uidNumber", "gidNumber", NULL };
    if (pxtype == USER) {
	if (mdata.group == NULL) {
	    fprintf(stderr,
		    "No POSIX GROUP (-G <group>) selected for USER ADD, Exiting...\n");
	    exit(EXIT_FAILURE);
	}
	if (mdata.uidnum != NULL) {
	    goto idpassed;
	} else {
	    filter = UIDNUM;
	}
    } else if (pxtype == GROUP) {
	if (mdata.gidnum != NULL) {
	    goto idpassed;
	} else {
	    filter = GIDNUM;
	}
    }
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, mask, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    /* get next available uid or gid */
    for (entry = ldap_first_entry(ld, msg);
	 entry != NULL; entry = ldap_next_entry(ld, entry)) {
	if (pxtype == USER) {
	    if (ldap_sort_entries(ld, &entry, "uidNumber", strcmp))
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    if (auth.debug) {
		fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	    }
	} else if (pxtype == GROUP) {
	    if (ldap_sort_entries(ld, &entry, "gidNumber", strcmp))
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    if (auth.debug) {
		fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	    }
	}
	for (attr = ldap_first_attribute(ld, entry, &ber);
	     attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
	    if (pxtype == USER) {
		if ((strstr(attr, "uid") != 0)) {
		    vals = ldap_get_values_len(ld, entry, attr);
		    mdata.uidnum = strdup(vals[0]->bv_val);
		    a = atoi(mdata.uidnum) + 1;
		    snprintf(mdata.uidnum, 6, "%d", a);
		    ldap_value_free_len(vals);
		}
	    } else if (pxtype == GROUP) {
		vals = ldap_get_values_len(ld, entry, attr);
		mdata.gidnum = strdup(vals[0]->bv_val);
		a = atoi(mdata.gidnum) + 1;
		snprintf(mdata.gidnum, 6, "%d", a);
		ldap_value_free_len(vals);
	    }
	    ldap_memfree(attr);
	}
    }

  idpassed:;

    a = 0;
    char *_g_gidnumber[] = { mdata.gidnum, NULL };
    /* GROUP conditional jump */
    if (pxtype == GROUP) {
	if (mdata.member == NULL) {
	    a = 5;
	} else {
	    a = 6;
	}
	goto groupstart;
    }

    /* for USER only */
    filter = center(cbuf, center(cbuf, POSIXGROUP, mdata.group), "))");
    //center_free(cbuf);
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg)
	!= LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
	fprintf(stderr, "Group name %s not matched to any DN\n",
		mdata.group);
	return 1;
    }
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "POSIX Group matched DN: %s\n\n", dn);
	user_dn =
	    strdup(center
		   (cbuf,
		    center(cbuf, center(cbuf, "uid=", mdata.user), ","),
		    dn));
	group_dn = strdup(dn);
	center_free(cbuf);
	ldap_memfree(dn);
    }
    vals = ldap_get_values_len(ld, entry, "description");
    if (vals[0]->bv_val != NULL) {
	if (auth.debug)
	    fprintf(stderr, "%s : role, len %lu\n", vals[0]->bv_val,
		    strlen(vals[0]->bv_val));
	role = strdup(vals[0]->bv_val);
    }
    ldap_value_free_len(vals);

    vals = ldap_get_values_len(ld, entry, "gidNumber");
    char *gidnum = NULL;
    if (vals[0]->bv_val != NULL) {
	if (auth.debug)
	    fprintf(stderr, "%s : gidNumber, len %lu\n", vals[0]->bv_val,
		    strlen(vals[0]->bv_val));
	gidnum = strdup(vals[0]->bv_val);
    }
    ldap_value_free_len(vals);
/*
    if (ber != NULL) {
	ber_free(ber, 0);
    }
*/
    ldap_msgfree(msg);

    if (mdata.homes == NULL) {
	mdata.homes = strdup(center(cbuf, "/home/", mdata.user));
    }
    if (mdata.shell == NULL) {
	mdata.shell = strdup("/bin/bash");
    }
    center_free(cbuf);
    char *mbx = strdup(center(cbuf, mdata.user, AT_EMAIL));
    center_free(cbuf);
#ifdef HDB_LDAP
    char *principal = strdup(center(cbuf, mdata.user, AT_REALM));
    center_free(cbuf);
    char *userpwd = strdup(center(cbuf, "{K5KEY}", principal));
    center_free(cbuf);
#endif				/* HDB_LDAP */
    char *ge_cos = strdup(center(cbuf,
				 center(cbuf,
					center(cbuf,
					       center(cbuf,
						      mdata.firstname,
						      " "),
					       mdata.lastname), ";"),
				 role));
    char *_homedirectory[] = { mdata.homes, NULL };
    char *_gecos[] = { ge_cos, NULL };
    char *_u_cn[] = { mdata.user, NULL };
    char *_givenname[] = { mdata.firstname, NULL };
    char *_sn[] = { mdata.lastname, NULL };
    char *_mail[] = { mbx, NULL };
    char *_uid[] = { mdata.user, NULL };
    char *_carlicense[] = { "XxXxXxXxXxXxXxXxX", NULL };
    char *_loginshell[] = { mdata.shell, NULL };
    char *_uidnumber[] = { mdata.uidnum, NULL };
    char *_u_gidnumber[] = { gidnum, NULL };
#ifdef QMAIL
    char *host;
    char *addr;
    if (mdata.mhost != NULL) {
	host = strdup(mdata.mhost);
    } else {
	host = "mailhost.com";
    }
    if (mdata.altaddr != NULL) {
	addr = strdup(mdata.altaddr);
    } else {
	addr = strdup(mbx);
    }
    char *_accountstatus[] = { "active", NULL };
    char *_mailhost[] = { host, NULL };
    char *_mailalternateaddress[] = { addr, NULL };
    char *_mailmessagestore[] =
	{ center(cbuf, "/var/qmail/maildirs/", mdata.user), NULL };
#endif				/* QMAIL */
#ifdef SSH_LPK
    char *_sshpublickey[] = { "0", NULL };
#endif				/* SSH_LPK */
#ifdef HDB_LDAP
    char *_krb5principalname[] = { principal, NULL };
    char *_userpassword[] = { userpwd, NULL };
    char *_krb5passwordend[] = { "20071231235959Z", NULL };
    char *_krb5keyversionnumber[] = { "0", NULL };
    char *_krb5maxlife[] = { "86400", NULL };
    char *_krb5maxrenew[] = { "604800", NULL };
    char *_krb5kdcflags[] = { "126", NULL };
    char *_krb5key[] = { "0", NULL };
#else
    char *_userpassword[] = { "DUMMYIKNOWWILLCEECHANGED", NULL };
#endif				/* HDB_LDAP */
    char *U_objectclass[] = { "top",
	"person",
	"inetOrgPerson",
	"organizationalPerson",
	"posixAccount",
	"shadowAccount",
#ifdef PPOLICY
	"pwdPolicy",
#endif				/* PPOLICY */
#ifdef QMAIL
	"qmailUser",
#endif				/* QMAIL */
#ifdef HDB_LDAP
	"krb5Principal",
	"krb5KDCEntry",
#endif				/* HDB_LDAP */
#ifdef SSH_LPK
	"ldapPublicKey",
#endif				/* SSH_LPK */
	"simpleSecurityObject",
	NULL
    };

  groupstart:
    if (pxtype == USER) {
	int n;
	n = 13;
	int modc = n;
#ifdef HDB_LDAP
	n = n + 7;
#endif				/* HDB_LDAP */
#ifdef QMAIL
	n = n + 5;
#endif				/* QMAIL */
#ifdef SSH_LPK
	n = n + 1;
#endif				/* SSH_LPK */
	n = n + 1;

	LDAPMod **useradd;
	useradd = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
	for (i = 0; i < n; i++) {
	    useradd[i] = (LDAPMod *) calloc(1, sizeof(LDAPMod));
	    useradd[i]->mod_op = LDAP_MOD_ADD;
	    if (useradd[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "malloc ERROR!\n");
		exit(ENOMEM);
	    }
	}
	useradd[0]->mod_type = "objectClass";
	useradd[0]->mod_values = U_objectclass;
	useradd[1]->mod_type = "cn";
	useradd[1]->mod_values = _u_cn;
	useradd[2]->mod_type = "sn";
	useradd[2]->mod_values = _sn;
	useradd[3]->mod_type = "givenName";
	useradd[3]->mod_values = _givenname;
	useradd[4]->mod_type = "uid";
	useradd[4]->mod_values = _uid;
	useradd[5]->mod_type = "mail";
	useradd[5]->mod_values = _mail;
	useradd[6]->mod_type = "gecos";
	useradd[6]->mod_values = _gecos;
	useradd[7]->mod_type = "uidNumber";
	useradd[7]->mod_values = _uidnumber;
	useradd[8]->mod_type = "gidNumber";
	useradd[8]->mod_values = _u_gidnumber;
	useradd[9]->mod_type = "homeDirectory";
	useradd[9]->mod_values = _homedirectory;
	useradd[10]->mod_type = "loginShell";
	useradd[10]->mod_values = _loginshell;
	useradd[11]->mod_type = "userPassword";
	useradd[11]->mod_values = _userpassword;
	useradd[12]->mod_type = "carLicense";
	useradd[12]->mod_values = _carlicense;
#ifdef QMAIL
	useradd[modc]->mod_type = "accountStatus";
	useradd[modc]->mod_values = _accountstatus;
	modc++;
	useradd[modc]->mod_type = "mailHost";
	useradd[modc]->mod_values = _mailhost;
	modc++;
	useradd[modc]->mod_type = "mailMessageStore";
	useradd[modc]->mod_values = _mailmessagestore;
	modc++;
	useradd[modc]->mod_type = "mailLocalAddress";
	useradd[modc]->mod_values = _mail;
	modc++;
	useradd[modc]->mod_type = "mailAlternateAddress";
	useradd[modc]->mod_values = _mailalternateaddress;
	modc++;
#endif				/* QMAIL */
#ifdef HDB_LDAP
	useradd[modc]->mod_type = "krb5PrincipalName";
	useradd[modc]->mod_values = _krb5principalname;
	modc++;
	useradd[modc]->mod_type = "krb5MaxLife";
	useradd[modc]->mod_values = _krb5maxlife;
	modc++;
	useradd[modc]->mod_type = "krb5MaxRenew";
	useradd[modc]->mod_values = _krb5maxrenew;
	modc++;
	useradd[modc]->mod_type = "krb5KDCFlags";
	useradd[modc]->mod_values = _krb5kdcflags;
	modc++;
	useradd[modc]->mod_type = "krb5KeyVersionNumber";
	useradd[modc]->mod_values = _krb5keyversionnumber;
	modc++;
	useradd[modc]->mod_type = "krb5PasswordEnd";
	useradd[modc]->mod_values = _krb5passwordend;
	modc++;
	useradd[modc]->mod_type = "krb5Key";
	useradd[modc]->mod_values = _krb5key;
	modc++;
#endif				/* HDB_LDAP */
#ifdef SSH_LPK
	useradd[modc]->mod_type = "sshPublicKey";
	useradd[modc]->mod_values = _sshpublickey;
	modc++;
#endif				/* SSH_LPK */
	useradd[modc] = NULL;

	if (auth.debug)
	    fprintf(stderr, "user=%s, group=%s, uid=%s, gecos=%s\n",
		    mdata.user, mdata.group, mdata.uidnum, ge_cos);

	if (ldap_add_ext_s(ld, user_dn, useradd, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stderr, "Attempted DN: %s, len %lu\n", user_dn,
		    strlen(user_dn));
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
#ifdef TOOL_LOG
	    log_event(user_dn, USER, ADD, "FAILED");
#endif				/* TOOL_LOG */
	    return 1;
	}
	fprintf(stdout, "POSIX User Account import of %s SUCCESSFUL.\n",
		mdata.user);
	fprintf(stdout, "Added DN: %s\n", user_dn);
#ifdef TOOL_LOG
	log_event(user_dn, USER, ADD, "SUCCESSFUL - IMPORTED");
#endif				/* TOOL_LOG */
	if ((uxds_grp_mem(auth.debug, ADD, mdata.user, group_dn, ld)) != 0) {
	    fprintf(stderr, "adding memberUid FAILED\n");
	}
#ifdef HAVE_LDAP_SASL_GSSAPI
	if ((mdata.cpw == 1) || (mdata.setpass != NULL)) {
	    char *name = get_krbname(auth, FALSE);
	    putenv(center(cbuf, "KRB5CCNAME=/tmp/kacache_", name));
	    if (mdata.cpw == 1) {
		if (setpwd(mdata.user, randstr()) != 0) {
		    fprintf(stderr, "Password NOT set");
		}
		if (mdata.exp == 1) {
		    if ((uxds_user_expire(0, user_dn, ld)) != 0) {
			fprintf(stderr, "Password not EXPIRED for %s\n",
				mdata.user);
		    }

		}
	    } else if (mdata.setpass != NULL) {
		if (setpwd(mdata.user, mdata.setpass) != 0) {
		    fprintf(stderr, "Password NOT set\n");
		}
	    }
	}
#ifdef PTS
	if (pts_wrap(PTSCRT, mdata.user, MY_CELL, mdata.uidnum)
	    != 0) {
	    fprintf(stderr, "ERROR: User %s not created in pts database\n",
		    mdata.user);
	}
#if 0
	if (strcmp(mdata.group, "sysops") == 0) {
	    char *ptsgrp = "system:administrators";
	    if (pts_wrap(PTSGRP, mdata.user, MY_CELL, ptsgrp) != 0) {
		fprintf(stderr, "ERROR: User %s not added to pts admins",
			mdata.user);
	    }
	}
#endif
#endif				/* PTS */
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	free(filter);

	return 0;
    }
    if (pxtype == GROUP) {
	i = 0;
	if (a == 6) {
	    mems = calloc(1, strlen(mdata.member) + 1);
	    mems[i] = strtok(mdata.member, ",");
	    i++;
	    while ((mems[i] = strtok(NULL, ",")) != NULL) {
		i++;
	    }
	    mems[i] = NULL;
	}

	LDAPMod **groupadd;

	groupadd = (LDAPMod **) calloc(a, sizeof(LDAPMod *));
	for (i = 0; i < a; i++) {
	    groupadd[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    groupadd[i]->mod_op = LDAP_MOD_ADD;
	    if (groupadd[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "malloc ERROR!\n");
		exit(ENOMEM);
	    }
	}

	groupadd[0]->mod_type = "objectClass";
	groupadd[0]->mod_values = G_objectclass;
	groupadd[1]->mod_type = "cn";
	groupadd[1]->mod_values = _g_cn;
	groupadd[2]->mod_type = "gidNumber";
	groupadd[2]->mod_values = _g_gidnumber;
	groupadd[3]->mod_type = "description";
	groupadd[3]->mod_values = _description;
	if (a == 6) {
	    groupadd[4]->mod_type = "memberUid";
	    groupadd[4]->mod_values = mems;
	    groupadd[5] = NULL;
	} else {
	    groupadd[4] = NULL;
	}
	if (auth.basedn == NULL) {
	    auth.basedn = strdup(UXDS_POSIX_OU);
	}
	group_dn =
	    center(cbuf,
		   center(cbuf, center(cbuf, "cn=", mdata.group), ","),
		   auth.basedn);
	center_free(cbuf);
	if (auth.debug)
	    fprintf(stderr,
		    "group=%s, gid=%s, descr=%s, memberuid(s)=%s\n",
		    mdata.group, mdata.gidnum, mdata.comment,
		    mdata.member);
	if (ldap_add_ext_s(ld, group_dn, groupadd, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stdout, "Attempted DN: %s\n", group_dn);
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
#ifdef TOOL_LOG
	    log_event(group_dn, GROUP, ADD, "FAILED");
#endif				/* TOOL_LOG */
	    return 1;
	}
	fprintf(stdout, "POSIX Group Account import of %s SUCCESSFUL.\n",
		mdata.group);
	fprintf(stdout, "Added DN: %s\n", group_dn);
#ifdef TOOL_LOG
	log_event(group_dn, GROUP, ADD, "SUCCESSFUL - IMPORTED");
#endif				/* TOOL_LOG */

    }

    return 0;
}

int uxds_acct_del(uxds_acct_t pxtype, struct mod_data mdata, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    static authzdata auth;

    char *dn;
    char *filter = NULL;
    char *fbuf = NULL;
    char *acct_type = NULL;

    switch (pxtype) {
    case USER:
	acct_type = "POSIX User";
	filter =
	    center(fbuf, center(fbuf, POSIXACCOUNT, mdata.user), "))");
	break;
    case GROUP:
	acct_type = "POSIX Group";
	filter = center(fbuf, center(fbuf, POSIXGROUP, mdata.group), "))");
	break;
    default:
	break;
    }
    if (auth.debug)
	fprintf(stderr, "search filter used: %s, len %lu\n", filter,
		strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
	fprintf(stderr, "Account name not matched to any DN\n");
	return 1;
    }
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "%s matched DN: %s\n\n", acct_type, dn);
	if (pxtype == USER) {
	    mdata.member = strdup(dn);
	    if (mdata.user != NULL) {
		fprintf(stderr, "Deleting %s account - %s....\n",
			acct_type, mdata.user);
	    }
	} else if (pxtype == GROUP) {
	    if (mdata.group != NULL) {
		fprintf(stderr, "Deleting %s account - %s....\n",
			acct_type, mdata.group);
	    }
	}
    }
    if (ldap_delete_ext_s(ld, dn, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "POSIX Account deletion UNSUCCESSFUL.\n");
#ifdef TOOL_LOG
	log_event(dn, pxtype, DEL, "FAILED");
#endif				/* TOOL_LOG */

	exit(EXIT_FAILURE);
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
    }
#ifdef TOOL_LOG
    log_event(dn, pxtype, DEL, "SUCCESSFUL - DELETED");
#endif				/* TOOL_LOG */
    if (pxtype == USER) {
	mdata.member = strstr(mdata.member, "cn=");
	if ((uxds_grp_mem(auth.debug, DEL, mdata.user, mdata.member, ld))
	    != 0) {
	    fprintf(stderr, "deleting memberUid FAILED\n");
	}
#ifdef PTS
	if (pts_wrap(PTSDEL, mdata.user, MY_CELL) != 0) {
	    fprintf(stderr,
		    "ERROR: User %s not deleted from pts database\n",
		    mdata.user);
	}
#endif				/* PTS */
    }
    fprintf(stderr, "POSIX Account DELETED.\n");
    free(filter);

    return 0;
}

int uxds_acct_mod(uxds_acct_t pxtype, struct mod_data mdata, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    static authzdata auth;

    int i;
    int a = 0;
    int modc;
    char *cbuf = NULL;
    char *dn = NULL;
    char *role = NULL;
    char *mod_dn = NULL;
    char *old_gecos = NULL;
    char *xgecos = NULL;
    char *ge_cos = NULL;
    char *_g_gidnumber[] = { mdata.gidnum, NULL };
    char *_description[] = { mdata.comment, NULL };
    char *fbuf = NULL;
    char *filter = NULL;
    char *acct_type = NULL;
    if (mdata.modrdn == 1) {
	pxtype = GROUP;
    }
    switch (pxtype) {
    case USER:
	acct_type = "POSIX User";
	filter =
	    center(fbuf, center(fbuf, POSIXACCOUNT, mdata.user), "))");
	break;
    case GROUP:
	acct_type = "POSIX Group";
	filter = center(fbuf, center(fbuf, POSIXGROUP, mdata.group), "))");
	break;
    default:
	break;
    }
    center_free(fbuf);
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
	fprintf(stderr, "Using %s filter matched no DN.\n", filter);
	return 1;
    }
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "%s matched DN: %s\n\n", acct_type, dn);
	mod_dn = strdup(dn);
	if (auth.debug)
	    printf("using dn:%s\n", mod_dn);
	ldap_memfree(dn);
    }
    if (mdata.modrdn == 1) {
	vals = ldap_get_values_len(ld, entry, "gidNumber");
	mdata.gidnum = strdup(vals[0]->bv_val);
	ldap_value_free_len(vals);
	vals = ldap_get_values_len(ld, entry, "description");
	mdata.comment = strdup(vals[0]->bv_val);
	ldap_value_free_len(vals);
	goto modrdn;
    }
    if (pxtype == GROUP) {
	if (mdata.member != NULL) {
	    a = 6;
	} else {
	    a = 5;
	}
	goto groupstart;
    }
    if ((mdata.firstname == NULL) && (mdata.lastname == NULL)) {
	goto gecosnull;
    }
    if (mdata.firstname == NULL) {
	vals = ldap_get_values_len(ld, entry, "givenName");
	if (vals[0]->bv_val != NULL) {
	    if (auth.debug)
		fprintf(stderr, "%s : first name, len %lu\n",
			vals[0]->bv_val, strlen(vals[0]->bv_val));
	    mdata.firstname = strdup(vals[0]->bv_val);
	    ldap_value_free_len(vals);
	}
    }
    if (mdata.lastname == NULL) {
	vals = ldap_get_values_len(ld, entry, "sn");
	if (vals[0]->bv_val != NULL) {
	    if (auth.debug)
		fprintf(stderr, "%s : sn, len %lu\n", vals[0]->bv_val,
			strlen(vals[0]->bv_val));
	    mdata.lastname = strdup(vals[0]->bv_val);
	    ldap_value_free_len(vals);
	}
    }
    vals = ldap_get_values_len(ld, entry, "gecos");
    if (vals[0]->bv_val != NULL) {
	if (auth.debug)
	    fprintf(stderr, "%s : gecos, len %lu\n", vals[0]->bv_val,
		    strlen(vals[0]->bv_val));
	old_gecos = strdup(vals[0]->bv_val);
    }
    ldap_value_free_len(vals);
    ldap_msgfree(msg);
    xgecos = strdup(old_gecos);
    role = strtok(xgecos, ";");
    role = strtok(NULL, ";");
    ge_cos =
	center(cbuf,
	       center(cbuf,
		      center(cbuf, center(cbuf, mdata.lastname, ","),
			     mdata.firstname), ";"), role);
    center_free(cbuf);
    if (auth.debug)
	fprintf(stderr, "gecos is now : %s\n", ge_cos);
  gecosnull:;
    char *_homedirectory[] = { mdata.homes, NULL };
    char *_gecos[] = { ge_cos, NULL };
    char *_givenname[] = { mdata.firstname, NULL };
    char *_sn[] = { mdata.lastname, NULL };
    char *_loginshell[] = { mdata.shell, NULL };
    char *_uidnumber[] = { mdata.uidnum, NULL };
    char *_u_gidnumber[] = { mdata.gidnum, NULL };
#ifdef QMAIL
    char *host = NULL;
    char *addr = NULL;
    if (mdata.mhost != NULL) {
	host = strdup(mdata.mhost);
    }
    if (mdata.altaddr != NULL) {
	addr = strdup(mdata.altaddr);
    }
    char *_mailhost[] = { host, NULL };
    char *_mailalternateaddress[] = { addr, NULL };
#endif				/* QMAIL */

  groupstart:
    if (pxtype == USER) {
	int n = mdata._entry + 4;

	LDAPMod **usermod;

	usermod = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
	for (i = 0; i < n; i++) {
	    usermod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    usermod[i]->mod_op = LDAP_MOD_REPLACE;
	    if (usermod[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "malloc ERROR!\n");
		exit(ENOMEM);
	    }
	}
	modc = 0;
	if (_sn[0] != NULL) {
	    usermod[modc]->mod_type = "sn";
	    usermod[modc]->mod_values = _sn;
	    modc++;
	}
	if (_givenname[0] != NULL) {
	    usermod[modc]->mod_type = "givenName";
	    usermod[modc]->mod_values = _givenname;
	    modc++;
	}
	if (_gecos[0] != NULL) {
	    usermod[modc]->mod_type = "gecos";
	    usermod[modc]->mod_values = _gecos;
	    modc++;
	}
	if (_uidnumber[0] != NULL) {
	    usermod[modc]->mod_type = "uidNumber";
	    usermod[modc]->mod_values = _uidnumber;
	    modc++;
	}
	if (_u_gidnumber[0] != NULL) {
	    usermod[modc]->mod_type = "gidNumber";
	    usermod[modc]->mod_values = _u_gidnumber;
	    modc++;
	}
	if (_homedirectory[0] != NULL) {
	    usermod[modc]->mod_type = "homeDirectory";
	    usermod[modc]->mod_values = _homedirectory;
	    modc++;
	}
	if (_loginshell[0] != NULL) {
	    usermod[modc]->mod_type = "loginShell";
	    usermod[modc]->mod_values = _loginshell;
	    modc++;
	}
#ifdef QMAIL
	if (_mailhost[0] != NULL) {
	    usermod[modc]->mod_type = "mailHost";
	    usermod[modc]->mod_values = _mailhost;
	    modc++;
	}
	if (_mailalternateaddress[0] != NULL) {
	    usermod[modc]->mod_type = "mailAlternateAddress";
	    usermod[modc]->mod_values = _mailalternateaddress;
	    modc++;
	}
#endif				/* QMAIL */
	if (modc > 0) {
	    usermod[modc] = NULL;
	}
#ifdef HAVE_LDAP_SASL_GSSAPI
	else if ((mdata.cpw == 1) || (mdata.exp == 1)) {
	    goto skipmod;
	}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	else {
	    fprintf(stderr,
		    "FATAL ERROR.... no attributes came through for modification!\n");
	    return 1;
	}
	if (ldap_modify_ext_s(ld, mod_dn, usermod, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stdout, "Attempted DN: %s, len %lu\n", mod_dn,
		    strlen(mod_dn));
#ifdef TOOL_LOG
	    log_event(mod_dn, USER, MOD, "FAILED");
#endif				/* TOOL_LOG */
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	    return 1;
	}
	fprintf(stdout,
		"POSIX User Account Modification of %s SUCCESSFUL.\n",
		mdata.user);
	fprintf(stdout, "Modified DN: %s\n", mod_dn);
#ifdef HAVE_LDAP_SASL_GSSAPI
      skipmod:;
	if (mdata.cpw == 1) {
	    char *name = get_krbname(auth, FALSE);
	    putenv(center(cbuf, "KRB5CCNAME=/tmp/kacache_", name));
	    if (setpwd(mdata.user, randstr()) != 0) {
		fprintf(stderr, "Password not set for %s\n", mdata.user);
	    }
	}

	if (mdata.exp == 1) {
	    if ((uxds_user_expire(0, mod_dn, ld)) != 0) {
		fprintf(stderr, "Password not EXPIRED for %s\n",
			mdata.user);
	    }
	    fprintf(stdout, "Password for %s EXPIRED to 12-31-1999\n",
		    mdata.user);
	}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#ifdef TOOL_LOG
	log_event(mod_dn, USER, MOD, "SUCCESSFUL");
#endif				/* TOOL_LOG */

	return 0;
    }
    if (pxtype == GROUP) {
	char **mems = NULL;
	i = 0;
	if (a == 6) {
	    mems = calloc(1, strlen(mdata.member) + 1);
	    mems[i] = strtok(mdata.member, ",");
	    i++;
	    while ((mems[i] = strtok(NULL, ",")) != NULL) {
		i++;
	    }
	    mems[i] = NULL;
	}

	int n = mdata._entry + 2;

	LDAPMod **groupmod;

	groupmod = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
	for (i = 0; i < n; i++) {
	    groupmod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    groupmod[i]->mod_op = LDAP_MOD_REPLACE;
	    if (groupmod[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "malloc ERROR!\n");
		exit(ENOMEM);
	    }
	}
	modc = 0;
	if (_g_gidnumber[0] != NULL) {
	    groupmod[modc]->mod_type = "gidNumber";
	    groupmod[modc]->mod_values = _g_gidnumber;
	    modc++;
	}
	if (_description[0] != NULL) {
	    groupmod[modc]->mod_type = "description";
	    groupmod[modc]->mod_values = _description;
	    modc++;
	}
	if (a == 6) {
	    if (mems[0] != NULL) {
		if (mdata.membit == 0) {
		    groupmod[modc]->mod_op = LDAP_MOD_ADD;
		} else if (mdata.membit == 1) {
		    groupmod[modc]->mod_op = LDAP_MOD_DELETE;
		}
	    }
	    groupmod[modc]->mod_type = "memberUid";
	    groupmod[modc]->mod_values = mems;
	    modc++;
	}
	if (modc > 0) {
	    groupmod[modc] = NULL;
	} else {
	    fprintf(stderr,
		    "FATAL ERROR.... no attributes came through for modification!\n");
	    return 1;
	}
	if (auth.debug) {
	    fprintf(stderr, "group = %s\n", mdata.group);
	    fprintf(stderr, "groupDN = %s\n", mod_dn);
	}
	center_free(cbuf);
	if (ldap_modify_ext_s(ld, mod_dn, groupmod, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stdout, "Attempted DN: %s\n", mod_dn);
#ifdef TOOL_LOG
	    log_event(mod_dn, GROUP, MOD, "FAILED");
#endif				/* TOOL_LOG */
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	    return 1;
	}
	fprintf(stdout,
		"POSIX Group Account Modification of %s SUCCESSFUL.\n",
		mdata.group);
	fprintf(stdout, "Modified DN: %s\n", mod_dn);
#ifdef TOOL_LOG
	log_event(mod_dn, GROUP, MOD, "SUCCESSFUL");
#endif				/* TOOL_LOG */

	return 0;
    }
    /* MODRDN operation for POSIX user primary group change */
  modrdn:;
    char *old_dn = NULL;
    filter = center(fbuf, center(fbuf, POSIXACCOUNT, mdata.user), "))");
    center_free(fbuf);
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
	fprintf(stderr, "Using %s filter matched no DN.\n", filter);
	return 1;
    }
    /* get out present DN */
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	if (auth.debug)
	    fprintf(stderr, "Matched DN: %s\n\n", dn);
	old_dn = strdup(dn);
	if (auth.debug)
	    fprintf(stderr, "MODRDN using old DN:%s\n", old_dn);
	ldap_memfree(dn);
    }
    vals = ldap_get_values_len(ld, entry, "gecos");
    char *gcos =
	center(cbuf, center(cbuf, strtok(vals[0]->bv_val, ";"), ";"),
	       mdata.comment);
    ldap_value_free_len(vals);
    fprintf(stderr, "MODRDN to new parent DN: %s\n", mod_dn);
    char *new_rdn = center(fbuf, "uid=", mdata.user);
    center_free(fbuf);
    /* do it */
    if (ldap_rename_s(ld, old_dn, new_rdn, mod_dn, 1, NULL, NULL) != 0) {
#ifdef TOOL_LOG
	log_event(new_rdn, USER, MOD, "MODRDN FAILED");
#endif				/* TOOL_LOG */
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
    }
    /* delete memberUid from old posixGroup and add it to new */
    old_dn = strstr(old_dn, "cn=");
    if ((uxds_grp_mem(auth.debug, DEL, mdata.user, old_dn, ld)) != 0) {
	fprintf(stderr, "deleting memberUid FAILED\n");
    }
    if ((uxds_grp_mem(auth.debug, ADD, mdata.user, mod_dn, ld)) != 0) {
	fprintf(stderr, "adding memberUid FAILED\n");
    }
    /* change gidNumber & gecos for user */
    char *_gidN[] = { mdata.gidnum, NULL };
    char *_gcos[] = { gcos, NULL };

    LDAPMod **gidmod;

    gidmod = (LDAPMod **) calloc(3, sizeof(LDAPMod *));
    gidmod[0] = (LDAPMod *) malloc(sizeof(LDAPMod));
    gidmod[1] = (LDAPMod *) malloc(sizeof(LDAPMod));

    gidmod[0]->mod_op = LDAP_MOD_REPLACE;
    gidmod[0]->mod_type = "gidNumber";
    gidmod[0]->mod_values = _gidN;
    gidmod[1]->mod_op = LDAP_MOD_REPLACE;
    gidmod[1]->mod_type = "gecos";
    gidmod[1]->mod_values = _gcos;
    gidmod[2] = NULL;

    mod_dn = center(fbuf, center(fbuf, new_rdn, ","), mod_dn);
    center_free(fbuf);
    if (auth.debug)
	fprintf(stderr, "%s -> new dn\n", mod_dn);
    if (ldap_modify_ext_s(ld, mod_dn, gidmod, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    fprintf(stdout,
	    "POSIX User Account %s PRIMARY GROUP CHANGE to %s SUCCESSFUL.\n",
	    mdata.user, mdata.group);
#ifdef TOOL_LOG
    log_event(new_rdn, USER, MOD,
	      center(cbuf, mdata.group,
		     " is POSIX GROUP - MODRDN SUCCESSFUL"));
    center_free(cbuf);
#endif				/* TOOL_LOG */

    return 0;
}

int uxds_grp_mem(int debug, uxds_tool_t op, char *user, char *grpdn, LDAP * ld)
{
    int mtype;
    char *oper;
    char *cbuf = NULL;
    switch (op) {
    case ADD:
	mtype = 0;
	oper = "ADD";
	break;
    case DEL:
	mtype = 1;
	oper = "DELETE";
	break;
    default:
	fprintf(stdout, "REPLACE not implemented\n");
	return 1;
	break;
    }

    char *_memberuid[] = { user, NULL };

    LDAPMod **members;

    members = (LDAPMod **) calloc(2, sizeof(LDAPMod *));
    members[0] = (LDAPMod *) malloc(sizeof(LDAPMod));

    members[0]->mod_op = mtype;
    members[0]->mod_type = "memberUid";
    members[0]->mod_values = _memberuid;
    members[1] = NULL;

    if (ldap_modify_ext_s(ld, grpdn, members, NULL, NULL) != LDAP_SUCCESS) {
	if (debug)
	    fprintf(stdout, "Failed to %s memberUid %s using DN: %s\n",
		    oper, user, grpdn);
#ifdef TOOL_LOG
	log_event(grpdn, GROUP, MOD,
		  center(cbuf, oper, " of memberUid FAILED"));
#endif				/* TOOL_LOG */
	center_free(cbuf);
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    fprintf(stderr, "%s of memberUid %s using POSIX Group DN:\n%s\n",
	    oper, user, grpdn);
#ifdef TOOL_LOG
    log_event(grpdn, GROUP, MOD,
	      center(cbuf, oper, " of memberUid SUCCESSFUL"));
#endif				/* TOOL_LOG */
    center_free(cbuf);

    return 0;
}

/* expire password for four flavors */
int uxds_user_expire(int type, char *dn, LDAP * ld)
{
    enum { KRB5, PPLCY, SAMBA, AD };	/* pplcy/samba/ad future */

    int i, e;
    char *expiry = NULL;
    char *xattr = NULL;

    switch (type) {
    case KRB5:
	expiry = "krb5PasswordEnd";
	xattr = "19991231235959Z";
	break;
    case PPLCY:
	expiry = "pwdReset";
	xattr = "TRUE";
	break;
    case SAMBA:
	expiry = "sambaPwdMustChange";
	xattr = "946684799";	/* 12-31-1999 23:59:59 ZULU */
	break;
    case AD:
	expiry = "accountExpires";
	xattr = "000000100000";	/* M$ - it's a long time in the past */
	break;
    default:
	break;
    }
    e = 2;
    char *actual[] = { xattr, NULL };
#ifdef PPOLICY
    /* if ppolicy is enabled reset this too */
    if (type == KRB5) {
	xattr = NULL;
	xattr = "TRUE";
	e++;
    }
    char *pp[] = { xattr, NULL };
#endif				/* PPOLICY */

    LDAPMod **exp;

    exp = (LDAPMod **) calloc(e, sizeof(LDAPMod *));
    for (i = 0; i < e; i++) {
	exp[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
    }
    exp[0]->mod_op = LDAP_MOD_REPLACE;
    exp[0]->mod_type = expiry;
    exp[0]->mod_values = actual;
#ifdef PPOLICY
    if (e == 3) {
	exp[1]->mod_op = LDAP_MOD_REPLACE;
	exp[1]->mod_type = "pwdReset";
	exp[1]->mod_values = pp;
	exp[2] = NULL;
    } else {
	exp[1] = NULL;
    }
#else
    exp[1] = NULL;
#endif				/* PPOLICY */

    if (ldap_modify_ext_s(ld, dn, exp, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }

    return 0;
}

#ifdef PTS
/* wrapper for OpenAFS pts binary to create/delete accounts */
int pts_wrap(ptsflag flag, char *ptsname, char *cellname, ...)
{
    pid_t pid;
    int i;
    int status;
    va_list ap;
    char **pts_str;
    char *ptsgrp = NULL;
    char *idnum = NULL;

    /* fork off child pts exec proc */
    if ((pid = fork()) < 0) {
	fprintf(stderr, "ERROR: forking child pts process failed\n");
	return 1;
    } else if (pid == 0) {
	pts_str = (char **) calloc(9, sizeof(char *));
        for (i = 0; i < 9; i++) {
            pts_str[i] = (char *) malloc(sizeof(char));
            if (pts_str[i] == (char *) NULL) {
                fprintf(stderr, "malloc ERROR!\n");
                exit(ENOMEM);
            }
        }

	pts_str[0] = "pts";
	switch (flag) {
	case PTSCRT:
	    va_start(ap, cellname);
	    idnum = va_arg(ap, char *);
	    pts_str[1] = "createuser";
	    pts_str[2] = "-name";
	    pts_str[3] = ptsname;
	    pts_str[4] = "-cell";
	    pts_str[5] = cellname;
	    pts_str[6] = "-id";
	    pts_str[7] = idnum;
	    pts_str[8] = NULL;
	    va_end(ap);
	    break;
	case PTSGRP:
	    va_start(ap, cellname);
	    ptsgrp = va_arg(ap, char *);
	    pts_str[1] = "adduser";
	    pts_str[2] = ptsname;
	    pts_str[3] = ptsgrp;
	    pts_str[4] = "-cell";
	    pts_str[5] = cellname;
	    pts_str[6] = NULL;
	    va_end(ap);
	    break;
	case PTSDEL:
	    pts_str[1] = "delete";
	    pts_str[2] = ptsname;
	    pts_str[3] = "-cell";
	    pts_str[4] = cellname;
	    pts_str[5] = NULL;
	    break;
	default:
	    /*should never get here */
	    break;
	}
	/* do it */
	if (execv(PTS_BIN, pts_str) != 0) {
	    return 1;
	}
    } else {
	while (wait(&status) != pid);
    }
    for (i = 0; i != '\0'; i++) {
        free(pts_str[i]);
    }

    return 0;
}
#endif				/* PTS */
