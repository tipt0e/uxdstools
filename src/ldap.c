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
char *res = "ldap_err2string returned";
struct berval **vals;

int uxds_user_authz(int select, uxds_authz_t auth, LDAP * ld)
{
    int proto;
    int authmethod = 0;
#ifdef HAVE_LDAP_SASL
    char *sasl_mech = NULL;
    unsigned sasl_flags = 0;
#endif				/* HAVE_LDAP_SASL */

    if (auth.debug) {
	fprintf(stderr, "sflag value is %i -> ", select);
	fprintf(stderr,
		"(0 = SIMPLE, 1 = SASL non GSSAPI, 2 = SASL/GSSAPI)\n");
	fprintf(stderr, "LDAP host URI is: %s\n", auth.uri);
    }
#ifdef HAVE_LDAP_SASL
/* SASL authentication chosen */
    if ((select > 0) || (auth.pkcert)) {
	authmethod = LDAP_AUTH_SASL;
	sasl_mech = auth.saslmech;
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
	fprintf(stdout, "SUCCESSFUL bind using URI %s\n", auth.uri);
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
    return rc;
}

/* perform search operation and parse - based on account type argument */
int uxds_acct_parse(uxds_bind_t bind, uxds_authz_t auth, LDAP * ld)
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
    char *accttype = NULL;
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

    char *filter =
	(char *) calloc(1, (strlen(SUDOUSER) + strlen(auth.pxacct) + 1));
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
	switch (bind) {
	case SIMPLE:
	    base = strdup(auth.binddn);
	    filter = "uid=*";
	    if (auth.debug)
		fprintf(stderr, "search filter string: %s\n", filter);
	    break;
#ifdef HAVE_LDAP_SASL
	case SASL:
	    filter = center(fbuf, "uid=", auth.username);
	    if (auth.debug)
		fprintf(stderr, "search filter string: %s\n", filter);
	    break;
#ifdef HAVE_LDAP_SASL_GSSAPI
	case GSSAPI:
	    kuser = get_krbname(auth, FALSE);
	    if (auth.debug)
		fprintf(stderr,
			"user account filter half returned: %s, size %lu len %lu\n",
			kuser, sizeof(kuser), strlen(kuser));
	    filter = (center(fbuf, "uid=", kuser));
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
	/* XXX too lazy to use the macros */
	if (!snprintf
	    (filter, (strlen(POSIXACCOUNT) + strlen(auth.pxacct) + 1),
	     POSIXACCOUNT, auth.pxacct))
	    break;
	accttype = "POSIX User";
	break;
    case GROUP:
	if (!snprintf
	    (filter, (strlen(POSIXGROUP) + strlen(auth.pxacct) + 1),
	     POSIXGROUP, auth.pxacct))
	    break;
	accttype = "POSIX Group";
	break;
    case SUDOER:
	if (!snprintf
	    (filter, (strlen(SUDOUSER) + strlen(auth.pxacct) + 1),
	     SUDOUSER, auth.pxacct))
	    break;
	accttype = "SUDOer";
	break;
    default:
	fprintf(stderr, "FATAL: Bad LDAP search filter\n");
	return 1;
	break;
    }
    if (auth.debug)
	fprintf(stderr, "using '%s' as selected account\n", auth.pxacct);

    /* perform search */
    if (auth.debug)
	fprintf(stderr, "final passed filter: %s\n", filter);
    if (auth.ldif != NULL) {
	attr_mask[0] = NULL;
    }
    if (ldap_search_ext_s
	(ld, auth.basedn, LDAP_SCOPE_SUBTREE, filter, attr_mask, 0,
	 NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }

    free(filter);

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
	    fprintf(stderr, "%s matched DN: %s\n", accttype, dn);
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

    return 0;
}

int uxds_acct_add(uxds_acct_t pxtype, uxds_data_t mdata, LDAP * ld)
{
    BerElement *ber = NULL;
    LDAPMessage *msg = NULL;
    LDAPMessage *entry = NULL;

    static uxds_authz_t auth;
    struct posixid pxid;

    int i;
    int a;
    char *attr = NULL;
    char **mems = NULL;
    char *dn = NULL;
    char *role = NULL;
#ifdef QMAIL
    char *mbx = NULL;
    char *addr = NULL;
    char *host = NULL;
#endif				/* QMAIL */
    char *user_dn = NULL;
    char *group_dn = NULL;
    char *filter = NULL;
    char *mygecos = NULL;

    if (pxtype == USER) {
	if (mdata.group == NULL) {
	    fprintf(stderr,
		    "No POSIX GROUP (-G <group>) selected for USER ADD, Exiting...\n");
	    exit(EXIT_FAILURE);
	}
	if (mdata.uidnum == NULL) {
	    pxid =
		get_next_pxid(ld, msg, entry, attr, pxtype, ber,
			      auth.debug);
	    if (pxid.fail) {
		return 1;
	    } else {
		mdata.uidnum = pxid.uidnum;
	    }
	}
    } else if (pxtype == GROUP) {
	if (mdata.gidnum == NULL) {
	    pxid =
		get_next_pxid(ld, msg, entry, attr, pxtype, ber,
			      auth.debug);
	    if (pxid.fail) {
		return 1;
	    } else {
		mdata.gidnum = pxid.gidnum;
	    }
	}
    }

    filter = realloc(filter, (PG_LEN + 1));

    a = 0;
    /* XXX GROUP conditional jump */
    if (pxtype == GROUP) {
	goto groupstart;
    }

    /* for USER only */
    if (!snprintf(filter, PG_LEN, POSIXGROUP, mdata.group))
	return 1;
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg)
	!= LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }

    free(filter);

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
	fprintf(stderr, "POSIX Group matched DN: %s\n", dn);
	user_dn = realloc(user_dn, strlen(mdata.user) + strlen(dn) + 6);
	if (!snprintf(user_dn, strlen(mdata.user) + strlen(dn) + 6,
		      "uid=%s,%s", mdata.user, dn))
	    return 1;
	group_dn = strdup(dn);

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
    ldap_msgfree(msg);

    char *user_oc[] = {
	"top",
	"person",
	"inetOrgPerson",
	"organizationalPerson",
	"posixAccount",
        "shadowAccount",
#ifdef QMAIL
	"qmailUser",
#endif
#ifdef HDB_LDAP
	"krb5Principal",
	"krb5KDCEntry",
#endif				/* HDB_LDAP */
#ifdef SSH_LPK
	"ldapPublicKey",
#endif				/* SSH_LPK */
	NULL
    };

    if (mdata.homes == NULL) {
	mdata.homes = strdup(center(cbuf, "/home/", mdata.user));
    }
    if (mdata.shell == NULL) {
	mdata.shell = strdup("/bin/sh");
    }
    mygecos = realloc(mygecos, (GC_LEN + 3));
    if (!snprintf
	(mygecos, GC_LEN, MY_GECOS, mdata.firstname, mdata.lastname, role))
	return 1;
#ifdef QMAIL
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
#endif				/* QMAIL */

    char *principal = center(cbuf, mdata.user, AT_REALM);

    /*
     * because objectClass is already an array, we have to
     * put dummy values for user_attr[0] so we can start
     * from user_attr[1] when we fill up the LDAPMod struct
     */
    uxds_attr_t user_attr[] = {
	{USER, "dummy", "dummy"},	/* dummy values */
	{USER, "cn", mdata.user},
	{USER, "givenName", mdata.firstname},
	{USER, "sn", mdata.lastname},
	{USER, "uid", mdata.user},
	{USER, "mail", center(cbuf, mdata.user, AT_EMAIL)},
	{USER, "gecos", mygecos},
	{USER, "uidNumber", mdata.uidnum},
	{USER, "gidNumber", gidnum},
	{USER, "homeDirectory", mdata.homes},
	{USER, "loginShell", "/bin/sh"},
#ifdef HDB_LDAP
	{USER, "userPassword", center(cbuf, "{K5KEY}", principal)},
#else
	{USER, "userPassword", "DUMMYIKNOWWILLCEECHANGED"},
#endif				/* HDB_LDAP */
	{USER, "carLicense", "XxXxXxXxXxXxXxXxX"},
#ifdef QMAIL
	{USER, "accountStatus", "active"},
	{USER, "mailHost", host},
	{USER, "mailMessageStore", addr},
	{USER, "mailLocalAddress",
	 center(cbuf, "/var/qmail/maildirs/", mdata.user)},
	{USER, "mailAlternateAddress", addr},
#endif				/* QMAIL */
#ifdef HDB_LDAP
	{USER, "krb5PrincipalName", principal},
	{USER, "krb5MaxLife", "86400"},
	{USER, "krb5MaxRenew", "604800"},
	{USER, "krb5KDCFlags", "126"},
	{USER, "krb5KeyVersionNumber", "0"},
	{USER, "krb5PasswordEnd", "20071231235959Z"},
	{USER, "krb5Key", "0"},
#endif				/* HDB_LDAP */
#ifdef SSH_LPK
	{USER, "sshPublicKey", "0"},
#endif				/* SSH_LPK */
	{0, NULL, NULL}
    };

  groupstart:
    if (pxtype == USER) {
	i = 0;
	while (user_attr[i].attrib != NULL) {
	    i++;
	}
	int n;
	n = i + 1;

	LDAPMod **useradd;
	useradd = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
	useradd[0] = (LDAPMod *) calloc(1, sizeof(LDAPMod));
	useradd[0]->mod_op = LDAP_MOD_ADD;
	useradd[0]->mod_type = "objectClass";
	useradd[0]->mod_values = user_oc;
	for (i = 1; user_attr[i].value != NULL; i++) {
	    useradd[i] = (LDAPMod *) calloc(1, sizeof(LDAPMod));
	    if (!useradd[i]) {
		fprintf(stderr, "ERROR! Not enough memory\n");
		return ENOMEM;
	    }
	    useradd[i]->mod_op = LDAP_MOD_ADD;
	    useradd[i]->mod_type = user_attr[i].attrib;
	    useradd[i]->mod_values =
		calloc(2, strlen(user_attr[i].value) + 1);
	    useradd[i]->mod_values[0] = user_attr[i].value;
	}
	useradd[i + 1] = NULL;

	if (auth.debug)
	    fprintf(stderr, "user=%s, group=%s, uid=%s, gecos=%s\n",
		    mdata.user, mdata.group, mdata.uidnum, mygecos);

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
	if (useradd) {
	    for (i = 0; useradd[i] != NULL; i++) {
		free(useradd[i]);
	    }
	    free(useradd);
	}
	free(mygecos);

	return 0;
    }
    if (pxtype == GROUP) {
	i = 0;
	if (mdata.member) {
	    mems = calloc(1, strlen(mdata.member) + 1);
	    mems[i] = strtok(mdata.member, ",");
	    i++;
	    while ((mems[i] = strtok(NULL, ",")) != NULL) {
		i++;
	    }
	    mems[i] = NULL;
        }
	char *group_oc[] = {
	    "top",
	    "posixGroup",
	    NULL
	};

	uxds_attr_t group_attr[] = {
	    {GROUP, "dummy", "dummy"},	/* Dummy Value */
	    {GROUP, "cn", mdata.group},
	    {GROUP, "gidNumber", mdata.gidnum},
	    {GROUP, "description", mdata.comment},
	    {0, NULL, NULL}
	};
	int attrs;
	if (mems)
	    attrs = i + 4;
	else
	    attrs = 4;
        
        attrs = attrs + 1;

	LDAPMod **groupadd;
	groupadd = (LDAPMod **) calloc(attrs, sizeof(LDAPMod *));
	for (i = 0; i < attrs; i++) {
	    groupadd[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    if (groupadd[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "ERROR! Not enough memory\n");
		exit(ENOMEM);
	    }
	}
	groupadd[0]->mod_op = LDAP_MOD_ADD;
	groupadd[0]->mod_type = "objectClass";
	groupadd[0]->mod_values = group_oc;

	for (i = 1; group_attr[i].value != NULL; i++) {
	    groupadd[i]->mod_op = LDAP_MOD_ADD;
	    groupadd[i]->mod_type = group_attr[i].attrib;
	    groupadd[i]->mod_values =
		calloc(2, strlen(group_attr[i].value) + 1);
	    groupadd[i]->mod_values[0] = group_attr[i].value;
	}

	if (mems) {
	    groupadd[i]->mod_op = LDAP_MOD_ADD;
	    groupadd[i]->mod_type = "memberUid";
	    groupadd[i]->mod_values = mems;
	}
	groupadd[i + 1] = NULL;

	if (auth.basedn == NULL) {
	    auth.basedn = UXDS_POSIX_OU;
	}
	group_dn =
	    realloc(group_dn,
		    strlen(mdata.group) + strlen(auth.basedn) + 5);
	if (!snprintf
	    (group_dn, strlen(mdata.group) + strlen(auth.basedn) + 5,
	     "cn=%s,%s", mdata.group, auth.basedn))
	    return 1;
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
	if (groupadd) {
	    for (i = 0; groupadd[i] != NULL; i++) {
		free(groupadd[i]);
	    }
	}
	if (mems) {
	    free(groupadd);
	    free(mems);
	}

    }

    return 0;
}

int uxds_acct_del(uxds_acct_t pxtype, uxds_data_t mdata, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    static uxds_authz_t auth;

    char *dn;
    char *filter = NULL;
    char *acct_type = NULL;

    switch (pxtype) {
    case USER:
	filter = realloc(filter, (PA_LEN + 1));
	if (!snprintf(filter, PA_LEN, POSIXACCOUNT, mdata.user))
	    break;
	acct_type = "POSIX User";
	break;
    case GROUP:
	filter = realloc(filter, (PG_LEN + 1));
	if (!snprintf(filter, PG_LEN, POSIXGROUP, mdata.group))
	    break;
	acct_type = "POSIX Group";
	break;
    default:
	fprintf(stderr, "FATAL: Bad LDAP search filter\n");
	return 1;
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

    free(filter);

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
	fprintf(stderr, "%s matched DN: %s\n", acct_type, dn);
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

    return 0;
}

int uxds_acct_mod(uxds_acct_t pxtype, uxds_data_t mdata, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    static uxds_authz_t auth;

    int i;
    int a = 0;
    char *cbuf = NULL;
    char *dn = NULL;
    char *role = NULL;
    char *mod_dn = NULL;
    char *old_gecos = NULL;
    char *xgecos = NULL;
    char *fbuf = NULL;
    char *mygecos = NULL;
    char *filter = NULL;
    char *acct_type = NULL;

    if (mdata.modrdn == 1) {
	pxtype = GROUP;
    }
    switch (pxtype) {
    case USER:
	filter = realloc(filter, (PA_LEN + 1));
	if (!snprintf(filter, PA_LEN, POSIXACCOUNT, mdata.user))
	    break;
	acct_type = "POSIX User";
	break;
    case GROUP:
	filter = realloc(filter, (PG_LEN + 1));
	if (!snprintf(filter, PG_LEN, POSIXGROUP, mdata.group))
	    break;
	acct_type = "POSIX Group";
	break;
    default:
	fprintf(stderr, "FATAL: BAD LDAP search filter\n");
	return 1;
	break;
    }

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

    free(filter);

    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "%s matched DN: %s\n", acct_type, dn);
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
    mygecos = realloc(mygecos, (GC_LEN + 3));
    if (!snprintf
	(mygecos, GC_LEN, MY_GECOS, mdata.firstname, mdata.lastname, role))
	return 1;
    if (auth.debug)
	fprintf(stderr, "gecos is now : %s\n", mygecos);
  gecosnull:;
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
#endif
    uxds_attr_t moduser_attr[] = {
	{USER, "homeDirectory", mdata.homes},
	{USER, "gecos", mygecos},
	{USER, "givenName", mdata.firstname},
	{USER, "sn", mdata.lastname},
	{USER, "loginShell", mdata.shell},
	{USER, "uidNumber", mdata.uidnum},
	{USER, "gidNumber", mdata.gidnum},
#ifdef QMAIL
	{USER, "mailHost", host},
	{USER, "mailAlternateAddress", addr},
#endif				/* QMAIL */
	{0, NULL, NULL}
    };
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
#endif
  groupstart:
    if (pxtype == USER) {
	i = 0;
	int n = 0;
	for (i = 0; moduser_attr[i].attrib != NULL; i++) {
	    if (moduser_attr[i].value != NULL) {
		n++;
	    }
	}
	n = n + 1;

	LDAPMod **usermod;
	usermod = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
	for (i = 0; i < n; i++) {
	    usermod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    if (usermod[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "ERROR! Not enough memory\n");
		exit(ENOMEM);
	    }
	}
	n = 0;
	for (i = 0; moduser_attr[i].attrib != NULL; i++) {
	    if (moduser_attr[i].value != NULL) {
		usermod[n]->mod_op = LDAP_MOD_REPLACE;
		usermod[n]->mod_type = moduser_attr[i].attrib;
		usermod[n]->mod_values =
		    calloc(2, strlen(moduser_attr[i].value) + 1);
		usermod[n]->mod_values[0] = moduser_attr[i].value;
		n++;
	    }
	}
	usermod[n] = NULL;

#ifdef HAVE_LDAP_SASL_GSSAPI
	if ((mdata.cpw == 1) || (mdata.exp == 1)) {
	    goto skipmod;
	}
#endif				/* HAVE_LDAP_SASL_GSSAPI */
	if (!usermod[0]) {
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
	if (usermod) {
	    for (i = 0; usermod[i] != NULL; i++) {
		free(usermod[i]);
	    }
	    free(usermod);
	}
	free(mygecos);

	return 0;
    }
    if (pxtype == GROUP) {
	char **mems = NULL;
	i = 0;
	int num = 0;
	if (a == 6) {
	    mems = calloc(1, strlen(mdata.member) + 1);
	    mems[i] = strtok(mdata.member, ",");
	    i++;
	    while ((mems[i] = strtok(NULL, ",")) != NULL) {
		i++;
	    }
	    mems[i] = NULL;
	}
	if (mems)
	    num = num + 1;

	uxds_attr_t modgroup_attr[] = {
	    {GROUP, "gidNumber", mdata.gidnum}
	    ,
	    {GROUP, "description", mdata.comment}
	    ,
	    {0, NULL, NULL}
	};

	for (i = 0; modgroup_attr[i].attrib != NULL; i++) {
	    if (modgroup_attr[i].value != NULL) {
		num++;
	    }
	}
	num = num + 1;

	LDAPMod **groupmod;
	groupmod = (LDAPMod **) calloc(num, sizeof(LDAPMod *));
	for (i = 0; i < num; i++) {
	    groupmod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	    if (groupmod[i] == (LDAPMod *) NULL) {
		fprintf(stderr, "ERROR! Not enough memory\n");
		exit(ENOMEM);
	    }
	}
	num = 0;
	for (i = 0; modgroup_attr[i].attrib != NULL; i++) {
	    if (modgroup_attr[i].value != NULL) {
		groupmod[num]->mod_op = LDAP_MOD_REPLACE;
		groupmod[num]->mod_type = modgroup_attr[i].attrib;
		groupmod[num]->mod_values =
		    calloc(2, strlen(modgroup_attr[i].value) + 1);
		groupmod[num]->mod_values[0] = modgroup_attr[i].value;
		num++;
	    }
	}
	if (mems) {
	    if (mdata.membit == 0)
		groupmod[num]->mod_op = LDAP_MOD_ADD;
	    else if (mdata.membit == 1)
		groupmod[num]->mod_op = LDAP_MOD_DELETE;
	    groupmod[num]->mod_type = "memberUid";
	    groupmod[num]->mod_values = mems;
	    num++;
	}
	groupmod[num] = NULL;

	if (!groupmod[0]) {
	    fprintf(stderr,
		    "FATAL ERROR.... no attributes came through for modification!\n");
	    return 1;
	}
	if (auth.debug) {
	    fprintf(stderr, "group = %s\n", mdata.group);
	    fprintf(stderr, "groupDN = %s\n", mod_dn);
	}
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
	if (groupmod) {
	    for (i = 0; groupmod[i] != NULL; i++) {
		free(groupmod[i]);
	    }
	}
	if (mems) {
	    free(mems);
	    free(groupmod);
	}

	return 0;
    }
    /* MODRDN operation for POSIX user primary group change */
  modrdn:;
    char *old_dn = NULL;
    filter = (char *) calloc(1, (PA_LEN + 1));
    if (!snprintf(filter, PA_LEN, POSIXACCOUNT, mdata.user))
	return 1;
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
	    fprintf(stderr, "Matched DN: %s\n", dn);
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
    uxds_attr_t gidmod_attr[] = {
	{USER, "gidNumber", mdata.gidnum}
	,
	{USER, "gecos", gcos}
	,
	{0, NULL, NULL}
    };

    LDAPMod **gidmod;
    gidmod = (LDAPMod **) calloc(3, sizeof(LDAPMod *));
    for (i = 0; gidmod_attr[i].attrib != NULL; i++) {
	gidmod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	gidmod[i]->mod_op = LDAP_MOD_REPLACE;
	gidmod[i]->mod_type = gidmod_attr[i].attrib;
	gidmod[i]->mod_values =
	    calloc(2, strlen(gidmod_attr[i].value) + 1);
	gidmod[i]->mod_values[0] = gidmod_attr[i].value;
    }
    gidmod[i] = NULL;

    mod_dn = center(fbuf, center(fbuf, new_rdn, ","), mod_dn);
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
#endif				/* TOOL_LOG */
    free(filter);
    if (gidmod) {
	for (i = 0; gidmod[i] != NULL; i++) {
	    free(gidmod[i]);
	}
	free(gidmod);
    }

    return 0;
}

int uxds_grp_mem(int debug, uxds_tool_t op, char *user, char *grpdn,
		 LDAP * ld)
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
    if (exp) {
	for (i = 0; exp[i] != NULL; i++) {
	    free(exp[i]);
	}
	free(exp);
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

struct posixid get_next_pxid(LDAP * ld, LDAPMessage * msg,
			     LDAPMessage * entry, char *attr,
			     uxds_acct_t pxtype, BerElement * ber,
			     int debug)
{
    struct posixid pxid;
    pxid.fail = 0;
    pxid.uidnum = NULL;
    pxid.gidnum = NULL;

    char *filter = NULL;
    char *type = NULL;
    char *mask[] = { "uidNumber", "gidNumber", NULL };

    if (pxtype == USER) {
	filter = UIDNUM;
	type = "uidNumber";
    }
    if (pxtype == GROUP) {
	filter = GIDNUM;
	type = "gidNumber";
    }
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, mask, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	pxid.fail = 1;
	return pxid;
    }
    if (debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }

    /* get next available uid or gid */
    for (entry = ldap_first_entry(ld, msg);
	 entry != NULL; entry = ldap_next_entry(ld, entry)) {
	if (ldap_sort_entries(ld, &entry, type, strcmp)) {
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	}
	if (debug) {
	    fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	}
	for (attr = ldap_first_attribute(ld, entry, &ber);
	     attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
	    if (pxtype == USER) {
		if ((strstr(attr, "uid") != 0)) {
		    pxid.uidnum = return_idnum(ld, entry, attr);
		}
	    } else if (pxtype == GROUP) {
		pxid.gidnum = return_idnum(ld, entry, attr);
	    }
	    ldap_memfree(attr);
	}
    }
    return pxid;
}

/* extract actual idnumber */
char *return_idnum(LDAP * ld, LDAPMessage * entry, char *attr)
{
    int a = 0;
    char *idnum = NULL;

    vals = ldap_get_values_len(ld, entry, attr);
    idnum = strdup(vals[0]->bv_val);
    a = atoi(idnum) + 1;
    snprintf(idnum, 6, "%d", a);
    ldap_value_free_len(vals);

    return idnum;
}
