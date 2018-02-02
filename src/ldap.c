/* LDAP functions */

#include "uxds.h"
#include "uxds_strings.h"
#include "uxds_sasl.h"
#include "uxds_krb5.h"
#ifdef PTS
#include "uxds_afs.h"
#endif				/* PTS */
#ifdef TOOL_LOG
#include "uxds_log.h"
#endif				/* TOOL_LOG */

int i;
int rc;
char *cbuf = NULL;
struct berval **vals;

int uxds_user_authz(uxds_bind_t sflag, uxds_authz_t auth, LDAP * ld)
{
    int proto;
    char *sasl_mech = NULL;
    unsigned sasl_flags = 0;

    if (auth.debug) {
	fprintf(stderr, "sflag value is %i -> ", sflag);
	fprintf(stderr,
		"(0 = SASL/GSSAPI, 1 = KINIT)\n");
	fprintf(stderr, "LDAP host URI is: %s\n", auth.uri);
    }
    sasl_mech = auth.saslmech;
    if (auth.verb == 1)
        sasl_flags = LDAP_SASL_INTERACTIVE;	/* [-V] some mechs need? */
    else
	sasl_flags = LDAP_SASL_QUIET;	/* default */
    if (sflag == GSSAPI) {
	if (auth.debug)
            fprintf(stderr,
		"used GSSAPI -> credentials cache is: %s\n",
		auth.credcache);
    }
    proto = LDAP_VERSION3;

    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &proto) !=
	LDAP_OPT_SUCCESS) {
	fprintf(stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
		proto);
	return 1;
    }
    if (sflag == GSSAPI) {
	if (auth.credcache != NULL) {
            auth.credcache =
	    center(cbuf, "KRB5CCNAME=", auth.credcache);
	    if (auth.debug)
		fprintf(stderr, "'%s' exported\n", auth.credcache);
	    if (putenv(auth.credcache)) {
		fprintf(stderr, "putenv() call failed\n");
		return 1;
            }
	}
	if (auth.binddn != NULL) {
	    if (auth.debug)
		fprintf(stderr, "selected dn: %s\n", auth.binddn);
	}
	rc = ldap_sasl_interactive_bind_s(ld, auth.binddn,
					  sasl_mech, NULL, NULL,
					  sasl_flags, uxds_sasl_interact,
					  &auth);
    }

    if (rc != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	ldap_unbind_ext_s(ld, NULL, NULL);
	return 1;
    }
    if (auth.debug)
	fprintf(stdout, "SUCCESSFUL bind using URI %s\n", auth.uri);
    /* get SASL SSF factor - debug */
    if (auth.debug) {
	sasl_ssf_t ssf;
	unsigned long val = 0;
	if (!ldap_get_option(ld, LDAP_OPT_X_SASL_SSF, &ssf)) {
	    val = (unsigned long) ssf;
	}
	fprintf(stderr, "SSF level is: %lu\n", val);
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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

    int all = 0;
    char *dn = NULL;
    char *attr = NULL;
    char *fbuf = NULL;
    char *accttype = NULL;
    /* only pull these values */
    char *attr_mask[] = { "cn",
	"sn",
	"givenName",
	"mail",
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
	NULL
    };

    char *filter =
	(char *) calloc(1, strlen(SUDOUSER) + strlen(auth.pxacct) + 1);
    ERRNOMEM(filter);
    char *kuser = NULL;
    if (auth.debug)
	fprintf(stderr, "account type vars: account = %i\n", auth.acct);
    if (strchr(auth.pxacct, '*') != NULL)
	all = 1;
    switch (auth.acct) {
	/* if user/group/sudoer argument not selected - then do who am i? */
    case SELF:
	switch (bind) {
	case KINIT:
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
    if (auth.ldif != NULL) 
	attr_mask[0] = NULL;
    
    if (ldap_search_ext_s
	(ld, auth.basedn, LDAP_SCOPE_SUBTREE, filter, attr_mask, 0,
	 NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }

    if (filter)
	free(filter);

    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    if (accttype == NULL)
	accttype = "Your";
    if (all == 1) {
	fprintf(stdout, "------- %s Account Listing -------\n", accttype);
	for (entry = ldap_first_entry(ld, msg);
	     entry != NULL; entry = ldap_next_entry(ld, entry)) {
	    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
		fprintf(stdout, "DN: %s\n", dn);
		ldap_memfree(dn);
	    } else {
		fprintf(stderr, "account %s not matched to any DN\n",
			auth.pxacct);
		return 1;
	    }
	}
	ldap_msgfree(msg);
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
		ldap_msgfree(msg);
		ldap_msgfree(entry);

		return 0;
	    }
	} else {
	    fprintf(stderr, "account %s not matched to any DN\n",
		    auth.pxacct);
	    return 1;
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
		    if (strcmp(attr, "krb5Key") == 0)
			vals[i]->bv_val =
			    base64(vals[i]->bv_val,
				   strlen(vals[i]->bv_val));
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
    if (ber != NULL)
	ber_free(ber, 0);
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

    char *attr = NULL;
    char *dn = NULL;
    char *role = NULL;
    char *user_dn = NULL;
    char *group_dn = NULL;
    char *filter = NULL;

    if (pxtype == USER) {
	if (mdata.group == NULL) {
	    fprintf(stderr,
		    "No POSIX GROUP (-G <group>) selected for USER ADD, Exiting...\n");
	    return 1;
	}
	if (mdata.uidnum == NULL) {
	    pxid =
		get_next_pxid(ld, msg, entry, attr, pxtype, ber,
			      auth.debug);
	    if (pxid.fail)
		return 1;
	    else
		mdata.uidnum = pxid.uidnum;
	}
    } else if (pxtype == GROUP) {
	if (mdata.gidnum == NULL) {
	    pxid =
		get_next_pxid(ld, msg, entry, attr, pxtype, ber,
			      auth.debug);
	    if (pxid.fail)
		return 1;
	    else {
		mdata.gidnum = pxid.gidnum;
	    }
	}
    }

    filter = realloc(filter, (PG_LEN + 1));

    /* XXX GROUP conditional jump */
    if (pxtype == GROUP)
	goto groupstart;

    /* for USER only */
    if (!snprintf(filter, PG_LEN, POSIXGROUP, mdata.group))
	return 1;
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg)
	!= LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }

    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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

    char *user_oc[] = {
	"top",
	"person",
	"inetOrgPerson",
	"organizationalPerson",
	"posixAccount",
	"shadowAccount",
	"krb5Principal",
	"krb5KDCEntry",
#ifdef SSH_LPK
        "ldapPublicKey",
#endif                         /* SSH_LPK */
	NULL
    };

    if (mdata.homes == NULL)
	mdata.homes = strdup(center(cbuf, "/home/", mdata.user));
    if (mdata.shell == NULL)
	mdata.shell = strdup("/bin/bash");
    if (mdata.xgecos == NULL) {
        mdata.xgecos = realloc(mdata.xgecos, (GC_LEN + 3));
        if (!snprintf
	    (mdata.xgecos, GC_LEN, MY_GECOS, mdata.firstname, mdata.lastname, role))
	    return 1;
    }	
    char *principal = center(cbuf, mdata.user, AT_REALM);
    /*
     * XXX because objectClass is already an array, we 
     * put dummy values for user_attr[0] so we can start
     * from user_attr[1] when we fill up the LDAPMod struct
     */
    uxds_attr_t user_attr[] = {
	{USER, "dummy", "dummy"},	/* dummy values how many time can you say 'dummy' */
	{USER, "cn", mdata.user},
	{USER, "givenName", mdata.firstname},
	{USER, "sn", mdata.lastname},
	{USER, "uid", mdata.user},
	{USER, "mail", center(cbuf, mdata.user, AT_EMAIL)},
	{USER, "gecos", mdata.xgecos},
	{USER, "uidNumber", mdata.uidnum},
	{USER, "gidNumber", gidnum},
	{USER, "homeDirectory", mdata.homes},
	{USER, "loginShell", mdata.shell},
	{USER, "userPassword", "{K5KEY}"},
	{USER, "carLicense", "XxXxXxXxXxXxXxXxX"},
	{USER, "krb5PrincipalName", principal},
	{USER, "krb5MaxLife", "86400"},
	{USER, "krb5MaxRenew", "604800"},
	{USER, "krb5KDCFlags", "126"},
	{USER, "krb5KeyVersionNumber", "0"},
	{USER, "krb5PasswordEnd", "20071231235959Z"},
	{USER, "krb5Key", "0"},
#ifdef SSH_LPK
	{USER, "sshPublicKey", "ssh-rsa"},
#endif                         /* SSH_LPK */
	{0, NULL, NULL}
    };

  groupstart:
    if (pxtype == USER) {

	LDAPMod **useradd;
	useradd = uxds_add_ldapmod(user_attr, user_oc, LDAP_MOD_ADD);

	if (auth.debug)
	    fprintf(stderr, "user=%s, group=%s, uid=%s, gecos=%s\n",
		    mdata.user, mdata.group, mdata.uidnum, mdata.xgecos);

	if (ldap_add_ext_s(ld, user_dn, useradd, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stderr, "Attempted DN: %s, len %lu\n", user_dn,
		    strlen(user_dn));
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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
#ifdef PTS
	if (pts_wrap(PTSCRT, mdata.user, MY_CELL, mdata.uidnum, USER)
	    != 0)
	    fprintf(stderr, "ERROR: User %s not created in pts database\n",
		    mdata.user);
	if (pts_wrap(PTSGRP, mdata.user, MY_CELL, mdata.group, ADD)
	    != 0)
	    fprintf(stderr, "ERROR: User %s not added to group %s\n",
		    mdata.user, mdata.group);
#endif
	if ((uxds_grp_mem(auth.debug, ADD, mdata.user, group_dn, 0, ld))
	    != 0) 
	    fprintf(stderr, "adding memberUid FAILED\n");
	
	if ((uxds_grp_mem(auth.debug, ADD, user_dn, group_dn, 1, ld))
            != 0)
	    fprintf(stderr, "adding member FAILED\n");
	if ((mdata.cpw == 1) || (mdata.setpass)) {
	    char *name = get_krbname(auth, FALSE);
	    if (putenv(center(cbuf, "KRB5CCNAME=/tmp/kacache_", name))) {
		fprintf(stderr, "putenv() call failed\n");
		return 1;
	    }
	    if (mdata.cpw == 1)
		mdata.setpass = randstr(PASSLEN);
	    if (setpwd(mdata.user, mdata.setpass) != 0)
		fprintf(stderr, "Password NOT set for %s\n", mdata.user);
	}
	if (mdata.exp == 1) {
	    if ((uxds_user_expire(0, user_dn, ld)) != 0)
		fprintf(stderr, "Password not EXPIRED for %s\n",
			mdata.user);
	    fprintf(stdout, "Password for %s EXPIRED to 12-31-1999\n",
		    mdata.user);
	}
	if (useradd) {
            for (i = 0; useradd[i] != NULL; i++) {
                free(useradd[i]);
	    }
	    free(useradd);
	}
	if (msg)
	    ldap_msgfree(msg);

	return 0;
    }
    if (pxtype == GROUP) {
	if (!auth.basedn)
	    auth.basedn = strdup(UXDS_POSIX_OU);

	char *group_oc[] = {
	    "top",
	    "posixGroup",
	    "groupOfNames",
	    NULL
	};

	uxds_attr_t group_attr[] = {
	    {GROUP, "dummy", "dummy"},	/* Dummy Value */
	    {GROUP, "cn", mdata.group},
	    {GROUP, "gidNumber", mdata.gidnum},
	    {GROUP, "description", mdata.comment},
	    {GROUP, "member", "uid=dummy,cn=dummy," UXDS_POSIX_OU},
	    {0, NULL, NULL}
	};
        
	LDAPMod **groupadd;
        groupadd = uxds_add_ldapmod(group_attr, group_oc, LDAP_MOD_ADD);
                
	group_dn = calloc(1, strlen(mdata.group) + strlen(auth.basedn) + 5);
        snprintf(group_dn, strlen(mdata.group) + strlen(auth.basedn) + 5,
	  "cn=%s,%s", mdata.group, auth.basedn);
	if (auth.debug)
	    fprintf(stderr,
		    "group=%s, gid=%s, descr=%s, memberuid(s)=%s\n",
		    mdata.group, mdata.gidnum, mdata.comment,
		    mdata.member);

	if (ldap_add_ext_s(ld, group_dn, groupadd, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stdout, "Attempted DN: %s\n", group_dn);
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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

	exit(0); /* XXX preventing weird double free() bug */
#ifdef PTS
	if (pts_wrap(PTSCRT, mdata.group, MY_CELL, mdata.gidnum, GROUP)
	    != 0)
	    fprintf(stderr,
		    "ERROR: Group %s not created in pts database\n",
		    mdata.group);
	/* PTS */
#endif
	if (groupadd) {
	    for (i = 0; groupadd[i] != NULL; i++) {
		free(groupadd[i]);
	    }
	    free(groupadd);
	}
    }

    exit(0);
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
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }

    free(filter);

    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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
	    if (mdata.group != NULL)
		fprintf(stderr, "Deleting %s account - %s....\n",
			acct_type, mdata.group);
	}
    }
    if (ldap_delete_ext_s(ld, dn, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	fprintf(stderr, "POSIX Account deletion UNSUCCESSFUL.\n");
#ifdef TOOL_LOG
	log_event(dn, pxtype, DEL, "FAILED");
#endif				/* TOOL_LOG */

	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
    }
#ifdef TOOL_LOG
    log_event(dn, pxtype, DEL, "SUCCESSFUL - DELETED");
#endif				/* TOOL_LOG */
    if (pxtype == USER) {
	mdata.member = strstr(mdata.member, "cn=");
	if ((uxds_grp_mem(auth.debug, DEL, mdata.user, mdata.member, 0, ld))
	    != 0)
	    fprintf(stderr, "deleting memberUid FAILED\n");
	if ((uxds_grp_mem(auth.debug, DEL, dn, mdata.member, 1, ld))
            != 0)
	    fprintf(stderr, "deleting member FAILED\n");
            
#ifdef PTS
	if (pts_wrap(PTSDEL, mdata.user, MY_CELL) != 0)
	    fprintf(stderr,
		    "ERROR: User %s not deleted from pts database\n",
		    mdata.user);
    }
    if (pxtype == GROUP) {
	if (pts_wrap(PTSDEL, mdata.group, MY_CELL) != 0)
	    fprintf(stderr,
		    "ERROR: Group %s not deleted from pts database\n",
		    mdata.group);
#endif				/* PTS */
    }
    fprintf(stderr, "POSIX Account DELETED.\n");
    if (msg)
	ldap_msgfree(msg);

    return 0;
}

int uxds_acct_mod(uxds_acct_t pxtype, uxds_data_t mdata, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    static uxds_authz_t auth;

    char *cbuf = NULL;
    char *mod_dn = NULL;
    char *filter = NULL;
    char *acct_type = NULL;
    char **mems; 
    uxds_tool_t op;

    if (mdata.modrdn == 1) 
	pxtype = GROUP;
    
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
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }
    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
	fprintf(stderr, "Using %s filter matched no DN.\n", filter);
	return 1;
    }

    if ((mod_dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "%s matched DN: %s\n", acct_type, mod_dn);
	if (auth.debug)
	    ldap_memfree(mod_dn);
    }
    if (mdata.modrdn == 1) {
	vals = ldap_get_values_len(ld, entry, "gidNumber");
	mdata.gidnum = strdup(vals[0]->bv_val);
	ldap_value_free_len(vals);
	vals = ldap_get_values_len(ld, entry, "description");
	mdata.comment = strdup(vals[0]->bv_val);
	ldap_value_free_len(vals);
	if (uxds_acct_modrdn
	    (mdata, mod_dn, filter, auth.debug, entry, msg, ld)) {
	    fprintf(stderr, "modrdn procedure FAILED...\n");
	    return 1;
	}

	return 0;
    }

    if (pxtype == GROUP) {
	goto groupstart;	/* XXX */
    }

    if (mdata.xgecos == NULL) {
        char *tag = malloc(sizeof(char));
	snprintf(tag, strlen("UXDSAcct") + 1, "%s", "UXDSAcct");
        vals = ldap_get_values_len(ld, entry, "gecos");
	if (strstr(vals[0]->bv_val, tag) != NULL) { 
            if ((mdata.firstname != NULL) || (mdata.lastname != NULL)) {
                mdata.xgecos = calloc(1, sizeof(char *));
       	        mdata.xgecos = build_gecos(mdata, entry, auth.debug, ld);
	    } 
	    if (!mdata.xgecos) {
                if ((mdata.cpw) || (mdata.exp) || (mdata.setpass))
		    goto groupstart;
		else
	            fprintf(stderr, "FATAL: could not build GECOS attribute\n");
	        return 1;
	    }
	} else {
	    fprintf(stderr, "Custom GECOS field exists - " \
	            "no need for modification.\n");
	    return 0;
	}
    }	
    if (msg)
        ldap_msgfree(msg);

    uxds_attr_t moduser_attr[] = {
	{USER, "homeDirectory", mdata.homes},
	{USER, "loginShell", mdata.shell},
	{USER, "uidNumber", mdata.uidnum},
	{USER, "gidNumber", mdata.gidnum},
	{USER, "gecos", mdata.xgecos},
	{0, NULL, NULL}
    };
  groupstart:
    if (pxtype == USER) {

	LDAPMod **usermod;	

/* XXX */
	if ((mdata.homes != NULL) ||
            (mdata.shell != NULL) ||
            (mdata.uidnum != NULL) ||
            (mdata.gidnum != NULL))  
	    usermod = uxds_add_ldapmod(moduser_attr, NULL, LDAP_MOD_REPLACE);
        else 
	    usermod = NULL;

	if ((!mdata.cpw) && (!mdata.exp) && (!mdata.setpass)) {
	    if (!usermod[0]) {
		fprintf(stderr,
			"FATAL ERROR.... no attributes came through for modification!\n");
		return 1;
	    }
	}
	if ((mdata.cpw == 1) || (mdata.setpass)) {
	    char *name = get_krbname(auth, FALSE);
	    if (putenv(center(cbuf, "KRB5CCNAME=/tmp/kacache_", name))) {
		fprintf(stderr, "putenv() call failed\n");
		return 1;
	    }
	    if (mdata.cpw == 1)
		mdata.setpass = randstr(PASSLEN);
	    if (setpwd(mdata.user, mdata.setpass) != 0) {
		fprintf(stderr, "Password not set for %s\n", mdata.user);
		return 1;
            }

	}
	if (mdata.exp == 1) {
	    if ((uxds_user_expire(0, mod_dn, ld)) != 0)
		fprintf(stderr, "Password not EXPIRED for %s\n",
			mdata.user);
	    fprintf(stdout, "Password for %s EXPIRED to 12-31-1999\n",
		    mdata.user);
	}
	if (!usermod)
	    return 0;

	if (ldap_modify_ext_s(ld, mod_dn, usermod, NULL, NULL) !=
	    LDAP_SUCCESS) {
	    fprintf(stdout, "Attempted DN: %s, len %lu\n", mod_dn,
		    strlen(mod_dn));
#ifdef TOOL_LOG
	    log_event(mod_dn, USER, MOD, "FAILED");
#endif				/* TOOL_LOG */
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	    fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	    return 1;
	}
	printf("got here...\n");
	fprintf(stdout,
		"POSIX User Account Modification of %s SUCCESSFUL.\n",
		mdata.user);
	fprintf(stdout, "Modified DN: %s\n", mod_dn);
#ifdef TOOL_LOG
	log_event(mod_dn, USER, MOD, "SUCCESSFUL");
#endif				/* TOOL_LOG */
	if (usermod) {
	    for (i = 0; usermod[i] != NULL; i++) {
		free(usermod[i]);
	    }
	}

	return 0;
    }
    if (pxtype == GROUP) {
	i = 0;
	int debug = 1;

        if (mdata.member) {
	    int c = 1;
	    char *p = mdata.member;
	    while((p = strchr(p, ',')) != NULL) {
                c++;
                p++;
	    }
	    c++;
	    i = 0;
            mems = calloc(c, strlen(mdata.member) + 1);
  	    ERRNOMEM(mems);
   	    mems[i] = strtok(mdata.member, ",");
   	    i++;
    	    while ((mems[i] = strtok(NULL, ",")) != NULL) {
                i++;
	    }
    	    mems[i] = NULL;
	    if (mdata.membit == 0)
                op = ADD;
	    if (mdata.membit == 1)
		op = DEL;
	    for (i = 0; mems[i] != NULL; i++) {
                if ((uxds_grp_mem(debug, op, mems[i], mod_dn, 0, ld))
	            != 0) {
		    if (mdata.membit == 0) {
	                fprintf(stderr, "adding memberUid FAILED\n");
		    }
		    if (mdata.membit == 1) {
	                fprintf(stderr, "deleting memberUid FAILED\n");
	            }
		}
                
		char *userdn = calloc(1, strlen(mod_dn) + 16);
		snprintf(userdn, strlen(mod_dn) + 16, "%s%s%s%s", "uid=", mems[0], ",", mod_dn);
                if ((uxds_grp_mem(debug, op, userdn, mod_dn, 1, ld))
	            != 0) {
		    if (mdata.membit == 0) {
	                fprintf(stderr, "adding member FAILED\n");
		        return 1;
		    }
		    if (mdata.membit == 1) {
	                fprintf(stderr, "deleting member FAILED\n");
	                return 1;
	            }
		}
            }
	    if (!mdata.comment || !mdata.gidnum) {
                return 0;
	    }
        }
	uxds_attr_t modgroup_attr[] = {
	    {GROUP, "gidNumber", mdata.gidnum},
	    {GROUP, "description", mdata.comment},
	    {0, NULL, NULL}
	};
        
	LDAPMod **groupmod;
	groupmod = uxds_add_ldapmod(modgroup_attr, NULL, LDAP_MOD_REPLACE);

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
	    fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	    return 1;
	}
	fprintf(stdout,
		"POSIX Group Account Modification of %s SUCCESSFUL.\n",
		mdata.group);
	fprintf(stdout, "Modified DN: %s\n", mod_dn);
#ifdef TOOL_LOG
	log_event(mod_dn, GROUP, MOD, "SUCCESSFUL");
#endif				/* TOOL_LOG */
	if (groupmod) 
	    for (i = 0; groupmod[i] != NULL; i++) {
		free(groupmod[i]);
	    }
    }
    return 0;
}

/* MODRDN operation for POSIX user primary group change */
int uxds_acct_modrdn(uxds_data_t mdata, char *mod_dn, char *filter,
		     int debug, LDAPMessage * entry, LDAPMessage * msg,
		     LDAP * ld)
{
    char *fbuf = NULL;
    char *old_dn = NULL;
    char *dn = NULL;
    char *gecos = NULL;
    struct berval **fname;
    struct berval **lname;

    if (!snprintf(filter, PA_LEN, POSIXACCOUNT, mdata.user))
	return 1;
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }

    if (debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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
	if (debug)
	    fprintf(stderr, "Matched DN: %s\n", dn);
	old_dn = strdup(dn);
	if (debug)
	    fprintf(stderr, "MODRDN using old DN:%s\n", old_dn);
	ldap_memfree(dn);
    }
    fname = ldap_get_values_len(ld, entry, "givenName");
    lname = ldap_get_values_len(ld, entry, "sn");
#define MRDN_LEN    (strlen(MY_GECOS) + strlen(fname[0]->bv_val) + \
		     strlen(lname[0]->bv_val) + strlen(mdata.comment) + 1)
    gecos = calloc(1, MRDN_LEN);
    ERRNOMEM(gecos);
    if (!snprintf
	(gecos, MRDN_LEN, MY_GECOS, fname[0]->bv_val, lname[0]->bv_val,
	 mdata.comment))
	return 1;

    ldap_value_free_len(fname);
    ldap_value_free_len(lname);

    fprintf(stderr, "MODRDN to new parent DN: %s\n", mod_dn);
    char *new_rdn = center(fbuf, "uid=", mdata.user);
    /* do it */
    if (ldap_rename_s(ld, old_dn, new_rdn, mod_dn, 1, NULL, NULL) != 0) {
#ifdef TOOL_LOG
	log_event(new_rdn, USER, MOD, "MODRDN FAILED");
#endif				/* TOOL_LOG */
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }
    if (debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
    }
    /* delete memberUid from old posixGroup and add it to new */
    old_dn = strstr(old_dn, "cn=");
    if ((uxds_grp_mem(debug, ADD, mdata.user, mod_dn, 0, ld))
	!= 0)
	fprintf(stderr, "adding memberUID FAILED\n");
    if ((uxds_grp_mem(debug, DEL, mdata.user, old_dn, 0, ld))
	!= 0) 
	fprintf(stderr, "deleting memberUid FAILED\n");
#ifdef PTS
    char *oldgroup = strdup(old_dn);
    oldgroup = strtok(oldgroup, ",");
    for (i = 0; i < strlen(oldgroup) - 1; i++) {
	oldgroup[i] = oldgroup[i + 3];
    }
    oldgroup[i] = '\0';
    if (pts_wrap(PTSGRP, mdata.user, MY_CELL, oldgroup, DEL) != 0) 
	fprintf(stderr, "Failed to DELETE %s from group %s\n",
		mdata.user, oldgroup);
    free(oldgroup);
#endif				/* PTS */
    char *new_dn = calloc(1, strlen(mdata.user) + strlen(mod_dn) + 16);
    snprintf(new_dn, strlen(mdata.user) + strlen(mod_dn) + 16, "%s%s%s%s", "uid=", mdata.user, ",", mod_dn);
    if ((uxds_grp_mem(debug, ADD, new_dn, mod_dn, 1, ld)) 
	!= 0) {
        fprintf(stderr, "adding member FAILED\n");
    }

    char *del_dn = calloc(1, strlen(mdata.user) + strlen(old_dn) + 16);
    snprintf(del_dn, strlen(mdata.user) + strlen(old_dn) + 16, "%s%s%s%s", "uid=", mdata.user, ",", old_dn);
    if ((uxds_grp_mem(debug, DEL, del_dn, old_dn, 1, ld))
	!= 0) {
	fprintf(stderr, "deleting memberUid FAILED\n");
    }
#ifdef PTS
    if (pts_wrap(PTSGRP, mdata.user, MY_CELL, mdata.group, ADD) != 0)
	fprintf(stderr, "Failed to ADD %s to group %s\n",
		mdata.user, mdata.group);
#endif				/* PTS */
    /* change gidNumber & gecos for user */
    uxds_attr_t gidmod_attr[] = {
	{USER, "gidNumber", mdata.gidnum},
	{USER, "gecos", gecos},
	{0, NULL, NULL}
    };

    LDAPMod **gidmod;
    gidmod = uxds_add_ldapmod(gidmod_attr, NULL, LDAP_MOD_REPLACE);

    if (debug)
	fprintf(stderr, "%s -> new dn\n", new_dn);
    if (ldap_modify_ext_s(ld, new_dn, gidmod, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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
    if (gidmod) {
	for (i = 0; gidmod[i] != NULL; i++) {
	    free(gidmod[i]);
	}
	free(gidmod);
    }
    free(gecos);
    center_free(mod_dn);
    ldap_msgfree(msg);

    return 0;
}

LDAPMod **uxds_add_ldapmod(uxds_attr_t * attrs, char *oc[], int modify)
{
    LDAPMod **acctdata;
    int i;
    int n;

    n = 0;
    for (i = 0; attrs[i].attrib != NULL; i++) {
	if (modify == LDAP_MOD_REPLACE) {
	    if (attrs[n].value != NULL)
		n++;
	}
    }
    i = i + 2;
    n = n + 2;

    if (modify == LDAP_MOD_ADD)
	acctdata = (LDAPMod **) calloc(i, sizeof(LDAPMod *));
    if (modify == LDAP_MOD_REPLACE)
	acctdata = (LDAPMod **) calloc(n, sizeof(LDAPMod *));
    ERRNOMEM(acctdata);

    if (modify == LDAP_MOD_ADD) {
	acctdata[0] = (LDAPMod *) calloc(1, sizeof(LDAPMod));
	ERRNOMEM(acctdata[0]);
	acctdata[0]->mod_op = LDAP_MOD_ADD;
	acctdata[0]->mod_type = "objectClass";
	acctdata[0]->mod_values = oc;

	fprintf(stdout, "Importing attributes...\n");

	for (i = 1; attrs[i].value != NULL; i++) {
	    acctdata[i] = (LDAPMod *) calloc(2, sizeof(LDAPMod));
	    ERRNOMEM(acctdata[i]);
	    acctdata[i]->mod_op = LDAP_MOD_ADD;
	    acctdata[i]->mod_type = attrs[i].attrib;
	    acctdata[i]->mod_values = calloc(2, 2 * sizeof(char *));
	    ERRNOMEM(acctdata[i]->mod_values);
	    acctdata[i]->mod_values[0] = attrs[i].value;
	}
    }

    if (modify == LDAP_MOD_REPLACE) {
	for (i = 0; i < n; i++) {
	    acctdata[i] = (LDAPMod *) calloc(1, sizeof(LDAPMod));
	    ERRNOMEM(acctdata[i]);
	}
	n = 0;
	for (i = 0; attrs[i].attrib != NULL; i++) {
	    if (attrs[i].value != NULL) {
		acctdata[n]->mod_op = LDAP_MOD_REPLACE;
		acctdata[n]->mod_type = attrs[i].attrib;
		acctdata[n]->mod_values = calloc(2, 2 * sizeof(char *));
		ERRNOMEM(acctdata[n]->mod_values);
		acctdata[n]->mod_values[0] = attrs[i].value;
		n++;
	    }
	}
	acctdata[n] = NULL;
    }

    return acctdata;
}

int uxds_grp_mem(int debug, uxds_tool_t op, char *user, char *grpdn,
		 int type, LDAP * ld)
{
    int mtype;
    char *oper;
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
	fprintf(stdout, "Supports ADD or DELETE ONLY\n");
	return 1;
	break;
    }

    char *_memberuid[] = { user, NULL };

    LDAPMod **members;
    members = (LDAPMod **) calloc(2, sizeof(LDAPMod *));
    ERRNOMEM(members);
    members[0] = (LDAPMod *) malloc(sizeof(LDAPMod));
    ERRNOMEM(members[0]);
    members[0]->mod_op = mtype;
    if (type == 0)
        members[0]->mod_type = "memberUid";
    if (type == 1)
        members[0]->mod_type = "member";
    members[0]->mod_values = _memberuid;
    members[1] = NULL;
    char *result;
    if (type == 0)
        result = "memberUid";
    if (type == 1)
	result = "member";
    if (ldap_modify_ext_s(ld, grpdn, members, NULL, NULL) != LDAP_SUCCESS) {
	fprintf(stdout, "Failed to %s %s %s using DN: %s\n",
		oper, result, user, grpdn);
#ifdef TOOL_LOG
	log_event(grpdn, GROUP, MOD,
		  center(cbuf, oper, " of memberUid FAILED"));
#endif				/* TOOL_LOG */
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	return 1;
    }

    if (type == 0)
        fprintf(stderr, "SUCCESSFUL %s of memberUid %s using POSIX Group DN:\n%s\n",
 	        oper, user, grpdn);
    if (type == 1)
        fprintf(stderr, "SUCCESSFUL %s of member %s using POSIX Group DN:\n%s\n",
 	        oper, user, grpdn);
#ifdef TOOL_LOG
    if (type == 0)
        log_event(grpdn, GROUP, MOD,
         	      center(cbuf, oper, " of memberUid SUCCESSFUL"));
    if (type == 1)
        log_event(grpdn, GROUP, MOD,
         	      center(cbuf, oper, " of member SUCCESSFUL"));

#endif				/* TOOL_LOG */
    return 0;
}

/* expire password for four flavors */
int uxds_user_expire(int type, char *dn, LDAP * ld)
{
    enum { KRB5, PPLCY, SAMBA, AD };	/* pplcy/samba/ad future */

    int e;
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
    ERRNOMEM(exp);
    for (i = 0; i < e; i++) {
	exp[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	ERRNOMEM(exp[i]);
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
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
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
    int status;
    va_list ap;
    uxds_acct_t pxtype;
    uxds_tool_t op;
    char **pts_str;
    char *ptsgrp = NULL;
    char *idnum = NULL;

    /* fork off child pts exec proc */
    if ((pid = fork()) < 0) {
	fprintf(stderr, "ERROR: forking child pts process failed\n");
	return 1;
    } else if (pid == 0) {
	pts_str = (char **) calloc(9, sizeof(char *));
	ERRNOMEM(pts_str);
	for (i = 0; i < 9; i++) {
	    pts_str[i] = (char *) malloc(sizeof(char));
	    ERRNOMEM(pts_str[i]);
	}

	pts_str[0] = "pts";
	switch (flag) {
	case PTSCRT:
	    va_start(ap, cellname);
	    idnum = va_arg(ap, char *);
	    pxtype = va_arg(ap, uxds_acct_t);
	    if (pxtype == USER) {
		pts_str[1] = "createuser";
		pts_str[7] = idnum;
	    } else if (pxtype == GROUP) {
		pts_str[1] = "creategroup";
		pts_str[7] = center(pts_str[7], "-", idnum);
	    }
	    pts_str[2] = "-name";
	    pts_str[3] = ptsname;
	    pts_str[4] = "-cell";
	    pts_str[5] = cellname;
	    pts_str[6] = "-id";
	    pts_str[8] = NULL;
	    va_end(ap);
	    break;
	case PTSGRP:
	    va_start(ap, cellname);
	    ptsgrp = va_arg(ap, char *);
	    op = va_arg(ap, uxds_tool_t);
	    if (op == ADD)
		pts_str[1] = "adduser";
	    else if (op == DEL)
		pts_str[1] = "removeuser";
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
	if (execv(PTS_BIN, pts_str) != 0)
	    return 1;
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
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	pxid.fail = 1;
	return pxid;
    }
    if (debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	fprintf(stderr, "The number of entries returned was %d\n",
		ldap_count_entries(ld, msg));
    }

    /* get next available uid or gid */
    for (entry = ldap_first_entry(ld, msg);
	 entry != NULL; entry = ldap_next_entry(ld, entry)) {
	/* XXX ldap_sort_entries is DEPRECATED */
	if (ldap_sort_entries(ld, &entry, type, strcmp)) 
	    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	if (debug)
	    fprintf(stderr, "%s: %s\n", RES, ldap_err2string(rc));
	for (attr = ldap_first_attribute(ld, entry, &ber);
	     attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
	    if (pxtype == USER) {
		if ((strstr(attr, "uid") != 0)) 
		    pxid.uidnum = return_idnum(ld, entry, attr);
	    } else if (pxtype == GROUP) {
		pxid.gidnum = return_idnum(ld, entry, attr);
	    }
	    ldap_memfree(attr);
	}
    }
    ldap_msgfree(msg);

    return pxid;
}

/* extract actual idnumber */
char *return_idnum(LDAP * ld, LDAPMessage * entry, char *attr)
{
    int a = 0;
    int len = 0;
    char *idnum = NULL;

    vals = ldap_get_values_len(ld, entry, attr);
    idnum = strdup(vals[0]->bv_val);
    len = strlen(idnum) + 1;
    a = atoi(idnum) + 1;
    snprintf(idnum, len, "%d", a);
    ldap_value_free_len(vals);

    return idnum;
}

char *build_gecos(uxds_data_t mdata, LDAPMessage * entry, int debug,
		  LDAP * ld)
{
    char *role = NULL;
    char *old_gecos = NULL;

    if (mdata.firstname == NULL) {
	vals = ldap_get_values_len(ld, entry, "givenName");
	if (vals[0]->bv_val != NULL) {
	    if (debug)
		fprintf(stderr, "%s : first name, len %lu\n",
			vals[0]->bv_val, strlen(vals[0]->bv_val));
	    mdata.firstname = strdup(vals[0]->bv_val);
	    ldap_value_free_len(vals);
	}
    }
    if (mdata.lastname == NULL) {
	vals = ldap_get_values_len(ld, entry, "sn");
	if (vals[0]->bv_val != NULL) {
	    if (debug)
		fprintf(stderr, "%s : sn, len %lu\n", vals[0]->bv_val,
			strlen(vals[0]->bv_val));
	    mdata.lastname = strdup(vals[0]->bv_val);
	    ldap_value_free_len(vals);
	}
    }
    vals = ldap_get_values_len(ld, entry, "gecos");
    if (vals[0]->bv_val != NULL) {
	if (debug)
	    fprintf(stderr, "%s : gecos, len %lu\n", vals[0]->bv_val,
		    strlen(vals[0]->bv_val));
	old_gecos = strdup(vals[0]->bv_val);
    }
    ldap_value_free_len(vals);
    role = strdup(old_gecos);
    role = strtok(role, ";");
    /* move 2 positions along the string */
    for (i = 0; i < 2; i++) {
	role = strtok(NULL, ";");
    }
    char *mygecos = calloc(1, sizeof(char *));
    ERRNOMEM(mygecos);
    if (!snprintf
	(mygecos, GC_LEN, MY_GECOS, mdata.firstname, mdata.lastname, role))
	return NULL;
    
    return mygecos;
}
