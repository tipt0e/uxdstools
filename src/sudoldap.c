/* sudo ldap functions */

#include "uxds.h"
#include "uxds_strings.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "uxds_krb5.h"
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#ifdef TOOL_LOG
#include "uxds_log.h"
#endif				/* TOOL_LOG */

int rc;
int a;
int i;
char *dn;
struct berval **vals;

int uxds_sudo_add(uxds_authz_t auth, uxds_sudo_t * su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    char *cbuf = NULL;
    char **cmds;
    char **opts = NULL;
    char *su_dn;
    char *filter = (char *) calloc(1, (SU_LEN + 1));
    ERRNOMEM(filter);

    if (su->type == USER) {
	if (!snprintf
	    (filter, (strlen(POSIXACCOUNT) + strlen(su->sudoer) + 1),
	     POSIXACCOUNT, su->sudoer))
	    return 1;
    }
    if (su->type == GROUP) {
	if (!snprintf
	    (filter, (strlen(POSIXGROUP) + strlen(su->sudoer) + 1),
	     POSIXGROUP, su->sudoer))
	    return 1;
    }
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
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
	fprintf(stderr, "Account name %s not matched to any DN\n",
		su->sudoer);
	return 1;
    }

    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "SUDOer matched DN: %s\n", dn);
	ldap_memfree(dn);
    }
    if (su->type == GROUP) {
	su->sudoer = center(cbuf, "%", su->sudoer);
    }
    char *sudo_oc[] = {
	"top",
	"sudoRole",
	NULL
    };
    cmds = calloc(1, strlen(su->cmd) + 1);
    ERRNOMEM(cmds);
    a = 5;
    i = 0;
    cmds[i] = strtok(su->cmd, ",");
    i++;
    while ((cmds[i] = strtok(NULL, ",")) != NULL) {
	i++;
    }
    cmds[i++] = NULL;
    if (su->opt != NULL) {
	a++;
	opts = calloc(1, strlen(su->opt) + 1);
	ERRNOMEM(opts);
	i = 0;
	opts[i] = strtok(su->opt, ",");
	i++;
	while ((opts[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	opts[i++] = NULL;
    }

    /*
     * XXX dummy values are used here until uxds_acct_t
     * is changed to contain a union
     */
    uxds_attr_t sudo_attr[] = {
	{SUDOER, "objectClass", "dummy"},
	{SUDOER, "cn", su->sudoer},
	{SUDOER, "sudoUser", su->sudoer},
	{SUDOER, "sudoHost", "ALL"},
	{SUDOER, "sudoCommand", "dummy"},
	{SUDOER, "sudoOption", "dummy"},
	{0, NULL, NULL}
    };
    i = 0;
    while (sudo_attr[i].value != NULL) {
	i++;
    }
    i = i + 1;

    LDAPMod **sudoadd;
    sudoadd = (LDAPMod **) calloc(i, sizeof(LDAPMod *));
    ERRNOMEM(sudoadd);
    for (i = 0; sudo_attr[i].value != NULL; i++) {
	sudoadd[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	ERRNOMEM(sudoadd[i]);
	sudoadd[i]->mod_op = LDAP_MOD_ADD;
	sudoadd[i]->mod_type = sudo_attr[i].attrib;
	/* XXX */
	if (!strcmp(sudoadd[i]->mod_type, "objectClass")) {
	    sudoadd[i]->mod_values = sudo_oc;
	} else if (!strcmp(sudoadd[i]->mod_type, "sudoCommand")
            && (cmds)) {
	    sudoadd[i]->mod_values = cmds;
	} else if (!strcmp(sudoadd[i]->mod_type, "sudoOption")
            && (opts)) {
	    sudoadd[i]->mod_values = opts;
	} else {
	    sudoadd[i]->mod_values =
		calloc(2, strlen(sudo_attr[i].value) + 1);
	    ERRNOMEM(sudoadd[i]->mod_values);
	    sudoadd[i]->mod_values[0] = sudo_attr[i].value;
            if (!strcmp(sudoadd[i]->mod_values[0], "dummy")) {
                break; /* XXX foe sho */
            }
	}
    }
    sudoadd[i] = NULL;

    if (auth.basedn == NULL) {
	auth.basedn = UXDS_POSIX_OU;
    }
    /* 16 is len of "cn=" + ",ou=sudoers," + 1 for null byte */
    su_dn = calloc(1, strlen(su->sudoer) + strlen(auth.basedn) + 16);
    ERRNOMEM(su_dn);
    if (!snprintf(su_dn, strlen(su->sudoer) + strlen(auth.basedn) + 16,
            "%s%s%s%s", "cn=", su->sudoer, ",ou=sudoers,", auth.basedn))
        return 1;

    fprintf(stderr, "DN is %s\n", su_dn);
    if (ldap_add_ext_s(ld, su_dn, sudoadd, NULL, NULL) != LDAP_SUCCESS) {
	fprintf(stderr, "Attempted DN: %s, len %lu\n", su_dn,
		strlen(su_dn));
#ifdef TOOL_LOG
	log_event(su_dn, SUDOER, ADD, "attempt FAILED");
#endif				/* TOOL_LOG */
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
    }
    fprintf(stderr, "SUDOer Account %s ADDED.\n", su->sudoer);
#ifdef TOOL_LOG
    log_event(su_dn, SUDOER, ADD, "attempt SUCCESSFUL - IMPORTED");
#endif				/* TOOL_LOG */
    if (sudoadd) {
	for (i = 0; sudoadd[i] != NULL; i++) {
	    free(sudoadd[i]);
	}
    }
    ldap_msgfree(msg);
    free(su_dn);

    return 0;
}

int uxds_sudo_del(uxds_authz_t auth, uxds_sudo_t * su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    char *filter = (char *) calloc(1, (SU_LEN + 1));
    ERRNOMEM(filter);

    if (!snprintf(filter, SU_LEN, SUDOUSER, su->sudoer))
	return 1;
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
			  NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
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
	fprintf(stderr, "SUDOer Account name %s not matched to any DN\n",
		su->sudoer);
	return 1;
    }
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "SUDOer matched DN: %s\n", dn);
    }
    if (ldap_delete_ext_s(ld, dn, NULL, NULL) != LDAP_SUCCESS) {
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
#ifdef TOOL_LOG
	log_event(dn, SUDOER, DEL, "attempt FAILED");
#endif				/* TOOL_LOG */
	fprintf(stderr, "SUDOer Account deletion UNSUCCESSFUL.");
	return 1;
    }
    fprintf(stderr, "SUDOer Account %s DELETED.\n", su->sudoer);
#ifdef TOOL_LOG
    log_event(dn, SUDOER, DEL, "attempt SUCCESSFUL - DELETED");
#endif				/* TOOL_LOG */
    if (msg)
	ldap_msgfree(msg);

    return 0;

}

int uxds_sudo_mod(uxds_authz_t auth, uxds_sudo_t * su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    int c;
    char *su_dn;
    char **cmds = NULL;
    char **opts = NULL;
    char *filter = (char *) calloc(1, (SU_LEN + 1));
    ERRNOMEM(filter);

    if (!snprintf(filter, SU_LEN, SUDOUSER, su->sudoer))
	return 1;
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
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
	fprintf(stderr, "SUDOer Account name %s not matched to any DN\n",
		su->sudoer);
	return 1;
    }
    if ((dn = ldap_get_dn(ld, entry)) != NULL) {
	fprintf(stderr, "SUDOer matched DN: %s\n", dn);
    }
    a = 1;
    i = 0;
    if (su->cmd != NULL) {
	cmds = calloc(1, strlen(su->cmd) + 1);
	ERRNOMEM(cmds);
	cmds[i] = strtok(su->cmd, ",");
	i++;
	while ((cmds[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	cmds[i++] = NULL;
	a++;
    }
    i = 0;
    if (su->opt != NULL) {
	a++;
	opts = calloc(1, strlen(su->opt) + 1);
	ERRNOMEM(opts);
	opts[i] = strtok(su->opt, ",");
	i++;
	while ((opts[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	opts[i++] = NULL;
	a++;
    }
    a = a + 2;

    LDAPMod **sudomod;
    sudomod = (LDAPMod **) calloc(a, sizeof(LDAPMod *));
    ERRNOMEM(sudomod);
    for (i = 0; i < a; i++) {
	sudomod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	ERRNOMEM(sudomod[i]);
	if (su->tool == DEL) {
	    sudomod[i]->mod_op = LDAP_MOD_DELETE;
        } else {
	    sudomod[i]->mod_op = LDAP_MOD_ADD;
	}
    }

    c = 0;
    if (su->cmd != NULL) {
	sudomod[c]->mod_type = "sudoCommand";
	sudomod[c]->mod_values = cmds;
	c++;
    }
    if (su->opt != NULL) {
	sudomod[c]->mod_type = "sudoOption";
	sudomod[c]->mod_values = opts;
	c++;
	sudomod[c] = NULL;
    } else {
	sudomod[c] = NULL;
    }
    if (auth.basedn == NULL) {
	auth.basedn = strdup(UXDS_POSIX_OU);
    }
    su_dn = calloc(1, strlen(su->sudoer) + strlen(auth.basedn) + 16);
    ERRNOMEM(su_dn);
    if (!snprintf(su_dn, strlen(su->sudoer) + strlen(auth.basedn) + 16,
            "%s%s%s%s", "cn=", su->sudoer, ",ou=sudoers,", auth.basedn)) 
        return 1;

    if (ldap_modify_ext_s(ld, su_dn, sudomod, NULL, NULL) != LDAP_SUCCESS) {
	fprintf(stdout, "Attempted DN: %s, len %lu\n", su_dn,
		strlen(su_dn));
#ifdef TOOL_LOG
	log_event(su_dn, SUDOER, MOD, "attempt FAILED");
#endif				/* TOOL_LOG */
	ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
	fprintf(stderr, "%s: %s\n", res, ldap_err2string(rc));
	return 1;
    }
    fprintf(stdout, "SUDOer Account Modification of %s SUCCESSFUL.\n",
	    su->sudoer);
#ifdef TOOL_LOG
    log_event(su_dn, SUDOER, MOD, "attempt SUCCESSFUL");
#endif				/* TOOL_LOG */
    if (sudomod) {
	for (i = 0; sudomod[i] != NULL; i++) {
	    free(sudomod[i]);
	}
    }
    free(su_dn);
    if (msg)
	ldap_msgfree(msg);

    return 0;
}
