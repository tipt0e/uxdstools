/* sudo ldap functions */

#include "uxds.h"
#include "strings.h"
#ifdef HAVE_LDAP_SASL_GSSAPI
#include "krb5.h"
#endif  /* HAVE_LDAP_SASL_GSSAPI */
#ifdef TOOL_LOG
#include "log.h"
#endif  /* TOOL_LOG */

int rc;
char *res;
struct berval **vals;

int uxds_sudo_add(authzdata auth, struct sudoers *su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    int i;
    int a;
    char *dn;
    char *cbuf = NULL;
    char **cmds;
    char **opts = NULL;
    char *filter = NULL;
    char *su_dn;

    if (su->type == USER) {
	filter =
	    strdup(center
		   (cbuf, center(cbuf, POSIXACCOUNT, su->sudoer), "))"));
    }
    if (su->type == GROUP) {
	filter =
	    strdup(center
		   (cbuf, center(cbuf, POSIXGROUP, su->sudoer), "))"));
    }
    center_free(cbuf);
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
                          NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
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
	fprintf(stderr, "SUDOer matched DN: %s\n\n", dn);
	center_free(cbuf);
	ldap_memfree(dn);
    }
    if (su->type == GROUP) {
	su->sudoer = center(cbuf, "%", su->sudoer);
    }
    char *_objectclass[] = { "top", "sudoRole", NULL };
    char *_cn[] = { su->sudoer, NULL };
    char *_sudouser[] = { su->sudoer, NULL };
    char *_sudohost[] = { "ALL", NULL };
    cmds = calloc(1, strlen(su->cmd_s) + 1);
    a = 5;
    i = 0;
    cmds[i] = strtok(su->cmd_s, ",");
    i++;
    while ((cmds[i] = strtok(NULL, ",")) != NULL) {
	i++;
    }
    cmds[i++] = NULL;
    if (su->opt_s != NULL) {
	a++;
	opts = calloc(1, strlen(su->opt_s) + 1);
	i = 0;
	opts[i] = strtok(su->opt_s, ",");
	i++;
	while ((opts[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	opts[i++] = NULL;
    }
    a = a + 2;

    //LDAPMod objectClass, cn, sudoUser, sudoHost, sudoCommand, sudoOption;

    LDAPMod **sudoadd;
    sudoadd = (LDAPMod **) calloc(a, sizeof(LDAPMod *));
    for (i = 0; i < a; i++) {
	sudoadd[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	sudoadd[i]->mod_op = LDAP_MOD_ADD;
	if (sudoadd[i] == (LDAPMod *) NULL) {
	    fprintf(stderr, "malloc ERROR!\n");
	    exit(ENOMEM);
	}
    }
    sudoadd[0]->mod_type = "objectClass";
    sudoadd[0]->mod_values = _objectclass;
    sudoadd[1]->mod_type = "cn";
    sudoadd[1]->mod_values = _cn;
    sudoadd[2]->mod_type = "sudoUser";
    sudoadd[2]->mod_values = _sudouser;
    sudoadd[3]->mod_type = "sudoHost";
    sudoadd[3]->mod_values = _sudohost;
    sudoadd[4]->mod_type = "sudoCommand";
    sudoadd[4]->mod_values = cmds;
    if (su->opt_s != NULL) {
	sudoadd[5]->mod_type = "sudoOption";
	sudoadd[5]->mod_values = opts;
	sudoadd[6] = NULL;
    } else {
	sudoadd[5] = NULL;
    }
    if (auth.basedn == NULL) {
	auth.basedn = strdup(UXDS_POSIX_OU);
    }
    su_dn =
	center(cbuf,
	       center(cbuf, center(cbuf, "cn=", su->sudoer),
		      ",ou=sudoers,"), auth.basedn);
    fprintf(stderr, "DN is %s\n", su_dn);
    if (ldap_add_ext_s(ld, su_dn, sudoadd, NULL, NULL) != LDAP_SUCCESS) {
	fprintf(stderr, "Attempted DN: %s, len %lu\n", su_dn,
		strlen(su_dn));
#ifdef TOOL_LOG
	log_event(su_dn, SUDOER, ADD, "attempt FAILED");
#endif				/* TOOL_LOG */
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
    }
    fprintf(stderr, "SUDOer Account %s ADDED.\n", su->sudoer);
#ifdef TOOL_LOG
    log_event(su_dn, SUDOER, ADD, "attempt SUCCESSFUL - IMPORTED");
#endif				/* TOOL_LOG */
    //ldap_mods_free(sudoadd, 1);
    free(filter);

    return 0;
}

int uxds_sudo_del(authzdata auth, struct sudoers *su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    char *dn;
    char *cbuf = NULL;
    char *filter = NULL;

    filter =
	strdup(center(cbuf, center(cbuf, SUDOUSER, su->sudoer), "))"));
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0, 
                          NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
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
	fprintf(stderr, "SUDOer matched DN: %s\n\n", dn);
	center_free(cbuf);
    }
    if (ldap_delete_ext_s(ld, dn, NULL, NULL) != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
#ifdef TOOL_LOG
	log_event(dn, SUDOER, DEL, "attempt FAILED");
#endif				/* TOOL_LOG */
	fprintf(stderr, "SUDOer Account deletion UNSUCCESSFUL.");
	exit(EXIT_FAILURE);
    }
    fprintf(stderr, "SUDOer Account %s DELETED.\n", su->sudoer);
#ifdef TOOL_LOG
    log_event(dn, SUDOER, DEL, "attempt SUCCESSFUL - DELETED");
#endif				/* TOOL_LOG */

    return 0;

}

int uxds_sudo_mod(authzdata auth, struct sudoers *su, LDAP * ld)
{
    LDAPMessage *msg;
    LDAPMessage *entry;

    int i;
    int a;
    int c;
    char *dn;
    char *cbuf = NULL;
    char *su_dn;
    char **cmds = NULL;
    char **opts = NULL;
    char *filter = NULL;

    filter =
	strdup(center(cbuf, center(cbuf, SUDOUSER, su->sudoer), "))"));
    if (auth.debug)
	fprintf(stderr, "filter is %s, len %lu\n", filter, strlen(filter));
    if (ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUBTREE, filter, NULL, 0,
                          NULL, NULL, NULL, 0,  &msg) != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
	return 1;
    }
    if (auth.debug) {
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
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
	fprintf(stderr, "SUDOer matched DN: %s\n\n", dn);
	center_free(cbuf);
    }
    a = 1;
    i = 0;
    if (su->cmd_s != NULL) {
	cmds = calloc(1, strlen(su->cmd_s) + 1);
	cmds[i] = strtok(su->cmd_s, ",");
	i++;
	while ((cmds[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	cmds[i++] = NULL;
	a++;
    }
    i = 0;
    if (su->opt_s != NULL) {
	a++;
	opts = calloc(1, strlen(su->opt_s) + 1);
	opts[i] = strtok(su->opt_s, ",");
	i++;
	while ((opts[i] = strtok(NULL, ",")) != NULL) {
	    i++;
	}
	opts[i++] = NULL;
	a++;
    }
    a++;

    //LDAPMod sudoCommand, sudoOption;

    LDAPMod **sudomod;
    sudomod = (LDAPMod **) calloc(a, sizeof(LDAPMod *));
    for (i = 0; i < a; i++) {
	sudomod[i] = (LDAPMod *) malloc(sizeof(LDAPMod));
	if (su->tool == DEL) {
	    sudomod[i]->mod_op = LDAP_MOD_DELETE;
	} else {
	    sudomod[i]->mod_op = LDAP_MOD_ADD;
	}
	if (sudomod[i] == (LDAPMod *) NULL) {
	    fprintf(stderr, "malloc ERROR!\n");
	    exit(ENOMEM);
	}
    }

    c = 0;
    if (su->cmd_s != NULL) {
	sudomod[c]->mod_type = "sudoCommand";
	sudomod[c]->mod_values = cmds;
	c++;
    }
    if (su->opt_s != NULL) {
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
    su_dn =
	center(cbuf,
	       center(cbuf, center(cbuf, "cn=", su->sudoer),
		      ",ou=sudoers,"), auth.basedn);

    if (ldap_modify_ext_s(ld, su_dn, sudomod, NULL, NULL) != LDAP_SUCCESS) {
	fprintf(stdout, "Attempted DN: %s, len %lu\n", su_dn,
		strlen(su_dn));
#ifdef TOOL_LOG
	log_event(su_dn, SUDOER, MOD, "attempt FAILED");
#endif				/* TOOL_LOG */
        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
        fprintf(stderr, "%s: %s", res, ldap_err2string(rc));
	return 1;
    }
    fprintf(stdout, "SUDOer Account Modification of %s SUCCESSFUL.\n",
	    su->sudoer);
#ifdef TOOL_LOG
    log_event(su_dn, SUDOER, MOD, "attempt SUCCESSFUL");
#endif				/* TOOL_LOG */

    return 0;
}
