/* krb5 functions */

#include "uxds.h"
#ifdef HAVE_LDAP_SASL_GSSAPI

/* get user principal name or ccache location 
 * from krb5 ccache (parse = 0|1)
 */
char *get_krbname(authzdata auth, int parse)
{
    krb5_context context;
    krb5_error_code error;
    krb5_ccache id;
    krb5_creds creds;

    char *buf;
    char *value;

    if (krb5_init_context(&context) != 0) {
	errx(1, "krb5_context");
    }
    error = krb5_cc_default(context, &id);
    if (error) {
	krb5_err(context, 1, error, "krb5_cc_default");
    }
    if (parse == 1) {
	value = strdup(krb5_cc_default_name(context));
	krb5_cc_close(context, id);
	krb5_free_context(context);
	/* return the ccache loc */
	return value;
    }
    auth.credcache = strdup(krb5_cc_default_name(context));
    if (auth.credcache == NULL) {
	errx(1, "krb5_cc_default_name");
    }
    if (auth.debug)
	fprintf(stderr,
		"credentials cache pulled from krb5_cc_default_name: %s\n",
		auth.credcache);

    error = krb5_cc_get_principal(context, id, &creds.client);
    if (error) {
	krb5_err(context, 1, error, "krb5_cc_get_principal");
    }
    if (parse == 0) {
	error =
	    krb5_unparse_name_flags(context, creds.client,
				    KRB5_PRINCIPAL_UNPARSE_NO_REALM, &buf);
    } else {
	error =
	    krb5_unparse_name_flags(context, creds.client,
				    KRB5_PRINCIPAL_UNPARSE_DISPLAY, &buf);
    }

    if (error) {
	krb5_err(context, 1, error, "krb5_unparse_name_flags");
    }
    value = strdup(buf);
    if (auth.debug)
	fprintf(stderr, "krb5_unparse_name_flags returned %s\n", value);
    krb5_cc_close(context, id);
    krb5_free_context(context);
    free(buf);

    return value;
}

/* get krb5 initial ticket for service */
int get_tkts(char *user, char *service, authzdata auth)
{
    krb5_context context;
    krb5_error_code error;
    //krb5_prompt prompt;
    krb5_get_init_creds_opt *opt;
    krb5_creds cred;
    krb5_ccache ccache;
    krb5_deltat start_time = 0;	/* start now */
    krb5_deltat ticket_life = 1860;	/* 31 minutes */
    /* krb5_deltat renew = 0;  future use */
    /* krb5_enctype *enctype = NULL; future use */
    krb5_principal target;
    char *buf = NULL;

#if 0
#ifdef HAVE_AFS
    if (k_hasafs()) {
        if (k_setpag() != 0) {
            fprintf(stderr, "Unable to create PAG\n");
        }
    }  
#endif   /* HAVE_AFS */
#endif
    /* needed for krb5_posix_prompter */
    /*prompt.prompt = "Enter Kerberos Password:";
     *prompt.hidden = 1;
     *prompt.type = KRB5_PROMPT_TYPE_PREAUTH;
     */

    /* initialize context from krb5.conf */
    if (krb5_init_context(&context) != 0) {
	errx(1, "krb5_context");
    }
    /* get defaults from krb5.conf */
    error = krb5_cc_default(context, &ccache);
    if (error) {
	krb5_err(context, 1, error, "krb5_cc_default");
    }
    /* set our value for below debug */
    auth.credcache = strdup(krb5_cc_default_name(context));
    if (auth.credcache == NULL) {
	errx(1, "krb5_cc_default_name");
    }
    if (auth.debug)
	fprintf(stderr,
		"credentials cache pulled from krb5_cc_default_name: %s\n",
		auth.credcache);
    /* set desired principal to user name from authzdata */
    error = krb5_parse_name(context, user, &target);
    if (error) {
	krb5_err(context, 1, error, "krb5_parse_name");
    }
    /* just checking to see if its the same */
    if (auth.debug) {
	error =
	    krb5_unparse_name_flags(context, target,
				    KRB5_PRINCIPAL_UNPARSE_NO_REALM, &buf);
	fprintf(stderr, "%s is short principal name pulled from ccache\n",
		buf);
	free(buf);
	error =
	    krb5_unparse_name_flags(context, target,
				    KRB5_PRINCIPAL_UNPARSE_DISPLAY, &buf);
	fprintf(stderr,
		"%s is the full principal name pulled from ccache\n", buf);
	free(buf);
    }
    /* clear our cred cache */
    memset(&cred, 0, sizeof(cred));
    /* we are setting non-default ticket life so we have to alloc our own creds struct */
    error = krb5_get_init_creds_opt_alloc(context, &opt);
    if (error) {
	krb5_err(context, 1, error, "krb5_get_init_creds_opt_alloc");
    }
    /* set "kinit" */
    krb5_get_init_creds_opt_set_default_flags(context, "kinit",
					      krb5_principal_get_realm
					      (context, target), opt);
    /* ticket_life = 31 minutes */
    krb5_get_init_creds_opt_set_tkt_life(opt, ticket_life);
    /* circumventing krb5_prompter_posix() with getpwd() */
    krb5_get_init_creds_opt_set_pa_password(context, opt, auth.password->bv_val,
					    NULL);

    /* set up auth */
    error = krb5_get_init_creds_password(context, &cred, target, NULL, NULL,	/* <- krb5_prompter_posix, */
					 NULL, start_time, service, opt);
    if (error) {
	krb5_err(context, 1, error, "krb5_get_init_creds_password");
    }
    krb5_get_init_creds_opt_free(context, opt);
    /* is the password good ? */
    switch (error) {
    case 0:
	break;
    case KRB5_LIBOS_PWDINTR:
	exit(EXIT_FAILURE);
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:
    case KRB5KRB_AP_ERR_MODIFIED:
    case KRB5KDC_ERR_PREAUTH_FAILED:
	krb5_errx(context, 1, "Password incorrect");
	break;
    case KRB5KRB_AP_ERR_V4_REPLY:
	krb5_errx(context, 1, "Kerberos 4 reply no good");
	break;
    default:
	krb5_err(context, 1, error, "krb5_get_init_creds");
    }
    /* just checking the lifetime of the tkt */
    if (auth.debug) {
	if (ticket_life != 0) {
	    char life[64];
	    unparse_time_approx(cred.times.endtime - cred.times.starttime,
				life, sizeof(life));
	    krb5_warnx(context, "NOTICE: ticket lifetime is %s", life);
	}
    }
    /* save our cred to default cache location */
    error = krb5_cc_initialize(context, ccache, target);

    if (auth.debug)
	fprintf(stderr, "initializing creds cache\n");

    if (error)
	krb5_err(context, 1, error, "krb5_cc_initialize");

    if (auth.debug)
	fprintf(stderr, "storing credential in %s\n", auth.credcache);

    error = krb5_cc_store_cred(context, ccache, &cred);
    if (error)
	krb5_err(context, 1, error, "krb5_cc_store_cred");
#ifdef HAVE_AFS
    if (k_hasafs()) 
        krb5_afslog(context, ccache, NULL, NULL);  
#endif 	/* HAVE_AFS */

#if 0
/*
 * good test here to grab more creds with tgt ---->
 * kadmin/admin is just an example
 * host/hostname, HTTP/hostname are other possibilities
 */
    if((mdata.cpw == 1) || (mdata.setpass != NULL)) {
        memset(&opt, 0, sizeof(opt));
        memset(&cred, 0, sizeof(cred));
	putenv("KRB5CCNAME=/tmp/kadmin_cache");

        error = krb5_make_principal(context, &kadmin, NULL, "kadmin", "admin", NULL);
        if(error)
            krb5_err(context, 1, error, "krb5_make_principal");

        error = krb5_get_creds_opt_alloc(context, &opt);
        if(error)
            krb5_err(context, 1, error, "krb5_get_creds_opt_alloc");

        // add options here
        //krb5_get_creds_opt_add_options(context, opt, KRB5_GC_FORWARDABLE);
        //krb5_get_creds_opt_add_options(context, opt, KRB5_GC_CONSTRAINED_DELEGATION);

        error = krb5_get_creds(context, opt, ccache, kadmin, &cred);
        if(error)
            krb5_err(context, 1, error, "krb5_get_creds");

        memset(&cred, 0, sizeof(cred));
       
    }
#endif
    krb5_free_cred_contents(context, &cred);

    /*
    if (enctype)
	free(enctype);
    */

    krb5_cc_close(context, ccache);
    krb5_free_context(context);

    return 0;
}

/* 
 * sets password for luseradd/mod
 * uses /tmp/kacache_%uid and is valid for 5 minutes
 * uses randstr() in strings.c for passwd (for now)
 * and depends on putenv() to locate the cache for ctx
 * randstr() could be moved in here if no 2nd arg desired 
 * is was just placed for future use (i.e. pwds on cmd line)
 */
int setpwd(char *user, char *passwd)
{
    krb5_context context;
    krb5_principal target;
    krb5_ccache ccache;
    krb5_error_code error;
    krb5_data result_code_string, result_string;
    int result_code;

    krb5_data_zero(&result_code_string);
    krb5_data_zero(&result_string);

    if (krb5_init_context(&context) != 0) {
	errx(1, "krb5_context");
    }
    error = krb5_cc_default(context, &ccache);
    if (error) {
	krb5_err(context, 1, error, "krb5_cc_default");
    }

    /* it had better be /tmp/kacache_%uid or putenv() failed -->
     * fprintf(stderr,"%s is ccache\n",strdup(krb5_cc_default_name(context)));
     */ 

    error = krb5_parse_name(context, user, &target);

    if (error) {
	krb5_err(context, 1, error, "krb5_parse_name");
    }

    /* passwd = randstr() or mdata.setpass, depending */
    error = krb5_set_password_using_ccache(context, ccache, passwd, target,
					   &result_code,
					   &result_code_string,
					   &result_string);

    if (error) {
	krb5_warn(context, error, "krb5_set_password_using_ccache");
	return 1;
    }
    /* success - ripped from heimdal kpasswd.c */
    if (result_code != 0) {
	printf("%s%s%.*s\n",
	       krb5_passwd_result_to_string(context, result_code),
	       result_string.length > 0 ? " : " : "",
	       (int) result_string.length,
	       result_string.length >
	       0 ? (char *) result_string.data : "");
    }
    printf("%s's Password set to \"%s\"\n", user, passwd);

    krb5_data_free(&result_code_string);
    krb5_data_free(&result_string);

    //krb5_cc_destroy(context, ccache);
    krb5_cc_close(context, ccache);
    krb5_free_context(context);
    /* if you want to delete or keep it is good for 5 min */
    //unlink("/tmp/kadmin_cache");

    return error != 0;
}

#endif				/* #ifdef HAVE_LDAP_SASL_GSSAPI */