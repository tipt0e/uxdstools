/* krb.h */

/* get short principal name from krb5 creds cache */
char *get_krbname(uxds_authz_t auth, int parse);
/* lazy kinit */
krb5_error_code get_tkts(char *user, char *service, uxds_authz_t auth);
/* set password krb5Key */
krb5_error_code setpwd(char *user, char *passwd);
