/* krb.h */

/* get short principal name from krb5 creds cache */
char *get_krbname(uxds_authz_t auth, int parse);
/* lazy kinit */
int get_tkts(char *user, char *service, uxds_authz_t auth);
/* set password krb5Key */
int setpwd(char *user, char *passwd);
