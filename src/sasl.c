/* sasl functions */

#include "uxds.h"
#ifdef HAVE_LDAP_SASL
#include <sasl/sasl.h>
#include "uxds_sasl.h"

/* get SASL callbacks */
int uxds_sasl_interact(LDAP * ld, unsigned flags, void *defaults,
			void *in)
{
    uxds_authz_t *auth = (uxds_authz_t *) defaults;

    sasl_interact_t *interact = (sasl_interact_t *) in;
    if (ld == NULL)
	return LDAP_PARAM_ERROR;

    while (interact->id != SASL_CB_LIST_END) {
	if (auth->debug)
	    fprintf(stderr, "sasl callback is: %lu\n", interact->id);
	interact->defresult = calloc(1, sizeof(sasl_interact_t));

	switch (interact->id) {
	case SASL_CB_GETREALM:
	    if (auth->debug)
		fprintf(stderr,
			"uxds_sasl_interact asked for SASL_CB_GETREALM, returned %s\n",
			auth->realm);
	    interact->defresult = auth->realm;
	    break;
	case SASL_CB_AUTHNAME:
	    if (auth->debug)
		fprintf(stderr,
			"uxds_sasl_interact asked for SASL_CB_AUTHNAME, returned %s\n",
			auth->binddn);
	    interact->defresult = auth->binddn;
	    break;
	case SASL_CB_PASS:
	    if (auth->debug)
		fprintf(stderr,
			"uxds_sasl_interact asked for SASL_CB_PASS, returned <HIDDEN>\n");
	    /* auth->password); */
	    interact->defresult = auth->password->bv_val;
	    break;
	case SASL_CB_USER:
	    if (auth->debug)
		fprintf(stderr,
			"uxds_sasl_interact asked for SASL_CB_USER, returned %s\n",
			auth->username);
	    interact->defresult = auth->username;
	    if (auth->debug)
		fprintf(stderr,
			"attempting SASL bind using user %s credentials\n",
			auth->username);
	    break;
	default:
	    if (auth->debug)
		fprintf(stderr,
			"uxds_sasl_interact asked for unknown %lu\n",
			interact->id);
	    break;
	}
	interact->result = (interact->defresult
			    && *interact->defresult) ? interact->
	    defresult : (char *) "";
	interact->len = strlen((char *) interact->result);

	interact++;
    }
    return LDAP_SUCCESS;
}
#endif				/* HAVE_LDAP_SASL */
