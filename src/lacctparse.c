/*
 * UNIX Directory Service Account Parser
 * (c) 2008-2010 Michael Brown
 *
 *
 *   Part of:
 *
 * --UXDSTOOLS-SUITE-------------------------------------------------
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uxds.h"

int main(int argc, char *argv[])
{
    LDAP *ld;
    int rc;
    int sflag;
    authzdata auth;
    char *bin = argv[0];
    sflag = parse_argvs(argc, argv, SELF, EYE, 3, &auth, NULL, bin);

    /* initialize LDAP context */
    rc = ldap_initialize(&ld, auth.l_uri);
    if(rc != LDAP_SUCCESS) {
	fprintf(stderr, "Could not create LDAP session handle (%d): %s\n",
		rc, ldap_err2string(rc));
	exit(EXIT_FAILURE);
    }

    /* authenticate and bind to ds */
    if (uxds_user_authz(sflag, auth, ld) != 0) {
	fprintf(stderr, "uxds_user_authz failed.\n");
	exit(EXIT_FAILURE);
    }
    /* parse selected account */
    if (uxds_acct_parse(sflag, auth, ld) != 0) {
	fprintf(stderr, "uxds_acct_parse failed.\n");
	exit(EXIT_FAILURE);
    }
    /* unbind from ds when request completed */
    if (uxds_ldap_unbind(ld) != 0) {
	fprintf(stderr, "uxds_ldap_unbind failed.\n");
	exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}