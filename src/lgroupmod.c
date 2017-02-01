/*
 * UNIX Directory Service POSIX Group Account Modify
 * (c) 2008-2017 Michael Brown
 *
 *   Part of:
 *
 * --UXDSTOOLS-SUITE-------------------------------------------------
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
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
    uxds_bind_t sflag;
    uxds_authz_t auth;
    uxds_data_t mdata;
    char *bin = argv[0];
    sflag = parse_args(argc, argv, GROUP, MOD, 7, &auth, &mdata, bin);

    /* initialize LDAP context */
    rc = ldap_initialize(&ld, auth.uri);
    if (rc != LDAP_SUCCESS) {
	fprintf(stderr, "Could not create LDAP session handle (%d): %s\n",
		rc, ldap_err2string(rc));
	exit(EXIT_FAILURE);
    }

    /* authenticate */
    if (uxds_user_authz(sflag, auth, ld) != 0) {
	fprintf(stderr, "uxds_user_authz failed.\n");
	exit(EXIT_FAILURE);
    }

    /* modify operation */
    if (uxds_acct_mod(GROUP, mdata, ld) != 0) {
	fprintf(stderr, "uxds_acct_mod GROUP MODIFY failed.\n");
	exit(EXIT_FAILURE);
    }

    /* unbind from ds */
    if (uxds_ldap_unbind(ld) != 0) {
	fprintf(stderr, "uxds_ldap_unbind failed.\n");
	exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}
