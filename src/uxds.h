/*
 * ******* ltools.h ********
 *
 *   header file for:
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

/* std headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>		/* struct timeval: OpenLDAP future use */
#include <parse_time.h>
#include <errno.h>		/* ENOMEM, etc. */
#include <ctype.h>
#include <err.h>
#include <unistd.h>		/* is necessary?? */
#include <termios.h>		/* need to tweak for Sun */
#include <krb5.h>		/* Heimdal kerberos */
#include <lber.h>		/* future use */
#include <ldap.h>		/* OpenLDAP header */
#include <sys/wait.h>
#include "config.h"
#include "realm.h"
#define rpl_malloc malloc
/* config.h */

#ifdef HAVE_LDAP_SASL
#  ifdef HAVE_SASL_SASL_H
#    include <sasl/sasl.h>
#  elif defined (HAVE_SASL_H)
#    include <sasl.h>
#  else
#    undef HAVE_LDAP_SASL
#  endif			/* HAVE_SASL_SASL_H */
#endif				/* HAVE_LDAP_SASL */
#if SASL_VERSION_MAJOR < 2
#  undef HAVE_LDAP_SASL
#endif				/* maybe a fart */
#ifdef HAVE_LDAP_SASL_GSSAPI
#  ifdef HAVE_KRB5_H
#    ifdef HAVE_LIBKRB5
#      include <krb5.h>
#    else
#      undef HAVE_LDAP_SASL_GSSAPI
#    endif			/* HAVE_LIBKRB5 */
#  endif			/* HAVE_KRB5_H */
#endif				/* HAVE_LDAP_SASL_GSSAPI */
#ifdef HAVE_AFS
#include <kafs.h>
#endif 	/* HAVE_AFS */

/* 
 * mikro-net defaults if no realm chosen 
 *
 * "all the king's horses &\all the king's men\";
 *
 */

#ifndef AT_EMAIL
#define AT_EMAIL 	"@mikro-net.com"
#endif				/* AT_EMAIL */
#ifndef AT_REALM
#define AT_REALM 	"@MIKRO-NET.COM"
#endif				/* AT_REALM */
#ifndef UXDS_POSIX_OU
#define UXDS_POSIX_OU 	"ou=unix,dc=mikro-net,dc=com"
#endif				/* UXDS_POSIX_OU */
#ifndef UXDS_LOG
#define UXDS_LOG	"/tmp/utools.log"
#endif				/* UXDS_LOG */

/* search filters  */
/* -> LEFT sides for center() */
#define POSIXACCOUNT  "(&(objectclass=posixAccount)(uid="
#define POSIXGROUP    "(&(objectclass=posixGroup)(cn="
#define SUDOUSER      "(&(objectclass=sudoRole)(sudoUser="
/* sort IDNUM logic for highest choice */
#define UIDNUM        "(&(objectclass=posixAccount)(uidNumber=*))"
#define GIDNUM        "(&(objectclass=posixGroup)(gidNumber=*))"

/* boolean for parsing - get_krbname() */
#define FALSE	0
#define TRUE	1

/* account type */
typedef enum { SELF, USER, GROUP, SUDOER } usrt;

/* authentication data, holds parsedata for ease */
typedef struct {
    int debug;			/* debug flag */
    int verb;			/* SASL verbose if 1 */
    char *ldif;			/* ldif export flag */
    char *l_uri;		/* LDAP host URI if not default */
    char *realm;		/* SASL realm - optional */
    char *username;		/* SASL authcid */
    struct berval *password;	/* Simple or SASL Bind */
    char *binddn;		/* Simple bind DN or SASL authzid when "dn:DN" */
#ifdef HAVE_LDAP_SASL
    char *s_mech;		/* SASL mechanism */
#ifdef HAVE_LDAP_SASL_GSSAPI
    char *credcache;		/* Krb5 credentials cache */
    char *pkcert;               /* PK-INIT certificate */
#endif  /* HAVE_LDAP_SASL_GSSAPI */
#endif  /* HAVE_LDAP_SASL */
    usrt acct;			/* account type marker */
    char *pxacct;		/* account to parse */
    char *basedn;		/* base dn for ops */
} authzdata;

/* options to parse cmd line input and process output :*/
typedef enum { U, H, V } useout;

typedef enum { ADD, MOD, DEL, EYE } toolop;

typedef enum { XARGS, XACCT, XBOTH, XBIND } optflag;

struct cmdopts {
    int dash;			/* parse '-' */
    int letter;			/* optarg */
    char *chosen;		/* switch argument */
    char *binary;		/* argv[0] */
};

/* account data passed to LDAPMod structs */
struct mod_data {
    int _entry;			/* calc args for op */
    int modrdn;			/* flag for modrdn op */
    int membit;			/* flag for memberUid add/del */
    int cpw;			/* change pwd flag */
    int exp;			/* expire pwd flag */
    char *user;			/* user to add/modify */
    char *group;		/* group to ditto */
    char *ou;			/* ou if selected */
#ifdef QMAIL
    char *mhost;		/* mailhost for qmail */
    char *altaddr;		/* alt mail address for qmail */
#endif				/* QMAIL */
    char *firstname;		/* givenName */
    char *lastname;		/* sn */
    char *uidnum;		/* uidNumber */
    char *gidnum;		/* gidNumber */
    char *homes;		/* homeDirectory */
    char *shell;		/* loginShell */
    char *member;		/* memberUid */
    char *comment;		/* group description */
    char *setpass;		/* set password to a string */
    struct sudoers *su;		/* sudoers data */
};

/* sudoers data so parse_argvs() can get it from mod_data */
struct sudoers {
    toolop tool;		/* operation performed */
    char *ou;			/* OU for SUDOers */
    char *sudoer;		/* sudoer name (sudoUser) */
    char *cmd_s;		/* sudoCommand */
    char *opt_s;		/* sudoOption */
    usrt type;			/* USER = 1 or GROUP = 2 */
};

/* menu option output handler */
void optmask(char *argt, usrt type, struct cmdopts opts, optflag flag);

/* usage and help output */
void usage(useout mflag, char *binary, usrt atype, toolop op);

/* parse command line args */
int parse_argvs(int argc, char **argv, usrt atype, toolop op, int arg_n,
		authzdata * auth, struct mod_data *mdata, char *binary);

/* LDAP authorization handler */
int uxds_user_authz(int select, authzdata auth, LDAP * ld);

/* unbind form directory service */
int uxds_ldap_unbind(LDAP * ld);

/* parse account handler */
int uxds_acct_parse(int bindtype, authzdata auth, LDAP * ld);

/* add del mod POSIX account functions */
int uxds_acct_add(usrt pxtype, struct mod_data mdata, LDAP * ld);

int uxds_acct_del(usrt pxtype, struct mod_data mdata, LDAP * ld);

int uxds_acct_mod(usrt pxtype, struct mod_data mdata, LDAP * ld);

/* memberUid attribute manipulation */
int uxds_grp_mem(int debug, toolop op, char *user, char *grpdn, LDAP * ld);

/* expire password */
int uxds_user_expire(int type, char *dn, LDAP * ld);

/* SUDOer add mod del functions */
int uxds_sudo_add(authzdata auth, struct sudoers *su, LDAP * ld);

int uxds_sudo_del(authzdata auth, struct sudoers *su, LDAP * ld);

int uxds_sudo_mod(authzdata auth, struct sudoers *su, LDAP * ld);
