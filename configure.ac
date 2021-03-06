dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(uxdstools,0.8-git,ronin.crip@gmail.com) 

AC_CONFIG_SRCDIR([src/krb5.c])
AC_CONFIG_HEADER([src/config.h])

AC_ARG_ENABLE(sasl,
[  --enable-sasl           compile with support for Cyrus SASL],
    [SASL="$enableval"],
    [SASL="yes"
    if test "$SASL" = "no"; then
        echo "SASL disabled....."
    fi
    if test "$SASL" = "yes"; then
        AC_DEFINE(HAVE_LDAP_SASL, 1, [Compile with Cyrus SASL support])
        echo "SASL support selected....."
    fi]

)
dnl   AC_DEFINE(DISABLE_WITH_SASL)
AC_ARG_ENABLE(gssapi,
[  --enable-gssapi         compile with support for Heimdal Kerberos],
    [GSSAPI="$enableval"],
    [GSSAPI="yes"
    KRB5="yes"
    if test "$SASL" = "no"; then
        GSSAPI="no"
        echo "SASL disabled, disabling support for GSSAPI....."
    else
        if test "$GSSAPI" = "yes"; then
            AC_DEFINE(HAVE_LDAP_SASL_GSSAPI, 1, [Compile with Heimdal Kerberos support])
            echo "GSSAPI (Heimdal) support selected....."
        else
            echo "GSSAPI support disabled"
        fi
    fi]
)
dnl   AC_DEFINE(DISABLE_WITH_SASL_GSSAPI)
AC_ARG_ENABLE(realm,
[  --enable-realm[=REALM.TLD]
                          enables hdb-ldap with krb5 realm for
		          'userPassword' & 'krb5PrincipalName'
			  requires hdb.schema loaded in your ldap server],
    [REALM="$enableval"
    if test "$REALM" = ""; then
        echo "hdb-ldap enabled: no realm selected->calculating from files..."
	AC_DEFINE(HDB_LDAP, 1, [hdb-ldap krb5 attrs enablement])
     elif test "$REALM" != "no"; then
        echo "hdb-ldap enabled: using selected realm...." "$REALM"
	AC_DEFINE(HDB_LDAP, 1, [hdb-ldap krb5 attrs enablement])
     fi]
)
AC_ARG_ENABLE(pts,
[  --enable-pts
                          enables OpenAFS PTServer account administration],
    [PTS="yes"
    AC_DEFINE(PTS, 1, [enable pts integration])]
)
AC_ARG_ENABLE(mail,
[  --enable-mail[=domain.tld]
                          enables mail attrs with selected maildomain],
    [MAIL="$enableval"]
)
AC_ARG_ENABLE(qmail,
[  --enable-qmail[=domain.tld]
                          enables Qmail attrs with selected maildomain
			  requires qmail.schema loaded in your ldap server],

    [QMAIL="yes"
    AC_DEFINE(QMAIL, 1, [enable Qmail attributes])]
)
AC_ARG_ENABLE(sshlpk,
[  --enable-sshlpk
                          enables ldapPublicKey objectclass and 
			  sshPublicKey attribute for ssh pubkey storage
			  requires lpk.schema loaded in your ldap server],

    [SSH="yes"
    AC_DEFINE(SSH_LPK, 1, [enable openssh-lpk stuff])]
)
    
AC_ARG_ENABLE(sudoers,
[  --enable-sudoers[=ou_location]
                          build sudoer admin tools (with OU location) i.e. * ou=sudoers *
			  default is 'ou=sudoers,ou=unix,dc=yourrealm,dc=tld'
			  as detected by 'configure'],

     [SUOU="$enableval"
     SUDOON="yes"]
)
AC_ARG_ENABLE(ppolicy,
[  --enable-ppolicy
                          enables pwdPolicy objectclass for OpenLDAP password
			  policies.  Requires slapo-ppolicy overlay be loaded in your
			  ldap server],
      
      [AC_DEFINE(PPOLICY, 1, [enable ppolicy for OpenLDAP password policies])]
)
AC_ARG_ENABLE(log,
[  --enable-log[=path]
			  enable logging to path
			  defaults to /tmp/uxds.log],
     
    [LOGPATH="$enableval"
    LOGGER="yes"
    if test "$LOGPATH" = "yes"; then
        LOGPATH="/tmp/uxdslog"
    fi
    AC_DEFINE(TOOL_LOG, 1, [enable logging])]
)

sh resolv.sh "$REALM" "$MAIL" "$LOGPATH"

AC_PROG_CC

AM_INIT_AUTOMAKE(uxdstools, [$PACKAGE_VERSION])

AM_CONDITIONAL(SUDOON, [test x"$SUDOON" = x"yes"])
AM_CONDITIONAL(SASL, [test x"$SASL" = x"yes"])
AM_CONDITIONAL(GSSAPI, [test x"$GSSAPI" = x"yes"])
AM_CONDITIONAL(PTS, [test x"$PTS" = x"yes"])
AM_CONDITIONAL(LOGGER, [test x"$LOGGER" = x"yes"])

dnl Checks for programs.

dnl Checks for libraries.
AC_CHECK_LIB(ldap, ldap_initialize)

if test "$GSSAPI" = "yes"; then
    AC_CHECK_LIB(krb5, krb5_init_context)
    AC_CHECK_LIB(crypto, BIO_new)
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(stdlib.h string.h errno.h sys/time.h termios.h unistd.h ldap.h lber.h)

if test "$SASL" = "yes"; then
    AC_CHECK_HEADERS(sasl.h sasl/sasl.h)
fi

if test "$GSSAPI" = "yes"; then
    AC_CHECK_HEADERS(krb5.h openssl/bio.h openssl/evp.h openssl/buffer.h)
fi

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

dnl Checks for library functions.
AC_FUNC_MALLOC

AC_CHECK_FUNCS(putenv strncasecmp strstr ldap_initialize ldap_err2string ldap_set_option ldap_sasl_bind_s ldap_search_ext_s ldap_first_entry ldap_get_dn ldap_memfree ldap_first_attribute ldap_next_attribute ldap_get_values_len ldap_value_free_len ldap_msgfree ldap_add_ext_s ldap_delete_ext_s ldap_modify_ext_s ldap_unbind_ext_s)

if test "$SASL" = "yes"; then
    AC_CHECK_FUNCS(ldap_sasl_interactive_bind_s)
fi

if test "$GSSAPI" = "yes"; then
     AC_CHECK_FUNCS(errx krb5_init_context krb5_cc_default krb5_cc_default_name krb5_cc_get_principal krb5_unparse_name_flags krb5_err krb5_cc_close krb5_free_context krb5_parse_name krb5_get_init_creds_opt_alloc krb5_principal_get_realm krb5_get_init_creds_opt_set_default_flags krb5_get_init_creds_opt_set_tkt_life krb5_get_init_creds_opt_set_pa_password krb5_get_init_creds_password krb5_get_init_creds_opt_set_pkinit krb5_kt_resolve krb5_get_init_creds_keytab krb5_kt_close krb5_get_init_creds_opt_free krb5_cc_initialize krb5_cc_store_cred krb5_set_password_using_ccache krb5_passwd_result_to_string krb5_warn krb5_data_zero krb5_data_free BIO_new BIO_f_base64 BIO_s_mem BIO_push BIO_write BIO_ctrl BIO_free_all)
fi

if test "$PTS" = "yes"; then
    AC_CHECK_FILE("/usr/bin/pts", [AFSPTS=/usr/bin/pts], [
          AC_CHECK_FILE("/usr/local/bin/pts", [AFSPTS=/usr/local/bin/pts] [
    AC_MSG_ERROR([Couldn't find OpenAFS binary])])])
    AC_DEFINE_UNQUOTED(PTS_BIN, "$AFSPTS", [OpenAFS pts binary path])
fi

AC_CONFIG_FILES(Makefile src/Makefile man/Makefile)
AC_OUTPUT
