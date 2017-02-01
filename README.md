    --    --    --    --    --    --    --    --    --    --    --
      			    uxdstools
    --    --    --    --    --    --    --    --    --    --    --

Generic command line tools to administrate POSIX user and group
accounts located inside an LDAP Directory.

Supports both simple and SASL binds for authentication,
including GSSAPI if Heimdal is available at compile time.
If GSSAPI support is enabled, a kerberos ticket-granting-ticket
will be obtained with a lifetime of 30 minutes when either of the
password options (command line or input) are selected.

This project is in beta but most of the functionality is available:

lacctparse - lookup user and group (add sudoer if available) attributes<br>
luseradd - add POSIX user to directory service<br>
luserdel - delete POSIX user from directory service<br>
lusermod - modify POSIX user attrs in directory service<br>
lgroupadd - add POSIX group to directory service<br>
lgroupdel- delete POSIX group from directory service<br>
lgroupmod - modify POSIX group attrs in directory service<br>
<br>
and if sudoers is enabled:<br>
<br>
lsudoadd - add SUDOer account to directory service<br>
lsudomod - modify SUDOer account in directory service<br>
lsudodel - delete SUDOer account from directory service<br>
<br>
All (except lacctparse) are named in reverence to command line tools used on<br>
UNIX (Linux, Solaris) systems to manage local accounts, with the 'l' prefix<br>
signifying LDAP.<br>
<br>
A specific host can be specified, otherwise the default uses the<br>
OpenLDAP libraries to look up specific host information through ldap.conf(5).<br>
<br>
SASL support requires <sasl.h> from the Cyrus-SASL distribution, and OpenLDAP
libraries linked against Cyrus-SASL.
<br>
Warning: only SASL/GSSAPI support was really tested, thats all have here on my home network.<br>
Should work with other mechanisms, though. YMMV.<br>
SASL-GSSAPI support requires OpenLDAP to be additionally linked to SASL with<br>
GSSAPI support, as well as krb5.h and libkrb5 from Heimdal.

To build:

If obtaining from a git repository, run ./autogen.sh in the top directory.

Run the included configure script. './configure --help' will show the specific options.

These options are unique to uxdstools: **

    --enable-sasl=(yes|no) 

include Cyrus-SASL support for authentication
requires OpenLDAP libraries to be linked against
the Cyrus-SASL distribution
DEFAULT is "yes"

    --enable-gssapi(yes|no)\

include GSSAPI support for authentication
requires Heimdal Kerberos libraries
DEFAULT is "yes"

    --enable-realm=REALM.TLD 

enable HDB-LDAP attributes in user accounts, takes REALM.TLD
as argument to choose your local krb5 realm
if you do not define one, configure will try to figure it out
from your local /etc/resolv.conf file
requires your directory to have the 'hdb.schema' schema from
Heimdal loaded
DEFAULT is NULL

    --enable-maildomain=realm.tld 

choose mail domain for 'mail' user attribute
if you do not define one, configure will try to figure it out from
your local /etc/resolv.conf file
DEFAULT is NULL

    --enable-sudoers

enable SUDOers ldap attributes, requires sudo schema be loaded
in your ldap server
DEFAULT is no

    --enable-qmail=realm.tld   enable QMail attributes, if your ldap server has the qmail schema 

loaded
DEFAULT is no

    --enable-sshlpk            enable sshPublicKey stuff, if your ldap server has the lpk.schema

loaded
DEFAULT is no

    --enable-log=path          enable logging to file path (default is ./tmp/uxds_t.log)

DEFAULT is no

    --enable-pts               enable creation of user in OpenAFS PTS database, this requires

an OpenAFS setup using Krb5, checks for pts binary
DEFAULT is no


AUTHENTICATION options:

** The below options do not require SASL: **

    -D DN 

Distinguished name to used to bind to LDAP directory. If SASL
support is disabled, this always reverts to a simple bind operation
(and in the case of lacctparse, an anonymous bind can be attempted
sans password) by default. With SASL support enabled this can also
be used in conjunction with a mech (see -m below) as an identity with
which to bind, depending on how your local directory service is
configured.

    -p|-P passwd 

When -p is used, the password is taken as the argument to this
switch on the command line. If there are any special characters
you may enclose the argument in single quotes, e.g, 'p4$$w0rd!',
and the input will be accepted correctly.
When -P is used, the password is accepted into a prompt,
"Enter password credential:". The password is shadowed with
null characters and the input string is used as material to bind
the directory, whether simple or SASL binds.
With GSSAPI enabled, the password string will be inserted into
your local krb5 context (from krb5.conf) and attempt to obtain
a ticket-granting-ticket (lasting a period of 31 minutes) and
place said ticket into the default credentials cache. It will
then use this ticket for any further operations performed against
the LDAP tree, and further uxdstools can be called with "-m GSSAPI"
(see below) without the password argument.

    -H URI 

The expectation here is an LDAP resource URI,
e.g. ldap://server.example.com. If SSL/TLS support is
linKed into your OpenLDAP libraries, this will automatically
connect via SSL/TLS depending on the CA certificate options
configured in your local ldap.conf. This is an optional argument
as the OpenLDAP function will attempt to figure out needed host
information via your local ldap.conf file.
example:
-H ldaps://mysecureldap.example.net

** The options below require SASL to be enabled: **

    -m mech

This option requires the OpenLDAP libraries be linked against
Cyrus-SASL, and the sasl.h header file be available.
SASL mechanism, such as GSSAPI, DIGEST-MD5, CRAM-MD5, PLAIN,
etc. This switch is REQUIRED for all SASL bind attempts excepting
when GSSAPI support is enabled, in which case GSSAPI is hardcoded
as the default. For simple binds, this switch is not required,
"NONE" is included for "completeness".
For non-GSSAPI binds, an identity string and password is REQUIRED
(see -u, -D, -p, -P below), where identity string can be a
Distingushed Name or a username.
For GSSAPI binds only '-m GSSAPI' is required, if you have an
active ticket in your default credential cache. The OpenLDAP
libraries take care of obtaining the ldap service ticket needed
to perform operations on your directory. If you don't have a
ticket, and don't feel like using kinit, you may use the password
options (-p, -P) above, along with a username (-u) identity.

    -V

Enables SASL_INTERACTIVE mode, more descriptive (verbose), and
apparently needed by some mechanisms.

    -u user

With non-GSSAPI binds, this argument is used as the SASL authentication
identity, or "authcid" used to gain access to the directory service.
Depending on the your SASL configuration, this may also require the
-D <DN> argument. I have not extesnively tested anything but GSSAPI, so
use at your own risk. The mech (-m, see above) is REQUIRED to be set
without GSSAPI.
With GSSAPI enabled, this is parsed into the principal name with
your krb5 default realm information in your local krb5.conf. A context
is initialized, and along with the password (-p, -P) arguments above
a kerberos ticket is obtained. The mech is set to be GSSAPI by default,
so no mech argument (-m) is necessary here.

    -r realm 

Realm for SASL identity, some callbacks need this.
Not tested and totally optional at this point. With debugging enabled,
(see -d, below) it is possible to see if this is needed by you, as the
callbacks are spelled out.

** The next options requires GSSAPI support to be enabled. **

    -K FILE:/path/to/x509_certificate

With GSSAPI enabled, this allows for rudimentary PK-INIT authentication 
using an x509 certificate.  At this time it does not accept passphrases for 
private keys.  It will gain a kadmin/changepw ticket for use in changing 
principal passwords. Requires '-u <krb5Principal>' argument.

    -T FILE:/path/to/keytab

With GSSAPI enabled, this allows for kerberos authentication
using a keytab. It will gain a kadmin/changepw ticket for use in changing
principal passwords. Requires '-u <krb5Principal>' argument.

    -c ccache 

With '-m GSSAPI', an alternate location for the Kerberos credentials
cache can be defined. This can be a path, e.g. /tmp/krb5cc_100 or
preceded by 'METHOD:', as in FILE:/tmp/krb5cc_100 or KCM:100. This will
then be set into the environment KRB5CCNAME to tell the tool where
the cache is to use for operations.

Options for target POSIX account manipulation:

** The below option only applies to the "luser" tools: **

    -U user 

Username (uid attribute) of the user you wish to admin.

With 'luseradd', this input is appended on the group
selected, (see -G, below) then appended to the ou that
holds your unix users (which was defined at compile time).
By default this is "ou=unix,dc=yourdomain,dc=org",
depending on what domain was selected by the configure script.
[TO DO: allow user to change this at configure ->
with     --enable-ou or     --enable-oupath]
So you if choose -U luser -G slakaz the dn on an add attempt
would be: "uid=luser,cn=slakaz,ou=unix,dc=yourdomain,dc=org".
Also, a memberUid attribute describing this username is added
to the user's primary group account int LDAP.

With 'luserdel', the DN is taken using a (&(posixAccount)(uid=<NAME>))
filter with ldap_search and an ldap_delete operation is performed,
removing the account.
The memberUid attribute under the former user's primary group account
is then removed as well.

With 'lusermod', the DN is again calculated by the search filter
(&(PosixAccount)(uid=<NAME>)), and that DN is selected for
whatever is chosen to be modified.

** The next options will apply to each tool as described: **

    -G group 

Group name (cn attribute) of the group you wish to admin.

With the 'lgroupadd' tool, this input is appended on the ou
that holds your unix users (which was defined at compile time).
This is used as the DN to add to the directory and stick the
posixGroup attributes into.

With the 'lgroupmod' & 'lgroupdel' tools, this input is used
just as '-U' user, is used above, except in this case to obtain
the DN we use the search filter: (&(posixGroup)(cn=<NAME>)).

With 'luseradd', this switch is required, where it is required
to establish primary POSIX group membership, and a 'memberUid'
attribute is added to the user's primary group account in LDAP.

With 'lusermod', this switch can be called with no other modify
switches (by itself) to affect the user changing its primary group to
that which is used as the argument:
$ lusermod -D DN -U luser -G newgroup -P
The memberUid attribute describing the user will be deleted from
the old primary and added to the new primary group account in LDAP.

    -f name 
    -l name 

These are used to create the GECOS field, see below.
They are required for adds to populate the givenName and
sn attributes, but you can't make your own custom gecos without
patching the code.  The next release may change this.
Please don't shoot me.
First name: [givenName]
Last name: [sn]
These are combined along with the description attribute of the
user's primary POSIX group to create the GECOS field like so:

Lastname,Firstname;My Primary Group

This is just to provide some standardiztion. This will be changed
in the next release to optional and any gecos could be created upon
an add.

    -I description

This input is required by 'lgroupadd' and fills the posixGroup
"description" attribute, basically a gecos for the group account.

***
The following are all used in luseradd, lusermod, lgroupadd
& lgroupmod and are all optional upon an initial user import.
They are all modifiable using the 'mod' tools:

    -M memberUid

This input is used by 'lgroupadd' if a user is desired to be added to
the group account as a 'memberUid' attribute.  For 'lgroupmod', it 
will be added to the selected group, again as a memberUid attribute.
If multiple users are desired, they must be separated with commas;
e.g. -M grp1,grp2,grp3.

    -R memberUid

This is used by 'lgroupmod' to remove the described user account's 
memberUid attribute from the POSIX group account.
If multiple users are desired, they must be separated with commas;
e.g. -R grp1,grp2,grp3.

    -N uidN|gidN 

gidN (u|g)idNumber attribute for the user or group account. This is
attribute for the user or group account. The add tool will search all
(u|g)idNumbers in the directory and use the next logical available number
(highest (u|g)idNumber + 1).

    -S shell

Sets the loginShell attribute for the user's default shell.
If not set, defaults to "/bin/sh".
If not set, defaults to "/home/[user chosen]".

    -X path

Sets the homeDirectory attribute for the user's default home
directory. If not set, defaults to "/home/[user chosen]".
***

    -y

This option is only visible with 'luseradd' and 'lusermod' when GSSAPI
support is enabled.  It will set or reset the desired user's password 
(krb5Key) attribute to a random 8-character string. In this process, it 
will set another credentials cache to /tmp/kacache_%username (of tool
user) containing a kadmin/changepw ticket used as creds to set the password.
This ticket is valid for 5 minutes so it can be used with subsequent calls
to lusermod or luseradd in a scripting situation to reset passwords or create
users with passwords set.

    -e

This option is only visible with 'luseradd' and 'lusermod' when GSSAPI
support and or Ppolicy supoprt is enabled.  With GSSAPI, it will set the
'krb5PasswordEnd' attribute to '19991231235959Z', effectively expiring the
account to Dec 31, 1999.  With ppolicy enabled, it will set the 'pwdReset'
attribute to 'TRUE', effectively making the account change is password
before it can authenticate to the directory.

*** for 'luseradd' & 'lusermod' if Qmail attributes are enabled:

    -E email

Sets mailAlternateAddress attribute for mail delivery.
Defaults to whats in 'mail'.

    -Q fqdn

Sets mailHost attribute for mail delivery.  Defaults to
'mailhost.com' if not selected.

Miscellaneous options:

    -d Sets the debug bit for verbose output.

There is some debugging output to be had if things do not work as
expected, this switch takes no arguments.

    -v|--version 

Shows the version info and exits.

    -h|--help 

Shows verbose output of options and exits.


User and Group structure:

Without '--enable-realm' upon configure, 'luseradd' will add a user
that looks like this if you were using an ldif:

    # luser, slakaz, unix, mikro-net.com
    dn: uid=luser,cn=slakaz,ou=unix,dc=mikro-net,dc=com
    objectClass: top
    objectClass: person
    objectClass: inetOrgPerson
    objectClass: organizationalPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: simpleSecurityObject
    cn: luser
    sn: Added
    givenName: Luser
    uid: luser
    mail: luser@mikro-net.com
    uidNumber: 55555
    gidNumber: 1111
    gecos: Added,Luser;SLAKAZ System Group
    homeDirectory: /home/luser
    loginShell: /bin/sh
    carLicense: XxXxXxXxXxXxXxXxX
    userPassword:: RFVNTVk=

With '--enable-realm' the hdb-ldap pieces are introduced, and the user
looks like this:

    # luser, slakaz, unix, mikro-net.com
    dn: uid=luser,cn=slakaz,ou=unix,dc=mikro-net,dc=com
    objectClass: top
    objectClass: person
    objectClass: inetOrgPerson
    objectClass: organizationalPerson
    objectClass: posixAccount
    objectClass: shadowAccount
    objectClass: krb5Principal
    objectClass: krb5KDCEntry
    objectClass: simpleSecurityObject
    cn: luser
    sn: Added
    givenName: Luser
    uid: luser
    mail: luser@mikro-net.com
    uidNumber: 55555
    gidNumber: 1111
    gecos: Added,Luser;SLAKAS System Group
    homeDirectory: /home/luser
    loginShell: /bin/sh
    carLicense: XxXxXxXxXxXxXxXxX
    userPassword: {K5KEY}
    krb5Key: 0
    krb5PrincipalName: luser@MIKRO-NET.COM
    krb5MaxLife: 86400
    krb5MaxRenew: 604800
    krb5KDCFlags: 126
    krb5PasswordEnd: 20071231235959Z

Probably need a switch to use {SASL} as an alternative to {K5KEY}
for those that use saslauthd instead of smbk5pwd to handle simple
binds with kerberos passwords. I leave that as a To Do.

Group structure looks like this:

    # slakaz, unix, mikro-net.com
    dn: cn=slakaz,ou=unix,dc=mikro-net,dc=com
    cn: slakaz
    description: SLAKAZ System Group
    objectClass: top
    objectClass: posixGroup
    gidNumber: 1111
    memberUid: luser

This again, is beta software, tested only by me, and it comes with no
guarantes or warranties. But I hope someone can find it useful.

To Do:
Support MIT kerberos in addition to Heimdal
Enable attributes for SAMBA accounts
Enable attributes for Active Directory accounts

Copyright (c) 2008-2017, Michael Brown <ronin.crip@gmail.com>
