#!/bin/sh

# build realm.h from configure

DOMAIN=$1
MAIL=$2
LOGPATH=$3
CELL=$4

case $1 in 
   
   *\.*)
	DOMAIN=$1
	;;
    *)
	if [ -f /etc/krb5.conf ]
	then
	    DOMAIN=$(grep -a1 realms /etc/krb5.conf | grep '=' | awk '{print $1}' | tr \[:upper:\] \[:lower:\])
	else 
	    DOMAIN=$(hostname -f | awk -F\. '{if ($4 ~ /^$|0/) print $2 "." $3; else print $2 "." $3 "." $4;}')
	fi
	;;
esac

echo "searching for domain/realm components....."
if [ ${DOMAIN} ]; then
    echo "found domain -> which is: ${DOMAIN}"
    DOM=${DOMAIN}
else
    echo "no domain found...."
    echo "you may need to set an FQDN for this system"
    exit 1
fi
if [ !${MAIL} ]; then
    MAIL=${DOM}
else
    MAIL=${MAIL}
fi

echo "using $DOMAIN to calculate unix ou DN...."
AT_MAIL=$(echo "@${MAIL}" | tr "[:upper:]" "[:lower:]")
AT_REALM=$(echo "@${DOM}" | tr "[:lower:]" "[:upper:]")
OU=$(echo ${DOM} | awk -F\. '{if ($3 ~ /^$|0/) print "ou=unix,dc=" $1 ",dc=" $2; else print "ou=unix,dc=" $1 ",dc=" $2 ",dc=" $3;}')
echo "${OU}"
echo "${AT_MAIL}"
echo "${AT_REALM}"
echo "/*" > ./realm.h
echo " *" >> ./realm.h
echo " * realm.h" >> ./realm.h
echo " *" >> ./realm.h
echo " * holds defines for mail, realm, and OU" >> ./realm.h
echo " */" >> ./realm.h
echo "" >> ./realm.h
echo "" >> ./realm.h
echo "#define AT_EMAIL 	\"${AT_MAIL}\"" >> ./realm.h
echo "#define AT_REALM 	\"${AT_REALM}"\" >> ./realm.h
echo "#define UXDS_POSIX_OU 	\"${OU}"\" >> ./realm.h
echo "/* log location from configure */" >> ./realm.h
echo "#define UXDS_LOG	\"${LOGPATH}"\" >> ./realm.h
echo "#define MY_CELL  \"${DOM}"\" >> ./realm.h
echo "" >> ./realm.h
echo "#define MY_GECOS  \"UXDSAcct;%s %s;%s"\" >> ./realm.h
echo "" >> ./realm.h
echo "/* end realm.h */" >> ./realm.h
mv ./realm.h src
MACHINE=$(uname -m)
if [ "${MACHINE}" = "i386" ]; then
    cd src
    cp ldap.c ldap64.c
    cp sudoldap.c sudoldap64.c
    patch < ldap_c_32bit.diff
    patch < sudoldap_c_32bit.diff
fi
