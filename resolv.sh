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
	DOMAIN=`grep -a1 realms /etc/krb5.conf | grep '=' | awk '{print $1}' | tr \[:upper:\] \[:lower:\]` 
       ;;
esac

echo "searching for domain components in /etc/resolv.conf......"
if [ ${DOMAIN} ]; then
    echo "found domain -> which is: ${DOMAIN}"
    DOM=${DOMAIN}
else
    echo "no domain found...."
    exit 1
fi
if [ !${MAIL} ]; then
    MAIL=${DOM}
else
    MAIL=${MAIL}
fi

echo "using $DOMAIN to calculate unix ou DN...."
AT_MAIL=`echo "@${MAIL}" | tr "[:upper:]" "[:lower:]"`
AT_REALM=`echo "@${DOM}" | tr "[:lower:]" "[:upper:]"`
OU=`echo ${DOM} | awk -F\. '{print "ou=unix,dc=" $1 ",dc=" $2 }'`
echo ${OU}
echo ${AT_MAIL}
echo ${AT_REALM}
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
echo "#define UXDS_LOG	\"${LOGPATH}"\" >> realm.h
echo "#define MY_CELL  \"${DOM}"\" >> realm.h
echo "" >> realm.h
echo "#define MY_GECOS  \"UXDSAcct;%s %s;%s"\" >> realm.h
echo "" >> realm.h
echo "/* end realm.h */" >> realm.h
mv realm.h src
MACHINE=`uname -m`
if [ "${MACHINE}" = "i386" ]; then
    cd src
    cp ldap.c ldap64.c
    cp sudoldap.c sudoldap64.c
    patch < ldap_c_32bit.diff
    patch < sudoldap_c_32bit.diff
fi
