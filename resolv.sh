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
       DOMAIN=`cat /etc/resolv.conf | grep domain | awk '{print $2}'`
       SEARCH=`cat /etc/resolv.conf | grep search | awk '{print $2}'`
       ;;
esac

echo "searching for domain components in /etc/resolv.conf......"
if [ ${DOMAIN} ]; then
    echo "found domain -> which is:  ${DOMAIN}"
    DOM=${DOMAIN}
elif [ ${SEARCH} != NULL ]; then
   echo "found search -> which is:  ${SEARCH}"
    DOM=${SEARCH}
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
echo "/* end realm.h */" >> realm.h

MACHINE=`uname -m`
if [ ${MACHINE} == "i386" ]; then
    cd src
    patch < ldap_c_32bit.diff
    patch < sudoldap_c_32bit.diff
fi
