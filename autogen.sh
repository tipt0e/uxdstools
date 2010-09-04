#!/bin/sh
PATH=/bin:/usr/bin:/usr/local/bin:~/bin
export PATH
aclocal && autoheader && autoconf && automake
