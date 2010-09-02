#!/bin/sh
# compiles all features
./configure \
--prefix=/usr \
--enable-realm \
--enable-pts \
--enable-sudoers \
--enable-sshlpk \
--enable-log
