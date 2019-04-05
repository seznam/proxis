#!/bin/bash

set -x

. ./functions.sh

launch_redis redis-nopass.conf
[ $? -ne 0 ] && echo "failed to launch redis" && exit 1
launch_proxis proxis-cert.conf
[ $? -ne 0 ] && echo "failed to launch proxis" && exit 1
launch_stunnel stunnel.conf
[ $? -ne 0 ] && echo "failed to launch stunnel" && exit 1

rc=0

port=16370

acl="allow-cert"

echo -n "$acl: permit ... "
test_command $port PONG ping || rc=$((rc+1))

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" flushdb || rc=$((rc+1))

port=16371

acl="deny-cert"

echo -n "$acl: permit ... "
test_command $port OK flushdb || rc=$((rc+1))

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" ping || rc=$((rc+1))

stop_stunnel
stop_proxis
stop_redis

exit $rc
