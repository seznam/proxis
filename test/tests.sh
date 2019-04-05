#!/bin/bash

. ./functions.sh

failcount=0

port=16377

acl="allow-net"

echo -n "$acl: permit ... "
test_command $port PONG ping || failcount=$((failcount+1))

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" flushdb || failcount=$((failcount+1))

port=16378

acl="allow-ip"

echo -n "$acl: permit ... "
test_command $port OK set key value || failcount=$((failcount+1))

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" flushdb || failcount=$((failcount+1))

acl="allow-auth"

echo -n "$acl: permit ... "
test_auth_command $port value get key || failcount=$((failcount+1))

echo -n "$acl: forbid ... "
test_auth_command $port "ERR.*NOT AUTHORIZED" flushdb || failcount=$((failcount+1))

port=16379

acl="deny-net"

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" ping || failcount=$((failcount+1))

echo -n "$acl: permit ... "
test_command $port "OK" flushdb || failcount=$((failcount+1))

port=16380

acl="deny-ip"

echo -n "$acl: forbid ... "
test_command $port "ERR.*NOT AUTHORIZED" set key value || failcount=$((failcount+1))

echo -n "$acl: permit ... "
test_command $port "OK" flushdb || failcount=$((failcount+1))

acl="deny-auth"

echo -n "$acl: forbid ... "
test_auth_command $port "ERR.*NOT AUTHORIZED" get key || failcount=$((failcount+1))

echo -n "$acl: permit ... "
test_auth_command $port "OK" flushdb || failcount=$((failcount+1))

[ $failcount -gt 0 ] && exit 1 || exit 0
