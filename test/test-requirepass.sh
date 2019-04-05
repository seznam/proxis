#!/bin/bash

set -x

. ./functions.sh

launch_redis redis-requirepass.conf
[ $? -ne 0 ] && echo "failed to launch redis" && exit 1
launch_proxis proxis-requirepass.conf
[ $? -ne 0 ] && echo "failed to launch proxis" && exit 1

./tests.sh && rc=0 || rc=1

stop_proxis
stop_redis

exit $rc
