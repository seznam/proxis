#!/bin/bash

set -x

. ./functions.sh

launch_proxis proxis-nopass.conf
[ $? -ne 0 ] && echo "failed to launch proxis" && exit 1

echo -n "no redis ... "
test_command 16377 "Error:" ping && rc=0 || rc=1

stop_proxis

exit $rc
