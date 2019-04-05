#!/bin/bash

function launch_redis
{
	config=$1
	redis-server $config
	rc=$?
	sleep 1
	return $rc
}

function launch_stunnel
{
	config=$1
	stunnel $config
	rc=$?
	sleep 1
	return $rc
}

function launch_proxis
{
	config=$1
	../src/proxis -c $config >> proxis.log
	rc=$?
	sleep 1
	return $rc
}

function stop_redis
{
	[ -f redis.pid ] && kill $(cat redis.pid)
	sleep 1
}

function stop_stunnel
{
	[ -f /tmp/proxis-stunnel-test.pid ] && kill $(cat /tmp/proxis-stunnel-test.pid)
	sleep 1
}

function stop_proxis
{
	[ -f proxis.pid ] && kill $(cat proxis.pid)
	sleep 1
}

function test_command
{
	port=$1
	expect=$2

	shift 2

	output=$(redis-cli -h 127.0.0.1 -p $port $@ 2>&1)

	[[ $output =~ $expect ]] && ( echo "ok" ; return 0 ) || ( echo "failed" ; return 1 )
}

function test_auth_command
{
	port=$1
	expect=$2

	shift 2

	output=$(redis-cli -h 127.0.0.1 -p $port -a AuthorizeMe $@ 2>&1)

	[[ $output =~ $expect ]] && ( echo "ok" ; return 0 ) || ( echo "failed" ; return 1 )
}
