![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-FreeBSD-blue.svg?style=flat)

# Proxis: TLS + ACL proxy for redis

Simple proxy that encrypts traffic to redis clients and controls access to
particular redis commands, based either on "auth" command sent by a client,
commonName found in a client's certificate or client's ip address.

# Usage

Proxy operation is controlled via easily readable configuration directives. In
section "acl", one or more identities are defined, their authentication methods
and particular redis commands they are allowed or denied to perform. One or more
entries in section "proxy" then describes what proxy to run on what address:port,
what redis server it should use and what "acl" entries it should assign to clients.

# Requirements

- OpenSSL (>= 1.1.0)
- libevent (>= 2.1.8)
- libconfig (>= 1.5.0)

# Examples

## Clients authorization based on their address

```
acl: (
  {
    id: "incoming"
    net: [ "10.0.0.0/8" ]
    allow: [ "select", "set", "setex", "quit" ]
  },
  {
    id: "processing"
    net: [ "10.10.10.0/24", "10.10.20.0/24" ]
    deny: [ "flushall", "flushdb" ]
  }
)

proxy: (
  {
    listen: "10.10.10.1:6379"
    redis: "127.0.0.1:6379"
    redis_auth: "redispassword"
    redis_timeout: 3
    acl: [ "incoming", "processing" ]
  }
)
```

This configuration defines two ACL entries, "incoming" and "processing". First
one covers clients connecting from 10.0.0.0/8, and allows them to use only four
redis commands. Second one matches clients coming from subnets 10.10.10.0/24
and 10.10.20.0/24, and allows them to use any redis command except flushing
databases.

Next, it describes a proxy that accepts clients on 10.10.10.1:6379. Clients are
assigned to either "incoming" or "processing" (or nothing if coming from
another network) and their filtered commands are then being passed to redis
server at 127.0.0.1:6379. This redis is password-protected, but the password is
only used by proxis. Clients don't need to authenticate with "AUTH" command,
they are authorized simply by connecting to proxis.

Note that clients coming from 10.10.10.0/24 and 10.10.20.0/24 match also ACL
entry "incoming", but proxis correctly assigns them to "processing" because of
more relevant subnet match.

## Clients required to authenticate with their passwords

```
acl: (
  {
    id: "read"
    auth: "ReadOnlySecret"
    allow: [ "select", "get", "hget", "hkeys", "quit" ]
  },
  {
    id: "write"
    auth: "SecretWriteOnly"
    allow: [ "select", "set", "hset", "quit" ]
  },
  {
    id: "any"
    auth: "AlmightyPassword"
    deny: [ "?" ]
  }
)

proxy: (
  {
    listen: "10.10.10.1:6379"
    redis: "127.0.0.1:6379"
    redis_timeout: 3
    acl: [ "read", "write", "any" ]
  }
)
```

This proxy requires clients to authenticate themselves via "AUTH" redis
command. The command is not sent to real redis, but is "consumed" by proxis
itself and is used to assign a client to particular "acl" entry. There are
three "acl" entries defined, allowing the clients to just read, just write or
to perform anything on a real redis. Note that allowing any command is achieved
by simply denying a non-existing one. Also note that redis server in this
example is not password-protected, thus proxis doesn't need to authenticate
itself and there's no "redis_auth" directive.

## Clients authenticating with TLS certificate

```
acl: (
  {
    id: "reader"
    cert: "client1.seznam.net"
    allow: [ "select", "get", "hget", "quit" ]
  },
  {
    id: "indexer"
    cert: "client2.seznam.net"
    deny: [ "flushdb", "flushall" ]
  }
)

proxy: (
  {
    listen: "10.10.10.1:6378"
    cert: "/path/to/cert.pem"
    key: "/path/to/key.pem"
    ca: "/etc/custom-ca-certificates.crt"
    redis: "10.200.10.1:6379"
    redis_timeout: 3
    acl: [ "reader", "indexer" ]
  }
)
```

In this example, proxis accepts TLS clients on port 6378 and passes their
filtered commands in plaintext to redis at 10.200.10.1:6379. Proxis presents
itself with certificate defined under "cert" using key "key". Accepted clients
are assigned first ACL entry that matches its "cert" with commonName attribute
of a client's certificate.

List of trusted authorities is defined under "ca", default is
/etc/ssl/certs/ca-certificates.crt. When it's set to "" (an empty string),
proxis treats any client's certificate as trusted. This can be used in cases
where traffic encryption is required but you don't want to be concerned with
CA maintenance. In such case, you wouldn't want proxis to authenticate clients
via "cert", because commonName can be forged, but you'd use "auth" or "net"
instead.

# Combining configuration entries

Multiple "proxy" entries can be defined (just like "acl" entries), so you can
combine TLS and plaintext listening ports to accept both native and TLS-aware
clients (and direct them all to one common redis, for example).

Also, different authentication mechanisms can be combined in one configuration.
Choosing "the right" ACL entry for a client then proceeds this way:

- when a client is connected, proxis tries to pick ACL entry that best matches
  its "net" to a client's address

- in case of TLS client, proxis then picks ACL entry matching its "cert" to
  commonName of a client's certificate (note: no ACL entry is assigned when
  nothing matches here, leaving a client with no privileges at all)

- if a client then sends "AUTH" redis command, proxis uses it to pick matching
  ACL entry (and again, if nothing matches, client is denied to perform
  anything, except another "AUTH")

# Credits

Written by Luka Musin and [Daniel Bilik](https://github.com/ddbilik/), copyright [Seznam.cz](https://onas.seznam.cz/en/), licensed under the terms of the FreeBSD License (the 2-Clause BSD License).
