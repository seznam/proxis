#ifndef PROXY_H
#define PROXY_H

#include <netinet/in.h>
#include <event.h>
#include <event2/listener.h>

#include "acl.h"
#include "resp.h"
#include "worker.h"

#define MAXHOSTNAME 256

typedef struct {
	char address[INET6_ADDRSTRLEN];
	char common_name[MAXHOSTNAME];
	struct sockaddr sa;
} proxy_peer_t;

typedef struct {
	proxy_peer_t local;
	SSL_CTX *ssl_ctx;
	const char *ca, *cert, *key;
	resp_t *authok, *autherr;
} proxy_frontend_t;

typedef struct {
	proxy_peer_t remote;
	resp_t *auth, *nauth;
	struct timeval timeout;
} proxy_backend_t;

typedef struct {
	worker_t *worker;
	struct event_base *eb;
	struct evconnlistener *ecl;
	proxy_frontend_t frontend;
	proxy_backend_t backend;
	acl_t **acl;
} proxy_t;

proxy_t *proxy_create(config_setting_t *config, acl_t **acl);
void proxy_destroy(proxy_t *proxy);
void proxy_start(proxy_t *proxy);
void proxy_stop(proxy_t *proxy);

#endif
