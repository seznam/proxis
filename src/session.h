#ifndef SESSION_H
#define SESSION_H

#include "acl.h"
#include "proxy.h"
#include "resp.h"

typedef enum {
	SESSION_SERVER_CONNECT, SESSION_SERVER_AUTH, SESSION_CLIENT_CHECK, SESSION_CLIENT_PASS, SESSION_CLIENT_BLOCK, SESSION_CLIENT_AUTH
} session_state_t;

typedef struct {
	proxy_t *proxy;
	proxy_peer_t remote;
	acl_t *acl;
	SSL *ssl;
	struct bufferevent *client, *server;
	session_state_t ss;
	resp_buffer_t rs;
} session_t;

session_t *session_create(proxy_t *proxy, evutil_socket_t fd, struct sockaddr *address, int socklen);

#endif
