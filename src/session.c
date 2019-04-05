/* Copyright (c) 2018, Seznam.cz, a.s.
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
   TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
   BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <event.h>
#include <event2/util.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include "log.h"
#include "acl.h"
#include "proxy.h"
#include "session.h"
#include "resp.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

void session_destroy(session_t *session)
{
	if (session == NULL)
		return;

	bufferevent_free(session->client);
	bufferevent_free(session->server);
	free(session);
}

void session_drop(session_t *session, char *err)
{
	resp_t *r;

	if (session == NULL)
		return;

	if (err && (r = resp_err(err))) {
		bufferevent_write(session->client, r->payload, r->len);
		free(r);
	}

	if (session->ssl != NULL) {
		SSL_set_shutdown(session->ssl, SSL_RECEIVED_SHUTDOWN);
		SSL_shutdown(session->ssl);
	}

	session_destroy(session);
}

void session_client_event(struct bufferevent *be, short events, void *arg)
{
	session_t *session = (session_t *)arg;

	if (events & BEV_EVENT_ERROR) {
		LOG(E1, "got error from client %s, %s", session->remote.address, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		session_drop(session, NULL);
	} else if (events & BEV_EVENT_EOF) {
		LOG(D1, "client %s has closed connection", session->remote.address);
		session_drop(session, NULL);
	}
}

void session_server_event(struct bufferevent *be, short events, void *arg)
{
	session_t *session = (session_t *)arg;

	if (events & BEV_EVENT_CONNECTED) {
		if (session->proxy->backend.auth == NULL) {
			bufferevent_set_timeouts(session->server, NULL, NULL);
			session->ss = SESSION_CLIENT_CHECK;
			bufferevent_enable(session->client, EV_READ | EV_WRITE);
			return;
		}
		if (bufferevent_write(session->server, session->proxy->backend.auth->payload, session->proxy->backend.auth->len) == 0) {
			session->ss = SESSION_SERVER_AUTH;
		} else {
			LOG(E1, "failed to authenticate to server %s, %s", session->proxy->backend.remote.address, strerror(errno));
			session_drop(session, "failed to authenticate to a server");
		}
	} else if (events & BEV_EVENT_TIMEOUT) {
		LOG(E1, "timeout reached while connecting to server %s", session->proxy->backend.remote.address);
		session_drop(session, "timeout reached while connecting to a server");
	} else if (events & BEV_EVENT_ERROR) {
		LOG(E1, "got error from server %s, %s", session->proxy->backend.remote.address, evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
		session_drop(session, "got error from a server");
	} else if (events & BEV_EVENT_EOF) {
		LOG(W1, "server %s has closed connection", session->proxy->backend.remote.address);
		session_drop(session, "server has closed connection");
	}
}

void session_client_read(struct bufferevent *be, void *arg)
{
	session_t *session = (session_t *)arg;
	struct evbuffer *src = bufferevent_get_input(session->client);
	struct evbuffer *dst = bufferevent_get_output(session->server);
	int i;
	const char **c = NULL;
	char *password;
	X509 *cert;

	if ((session->ssl != NULL) && (session->remote.common_name[0] == '\0')) {
		cert = SSL_get_peer_certificate(session->ssl);
		if (cert) {
			X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, session->remote.common_name, MAXHOSTNAME);
			session->acl = acl_match_cert(session->proxy->acl, session->remote.common_name);
			LOG(D1, "client %s has sent a certificate for commonName '%s'", session->remote.address, session->remote.common_name);
		}
	}

	if ((session->ss == SESSION_SERVER_CONNECT) || (session->ss == SESSION_SERVER_AUTH))
		return;

	while ((i = resp_parse_buffer(&session->rs)) > 0) {
		if (session->ss == SESSION_CLIENT_CHECK) {
			if (strncasecmp(session->rs.cmd, "auth", MIN(4, session->rs.cmdlen)) == 0) {
				/* NOTE: in case we've got 'auth' command with correct number of arguments,
				         we're gonna process it ourselves, otherwise we pass it to let redis
				         generate an error for a client */
				session->ss = (session->rs.pending_parts == 1) ? SESSION_CLIENT_AUTH:SESSION_CLIENT_PASS;
				continue;
			}
			session->ss = SESSION_CLIENT_BLOCK;
			if (session->acl) {
				c = session->acl->allow;
				if ((c == NULL) && (session->acl->deny != NULL)) {
					c = session->acl->deny;
					session->ss = SESSION_CLIENT_PASS;
				}
			}
			while (c && *c) {
				i = strlen(*c);
				if (strncasecmp(session->rs.cmd, *c, MIN(i, session->rs.cmdlen)) == 0) {
					session->ss = (session->ss == SESSION_CLIENT_PASS) ? SESSION_CLIENT_BLOCK:SESSION_CLIENT_PASS;
					break;
				}
				c++;
			}
			session->rs.cmd[session->rs.cmdlen] = '\0';
			LOG(D1, "command '%s' from client %s %s using acl '%s'", session->rs.cmd, session->remote.address, (session->ss == SESSION_CLIENT_PASS) ? "allowed":"blocked", (session->acl) ? session->acl->id:"");
			session->rs.cmd[session->rs.cmdlen] = '\n';
		}
		if (session->ss == SESSION_CLIENT_PASS) {
			session->rs.parsed -= evbuffer_remove_buffer(src, dst, session->rs.parsed);
		} else if (session->ss == SESSION_CLIENT_BLOCK) {
			if (evbuffer_drain(src, session->rs.parsed) != 0) {
				LOG(E1, "evbuffer_drain() failed, dropping session from client %s", session->remote.address);
				session_drop(session, NULL);
				continue;
			}
			session->rs.parsed = 0;
		} else if (session->ss == SESSION_CLIENT_AUTH) {
			if ((password = resp_get_last_value(&session->rs)) == NULL)
				continue;
			session->acl = acl_match_auth(session->proxy->acl, password);
			free(password);
			if (session->acl == NULL) {
				i = bufferevent_write(session->client, session->proxy->frontend.autherr->payload, session->proxy->frontend.autherr->len);
				LOG(W1, "invalid 'auth' from client %s, not using any acl entry", session->remote.address);
			} else {
				i = bufferevent_write(session->client, session->proxy->frontend.authok->payload, session->proxy->frontend.authok->len);
				LOG(D1, "successful 'auth' from client %s, using acl '%s'", session->remote.address, session->acl->id);
			}
			if (i == -1) {
				LOG(E1, "bufferevent_write() failed, dropping session from client %s", session->remote.address);
				session_drop(session, NULL);
				continue;
			}
			if (evbuffer_drain(src, session->rs.parsed) != 0) {
				LOG(E1, "evbuffer_drain() failed, dropping session from client %s", session->remote.address);
				session_drop(session, NULL);
				continue;
			}
			session->rs.parsed = 0;
			session->ss = SESSION_CLIENT_CHECK;
		}
		if (session->rs.pending_parts == 0) {
			session->rs.cmd = NULL;
			session->rs.cmdlen = 0;
			if (session->ss == SESSION_CLIENT_BLOCK) {
				/* NOTE: sort-of hack for pipelined client commands
				         when a client command has been blocked, we send non-existing
				         command to backend to let redis itself generate an error for us
				         this way, we don't need to inspect every redis response, waiting
				         for "the right moment" to send our own "not authorized" error
				*/
				if (bufferevent_write(session->server, session->proxy->backend.nauth->payload, session->proxy->backend.nauth->len) != 0) {
					LOG(E1, "got error from server %s, %s", session->proxy->backend.remote.address, strerror(errno));
					session_drop(session, "got error from a server");
					continue;
				}
			}
			session->ss = SESSION_CLIENT_CHECK;
		}
	}

	if (i == -1) {
		LOG(E1, "resp_parse_buffer() failed, dropping session from client %s", session->remote.address);
		session_drop(session, NULL);
	}
}

void session_server_read(struct bufferevent *be, void *arg)
{
	session_t *session = (session_t *)arg;

	if (session->ss > SESSION_SERVER_AUTH) {
		bufferevent_read_buffer(session->server, bufferevent_get_output(session->client));
	} else if (session->ss == SESSION_SERVER_AUTH) {
		struct evbuffer *input = bufferevent_get_input(session->server);
		char *response = evbuffer_pullup(input, 5);
		if (response == NULL)
			return;
		if (strncmp(response, "+OK\r\n", 5)) {
			response[4] = '\0';
			LOG(W1, "unexpected auth response from server %s, %s", session->proxy->backend.remote.address, response);
			session_drop(session, "unexpected auth response from a server");
		} else {
			evbuffer_drain(input, 5);
			bufferevent_set_timeouts(session->server, NULL, NULL);
			session->ss = SESSION_CLIENT_CHECK;
			bufferevent_enable(session->client, EV_READ | EV_WRITE);
		}
	}
}

session_t *session_create(proxy_t *proxy, evutil_socket_t fd, struct sockaddr *sa, int salen)
{
	session_t *session = (session_t *)malloc(sizeof(session_t));

	if (session == NULL) {
		LOG(E1, "failed initialize session, %s", strerror(errno));
		return(NULL);
	}

	memset(session, 0, sizeof(session_t));

	session->proxy = proxy;

	memcpy(&session->remote.sa, sa, salen);

	getnameinfo(sa, salen, session->remote.address, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);

	session->acl = acl_match_net(proxy->acl, session->remote.address);

	if (proxy->frontend.ssl_ctx) {
		if ((session->ssl = SSL_new(proxy->frontend.ssl_ctx)) == NULL) {
			LOG(E1, "SSL_new() failed, %s", strerror(errno));
			return(NULL);
		}
		session->client = bufferevent_openssl_socket_new(proxy->eb, fd, session->ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	} else {
		session->client = bufferevent_socket_new(proxy->eb, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	if (session->client == NULL) {
		LOG(E1, "failed to initialize client bufferevent, %s", strerror(errno));
		free(session);
		return(NULL);
	}

	session->rs.eb = bufferevent_get_input(session->client);

	session->server = bufferevent_socket_new(proxy->eb, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	if (session->server == NULL) {
		LOG(E1, "failed to initialize server bufferevent, %s", strerror(errno));
		free(session);
		return(NULL);
	}

	bufferevent_socket_connect(session->server, &proxy->backend.remote.sa, sizeof(struct sockaddr));

	bufferevent_setcb(session->client, session_client_read, NULL, session_client_event, session);
	bufferevent_setcb(session->server, session_server_read, NULL, session_server_event, session);

	bufferevent_enable(session->client, EV_WRITE); // NOTE: we enable EV_READ on a client side later, when connected to a server
	bufferevent_enable(session->server, EV_READ | EV_WRITE);

	/* NOTE: bufferevent timeouts have been broken prior to libevent 2.1.2 */
	bufferevent_set_timeouts(session->server, &proxy->backend.timeout, NULL);

	session->ss = SESSION_SERVER_CONNECT;

	return(session);
}
