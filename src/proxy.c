/*
   Copyright (c) 2018-2019, Seznam.cz, a.s.

   Author: Daniel Bilik (daniel.bilik@firma.seznam.cz)

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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libconfig.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event.h>
#include <event2/util.h>

#include "log.h"
#include "proxy.h"
#include "session.h"
#include "resp.h"
#include "worker.h"

void proxy_accept(struct evconnlistener *ecl, evutil_socket_t fd, struct sockaddr *address, int socklen, void *arg)
{
	proxy_t *proxy = (proxy_t *)arg;
	session_t *session = session_create(proxy, fd, address, socklen);

	if (session)
		LOG(D1, "accepted connection from client %s", session->remote.address);
}

void proxy_worker(void *i)
{
	proxy_t *proxy = (proxy_t *)i;

	event_base_loop(proxy->eb, 0);
}

proxy_t *proxy_create(config_setting_t *config, acl_t **acl)
{
	int n, i;
	const char *value;
	config_setting_t *s;
	acl_t **a;
	proxy_t *proxy = (proxy_t *)malloc(sizeof(proxy_t));

	if (proxy == NULL) {
		LOG(E1, "malloc() failed, %s", strerror(errno));
		return(NULL);
	}

	if (config_setting_is_group(config) == CONFIG_FALSE) {
		LOG(E1, "invalid config entry");
		return(NULL);
	}

	memset(proxy, 0, sizeof(proxy_t));

	if ((proxy->worker = worker_create("proxy", proxy_worker, (void *)proxy)) == NULL) {
		LOG(E1, "failed failed to initialize worker");
		return(NULL);
	}

	if ((proxy->eb = event_base_new()) == NULL) {
		LOG(E1, "event_base_new() failed, %s", strerror(errno));
		return(NULL);
	}

	if (config_setting_lookup_string(config, "listen", &value) == CONFIG_FALSE) {
		LOG(E1, "'proxy' entry without valid 'listen'");
		return(NULL);
	}

	n = sizeof(proxy->frontend.local.sa);

	if (evutil_parse_sockaddr_port(value, &proxy->frontend.local.sa, &n) == -1) {
		LOG(E1, "failed to parse 'listen' '%s'", value);
		return(NULL);
	}

	value = NULL;

	proxy->ecl = evconnlistener_new_bind(proxy->eb, NULL, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE, -1, &proxy->frontend.local.sa, n);

	if (proxy->ecl == NULL) {
		LOG(E1, "evconnlistener_new_bind() failed, %s", strerror(errno));
		return(NULL);
	}

	config_setting_lookup_string(config, "cert", &proxy->frontend.cert);
	config_setting_lookup_string(config, "key", &proxy->frontend.key);

	if (proxy->frontend.cert && proxy->frontend.key) {
		config_setting_lookup_string(config, "ca", &proxy->frontend.ca);
		if (proxy->frontend.ca == NULL)
			proxy->frontend.ca = strdup("/etc/ssl/certs/ca-certificates.crt");
		if ((strlen(proxy->frontend.ca) > 0) && (access(proxy->frontend.ca, F_OK) == -1)) {
			LOG(E1, "failed to read '%s', %s", proxy->frontend.ca, strerror(errno));
			return(NULL);
		}
		if ((proxy->frontend.ssl_ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
			LOG(E1, "SSL_CTX_new() failed");
			return(NULL);
		}
		SSL_CTX_set_options(proxy->frontend.ssl_ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET|SSL_OP_NO_RENEGOTIATION);
		if (strlen(proxy->frontend.ca) == 0) {
			SSL_CTX_set_verify(proxy->frontend.ssl_ctx, SSL_VERIFY_NONE, NULL);
		} else if (SSL_CTX_load_verify_locations(proxy->frontend.ssl_ctx, proxy->frontend.ca, NULL) != 1) {
			LOG(E1, "SSL_CTX_load_verify_locations() failed, %s", ERR_error_string(ERR_get_error(), NULL));
			return(NULL);
		} else {
			SSL_CTX_set_verify(proxy->frontend.ssl_ctx, SSL_VERIFY_PEER, NULL);
		}
		if (SSL_CTX_use_certificate_file(proxy->frontend.ssl_ctx, proxy->frontend.cert, SSL_FILETYPE_PEM) != 1) {
			LOG(E1, "SSL_CTX_use_certificate_file() failed, %s", ERR_error_string(ERR_get_error(), NULL));
			return(NULL);
		}
		if (SSL_CTX_use_PrivateKey_file(proxy->frontend.ssl_ctx, proxy->frontend.key, SSL_FILETYPE_PEM) != 1) {
			LOG(E1, "SSL_CTX_use_PrivateKey_file() failed, %s", ERR_error_string(ERR_get_error(), NULL));
			return(NULL);
		}
	} else if (proxy->frontend.cert || proxy->frontend.key) {
		LOG(E1, "'proxy' entry without valid 'cert'+'key'");
		return(NULL);
	}

	if (config_setting_lookup_string(config, "redis", &value) == CONFIG_FALSE) {
		LOG(E1, "'proxy' entry without valid 'redis'");
		return(NULL);
	}

	if (evutil_parse_sockaddr_port(value, &proxy->backend.remote.sa, &n) == -1) {
		LOG(E1, "failed to parse 'redis' '%s'", value);
		return(NULL);
	}

	value = NULL;

	getnameinfo(&proxy->backend.remote.sa, n, proxy->backend.remote.address, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST);

	proxy->backend.timeout.tv_sec = 3;

	config_setting_lookup_int(config, "redis_timeout", (int *)&proxy->backend.timeout.tv_sec);
	config_setting_lookup_string(config, "redis_auth", &value);

	if (value)
		proxy->backend.auth = resp_command("AUTH", value, NULL);

	proxy->backend.nauth = resp_command("NOT AUTHORIZED", NULL);

	s = config_setting_get_member(config, "acl");
	n = config_setting_length(s);

	if (config_setting_is_array(s) && (n > 0)) {
		proxy->acl = (acl_t **)malloc((n + 1) * sizeof(acl_t *));
		if (proxy->acl == NULL) {
			LOG(E1, "malloc() failed, %s", strerror(errno));
			return(NULL);
		}
		memset(proxy->acl, 0, (n + 1) * sizeof(acl_t *));
		for (i = 0; i < n; i++) {
			value = NULL;
			if ((value = config_setting_get_string_elem(s, i)) == NULL) {
				LOG(E1, "invalid 'acl' entry");
				return(NULL);
			}
			a = acl;
			while (a) {
				if (strcmp((*a)->id, value) == 0) {
					proxy->acl[i] = *a;
					break;
				}
				a++;
			}
			if (proxy->acl[i] == NULL) {
				LOG(E1, "unknown 'acl' entry '%s'", value);
				return(NULL);
			}
		}
	}

	proxy->frontend.authok = resp_msg("OK");
	proxy->frontend.autherr = resp_err("ERR invalid password");

	return(proxy);
}

void proxy_destroy(proxy_t *proxy)
{
	if (proxy == NULL)
		return;

	proxy_stop(proxy);

	worker_destroy(proxy->worker);

	evconnlistener_free(proxy->ecl);
	event_base_free(proxy->eb);

	resp_free(proxy->backend.auth);
	resp_free(proxy->backend.nauth);
	resp_free(proxy->frontend.authok);
	resp_free(proxy->frontend.autherr);

	free(proxy->acl);

	if (proxy->frontend.ssl_ctx)
		SSL_CTX_free(proxy->frontend.ssl_ctx);

	free(proxy);
}

void proxy_start(proxy_t *proxy)
{
	if (proxy == NULL)
		return;

	evconnlistener_set_cb(proxy->ecl, proxy_accept, proxy);

	worker_instruct(proxy->worker, RUN);
}

void proxy_stop(proxy_t *proxy)
{
	if (proxy == NULL)
		return;

	evconnlistener_disable(proxy->ecl);

	event_base_loopbreak(proxy->eb);

	worker_instruct(proxy->worker, SLEEP);
}
