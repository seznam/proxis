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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libconfig.h>

#include "log.h"
#include "acl.h"

int acl_net_init(const char *cidr, acl_net_t *dst)
{
	char *slash;
	int i;
	struct in6_addr a;

	if ((cidr == NULL) || (dst == NULL))
		return(-1);

	memset(dst, 0, sizeof(acl_net_t));

	dst->family = (strchr(cidr, ':')) ? AF_INET6:AF_INET;

	if ((slash = strchr(cidr, '/')) != NULL) {
		if (sscanf(slash + 1, "%d", &dst->bits) != 1)
			return(-1);
		*slash = '\0';
	} else if (dst->family == AF_INET6) {
		dst->bits = 128;
	} else {
		dst->bits = 32;
	}

	i = inet_pton(dst->family, cidr, &a);

	if (slash)
		*slash = '/';

	if (i != 1)
		return(-1);

#ifdef LINUX
	const uint32_t *n = &a.s6_addr32[0];
#else
	const uint32_t *n = &a.__u6_addr.__u6_addr32[0];
#endif

	int bits_full = dst->bits >> 5;
	int bits_partial = dst->bits & 0x1f;

	if (bits_full)
		memcpy(dst->network, n, bits_full << 2);

	if (bits_partial) {
		uint32_t mask = htonl((0xffffffffu) << (32 - bits_partial));
		dst->network[bits_full] = (dst->network[bits_full] ^ n[bits_full]) & mask;
	}

	return(0);
}

acl_t *acl_create(config_setting_t *config)
{
	int a, i;
	config_setting_t *s;
	acl_t *acl = (acl_t *)malloc(sizeof(acl_t));

	if ((acl == NULL) || (config_setting_is_group(config) == CONFIG_FALSE))
		return(NULL);

	memset(acl, 0, sizeof(acl_t));

	if (config_setting_lookup_string(config, "id", &acl->id) == CONFIG_FALSE) {
		LOG(E1, "'acl' without valid 'id'");
		return(NULL);
	}

	config_setting_lookup_string(config, "auth", &acl->auth);

	config_setting_lookup_string(config, "cert", &acl->cert);

	s = config_setting_get_member(config, "net");

	a = ((s != NULL) && (config_setting_is_array(s) == CONFIG_TRUE)) ? config_setting_length(s):0;

	acl->net = (acl_net_t *)malloc((a + 1) * sizeof(acl_net_t));
	if (acl->net == NULL) {
		LOG(E1, "malloc() failed, %s", strerror(errno));
		return(NULL);
	}

	memset(acl->net, 0, (a + 1) * sizeof(acl_net_t));

	for (i = 0; i < a; i++)
		if (acl_net_init(config_setting_get_string_elem(s, i), acl->net + i) == -1) {
			LOG(E1, "failed to parse 'net' for acl '%s'", acl->id);
			return(NULL);
		}

	s = config_setting_get_member(config, "allow");

	if ((s != NULL) && (config_setting_is_array(s) == CONFIG_TRUE) && ((a = config_setting_length(s)) > 0)) {
		acl->allow = (const char **)malloc((a + 1) * sizeof(char *));
		if (acl->allow == NULL) {
			LOG(E1, "malloc() failed, %s", strerror(errno));
			return(NULL);
		}
		memset(acl->allow, 0, (a + 1) * sizeof(char *));
		for (i = 0; i < a; i++)
			if ((acl->allow[i] = config_setting_get_string_elem(s, i)) == NULL) {
				LOG(E1, "failed to parse 'allow' for acl '%s'", acl->id);
				return(NULL);
			}
	}

	s = config_setting_get_member(config, "deny");

	if ((s != NULL) && (config_setting_is_array(s) == CONFIG_TRUE) && ((a = config_setting_length(s)) > 0)) {
		acl->deny = (const char **)malloc((a + 1) * sizeof(char *));
		if (acl->deny == NULL) {
			LOG(E1, "malloc() failed, %s", strerror(errno));
			return(NULL);
		}
		memset(acl->deny, 0, (a + 1) * sizeof(char *));
		for (i = 0; i < a; i++)
			if ((acl->deny[i] = config_setting_get_string_elem(s, i)) == NULL) {
				LOG(E1, "failed to parse 'deny' for acl '%s'", acl->id);
				return(NULL);
			}
	}

	return(acl);
}

void acl_destroy(acl_t *acl)
{
	if (acl == NULL)
		return;

	free(acl->net);
	free(acl->allow);
	free(acl->deny);
	free(acl);
}

acl_t *acl_match_net(acl_t **acl, char *address)
{
	char a[INET6_ADDRSTRLEN];
	acl_net_t n1, *n2;
	acl_t *result = NULL;
	int bits = 0;

	if (address == NULL)
		return(NULL);

	memset(a, 0, INET6_ADDRSTRLEN);

	while (*acl) {
		n2 = (*acl)->net;
		while (n2->bits > 0) {
			sprintf(a, "%s/%d", address, n2->bits);
			acl_net_init(a, &n1);
			if (memcmp(&n1.network, &n2->network, sizeof(acl_network_t)) == 0) {
				if ((result == NULL) || (bits < n2->bits)) {
					result = *acl;
					bits = n2->bits;
				}
			}
			n2++;
		}
		acl++;
	}

	return(result);
}

acl_t *acl_match_auth(acl_t **acl, char *auth)
{
	acl_t *result = NULL;

	if (auth == NULL)
		return(NULL);

	while (*acl) {
		if ((*acl)->auth != NULL)
			if (strcmp(auth, (*acl)->auth) == 0) {
				result = *acl;
				break;
			}
		acl++;
	}

	return(result);
}

acl_t *acl_match_cert(acl_t **acl, char *cert)
{
	acl_t *result = NULL;

	if (cert == NULL)
		return(NULL);

	while (*acl) {
		if ((*acl)->cert != NULL)
			if (strcmp(cert, (*acl)->cert) == 0) {
				result = *acl;
				break;
			}
		acl++;
	}

	return(result);
}
