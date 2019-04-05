#ifndef ACL_H
#define ACL_H

#include <netinet/in.h>
#include <libconfig.h>

typedef uint32_t acl_network_t[4];

typedef struct {
	int family;
	int bits;
	acl_network_t network;
} acl_net_t;

typedef struct {
	const char *id;
	const char *auth;
	const char *cert;
	acl_net_t *net;
	const char **allow;
	const char **deny;
} acl_t;

acl_t *acl_create(config_setting_t *config);
void acl_destroy(acl_t *acl);
acl_t *acl_match_net(acl_t **acl, char *address);
acl_t *acl_match_auth(acl_t **acl, char *auth);
acl_t *acl_match_cert(acl_t **acl, char *cert);

#endif
