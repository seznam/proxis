#ifndef RESP_H
#define RESP_H

#include <event.h>

typedef enum {
	RESP_MSG, RESP_ERR, RESP_INT, RESP_STRING, RESP_ARRAY
} resp_type_t;

typedef struct {
	struct evbuffer *eb;
	int parsed;
	int pending_parts;
	int pending_bytes, expected_bytes;
	char *cmd;
	int cmdlen;
} resp_buffer_t;

typedef struct {
	resp_type_t type;
	void *payload;
	int len;
} resp_t;

resp_t *resp_msg(char *msg);
resp_t *resp_err(char *err);
resp_t *resp_command(char *command, ...);
void resp_free(resp_t *obj);
int resp_parse_buffer(resp_buffer_t *buffer);
char *resp_get_last_value(resp_buffer_t *buffer);

#endif
