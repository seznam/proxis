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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <event.h>

#include "resp.h"

resp_t *resp_string(resp_type_t type, char prefix, char *content)
{
	resp_t *result = (resp_t *)malloc(sizeof(resp_t));

	if ((result == NULL) || (content == NULL))
		return(NULL);

	result->type = type;
	result->payload = (char *)malloc(strlen(content) + 5);

	if (result->payload == NULL) {
		free(result);
		return(NULL);
	}

	memset(result->payload, 0, strlen(content) + 5);
	sprintf((char *)result->payload, "%c%s\r\n", prefix, content);

	result->len = strlen(result->payload);

	return(result);
}

resp_t *resp_msg(char *msg)
{
	return(resp_string(RESP_MSG, '+', msg));
}

resp_t *resp_err(char *err)
{
	return(resp_string(RESP_ERR, '-', err));
}

// NOTE: commands composed via resp_command() cannot contain \0, beacuse strlen() and sprintf() are used here
resp_t *resp_command(char *command, ...)
{
	va_list va;
	char *arg;
	int count = 1, len = strlen(command) + 20;
	resp_t *result = (resp_t *)malloc(sizeof(resp_t));

	if ((result == NULL) || (command == NULL))
		return(NULL);

	va_start(va, command);

	while ((arg = va_arg(va, char *))) {
		len += strlen(arg) + 15;
		count++;
	}

	va_end(va);

	result->type = RESP_ARRAY;
	result->payload = (char *)malloc(len);

	if (result->payload == NULL) {
		free(result);
		return(NULL);
	}

	memset(result->payload, 0, len);
	sprintf((char *)result->payload, "*%d\r\n$%ld\r\n%s\r\n", count, strlen(command), command);

	va_start(va, command);

	while ((arg = va_arg(va, char *)))
		sprintf((char *)result->payload + strlen(result->payload), "$%ld\r\n%s\r\n", strlen(arg), arg);

	va_end(va);

	result->len = strlen(result->payload);

	return(result);
}

void resp_free(resp_t *obj)
{
	if (obj == NULL)
		return;

	free(obj->payload);
	obj->payload = NULL;
	obj->len = 0;
	free(obj);
}

int resp_parse_quantity(resp_buffer_t *buffer, char prefix, int *dst)
{
	char *c;
	int i;

	if ((buffer == NULL) || (buffer->eb == NULL))
		return(-1);

	i = buffer->parsed + 4;

	while ((c = evbuffer_pullup(buffer->eb, i)) != NULL) {
		if ((c[i - 2] == '\r') && (c[i - 1] == '\n'))
			break;
		i++;
	}

	if (c == NULL)
		return(0);

	if (c[buffer->parsed] != prefix)
		return(-1);

	c[i - 1] = '\0';
	if (sscanf(c + buffer->parsed + 1, "%d\r", dst) != 1)
		return(-1);
	c[i - 1] = '\n';

	buffer->parsed = i;

	return(1);
}

int resp_parse_count(resp_buffer_t *buffer, int *dst)
{
	return(resp_parse_quantity(buffer, '*', dst));
}

int resp_parse_length(resp_buffer_t *buffer, int *dst)
{
	return(resp_parse_quantity(buffer, '$', dst));
}

int resp_parse_buffer(resp_buffer_t *buffer)
{
	char *c;
	int i;

	if (buffer == NULL)
		return(-1);

	if (buffer->pending_parts == 0) {
		i = resp_parse_count(buffer, &buffer->pending_parts);
		if (i <= 0)
			return(i);
	}

	if (buffer->pending_parts == 0)
		return(buffer->parsed);

	if (buffer->pending_bytes == 0) {
		i = resp_parse_length(buffer, &buffer->pending_bytes);
		if (i <= 0)
			return(i);
		buffer->expected_bytes = buffer->pending_bytes;
	}

	if (buffer->cmd == NULL) {
		i = buffer->pending_bytes + 2;
		if ((c = evbuffer_pullup(buffer->eb, buffer->parsed + i)) == NULL)
			return(0);
		buffer->cmd = c + buffer->parsed;
		buffer->cmdlen = buffer->pending_bytes;
		buffer->pending_bytes = 0;
		buffer->pending_parts--;
	} else {
		i = evbuffer_get_length(buffer->eb) - buffer->parsed;
		if (i >= (buffer->pending_bytes + 2)) {
			i = buffer->pending_bytes + 2;
			buffer->pending_bytes = 0;
			buffer->pending_parts--;
		} else {
			buffer->pending_bytes -= i;
		}
	}

	buffer->parsed += i;

	return(buffer->parsed);
}

char *resp_get_last_value(resp_buffer_t *buffer) {
	char *c;

	if (buffer->pending_bytes > 0)
		return(NULL);

	if ((c = evbuffer_pullup(buffer->eb, buffer->parsed)) == NULL)
		return(NULL);

	c += buffer->parsed - (buffer->expected_bytes + 2);

	return(strndup(c, buffer->expected_bytes));
}
