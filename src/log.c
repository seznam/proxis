/* Copyright (c) 2006-2012, Daniel Bilik <daniel.bilik@neosystem.cz>
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#include "log.h"

extern char **environ;

struct logmask_t {
	char err, warn, info, debug, fatal;
} logmask;

FILE *logfile = NULL;

void
log_set_mask(const char *mask)
{
	char **env = environ, *a = *env, defaultmask[] = "E9W4I2D0F9", allmask[] = "E9W9I9D9F9";

	if (mask && (strcasecmp(mask, "ALL") == 0))
		mask = allmask;

	if (mask == NULL) {
		mask = defaultmask;
		while (a)
			if (strcasecmp(a, "LOGMASK=ALL") == 0) {
				mask = allmask;
				a = NULL;
			} else if (strstr(a, "LOGMASK=") == a) {
				mask = strchr(a, '=') + 1;
				a = NULL;
			} else {
				env++;
				a = *env;
			}
	}

	while (*mask) {
		switch ((int) *mask) {
		case 'E':
			mask++;
			logmask.err = (int) *mask - 48;
			break;
		case 'W':
			mask++;
			logmask.warn = (int) *mask - 48;
			break;
		case 'I':
			mask++;
			logmask.info = (int) *mask - 48;
			break;
		case 'D':
			mask++;
			logmask.debug = (int) *mask - 48;
			break;
		case 'F':
			mask++;
			logmask.fatal = (int) *mask - 48;
			break;
		}
		mask++;
	}
}

int
log_open(const char *path, const char *logmask)
{
	log_set_mask(logmask);

	if (path == NULL) {
		logfile = stdout;
		return(0);
	}

	if ((logfile = fopen(path, "a")) == NULL)
		return(-1);

	if (setvbuf(logfile, (char *)NULL, _IOLBF, 0) == EOF)
		return(-1);

	return(0);
}

int
log_close(void)
{
	if (logfile != NULL) {
		if (logfile == stdout) {
			logfile = NULL;
			return(0);
		}
		flockfile(logfile);
		if (fclose(logfile) == 0) {
			logfile = NULL;
			return(0);
		} else
			return(-2);
	} else
		return(-1);
}

int
log_write(char level, char *message, ...)
{
	char *fullmessage, a, b, *c, *d;
	signed int e;
	unsigned int f;
	long int g;
	double h;
	char now[20] = "";
	time_t timeunix;
	struct tm *timestruct;
	va_list data;

	if (logfile == NULL)
		return(-1);

	switch (level & 240) {
	case 16:
		a = logmask.err;
		b = 'E';
		break;
	case 32:
		a = logmask.warn;
		b = 'W';
		break;
	case 64:
		a = logmask.info;
		b = 'I';
		break;
	case 128:
		a = logmask.debug;
		b = 'D';
		break;
	case 144:
		a = logmask.fatal;
		b = 'F';
		break;
	default:
		a = 0;
		b = 0;
	}

	if (a >= (level & 15)) {
		time(&timeunix);
		timestruct = localtime(&timeunix);
		strftime(now, 20, "%d/%m/%Y %H:%M:%S", timestruct);
		if ((fullmessage = malloc(strlen(now) + strlen(message) + 6)) == NULL) {
			fprintf(logfile, "malloc() problem: can't allocate memory: %s (%s:%d)\n", strerror(errno), __FILE__, __LINE__);
			return(-2);
		}
		sprintf(fullmessage, "%s %c%d: %s", now, b, (level & 15), message);
		va_start(data, message);
		c = fullmessage;
		while (logfile && ftrylockfile(logfile))
			usleep(5000);
		while (*c && logfile) {
			if ((*c) == '%') {
				c++;
				switch (*c) {
				case 's':
					d = va_arg(data, char *);
					if (d == NULL)
						fprintf(logfile, "(null)");
					else
						fprintf(logfile, "%s", d);
					break;
				case 'd':
					e = va_arg(data, signed int);
					fprintf(logfile, "%d", e);
					break;
				case 'u':
					f = va_arg(data, unsigned int);
					fprintf(logfile, "%d", f);
					break;
				case 'l':
					g = va_arg(data, long int);
					fprintf(logfile, "%ld", g);
					break;
				case 'f':
					h = va_arg(data, double);
					fprintf(logfile, "%f", h);
					break;
				default:
					fprintf(logfile, "%%%c", *c);
				}
			}
			else
				fprintf(logfile, "%c", *c);
			c++;
		}
		if (logfile)
			funlockfile(logfile);
		va_end(data);
		free(fullmessage);
	}

	return(0);
}

void
log_dump_mask(void)
{
	LOG(D4, "logmask set: E%dW%dI%dD%dF%d", logmask.err, logmask.warn, logmask.info, logmask.debug, logmask.fatal);
}
