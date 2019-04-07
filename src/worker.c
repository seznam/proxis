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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "log.h"
#include "worker.h"

#define USLEEP 5000

void *worker_thread(void *arg)
{
	useconds_t time_sleep;
	worker_t *me = (worker_t *)arg;

	if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) != 0)
		LOG(W1, "pthread_setcancelstate() failed, %s", strerror(errno));
	if (pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) != 0)
		LOG(W1, "pthread_setcanceltype() failed, %s", strerror(errno));

	while (me->state != EXIT) {
		time_sleep = USLEEP;
		switch (me->command) {
		case SLEEP:
			if (me->state != SLEEP) {
				LOG(D1, "%s falling asleep", me->name);
				me->state = SLEEP;
			}
			break;
		case RUN:
			if (me->state != RUN) {
				LOG(D1, "%s awaking", me->name);
				me->state = RUN;
			}
			me->run(me->arg);
			break;
		case EXIT:
			time_sleep = 0;
			LOG(D1, "%s exiting", me->name);
			me->state = EXIT;
			break;
		}
		usleep(time_sleep);
	}

	return(NULL);
}

void worker_instruct(worker_t *w, worker_command_t command)
{
	int timeout = time(NULL) + 5;

	if (w == NULL)
		return;

	w->command = command;

	while ((w->state != w->command) && (timeout < time(NULL)))
		usleep(USLEEP);
}

worker_t *worker_create(char *name, void (*run)(void *), void *arg)
{
	worker_t *w = NULL;

	if ((w = (worker_t *)malloc(sizeof(worker_t))) == NULL) {
		LOG(E1, "malloc() failed, %s", strerror(errno));
		return(NULL);
	}

	w->name = strdup(name);
	w->run = run;
	w->arg = arg;
	w->state = INIT;
	w->command = SLEEP;

	if (pthread_create(&w->id, 0, worker_thread, w) != 0) {
		LOG(E1, "pthread_create() failed, %s", strerror(errno));
		free(w);
		return(NULL);
	}

	LOG(I1, "%s created", name);

	return(w);
}

void worker_destroy(worker_t *w)
{
	if (w == NULL)
		return;

	worker_instruct(w, EXIT);

	pthread_join(w->id, NULL);

	LOG(I1, "%s destroyed", w->name);

	if (w->name)
		free(w->name);
}
