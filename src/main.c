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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <pwd.h>
#include <libconfig.h>
#include <openssl/ssl.h>

#include "log.h"
#include "acl.h"
#include "proxy.h"

#define NAME PROJECT_NAME
#define VERSION PROJECT_VERSION

int sigterm, sighup, sigalarm, sigusr1, sigusr2;

void usage(char *command)
{
	printf("%s (%s): TLS + ACL proxy for redis\n\n", NAME, VERSION);
	printf("Usage: %s [options]\n\n", command);
	printf("Options:\n");
	printf("  -h --help           Print this help\n");
	printf("  -c --config file    Read configuration from file\n");
	printf("  -t --test           Test configuration\n");
	printf("  -f --foreground     Don't daemonize and run in foreground\n");
	printf("\n");
	exit(1);
}

void
signal_handle(int sig)
{
	switch (sig) {
	case SIGTERM:
		sigterm = 1;
		signal(SIGTERM, signal_handle);
		break;
	case SIGHUP:
		sighup = 1;
		signal(SIGHUP, signal_handle);
		break;
	case SIGALRM:
		sigalarm = 1;
		signal(SIGALRM, signal_handle);
		break;
	case SIGUSR1:
		sigusr1 = 1;
		signal(SIGUSR1, signal_handle);
		break;
	case SIGUSR2:
		sigusr2 = 1;
		signal(SIGUSR2, signal_handle);
		break;
	}
}

int main(int argc, char **argv)
{
	int a, i = 0, daemonize = 1, test = 0;
	FILE *pid;
	struct passwd *process_user = NULL;
	uid_t process_user_id;
	config_t config;
	config_setting_t *s;
	acl_t **acl;
	proxy_t **proxy, **p;

	struct option long_options[] = {
		{"config", required_argument, 0, 'c'},
		{"test", no_argument, 0, 't'},
		{"help", no_argument, 0, 'h'},
		{"foreground", no_argument, 0, 'f'},
		{NULL, 0, 0, 0}
	};

	if (log_open(NULL, "ALL") < 0) {
		printf("log_open() problem: can't open stdout for initial logging\n");
		exit(1);
	}

	memset(&config, 0, sizeof(config_t));

	while ((a = getopt_long(argc, argv, "c:t:hf", long_options, &i)) != -1)
		switch (a) {
		case 'c':
			LOG(D1, "got configuration file '%s'", optarg);
			if (config_read_file(&config, optarg) != CONFIG_TRUE) {
				LOG(E1, "failed to read configuration from '%s', %s on line %d", optarg, config_error_text(&config), config_error_line(&config));
				exit(1);
			}
			break;
		case 't':
			test = 1;
			break;
		case 'f':
			daemonize = 0;
			break;
		default:
			usage(argv[0]);
			return((a == 'h') ? 0:1);
			break;
		}

	if (config.root == NULL) {
		LOG(E1, "missing configuration file");
		usage(argv[0]);
		exit(1);
	}

	LOG(I1, "initializing");

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif

	const char *user = NULL;
	config_lookup_string(&config, "user", &user);

	if (user) {
		if ((process_user = getpwnam(user)) == NULL)
			if (sscanf(user, "%d", &process_user_id) == 1)
				process_user = getpwuid(process_user_id);
		if (process_user == NULL) {
			LOG(E1, "can't resolve user '%s' to run as, exiting", user);
			exit(1);
		}
	}

	s = config_lookup(&config, "acl");
	if (s == NULL) {
		LOG(E1, "missing 'acl' configuration");
		exit(1);
	}
	i = config_setting_length(s);
	if ((config_setting_is_list(s) == CONFIG_FALSE) || (i == 0)) {
		LOG(E1, "invalid 'acl' configuration");
		exit(1);
	}
	if ((acl = (acl_t **)malloc((i + 1) * sizeof(acl_t *))) == NULL) {
		LOG(E1, "malloc() failed, %s", strerror(errno));
		exit(1);
	}
	memset(acl, 0, (i + 1) * sizeof(acl_t *));
	for (a = 0; a < i; a++)
		if ((acl[a] = acl_create(config_setting_get_elem(s, a))) == NULL)
			exit(1);

	if (daemonize && !test) {
		LOG(I1, "forking to background");
		pid_t reborn = fork();
		const char *pidfile = NULL;
		switch (reborn) {
		case -1:
			LOG(E1, "fork() failed, %s", strerror(errno));
			exit(1);
			break;
		case 0:
			close(0);
			close(2);
			break;
		default:
			LOG(D1, "backgrounded to pid %d", reborn);
			config_lookup_string(&config, "pidfile", &pidfile);
			if (pidfile != NULL) {
				if ((pid = fopen(pidfile, "w")) == NULL) {
					LOG(W1, "fopen() failed: can't write pid file '%s'; %s", pidfile, strerror(errno));
				} else {
					fprintf(pid, "%d\n", reborn);
					fclose(pid);
				}
			}
			sleep(1);
			exit(0);
			break;
		}
	}

	s = config_lookup(&config, "proxy");
	if (s == NULL) {
		LOG(E1, "missing 'proxy' configuration");
		exit(1);
	}
	i = config_setting_length(s);
	if ((config_setting_is_list(s) == CONFIG_FALSE) || (i == 0)) {
		LOG(E1, "invalid 'proxy' configuration");
		exit(1);
	}
	if ((proxy = (proxy_t **)malloc((i + 1) * sizeof(proxy_t *))) == NULL) {
		LOG(E1, "malloc() failed, %s", strerror(errno));
		exit(1);
	}
	memset(proxy, 0, (i + 1) * sizeof(proxy_t *));
	for (a = 0; a < i; a++)
		if ((proxy[a] = proxy_create(config_setting_get_elem(s, a), acl)) == NULL)
			exit(1);

	const char *chroot_dir = NULL;
	config_lookup_string(&config, "chroot", &chroot_dir);

	if (chroot_dir != NULL) {
		LOG(D1, "chrooting to '%s'", chroot_dir);
		if (chdir(chroot_dir) == -1) {
			LOG(E1, "chdir() to '%s' failed, %s", chroot_dir, strerror(errno));
			exit(1);
		}
		if (chroot(chroot_dir) == -1) {
			LOG(E1, "chroot() to '%s' failed, %s", chroot_dir, strerror(errno));
			exit(1);
		}
	}

	if (process_user != NULL) {
		if (seteuid(process_user->pw_uid) == -1) {
			LOG(E1, "setuid() to '%s' failed, %s", user, strerror(errno));
			exit(1);
		}
		LOG(D1, "running as user '%s'", user);
	}

	if (test) {
		printf("config file test successful\n");
		exit(0);
	}

	const char *logfile = NULL, *logmask = NULL;
	config_lookup_string(&config, "logfile", &logfile);
	config_lookup_string(&config, "logmask", &logmask);

	LOG(D1, "opening logfile '%s'", logfile);

	if (log_open(logfile, logmask) == -1) {
		log_open(NULL, NULL);
		LOG(E1, "log_open() problem: can't open logfile '%s'; %s", logfile, strerror(errno));
		exit(1);
	}

	if (daemonize)
		close(1);

	LOG(I1, "logfile opened");
	log_dump_mask();

	signal(SIGTERM, signal_handle);
	signal(SIGALRM, signal_handle);
	signal(SIGHUP, signal_handle);
	signal(SIGUSR1, signal_handle);
	signal(SIGUSR2, signal_handle);

	p = proxy;

	while (*p)
		proxy_start(*(p++));

	while (1) {
		if (sigterm) {
			LOG(I1, "got TERM signal, exiting");
			break;
		}
		if (sighup) {
			LOG(I1, "got HUP signal, closing logfile");
			log_close();
			if (log_open(logfile, logmask) != -1)
				LOG(I1, "logfile re-opened");
			sighup = 0;
		}
		usleep(10000);
	}

	p = proxy;

	while (*p)
		proxy_stop(*(p++));

	LOG(I1, "closing logfile");
	log_close();

	config_destroy(&config);

	return(0);
}
