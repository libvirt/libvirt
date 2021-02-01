/*
 * commandhelper.c: Auxiliary program for commandtest
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define VIR_NO_GLIB_STDIO /* This file intentionally does not link to libvirt/glib */
#include "testutils.h"

#ifndef WIN32
# include <poll.h>

/* Some UNIX lack it in headers & it doesn't hurt to redeclare */
extern char **environ;

# define VIR_FROM_THIS VIR_FROM_NONE

struct Arguments {
    int readfds[3];
    int numreadfds;
    bool daemonize_check;
    bool close_stdin;
};

static struct Arguments *parseArguments(int argc, char** argv)
{
    struct Arguments* args = NULL;
    int ret = -1;
    size_t i;

    if (!(args = calloc(1, sizeof(*args))))
        goto cleanup;

    args->numreadfds = 1;
    args->readfds[0] = STDIN_FILENO;

    for (i = 1; i < argc; i++) {
        if (STREQ(argv[i - 1], "--readfd")) {
            char c;

            if (1 != sscanf(argv[i], "%u%c",
                            &args->readfds[args->numreadfds++], &c)) {
                printf("Could not parse fd %s\n", argv[i]);
                goto cleanup;
            }
        } else if (STREQ(argv[i], "--check-daemonize")) {
            args->daemonize_check = true;
        } else if (STREQ(argv[i], "--close-stdin")) {
            args->close_stdin = true;
        }
    }

    ret = 0;

 cleanup:
    if (ret == 0)
        return args;

    free(args);
    return NULL;
}

static void printArguments(FILE *log, int argc, char** argv)
{
    size_t i;

    for (i = 1; i < argc; i++) {
        fprintf(log, "ARG:%s\n", argv[i]);
    }
}

static int envsort(const void *a, const void *b)
{
    const char *astr = *(const char**)a;
    const char *bstr = *(const char**)b;

    while (true) {
        char achar = (*astr == '=') ? '\0' : *astr;
        char bchar = (*bstr == '=') ? '\0' : *bstr;

        if ((achar == '\0') || (achar != bchar))
            return achar - bchar;

        astr++;
        bstr++;
    }
}

static int printEnvironment(FILE *log)
{
    char **newenv;
    size_t length;
    size_t i;
    int ret = -1;

    for (length = 0; environ[length]; length++) {
    }

    if (!(newenv = malloc(sizeof(*newenv) * length)))
        goto cleanup;

    for (i = 0; i < length; i++) {
        newenv[i] = environ[i];
    }

    qsort(newenv, length, sizeof(newenv[0]), envsort);

    for (i = 0; i < length; i++) {
        /* Ignore the variables used to instruct the loader into
         * behaving differently, as they could throw the tests off. */
        if (!STRPREFIX(newenv[i], "LD_"))
            fprintf(log, "ENV:%s\n", newenv[i]);
    }

    ret = 0;

 cleanup:
    if (newenv)
        free(newenv);
    return ret;
}

static int printFds(FILE *log)
{
    long int open_max = sysconf(_SC_OPEN_MAX);
    size_t i;

    if (open_max < 0)
        return -1;

    for (i = 0; i < open_max; i++) {
        int ignore;

        if (i == fileno(log))
            continue;

        if (fcntl(i, F_GETFD, &ignore) == -1 && errno == EBADF)
            continue;

        fprintf(log, "FD:%zu\n", i);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct Arguments *args = parseArguments(argc, argv);
    size_t i;
    char *cwd;
    FILE *log = fopen(abs_builddir "/commandhelper.log", "w");
    int ret = EXIT_FAILURE;
    struct pollfd fds[3];
    char *buffers[3] = {NULL, NULL, NULL};
    size_t buflen[3] = {0, 0, 0};
    size_t daemonize_retries = 3;
    char buf[1024];
    ssize_t got;

    if (!log || !args)
        goto cleanup;

    printArguments(log, argc, argv);

    if (printEnvironment(log) != 0)
        goto cleanup;

    if (printFds(log) != 0)
        goto cleanup;

    while (true) {
        bool daemonized = getpgrp() != getppid();

        if (args->daemonize_check && !daemonized && daemonize_retries-- > 0) {
            usleep(100*1000);
            continue;
        }

        fprintf(log, "DAEMON:%s\n", daemonized ? "yes" : "no");
        break;
    }

    if (!(cwd = getcwd(NULL, 0)))
        goto cleanup;
    if (strlen(cwd) > strlen(".../commanddata") &&
        STREQ(cwd + strlen(cwd) - strlen("/commanddata"), "/commanddata"))
        strcpy(cwd, ".../commanddata");
# ifdef __APPLE__
    char *noprivateprefix = NULL;
    if (strstr(cwd, "/private"))
        noprivateprefix = cwd + strlen("/private");
    else
        noprivateprefix = cwd;
    fprintf(log, "CWD:%s\n", noprivateprefix);
# else
    fprintf(log, "CWD:%s\n", cwd);
# endif
    free(cwd);

    fprintf(log, "UMASK:%04o\n", umask(0));

    if (args->close_stdin) {
        if (freopen("/dev/null", "r", stdin) != stdin)
            goto cleanup;
        usleep(100*1000);
    }

    fprintf(stdout, "BEGIN STDOUT\n");
    fflush(stdout);
    fprintf(stderr, "BEGIN STDERR\n");
    fflush(stderr);

    for (i = 0; i < args->numreadfds; i++) {
        fds[i].fd = args->readfds[i];
        fds[i].events = POLLIN;
        fds[i].revents = 0;
    }

    for (;;) {
        unsigned ctr = 0;

        if (poll(fds, args->numreadfds, -1) < 0) {
            printf("poll failed: %s\n", strerror(errno));
            goto cleanup;
        }

        for (i = 0; i < args->numreadfds; i++) {
            short revents = POLLIN | POLLHUP | POLLERR;

# ifdef __APPLE__
            /*
             * poll() on /dev/null will return POLLNVAL
             * Apple-Feedback: FB8785208
             */
            revents |= POLLNVAL;
# endif

            if (fds[i].revents & revents) {
                fds[i].revents = 0;

                got = read(fds[i].fd, buf, sizeof(buf));
                if (got < 0)
                    goto cleanup;
                if (got == 0) {
                    /* do not want to hear from this fd anymore */
                    fds[i].events = 0;
                } else {
                    buffers[i] = realloc(buffers[i], buflen[i] + got);
                    if (!buf[i]) {
                        fprintf(stdout, "Out of memory!\n");
                        goto cleanup;
                    }
                    memcpy(buffers[i] + buflen[i], buf, got);
                    buflen[i] += got;
                }
            }
        }
        for (i = 0; i < args->numreadfds; i++) {
            if (fds[i].events) {
                ctr++;
                break;
            }
        }
        if (ctr == 0)
            break;
    }

    for (i = 0; i < args->numreadfds; i++) {
        if (fwrite(buffers[i], 1, buflen[i], stdout) != buflen[i])
            goto cleanup;
        if (fwrite(buffers[i], 1, buflen[i], stderr) != buflen[i])
            goto cleanup;
    }

    fprintf(stdout, "END STDOUT\n");
    fflush(stdout);
    fprintf(stderr, "END STDERR\n");
    fflush(stderr);

    ret = EXIT_SUCCESS;

 cleanup:
    for (i = 0; i < G_N_ELEMENTS(buffers); i++)
        free(buffers[i]);
    if (args)
        free(args);
    if (log)
        fclose(log);
    return ret;
}

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
