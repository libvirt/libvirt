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

/* This file intentionally does not link to libvirt/glib */
#define VIR_NO_GLIB_STDIO
#define cleanup(T, F) __attribute__((cleanup(F))) T
#include "testutils.h"

#ifndef WIN32
# include <poll.h>

/* Some UNIX lack it in headers & it doesn't hurt to redeclare */
extern char **environ;

# define VIR_FROM_THIS VIR_FROM_NONE

struct Arguments {
    int *readfds;
    int numreadfds;
    bool daemonize_check;
    bool close_stdin;
};

static void cleanupArguments(struct Arguments **ptr)
{
    struct Arguments *args = *ptr;

    if (args)
        free(args->readfds);

    free(args);
}

static void cleanupStringList(char ***ptr)
{
    char **strings = *ptr;

    if (strings) {
        char **str;
        for (str = strings; *str; str++)
            free(*str);
    }

    free(strings);
}

static void cleanupFile(FILE **ptr)
{
    FILE *file = *ptr;
    fclose(file);
}

static void cleanupGeneric(void *ptr)
{
    void **ptrptr = ptr;
    free (*ptrptr);
}

static struct Arguments *parseArguments(int argc, char** argv)
{
    cleanup(struct Arguments *, cleanupArguments) args = NULL;
    struct Arguments *ret;
    size_t i;

    if (!(args = calloc(1, sizeof(*args))))
        return NULL;

    if (!(args->readfds = calloc(1, sizeof(*args->readfds))))
        return NULL;

    args->numreadfds = 1;
    args->readfds[0] = STDIN_FILENO;

    for (i = 1; i < argc; i++) {
        if (STREQ(argv[i - 1], "--readfd")) {
            char c;

            args->readfds = realloc(args->readfds,
                                    (args->numreadfds + 1) *
                                    sizeof(*args->readfds));
            if (!args->readfds)
                return NULL;

            if (1 != sscanf(argv[i], "%u%c",
                            &args->readfds[args->numreadfds++], &c)) {
                printf("Could not parse fd %s\n", argv[i]);
                return NULL;
            }
        } else if (STREQ(argv[i], "--check-daemonize")) {
            args->daemonize_check = true;
        } else if (STREQ(argv[i], "--close-stdin")) {
            args->close_stdin = true;
        }
    }

    ret = g_steal_pointer(&args);
    return ret;
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
    cleanup(char **, cleanupGeneric) newenv = NULL;
    size_t length;
    size_t i;

    for (length = 0; environ[length]; length++) {
    }

    if (length == 0)
        return 0;

    if (!(newenv = malloc(sizeof(*newenv) * length)))
        return -1;

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

    return 0;
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

static void printDaemonization(FILE *log, struct Arguments *args)
{
    int retries = 3;

    if (args->daemonize_check) {
        while ((getpgrp() == getppid()) && (retries-- > 0)) {
            usleep(100 * 1000);
        }
    }

    fprintf(log, "DAEMON:%s\n", getpgrp() != getppid() ? "yes" : "no");
}

static int printCwd(FILE *log)
{
    cleanup(char *, cleanupGeneric) cwd = NULL;
    char *display;

    if (!(cwd = getcwd(NULL, 0)))
        return -1;

    if ((display = strstr(cwd, "/commanddata")) &&
        STREQ(display, "/commanddata")) {
        fprintf(log, "CWD:.../commanddata\n");
        return 0;
    }

    display = cwd;

# ifdef __APPLE__
    if (strstr(cwd, "/private"))
        display = cwd + strlen("/private");
# endif

    fprintf(log, "CWD:%s\n", display);
    return 0;
}

static int printInput(struct Arguments *args)
{
    char buf[1024];
    cleanup(struct pollfd *, cleanupGeneric) fds = NULL;
    cleanup(char **, cleanupStringList) buffers = NULL;
    cleanup(size_t *, cleanupGeneric) buflen = NULL;
    size_t i;
    ssize_t got;

    if (!(fds = calloc(args->numreadfds, sizeof(*fds))))
        return -1;

    /* plus one NULL terminator */
    if (!(buffers = calloc(args->numreadfds + 1, sizeof(*buffers))))
        return -1;

    if (!(buflen = calloc(args->numreadfds, sizeof(*buflen))))
        return -1;

    if (args->close_stdin) {
        if (freopen("/dev/null", "r", stdin) != stdin)
            return -1;
        usleep(100 * 1000);
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
            return -1;
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
                    return -1;
                if (got == 0) {
                    /* do not want to hear from this fd anymore */
                    fds[i].events = 0;
                } else {
                    buffers[i] = realloc(buffers[i], buflen[i] + got);
                    if (!buf[i]) {
                        fprintf(stdout, "Out of memory!\n");
                        return -1;
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
            return -1;
        if (fwrite(buffers[i], 1, buflen[i], stderr) != buflen[i])
            return -1;
    }

    fprintf(stdout, "END STDOUT\n");
    fflush(stdout);
    fprintf(stderr, "END STDERR\n");
    fflush(stderr);

    return 0;
}

int main(int argc, char **argv) {
    cleanup(struct Arguments *, cleanupArguments) args = NULL;
    cleanup(FILE *, cleanupFile) log = NULL;

    if (!(log = fopen(abs_builddir "/commandhelper.log", "w")))
        return EXIT_FAILURE;

    if (!(args = parseArguments(argc, argv)))
        return EXIT_FAILURE;

    printArguments(log, argc, argv);

    if (printEnvironment(log) != 0)
        return EXIT_FAILURE;

    if (printFds(log) != 0)
        return EXIT_FAILURE;

    printDaemonization(log, args);

    if (printCwd(log) != 0)
        return EXIT_FAILURE;

    fprintf(log, "UMASK:%04o\n", umask(0));

    if (printInput(args) != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
