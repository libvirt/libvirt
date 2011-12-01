/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

/*
 * When libvirt initializes, it creates a thread local for storing
 * the last virErrorPtr instance. It also registers a cleanup
 * callback for the thread local that will be invoked whenever
 * a thread exits.
 *
 * If the libvirt.so library was dlopen()'d and is dlclose()'d
 * while there is still a thread present, then when that thread
 * later exits, the libvirt cleanup callback will be invoked.
 * Unfortunately libvirt.so will no longer be in memory so the
 * callback SEGVs (if you're lucky), or invokes unlreated
 * code at the same address as the old callback (if you're
 * unlucky).
 *
 * To fix the problem libvirt is linked '-z nodelete' which
 * prevents the code being removed from memory at dlclose().
 *
 * This test case demonstrates this SEGV scenario. If this
 * test does not SEGV, then the '-z nodelete' fix is working
 */

#include <config.h>

#ifdef linux

# include <dlfcn.h>
# include <pthread.h>
# include <stdbool.h>
# include <stdio.h>
# include <unistd.h>
# include <signal.h>

# include "internal.h"
# include "ignore-value.h"
# include "testutils.h"

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
bool running = false;
bool quit = false;

static void *threadMain(void *arg)
{
    void (*startup)(void) = arg;

    startup();

    pthread_mutex_lock(&lock);
    running = true;
    pthread_cond_signal(&cond);

    while (!quit) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);

    return NULL;
}

static void sigHandler(int sig)
{
    ignore_value(write(STDERR_FILENO, "FAIL\n", 5));
    signal(sig, SIG_DFL);
    raise(sig);
}

/* We're not using the testutils.c main() wrapper because
 * we don't want  'shunloadtest' itself to link against
 * libvirt.so. We need to test dlopen()'ing of libvirt.so
 */
int main(int argc ATTRIBUTE_UNUSED, char **argv)
{
    void (*startup)(void);
    pthread_t t;
    void *lib;
    char *theprogname;

    theprogname = argv[0];
    if (STRPREFIX(theprogname, "./"))
        theprogname += 2;

    fprintf(stderr, "TEST: %s\n", theprogname);
    fprintf(stderr, "      .%*s 1   ", 39, "");
    signal(SIGSEGV, sigHandler);

    if (!(lib = dlopen("./.libs/libshunload.so", RTLD_LAZY))) {
        fprintf(stderr, "Cannot load ./.libs/libshunload.so %s\n", dlerror());
        return 1;
    }
    if (!(startup = dlsym(lib, "shunloadStart"))) {
        fprintf(stderr, "Cannot find shunloadStart %s\n", dlerror());
        return 1;
    }

    /*
     * Create a thread which is going to initialize libvirt
     * and raise an error
     */
    pthread_create(&t, NULL, threadMain, startup);

    /* Wait for the thread to start and call libvirt */
    pthread_mutex_lock(&lock);
    while (!running) {
        pthread_cond_wait(&cond, &lock);
    }

    /* Close the shared library (and thus make libvirt.so
     * non-resident */
    dlclose(lib);

    /* Tell the thread to quit */
    quit = true;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    pthread_join(t, NULL);

    /* If we got to here the thread successfully exited without
     * causing a SEGV !
     */

    fprintf(stderr, "OK\n");

    return 0;
}

#else
# include "testutils.h"

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif
