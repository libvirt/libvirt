/*
 * eventtest.c: Test the libvirtd event loop impl
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include "testutils.h"
#include "internal.h"
#include "threads.h"
#include "logging.h"
#include "util.h"
#include "../qemud/event.h"

#define NUM_FDS 5
#define NUM_TIME 5

static struct handleInfo {
    int pipeFD[2];
    int fired;
    int watch;
    int error;
    int delete;
} handles[NUM_FDS];

static struct timerInfo {
    int timeout;
    int timer;
    int fired;
    int error;
    int delete;
} timers[NUM_TIME];

enum {
    EV_ERROR_NONE,
    EV_ERROR_WATCH,
    EV_ERROR_FD,
    EV_ERROR_EVENT,
    EV_ERROR_DATA,
};

static void
testPipeReader(int watch, int fd, int events, void *data)
{
    struct handleInfo *info = data;
    char one;

    info->fired = 1;

    if (watch != info->watch) {
        info->error = EV_ERROR_WATCH;
        return;
    }

    if (fd != info->pipeFD[0]) {
        info->error = EV_ERROR_FD;
        return;
    }

    if (!(events & VIR_EVENT_HANDLE_READABLE)) {
        info->error = EV_ERROR_EVENT;
        return;
    }
    if (read(fd, &one, 1) != 1) {
        info->error = EV_ERROR_DATA;
        return;
    }
    info->error = EV_ERROR_NONE;

    if (info->delete != -1)
        virEventRemoveHandleImpl(info->delete);
}


static void
testTimer(int timer, void *data)
{
    struct timerInfo *info = data;

    info->fired = 1;

    if (timer != info->timer) {
        info->error = EV_ERROR_WATCH;
        return;
    }

    info->error = EV_ERROR_NONE;

    if (info->delete != -1)
        virEventRemoveTimeoutImpl(info->delete);
}

static pthread_mutex_t eventThreadMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t eventThreadRunCond = PTHREAD_COND_INITIALIZER;
static int eventThreadRunOnce = 0;
static pthread_cond_t eventThreadJobCond = PTHREAD_COND_INITIALIZER;
static int eventThreadJobDone = 0;


static void *eventThreadLoop(void *data ATTRIBUTE_UNUSED) {
    while (1) {
        pthread_mutex_lock(&eventThreadMutex);
        while (!eventThreadRunOnce) {
            pthread_cond_wait(&eventThreadRunCond, &eventThreadMutex);
        }
        eventThreadRunOnce = 0;
        pthread_mutex_unlock(&eventThreadMutex);

        virEventRunOnce();

        pthread_mutex_lock(&eventThreadMutex);
        eventThreadJobDone = 1;
        pthread_cond_signal(&eventThreadJobCond);
        pthread_mutex_unlock(&eventThreadMutex);
    }
    return NULL;
}


static int
verifyFired(int handle, int timer)
{
    int handleFired = 0;
    int timerFired = 0;
    int i;
    for (i = 0 ; i < NUM_FDS ; i++) {
        if (handles[i].fired) {
            if (i != handle) {
                fprintf(stderr, "FAIL Handle %d fired, but expected %d\n", i, handle);
                return EXIT_FAILURE;
            } else {
                if (handles[i].error != EV_ERROR_NONE) {
                    fprintf(stderr, "FAIL Handle %d fired, but had error %d\n", i,
                            handles[i].error);
                    return EXIT_FAILURE;
                }
                handleFired = 1;
            }
        } else {
            if (i == handle) {
                fprintf(stderr, "FAIL Handle %d should have fired, but didn't\n", handle);
                return EXIT_FAILURE;
            }
        }
    }
    if (handleFired != 1 && handle != -1) {
        fprintf(stderr, "FAIL Something wierd happened, expecting handle %d\n", handle);
        return EXIT_FAILURE;
    }


    for (i = 0 ; i < NUM_TIME ; i++) {
        if (timers[i].fired) {
            if (i != timer) {
                fprintf(stderr, "FAIL Timer %d fired, but expected %d\n", i, timer);
                return EXIT_FAILURE;
            } else {
                if (timers[i].error != EV_ERROR_NONE) {
                    fprintf(stderr, "FAIL Timer %d fired, but had error %d\n", i,
                            timers[i].error);
                    return EXIT_FAILURE;
                }
                timerFired = 1;
            }
        } else {
            if (i == timer) {
                fprintf(stderr, "FAIL Timer %d should have fired, but didn't\n", timer);
                return EXIT_FAILURE;
            }
        }
    }
    if (timerFired != 1 && timer != -1) {
        fprintf(stderr, "FAIL Something wierd happened, expecting timer %d\n", timer);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void
startJob(const char *msg, int *test)
{
    fprintf(stderr, "%2d: %s ", (*test)++, msg);
    eventThreadRunOnce = 1;
    eventThreadJobDone = 0;
    pthread_cond_signal(&eventThreadRunCond);
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    pthread_mutex_lock(&eventThreadMutex);
}

static int
finishJob(int handle, int timer)
{
    struct timespec waitTime;
    int rc;
    clock_gettime(CLOCK_REALTIME, &waitTime);
    waitTime.tv_sec += 5;
    rc = 0;
    while (!eventThreadJobDone && rc == 0)
        rc = pthread_cond_timedwait(&eventThreadJobCond, &eventThreadMutex, &waitTime);
    if (rc != 0) {
        fprintf(stderr, "FAIL Timed out waiting for pipe event\n");
        return EXIT_FAILURE;
    }

    if (verifyFired(handle, timer) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    fprintf(stderr, "OK\n");
    return EXIT_SUCCESS;
}

static void
resetAll(void)
{
    int i;
    for (i = 0 ; i < NUM_FDS ; i++) {
        handles[i].fired = 0;
        handles[i].error = EV_ERROR_NONE;
    }
    for (i = 0 ; i < NUM_TIME ; i++) {
        timers[i].fired = 0;
        timers[i].error = EV_ERROR_NONE;
    }
}

static int
mymain(int argc, char **argv)
{
    int ret = 0;
    char *progname;
    int i;
    pthread_t eventThread;
    char one = '1';
    int test = 1;

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return EXIT_FAILURE;
    }

    for (i = 0 ; i < NUM_FDS ; i++) {
        if (pipe(handles[i].pipeFD) < 0) {
            fprintf(stderr, "Cannot create pipe: %d", errno);
            return EXIT_FAILURE;
        }
    }

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;
    char *debugEnv = getenv("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv && *debugEnv != '0') {
        if (STREQ(debugEnv, "2") || STREQ(debugEnv, "info"))
            virLogSetDefaultPriority(VIR_LOG_INFO);
        else if (STREQ(debugEnv, "3") || STREQ(debugEnv, "warning"))
            virLogSetDefaultPriority(VIR_LOG_WARN);
        else if (STREQ(debugEnv, "4") || STREQ(debugEnv, "error"))
            virLogSetDefaultPriority(VIR_LOG_ERROR);
        else
            virLogSetDefaultPriority(VIR_LOG_DEBUG);
    }

    virEventInit();

    for (i = 0 ; i < NUM_FDS ; i++) {
        handles[i].delete = -1;
        handles[i].watch =
            virEventAddHandleImpl(handles[i].pipeFD[0],
                                  VIR_EVENT_HANDLE_READABLE,
                                  testPipeReader,
                                  &handles[i], NULL);
    }

    for (i = 0 ; i < NUM_TIME ; i++) {
        timers[i].delete = -1;
        timers[i].timeout = -1;
        timers[i].timer =
            virEventAddTimeoutImpl(timers[i].timeout,
                                   testTimer,
                                   &timers[i], NULL);
    }

    pthread_create(&eventThread, NULL, eventThreadLoop, NULL);

    pthread_mutex_lock(&eventThreadMutex);

    /* First time, is easy - just try triggering one of our
     * registered handles */
    startJob("Simple write", &test);
    ret = safewrite(handles[1].pipeFD[1], &one, 1);
    if (finishJob(1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another handle */
    virEventRemoveHandleImpl(handles[0].watch);
    startJob("Deleted before poll", &test);
    ret = safewrite(handles[1].pipeFD[1], &one, 1);
    if (finishJob(1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    /* NB: this case is subject to a bit of a race condition.
     * We yield & sleep, and pray that the other thread gets
     * scheduled before we run EventRemoveHandleImpl */
    startJob("Interrupted during poll", &test);
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    usleep(100 * 1000);
    pthread_mutex_lock(&eventThreadMutex);
    virEventRemoveHandleImpl(handles[1].watch);
    if (finishJob(-1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later handle during dispatch */

    /* NB: this case is subject to a bit of a race condition.
     * Only 1 time in 3 does the 2nd write get triggered by
     * before poll() exits for the first safewrite(). We don't
     * see a hard failure in other cases, so nothing to worry
     * about */
    startJob("Deleted during dispatch", &test);
    handles[2].delete = handles[3].watch;
    ret = safewrite(handles[2].pipeFD[1], &one, 1);
    ret = safewrite(handles[3].pipeFD[1], &one, 1);
    if (finishJob(2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    startJob("Deleted during dispatch", &test);
    handles[2].delete = handles[2].watch;
    ret = safewrite(handles[2].pipeFD[1], &one, 1);
    if (finishJob(2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();



    /* Run a timer on its own */
    virEventUpdateTimeoutImpl(timers[1].timer, 100);
    startJob("Firing a timer", &test);
    if (finishJob(-1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeoutImpl(timers[1].timer, -1);

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another timer */
    virEventUpdateTimeoutImpl(timers[1].timer, 100);
    virEventRemoveTimeoutImpl(timers[0].timer);
    startJob("Deleted before poll", &test);
    if (finishJob(-1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeoutImpl(timers[1].timer, -1);

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    /* NB: this case is subject to a bit of a race condition.
     * We yield & sleep, and pray that the other thread gets
     * scheduled before we run EventRemoveTimeoutImpl */
    startJob("Interrupted during poll", &test);
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    usleep(100 * 1000);
    pthread_mutex_lock(&eventThreadMutex);
    virEventRemoveTimeoutImpl(timers[1].timer);
    if (finishJob(-1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later timer during dispatch */

    /* NB: this case is subject to a bit of a race condition.
     * Only 1 time in 3 does the 2nd write get triggered by
     * before poll() exits for the first safewrite(). We don't
     * see a hard failure in other cases, so nothing to worry
     * about */
    virEventUpdateTimeoutImpl(timers[2].timer, 100);
    virEventUpdateTimeoutImpl(timers[3].timer, 100);
    startJob("Deleted during dispatch", &test);
    timers[2].delete = timers[3].timer;
    if (finishJob(-1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeoutImpl(timers[2].timer, -1);

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    virEventUpdateTimeoutImpl(timers[2].timer, 100);
    startJob("Deleted during dispatch", &test);
    timers[2].delete = timers[2].timer;
    if (finishJob(-1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    for (i = 0 ; i < NUM_FDS ; i++)
        virEventRemoveHandleImpl(handles[i].watch);
    for (i = 0 ; i < NUM_TIME ; i++)
        virEventRemoveTimeoutImpl(timers[i].timer);


    //pthread_kill(eventThread, SIGTERM);

    return EXIT_SUCCESS;
}


VIRT_TEST_MAIN(mymain)
