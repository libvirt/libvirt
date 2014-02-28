/*
 * eventtest.c: Test the libvirtd event loop impl
 *
 * Copyright (C) 2009, 2011-2013 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>
#include <time.h>

#include "testutils.h"
#include "internal.h"
#include "virfile.h"
#include "virthread.h"
#include "virlog.h"
#include "virutil.h"
#include "vireventpoll.h"

VIR_LOG_INIT("tests.eventtest");

#define NUM_FDS 31
#define NUM_TIME 31

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
        virEventPollRemoveHandle(info->delete);
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
        virEventPollRemoveTimeout(info->delete);
}

static pthread_mutex_t eventThreadMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t eventThreadRunCond = PTHREAD_COND_INITIALIZER;
static int eventThreadRunOnce = 0;
static pthread_cond_t eventThreadJobCond = PTHREAD_COND_INITIALIZER;
static int eventThreadJobDone = 0;


ATTRIBUTE_NORETURN static void *eventThreadLoop(void *data ATTRIBUTE_UNUSED) {
    while (1) {
        pthread_mutex_lock(&eventThreadMutex);
        while (!eventThreadRunOnce) {
            pthread_cond_wait(&eventThreadRunCond, &eventThreadMutex);
        }
        eventThreadRunOnce = 0;
        pthread_mutex_unlock(&eventThreadMutex);

        virEventPollRunOnce();

        pthread_mutex_lock(&eventThreadMutex);
        eventThreadJobDone = 1;
        pthread_cond_signal(&eventThreadJobCond);
        pthread_mutex_unlock(&eventThreadMutex);
    }
}


static int
verifyFired(const char *name, int handle, int timer)
{
    int handleFired = 0;
    int timerFired = 0;
    size_t i;
    for (i = 0; i < NUM_FDS; i++) {
        if (handles[i].fired) {
            if (i != handle) {
                virtTestResult(name, 1,
                               "Handle %zu fired, but expected %d\n", i,
                               handle);
                return EXIT_FAILURE;
            } else {
                if (handles[i].error != EV_ERROR_NONE) {
                    virtTestResult(name, 1,
                                   "Handle %zu fired, but had error %d\n", i,
                                   handles[i].error);
                    return EXIT_FAILURE;
                }
                handleFired = 1;
            }
        } else {
            if (i == handle) {
                virtTestResult(name, 1,
                               "Handle %d should have fired, but didn't\n",
                               handle);
                return EXIT_FAILURE;
            }
        }
    }
    if (handleFired != 1 && handle != -1) {
        virtTestResult(name, 1,
                       "Something weird happened, expecting handle %d\n",
                       handle);
        return EXIT_FAILURE;
    }


    for (i = 0; i < NUM_TIME; i++) {
        if (timers[i].fired) {
            if (i != timer) {
                virtTestResult(name, 1,
                               "Timer %zu fired, but expected %d\n", i, timer);
                return EXIT_FAILURE;
            } else {
                if (timers[i].error != EV_ERROR_NONE) {
                    virtTestResult(name, 1,
                                   "Timer %zu fired, but had error %d\n", i,
                                   timers[i].error);
                    return EXIT_FAILURE;
                }
                timerFired = 1;
            }
        } else {
            if (i == timer) {
                virtTestResult(name, 1,
                               "Timer %d should have fired, but didn't\n",
                               timer);
                return EXIT_FAILURE;
            }
        }
    }
    if (timerFired != 1 && timer != -1) {
        virtTestResult(name, 1,
                       "Something weird happened, expecting timer %d\n",
                       timer);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static void
startJob(void)
{
    eventThreadRunOnce = 1;
    eventThreadJobDone = 0;
    pthread_cond_signal(&eventThreadRunCond);
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    pthread_mutex_lock(&eventThreadMutex);
}

static int
finishJob(const char *name, int handle, int timer)
{
    struct timespec waitTime;
    int rc;
    clock_gettime(CLOCK_REALTIME, &waitTime);
    waitTime.tv_sec += 5;
    rc = 0;
    while (!eventThreadJobDone && rc == 0)
        rc = pthread_cond_timedwait(&eventThreadJobCond, &eventThreadMutex,
                                    &waitTime);
    if (rc != 0) {
        virtTestResult(name, 1, "Timed out waiting for pipe event\n");
        return EXIT_FAILURE;
    }

    if (verifyFired(name, handle, timer) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    virtTestResult(name, 0, NULL);
    return EXIT_SUCCESS;
}

static void
resetAll(void)
{
    size_t i;
    for (i = 0; i < NUM_FDS; i++) {
        handles[i].fired = 0;
        handles[i].error = EV_ERROR_NONE;
    }
    for (i = 0; i < NUM_TIME; i++) {
        timers[i].fired = 0;
        timers[i].error = EV_ERROR_NONE;
    }
}

static int
mymain(void)
{
    size_t i;
    pthread_t eventThread;
    char one = '1';

    for (i = 0; i < NUM_FDS; i++) {
        if (pipe(handles[i].pipeFD) < 0) {
            fprintf(stderr, "Cannot create pipe: %d", errno);
            return EXIT_FAILURE;
        }
    }

    if (virThreadInitialize() < 0)
        return EXIT_FAILURE;
    char *debugEnv = getenv("LIBVIRT_DEBUG");
    if (debugEnv && *debugEnv && (virLogParseDefaultPriority(debugEnv) == -1)) {
        fprintf(stderr, "Invalid log level setting.\n");
        return EXIT_FAILURE;
    }

    virEventPollInit();

    for (i = 0; i < NUM_FDS; i++) {
        handles[i].delete = -1;
        handles[i].watch =
            virEventPollAddHandle(handles[i].pipeFD[0],
                                  VIR_EVENT_HANDLE_READABLE,
                                  testPipeReader,
                                  &handles[i], NULL);
    }

    for (i = 0; i < NUM_TIME; i++) {
        timers[i].delete = -1;
        timers[i].timeout = -1;
        timers[i].timer =
            virEventPollAddTimeout(timers[i].timeout,
                                   testTimer,
                                   &timers[i], NULL);
    }

    pthread_create(&eventThread, NULL, eventThreadLoop, NULL);

    pthread_mutex_lock(&eventThreadMutex);

    /* First time, is easy - just try triggering one of our
     * registered handles */
    startJob();
    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Simple write", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another handle */
    virEventPollRemoveHandle(handles[0].watch);
    startJob();
    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted before poll", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    /* NB: this case is subject to a bit of a race condition.
     * We yield & sleep, and pray that the other thread gets
     * scheduled before we run EventRemoveHandle */
    startJob();
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    usleep(100 * 1000);
    pthread_mutex_lock(&eventThreadMutex);
    virEventPollRemoveHandle(handles[1].watch);
    if (finishJob("Interrupted during poll", -1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later handle during dispatch */

    /* NB: this case is subject to a bit of a race condition.
     * Only 1 time in 3 does the 2nd write get triggered by
     * before poll() exits for the first safewrite(). We don't
     * see a hard failure in other cases, so nothing to worry
     * about */
    startJob();
    handles[2].delete = handles[3].watch;
    if (safewrite(handles[2].pipeFD[1], &one, 1) != 1
        || safewrite(handles[3].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted during dispatch", 2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    startJob();
    handles[2].delete = handles[2].watch;
    if (safewrite(handles[2].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted during dispatch", 2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();



    /* Run a timer on its own */
    virEventPollUpdateTimeout(timers[1].timer, 100);
    startJob();
    if (finishJob("Firing a timer", -1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventPollUpdateTimeout(timers[1].timer, -1);

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another timer */
    virEventPollUpdateTimeout(timers[1].timer, 100);
    virEventPollRemoveTimeout(timers[0].timer);
    startJob();
    if (finishJob("Deleted before poll", -1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventPollUpdateTimeout(timers[1].timer, -1);

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    /* NB: this case is subject to a bit of a race condition.
     * We yield & sleep, and pray that the other thread gets
     * scheduled before we run EventRemoveTimeout */
    startJob();
    pthread_mutex_unlock(&eventThreadMutex);
    sched_yield();
    usleep(100 * 1000);
    pthread_mutex_lock(&eventThreadMutex);
    virEventPollRemoveTimeout(timers[1].timer);
    if (finishJob("Interrupted during poll", -1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later timer during dispatch */

    /* NB: this case is subject to a bit of a race condition.
     * Only 1 time in 3 does the 2nd write get triggered by
     * before poll() exits for the first safewrite(). We don't
     * see a hard failure in other cases, so nothing to worry
     * about */
    virEventPollUpdateTimeout(timers[2].timer, 100);
    virEventPollUpdateTimeout(timers[3].timer, 100);
    startJob();
    timers[2].delete = timers[3].timer;
    if (finishJob("Deleted during dispatch", -1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventPollUpdateTimeout(timers[2].timer, -1);

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    virEventPollUpdateTimeout(timers[2].timer, 100);
    startJob();
    timers[2].delete = timers[2].timer;
    if (finishJob("Deleted during dispatch", -1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    for (i = 0; i < NUM_FDS - 1; i++)
        virEventPollRemoveHandle(handles[i].watch);
    for (i = 0; i < NUM_TIME - 1; i++)
        virEventPollRemoveTimeout(timers[i].timer);

    resetAll();

    /* Make sure the last handle still works several times in a row.  */
    for (i = 0; i < 4; i++) {
        startJob();
        if (safewrite(handles[NUM_FDS - 1].pipeFD[1], &one, 1) != 1)
            return EXIT_FAILURE;
        if (finishJob("Simple write", NUM_FDS - 1, -1) != EXIT_SUCCESS)
            return EXIT_FAILURE;

        resetAll();
    }


    /* Final test, register same FD twice, once with no
     * events, and make sure the right callback runs */
    handles[0].pipeFD[0] = handles[1].pipeFD[0];
    handles[0].pipeFD[1] = handles[1].pipeFD[1];

    handles[0].watch = virEventPollAddHandle(handles[0].pipeFD[0],
                                             0,
                                             testPipeReader,
                                             &handles[0], NULL);
    handles[1].watch = virEventPollAddHandle(handles[1].pipeFD[0],
                                             VIR_EVENT_HANDLE_READABLE,
                                             testPipeReader,
                                             &handles[1], NULL);
    startJob();
    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Write duplicate", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    //pthread_kill(eventThread, SIGTERM);

    return EXIT_SUCCESS;
}

VIRT_TEST_MAIN(mymain)
