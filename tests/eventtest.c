/*
 * eventtest.c: Test the libvirtd event loop impl
 *
 * Copyright (C) 2009, 2011-2014 Red Hat, Inc.
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

#include <signal.h>
#include <time.h>

#if WITH_MACH_CLOCK_ROUTINES
# include <mach/clock.h>
# include <mach/mach.h>
#endif

#include "testutils.h"
#include "internal.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"

VIR_LOG_INIT("tests.eventtest");

#define NUM_FDS 31
#define NUM_TIME 31

static pthread_mutex_t eventThreadMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t eventThreadCond = PTHREAD_COND_INITIALIZER;
static bool eventThreadSignaled;

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

struct testEventResultData {
    bool failed;
    const char *msg;
};

static int
testEventResultCallback(const void *opaque)
{
    const struct testEventResultData *data = opaque;

    if (data->failed && data->msg)
        fprintf(stderr, "%s", data->msg);
    return data->failed;
}

static void
G_GNUC_PRINTF(3, 4)
testEventReport(const char *name, bool failed, const char *msg, ...)
{
    va_list vargs;
    g_autofree char *str = NULL;
    struct testEventResultData data;

    va_start(vargs, msg);

    if (msg)
        str = g_strdup_vprintf(msg, vargs);

    data.failed = failed;
    data.msg = str;
    ignore_value(virTestRun(name, testEventResultCallback, &data));

    va_end(vargs);
}

static void
testPipeReader(int watch, int fd, int events, void *data)
{
    struct handleInfo *info = data;
    char one;

    VIR_DEBUG("Handle callback watch=%d fd=%d ev=%d", watch, fd, events);
    pthread_mutex_lock(&eventThreadMutex);

    info->fired = 1;

    if (watch != info->watch) {
        info->error = EV_ERROR_WATCH;
        goto cleanup;
    }

    if (fd != info->pipeFD[0]) {
        info->error = EV_ERROR_FD;
        goto cleanup;
    }

    if (!(events & VIR_EVENT_HANDLE_READABLE)) {
        info->error = EV_ERROR_EVENT;
        goto cleanup;
    }
    if (read(fd, &one, 1) != 1) {
        info->error = EV_ERROR_DATA;
        goto cleanup;
    }
    info->error = EV_ERROR_NONE;

    if (info->delete != -1)
        virEventRemoveHandle(info->delete);

 cleanup:
    pthread_cond_signal(&eventThreadCond);
    eventThreadSignaled = true;
    pthread_mutex_unlock(&eventThreadMutex);
}


static void
testTimer(int timer, void *data)
{
    struct timerInfo *info = data;

    VIR_DEBUG("Timer callback timer=%d", timer);
    pthread_mutex_lock(&eventThreadMutex);

    info->fired = 1;

    if (timer != info->timer) {
        info->error = EV_ERROR_WATCH;
        goto cleanup;
    }

    info->error = EV_ERROR_NONE;

    if (info->delete != -1)
        virEventRemoveTimeout(info->delete);

 cleanup:
    pthread_cond_signal(&eventThreadCond);
    eventThreadSignaled = true;
    pthread_mutex_unlock(&eventThreadMutex);
}

G_GNUC_NORETURN static void *eventThreadLoop(void *data G_GNUC_UNUSED) {
    while (1)
        virEventRunDefaultImpl();
    abort();
}


static void
waitEvents(int nhandle, int ntimer)
{
    int ngothandle = 0;
    int ngottimer = 0;
    size_t i;

    VIR_DEBUG("Wait events nhandle %d ntimer %d",
              nhandle, ntimer);
    while (ngothandle != nhandle || ngottimer != ntimer) {
        while (!eventThreadSignaled)
            pthread_cond_wait(&eventThreadCond, &eventThreadMutex);

        eventThreadSignaled = false;

        ngothandle = ngottimer = 0;
        for (i = 0; i < NUM_FDS; i++) {
            if (handles[i].fired)
                ngothandle++;
        }
        for (i = 0; i < NUM_TIME; i++) {
            if (timers[i].fired)
                ngottimer++;
        }

        VIR_DEBUG("Wait events ngothandle %d ngottimer %d",
                  ngothandle, ngottimer);
    }

}


static int
verifyFired(const char *name, int handle, int timer)
{
    int handleFired = 0;
    int timerFired = 0;
    size_t i;
    VIR_DEBUG("Verify fired handle %d timer %d", handle, timer);
    for (i = 0; i < NUM_FDS; i++) {
        if (handles[i].fired) {
            if (i != handle) {
                testEventReport(name, 1,
                               "Handle %zu fired, but expected %d\n", i,
                               handle);
                return EXIT_FAILURE;
            } else {
                if (handles[i].error != EV_ERROR_NONE) {
                    testEventReport(name, 1,
                                   "Handle %zu fired, but had error %d\n", i,
                                   handles[i].error);
                    return EXIT_FAILURE;
                }
                handleFired = 1;
            }
        } else {
            if (i == handle) {
                testEventReport(name, 1,
                               "Handle %d should have fired, but didn't\n",
                               handle);
                return EXIT_FAILURE;
            }
        }
    }
    if (handleFired != 1 && handle != -1) {
        testEventReport(name, 1,
                       "Something weird happened, expecting handle %d\n",
                       handle);
        return EXIT_FAILURE;
    }


    for (i = 0; i < NUM_TIME; i++) {
        if (timers[i].fired) {
            if (i != timer) {
                testEventReport(name, 1,
                               "Timer %zu fired, but expected %d\n", i, timer);
                return EXIT_FAILURE;
            } else {
                if (timers[i].error != EV_ERROR_NONE) {
                    testEventReport(name, 1,
                                   "Timer %zu fired, but had error %d\n", i,
                                   timers[i].error);
                    return EXIT_FAILURE;
                }
                timerFired = 1;
            }
        } else {
            if (i == timer) {
                testEventReport(name, 1,
                               "Timer %d should have fired, but didn't\n",
                               timer);
                return EXIT_FAILURE;
            }
        }
    }
    if (timerFired != 1 && timer != -1) {
        testEventReport(name, 1,
                       "Something weird happened, expecting timer %d\n",
                       timer);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


static int
finishJob(const char *name, int handle, int timer)
{
    pthread_mutex_lock(&eventThreadMutex);

    waitEvents(handle == -1 ? 0 : 1,
               timer == -1 ? 0 : 1);

    if (verifyFired(name, handle, timer) != EXIT_SUCCESS) {
        pthread_mutex_unlock(&eventThreadMutex);
        return EXIT_FAILURE;
    }

    testEventReport(name, 0, NULL);

    pthread_mutex_unlock(&eventThreadMutex);
    return EXIT_SUCCESS;
}

static void
resetAll(void)
{
    size_t i;
    pthread_mutex_lock(&eventThreadMutex);
    for (i = 0; i < NUM_FDS; i++) {
        handles[i].fired = 0;
        handles[i].error = EV_ERROR_NONE;
    }
    for (i = 0; i < NUM_TIME; i++) {
        timers[i].fired = 0;
        timers[i].error = EV_ERROR_NONE;
    }
    pthread_mutex_unlock(&eventThreadMutex);
}

static int
mymain(void)
{
    size_t i;
    pthread_t eventThread;
    char one = '1';
    char *debugEnv = getenv("LIBVIRT_DEBUG");

    for (i = 0; i < NUM_FDS; i++) {
        if (virPipeQuiet(handles[i].pipeFD) < 0) {
            fprintf(stderr, "Cannot create pipe: %d", errno);
            return EXIT_FAILURE;
        }
    }

    if (debugEnv && *debugEnv &&
        (virLogSetDefaultPriority(virLogParseDefaultPriority(debugEnv)) < 0)) {
        fprintf(stderr, "Invalid log level setting.\n");
        return EXIT_FAILURE;
    }

    virEventRegisterDefaultImpl();

    for (i = 0; i < NUM_FDS; i++) {
        handles[i].delete = -1;
        handles[i].watch =
            virEventAddHandle(handles[i].pipeFD[0],
                              VIR_EVENT_HANDLE_READABLE,
                              testPipeReader,
                              &handles[i], NULL);
    }

    for (i = 0; i < NUM_TIME; i++) {
        timers[i].delete = -1;
        timers[i].timeout = -1;
        timers[i].timer =
            virEventAddTimeout(timers[i].timeout,
                               testTimer,
                               &timers[i], NULL);
    }

    pthread_create(&eventThread, NULL, eventThreadLoop, NULL);

    /* First time, is easy - just try triggering one of our
     * registered handles */
    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Simple write", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another handle */
    virEventRemoveHandle(handles[0].watch);
    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted before poll", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    virEventRemoveHandle(handles[1].watch);
    if (finishJob("Interrupted during poll", -1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later handle during dispatch */

    handles[2].delete = handles[3].watch;
    if (safewrite(handles[2].pipeFD[1], &one, 1) != 1
        || safewrite(handles[3].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted during dispatch", 2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    handles[2].delete = handles[2].watch;
    if (safewrite(handles[2].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Deleted during dispatch", 2, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();



    /* Run a timer on its own */
    virEventUpdateTimeout(timers[1].timer, 100);
    if (finishJob("Firing a timer", -1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeout(timers[1].timer, -1);

    resetAll();

    /* Now lets delete one before starting poll(), and
     * try triggering another timer */
    virEventUpdateTimeout(timers[1].timer, 100);
    virEventRemoveTimeout(timers[0].timer);
    if (finishJob("Deleted before poll", -1, 1) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeout(timers[1].timer, -1);

    resetAll();

    /* Next lets delete *during* poll, which should interrupt
     * the loop with no event showing */

    virEventRemoveTimeout(timers[1].timer);
    if (finishJob("Interrupted during poll", -1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    resetAll();

    /* Getting more fun, lets delete a later timer during dispatch */

    virEventUpdateTimeout(timers[2].timer, 100);
    virEventUpdateTimeout(timers[3].timer, 100);
    timers[2].delete = timers[3].timer;
    if (finishJob("Deleted during dispatch", -1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    virEventUpdateTimeout(timers[2].timer, -1);

    resetAll();

    /* Extreme fun, lets delete ourselves during dispatch */
    virEventUpdateTimeout(timers[2].timer, 100);
    timers[2].delete = timers[2].timer;
    if (finishJob("Deleted during dispatch", -1, 2) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    for (i = 0; i < NUM_FDS - 1; i++)
        virEventRemoveHandle(handles[i].watch);
    for (i = 0; i < NUM_TIME - 1; i++)
        virEventRemoveTimeout(timers[i].timer);

    resetAll();

    /* Make sure the last handle still works several times in a row.  */
    for (i = 0; i < 4; i++) {
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

    handles[0].watch = virEventAddHandle(handles[0].pipeFD[0],
                                         0,
                                         testPipeReader,
                                         &handles[0], NULL);
    handles[1].watch = virEventAddHandle(handles[1].pipeFD[0],
                                         VIR_EVENT_HANDLE_READABLE,
                                         testPipeReader,
                                         &handles[1], NULL);

    if (safewrite(handles[1].pipeFD[1], &one, 1) != 1)
        return EXIT_FAILURE;
    if (finishJob("Write duplicate", 1, -1) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /* pthread_kill(eventThread, SIGTERM); */

    return EXIT_SUCCESS;
}

VIR_TEST_MAIN(mymain)
