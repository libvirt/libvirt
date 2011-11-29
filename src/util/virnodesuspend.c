/*
 * virnodesuspend.c: Support for suspending a node (host machine)
 *
 * Copyright (C) 2011 Srivatsa S. Bhat <srivatsa.bhat@linux.vnet.ibm.com>
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

#include <config.h>
#include "virnodesuspend.h"

#include "command.h"
#include "threads.h"
#include "datatypes.h"

#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virNodeSuspendError(code, ...)                                     \
        virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                \
                             __FUNCTION__, __LINE__, __VA_ARGS__)


#define SUSPEND_DELAY 10 /* in seconds */

/* Give sufficient time for performing the suspend operation on the host */
#define MIN_TIME_REQ_FOR_SUSPEND 60 /* in seconds */

/*
 * Bitmask to hold the Power Management features supported by the host,
 * such as Suspend-to-RAM, Suspend-to-Disk, Hybrid-Suspend etc.
 */
static unsigned int hostPMFeatures;

virMutex virNodeSuspendMutex;

static bool aboutToSuspend;

static void virNodeSuspendLock(void)
{
    virMutexLock(&virNodeSuspendMutex);
}

static void virNodeSuspendUnlock(void)
{
    virMutexUnlock(&virNodeSuspendMutex);
}


/**
 * virNodeSuspendInit:
 *
 * Get the system-wide sleep states supported by the host, such as
 * Suspend-to-RAM, Suspend-to-Disk, or Hybrid-Suspend, so that a request
 * to suspend/hibernate the host can be handled appropriately based on
 * this information.
 *
 * Returns 0 if successful, and -1 in case of error.
 */
int virNodeSuspendInit(void)
{

    if (virMutexInit(&virNodeSuspendMutex) < 0)
        return -1;

    /* Get the power management capabilities supported by the host */
    hostPMFeatures = 0;
    if (virGetPMCapabilities(&hostPMFeatures) < 0) {
        if (geteuid() == 0)
            VIR_ERROR(_("Failed to get host power management features"));
    }

    return 0;
}


/**
 * virNodeSuspendSetNodeWakeup:
 * @alarmTime: time in seconds from now, at which the RTC alarm has to be set.
 *
 * Set up the RTC alarm to the specified time.
 * Return 0 on success, -1 on failure.
 */
static int virNodeSuspendSetNodeWakeup(unsigned long long alarmTime)
{
    virCommandPtr setAlarmCmd;
    int ret = -1;

    if (alarmTime <= MIN_TIME_REQ_FOR_SUSPEND) {
        virNodeSuspendError(VIR_ERR_INVALID_ARG, "%s", _("Suspend duration is too short"));
        return -1;
    }

    setAlarmCmd = virCommandNewArgList("rtcwake", "-m", "no", "-s", NULL);
    virCommandAddArgFormat(setAlarmCmd, "%lld", alarmTime);

    if (virCommandRun(setAlarmCmd, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virCommandFree(setAlarmCmd);
    return ret;
}

/**
 * virNodeSuspend:
 * @cmdString: pointer to the command string this thread has to execute.
 *
 * Actually perform the suspend operation by invoking the command.
 * Give a short delay before executing the command so as to give a chance
 * to virNodeSuspendForDuration() to return the status to the caller.
 * If we don't give this delay, that function will not be able to return
 * the status, since the suspend operation would have begun and hence no
 * data can be sent through the connection to the caller. However, with
 * this delay added, the status return is best-effort only.
 */
static void virNodeSuspend(void *cmdString)
{
    virCommandPtr suspendCmd = virCommandNew((char *)cmdString);

    VIR_FREE(cmdString);

    /*
     * Delay for sometime so that the function nodeSuspendForDuration()
     * can return the status to the caller.
     */
    sleep(SUSPEND_DELAY);
    if (virCommandRun(suspendCmd, NULL) < 0)
        VIR_WARN("Failed to suspend the host");

    virCommandFree(suspendCmd);

    /*
     * Now that we have resumed from suspend or the suspend failed,
     * reset 'aboutToSuspend' flag.
     */
    virNodeSuspendLock();
    aboutToSuspend = false;
    virNodeSuspendUnlock();
}

/**
 * nodeSuspendForDuration:
 * @conn: pointer to the hypervisor connection
 * @target: the state to which the host must be suspended to -
 *         VIR_NODE_SUSPEND_TARGET_MEM       (Suspend-to-RAM),
 *         VIR_NODE_SUSPEND_TARGET_DISK      (Suspend-to-Disk),
 *         VIR_NODE_SUSPEND_TARGET_HYBRID    (Hybrid-Suspend)
 * @duration: the time duration in seconds, for which the host must be
 *            suspended
 * @flags: any flag values that might need to be passed; currently unused.
 *
 * Suspend the node (host machine) for the given duration of time in the
 * specified state (such as Mem, Disk or Hybrid-Suspend). Attempt to resume
 * the node after the time duration is complete.
 *
 * First, an RTC alarm is set appropriately to wake up the node from its
 * sleep state. Then the actual node suspend operation is carried out
 * asynchronously in another thread, after a short time delay so as to
 * give enough time for this function to return status to its caller
 * through the connection. However this returning of status is best-effort
 * only, and should generally happen due to the short delay but might be
 * missed if the machine suspends first.
 *
 * Returns 0 in case the node is going to be suspended after a short delay,
 * -1 if suspending the node is not supported, or if a previous suspend
 * operation is still in progress.
 */
int nodeSuspendForDuration(virConnectPtr conn ATTRIBUTE_UNUSED,
                           unsigned int target,
                           unsigned long long duration,
                           unsigned int flags)
{
    static virThread thread;
    char *cmdString = NULL;

    virCheckFlags(0, -1);

    /*
     * Ensure that we are the only ones trying to suspend.
     * Fail if somebody has already initiated a suspend.
     */
    virNodeSuspendLock();

    if (aboutToSuspend) {
        /* A suspend operation is already in progress */
        virNodeSuspendUnlock();
        return -1;
    } else {
        aboutToSuspend = true;
    }

    virNodeSuspendUnlock();

    /* Check if the host supports the requested suspend target */
    switch (target) {
    case VIR_NODE_SUSPEND_TARGET_MEM:
        if (hostPMFeatures & (1 << VIR_NODE_SUSPEND_TARGET_MEM)) {
            cmdString = strdup("pm-suspend");
            if (cmdString == NULL) {
                virReportOOMError();
                goto cleanup;
            }
            break;
        }
        virNodeSuspendError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s", _("Suspend-to-RAM"));
        goto cleanup;

    case VIR_NODE_SUSPEND_TARGET_DISK:
        if (hostPMFeatures & (1 << VIR_NODE_SUSPEND_TARGET_DISK)) {
            cmdString = strdup("pm-hibernate");
            if (cmdString == NULL) {
                virReportOOMError();
                goto cleanup;
            }
            break;
        }
        virNodeSuspendError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s", _("Suspend-to-Disk"));
        goto cleanup;

    case VIR_NODE_SUSPEND_TARGET_HYBRID:
        if (hostPMFeatures & (1 << VIR_NODE_SUSPEND_TARGET_HYBRID)) {
            cmdString = strdup("pm-suspend-hybrid");
            if (cmdString == NULL) {
                virReportOOMError();
                goto cleanup;
            }
            break;
        }
        virNodeSuspendError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s", _("Hybrid-Suspend"));
        goto cleanup;

    default:
        virNodeSuspendError(VIR_ERR_INVALID_ARG, "%s", _("Invalid suspend target"));
        goto cleanup;
    }

    /* Just set the RTC alarm. Don't suspend yet. */
    if (virNodeSuspendSetNodeWakeup(duration) < 0)
        goto cleanup;

    if (virThreadCreate(&thread, false, virNodeSuspend, (void *)cmdString) < 0) {
        virNodeSuspendError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Failed to create thread to suspend the host\n"));
        goto cleanup;
    }

    return 0;

cleanup:
    VIR_FREE(cmdString);
    return -1;
}
