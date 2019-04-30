/*
 * virpolkit.c: helpers for using polkit APIs
 *
 * Copyright (C) 2013, 2014, 2016 Red Hat, Inc.
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
 */

#include <config.h>
#include <poll.h>

#include "virpolkit.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virprocess.h"
#include "viralloc.h"
#include "virdbus.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_POLKIT

VIR_LOG_INIT("util.polkit");

#if WITH_POLKIT

struct _virPolkitAgent {
    virCommandPtr cmd;
};

/*
 * virPolkitCheckAuth:
 * @actionid: permission to check
 * @pid: client process ID
 * @startTime: process start time, or 0
 * @uid: client process user ID
 * @details: NULL terminated (key, value) pair list
 * @allowInteraction: true if auth prompts are allowed
 *
 * Check if a client is authenticated with polkit
 *
 * Returns 0 on success, -1 on failure, -2 on auth denied
 */
int virPolkitCheckAuth(const char *actionid,
                       pid_t pid,
                       unsigned long long startTime,
                       uid_t uid,
                       const char **details,
                       bool allowInteraction)
{
    DBusConnection *sysbus;
    DBusMessage *reply = NULL;
    char **retdetails = NULL;
    size_t nretdetails = 0;
    bool is_authorized;
    bool is_challenge;
    bool is_dismissed = false;
    size_t i;
    int ret = -1;

    if (!(sysbus = virDBusGetSystemBus()))
        goto cleanup;

    VIR_INFO("Checking PID %lld running as %d",
             (long long) pid, uid);

    if (virDBusCallMethod(sysbus,
                          &reply,
                          NULL,
                          "org.freedesktop.PolicyKit1",
                          "/org/freedesktop/PolicyKit1/Authority",
                          "org.freedesktop.PolicyKit1.Authority",
                          "CheckAuthorization",
                          "(sa{sv})sa&{ss}us",
                          "unix-process",
                          3,
                          "pid", "u", (unsigned int)pid,
                          "start-time", "t", startTime,
                          "uid", "i", (int)uid,
                          actionid,
                          virStringListLength(details) / 2,
                          details,
                          allowInteraction,
                          "" /* cancellation ID */) < 0)
        goto cleanup;

    if (virDBusMessageDecode(reply,
                             "(bba&{ss})",
                             &is_authorized,
                             &is_challenge,
                             &nretdetails,
                             &retdetails) < 0)
        goto cleanup;

    for (i = 0; i < (nretdetails / 2); i++) {
        if (STREQ(retdetails[(i * 2)], "polkit.dismissed") &&
            STREQ(retdetails[(i * 2) + 1], "true"))
            is_dismissed = true;
    }

    VIR_DEBUG("is auth %d  is challenge %d",
              is_authorized, is_challenge);

    if (is_authorized) {
        ret = 0;
    } else {
        ret = -2;
        if (is_dismissed)
            virReportError(VIR_ERR_AUTH_CANCELLED, "%s",
                           _("user cancelled authentication process"));
        else if (is_challenge)
            virReportError(VIR_ERR_AUTH_UNAVAILABLE,
                           _("no polkit agent available to authenticate "
                             "action '%s'"),
                           actionid);
        else
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("access denied by policy"));
    }

 cleanup:
    virStringListFreeCount(retdetails, nretdetails);
    virDBusMessageUnref(reply);
    return ret;
}


/* virPolkitAgentDestroy:
 * @cmd: Pointer to the virCommandPtr created during virPolkitAgentCreate
 *
 * Destroy resources used by Polkit Agent
 */
void
virPolkitAgentDestroy(virPolkitAgentPtr agent)
{
    if (!agent)
        return;

    virCommandFree(agent->cmd);
    VIR_FREE(agent);
}

/* virPolkitAgentCreate:
 *
 * Allocate and setup a polkit agent
 *
 * Returns a virCommandPtr on success and NULL on failure
 */
virPolkitAgentPtr
virPolkitAgentCreate(void)
{
    virPolkitAgentPtr agent = NULL;
    int pipe_fd[2] = {-1, -1};
    struct pollfd pollfd;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    if (!isatty(STDIN_FILENO))
        goto error;

    if (pipe2(pipe_fd, 0) < 0)
        goto error;

    if (VIR_ALLOC(agent) < 0)
        goto error;

    agent->cmd = virCommandNewArgList(PKTTYAGENT, "--process", NULL);

    virCommandAddArgFormat(agent->cmd, "%lld", (long long int) getpid());
    virCommandAddArg(agent->cmd, "--notify-fd");
    virCommandAddArgFormat(agent->cmd, "%d", pipe_fd[1]);
    virCommandAddArg(agent->cmd, "--fallback");
    virCommandSetInputFD(agent->cmd, STDIN_FILENO);
    virCommandSetOutputFD(agent->cmd, &outfd);
    virCommandSetErrorFD(agent->cmd, &errfd);
    virCommandPassFD(agent->cmd, pipe_fd[1], VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    pipe_fd[1] = -1;
    if (virCommandRunAsync(agent->cmd, NULL) < 0)
        goto error;

    pollfd.fd = pipe_fd[0];
    pollfd.events = POLLHUP;

    if (poll(&pollfd, 1, -1) < 0)
        goto error;

    return agent;

 error:
    VIR_FORCE_CLOSE(pipe_fd[0]);
    VIR_FORCE_CLOSE(pipe_fd[1]);
    virPolkitAgentDestroy(agent);
    return NULL;
}


#else /* ! WITH_POLKIT */

int virPolkitCheckAuth(const char *actionid ATTRIBUTE_UNUSED,
                       pid_t pid ATTRIBUTE_UNUSED,
                       unsigned long long startTime ATTRIBUTE_UNUSED,
                       uid_t uid ATTRIBUTE_UNUSED,
                       const char **details ATTRIBUTE_UNUSED,
                       bool allowInteraction ATTRIBUTE_UNUSED)
{
    VIR_ERROR(_("Polkit auth attempted, even though polkit is not available"));
    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("authentication failed"));
    return -1;
}


void
virPolkitAgentDestroy(virPolkitAgentPtr agent ATTRIBUTE_UNUSED)
{
    return; /* do nothing */
}


virPolkitAgentPtr
virPolkitAgentCreate(void)
{
    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("polkit text authentication agent unavailable"));
    return NULL;
}
#endif /* WITH_POLKIT */
