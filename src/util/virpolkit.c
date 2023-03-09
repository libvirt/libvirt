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
#include <fcntl.h>
#include <unistd.h>

#include "virpolkit.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virgdbus.h"
#include "virfile.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_POLKIT

VIR_LOG_INIT("util.polkit");

#if WITH_POLKIT
# include <poll.h>

struct _virPolkitAgent {
    virCommand *cmd;
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
    GDBusConnection *sysbus;
    GVariantBuilder builder;
    GVariant *gprocess = NULL;
    GVariant *gdetails = NULL;
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariantIter) iter = NULL;
    char *retkey;
    char *retval;
    gboolean is_authorized;
    gboolean is_challenge;
    bool is_dismissed = false;
    const char **next;

    if (!(sysbus = virGDBusGetSystemBus()))
        return -1;

    VIR_INFO("Checking PID %lld running as %d",
             (long long) pid, uid);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "pid", g_variant_new_uint32(pid));
    g_variant_builder_add(&builder, "{sv}", "start-time", g_variant_new_uint64(startTime));
    g_variant_builder_add(&builder, "{sv}", "uid", g_variant_new_int32(uid));
    gprocess = g_variant_builder_end(&builder);

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{ss}"));

    if (details) {
        for (next = details; *next; next++) {
            const char *detail1 = *(next++);
            const char *detail2 = *next;
            g_variant_builder_add(&builder, "{ss}", detail1, detail2);
        }
    }

    gdetails = g_variant_builder_end(&builder);

    message = g_variant_new("((s@a{sv})s@a{ss}us)",
                            "unix-process",
                            gprocess,
                            actionid,
                            gdetails,
                            allowInteraction,
                            "" /* cancellation ID */);

    if (virGDBusCallMethod(sysbus,
                           &reply,
                           G_VARIANT_TYPE("((bba{ss}))"),
                           NULL,
                           "org.freedesktop.PolicyKit1",
                           "/org/freedesktop/PolicyKit1/Authority",
                           "org.freedesktop.PolicyKit1.Authority",
                           "CheckAuthorization",
                           message) < 0)
        return -1;

    g_variant_get(reply, "((bba{ss}))", &is_authorized, &is_challenge, &iter);

    while (g_variant_iter_loop(iter, "{ss}", &retkey, &retval)) {
        if (STREQ(retkey, "polkit.dismissed") && STREQ(retval, "true"))
            is_dismissed = true;
    }

    VIR_DEBUG("is auth %d  is challenge %d",
              is_authorized, is_challenge);

    if (is_authorized)
        return 0;

    if (is_dismissed) {
        virReportError(VIR_ERR_AUTH_CANCELLED, "%s",
                       _("user cancelled authentication process"));
    } else if (is_challenge) {
        virReportError(VIR_ERR_AUTH_UNAVAILABLE,
                       _("no polkit agent available to authenticate action '%1$s'"),
                       actionid);
    } else {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("access denied by policy"));
    }

    return -2;
}


/* virPolkitAgentDestroy:
 * @cmd: Pointer to the virCommand * created during virPolkitAgentCreate
 *
 * Destroy resources used by Polkit Agent
 */
void
virPolkitAgentDestroy(virPolkitAgent *agent)
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
 * Returns newly allocated virPolkitAgent * on success and NULL on failure
 */
virPolkitAgent *
virPolkitAgentCreate(void)
{
    virPolkitAgent *agent = NULL;
    int pipe_fd[2] = {-1, -1};
    struct pollfd pollfd;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    if (!virPolkitAgentAvailable()) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("polkit text authentication agent unavailable"));
        goto error;
    }

    if (virPipe(pipe_fd) < 0)
        goto error;

    agent = g_new0(virPolkitAgent, 1);

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

    if (poll(&pollfd, 1, -1) < 0) {
        virReportSystemError(errno, "%s",
                             _("error in poll call"));
        goto error;
    }

    return agent;

 error:
    VIR_FORCE_CLOSE(pipe_fd[0]);
    VIR_FORCE_CLOSE(pipe_fd[1]);
    virPolkitAgentDestroy(agent);
    return NULL;
}


/*
 * virPolkitAgentAvailable
 *
 * This function does some preliminary checking that the pkttyagent does not
 * fail starting so that it can be started without waiting for first failed
 * connection with VIR_ERR_AUTH_UNAVAILABLE.
 */
bool
virPolkitAgentAvailable(void)
{
    const char *termid = ctermid(NULL);
    VIR_AUTOCLOSE fd = -1;

    if (!virFileIsExecutable(PKTTYAGENT))
        return false;

    if (!termid)
        return false;

    /*
     *The pkttyagent needs to open the controlling terminal.
     *
     * Just in case we are running without a ctty make sure this open() does not
     * change that.
     *
     * We could check if our session has a controlling terminal available
     * instead, but it would require parsing `/proc/self/stat` on Linux, which
     * is not portable and moreover requires way more work than just open().
     */
    fd = open(termid, O_RDWR | O_NOCTTY);
    if (fd < 0)
        return false;

    return true;
}

#else /* ! WITH_POLKIT */

int virPolkitCheckAuth(const char *actionid G_GNUC_UNUSED,
                       pid_t pid G_GNUC_UNUSED,
                       unsigned long long startTime G_GNUC_UNUSED,
                       uid_t uid G_GNUC_UNUSED,
                       const char **details G_GNUC_UNUSED,
                       bool allowInteraction G_GNUC_UNUSED)
{
    VIR_ERROR(_("Polkit auth attempted, even though polkit is not available"));
    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("authentication failed"));
    return -1;
}


void
virPolkitAgentDestroy(virPolkitAgent *agent G_GNUC_UNUSED)
{
    return; /* do nothing */
}


virPolkitAgent *
virPolkitAgentCreate(void)
{
    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("polkit text authentication agent unavailable"));
    return NULL;
}

bool
virPolkitAgentAvailable(void)
{
    return false;
}

#endif /* WITH_POLKIT */
