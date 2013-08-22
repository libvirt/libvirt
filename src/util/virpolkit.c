/*
 * virpolkit.c: helpers for using polkit APIs
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#if WITH_POLKIT0
# include <polkit/polkit.h>
# include <polkit-dbus/polkit-dbus.h>
#endif

#include "virpolkit.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "virprocess.h"
#include "viralloc.h"
#include "virdbus.h"

#define VIR_FROM_THIS VIR_FROM_POLKIT

VIR_LOG_INIT("util.polkit");

#if WITH_POLKIT1
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
    int status = -1;
    bool authdismissed = 0;
    bool supportsuid = 0;
    char *pkout = NULL;
    virCommandPtr cmd = NULL;
    int ret = -1;
    static bool polkitInsecureWarned = false;

    VIR_DEBUG("Checking PID %lld UID %d startTime %llu",
              (long long)pid, (int)uid, startTime);

    if (startTime == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Start time is required for polkit auth"));
        return -1;
    }

    cmd = virCommandNewArgList(PKCHECK_PATH, "--action-id", actionid, NULL);
    virCommandSetOutputBuffer(cmd, &pkout);
    virCommandSetErrorBuffer(cmd, &pkout);

    virCommandAddArg(cmd, "--process");
# ifdef PKCHECK_SUPPORTS_UID
    supportsuid = 1;
# endif
    if (supportsuid) {
        virCommandAddArgFormat(cmd, "%lld,%llu,%lu",
                               (long long)pid, startTime, (unsigned long)uid);
    } else {
        if (!polkitInsecureWarned) {
            VIR_WARN("No support for caller UID with pkcheck. This deployment is known to be insecure.");
            polkitInsecureWarned = true;
        }
        virCommandAddArgFormat(cmd, "%lld,%llu",
                               (long long)pid, startTime);
    }
    if (allowInteraction)
        virCommandAddArg(cmd, "--allow-user-interaction");

    while (details && details[0] && details[1]) {
        virCommandAddArgList(cmd, "--detail", details[0], details[1], NULL);
        details += 2;
    }

    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    authdismissed = (pkout && strstr(pkout, "dismissed=true"));
    if (status != 0) {
        char *tmp = virProcessTranslateStatus(status);
        VIR_DEBUG("Policy kit denied action %s from pid %lld, uid %d: %s",
                  actionid, (long long)pid, (int)uid, NULLSTR(tmp));
        VIR_FREE(tmp);
        ret = -2;
        goto cleanup;
    }

    VIR_DEBUG("Policy allowed action %s from pid %lld, uid %d",
              actionid, (long long)pid, (int)uid);

    ret = 0;

 cleanup:
    if (ret < 0) {
        virResetLastError();

        if (authdismissed) {
            virReportError(VIR_ERR_AUTH_CANCELLED, "%s",
                           _("authentication cancelled by user"));
        } else if (pkout && *pkout) {
            virReportError(VIR_ERR_AUTH_FAILED, _("polkit: %s"), pkout);
        } else {
            virReportError(VIR_ERR_AUTH_FAILED, "%s", _("authentication failed"));
        }
    }

    virCommandFree(cmd);
    VIR_FREE(pkout);
    return ret;
}


#elif WITH_POLKIT0
int virPolkitCheckAuth(const char *actionid,
                       pid_t pid,
                       unsigned long long startTime ATTRIBUTE_UNUSED,
                       uid_t uid,
                       const char **details,
                       bool allowInteraction ATTRIBUTE_UNUSED)
{
    PolKitCaller *pkcaller = NULL;
    PolKitAction *pkaction = NULL;
    PolKitContext *pkcontext = NULL;
    PolKitError *pkerr = NULL;
    PolKitResult pkresult;
    DBusError err;
    DBusConnection *sysbus;
    int ret = -1;

    if (details) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("Details not supported with polkit v0"));
        return -1;
    }

    if (!(sysbus = virDBusGetSystemBus()))
        goto cleanup;

    VIR_INFO("Checking PID %lld running as %d",
             (long long) pid, uid);
    dbus_error_init(&err);
    if (!(pkcaller = polkit_caller_new_from_pid(sysbus,
                                                pid, &err))) {
        VIR_DEBUG("Failed to lookup policy kit caller: %s", err.message);
        dbus_error_free(&err);
        goto cleanup;
    }

    if (!(pkaction = polkit_action_new())) {
        char ebuf[1024];
        VIR_DEBUG("Failed to create polkit action %s",
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        goto cleanup;
    }
    polkit_action_set_action_id(pkaction, actionid);

    if (!(pkcontext = polkit_context_new()) ||
        !polkit_context_init(pkcontext, &pkerr)) {
        char ebuf[1024];
        VIR_DEBUG("Failed to create polkit context %s",
                  (pkerr ? polkit_error_get_error_message(pkerr)
                   : virStrerror(errno, ebuf, sizeof(ebuf))));
        if (pkerr)
            polkit_error_free(pkerr);
        dbus_error_free(&err);
        goto cleanup;
    }

# if HAVE_POLKIT_CONTEXT_IS_CALLER_AUTHORIZED
    pkresult = polkit_context_is_caller_authorized(pkcontext,
                                                   pkaction,
                                                   pkcaller,
                                                   0,
                                                   &pkerr);
    if (pkerr && polkit_error_is_set(pkerr)) {
        VIR_DEBUG("Policy kit failed to check authorization %d %s",
                  polkit_error_get_error_code(pkerr),
                  polkit_error_get_error_message(pkerr));
        goto cleanup;
    }
# else
    pkresult = polkit_context_can_caller_do_action(pkcontext,
                                                   pkaction,
                                                   pkcaller);
# endif
    if (pkresult != POLKIT_RESULT_YES) {
        VIR_DEBUG("Policy kit denied action %s from pid %lld, uid %d, result: %s",
                  actionid, (long long) pid, uid,
                  polkit_result_to_string_representation(pkresult));
        ret = -2;
        goto cleanup;
    }

    VIR_DEBUG("Policy allowed action %s from pid %lld, uid %d",
              actionid, (long long)pid, (int)uid);

    ret = 0;

 cleanup:
    if (ret < 0) {
        virResetLastError();
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("authentication failed"));
    }
    if (pkcontext)
        polkit_context_unref(pkcontext);
    if (pkcaller)
        polkit_caller_unref(pkcaller);
    if (pkaction)
        polkit_action_unref(pkaction);
    return ret;
}


#else /* ! WITH_POLKIT1 && ! WITH_POLKIT0 */

int virPolkitCheckAuth(const char *actionid,
                       pid_t pid,
                       unsigned long long startTime,
                       uid_t uid,
                       const char **details,
                       bool allowInteraction)
{
    VIR_ERROR(_("Polkit auth attempted, even though polkit is not available"));
    virReportError(VIR_ERR_AUTH_FAILED, "%s",
                   _("authentication failed"));
    return -1;
}


#endif /* WITH_POLKIT1 */
