/*
 * virinhibitor.c: helper APIs for inhibiting host actions
 *
 * Copyright (C) 2024 Red Hat, Inc.
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

#include "virinhibitor.h"
#include "virgdbus.h"
#include "virsystemd.h"
#include "virfile.h"
#include "virlog.h"
#include "virenum.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.inhibitor");

struct _virInhibitor {
    GMutex lock;
    size_t count;
    int fd;

    char *what;
    char *who;
    char *why;
    const char *mode;

    virInhibitorAction action;
    void *actionData;
};

VIR_ENUM_DECL(virInhibitorMode);

VIR_ENUM_IMPL(virInhibitorMode,
              VIR_INHIBITOR_MODE_LAST,
              "block", "delay");

#ifdef G_OS_UNIX
/* As per: https://www.freedesktop.org/wiki/Software/systemd/inhibit */
static int
virInhibitorAcquire(const char *what,
                    const char *who,
                    const char *why,
                    const char *mode,
                    int *inhibitorFD)
{
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GUnixFDList) replyFD = NULL;
    g_autoptr(GVariant) message = NULL;
    GDBusConnection *systemBus;
    int fd;
    int rc;

    VIR_DEBUG("what=%s who=%s why=%s mode=%s",
              NULLSTR(what), NULLSTR(who), NULLSTR(why), NULLSTR(mode));

    if (!(systemBus = virGDBusGetSystemBus())) {
        VIR_DEBUG("system dbus not available, skipping system inhibitor");
        return 0;
    }

    if (virSystemdHasLogind() < 0) {
        VIR_DEBUG("logind not available, skipping system inhibitor");
        return 0;
    }

    message = g_variant_new("(ssss)", what, who, why, mode);

    rc = virGDBusCallMethodWithFD(systemBus,
                                  &reply,
                                  G_VARIANT_TYPE("(h)"),
                                  &replyFD,
                                  NULL,
                                  "org.freedesktop.login1",
                                  "/org/freedesktop/login1",
                                  "org.freedesktop.login1.Manager",
                                  "Inhibit",
                                  message,
                                  NULL);

    if (rc < 0)
        return -1;

    if (g_unix_fd_list_get_length(replyFD) <= 0) {
        VIR_DEBUG("Missing inhibitor FD in logind reply");
        return -1;
    }

    fd = g_unix_fd_list_get(replyFD, 0, NULL);
    if (fd < 0) {
        VIR_DEBUG("Unable to get inhibitor FD from logind reply");
        return -1;
    }

    *inhibitorFD = fd;
    VIR_DEBUG("Got inhibitor FD %d", fd);
    return 0;
}
#endif


static char *
virInhibitorWhatFormat(virInhibitorWhat what)
{
    const char *whatstr[] = {
        "sleep",
        "shutdown",
        "idle",
        "handle-power-key",
        "handle-suspend-key",
        "handle-hibernate-key",
        "handle-lid-switch",
    };
    GString *str = g_string_new("");
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(whatstr); i++) {
        if (what & (1 << i)) {
            if (str->len)
                g_string_append(str, ":");
            g_string_append(str, whatstr[i]);
        }
    }

    return g_string_free(str, FALSE);
}


virInhibitor *virInhibitorNew(virInhibitorWhat what,
                              const char *who,
                              const char *why,
                              virInhibitorMode mode,
                              virInhibitorAction action,
                              void *actionData)
{
    virInhibitor *inhibitor = g_new0(virInhibitor, 1);

    inhibitor->fd = -1;
    inhibitor->what = virInhibitorWhatFormat(what);
    inhibitor->who = g_strdup(who);
    inhibitor->why = g_strdup(why);
    inhibitor->mode = virInhibitorModeTypeToString(mode);
    inhibitor->action = action;
    inhibitor->actionData = actionData;

    return inhibitor;
}

void virInhibitorHold(virInhibitor *inhibitor)
{
    g_mutex_lock(&inhibitor->lock);

    if (inhibitor->count == 0) {
        if (inhibitor->action) {
            inhibitor->action(true, inhibitor->actionData);
        }
#ifdef G_OS_UNIX
        if (virInhibitorAcquire(
                inhibitor->what, inhibitor->who, inhibitor->why,
                inhibitor->mode, &inhibitor->fd) < 0) {
            VIR_ERROR(_("Failed to acquire inhibitor: %1$s"),
                      virGetLastErrorMessage());
            virResetLastError();
        }
#else
        VIR_DEBUG("No inhibitor implementation on non-UNIX platforms");
#endif
    }
    inhibitor->count++;
    g_mutex_unlock(&inhibitor->lock);
}


void virInhibitorRelease(virInhibitor *inhibitor)
{
    g_mutex_lock(&inhibitor->lock);
    inhibitor->count--;
    if (inhibitor->count == 0) {
        VIR_FORCE_CLOSE(inhibitor->fd);
        if (inhibitor->action) {
            inhibitor->action(false, inhibitor->actionData);
        }
    }
    g_mutex_unlock(&inhibitor->lock);
}


void virInhibitorFree(virInhibitor *inhibitor)
{
    if (!inhibitor)
        return;

    g_free(inhibitor->what);
    g_free(inhibitor->who);
    g_free(inhibitor->why);
    VIR_FORCE_CLOSE(inhibitor->fd);
    g_free(inhibitor);
}
