/*
 * bhyve_rctl.c: Resource limits management with rctl(8)
 *
 * Copyright (C) 2026 The FreeBSD Foundation
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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "bhyve_rctl.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_rctl");


static int
bhyveRctlGetAmountFromRule(const char *rule, unsigned long long *amount)
{
    /* From rctl(8):
     *
     * Syntax for a rule is subject:subject-id:resource:action=amount/per.
     * A valid rule has all those fields specified, except for per, which
     * defaults to the value of subject.
     */
    g_auto(GStrv) tokens = NULL;
    unsigned long long bytes;

    if (!(tokens = g_strsplit_set(rule, "=/", 0)))
        return -1;

    if (g_strv_length(tokens) < 2)
        return -1;

    if (virStrToLong_ull(tokens[1], NULL, 10, &bytes) < 0)
        return -1;

    *amount = bytes / 1024;

    return 0;
}

int
bhyveRctlGetMemoryHardLimit(pid_t pid, unsigned long long *kb)
{
    g_auto(GStrv) lines = NULL;
    g_autofree char *outbuf = NULL;
    g_autoptr(virCommand) cmd = NULL;
    size_t i;

    cmd = virCommandNew("rctl");
    virCommandAddArgFormat(cmd, "process:%d:memoryuse", pid);
    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, NULL) < 0) {
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return -1;
    }

    /* Empty output means no matching rules, thus no limits */
    if (strlen(outbuf) == 0) {
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 0;
    }

    if (!(lines = g_strsplit(outbuf, "\n", 0)))
        return -1;

    /* There could be multiple actions for a resource, such as
     * 'log' for example, so we need to look for the 'deny' action
     * specifically */
    for (i = 0; lines[i]; i++)
        if (strstr(lines[i], ":deny="))
            return bhyveRctlGetAmountFromRule(lines[i], kb);

    return -1;
}
