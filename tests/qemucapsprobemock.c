/*
 * Copyright (C) 2016 Red Hat, Inc.
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
#include <dlfcn.h>

#include "internal.h"
#include "virjson.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_monitor_json.h"

#define LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
#include "qemu/qemu_monitor_priv.h"

#define REAL_SYM(realFunc) \
    do { \
        if (!realFunc && !(realFunc = dlsym(RTLD_NEXT, __FUNCTION__))) { \
            fprintf(stderr, "Cannot find real '%s' symbol\n", \
                    __FUNCTION__); \
            abort(); \
        } \
    } while (0)

static bool first = true;

static void
printLineSkipEmpty(const char *line,
                   FILE *fp)
{
    const char *p;

    for (p = line; *p; p++) {
        if (p[0] == '\n' && p[1] == '\n')
            continue;

        fputc(*p, fp);
    }
}


static int (*realQemuMonitorSend)(qemuMonitor *mon,
                                  qemuMonitorMessage *msg);

int
qemuMonitorSend(qemuMonitor *mon,
                qemuMonitorMessage *msg)
{
    g_autofree char *reformatted = NULL;

    REAL_SYM(realQemuMonitorSend);

    if (!(reformatted = virJSONStringReformat(msg->txBuffer, true))) {
        fprintf(stderr, "Failed to reformat command string '%s'\n", msg->txBuffer);
        abort();
    }

    if (first)
        first = false;
    else
        printLineSkipEmpty("\n", stdout);

    printLineSkipEmpty(reformatted, stdout);

    return realQemuMonitorSend(mon, msg);
}


static int (*realQemuMonitorJSONIOProcessLine)(qemuMonitor *mon,
                                               const char *line,
                                               qemuMonitorMessage *msg);

int
qemuMonitorJSONIOProcessLine(qemuMonitor *mon,
                             const char *line,
                             qemuMonitorMessage *msg)
{
    g_autoptr(virJSONValue) value = NULL;
    g_autofree char *json = NULL;
    int ret;

    REAL_SYM(realQemuMonitorJSONIOProcessLine);

    ret = realQemuMonitorJSONIOProcessLine(mon, line, msg);

    if (ret == 0) {
        if (!(value = virJSONValueFromString(line)) ||
            !(json = virJSONValueToString(value, true))) {
            fprintf(stderr, "Failed to reformat reply string '%s'\n", line);
            abort();
        }

        /* Ignore QMP greeting */
        if (virJSONValueObjectHasKey(value, "QMP"))
            return 0;

        if (first)
            first = false;
        else
            printLineSkipEmpty("\n", stdout);

        printLineSkipEmpty(json, stdout);
    }

    return ret;
}
