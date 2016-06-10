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
 *
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>
#include <stdio.h>
#include <dlfcn.h>

#include "internal.h"
#include "viralloc.h"
#include "virjson.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_monitor_json.h"

#define REAL_SYM(realFunc)                                                  \
    do {                                                                    \
        if (!realFunc && !(realFunc = dlsym(RTLD_NEXT, __FUNCTION__))) {    \
            fprintf(stderr, "Cannot find real '%s' symbol\n",               \
                    __FUNCTION__);                                          \
            abort();                                                        \
        }                                                                   \
    } while (0)


static int (*realQemuMonitorSend)(qemuMonitorPtr mon,
                                  qemuMonitorMessagePtr msg);

int
qemuMonitorSend(qemuMonitorPtr mon,
                qemuMonitorMessagePtr msg)
{
    REAL_SYM(realQemuMonitorSend);

    fprintf(stderr, "%s", msg->txBuffer);

    return realQemuMonitorSend(mon, msg);
}


static int (*realQemuMonitorJSONIOProcessLine)(qemuMonitorPtr mon,
                                               const char *line,
                                               qemuMonitorMessagePtr msg);

int
qemuMonitorJSONIOProcessLine(qemuMonitorPtr mon,
                             const char *line,
                             qemuMonitorMessagePtr msg)
{
    static bool first = true;
    virJSONValuePtr value = NULL;
    char *json = NULL;
    int ret;

    REAL_SYM(realQemuMonitorJSONIOProcessLine);

    ret = realQemuMonitorJSONIOProcessLine(mon, line, msg);

    if (ret == 0 &&
        (value = virJSONValueFromString(line)) &&
        (json = virJSONValueToString(value, 1))) {
        char *p;
        bool skip = false;

        if (first)
            first = false;
        else
            putchar('\n');

        for (p = json; *p; p++) {
            if (skip && *p == '\n') {
                continue;
            } else {
                skip = *p == '\n';
                putchar(*p);
            }
        }
    }

    VIR_FREE(json);
    virJSONValueFree(value);
    return ret;
}
