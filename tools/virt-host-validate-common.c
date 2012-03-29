/*
 * virt-host-validate-common.c: Sanity check helper APIs
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "util.h"
#include "memory.h"
#include "virfile.h"
#include "virt-host-validate-common.h"

static bool quiet;

void virHostMsgSetQuiet(bool quietFlag)
{
    quiet = quietFlag;
}

void virHostMsgCheck(const char *prefix,
                     const char *format,
                     ...)
{
    va_list args;
    char *msg;

    if (quiet)
        return;

    va_start(args, format);
    if (virVasprintf(&msg, format, args) < 0) {
        perror("malloc");
        abort();
    }
    va_end(args);

    fprintf(stdout, _("%6s: Checking %-60s: "), prefix, msg);
    VIR_FREE(msg);
}

static bool virHostMsgWantEscape(void)
{
    static bool detectTty = true;
    static bool wantEscape = false;
    if (detectTty) {
        if (isatty(STDOUT_FILENO))
            wantEscape = true;
        detectTty = false;
    }
    return wantEscape;
}

void virHostMsgPass(void)
{
    if (quiet)
        return;

    if (virHostMsgWantEscape())
        fprintf(stdout, "\033[32m%s\033[0m\n", _("PASS"));
    else
        fprintf(stdout, "%s\n", _("PASS"));
}


static const char * failMessages[] = {
    N_("FAIL"),
    N_("WARN"),
    N_("NOTE"),
};

verify(ARRAY_CARDINALITY(failMessages) == VIR_HOST_VALIDATE_LAST);

static const char *failEscapeCodes[] = {
    "\033[31m",
    "\033[33m",
    "\033[34m",
};

verify(ARRAY_CARDINALITY(failEscapeCodes) == VIR_HOST_VALIDATE_LAST);

void virHostMsgFail(virHostValidateLevel level,
                    const char *hint)
{
    if (virHostMsgWantEscape())
        fprintf(stdout, "%s%s\033[0m (%s)\n",
                failEscapeCodes[level], _(failMessages[level]), hint);
    else
        fprintf(stdout, "%s (%s)\n",
                _(failMessages[level]), hint);
}


int virHostValidateDevice(const char *hvname,
                          const char *dev_name,
                          virHostValidateLevel level,
                          const char *hint)
{
    virHostMsgCheck(hvname, "for device %s", dev_name);

    if (access(dev_name, R_OK|W_OK) < 0) {
        virHostMsgFail(level, hint);
        return -1;
    }

    virHostMsgPass();
    return 0;
}


bool virHostValidateHasCPUFlag(const char *name)
{
    FILE *fp = fopen("/proc/cpuinfo", "r");
    bool ret = false;

    if (!fp)
        return false;

    do {
        char line[1024];

        if (!fgets(line, sizeof(line), fp))
            break;

        if (strstr(line, name)) {
            ret = true;
            break;
        }
    } while (1);

    VIR_FORCE_FCLOSE(fp);

    return ret;
}


int virHostValidateLinuxKernel(const char *hvname,
                               int version,
                               virHostValidateLevel level,
                               const char *hint)
{
    struct utsname uts;
    unsigned long thisversion;

    uname(&uts);

    virHostMsgCheck(hvname, _("for Linux >= %d.%d.%d"),
                    ((version >> 16) & 0xff),
                    ((version >> 8) & 0xff),
                    (version & 0xff));

    if (STRNEQ(uts.sysname, "Linux")) {
        virHostMsgFail(level, hint);
        return -1;
    }

    if (virParseVersionString(uts.release, &thisversion, true) < 0) {
        virHostMsgFail(level, hint);
        return -1;
    }

    if (thisversion < version) {
        virHostMsgFail(level, hint);
        return -1;
    } else {
        virHostMsgPass();
        return 0;
    }
}
