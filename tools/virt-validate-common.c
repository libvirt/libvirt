/*
 * virt-validate-common.c: Sanity check helper APIs
 *
 * Copyright (C) 2012-2024 Red Hat, Inc.
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

#include <unistd.h>

#include "virt-validate-common.h"

static bool quiet;

void virValidateSetQuiet(bool quietFlag)
{
    quiet = quietFlag;
}

void virValidateCheck(const char *prefix,
                      const char *format,
                      ...)
{
    va_list args;
    g_autofree char *msg = NULL;

    if (quiet)
        return;

    va_start(args, format);
    msg = g_strdup_vprintf(format, args);
    va_end(args);

    fprintf(stdout, "%1$6s: %2$-69s: ", prefix, msg);
}

static bool virValidateWantEscape(void)
{
    static bool detectTty = true;
    static bool wantEscape;
    if (detectTty) {
        if (isatty(STDOUT_FILENO))
            wantEscape = true;
        detectTty = false;
    }
    return wantEscape;
}

void virValidatePass(void)
{
    if (quiet)
        return;

    if (virValidateWantEscape())
        fprintf(stdout, "\033[32m%s\033[0m\n", _("PASS"));
    else
        fprintf(stdout, "%s\n", _("PASS"));
}


static const char * failMessages[] = {
    N_("FAIL"),
    N_("WARN"),
    N_("NOTE"),
};

G_STATIC_ASSERT(G_N_ELEMENTS(failMessages) == VIR_VALIDATE_LAST);

static const char *failEscapeCodes[] = {
    "\033[31m",
    "\033[33m",
    "\033[34m",
};

G_STATIC_ASSERT(G_N_ELEMENTS(failEscapeCodes) == VIR_VALIDATE_LAST);

void virValidateFail(virValidateLevel level,
                     const char *format,
                     ...)
{
    va_list args;
    g_autofree char *msg = NULL;

    if (quiet)
        return;

    va_start(args, format);
    msg = g_strdup_vprintf(format, args);
    va_end(args);

    if (virValidateWantEscape())
        fprintf(stdout, "%s%s\033[0m (%s)\n",
                failEscapeCodes[level], _(failMessages[level]), msg);
    else
        fprintf(stdout, "%s (%s)\n",
                _(failMessages[level]), msg);
}
