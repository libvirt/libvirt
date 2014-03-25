/*
 * parallels_utils.c: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2012 Parallels, Inc.
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
 * License along with this library; If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <stdarg.h>

#include "vircommand.h"
#include "virerror.h"
#include "viralloc.h"
#include "virjson.h"
#include "parallels_utils.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

static int
parallelsDoCmdRun(char **outbuf, const char *binary, va_list list)
{
    virCommandPtr cmd = virCommandNewVAList(binary, list);
    int ret = -1;

    if (outbuf)
        virCommandSetOutputBuffer(cmd, outbuf);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    if (ret && outbuf)
        VIR_FREE(*outbuf);
    return ret;
}

/*
 * Run command and parse its JSON output, return
 * pointer to virJSONValue or NULL in case of error.
 */
virJSONValuePtr
parallelsParseOutput(const char *binary, ...)
{
    char *outbuf;
    virJSONValuePtr jobj = NULL;
    va_list list;
    int ret;

    va_start(list, binary);
    ret = parallelsDoCmdRun(&outbuf, binary, list);
    va_end(list);
    if (ret)
        return NULL;

    jobj = virJSONValueFromString(outbuf);
    if (!jobj)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid output from prlctl: %s"), outbuf);

    VIR_FREE(outbuf);
    return jobj;
}

/*
 * Run command and return its output, pointer to
 * buffer or NULL in case of error. Caller os responsible
 * for freeing the buffer.
 */
char *
parallelsGetOutput(const char *binary, ...)
{
    char *outbuf;
    va_list list;
    int ret;

    va_start(list, binary);
    ret = parallelsDoCmdRun(&outbuf, binary, list);
    va_end(list);
    if (ret)
        return NULL;

    return outbuf;
}

/*
 * Run prlctl command and check for errors
 *
 * Return value is 0 in case of success, else - -1
 */
int
parallelsCmdRun(const char *binary, ...)
{
    int ret;
    va_list list;

    va_start(list, binary);
    ret = parallelsDoCmdRun(NULL, binary, list);
    va_end(list);

    return ret;
}

/*
 * Return new file path in malloced string created by
 * concatenating first and second function arguments.
 */
char *
parallelsAddFileExt(const char *path, const char *ext)
{
    char *new_path = NULL;
    size_t len = strlen(path) + strlen(ext) + 1;

    if (VIR_ALLOC_N(new_path, len) < 0)
        return NULL;

    if (!virStrcpy(new_path, path, len)) {
        VIR_FREE(new_path);
        return NULL;
    }
    strcat(new_path, ext);

    return new_path;
}
