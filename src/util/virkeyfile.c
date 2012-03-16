/*
 * virkeyfile.c: "ini"-style configuration file handling
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
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>

#include "c-ctype.h"
#include "logging.h"
#include "memory.h"
#include "util.h"
#include "virhash.h"
#include "virkeyfile.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_CONF

typedef struct _virKeyFileGroup virKeyFileGroup;
typedef virKeyFileGroup *virKeyFileGroupPtr;

typedef struct _virKeyFileParserCtxt virKeyFileParserCtxt;
typedef virKeyFileParserCtxt *virKeyFileParserCtxtPtr;

struct _virKeyFile {
    virHashTablePtr groups;
};

struct _virKeyFileParserCtxt {
    virKeyFilePtr conf;

    const char *filename;

    const char *base;
    const char *cur;
    const char *end;
    size_t line;

    char *groupname;
    virHashTablePtr group;
};

/*
 * The grammar for the keyfile
 *
 * KEYFILE = (GROUP | COMMENT | BLANK )*
 *
 * COMMENT = ('#' | ';') [^\n]* '\n'
 * BLANK = (' ' | '\t' )* '\n'
 *
 * GROUP = '[' GROUPNAME ']' '\n' (ENTRY ) *
 * GROUPNAME = [^[]\n]+
 *
 * ENTRY = KEYNAME '=' VALUE
 * VALUE = [^\n]* '\n'
 * KEYNAME = [-a-zA-Z0-9]+
 */

#define IS_EOF (ctxt->cur >= ctxt->end)
#define IS_EOL(c) (((c) == '\n') || ((c) == '\r'))
#define CUR (*ctxt->cur)
#define NEXT if (!IS_EOF) ctxt->cur++;


#define virKeyFileError(ctxt, error, info) \
    virKeyFileErrorHelper(__FILE__, __FUNCTION__, __LINE__, ctxt, error, info)
static void
virKeyFileErrorHelper(const char *file, const char *func, size_t line,
                      virKeyFileParserCtxtPtr ctxt,
                      virErrorNumber error, const char *info)
{
    /* Construct the string 'filename:line: info' if we have that. */
    if (ctxt && ctxt->filename) {
        virReportErrorHelper(VIR_FROM_CONF, error, file, func, line,
                             _("%s:%zu: %s '%s'"), ctxt->filename, ctxt->line, info, ctxt->cur);
    } else {
        virReportErrorHelper(VIR_FROM_CONF, error, file, func, line,
                             "%s", info);
    }
}


static void virKeyFileValueFree(void *value, const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(value);
}

static int virKeyFileParseGroup(virKeyFileParserCtxtPtr ctxt)
{
    int ret = -1;
    const char *name;
    NEXT;

    ctxt->group = NULL;
    VIR_FREE(ctxt->groupname);

    name = ctxt->cur;
    while (!IS_EOF && c_isascii(CUR) && CUR != ']')
        ctxt->cur++;
    if (CUR != ']') {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "cannot find end of group name, expected ']'");
        return -1;
    }

    if (!(ctxt->groupname = strndup(name, ctxt->cur - name))) {
        virReportOOMError();
        return -1;
    }

    NEXT;

    if (!(ctxt->group = virHashCreate(10, virKeyFileValueFree)))
        goto cleanup;

    if (virHashAddEntry(ctxt->conf->groups, ctxt->groupname, ctxt->group) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    if (ret != 0) {
        virHashFree(ctxt->group);
        ctxt->group = NULL;
        VIR_FREE(ctxt->groupname);
    }

    return ret;
}

static int virKeyFileParseValue(virKeyFileParserCtxtPtr ctxt)
{
    int ret = -1;
    const char *keystart;
    const char *valuestart;
    char *key = NULL;
    char *value = NULL;
    size_t len;

    if (!ctxt->groupname || !ctxt->group) {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "value found before first group");
        return -1;
    }

    keystart = ctxt->cur;
    while (!IS_EOF && c_isalnum(CUR) && CUR != '=')
        ctxt->cur++;
    if (CUR != '=') {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "expected end of value name, expected '='");
        return -1;
    }

    if (!(key = strndup(keystart, ctxt->cur - keystart))) {
        virReportOOMError();
        return -1;
    }

    NEXT;
    valuestart = ctxt->cur;
    while (!IS_EOF && !IS_EOL(CUR))
        ctxt->cur++;
    if (!(IS_EOF || IS_EOL(CUR))) {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "unexpected end of value");
        goto cleanup;
    }
    len = ctxt->cur - valuestart;
    if (IS_EOF && !IS_EOL(CUR))
        len++;
    if (!(value = strndup(valuestart, len))) {
        virReportOOMError();
        goto cleanup;
    }

    if (virHashAddEntry(ctxt->group, key, value) < 0) {
        VIR_FREE(value);
        goto cleanup;
    }

    NEXT;

    ret = 0;

cleanup:
    VIR_FREE(key);
    return ret;
}

static int virKeyFileParseComment(virKeyFileParserCtxtPtr ctxt)
{
    NEXT;

    while (!IS_EOF && !IS_EOL(CUR))
        ctxt->cur++;

    NEXT;

    return 0;
}

static int virKeyFileParseBlank(virKeyFileParserCtxtPtr ctxt)
{
    while ((ctxt->cur < ctxt->end) && c_isblank(CUR))
        ctxt->cur++;

    if (!((ctxt->cur == ctxt->end) || IS_EOL(CUR))) {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "expected newline");
        return -1;
    }
    NEXT;
    return 0;
}

static int virKeyFileParseStatement(virKeyFileParserCtxtPtr ctxt)
{
    int ret = -1;

    if (CUR == '[') {
        ret = virKeyFileParseGroup(ctxt);
    } else if (c_isalnum(CUR)) {
        ret = virKeyFileParseValue(ctxt);
    } else if (CUR == '#' || CUR == ';') {
        ret = virKeyFileParseComment(ctxt);
    } else if (c_isblank(CUR) || IS_EOL(CUR)) {
        ret = virKeyFileParseBlank(ctxt);
    } else {
        virKeyFileError(ctxt, VIR_ERR_CONF_SYNTAX, "unexpected statement");
    }

    return ret;
}

static int virKeyFileParse(virKeyFilePtr conf,
                           const char *filename,
                           const char *data,
                           size_t len)
{
    virKeyFileParserCtxt ctxt;
    int ret = -1;

    VIR_DEBUG("Parse %p '%s' %p %zu", conf, filename, data, len);

    memset(&ctxt, 0, sizeof(ctxt));

    ctxt.filename = filename;
    ctxt.base = ctxt.cur = data;
    ctxt.end = data + len - 1;
    ctxt.line = 1;
    ctxt.conf = conf;

    while (ctxt.cur < ctxt.end) {
        if (virKeyFileParseStatement(&ctxt) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(ctxt.groupname);
    return ret;
}


static void virKeyFileEntryFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    virHashFree(payload);
}


virKeyFilePtr virKeyFileNew(void)
{
    virKeyFilePtr conf;

    if (VIR_ALLOC(conf) < 0) {
        virReportOOMError();
        goto error;
    }

    if (!(conf->groups = virHashCreate(10,
                                       virKeyFileEntryFree)))
        goto error;

    return conf;

error:
    virKeyFileFree(conf);
    return NULL;
}


#define MAX_CONFIG_FILE_SIZE (1024 * 1024)

int virKeyFileLoadFile(virKeyFilePtr conf,
                       const char *filename)
{
    char *data = NULL;
    ssize_t len;
    int ret;

    if ((len = virFileReadAll(filename, MAX_CONFIG_FILE_SIZE, &data)) < 0)
        return -1;

    ret = virKeyFileParse(conf, filename, data, len);

    VIR_FREE(data);

    return ret;
}


int virKeyFileLoadData(virKeyFilePtr conf,
                       const char *path,
                       const char *data,
                       size_t len)
{
    return virKeyFileParse(conf, path, data, len);
}


void virKeyFileFree(virKeyFilePtr conf)
{
    if (!conf)
        return;

    virHashFree(conf->groups);
    VIR_FREE(conf);
}


bool virKeyFileHasGroup(virKeyFilePtr conf,
                       const char *groupname)
{
    VIR_DEBUG("conf=%p groupname=%s", conf, groupname);
    return virHashLookup(conf->groups, groupname) != NULL;
}


bool virKeyFileHasValue(virKeyFilePtr conf,
                       const char *groupname,
                       const char *valuename)
{
    virHashTablePtr group = virHashLookup(conf->groups, groupname);
    VIR_DEBUG("conf=%p groupname=%s valuename=%s", conf, groupname, valuename);
    return group && virHashLookup(group, valuename) != NULL;
}

const char *virKeyFileGetValueString(virKeyFilePtr conf,
                                     const char *groupname,
                                     const char *valuename)
{
    virHashTablePtr group = virHashLookup(conf->groups, groupname);
    VIR_DEBUG("conf=%p groupname=%s valuename=%s", conf, groupname, valuename);
    return virHashLookup(group, valuename);
}
