/*
 * virconf.c: parser for a subset of the Python encoded Xen configuration files
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "virerror.h"
#include "virbuffer.h"
#include "virconf.h"
#include "virutil.h"
#include "c-ctype.h"
#include "virlog.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("util.conf");

/************************************************************************
 *									*
 *	Structures and macros used by the mini parser			*
 *									*
 ************************************************************************/

typedef struct _virConfParserCtxt virConfParserCtxt;
typedef virConfParserCtxt *virConfParserCtxtPtr;

struct _virConfParserCtxt {
    const char* filename;
    const char* base;
    const char* cur;
    const char *end;
    int line;

    virConfPtr conf;
};

#define CUR (*ctxt->cur)
#define NEXT if (ctxt->cur < ctxt->end) ctxt->cur++;
#define IS_EOL(c) (((c) == '\n') || ((c) == '\r'))

#define SKIP_BLANKS_AND_EOL                                             \
  do { while ((ctxt->cur < ctxt->end) && (c_isblank(CUR) || IS_EOL(CUR))) { \
         if (CUR == '\n') ctxt->line++;	                                \
         ctxt->cur++; } } while (0)
#define SKIP_BLANKS                                                     \
  do { while ((ctxt->cur < ctxt->end) && (c_isblank(CUR)))              \
          ctxt->cur++; } while (0)

/************************************************************************
 *									*
 *		Structures used by configuration data			*
 *									*
 ************************************************************************/

VIR_ENUM_IMPL(virConf, VIR_CONF_LAST,
              "*unexpected*",
              "long",
              "unsigned long",
              "string",
              "list");

typedef struct _virConfEntry virConfEntry;
typedef virConfEntry *virConfEntryPtr;

struct _virConfEntry {
    virConfEntryPtr next;
    char* name;
    char* comment;
    virConfValuePtr value;
};

struct _virConf {
    char *filename;
    unsigned int flags;
    virConfEntryPtr entries;
};

/**
 * virConfError:
 * @ctxt: the parser context if available or NULL
 * @error: the error number
 * @info: extra information string
 *
 * Handle an error at the xend daemon interface
 */
#define virConfError(ctxt, error, info) \
    virConfErrorHelper(__FILE__, __FUNCTION__, __LINE__, ctxt, error, info)
static void
virConfErrorHelper(const char *file, const char *func, size_t line,
                   virConfParserCtxtPtr ctxt,
                   virErrorNumber error, const char *info)
{
    if (error == VIR_ERR_OK)
        return;

    /* Construct the string 'filename:line: info' if we have that. */
    if (ctxt && ctxt->filename) {
        virReportErrorHelper(VIR_FROM_CONF, error, file, func, line,
                             _("%s:%d: %s"), ctxt->filename, ctxt->line, info);
    } else {
        virReportErrorHelper(VIR_FROM_CONF, error, file, func, line,
                             "%s", info);
    }
}


/************************************************************************
 *									*
 *		Structures allocations and deallocations		*
 *									*
 ************************************************************************/

/**
 * virConfFreeList:
 * @list: the list to free
 *
 * Free a list
 */
static void
virConfFreeList(virConfValuePtr list)
{
    virConfValuePtr next;

    while (list != NULL) {
        next = list->next;
        list->next = NULL;
        virConfFreeValue(list);
        list = next;
    }
}

/**
 * virConfFreeValue:
 * @val: the value to free
 *
 * Free a value
 */
void
virConfFreeValue(virConfValuePtr val)
{
    if (val == NULL)
        return;
    if (val->type == VIR_CONF_STRING &&
        val->str != NULL)
        VIR_FREE(val->str);
    if (val->type == VIR_CONF_LIST &&
        val->list != NULL)
        virConfFreeList(val->list);
    VIR_FREE(val);
}

virConfPtr
virConfNew(void)
{
    virConfPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;
    ret->filename = NULL;
    ret->flags = 0;

    return ret;
}

/**
 * virConfCreate:
 * @filename: the name to report errors
 * @flags: combination of virConfFlag(s)
 *
 * Create a configuration internal structure
 *
 * Returns a pointer or NULL in case of error.
 */
static virConfPtr
virConfCreate(const char *filename, unsigned int flags)
{
    virConfPtr ret = virConfNew();
    if (!ret)
        return NULL;

    if (VIR_STRDUP(ret->filename, filename) < 0) {
        VIR_FREE(ret);
        return NULL;
    }

    ret->flags = flags;
    return ret;
}

/**
 * virConfAddEntry:
 * @conf: the conf structure
 * @name: name of the entry or NULL for comment
 * @value: the value if any
 * @comm: extra comment for that entry if any
 *
 * add one entry to the conf, the parameters are included in the conf
 * if successful and freed on virConfFree()
 *
 * Returns a pointer to the entry or NULL in case of failure
 */
static virConfEntryPtr
virConfAddEntry(virConfPtr conf, char *name, virConfValuePtr value, char *comm)
{
    virConfEntryPtr ret, prev;

    if (conf == NULL)
        return NULL;
    if ((comm == NULL) && (name == NULL))
        return NULL;

    /* don't log fully commented out lines */
    if (name)
        VIR_DEBUG("Add entry %s %p", name, value);

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->name = name;
    ret->value = value;
    ret->comment = comm;

    if (conf->entries == NULL) {
        conf->entries = ret;
    } else {
        prev = conf->entries;
        while (prev->next != NULL)
            prev = prev->next;
        prev->next = ret;
    }
    return ret;
}

/************************************************************************
 *									*
 *			Serialization					*
 *									*
 ************************************************************************/

/**
 * virConfSaveValue:
 * @buf: output buffer
 * @val: a value
 *
 * Serialize the value to the buffer
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virConfSaveValue(virBufferPtr buf, virConfValuePtr val)
{
    if (val == NULL)
        return -1;
    switch (val->type) {
        case VIR_CONF_NONE:
            return -1;
        case VIR_CONF_LLONG:
            virBufferAsprintf(buf, "%lld", val->l);
            break;
        case VIR_CONF_ULLONG:
            virBufferAsprintf(buf, "%llu", val->l);
            break;
        case VIR_CONF_STRING:
            if (val->str) {
                if (strchr(val->str, '\n') != NULL) {
                    virBufferAsprintf(buf, "\"\"\"%s\"\"\"", val->str);
                } else if (strchr(val->str, '"') == NULL) {
                    virBufferAsprintf(buf, "\"%s\"", val->str);
                } else if (strchr(val->str, '\'') == NULL) {
                    virBufferAsprintf(buf, "'%s'", val->str);
                } else {
                    virBufferAsprintf(buf, "\"\"\"%s\"\"\"", val->str);
                }
            }
            break;
        case VIR_CONF_LIST: {
            virConfValuePtr cur;

            cur = val->list;
            virBufferAddLit(buf, "[ ");
            if (cur != NULL) {
                virConfSaveValue(buf, cur);
                cur = cur->next;
                while (cur != NULL) {
                    virBufferAddLit(buf, ", ");
                    virConfSaveValue(buf, cur);
                    cur = cur->next;
                }
            }
            virBufferAddLit(buf, " ]");
            break;
        }
        default:
            return -1;
    }
    return 0;
}

/**
 * virConfSaveEntry:
 * @buf: output buffer
 * @cur: a conf entry
 *
 * Serialize the entry to the buffer
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
virConfSaveEntry(virBufferPtr buf, virConfEntryPtr cur)
{
    if (cur->name != NULL) {
        virBufferAdd(buf, cur->name, -1);
        virBufferAddLit(buf, " = ");
        virConfSaveValue(buf, cur->value);
        if (cur->comment != NULL) {
            virBufferAddLit(buf, " #");
            virBufferAdd(buf, cur->comment, -1);
        }
    } else if (cur->comment != NULL) {
        virBufferAddLit(buf, "#");
        virBufferAdd(buf, cur->comment, -1);
    }
    virBufferAddLit(buf, "\n");
    return 0;
}

/************************************************************************
 *									*
 *			The parser core					*
 *									*
 ************************************************************************/

/**
 * virConfParseLong:
 * @ctxt: the parsing context
 * @val: the result
 *
 * Parse one long int value
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virConfParseLong(virConfParserCtxtPtr ctxt, long long *val)
{
    long long l = 0;
    int neg = 0;

    if (CUR == '-') {
        neg = 1;
        NEXT;
    } else if (CUR == '+') {
        NEXT;
    }
    if ((ctxt->cur >= ctxt->end) || (!c_isdigit(CUR))) {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("unterminated number"));
        return -1;
    }
    while ((ctxt->cur < ctxt->end) && (c_isdigit(CUR))) {
        l = l * 10 + (CUR - '0');
        NEXT;
    }
    if (neg)
        l = -l;
    *val = l;
    return 0;
}

/**
 * virConfParseString:
 * @ctxt: the parsing context
 *
 * Parse one string
 *
 * Returns a pointer to the string or NULL in case of error
 */
static char *
virConfParseString(virConfParserCtxtPtr ctxt)
{
    const char *base;
    char *ret = NULL;

    if (CUR == '\'') {
        NEXT;
        base = ctxt->cur;
        while ((ctxt->cur < ctxt->end) && (CUR != '\'') && (!IS_EOL(CUR)))
            NEXT;
        if (CUR != '\'') {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("unterminated string"));
            return NULL;
        }
        if (VIR_STRNDUP(ret, base, ctxt->cur - base) < 0)
            return NULL;
        NEXT;
    } else if ((ctxt->cur + 6 < ctxt->end) &&
               (STRPREFIX(ctxt->cur, "\"\"\""))) {
        /* String starts with python-style triple quotes """ */
        ctxt->cur += 3;
        base = ctxt->cur;

        /* Find the ending triple quotes */
        while ((ctxt->cur + 2 < ctxt->end) &&
               !(STRPREFIX(ctxt->cur, "\"\"\""))) {
            if (CUR == '\n')
                ctxt->line++;
            NEXT;
        }

        if (!STRPREFIX(ctxt->cur, "\"\"\"")) {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("unterminated string"));
            return NULL;
        }
        if (VIR_STRNDUP(ret, base, ctxt->cur - base) < 0)
            return NULL;
        ctxt->cur += 3;
    } else if (CUR == '"') {
        NEXT;
        base = ctxt->cur;
        while ((ctxt->cur < ctxt->end) && (CUR != '"') && (!IS_EOL(CUR)))
            NEXT;
        if (CUR != '"') {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("unterminated string"));
            return NULL;
        }
        if (VIR_STRNDUP(ret, base, ctxt->cur - base) < 0)
            return NULL;
        NEXT;
    } else if (ctxt->conf->flags & VIR_CONF_FLAG_LXC_FORMAT) {
        base = ctxt->cur;
        /* LXC config format doesn't support comments after the value */
        while ((ctxt->cur < ctxt->end) && (!IS_EOL(CUR)))
            NEXT;
        /* Reverse to exclude the trailing blanks from the value */
        while ((ctxt->cur > base) && (c_isblank(CUR)))
            ctxt->cur--;
        if (VIR_STRNDUP(ret, base, ctxt->cur - base) < 0)
            return NULL;
    }
    return ret;
}

/**
 * virConfParseValue:
 * @ctxt: the parsing context
 *
 * Parse one value
 *
 * Returns a pointer to the value or NULL in case of error
 */
static virConfValuePtr
virConfParseValue(virConfParserCtxtPtr ctxt)
{
    virConfValuePtr ret, lst = NULL, tmp, prev;
    virConfType type = VIR_CONF_NONE;
    char *str = NULL;
    long long l = 0;

    SKIP_BLANKS;
    if (ctxt->cur >= ctxt->end) {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("expecting a value"));
        return NULL;
    }
    if ((CUR == '"') || (CUR == '\'') ||
         (ctxt->conf->flags & VIR_CONF_FLAG_LXC_FORMAT)) {
        type = VIR_CONF_STRING;
        str = virConfParseString(ctxt);
        if (str == NULL)
            return NULL;
    } else if (CUR == '[') {
        if (ctxt->conf->flags & VIR_CONF_FLAG_VMX_FORMAT) {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX,
                         _("lists not allowed in VMX format"));
            return NULL;
        }
        type = VIR_CONF_LIST;
        NEXT;
        SKIP_BLANKS_AND_EOL;
        if ((ctxt->cur < ctxt->end) && (CUR != ']')) {
            if ((lst = virConfParseValue(ctxt)) == NULL)
                return NULL;
            SKIP_BLANKS_AND_EOL;
        }
        while ((ctxt->cur < ctxt->end) && (CUR != ']')) {

            /* Tell Clang that when execution reaches this point
               "lst" is guaranteed to be non-NULL.  This stops it
               from issuing an invalid NULL-dereference warning about
               "prev = lst; while (prev->next..." below.  */
            sa_assert(lst);

            if (CUR != ',') {
                virConfError(ctxt, VIR_ERR_CONF_SYNTAX,
                             _("expecting a separator in list"));
                virConfFreeList(lst);
                return NULL;
            }
            NEXT;
            SKIP_BLANKS_AND_EOL;
            if (CUR == ']')
                break;
            tmp = virConfParseValue(ctxt);
            if (tmp == NULL) {
                virConfFreeList(lst);
                return NULL;
            }
            prev = lst;
            while (prev->next != NULL) prev = prev->next;
            prev->next = tmp;
            SKIP_BLANKS_AND_EOL;
        }
        if (CUR == ']') {
            NEXT;
        } else {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX,
                         _("list is not closed with ]"));
            virConfFreeList(lst);
            return NULL;
        }
    } else if (c_isdigit(CUR) || (CUR == '-') || (CUR == '+')) {
        if (ctxt->conf->flags & VIR_CONF_FLAG_VMX_FORMAT) {
            virConfError(ctxt, VIR_ERR_CONF_SYNTAX,
                         _("numbers not allowed in VMX format"));
            return NULL;
        }
        type = (CUR == '-') ? VIR_CONF_LLONG : VIR_CONF_ULLONG;
        if (virConfParseLong(ctxt, &l) < 0)
            return NULL;
    } else {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("expecting a value"));
        return NULL;
    }
    if (VIR_ALLOC(ret) < 0) {
        virConfFreeList(lst);
        VIR_FREE(str);
        return NULL;
    }
    ret->type = type;
    ret->l = l;
    ret->str = str;
    ret->list = lst;
    return ret;
}

/**
 * virConfParseName:
 * @ctxt: the parsing context
 *
 * Parse one name
 *
 * Returns a copy of the new string, NULL in case of error
 */
static char *
virConfParseName(virConfParserCtxtPtr ctxt)
{
    const char *base;
    char *ret;

    SKIP_BLANKS;
    base = ctxt->cur;
    /* TODO: probably need encoding support and UTF-8 parsing ! */
    if (!c_isalpha(CUR) &&
        !((ctxt->conf->flags & VIR_CONF_FLAG_VMX_FORMAT) && (CUR == '.'))) {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("expecting a name"));
        return NULL;
    }
    while ((ctxt->cur < ctxt->end) &&
           (c_isalnum(CUR) || (CUR == '_') ||
            ((ctxt->conf->flags & VIR_CONF_FLAG_VMX_FORMAT) &&
             ((CUR == ':') || (CUR == '.') || (CUR == '-'))) ||
            ((ctxt->conf->flags & VIR_CONF_FLAG_LXC_FORMAT) &&
             (CUR == '.'))))
        NEXT;
    if (VIR_STRNDUP(ret, base, ctxt->cur - base) < 0)
        return NULL;
    return ret;
}

/**
 * virConfParseComment:
 * @ctxt: the parsing context
 *
 * Parse one standalone comment in the configuration file
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virConfParseComment(virConfParserCtxtPtr ctxt)
{
    const char *base;
    char *comm;

    if (CUR != '#')
        return -1;
    NEXT;
    base = ctxt->cur;
    while ((ctxt->cur < ctxt->end) && (!IS_EOL(CUR))) NEXT;
    if (VIR_STRNDUP(comm, base, ctxt->cur - base) < 0)
        return -1;
    if (virConfAddEntry(ctxt->conf, NULL, NULL, comm) == NULL) {
        VIR_FREE(comm);
        return -1;
    }
    return 0;
}

/**
 * virConfParseSeparator:
 * @ctxt: the parsing context
 *
 * Parse one separator between statement if not at the end.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virConfParseSeparator(virConfParserCtxtPtr ctxt)
{
    SKIP_BLANKS;
    if (ctxt->cur >= ctxt->end)
        return 0;
    if (IS_EOL(CUR)) {
        SKIP_BLANKS_AND_EOL;
    } else if (CUR == ';') {
        NEXT;
        SKIP_BLANKS_AND_EOL;
    } else {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("expecting a separator"));
        return -1;
    }
    return 0;
}

/**
 * virConfParseStatement:
 * @ctxt: the parsing context
 *
 * Parse one statement in the conf file
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
virConfParseStatement(virConfParserCtxtPtr ctxt)
{
    const char *base;
    char *name;
    virConfValuePtr value;
    char *comm = NULL;

    SKIP_BLANKS_AND_EOL;
    if (CUR == '#')
        return virConfParseComment(ctxt);
    name = virConfParseName(ctxt);
    if (name == NULL)
        return -1;
    SKIP_BLANKS;
    if (CUR != '=') {
        virConfError(ctxt, VIR_ERR_CONF_SYNTAX, _("expecting an assignment"));
        VIR_FREE(name);
        return -1;
    }
    NEXT;
    SKIP_BLANKS;
    value = virConfParseValue(ctxt);
    if (value == NULL) {
        VIR_FREE(name);
        return -1;
    }
    SKIP_BLANKS;
    if (CUR == '#') {
        NEXT;
        base = ctxt->cur;
        while ((ctxt->cur < ctxt->end) && (!IS_EOL(CUR))) NEXT;
        if (VIR_STRNDUP(comm, base, ctxt->cur - base) < 0) {
            VIR_FREE(name);
            virConfFreeValue(value);
            return -1;
        }
    }
    if (virConfAddEntry(ctxt->conf, name, value, comm) == NULL) {
        VIR_FREE(name);
        virConfFreeValue(value);
        VIR_FREE(comm);
        return -1;
    }
    return 0;
}

/**
 * virConfParse:
 * @filename: the name to report errors
 * @content: the configuration content in memory
 * @len: the length in bytes
 * @flags: combination of virConfFlag(s)
 *
 * Parse the subset of the Python language needed to handle simple
 * Xen configuration files.
 *
 * Returns a handle to lookup settings or NULL if it failed to
 *         read or parse the file, use virConfFree() to free the data.
 */
static virConfPtr
virConfParse(const char *filename, const char *content, int len,
             unsigned int flags)
{
    virConfParserCtxt ctxt;

    ctxt.filename = filename;
    ctxt.base = ctxt.cur = content;
    ctxt.end = content + len - 1;
    ctxt.line = 1;

    ctxt.conf = virConfCreate(filename, flags);
    if (ctxt.conf == NULL)
        return NULL;

    while (ctxt.cur < ctxt.end) {
        if (virConfParseStatement(&ctxt) < 0)
            goto error;
        if (virConfParseSeparator(&ctxt) < 0)
            goto error;
    }

    return ctxt.conf;

 error:
    virConfFree(ctxt.conf);
    return NULL;
}

/************************************************************************
 *									*
 *			The module entry points				*
 *									*
 ************************************************************************/

/* 10 MB limit on config file size as a sanity check */
#define MAX_CONFIG_FILE_SIZE (1024*1024*10)

/**
 * virConfReadFile:
 * @filename: the path to the configuration file.
 * @flags: combination of virConfFlag(s)
 *
 * Reads a configuration file.
 *
 * Returns a handle to lookup settings or NULL if it failed to
 *         read or parse the file, use virConfFree() to free the data.
 */
virConfPtr
virConfReadFile(const char *filename, unsigned int flags)
{
    char *content;
    int len;
    virConfPtr conf = NULL;

    VIR_DEBUG("filename=%s", NULLSTR(filename));

    if (filename == NULL) {
        virConfError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }

    if ((len = virFileReadAll(filename, MAX_CONFIG_FILE_SIZE, &content)) < 0)
        return NULL;

    if (len && len < MAX_CONFIG_FILE_SIZE && content[len - 1] != '\n') {
        VIR_DEBUG("appending newline to busted config file %s", filename);
        if (VIR_REALLOC_N(content, len + 2) < 0)
            goto cleanup;
        content[len++] = '\n';
        content[len] = '\0';
    }

    conf = virConfParse(filename, content, len, flags);

 cleanup:
    VIR_FREE(content);

    return conf;
}

/**
 * virConfReadMem:
 * @memory: pointer to the content of the configuration file
 * @len: length in byte
 * @flags: combination of virConfFlag(s)
 *
 * Reads a configuration file loaded in memory. The string can be
 * zero terminated in which case @len can be 0
 *
 * Returns a handle to lookup settings or NULL if it failed to
 *         parse the content, use virConfFree() to free the data.
 */
virConfPtr
virConfReadMem(const char *memory, int len, unsigned int flags)
{
    if ((memory == NULL) || (len < 0)) {
        virConfError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }
    if (len == 0)
        len = strlen(memory);

    return virConfParse("memory conf", memory, len, flags);
}

/**
 * virConfFree:
 * @conf: a configuration file handle
 *
 * Frees all data associated to the handle
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
virConfFree(virConfPtr conf)
{
    virConfEntryPtr tmp;
    if (conf == NULL)
        return 0;

    tmp = conf->entries;
    while (tmp) {
        virConfEntryPtr next;
        VIR_FREE(tmp->name);
        virConfFreeValue(tmp->value);
        VIR_FREE(tmp->comment);
        next = tmp->next;
        VIR_FREE(tmp);
        tmp = next;
    }
    VIR_FREE(conf->filename);
    VIR_FREE(conf);
    return 0;
}

/**
 * virConfGetValue:
 * @conf: a configuration file handle
 * @setting: the name of the entry
 *
 * Lookup the value associated to this entry in the configuration file
 *
 * Returns a pointer to the value or NULL if the lookup failed, the data
 *         associated will be freed when virConfFree() is called
 */
virConfValuePtr
virConfGetValue(virConfPtr conf, const char *setting)
{
    virConfEntryPtr cur;

    if (conf == NULL)
        return NULL;

    cur = conf->entries;
    while (cur != NULL) {
        if ((cur->name != NULL) &&
            ((conf->flags & VIR_CONF_FLAG_VMX_FORMAT &&
              STRCASEEQ(cur->name, setting)) ||
             STREQ(cur->name, setting)))
            return cur->value;
        cur = cur->next;
    }
    return NULL;
}


/**
 * virConfGetValueType:
 * @conf: the config object
 * @setting: the config entry name
 *
 * Query the type of the configuration entry @setting.
 *
 * Returns: the entry type, or VIR_CONF_NONE if not set.
 */
virConfType virConfGetValueType(virConfPtr conf,
                                const char *setting)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);
    if (!cval)
        return VIR_CONF_NONE;

    return cval->type;
}


/**
 * virConfGetValueString:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold string value
 *
 * Get the string value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type.
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueString(virConfPtr conf,
                          const char *setting,
                          char **value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value string %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_STRING) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected a string for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    VIR_FREE(*value);
    if (VIR_STRDUP(*value, cval->str) < 0)
        return -1;

    return 1;
}


/**
 * virConfGetValueStringList:
 * @conf: the config object
 * @setting: the config entry name
 * @compatString: true to treat string entry as a 1 element list
 * @value: pointer to hold NULL terminated string list
 *
 * Get the string list value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified. If @compatString is set to true
 * and the value is present as a string, this will be turned into
 * a 1 element list. The returned @value will be NULL terminated
 * if set.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type.
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueStringList(virConfPtr conf,
                              const char *setting,
                              bool compatString,
                              char ***values)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);
    size_t len;
    virConfValuePtr eval;

    VIR_DEBUG("Get value string list %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    virStringListFree(*values);
    *values = NULL;

    switch (cval->type) {
    case VIR_CONF_LIST:
        /* Calc length and check items */
        for (len = 0, eval = cval->list; eval; len++, eval = eval->next) {
            if (eval->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("%s: expected a string list for '%s' parameter"),
                               conf->filename, setting);
                return -1;
            }
        }

        if (VIR_ALLOC_N(*values, len + 1) < 0)
            return -1;

        for (len = 0, eval = cval->list; eval; len++, eval = eval->next) {
            if (VIR_STRDUP((*values)[len], eval->str) < 0) {
                virStringListFree(*values);
                *values = NULL;
                return -1;
            }
        }
        break;

    case VIR_CONF_STRING:
        if (compatString) {
            if (VIR_ALLOC_N(*values, cval->str ? 2 : 1) < 0)
                return -1;
            if (cval->str &&
                VIR_STRDUP((*values)[0], cval->str) < 0) {
                VIR_FREE(*values);
                return -1;
            }
            break;
        }
        /* fallthrough */

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       compatString ?
                       _("%s: expected a string or string list for '%s' parameter") :
                       _("%s: expected a string list for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    return 1;
}


/**
 * virConfGetValueBool:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold boolean value
 *
 * Get the boolean value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value set is not 1 or 0.
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueBool(virConfPtr conf,
                        const char *setting,
                        bool *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value bool %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_ULLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected a bool for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    if (((unsigned long long)cval->l) > 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: value for '%s' parameter must be 0 or 1"),
                       conf->filename, setting);
        return -1;
    }

    *value = cval->l == 1;

    return 1;
}


/**
 * virConfGetValueInt:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value is outside the
 * range that can be stored in an 'int'
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueInt(virConfPtr conf,
                       const char *setting,
                       int *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value int %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_LLONG &&
        cval->type != VIR_CONF_ULLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected a signed integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    if (cval->l > INT_MAX || cval->l < INT_MIN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: value for '%s' parameter must be in range %d:%d"),
                       conf->filename, setting, INT_MIN, INT_MAX);
        return -1;
    }

    *value = (int)cval->l;

    return 1;
}


/**
 * virConfGetValueUInt:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the unsigned integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value is outside the
 * range that can be stored in an 'unsigned int'
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueUInt(virConfPtr conf,
                        const char *setting,
                        unsigned int *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value uint %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_ULLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected an unsigned integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    if (((unsigned long long)cval->l) > UINT_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: value for '%s' parameter must be in range 0:%u"),
                       conf->filename, setting, UINT_MAX);
        return -1;
    }

    *value = (unsigned int)cval->l;

    return 1;
}


/**
 * virConfGetValueSizeT:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value is outside the
 * range that can be stored in a 'size_t'
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueSizeT(virConfPtr conf,
                         const char *setting,
                         size_t *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value size_t %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_ULLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected an unsigned integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

#if ULLONG_MAX > SIZE_MAX
    if (((unsigned long long)cval->l) > SIZE_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: value for '%s' parameter must be in range 0:%zu"),
                       conf->filename, setting, SIZE_MAX);
        return -1;
    }
#endif

    *value = (size_t)cval->l;

    return 1;
}


/**
 * virConfGetValueSSizeT:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value is outside the
 * range that can be stored in an 'ssize_t'
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueSSizeT(virConfPtr conf,
                          const char *setting,
                          ssize_t *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value ssize_t %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type == VIR_CONF_ULLONG) {
        if (((unsigned long long)cval->l) > SSIZE_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: value for '%s' parameter must be in range %zd:%zd"),
                           conf->filename, setting, (ssize_t)-SSIZE_MAX - 1, (ssize_t)SSIZE_MAX);
            return -1;
        }
    } else if (cval->type == VIR_CONF_LLONG) {
#if SSIZE_MAX < LLONG_MAX
        if (cval->l < (-SSIZE_MAX - 1) || cval->l > SSIZE_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: value for '%s' parameter must be in range %zd:%zd"),
                           conf->filename, setting, (ssize_t)-SSIZE_MAX - 1, (ssize_t)SSIZE_MAX);
            return -1;
        }
#endif
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected a signed integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    *value = (ssize_t)cval->l;

    return 1;
}


/**
 * virConfGetValueLLong:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type, or if the value is outside the
 * range that can be stored in an 'long long'
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueLLong(virConfPtr conf,
                         const char *setting,
                         long long *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value long long %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type == VIR_CONF_ULLONG) {
        if (((unsigned long long)cval->l) > LLONG_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: value for '%s' parameter must be in range %lld:%lld"),
                           conf->filename, setting, LLONG_MIN, LLONG_MAX);
            return -1;
        }
    } else if (cval->type != VIR_CONF_LLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected a signed integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    *value = cval->l;

    return 1;
}


/**
 * virConfGetValueULLong:
 * @conf: the config object
 * @setting: the config entry name
 * @value: pointer to hold integer value
 *
 * Get the integer value of the config name @setting, storing
 * it in @value. If the config entry is not present, then
 * @value will be unmodified.
 *
 * Reports an error if the config entry is set but has
 * an unexpected type.
 *
 * Returns: 1 if the value was present, 0 if missing, -1 on error
 */
int virConfGetValueULLong(virConfPtr conf,
                          const char *setting,
                          unsigned long long *value)
{
    virConfValuePtr cval = virConfGetValue(conf, setting);

    VIR_DEBUG("Get value unsigned long long %p %d",
              cval, cval ? cval->type : VIR_CONF_NONE);

    if (!cval)
        return 0;

    if (cval->type != VIR_CONF_ULLONG) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: expected an unsigned integer for '%s' parameter"),
                       conf->filename, setting);
        return -1;
    }

    *value = (unsigned long long)cval->l;

    return 1;
}

/**
 * virConfSetValue:
 * @conf: a configuration file handle
 * @setting: the name of the entry
 * @value: the new configuration value
 *
 * Set (or replace) the value associated to this entry in the configuration
 * file. The passed in 'value' will be owned by the conf object upon return
 * of this method, even in case of error. It should not be referenced again
 * by the caller.
 *
 * Returns 0 on success, or -1 on failure.
 */
int
virConfSetValue(virConfPtr conf,
                const char *setting,
                virConfValuePtr value)
{
    virConfEntryPtr cur, prev = NULL;

    if (value && value->type == VIR_CONF_STRING && value->str == NULL) {
        virConfFreeValue(value);
        return -1;
    }

    cur = conf->entries;
    while (cur != NULL) {
        if (STREQ_NULLABLE(cur->name, setting))
            break;
        prev = cur;
        cur = cur->next;
    }

    if (!cur) {
        if (VIR_ALLOC(cur) < 0) {
            virConfFreeValue(value);
            return -1;
        }
        cur->comment = NULL;
        if (VIR_STRDUP(cur->name, setting) < 0) {
            virConfFreeValue(value);
            VIR_FREE(cur);
            return -1;
        }
        cur->value = value;
        if (prev) {
            cur->next = prev->next;
            prev->next = cur;
        } else {
            cur->next = conf->entries;
            conf->entries = cur;
        }
    } else {
        virConfFreeValue(cur->value);
        cur->value = value;
    }
    return 0;
}

/**
 * virConfWalk:
 * @conf: a configuration file handle
 * @callback: the function to call to process each entry
 * @opaque: obscure data passed to callback
 *
 * Walk over all entries of the configuration file and run the callback
 * for each with entry name, value and the obscure data.
 *
 * Returns 0 on success, or -1 on failure.
 */
int virConfWalk(virConfPtr conf,
                virConfWalkCallback callback,
                void *opaque)
{
    virConfEntryPtr cur;

    if (!conf)
        return 0;

    cur = conf->entries;
    while (cur != NULL) {
        if (cur->name && cur->value &&
                callback(cur->name, cur->value, opaque) < 0)
            return -1;
        cur = cur->next;
    }
    return 0;
}

/**
 * virConfWriteFile:
 * @filename: the path to the configuration file.
 * @conf: the conf
 *
 * Writes a configuration file back to a file.
 *
 * Returns the number of bytes written or -1 in case of error.
 */
int
virConfWriteFile(const char *filename, virConfPtr conf)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfEntryPtr cur;
    int ret;
    int fd;
    char *content;
    unsigned int use;

    if (conf == NULL)
        return -1;

    cur = conf->entries;
    while (cur != NULL) {
        virConfSaveEntry(&buf, cur);
        cur = cur->next;
    }

    if (virBufferCheckError(&buf) < 0)
        return -1;

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        virBufferFreeAndReset(&buf);
        virConfError(NULL, VIR_ERR_WRITE_FAILED, _("failed to open file"));
        return -1;
    }

    use = virBufferUse(&buf);
    content = virBufferContentAndReset(&buf);
    ret = safewrite(fd, content, use);
    VIR_FREE(content);
    VIR_FORCE_CLOSE(fd);
    if (ret != (int)use) {
        virConfError(NULL, VIR_ERR_WRITE_FAILED, _("failed to save content"));
        return -1;
    }

    return ret;
}

/**
 * virConfWriteMem:
 * @memory: pointer to the memory to store the config file
 * @len: pointer to the length in bytes of the store, on output the size
 * @conf: the conf
 *
 * Writes a configuration file back to a memory area. @len is an IN/OUT
 * parameter, it indicates the size available in bytes, and on output the
 * size required for the configuration file (even if the call fails due to
 * insufficient space).
 *
 * Returns the number of bytes written or -1 in case of error.
 */
int
virConfWriteMem(char *memory, int *len, virConfPtr conf)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfEntryPtr cur;
    char *content;
    unsigned int use;

    if ((memory == NULL) || (len == NULL) || (*len <= 0) || (conf == NULL))
        return -1;

    cur = conf->entries;
    while (cur != NULL) {
        virConfSaveEntry(&buf, cur);
        cur = cur->next;
    }

    if (virBufferCheckError(&buf) < 0)
        return -1;

    use = virBufferUse(&buf);
    content = virBufferContentAndReset(&buf);

    if ((int)use >= *len) {
        *len = (int)use;
        VIR_FREE(content);
        return -1;
    }
    memcpy(memory, content, use);
    VIR_FREE(content);
    *len = use;
    return use;
}

static char *
virConfLoadConfigPath(const char *name)
{
    char *path;
    if (geteuid() == 0) {
        if (virAsprintf(&path, "%s/libvirt/%s",
                        SYSCONFDIR, name) < 0)
            return NULL;
    } else {
        char *userdir = virGetUserConfigDirectory();
        if (!userdir)
            return NULL;

        if (virAsprintf(&path, "%s/%s",
                        userdir, name) < 0) {
            VIR_FREE(userdir);
            return NULL;
        }
        VIR_FREE(userdir);
    }

    return path;
}

int
virConfLoadConfig(virConfPtr *conf, const char *name)
{
    char *path = NULL;
    int ret = -1;

    *conf = NULL;

    if (!(path = virConfLoadConfigPath(name)))
        goto cleanup;

    if (!virFileExists(path)) {
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Loading config file '%s'", path);
    if (!(*conf = virConfReadFile(path, 0)))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(path);
    return ret;
}
