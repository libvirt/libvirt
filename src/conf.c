/**
 * conf.c: parser for a subset of the Python encoded Xen configuration files
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
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

#include "internal.h"
#include "buf.h"
#include "conf.h"
#include "util.h"

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
#define IS_BLANK(c) (((c) == ' ') || ((c) == '\n') || ((c) == '\r') ||	\
                     ((c) == '\t'))
#define SKIP_BLANKS {while ((ctxt->cur < ctxt->end) && (IS_BLANK(CUR))){\
			   if (CUR == '\n') ctxt->line++;		\
			   ctxt->cur++;}}
#define IS_SPACE(c) (((c) == ' ') || ((c) == '\t'))
#define SKIP_SPACES {while ((ctxt->cur < ctxt->end) && (IS_SPACE(CUR)))	\
			   ctxt->cur++;}
#define IS_CHAR(c) ((((c) >= 'a') && ((c) <= 'z')) ||			\
                    (((c) >= 'A') && ((c) <= 'Z')))
#define IS_DIGIT(c) (((c) >= '0') && ((c) <= '9'))

/************************************************************************
 *									*
 *		Structures used by configuration data			*
 *									*
 ************************************************************************/

typedef struct _virConfEntry virConfEntry;
typedef virConfEntry *virConfEntryPtr;

struct _virConfEntry {
    virConfEntryPtr next;
    char* name;
    char* comment;
    virConfValuePtr value;
};

struct _virConf {
    const char* filename;
    virConfEntryPtr entries;
};

/**
 * virConfError:
 * @conf: the configuration if available
 * @error: the error number
 * @info: extra information string
 * @line: line for the error
 *
 * Handle an error at the xend daemon interface
 */
static void
virConfError(virConfPtr conf ATTRIBUTE_UNUSED,
             virErrorNumber error, const char *info, int line)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, NULL, VIR_FROM_CONF, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, line, 0, errmsg, info, line);
}


/************************************************************************
 *									*
 *		Structures allocations and deallocations		*
 *									*
 ************************************************************************/
static void virConfFreeValue(virConfValuePtr val);

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
static void
virConfFreeValue(virConfValuePtr val)
{
    if (val == NULL)
        return;
    if (val->type == VIR_CONF_STRING &&
        val->str != NULL)
        free(val->str);
    if (val->type == VIR_CONF_LIST &&
        val->list != NULL)
        virConfFreeList(val->list);
    free(val);
}

virConfPtr
__virConfNew(void)
{
    virConfPtr ret;

    ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"), 0);
        return(NULL);
    }
    ret->filename = NULL;

    return(ret);
}

/**
 * virConfCreate:
 * @filename: the name to report errors
 *
 * Create a configuration internal structure
 *
 * Returns a pointer or NULL in case of error.
 */
static virConfPtr
virConfCreate(const char *filename)
{
    virConfPtr ret = virConfNew();
    if (ret)
        ret->filename = filename;
    return(ret);
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
        return(NULL);
    if ((comm == NULL) && (name == NULL))
        return(NULL);

    ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"), 0);
        return(NULL);
    }

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
    return(ret);
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
        return(-1);
    switch (val->type) {
        case VIR_CONF_NONE:
	    return(-1);
	case VIR_CONF_LONG:
	    virBufferVSprintf(buf, "%ld", val->l);
	    break;
	case VIR_CONF_STRING:
	    if (strchr(val->str, '\n') != NULL) {
		virBufferVSprintf(buf, "\"\"\"%s\"\"\"", val->str);
	    } else if (strchr(val->str, '"') == NULL) {
		virBufferVSprintf(buf, "\"%s\"", val->str);
	    } else if (strchr(val->str, '\'') == NULL) {
		virBufferVSprintf(buf, "'%s'", val->str);
	    } else {
		virBufferVSprintf(buf, "\"\"\"%s\"\"\"", val->str);
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
	    return(-1);
    }
    return(0);
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
    return(0);
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
virConfParseLong(virConfParserCtxtPtr ctxt, long *val)
{
    long l = 0;
    int neg = 0;

    if (CUR == '-') {
        neg = 1;
	NEXT;
    } else if (CUR == '+') {
        NEXT;
    }
    if ((ctxt->cur >= ctxt->end) || (!IS_DIGIT(CUR))) {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("unterminated number"),
		     ctxt->line);
	return(-1);
    }
    while ((ctxt->cur < ctxt->end) && (IS_DIGIT(CUR))) {
        l = l * 10 + (CUR - '0');
	NEXT;
    }
    if (neg)
        l = -l;
    *val = l;
    return(0);
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
	    virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("unterminated string"),
			 ctxt->line);
	    return(NULL);
	}
	ret = strndup(base, ctxt->cur - base);
	NEXT;
    } else if ((ctxt->cur + 6 < ctxt->end) && (ctxt->cur[0] == '"') &&
               (ctxt->cur[1] == '"') && (ctxt->cur[2] == '"')) {
	ctxt->cur += 3;
	base = ctxt->cur;
	while ((ctxt->cur + 2 < ctxt->end) && (ctxt->cur[0] == '"') &&
	       (ctxt->cur[1] == '"') && (ctxt->cur[2] == '"')) {
	       if (CUR == '\n') ctxt->line++;
	       NEXT;
	}
	if ((ctxt->cur[0] != '"') || (ctxt->cur[1] != '"') ||
	    (ctxt->cur[2] != '"')) {
	    virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("unterminated string"),
			 ctxt->line);
	    return(NULL);
	}
	ret = strndup(base, ctxt->cur - base);
	ctxt->cur += 3;
    } else if (CUR == '"') {
        NEXT;
	base = ctxt->cur;
	while ((ctxt->cur < ctxt->end) && (CUR != '"') && (!IS_EOL(CUR)))
	    NEXT;
	if (CUR != '"') {
	    virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("unterminated string"),
			 ctxt->line);
	    return(NULL);
	}
	ret = strndup(base, ctxt->cur - base);
	NEXT;
    }
    return(ret);
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
    long  l = 0;

    SKIP_SPACES;
    if (ctxt->cur >= ctxt->end) {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("expecting a value"),
	             ctxt->line);
	return(NULL);
    }
    if ((CUR == '"') || (CUR == '\'')) {
        type = VIR_CONF_STRING;
        str = virConfParseString(ctxt);
	if (str == NULL)
	    return(NULL);
    } else if (CUR == '[') {
        type = VIR_CONF_LIST;
        NEXT;
	SKIP_BLANKS;
	if ((ctxt->cur < ctxt->end) && (CUR != ']')) {
	    lst = virConfParseValue(ctxt);
	    SKIP_BLANKS;
	}
	while ((ctxt->cur < ctxt->end) && (CUR != ']')) {
	    if (CUR != ',') {
		virConfError(NULL, VIR_ERR_CONF_SYNTAX,
		             _("expecting a separator in list"), ctxt->line);
	        virConfFreeList(lst);
		return(NULL);
	    }
	    NEXT;
	    SKIP_BLANKS;
	    if (CUR == ']') {
	        break;
	    }
	    tmp = virConfParseValue(ctxt);
	    if (tmp == NULL) {
	        virConfFreeList(lst);
		return(NULL);
	    }
	    prev = lst;
	    while (prev->next != NULL) prev = prev->next;
	    prev->next = tmp;
	    SKIP_BLANKS;
	}
	if (CUR == ']') {
	    NEXT;
	} else {
	    virConfError(NULL, VIR_ERR_CONF_SYNTAX,
			 _("list is not closed with ]"), ctxt->line);
	    virConfFreeList(lst);
	    return(NULL);
	}
    } else if (IS_DIGIT(CUR) || (CUR == '-') || (CUR == '+')) {
        if (virConfParseLong(ctxt, &l) < 0) {
	    return(NULL);
	}
        type = VIR_CONF_LONG;
    } else {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("expecting a value"),
	             ctxt->line);
	return(NULL);
    }
    ret = calloc(1, sizeof(*ret));
    if (ret == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"), 0);
	    free(str);
        return(NULL);
    }
    ret->type = type;
    ret->l = l;
    ret->str = str;
    ret->list = lst;
    return(ret);
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

    SKIP_SPACES;
    base = ctxt->cur;
    /* TODO: probably need encoding support and UTF-8 parsing ! */
    if (!IS_CHAR(CUR)) {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("expecting a name"), ctxt->line);
	return(NULL);
    }
    while ((ctxt->cur < ctxt->end) && ((IS_CHAR(CUR)) || (IS_DIGIT(CUR)) || (CUR == '_')))
        NEXT;
    ret = strndup(base, ctxt->cur - base);
    if (ret == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"),
	             ctxt->line);
        return(NULL);
    }
    return(ret);
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
        return(-1);
    NEXT;
    base = ctxt->cur;
    while ((ctxt->cur < ctxt->end) && (!IS_EOL(CUR))) NEXT;
    comm = strndup(base, ctxt->cur - base);
    if (comm == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"),
	             ctxt->line);
        return(-1);
    }
    virConfAddEntry(ctxt->conf, NULL, NULL, comm);
    return(0);
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
    SKIP_SPACES;
    if (ctxt->cur >= ctxt->end)
	return(0);
    if (IS_EOL(CUR)) {
	SKIP_BLANKS
    } else if (CUR == ';') {
	NEXT;
	SKIP_BLANKS;
    } else {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("expecting a separator"),
		     ctxt->line);
	return(-1);
    }
    return(0);
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

    SKIP_BLANKS;
    if (CUR == '#') {
        return(virConfParseComment(ctxt));
    }
    name = virConfParseName(ctxt);
    if (name == NULL)
        return(-1);
    SKIP_SPACES;
    if (CUR != '=') {
        virConfError(NULL, VIR_ERR_CONF_SYNTAX, _("expecting an assignment"),
	             ctxt->line);
        return(-1);
    }
    NEXT;
    SKIP_SPACES;
    value = virConfParseValue(ctxt);
    if (value == NULL) {
        free(name);
	return(-1);
    }
    SKIP_SPACES;
    if (CUR == '#') {
	NEXT;
	base = ctxt->cur;
	while ((ctxt->cur < ctxt->end) && (!IS_EOL(CUR))) NEXT;
	comm = strndup(base, ctxt->cur - base);
	if (comm == NULL) {
	    virConfError(NULL, VIR_ERR_NO_MEMORY, _("allocating configuration"),
	                 ctxt->line);
	    free(name);
	    virConfFreeValue(value);
	    return(-1);
	}
    }
    if (virConfAddEntry(ctxt->conf, name, value, comm) == NULL) {
        free(name);
	virConfFreeValue(value);
    free(comm);
	return(-1);
    }
    return(0);
}

/**
 * virConfParse:
 * @filename: the name to report errors
 * @content: the configuration content in memory
 * @len: the length in bytes
 *
 * Parse the subset of the Python language needed to handle simple
 * Xen configuration files.
 *
 * Returns an handle to lookup settings or NULL if it failed to
 *         read or parse the file, use virConfFree() to free the data.
 */
static virConfPtr
virConfParse(const char *filename, const char *content, int len) {
    virConfParserCtxt ctxt;

    ctxt.filename = filename;
    ctxt.base = ctxt.cur = content;
    ctxt.end = content + len - 1;
    ctxt.line = 1;

    ctxt.conf = virConfCreate(filename);
    if (ctxt.conf == NULL)
        return(NULL);

    while (ctxt.cur < ctxt.end) {
        if (virConfParseStatement(&ctxt) < 0)
	    goto error;
	if (virConfParseSeparator(&ctxt) < 0)
	    goto error;
    }

    return(ctxt.conf);

error:
    virConfFree(ctxt.conf);
    return(NULL);
}

/************************************************************************
 *									*
 *			The module entry points				*
 *									*
 ************************************************************************/

/* 10 MB limit on config file size as a sanity check */
#define MAX_CONFIG_FILE_SIZE (1024*1024*10)

/**
 * __virConfReadFile:
 * @filename: the path to the configuration file.
 *
 * Reads a configuration file.
 *
 * Returns an handle to lookup settings or NULL if it failed to
 *         read or parse the file, use virConfFree() to free the data.
 */
virConfPtr
__virConfReadFile(const char *filename)
{
    char *content;
    int len;
    virConfPtr conf;

    if (filename == NULL) {
        virConfError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__, 0);
        return(NULL);
    }

    if ((len = virFileReadAll(filename, MAX_CONFIG_FILE_SIZE, &content)) < 0) {
        virConfError(NULL, VIR_ERR_OPEN_FAILED, filename, 0);
        return NULL;
    }

    conf = virConfParse(filename, content, len);

    free(content);

    return conf;
}

/**
 * __virConfReadMem:
 * @memory: pointer to the content of the configuration file
 * @len: length in byte
 *
 * Reads a configuration file loaded in memory. The string can be
 * zero terminated in which case @len can be 0
 *
 * Returns an handle to lookup settings or NULL if it failed to
 *         parse the content, use virConfFree() to free the data.
 */
virConfPtr
__virConfReadMem(const char *memory, int len)
{
    if ((memory == NULL) || (len < 0)) {
        virConfError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__, 0);
        return(NULL);
    }
    if (len == 0)
        len = strlen(memory);

    return(virConfParse("memory conf", memory, len));
}

/**
 * __virConfFree:
 * @conf: a configuration file handle
 *
 * Frees all data associated to the handle
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
__virConfFree(virConfPtr conf)
{
    virConfEntryPtr tmp;
    if (conf == NULL) {
        virConfError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__, 0);
        return(-1);
    }

    tmp = conf->entries;
    while (tmp) {
        virConfEntryPtr next;
        free(tmp->name);
        virConfFreeValue(tmp->value);
        free(tmp->comment);
        next = tmp->next;
        free(tmp);
        tmp = next;
    }
    free(conf);
    return(0);
}

/**
 * __virConfGetValue:
 * @conf: a configuration file handle
 * @entry: the name of the entry
 *
 * Lookup the value associated to this entry in the configuration file
 *
 * Returns a pointer to the value or NULL if the lookup failed, the data
 *         associated will be freed when virConfFree() is called
 */
virConfValuePtr
__virConfGetValue(virConfPtr conf, const char *setting)
{
    virConfEntryPtr cur;

    cur = conf->entries;
    while (cur != NULL) {
        if ((cur->name != NULL) && (!strcmp(cur->name, setting)))
	    return(cur->value);
        cur = cur->next;
    }
    return(NULL);
}

/**
 * __virConfSetValue:
 * @conf: a configuration file handle
 * @entry: the name of the entry
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
__virConfSetValue (virConfPtr conf,
                  const char *setting,
                  virConfValuePtr value)
{
    virConfEntryPtr cur, prev = NULL;

    cur = conf->entries;
    while (cur != NULL) {
        if ((cur->name != NULL) && (!strcmp(cur->name, setting))) {
            break;
        }
        prev = cur;
        cur = cur->next;
    }

    if (!cur) {
        if (!(cur = malloc(sizeof(*cur)))) {
            virConfFreeValue(value);
            return (-1);
        }
        cur->comment = NULL;
        if (!(cur->name = strdup(setting))) {
            virConfFreeValue(value);
            free(cur);
            return (-1);
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
        if (cur->value) {
            virConfFreeValue(cur->value);
        }
        cur->value = value;
    }
    return (0);
}


/**
 * __virConfWriteFile:
 * @filename: the path to the configuration file.
 * @conf: the conf
 *
 * Writes a configuration file back to a file.
 *
 * Returns the number of bytes written or -1 in case of error.
 */
int
__virConfWriteFile(const char *filename, virConfPtr conf)
{
    virBufferPtr buf;
    virConfEntryPtr cur;
    int ret;
    int fd;

    if (conf == NULL)
        return(-1);

    buf = virBufferNew(500);
    if (buf == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("failed to allocate buffer"), 0);
        return(-1);
    }

    cur = conf->entries;
    while (cur != NULL) {
        virConfSaveEntry(buf, cur);
	cur = cur->next;
    }

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR );
    if (fd < 0) {
        virConfError(NULL, VIR_ERR_WRITE_FAILED, _("failed to open file"), 0);
        ret = -1;
	goto error;
    }

    ret = safewrite(fd, buf->content, buf->use);
    close(fd);
    if (ret != (int) buf->use) {
        virConfError(NULL, VIR_ERR_WRITE_FAILED, _("failed to save content"), 0);
        ret = -1;
	goto error;
    }
error:
    virBufferFree(buf);
    return(ret);
}

/**
 * __virConfWriteMem:
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
__virConfWriteMem(char *memory, int *len, virConfPtr conf)
{
    virBufferPtr buf;
    virConfEntryPtr cur;
    int ret;

    if ((memory == NULL) || (len == NULL) || (*len <= 0) || (conf == NULL))
        return(-1);

    buf = virBufferNew(500);
    if (buf == NULL) {
        virConfError(NULL, VIR_ERR_NO_MEMORY, _("failed to allocate buffer"), 0);
        return(-1);
    }

    cur = conf->entries;
    while (cur != NULL) {
        virConfSaveEntry(buf, cur);
        cur = cur->next;
    }

    if ((int) buf->use >= *len) {
        *len = buf->use;
        ret = -1;
        goto error;
    }
    memcpy(memory, buf->content, buf->use);
    ret = buf->use;
    *len = buf->use;
error:
    virBufferFree(buf);
    return(ret);
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
