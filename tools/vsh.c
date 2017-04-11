/*
 * vsh.c: common data to be used by clients to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2015 Red Hat, Inc.
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
 * Karel Zak <kzak@redhat.com>
 * Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "vsh.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include "c-ctype.h"
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <signal.h>

#if WITH_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "virerror.h"
#include "virbuffer.h"
#include "viralloc.h"
#include <libvirt/libvirt-qemu.h>
#include <libvirt/libvirt-lxc.h>
#include "virfile.h"
#include "virthread.h"
#include "vircommand.h"
#include "conf/domain_conf.h"
#include "virtypedparam.h"
#include "virstring.h"

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#ifdef WITH_READLINE
/* For autocompletion */
void *autoCompleteOpaque;
#endif

/* NOTE: It would be much nicer to have these two as part of vshControl
 * structure, unfortunately readline doesn't support passing opaque data
 * and only relies on static data accessible from the user-side callback
 */
const vshCmdGrp *cmdGroups;
const vshCmdDef *cmdSet;


/* simple handler for oom conditions */
static void
vshErrorOOM(void)
{
    fflush(stdout);
    fputs(_("error: Out of memory\n"), stderr);
    fflush(stderr);
    exit(EXIT_FAILURE);
}


double
vshPrettyCapacity(unsigned long long val, const char **unit)
{
    double limit = 1024;

    if (val < limit) {
        *unit = "B";
        return val;
    }
    limit *= 1024;
    if (val < limit) {
        *unit = "KiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val < limit) {
        *unit = "MiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val < limit) {
        *unit = "GiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val < limit) {
        *unit = "TiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    if (val < limit) {
        *unit = "PiB";
        return val / (limit / 1024);
    }
    limit *= 1024;
    *unit = "EiB";
    return val / (limit / 1024);
}


void *
_vshMalloc(vshControl *ctl, size_t size, const char *filename, int line)
{
    char *x;

    if (VIR_ALLOC_N(x, size) == 0)
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) size);
    exit(EXIT_FAILURE);
}

void *
_vshCalloc(vshControl *ctl, size_t nmemb, size_t size, const char *filename,
           int line)
{
    char *x;

    if (!xalloc_oversized(nmemb, size) &&
        VIR_ALLOC_N(x, nmemb * size) == 0)
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) (size*nmemb));
    exit(EXIT_FAILURE);
}

char *
_vshStrdup(vshControl *ctl, const char *s, const char *filename, int line)
{
    char *x;

    if (VIR_STRDUP(x, s) >= 0)
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %lu bytes"),
             filename, line, (unsigned long)strlen(s));
    exit(EXIT_FAILURE);
}

int
vshNameSorter(const void *a, const void *b)
{
    const char **sa = (const char**)a;
    const char **sb = (const char**)b;

    return vshStrcasecmp(*sa, *sb);
}


/*
 * Convert the strings separated by ',' into array. The returned
 * array is a NULL terminated string list. The caller has to free
 * the array using virStringListFree or a similar method.
 *
 * Returns the length of the filled array on success, or -1
 * on error.
 */
int
vshStringToArray(const char *str,
                 char ***array)
{
    char *str_copied = vshStrdup(NULL, str);
    char *str_tok = NULL;
    char *tmp;
    unsigned int nstr_tokens = 0;
    char **arr = NULL;
    size_t len = strlen(str_copied);

    /* tokenize the string from user and save its parts into an array */
    nstr_tokens = 1;

    /* count the delimiters, recognizing ,, as an escape for a
     * literal comma */
    str_tok = str_copied;
    while ((str_tok = strchr(str_tok, ','))) {
        if (str_tok[1] == ',')
            str_tok++;
        else
            nstr_tokens++;
        str_tok++;
    }

    /* reserve the NULL element at the end */
    if (VIR_ALLOC_N(arr, nstr_tokens + 1) < 0) {
        VIR_FREE(str_copied);
        return -1;
    }

    /* tokenize the input string, while treating ,, as a literal comma */
    nstr_tokens = 0;
    tmp = str_tok = str_copied;
    while ((tmp = strchr(tmp, ','))) {
        if (tmp[1] == ',') {
            memmove(&tmp[1], &tmp[2], len - (tmp - str_copied) - 2 + 1);
            len--;
            tmp++;
            continue;
        }
        *tmp++ = '\0';
        arr[nstr_tokens++] = vshStrdup(NULL, str_tok);
        str_tok = tmp;
    }
    arr[nstr_tokens++] = vshStrdup(NULL, str_tok);

    *array = arr;
    VIR_FREE(str_copied);
    return nstr_tokens;
}

virErrorPtr last_error;

/*
 * Quieten libvirt until we're done with the command.
 */
void
vshErrorHandler(void *opaque ATTRIBUTE_UNUSED,
                virErrorPtr error ATTRIBUTE_UNUSED)
{
    virFreeError(last_error);
    last_error = virSaveLastError();
}

/* Store a libvirt error that is from a helper API that doesn't raise errors
 * so it doesn't get overwritten */
void
vshSaveLibvirtError(void)
{
    virFreeError(last_error);
    last_error = virSaveLastError();
}


/* Store libvirt error from helper API but don't overwrite existing errors */
void
vshSaveLibvirtHelperError(void)
{
    if (last_error)
        return;

    if (!virGetLastError())
        return;

    vshSaveLibvirtError();
}


/*
 * Reset libvirt error on graceful fallback paths
 */
void
vshResetLibvirtError(void)
{
    virFreeError(last_error);
    last_error = NULL;
}

/*
 * Report an error when a command finishes.  This is better than before
 * (when correct operation would report errors), but it has some
 * problems: we lose the smarter formatting of virDefaultErrorFunc(),
 * and it can become harder to debug problems, if errors get reported
 * twice during one command.  This case shouldn't really happen anyway,
 * and it's IMHO a bug that libvirt does that sometimes.
 */
void
vshReportError(vshControl *ctl)
{
    if (last_error == NULL) {
        /* Calling directly into libvirt util functions won't trigger the
         * error callback (which sets last_error), so check it ourselves.
         *
         * If the returned error has CODE_OK, this most likely means that
         * no error was ever raised, so just ignore */
        last_error = virSaveLastError();
        if (!last_error || last_error->code == VIR_ERR_OK)
            goto out;
    }

    if (last_error->code == VIR_ERR_OK) {
        vshError(ctl, "%s", _("unknown error"));
        goto out;
    }

    vshError(ctl, "%s", last_error->message);

 out:
    vshResetLibvirtError();
}

/*
 * Detection of disconnections and automatic reconnection support
 */
static int disconnected; /* we may have been disconnected */

/* ---------------
 * Utils for work with command definition
 * ---------------
 */
const char *
vshCmddefGetInfo(const vshCmdDef * cmd, const char *name)
{
    const vshCmdInfo *info;

    for (info = cmd->info; info && info->name; info++) {
        if (STREQ(info->name, name))
            return info->data;
    }
    return NULL;
}

/* Check if the internal command definitions are correct */
static int
vshCmddefCheckInternals(const vshCmdDef *cmd)
{
    size_t i;
    const char *help = NULL;

    /* in order to perform the validation resolve the alias first */
    if (cmd->flags & VSH_CMD_FLAG_ALIAS) {
        if (!cmd->alias)
            return -1;
        cmd = vshCmddefSearch(cmd->alias);
    }

    /* Each command has to provide a non-empty help string. */
    if (!(help = vshCmddefGetInfo(cmd, "help")) || !*help)
        return -1;

    if (!cmd->opts)
        return 0;

    for (i = 0; cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (i > 63)
            return -1; /* too many options */
        if (opt->type == VSH_OT_BOOL) {
            if (opt->flags & VSH_OFLAG_REQ)
                return -1; /* bool options can't be mandatory */
            continue;
        }
        if (opt->type == VSH_OT_ALIAS) {
            size_t j;
            char *name = (char *)opt->help; /* cast away const */
            char *p;

            if (opt->flags || !opt->help)
                return -1; /* alias options are tracked by the original name */
            if ((p = strchr(name, '=')) &&
                VIR_STRNDUP(name, name, p - name) < 0)
                return -1;
            for (j = i + 1; cmd->opts[j].name; j++) {
                if (STREQ(name, cmd->opts[j].name) &&
                    cmd->opts[j].type != VSH_OT_ALIAS)
                    break;
            }
            if (name != opt->help) {
                VIR_FREE(name);
                /* If alias comes with value, replacement must not be bool */
                if (cmd->opts[j].type == VSH_OT_BOOL)
                    return -1;
            }
            if (!cmd->opts[j].name)
                return -1; /* alias option must map to a later option name */
            continue;
        }
        if (opt->type == VSH_OT_ARGV && cmd->opts[i + 1].name)
            return -1; /* argv option must be listed last */
    }
    return 0;
}

/* Parse the options associated with @cmd, i.e. test whether options are
 * required or need an argument.
 *
 * Returns -1 on error or 0 on success, filling the caller-provided bitmaps
 * which keep track of required options and options needing an argument.
 */
static int
vshCmddefOptParse(const vshCmdDef *cmd, uint64_t *opts_need_arg,
                  uint64_t *opts_required)
{
    size_t i;
    bool optional = false;

    *opts_need_arg = 0;
    *opts_required = 0;

    if (!cmd->opts)
        return 0;

    for (i = 0; cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (opt->type == VSH_OT_BOOL) {
            optional = true;
            continue;
        }

        if (opt->flags & VSH_OFLAG_REQ_OPT) {
            if (opt->flags & VSH_OFLAG_REQ)
                *opts_required |= 1ULL << i;
            else
                optional = true;
            continue;
        }

        if (opt->type == VSH_OT_ALIAS)
            continue; /* skip the alias option */

        *opts_need_arg |= 1ULL << i;
        if (opt->flags & VSH_OFLAG_REQ) {
            if (optional && opt->type != VSH_OT_ARGV)
                return -1; /* mandatory options must be listed first */
            *opts_required |= 1ULL << i;
        } else {
            optional = true;
        }
    }

    return 0;
}

static vshCmdOptDef helpopt = {
    .name = "help",
    .type = VSH_OT_BOOL,
    .help = N_("print help for this function")
};
static const vshCmdOptDef *
vshCmddefGetOption(vshControl *ctl, const vshCmdDef *cmd, const char *name,
                   uint64_t *opts_seen, size_t *opt_index, char **optstr,
                   bool report)
{
    size_t i;
    const vshCmdOptDef *ret = NULL;
    char *alias = NULL;

    if (STREQ(name, helpopt.name))
        return &helpopt;

    for (i = 0; cmd->opts && cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (STREQ(opt->name, name)) {
            if (opt->type == VSH_OT_ALIAS) {
                char *value;

                /* Two types of replacements:
                   opt->help = "string": straight replacement of name
                   opt->help = "string=value": treat boolean flag as
                   alias of option and its default value */
                sa_assert(!alias);
                if (VIR_STRDUP(alias, opt->help) < 0)
                    goto cleanup;
                name = alias;
                if ((value = strchr(name, '='))) {
                    *value = '\0';
                    if (*optstr) {
                        if (report)
                            vshError(ctl, _("invalid '=' after option --%s"),
                                     opt->name);
                        goto cleanup;
                    }
                    if (VIR_STRDUP(*optstr, value + 1) < 0)
                        goto cleanup;
                }
                continue;
            }
            if ((*opts_seen & (1ULL << i)) && opt->type != VSH_OT_ARGV) {
                if (report)
                    vshError(ctl, _("option --%s already seen"), name);
                goto cleanup;
            }
            *opts_seen |= 1ULL << i;
            *opt_index = i;
            ret = opt;
            goto cleanup;
        }
    }

    if (STRNEQ(cmd->name, "help") && report) {
        vshError(ctl, _("command '%s' doesn't support option --%s"),
                 cmd->name, name);
    }
 cleanup:
    VIR_FREE(alias);
    return ret;
}

static const vshCmdOptDef *
vshCmddefGetData(const vshCmdDef *cmd, uint64_t *opts_need_arg,
                 uint64_t *opts_seen)
{
    size_t i;
    const vshCmdOptDef *opt;

    if (!*opts_need_arg)
        return NULL;

    /* Grab least-significant set bit */
    i = ffsl(*opts_need_arg) - 1;
    opt = &cmd->opts[i];
    if (opt->type != VSH_OT_ARGV)
        *opts_need_arg &= ~(1ULL << i);
    *opts_seen |= 1ULL << i;
    return opt;
}

/*
 * Checks for required options
 */
static int
vshCommandCheckOpts(vshControl *ctl, const vshCmd *cmd, uint64_t opts_required,
                    uint64_t opts_seen)
{
    const vshCmdDef *def = cmd->def;
    size_t i;

    opts_required &= ~opts_seen;
    if (!opts_required)
        return 0;

    for (i = 0; def->opts[i].name; i++) {
        if (opts_required & (1ULL << i)) {
            const vshCmdOptDef *opt = &def->opts[i];

            vshError(ctl,
                     opt->type == VSH_OT_DATA || opt->type == VSH_OT_ARGV ?
                     _("command '%s' requires <%s> option") :
                     _("command '%s' requires --%s option"),
                     def->name, opt->name);
        }
    }
    return -1;
}

static const vshCmdDef *
vshCmdDefSearchGrp(const char *cmdname)
{
    const vshCmdGrp *g;
    const vshCmdDef *c;

    for (g = cmdGroups; g->name; g++) {
        for (c = g->commands; c->name; c++) {
            if (STREQ(c->name, cmdname))
                return c;
        }
    }

    return NULL;
}

static const vshCmdDef *
vshCmdDefSearchSet(const char *cmdname)
{
    const vshCmdDef *s;

    for (s = cmdSet; s->name; s++) {
        if (STREQ(s->name, cmdname))
            return s;
        }

    return NULL;
}

const vshCmdDef *
vshCmddefSearch(const char *cmdname)
{
    if (cmdGroups)
        return vshCmdDefSearchGrp(cmdname);
    else
        return vshCmdDefSearchSet(cmdname);
}

const vshCmdGrp *
vshCmdGrpSearch(const char *grpname)
{
    const vshCmdGrp *g;

    for (g = cmdGroups; g->name; g++) {
        if (STREQ(g->name, grpname) || STREQ(g->keyword, grpname))
            return g;
    }

    return NULL;
}

bool
vshCmdGrpHelp(vshControl *ctl, const char *grpname)
{
    const vshCmdGrp *grp = vshCmdGrpSearch(grpname);
    const vshCmdDef *cmd = NULL;

    if (!grp) {
        vshError(ctl, _("command group '%s' doesn't exist"), grpname);
        return false;
    } else {
        vshPrint(ctl, _(" %s (help keyword '%s'):\n"), grp->name,
                 grp->keyword);

        for (cmd = grp->commands; cmd->name; cmd++) {
            if (cmd->flags & VSH_CMD_FLAG_ALIAS)
                continue;
            vshPrint(ctl, "    %-30s %s\n", cmd->name,
                     _(vshCmddefGetInfo(cmd, "help")));
        }
    }

    return true;
}

bool
vshCmddefHelp(vshControl *ctl, const char *cmdname)
{
    const vshCmdDef *def = vshCmddefSearch(cmdname);
    const char *desc = NULL;
    char buf[256];
    uint64_t opts_need_arg;
    uint64_t opts_required;
    bool shortopt = false; /* true if 'arg' works instead of '--opt arg' */

    if (!def) {
        vshError(ctl, _("command '%s' doesn't exist"), cmdname);
        return false;
    }

    if (vshCmddefOptParse(def, &opts_need_arg, &opts_required)) {
        vshError(ctl, _("internal error: bad options in command: '%s'"),
                 def->name);
        return false;
    }

    fputs(_("  NAME\n"), stdout);
    fprintf(stdout, "    %s - %s\n", def->name,
            _(vshCmddefGetInfo(def, "help")));

    fputs(_("\n  SYNOPSIS\n"), stdout);
    fprintf(stdout, "    %s", def->name);
    if (def->opts) {
        const vshCmdOptDef *opt;
        for (opt = def->opts; opt->name; opt++) {
            const char *fmt = "%s";
            switch (opt->type) {
            case VSH_OT_BOOL:
                fmt = "[--%s]";
                break;
            case VSH_OT_INT:
                /* xgettext:c-format */
                fmt = ((opt->flags & VSH_OFLAG_REQ) ? "<%s>"
                       : _("[--%s <number>]"));
                if (!(opt->flags & VSH_OFLAG_REQ_OPT))
                    shortopt = true;
                break;
            case VSH_OT_STRING:
                /* xgettext:c-format */
                fmt = _("[--%s <string>]");
                if (!(opt->flags & VSH_OFLAG_REQ_OPT))
                    shortopt = true;
                break;
            case VSH_OT_DATA:
                fmt = ((opt->flags & VSH_OFLAG_REQ) ? "<%s>" : "[<%s>]");
                if (!(opt->flags & VSH_OFLAG_REQ_OPT))
                    shortopt = true;
                break;
            case VSH_OT_ARGV:
                /* xgettext:c-format */
                if (shortopt) {
                    fmt = (opt->flags & VSH_OFLAG_REQ)
                        ? _("{[--%s] <string>}...")
                        : _("[[--%s] <string>]...");
                } else {
                    fmt = (opt->flags & VSH_OFLAG_REQ) ? _("<%s>...")
                        : _("[<%s>]...");
                }
                break;
            case VSH_OT_ALIAS:
                /* aliases are intentionally undocumented */
                continue;
            }
            fputc(' ', stdout);
            fprintf(stdout, fmt, opt->name);
        }
    }
    fputc('\n', stdout);

    desc = vshCmddefGetInfo(def, "desc");
    if (*desc) {
        /* Print the description only if it's not empty.  */
        fputs(_("\n  DESCRIPTION\n"), stdout);
        fprintf(stdout, "    %s\n", _(desc));
    }

    if (def->opts && def->opts->name) {
        const vshCmdOptDef *opt;
        fputs(_("\n  OPTIONS\n"), stdout);
        for (opt = def->opts; opt->name; opt++) {
            switch (opt->type) {
            case VSH_OT_BOOL:
                snprintf(buf, sizeof(buf), "--%s", opt->name);
                break;
            case VSH_OT_INT:
                snprintf(buf, sizeof(buf),
                         (opt->flags & VSH_OFLAG_REQ) ? _("[--%s] <number>")
                         : _("--%s <number>"), opt->name);
                break;
            case VSH_OT_STRING:
                /* OT_STRING should never be VSH_OFLAG_REQ */
                if (opt->flags & VSH_OFLAG_REQ) {
                    vshError(ctl,
                             _("internal error: bad options in command: '%s'"),
                             def->name);
                    return false;
                }
                snprintf(buf, sizeof(buf), _("--%s <string>"), opt->name);
                break;
            case VSH_OT_DATA:
                /* OT_DATA should always be VSH_OFLAG_REQ */
                if (!(opt->flags & VSH_OFLAG_REQ)) {
                    vshError(ctl,
                             _("internal error: bad options in command: '%s'"),
                             def->name);
                    return false;
                }
                snprintf(buf, sizeof(buf), _("[--%s] <string>"),
                         opt->name);
                break;
            case VSH_OT_ARGV:
                snprintf(buf, sizeof(buf),
                         shortopt ? _("[--%s] <string>") : _("<%s>"),
                         opt->name);
                break;
            case VSH_OT_ALIAS:
                continue;
            }

            fprintf(stdout, "    %-15s  %s\n", buf, _(opt->help));
        }
    }
    fputc('\n', stdout);

    return true;
}

/* ---------------
 * Utils for work with runtime commands data
 * ---------------
 */
static void
vshCommandOptFree(vshCmdOpt * arg)
{
    vshCmdOpt *a = arg;

    while (a) {
        vshCmdOpt *tmp = a;

        a = a->next;

        VIR_FREE(tmp->data);
        VIR_FREE(tmp);
    }
}

static void
vshCommandFree(vshCmd *cmd)
{
    vshCmd *c = cmd;

    while (c) {
        vshCmd *tmp = c;

        c = c->next;

        if (tmp->opts)
            vshCommandOptFree(tmp->opts);
        VIR_FREE(tmp);
    }
}

/**
 * vshCommandOpt:
 * @cmd: parsed command line to search
 * @name: option name to search for
 * @opt: result of the search
 * @needData: true if option must be non-boolean
 *
 * Look up an option passed to CMD by NAME.  Returns 1 with *OPT set
 * to the option if found, 0 with *OPT set to NULL if the name is
 * valid and the option is not required, -1 with *OPT set to NULL if
 * the option is required but not present, and assert if NAME is not
 * valid (which indicates a programming error).  No error messages are
 * issued if a value is returned.
 */
static int
vshCommandOpt(const vshCmd *cmd, const char *name, vshCmdOpt **opt,
              bool needData)
{
    vshCmdOpt *candidate = cmd->opts;
    const vshCmdOptDef *valid = cmd->def->opts;
    int ret = 0;

    /* See if option is valid and/or required.  */
    *opt = NULL;
    while (valid) {
        assert(valid->name);
        if (STREQ(name, valid->name))
            break;
        valid++;
    }
    assert(!needData || valid->type != VSH_OT_BOOL);
    if (valid->flags & VSH_OFLAG_REQ)
        ret = -1;

    /* See if option is present on command line.  */
    while (candidate) {
        if (STREQ(candidate->def->name, name)) {
            *opt = candidate;
            ret = 1;
            break;
        }
        candidate = candidate->next;
    }
    return ret;
}

/**
 * vshCommandOptInt:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to int.
 * On error, a message is displayed.
 *
 * Return value:
 * >0 if option found and valid (@value updated)
 * 0 if option not found and not required (@value untouched)
 * <0 in all other cases (@value untouched)
 */
int
vshCommandOptInt(vshControl *ctl, const vshCmd *cmd,
                 const char *name, int *value)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if ((ret = virStrToLong_i(arg->data, NULL, 10, value)) < 0)
        vshError(ctl,
                 _("Numeric value '%s' for <%s> option is malformed or out of range"),
                 arg->data, name);
    else
        ret = 1;

    return ret;
}

static int
vshCommandOptUIntInternal(vshControl *ctl,
                          const vshCmd *cmd,
                          const char *name,
                          unsigned int *value,
                          bool wrap)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if (wrap)
        ret = virStrToLong_ui(arg->data, NULL, 10, value);
    else
        ret = virStrToLong_uip(arg->data, NULL, 10, value);
    if (ret < 0)
        vshError(ctl,
                 _("Numeric value '%s' for <%s> option is malformed or out of range"),
                 arg->data, name);
    else
        ret = 1;

    return ret;
}

/**
 * vshCommandOptUInt:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned int, reject negative numbers
 * See vshCommandOptInt()
 */
int
vshCommandOptUInt(vshControl *ctl, const vshCmd *cmd,
                  const char *name, unsigned int *value)
{
    return vshCommandOptUIntInternal(ctl, cmd, name, value, false);
}

/**
 * vshCommandOptUIntWrap:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned int, wraps negative numbers to positive
 * See vshCommandOptInt()
 */
int
vshCommandOptUIntWrap(vshControl *ctl, const vshCmd *cmd,
                      const char *name, unsigned int *value)
{
    return vshCommandOptUIntInternal(ctl, cmd, name, value, true);
}

static int
vshCommandOptULInternal(vshControl *ctl,
                        const vshCmd *cmd,
                        const char *name,
                        unsigned long *value,
                        bool wrap)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if (wrap)
        ret = virStrToLong_ul(arg->data, NULL, 10, value);
    else
        ret = virStrToLong_ulp(arg->data, NULL, 10, value);
    if (ret < 0)
        vshError(ctl,
                 _("Numeric value '%s' for <%s> option is malformed or out of range"),
                 arg->data, name);
    else
        ret = 1;

    return ret;
}

/*
 * vshCommandOptUL:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned long
 * See vshCommandOptInt()
 */
int
vshCommandOptUL(vshControl *ctl, const vshCmd *cmd,
                const char *name, unsigned long *value)
{
    return vshCommandOptULInternal(ctl, cmd, name, value, false);
}

/**
 * vshCommandOptULWrap:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned long, wraps negative numbers to positive
 * See vshCommandOptInt()
 */
int
vshCommandOptULWrap(vshControl *ctl, const vshCmd *cmd,
                    const char *name, unsigned long *value)
{
    return vshCommandOptULInternal(ctl, cmd, name, value, true);
}

/**
 * vshCommandOptStringQuiet:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as STRING. On error -1 is returned but no error is set.
 * Return value:
 * >0 if option found and valid (@value updated)
 * 0 if option not found and not required (@value untouched)
 * <0 in all other cases (@value untouched)
 */
int
vshCommandOptStringQuiet(vshControl *ctl ATTRIBUTE_UNUSED, const vshCmd *cmd,
                         const char *name, const char **value)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if (!*arg->data && !(arg->def->flags & VSH_OFLAG_EMPTY_OK))
        return -1;
    *value = arg->data;
    return 1;
}

/**
 * vshCommandOptStringReq:
 * @ctl virtshell control structure
 * @cmd command structure
 * @name option name
 * @value result (updated to NULL or the option argument)
 *
 * Gets a option argument as string.
 *
 * Returns 0 on success or when the option is not present and not
 * required, *value is set to the option argument. On error -1 is
 * returned and error message printed.
 */
int
vshCommandOptStringReq(vshControl *ctl,
                       const vshCmd *cmd,
                       const char *name,
                       const char **value)
{
    vshCmdOpt *arg;
    int ret;
    const char *error = NULL;

    /* clear out the value */
    *value = NULL;

    ret = vshCommandOpt(cmd, name, &arg, true);
    /* option is not required and not present */
    if (ret == 0)
        return 0;
    /* this should not be propagated here, just to be sure */
    if (ret == -1)
        error = N_("Mandatory option not present");
    else if (!*arg->data && !(arg->def->flags & VSH_OFLAG_EMPTY_OK))
        error = N_("Option argument is empty");

    if (error) {
        vshError(ctl, _("Failed to get option '%s': %s"), name, _(error));
        return -1;
    }

    *value = arg->data;
    return 0;
}

/**
 * vshCommandOptLongLong:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as long long
 * See vshCommandOptInt()
 */
int
vshCommandOptLongLong(vshControl *ctl, const vshCmd *cmd,
                      const char *name, long long *value)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if ((ret = virStrToLong_ll(arg->data, NULL, 10, value)) < 0)
        vshError(ctl,
                 _("Numeric value '%s' for <%s> option is malformed or out of range"),
                 arg->data, name);
    else
        ret = 1;

    return ret;
}

static int
vshCommandOptULongLongInternal(vshControl *ctl,
                               const vshCmd *cmd,
                               const char *name,
                               unsigned long long *value,
                               bool wrap)
{
    vshCmdOpt *arg;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if (wrap)
        ret = virStrToLong_ull(arg->data, NULL, 10, value);
    else
        ret = virStrToLong_ullp(arg->data, NULL, 10, value);
    if (ret < 0)
        vshError(ctl,
                 _("Numeric value '%s' for <%s> option is malformed or out of range"),
                 arg->data, name);
    else
        ret = 1;

    return ret;
}

/**
 * vshCommandOptULongLong:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as long long, rejects negative numbers
 * See vshCommandOptInt()
 */
int
vshCommandOptULongLong(vshControl *ctl, const vshCmd *cmd,
                       const char *name, unsigned long long *value)
{
    return vshCommandOptULongLongInternal(ctl, cmd, name, value, false);
}

/**
 * vshCommandOptULongLongWrap:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as long long, wraps negative numbers to positive
 * See vshCommandOptInt()
 */
int
vshCommandOptULongLongWrap(vshControl *ctl, const vshCmd *cmd,
                           const char *name, unsigned long long *value)
{
    return vshCommandOptULongLongInternal(ctl, cmd, name, value, true);
}

/**
 * vshCommandOptScaledInt:
 * @ctl virtshell control structure
 * @cmd command reference
 * @name option name
 * @value result
 * @scale default of 1 or 1024, if no suffix is present
 * @max maximum value permitted
 *
 * Returns option as long long, scaled according to suffix
 * See vshCommandOptInt()
 */
int
vshCommandOptScaledInt(vshControl *ctl, const vshCmd *cmd,
                       const char *name, unsigned long long *value,
                       int scale, unsigned long long max)
{
    vshCmdOpt *arg;
    char *end;
    int ret;

    if ((ret = vshCommandOpt(cmd, name, &arg, true)) <= 0)
        return ret;

    if (virStrToLong_ullp(arg->data, &end, 10, value) < 0 ||
        virScaleInteger(value, end, scale, max) < 0) {
        vshError(ctl,
                 _("Scaled numeric value '%s' for <%s> option is malformed or "
                   "out of range"), arg->data, name);
        return -1;
    }

    return 1;
}


/**
 * vshCommandOptBool:
 * @cmd command reference
 * @name option name
 *
 * Returns true/false if the option exists.  Note that this does NOT
 * validate whether the option is actually boolean, or even whether
 * name is legal; so that this can be used to probe whether a data
 * option is present without actually using that data.
 */
bool
vshCommandOptBool(const vshCmd *cmd, const char *name)
{
    vshCmdOpt *dummy;

    return vshCommandOpt(cmd, name, &dummy, false) == 1;
}

/**
 * vshCommandOptArgv:
 * @ctl virtshell control structure
 * @cmd command reference
 * @opt starting point for the search
 *
 * Returns the next argv argument after OPT (or the first one if OPT
 * is NULL), or NULL if no more are present.
 *
 * Requires that a VSH_OT_ARGV option be last in the
 * list of supported options in CMD->def->opts.
 */
const vshCmdOpt *
vshCommandOptArgv(vshControl *ctl ATTRIBUTE_UNUSED, const vshCmd *cmd,
                  const vshCmdOpt *opt)
{
    opt = opt ? opt->next : cmd->opts;

    while (opt) {
        if (opt->def->type == VSH_OT_ARGV)
            return opt;
        opt = opt->next;
    }
    return NULL;
}


/**
 * vshBlockJobOptionBandwidth:
 * @ctl: virsh control data
 * @cmd: virsh command description
 * @bytes: return bandwidth in bytes/s instead of MiB/s
 * @bandwidth: return value
 *
 * Extracts the value of --bandwidth either as a wrap-able number without scale
 * or as a scaled integer. The returned value is checked to fit into a unsigned
 * long data type. This is a legacy compatibility function and it should not
 * be used for things other the block job APIs.
 *
 * Returns 0 on success, -1 on error.
 */
int
vshBlockJobOptionBandwidth(vshControl *ctl,
                           const vshCmd *cmd,
                           bool bytes,
                           unsigned long *bandwidth)
{
    vshCmdOpt *arg;
    char *end;
    unsigned long long bw;
    int ret;

    if ((ret = vshCommandOpt(cmd, "bandwidth", &arg, true)) <= 0)
        return ret;

    /* due to historical reasons we declare to parse negative numbers and wrap
     * them to the unsigned data type. */
    if (virStrToLong_ul(arg->data, NULL, 10, bandwidth) < 0) {
        /* try to parse the number as scaled size in this case we don't accept
         * wrapping since it would be ridiculous. In case of a 32 bit host,
         * limit the value to ULONG_MAX */
        if (virStrToLong_ullp(arg->data, &end, 10, &bw) < 0 ||
            virScaleInteger(&bw, end, 1, ULONG_MAX) < 0) {
            vshError(ctl,
                     _("Scaled numeric value '%s' for <--bandwidth> option is "
                       "malformed or out of range"), arg->data);
            return -1;
        }

        if (!bytes)
            bw >>= 20;

        *bandwidth = bw;
    }

    return 0;
}


/*
 * Executes command(s) and returns return code from last command
 */
bool
vshCommandRun(vshControl *ctl, const vshCmd *cmd)
{
    const vshClientHooks *hooks = ctl->hooks;
    bool ret = true;

    while (cmd) {
        struct timeval before, after;
        bool enable_timing = ctl->timing;

        if (enable_timing)
            GETTIMEOFDAY(&before);

        if ((cmd->def->flags & VSH_CMD_FLAG_NOCONNECT) ||
            (hooks && hooks->connHandler && hooks->connHandler(ctl))) {
            ret = cmd->def->handler(ctl, cmd);
        } else {
            /* connection is not usable, return error */
            ret = false;
        }

        if (enable_timing)
            GETTIMEOFDAY(&after);

        /* try to automatically catch disconnections */
        if (!ret &&
            ((last_error != NULL) &&
             (((last_error->code == VIR_ERR_SYSTEM_ERROR) &&
               (last_error->domain == VIR_FROM_REMOTE)) ||
              (last_error->code == VIR_ERR_RPC) ||
              (last_error->code == VIR_ERR_NO_CONNECT) ||
              (last_error->code == VIR_ERR_INVALID_CONN))))
            disconnected++;

        if (!ret)
            vshReportError(ctl);

        if (STREQ(cmd->def->name, "quit") ||
            STREQ(cmd->def->name, "exit"))        /* hack ... */
            return ret;

        if (enable_timing) {
            double diff_ms = (((after.tv_sec - before.tv_sec) * 1000.0) +
                              ((after.tv_usec - before.tv_usec) / 1000.0));

            vshPrint(ctl, _("\n(Time: %.3f ms)\n\n"), diff_ms);
        } else {
            vshPrintExtra(ctl, "\n");
        }
        cmd = cmd->next;
    }
    return ret;
}

/* ---------------
 * Command parsing
 * ---------------
 */

typedef enum {
    VSH_TK_ERROR, /* Failed to parse a token */
    VSH_TK_ARG, /* Arbitrary argument, might be option or empty */
    VSH_TK_SUBCMD_END, /* Separation between commands */
    VSH_TK_END /* No more commands */
} vshCommandToken;

typedef struct _vshCommandParser vshCommandParser;
struct _vshCommandParser {
    vshCommandToken(*getNextArg)(vshControl *, vshCommandParser *,
                                 char **, bool);
    /* vshCommandStringGetArg() */
    char *pos;
    /* vshCommandArgvGetArg() */
    char **arg_pos;
    char **arg_end;
};

static bool
vshCommandParse(vshControl *ctl, vshCommandParser *parser)
{
    char *tkdata = NULL;
    vshCmd *clast = NULL;
    vshCmdOpt *first = NULL;

    if (ctl->cmd) {
        vshCommandFree(ctl->cmd);
        ctl->cmd = NULL;
    }

    while (1) {
        vshCmdOpt *last = NULL;
        const vshCmdDef *cmd = NULL;
        vshCommandToken tk;
        bool data_only = false;
        uint64_t opts_need_arg = 0;
        uint64_t opts_required = 0;
        uint64_t opts_seen = 0;

        first = NULL;

        while (1) {
            const vshCmdOptDef *opt = NULL;

            tkdata = NULL;
            tk = parser->getNextArg(ctl, parser, &tkdata, true);

            if (tk == VSH_TK_ERROR)
                goto syntaxError;
            if (tk != VSH_TK_ARG) {
                VIR_FREE(tkdata);
                break;
            }

            if (cmd == NULL) {
                /* first token must be command name */
                if (!(cmd = vshCmddefSearch(tkdata))) {
                    vshError(ctl, _("unknown command: '%s'"), tkdata);
                    goto syntaxError;   /* ... or ignore this command only? */
                }

                /* aliases need to be resolved to the actual commands */
                if (cmd->flags & VSH_CMD_FLAG_ALIAS) {
                    VIR_FREE(tkdata);
                    tkdata = vshStrdup(ctl, cmd->alias);
                    cmd = vshCmddefSearch(tkdata);
                }
                if (vshCmddefOptParse(cmd, &opts_need_arg,
                                      &opts_required) < 0) {
                    vshError(ctl,
                             _("internal error: bad options in command: '%s'"),
                             tkdata);
                    goto syntaxError;
                }
                VIR_FREE(tkdata);
            } else if (data_only) {
                goto get_data;
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       c_isalnum(tkdata[2])) {
                char *optstr = strchr(tkdata + 2, '=');
                size_t opt_index = 0;

                if (optstr) {
                    *optstr = '\0'; /* convert the '=' to '\0' */
                    optstr = vshStrdup(ctl, optstr + 1);
                }
                /* Special case 'help' to ignore all spurious options */
                if (!(opt = vshCmddefGetOption(ctl, cmd, tkdata + 2,
                                               &opts_seen, &opt_index,
                                               &optstr, true))) {
                    VIR_FREE(optstr);
                    if (STREQ(cmd->name, "help"))
                        continue;
                    goto syntaxError;
                }
                VIR_FREE(tkdata);

                if (opt->type != VSH_OT_BOOL) {
                    /* option data */
                    if (optstr)
                        tkdata = optstr;
                    else
                        tk = parser->getNextArg(ctl, parser, &tkdata, true);
                    if (tk == VSH_TK_ERROR)
                        goto syntaxError;
                    if (tk != VSH_TK_ARG) {
                        vshError(ctl,
                                 _("expected syntax: --%s <%s>"),
                                 opt->name,
                                 opt->type ==
                                 VSH_OT_INT ? _("number") : _("string"));
                        goto syntaxError;
                    }
                    if (opt->type != VSH_OT_ARGV)
                        opts_need_arg &= ~(1ULL << opt_index);
                } else {
                    tkdata = NULL;
                    if (optstr) {
                        vshError(ctl, _("invalid '=' after option --%s"),
                                 opt->name);
                        VIR_FREE(optstr);
                        goto syntaxError;
                    }
                }
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       tkdata[2] == '\0') {
                data_only = true;
                continue;
            } else {
 get_data:
                /* Special case 'help' to ignore spurious data */
                if (!(opt = vshCmddefGetData(cmd, &opts_need_arg,
                                             &opts_seen)) &&
                     STRNEQ(cmd->name, "help")) {
                    vshError(ctl, _("unexpected data '%s'"), tkdata);
                    goto syntaxError;
                }
            }
            if (opt) {
                /* save option */
                vshCmdOpt *arg = vshMalloc(ctl, sizeof(vshCmdOpt));

                arg->def = opt;
                arg->data = tkdata;
                arg->next = NULL;
                tkdata = NULL;

                if (!first)
                    first = arg;
                if (last)
                    last->next = arg;
                last = arg;

                vshDebug(ctl, VSH_ERR_INFO, "%s: %s(%s): %s\n",
                         cmd->name,
                         opt->name,
                         opt->type != VSH_OT_BOOL ? _("optdata") : _("bool"),
                         opt->type != VSH_OT_BOOL ? arg->data : _("(none)"));
            }
        }

        /* command parsed -- allocate new struct for the command */
        if (cmd) {
            vshCmd *c = vshMalloc(ctl, sizeof(vshCmd));
            vshCmdOpt *tmpopt = first;

            /* if we encountered --help, replace parsed command with
             * 'help <cmdname>' */
            for (tmpopt = first; tmpopt; tmpopt = tmpopt->next) {
                const vshCmdDef *help;
                if (STRNEQ(tmpopt->def->name, "help"))
                    continue;

                help = vshCmddefSearch("help");
                vshCommandOptFree(first);
                first = vshMalloc(ctl, sizeof(vshCmdOpt));
                first->def = help->opts;
                first->data = vshStrdup(ctl, cmd->name);
                first->next = NULL;

                cmd = help;
                opts_required = 0;
                opts_seen = 0;
                break;
            }

            c->opts = first;
            c->def = cmd;
            c->next = NULL;

            if (vshCommandCheckOpts(ctl, c, opts_required, opts_seen) < 0) {
                VIR_FREE(c);
                goto syntaxError;
            }

            if (!ctl->cmd)
                ctl->cmd = c;
            if (clast)
                clast->next = c;
            clast = c;
        }

        if (tk == VSH_TK_END)
            break;
    }

    return true;

 syntaxError:
    if (ctl->cmd) {
        vshCommandFree(ctl->cmd);
        ctl->cmd = NULL;
    }
    if (first)
        vshCommandOptFree(first);
    VIR_FREE(tkdata);
    return false;
}

/* --------------------
 * Command argv parsing
 * --------------------
 */

static vshCommandToken ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
vshCommandArgvGetArg(vshControl *ctl, vshCommandParser *parser, char **res,
                     bool report ATTRIBUTE_UNUSED)
{
    if (parser->arg_pos == parser->arg_end) {
        *res = NULL;
        return VSH_TK_END;
    }

    *res = vshStrdup(ctl, *parser->arg_pos);
    parser->arg_pos++;
    return VSH_TK_ARG;
}

bool
vshCommandArgvParse(vshControl *ctl, int nargs, char **argv)
{
    vshCommandParser parser;

    if (nargs <= 0)
        return false;

    parser.arg_pos = argv;
    parser.arg_end = argv + nargs;
    parser.getNextArg = vshCommandArgvGetArg;
    return vshCommandParse(ctl, &parser);
}

/* ----------------------
 * Command string parsing
 * ----------------------
 */

static vshCommandToken ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
vshCommandStringGetArg(vshControl *ctl, vshCommandParser *parser, char **res,
                       bool report)
{
    bool single_quote = false;
    bool double_quote = false;
    int sz = 0;
    char *p = parser->pos;
    char *q = vshStrdup(ctl, p);

    *res = q;

    while (*p && (*p == ' ' || *p == '\t'))
        p++;

    if (*p == '\0')
        return VSH_TK_END;
    if (*p == ';') {
        parser->pos = ++p;             /* = \0 or begin of next command */
        return VSH_TK_SUBCMD_END;
    }

    while (*p) {
        /* end of token is blank space or ';' */
        if (!double_quote && !single_quote &&
            (*p == ' ' || *p == '\t' || *p == ';'))
            break;

        if (!double_quote && *p == '\'') { /* single quote */
            single_quote = !single_quote;
            p++;
            continue;
        } else if (!single_quote && *p == '\\') { /* escape */
            /*
             * The same as the bash, a \ in "" is an escaper,
             * but a \ in '' is not an escaper.
             */
            p++;
            if (*p == '\0') {
                if (report)
                    vshError(ctl, "%s", _("dangling \\"));
                return VSH_TK_ERROR;
            }
        } else if (!single_quote && *p == '"') { /* double quote */
            double_quote = !double_quote;
            p++;
            continue;
        }

        *q++ = *p++;
        sz++;
    }
    if (double_quote) {
        if (report)
            vshError(ctl, "%s", _("missing \""));
        return VSH_TK_ERROR;
    }

    *q = '\0';
    parser->pos = p;
    return VSH_TK_ARG;
}

bool
vshCommandStringParse(vshControl *ctl, char *cmdstr)
{
    vshCommandParser parser;

    if (cmdstr == NULL || *cmdstr == '\0')
        return false;

    parser.pos = cmdstr;
    parser.getNextArg = vshCommandStringGetArg;
    return vshCommandParse(ctl, &parser);
}

/**
 * virshCommandOptTimeoutToMs:
 * @ctl virsh control structure
 * @cmd command reference
 * @timeout result
 *
 * Parse an optional --timeout parameter in seconds, but store the
 * value of the timeout in milliseconds.
 * See vshCommandOptInt()
 */
int
vshCommandOptTimeoutToMs(vshControl *ctl, const vshCmd *cmd, int *timeout)
{
    int ret;
    unsigned int utimeout;

    if ((ret = vshCommandOptUInt(ctl, cmd, "timeout", &utimeout)) <= 0)
        return ret;

    /* Ensure that the timeout is not zero and that we can convert
     * it from seconds to milliseconds without overflowing. */
    if (utimeout == 0 || utimeout > INT_MAX / 1000) {
        vshError(ctl,
                 _("Numeric value '%u' for <%s> option is malformed or out of range"),
                 utimeout,
                 "timeout");
        ret = -1;
    } else {
        *timeout = ((int) utimeout) * 1000;
    }

    return ret;
}


/* ---------------
 * Misc utils
 * ---------------
 */

/* Return a non-NULL string representation of a typed parameter; exit
 * if we are out of memory.  */
char *
vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
{
    int ret = 0;
    char *str = NULL;

    switch (item->type) {
    case VIR_TYPED_PARAM_INT:
        ret = virAsprintf(&str, "%d", item->value.i);
        break;

    case VIR_TYPED_PARAM_UINT:
        ret = virAsprintf(&str, "%u", item->value.ui);
        break;

    case VIR_TYPED_PARAM_LLONG:
        ret = virAsprintf(&str, "%lld", item->value.l);
        break;

    case VIR_TYPED_PARAM_ULLONG:
        ret = virAsprintf(&str, "%llu", item->value.ul);
        break;

    case VIR_TYPED_PARAM_DOUBLE:
        ret = virAsprintf(&str, "%f", item->value.d);
        break;

    case VIR_TYPED_PARAM_BOOLEAN:
        str = vshStrdup(ctl, item->value.b ? _("yes") : _("no"));
        break;

    case VIR_TYPED_PARAM_STRING:
        str = vshStrdup(ctl, item->value.s);
        break;

    default:
        vshError(ctl, _("unimplemented parameter type %d"), item->type);
    }

    if (ret < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        exit(EXIT_FAILURE);
    }
    return str;
}

void
vshDebug(vshControl *ctl, int level, const char *format, ...)
{
    va_list ap;
    char *str;

    /* Aligning log levels to that of libvirt.
     * Traces with levels >=  user-specified-level
     * gets logged into file
     */
    if (level < ctl->debug)
        return;

    va_start(ap, format);
    vshOutputLogFile(ctl, level, format, ap);
    va_end(ap);

    va_start(ap, format);
    if (virVasprintf(&str, format, ap) < 0) {
        /* Skip debug messages on low memory */
        va_end(ap);
        return;
    }
    va_end(ap);
    fputs(str, stdout);
    VIR_FREE(str);
}

void
vshPrintExtra(vshControl *ctl, const char *format, ...)
{
    va_list ap;
    char *str;

    if (ctl && ctl->quiet)
        return;

    va_start(ap, format);
    if (virVasprintfQuiet(&str, format, ap) < 0)
        vshErrorOOM();
    va_end(ap);
    fputs(str, stdout);
    VIR_FREE(str);
}


void
vshPrint(vshControl *ctl ATTRIBUTE_UNUSED, const char *format, ...)
{
    va_list ap;
    char *str;

    va_start(ap, format);
    if (virVasprintfQuiet(&str, format, ap) < 0)
        vshErrorOOM();
    va_end(ap);
    fputs(str, stdout);
    VIR_FREE(str);
}


bool
vshTTYIsInterruptCharacter(vshControl *ctl ATTRIBUTE_UNUSED,
                           const char chr ATTRIBUTE_UNUSED)
{
#ifndef WIN32
    if (ctl->istty &&
        ctl->termattr.c_cc[VINTR] == chr)
        return true;
#endif

    return false;
}


bool
vshTTYAvailable(vshControl *ctl)
{
    return ctl->istty;
}


int
vshTTYDisableInterrupt(vshControl *ctl ATTRIBUTE_UNUSED)
{
#ifndef WIN32
    struct termios termset = ctl->termattr;

    if (!ctl->istty)
        return -1;

    /* check if we need to set the terminal */
    if (termset.c_cc[VINTR] == _POSIX_VDISABLE)
        return 0;

    termset.c_cc[VINTR] = _POSIX_VDISABLE;
    termset.c_lflag &= ~ICANON;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &termset) < 0)
        return -1;
#endif

    return 0;
}


int
vshTTYRestore(vshControl *ctl ATTRIBUTE_UNUSED)
{
#ifndef WIN32
    if (!ctl->istty)
        return 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &ctl->termattr) < 0)
        return -1;
#endif

    return 0;
}


#if !defined(WIN32) && !defined(HAVE_CFMAKERAW)
/* provide fallback in case cfmakeraw isn't available */
static void
cfmakeraw(struct termios *attr)
{
    attr->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                         | INLCR | IGNCR | ICRNL | IXON);
    attr->c_oflag &= ~OPOST;
    attr->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    attr->c_cflag &= ~(CSIZE | PARENB);
    attr->c_cflag |= CS8;
}
#endif /* !WIN32 && !HAVE_CFMAKERAW */


int
vshTTYMakeRaw(vshControl *ctl ATTRIBUTE_UNUSED,
              bool report_errors ATTRIBUTE_UNUSED)
{
#ifndef WIN32
    struct termios rawattr = ctl->termattr;
    char ebuf[1024];

    if (!ctl->istty) {
        if (report_errors) {
            vshError(ctl, "%s",
                     _("unable to make terminal raw: console isn't a tty"));
        }

        return -1;
    }

    cfmakeraw(&rawattr);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawattr) < 0) {
        if (report_errors)
            vshError(ctl, _("unable to set tty attributes: %s"),
                     virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
#endif

    return 0;
}


void
vshError(vshControl *ctl, const char *format, ...)
{
    va_list ap;
    char *str;

    if (ctl != NULL) {
        va_start(ap, format);
        vshOutputLogFile(ctl, VSH_ERR_ERROR, format, ap);
        va_end(ap);
    }

    /* Most output is to stdout, but if someone ran virsh 2>&1, then
     * printing to stderr will not interleave correctly with stdout
     * unless we flush between every transition between streams.  */
    fflush(stdout);
    fputs(_("error: "), stderr);

    va_start(ap, format);
    /* We can't recursively call vshError on an OOM situation, so ignore
       failure here. */
    ignore_value(virVasprintf(&str, format, ap));
    va_end(ap);

    fprintf(stderr, "%s\n", NULLSTR(str));
    fflush(stderr);
    VIR_FREE(str);
}


void
vshEventLoop(void *opaque)
{
    vshControl *ctl = opaque;

    while (1) {
        bool quit;
        virMutexLock(&ctl->lock);
        quit = ctl->quit;
        virMutexUnlock(&ctl->lock);

        if (quit)
            break;

        if (virEventRunDefaultImpl() < 0)
            vshReportError(ctl);
    }
}


/*
 * Helpers for waiting for a libvirt event.
 */

/* We want to use SIGINT to cancel a wait; but as signal handlers
 * don't have an opaque argument, we have to use static storage.  */
static int vshEventFd = -1;
static struct sigaction vshEventOldAction;


/* Signal handler installed in vshEventStart, removed in vshEventCleanup.  */
static void
vshEventInt(int sig ATTRIBUTE_UNUSED,
            siginfo_t *siginfo ATTRIBUTE_UNUSED,
            void *context ATTRIBUTE_UNUSED)
{
    char reason = VSH_EVENT_INTERRUPT;
    if (vshEventFd >= 0)
        ignore_value(safewrite(vshEventFd, &reason, 1));
}


/* Event loop handler used to limit length of waiting for any other event. */
void
vshEventTimeout(int timer ATTRIBUTE_UNUSED,
                void *opaque)
{
    vshControl *ctl = opaque;
    char reason = VSH_EVENT_TIMEOUT;

    if (ctl->eventPipe[1] >= 0)
        ignore_value(safewrite(ctl->eventPipe[1], &reason, 1));
}


/**
 * vshEventStart:
 * @ctl vsh command struct
 * @timeout_ms max wait time in milliseconds, or 0 for indefinite
 *
 * Set up a wait for a libvirt event.  The wait can be canceled by
 * SIGINT or by calling vshEventDone() in your event handler.  If
 * @timeout_ms is positive, the wait will also end if the timeout
 * expires.  Call vshEventWait() to block the main thread (the event
 * handler runs in the event loop thread).  When done (including if
 * there was an error registering for an event), use vshEventCleanup()
 * to quit waiting.  Returns 0 on success, -1 on failure.  */
int
vshEventStart(vshControl *ctl, int timeout_ms)
{
    struct sigaction action;

    assert(ctl->eventPipe[0] == -1 && ctl->eventPipe[1] == -1 &&
           vshEventFd == -1 && ctl->eventTimerId >= 0);
    if (pipe2(ctl->eventPipe, O_CLOEXEC) < 0) {
        char ebuf[1024];

        vshError(ctl, _("failed to create pipe: %s"),
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    vshEventFd = ctl->eventPipe[1];

    action.sa_sigaction = vshEventInt;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &vshEventOldAction);

    if (timeout_ms)
        virEventUpdateTimeout(ctl->eventTimerId, timeout_ms);

    return 0;
}


/**
 * vshEventDone:
 * @ctl vsh command struct
 *
 * Call this from an event callback to let the main thread quit
 * blocking on further events.
 */
void
vshEventDone(vshControl *ctl)
{
    char reason = VSH_EVENT_DONE;

    if (ctl->eventPipe[1] >= 0)
        ignore_value(safewrite(ctl->eventPipe[1], &reason, 1));
}


/**
 * vshEventWait:
 * @ctl vsh command struct
 *
 * Call this in the main thread after calling vshEventStart() then
 * registering for one or more events.  This call will block until
 * SIGINT, the timeout registered at the start, or until one of your
 * event handlers calls vshEventDone().  Returns an enum VSH_EVENT_*
 * stating how the wait concluded, or -1 on error.
 */
int
vshEventWait(vshControl *ctl)
{
    char buf;
    int rv;

    assert(ctl->eventPipe[0] >= 0);
    while ((rv = read(ctl->eventPipe[0], &buf, 1)) < 0 && errno == EINTR);
    if (rv != 1) {
        char ebuf[1024];

        if (!rv)
            errno = EPIPE;
        vshError(ctl, _("failed to determine loop exit status: %s"),
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    return buf;
}


/**
 * vshEventCleanup:
 * @ctl vsh control struct
 *
 * Call at the end of any function that has used vshEventStart(), to
 * tear down any remaining SIGINT or timeout handlers.
 */
void
vshEventCleanup(vshControl *ctl)
{
    if (vshEventFd >= 0) {
        sigaction(SIGINT, &vshEventOldAction, NULL);
        vshEventFd = -1;
    }
    VIR_FORCE_CLOSE(ctl->eventPipe[0]);
    VIR_FORCE_CLOSE(ctl->eventPipe[1]);
    virEventUpdateTimeout(ctl->eventTimerId, -1);
}

#define LOGFILE_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_SYNC)

/**
 * vshOpenLogFile:
 *
 * Open log file.
 */
void
vshOpenLogFile(vshControl *ctl)
{
    if (ctl->logfile == NULL)
        return;

    if ((ctl->log_fd = open(ctl->logfile, LOGFILE_FLAGS, FILE_MODE)) < 0) {
        vshError(ctl, "%s",
                 _("failed to open the log file. check the log file path"));
        exit(EXIT_FAILURE);
    }
}

/**
 * vshOutputLogFile:
 *
 * Outputting an error to log file.
 */
void
vshOutputLogFile(vshControl *ctl, int log_level, const char *msg_format,
                 va_list ap)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *str = NULL;
    size_t len;
    const char *lvl = "";
    time_t stTime;
    struct tm stTm;

    if (ctl->log_fd == -1)
        return;

    /**
     * create log format
     *
     * [YYYY.MM.DD HH:MM:SS SIGNATURE PID] LOG_LEVEL message
    */
    time(&stTime);
    localtime_r(&stTime, &stTm);
    virBufferAsprintf(&buf, "[%d.%02d.%02d %02d:%02d:%02d %s %d] ",
                      (1900 + stTm.tm_year),
                      (1 + stTm.tm_mon),
                      stTm.tm_mday,
                      stTm.tm_hour,
                      stTm.tm_min,
                      stTm.tm_sec,
                      ctl->progname,
                      (int) getpid());
    switch (log_level) {
        case VSH_ERR_DEBUG:
            lvl = LVL_DEBUG;
            break;
        case VSH_ERR_INFO:
            lvl = LVL_INFO;
            break;
        case VSH_ERR_NOTICE:
            lvl = LVL_INFO;
            break;
        case VSH_ERR_WARNING:
            lvl = LVL_WARNING;
            break;
        case VSH_ERR_ERROR:
            lvl = LVL_ERROR;
            break;
        default:
            lvl = LVL_DEBUG;
            break;
    }
    virBufferAsprintf(&buf, "%s ", lvl);
    virBufferVasprintf(&buf, msg_format, ap);
    virBufferTrim(&buf, "\n", -1);
    virBufferAddChar(&buf, '\n');

    if (virBufferError(&buf))
        goto error;

    str = virBufferContentAndReset(&buf);
    len = strlen(str);

    /* write log */
    if (safewrite(ctl->log_fd, str, len) < 0)
        goto error;

    VIR_FREE(str);
    return;

 error:
    vshCloseLogFile(ctl);
    vshError(ctl, "%s", _("failed to write the log file"));
    virBufferFreeAndReset(&buf);
    VIR_FREE(str);
}

/**
 * vshCloseLogFile:
 *
 * Close log file.
 */
void
vshCloseLogFile(vshControl *ctl)
{
    char ebuf[1024];

    /* log file close */
    if (VIR_CLOSE(ctl->log_fd) < 0) {
        vshError(ctl, _("%s: failed to write log file: %s"),
                 ctl->logfile ? ctl->logfile : "?",
                 virStrerror(errno, ebuf, sizeof(ebuf)));
    }

    if (ctl->logfile) {
        VIR_FREE(ctl->logfile);
        ctl->logfile = NULL;
    }
}

#ifndef WIN32
static void
vshPrintRaw(vshControl *ctl, ...)
{
    va_list ap;
    char *key;

    va_start(ap, ctl);
    while ((key = va_arg(ap, char *)) != NULL)
        vshPrint(ctl, "%s\r\n", key);
    va_end(ap);
}

/**
 * vshAskReedit:
 * @msg: Question to ask user
 *
 * Ask user if he wants to return to previously
 * edited file.
 *
 * Returns 'y' if he wants to
 *         'n' if he doesn't want to
 *         'i' if he wants to try defining it again while ignoring validation
 *         'f' if he forcibly wants to
 *         -1  on error
 *          0  otherwise
 */
int
vshAskReedit(vshControl *ctl, const char *msg, bool relax_avail)
{
    int c = -1;

    if (!isatty(STDIN_FILENO))
        return -1;

    vshReportError(ctl);

    if (vshTTYMakeRaw(ctl, false) < 0)
        return -1;

    while (true) {
        vshPrint(ctl, "\r%s %s %s: ", msg, _("Try again?"),
                 relax_avail ? "[y,n,i,f,?]" : "[y,n,f,?]");
        c = c_tolower(getchar());

        if (c == '?') {
            vshPrintRaw(ctl,
                        "",
                        _("y - yes, start editor again"),
                        _("n - no, throw away my changes"),
                        NULL);

            if (relax_avail) {
                vshPrintRaw(ctl,
                            _("i - turn off validation and try to redefine "
                              "again"),
                            NULL);
            }

            vshPrintRaw(ctl,
                        _("f - force, try to redefine again"),
                        _("? - print this help"),
                        NULL);
            continue;
        } else if (c == 'y' || c == 'n' || c == 'f' ||
                   (relax_avail && c == 'i')) {
            break;
        }
    }

    vshTTYRestore(ctl);

    vshPrint(ctl, "\r\n");
    return c;
}
#else /* WIN32 */
int
vshAskReedit(vshControl *ctl,
             const char *msg ATTRIBUTE_UNUSED,
             bool relax_avail ATTRIBUTE_UNUSED)
{
    vshDebug(ctl, VSH_ERR_WARNING, "%s", _("This function is not "
                                           "supported on WIN32 platform"));
    return 0;
}
#endif /* WIN32 */


/* Common code for the edit / net-edit / pool-edit functions which follow. */
char *
vshEditWriteToTempFile(vshControl *ctl, const char *doc)
{
    char *ret;
    const char *tmpdir;
    int fd;
    char ebuf[1024];

    tmpdir = virGetEnvBlockSUID("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (virAsprintf(&ret, "%s/virshXXXXXX.xml", tmpdir) < 0) {
        vshError(ctl, "%s", _("out of memory"));
        return NULL;
    }
    fd = mkostemps(ret, 4, O_CLOEXEC);
    if (fd == -1) {
        vshError(ctl, _("mkostemps: failed to create temporary file: %s"),
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        VIR_FREE(ret);
        return NULL;
    }

    if (safewrite(fd, doc, strlen(doc)) == -1) {
        vshError(ctl, _("write: %s: failed to write to temporary file: %s"),
                 ret, virStrerror(errno, ebuf, sizeof(ebuf)));
        VIR_FORCE_CLOSE(fd);
        unlink(ret);
        VIR_FREE(ret);
        return NULL;
    }
    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("close: %s: failed to write or close temporary file: %s"),
                 ret, virStrerror(errno, ebuf, sizeof(ebuf)));
        unlink(ret);
        VIR_FREE(ret);
        return NULL;
    }

    /* Temporary filename: caller frees. */
    return ret;
}

/* Characters permitted in $EDITOR environment variable and temp filename. */
#define ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/_.:@"

int
vshEditFile(vshControl *ctl, const char *filename)
{
    const char *editor;
    virCommandPtr cmd;
    int ret = -1;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    editor = virGetEnvBlockSUID("VISUAL");
    if (!editor)
        editor = virGetEnvBlockSUID("EDITOR");
    if (!editor)
        editor = DEFAULT_EDITOR;

    /* Check that filename doesn't contain shell meta-characters, and
     * if it does, refuse to run.  Follow the Unix conventions for
     * EDITOR: the user can intentionally specify command options, so
     * we don't protect any shell metacharacters there.  Lots more
     * than virsh will misbehave if EDITOR has bogus contents (which
     * is why sudo scrubs it by default).  Conversely, if the editor
     * is safe, we can run it directly rather than wasting a shell.
     */
    if (strspn(editor, ACCEPTED_CHARS) != strlen(editor)) {
        if (strspn(filename, ACCEPTED_CHARS) != strlen(filename)) {
            vshError(ctl,
                     _("%s: temporary filename contains shell meta or other "
                       "unacceptable characters (is $TMPDIR wrong?)"),
                     filename);
            return -1;
        }
        cmd = virCommandNewArgList("sh", "-c", NULL);
        virCommandAddArgFormat(cmd, "%s %s", editor, filename);
    } else {
        cmd = virCommandNewArgList(editor, filename, NULL);
    }

    virCommandSetInputFD(cmd, STDIN_FILENO);
    virCommandSetOutputFD(cmd, &outfd);
    virCommandSetErrorFD(cmd, &errfd);
    if (virCommandRunAsync(cmd, NULL) < 0 ||
        virCommandWait(cmd, NULL) < 0) {
        vshReportError(ctl);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}

char *
vshEditReadBackFile(vshControl *ctl, const char *filename)
{
    char *ret;
    char ebuf[1024];

    if (virFileReadAll(filename, VSH_MAX_XML_FILE, &ret) == -1) {
        vshError(ctl,
                 _("%s: failed to read temporary file: %s"),
                 filename, virStrerror(errno, ebuf, sizeof(ebuf)));
        return NULL;
    }
    return ret;
}


/* Tree listing helpers.  */

static int
vshTreePrintInternal(vshControl *ctl,
                     vshTreeLookup lookup,
                     void *opaque,
                     int num_devices,
                     int devid,
                     int lastdev,
                     bool root,
                     virBufferPtr indent)
{
    size_t i;
    int nextlastdev = -1;
    int ret = -1;
    const char *dev = (lookup)(devid, false, opaque);

    if (virBufferError(indent))
        goto cleanup;

    /* Print this device, with indent if not at root */
    vshPrint(ctl, "%s%s%s\n", virBufferCurrentContent(indent),
             root ? "" : "+- ", dev);

    /* Update indent to show '|' or ' ' for child devices */
    if (!root) {
        virBufferAddChar(indent, devid == lastdev ? ' ' : '|');
        virBufferAddChar(indent, ' ');
        if (virBufferError(indent))
            goto cleanup;
    }

    /* Determine the index of the last child device */
    for (i = 0; i < num_devices; i++) {
        const char *parent = (lookup)(i, true, opaque);

        if (parent && STREQ(parent, dev))
            nextlastdev = i;
    }

    /* If there is a child device, then print another blank line */
    if (nextlastdev != -1)
        vshPrint(ctl, "%s  |\n", virBufferCurrentContent(indent));

    /* Finally print all children */
    virBufferAddLit(indent, "  ");
    if (virBufferError(indent))
        goto cleanup;
    for (i = 0; i < num_devices; i++) {
        const char *parent = (lookup)(i, true, opaque);

        if (parent && STREQ(parent, dev) &&
            vshTreePrintInternal(ctl, lookup, opaque,
                                 num_devices, i, nextlastdev,
                                 false, indent) < 0)
            goto cleanup;
    }
    virBufferTrim(indent, "  ", -1);

    /* If there was no child device, and we're the last in
     * a list of devices, then print another blank line */
    if (nextlastdev == -1 && devid == lastdev)
        vshPrint(ctl, "%s\n", virBufferCurrentContent(indent));

    if (!root)
        virBufferTrim(indent, NULL, 2);
    ret = 0;
 cleanup:
    return ret;
}

int
vshTreePrint(vshControl *ctl, vshTreeLookup lookup, void *opaque,
             int num_devices, int devid)
{
    int ret;
    virBuffer indent = VIR_BUFFER_INITIALIZER;

    ret = vshTreePrintInternal(ctl, lookup, opaque, num_devices,
                               devid, devid, true, &indent);
    if (ret < 0)
        vshError(ctl, "%s", _("Failed to complete tree listing"));
    virBufferFreeAndReset(&indent);
    return ret;
}

#if WITH_READLINE

/* -----------------
 * Readline stuff
 * -----------------
 */

/*
 * Generator function for command completion.  STATE lets us
 * know whether to start from scratch; without any state
 * (i.e. STATE == 0), then we start at the top of the list.
 */
static char *
vshReadlineCommandGenerator(const char *text, int state)
{
    static unsigned int grp_list_index, cmd_list_index;
    static size_t len;
    const char *name;
    const vshCmdGrp *grp;
    const vshCmdDef *cmds;

    if (!state) {
        grp_list_index = 0;
        cmd_list_index = 0;
        len = strlen(text);
    }

    grp = cmdGroups;

    /* Return the next name which partially matches from the
     * command list.
     */
    while (grp[grp_list_index].name) {
        cmds = grp[grp_list_index].commands;

        if (cmds[cmd_list_index].name) {
            while ((name = cmds[cmd_list_index].name)) {
                if (cmds[cmd_list_index++].flags & VSH_CMD_FLAG_ALIAS)
                    continue;

                if (STREQLEN(name, text, len))
                    return vshStrdup(NULL, name);
            }
        } else {
            cmd_list_index = 0;
            grp_list_index++;
        }
    }

    /* If no names matched, then return NULL. */
    return NULL;
}

static char *
vshReadlineOptionsGenerator(const char *text, int state, const vshCmdDef *cmd_parsed)
{
    static unsigned int list_index;
    static size_t len;
    static const vshCmdDef *cmd;
    const char *name;

    if (!state) {
        cmd = cmd_parsed;
        list_index = 0;
        len = strlen(text);
    }

    if (!cmd)
        return NULL;

    if (!cmd->opts)
        return NULL;

    while ((name = cmd->opts[list_index].name)) {
        char *res;

        list_index++;

        if (len > 2) {
            /* provide auto-complete only when the text starts with -- */
            if (STRNEQLEN(text, "--", 2))
                return NULL;
            if (STRNEQLEN(name, text + 2, len - 2))
                continue;
        } else if (STRNEQLEN(text, "--", len)) {
            return NULL;
        }
        res = vshMalloc(NULL, strlen(name) + 3);
        snprintf(res, strlen(name) + 3,  "--%s", name);
        return res;
    }

    /* If no names matched, then return NULL. */
    return NULL;
}

static char *
vshReadlineParse(const char *text, int state)
{
    static vshCommandParser parser, sanitizer;
    vshCommandToken tk;
    static const vshCmdDef *cmd;
    const vshCmdOptDef *opt = NULL;
    char *tkdata, *optstr, *const_tkdata, *completed_name;
    char *res = NULL;
    static char *ctext, *sanitized_text;
    static char **completed_list;
    static unsigned int completed_list_index;
    static uint64_t const_opts_need_arg, const_opts_required, const_opts_seen;
    uint64_t opts_seen;
    size_t opt_index;
    static bool cmd_exists, opts_filled, opt_exists;
    static bool non_bool_opt_exists, data_complete;

    if (!state) {
        parser.pos = rl_line_buffer;
        parser.getNextArg = vshCommandStringGetArg;

        ctext = vshStrdup(NULL, text);
        sanitizer.pos = ctext;
        sanitizer.getNextArg = vshCommandStringGetArg;

        const_tkdata = NULL;
        tkdata = NULL;
        sanitized_text = NULL;
        optstr = NULL;

        completed_list = NULL;
        completed_list_index = 0;

        /* Sanitize/de-quote the autocomplete text */
        tk = sanitizer.getNextArg(NULL, &sanitizer, &sanitized_text, false);

        /* No autocomplete if sanitized text is a token error or token end */
        if (tk == VSH_TK_ERROR)
            goto error;

        tk = parser.getNextArg(NULL, &parser, &const_tkdata, false);

        if (tk == VSH_TK_ERROR)
            goto error;

        /* Free-ing purposes */
        tkdata = const_tkdata;
        /* Skip leading space */
        virSkipSpaces((const char**)&tkdata);

        /* Handle ';'s */
        while (tk == VSH_TK_SUBCMD_END) {
            tk = parser.getNextArg(NULL, &parser, &const_tkdata, false);
            tkdata = const_tkdata;
        }

        /* Skip trailing space after ;*/
        virSkipSpaces((const char**)&tkdata);

        cmd_exists = false;
        opts_filled = false;
        non_bool_opt_exists = false;
        data_complete = false;

        const_opts_need_arg = 0;
        const_opts_required = 0;
        const_opts_seen = 0;

        opt_index = 0;

        cmd = NULL;
        opt = NULL;

        /* Parse till text to be auto-completed is reached */
        while (STRNEQ(tkdata, sanitized_text)) {
            if (!cmd) {
                if (!(cmd = vshCmddefSearch(tkdata)))
                    goto error;
                if (cmd->flags & VSH_CMD_FLAG_ALIAS)
                    cmd = vshCmddefSearch(cmd->alias);

                cmd_exists = true;
                if (vshCmddefOptParse(cmd, &const_opts_need_arg,
                                      &const_opts_required) < 0)
                    goto error;
                opts_seen = const_opts_seen;
                opts_filled = true;
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       c_isalnum(tkdata[2])) {
                /* Command retrieved successfully, move to options */
                optstr = strchr(tkdata + 2, '=');
                opt_index = 0;

                if (optstr) {
                    *optstr = '\0';
                    optstr = vshStrdup(NULL, optstr + 1);
                }

                if (!(opt = vshCmddefGetOption(NULL, cmd, tkdata + 2,
                                               &opts_seen, &opt_index,
                                               &optstr, false))) {
                    /* Parsing failed wrt autocomplete */
                    VIR_FREE(optstr);
                    goto error;
                }

                opts_seen = const_opts_seen;
                opt_exists = true;
                VIR_FREE(const_tkdata);
                if (opt->type != VSH_OT_BOOL) {
                    non_bool_opt_exists = true;
                    /* Opt exists and check for option data */
                    if (optstr) {
                        const_tkdata = optstr;
                        tkdata = const_tkdata;
                    } else {
                        VIR_FREE(const_tkdata);
                        tk = parser.getNextArg(NULL, &parser, &const_tkdata,
                                               false);

                        if (tk == VSH_TK_ERROR)
                            goto error;

                        tkdata = const_tkdata;
                        virSkipSpaces((const char **)&tkdata);
                    }
                    if (STREQ(tkdata, sanitized_text)) {
                        /* auto-complete non-bool option arg */
                        data_complete = true;
                        break;
                    }
                    non_bool_opt_exists = false;
                } else {
                    tkdata = NULL;
                    /* opt type is BOOL */
                    if (optstr) {
                        VIR_FREE(optstr);
                        goto error;
                    }
                }
            } else if (!opt_exists) {
                /* No -- option provided and some other token given
                 * Try to find the default option.
                 */
                if (!(opt = vshCmddefGetData(cmd, &const_opts_need_arg,
                                             &const_opts_seen))
                    || opt->type == VSH_OT_BOOL)
                    goto error;
                opt_exists = true;
                opts_seen = const_opts_seen;
            } else {
                /* In every other case, return NULL */
                goto error;
            }

            VIR_FREE(const_tkdata);
            tk = parser.getNextArg(NULL, &parser, &const_tkdata, false);

            if (tk == VSH_TK_ERROR)
                goto error;

            while (tk == VSH_TK_SUBCMD_END) {
                cmd = NULL;
                cmd_exists = false;
                opts_filled = false;
                opt = NULL;
                non_bool_opt_exists = false;
                tk = parser.getNextArg(NULL, &parser, &const_tkdata, false);
            }

            tkdata = const_tkdata;

            virSkipSpaces((const char**)&tkdata);
        }
        VIR_FREE(const_tkdata);
    }

    if (!cmd_exists) {
        res = vshReadlineCommandGenerator(sanitized_text, state);
    } else if (opts_filled && !non_bool_opt_exists) {
        res = vshReadlineOptionsGenerator(sanitized_text, state, cmd);
    } else if (non_bool_opt_exists && data_complete && opt && opt->completer) {
        if (!completed_list)
            completed_list = opt->completer(autoCompleteOpaque,
                                            opt->completer_flags);
        if (completed_list) {
            while ((completed_name = completed_list[completed_list_index])) {
                completed_list_index++;
                if (!STRPREFIX(completed_name, sanitized_text))
                    continue;
                res = vshStrdup(NULL, completed_name);
                return res;
            }
            res = NULL;
            virStringListFree(completed_list);
            completed_list_index = 0;
        }
    }

    if (!res) {
        VIR_FREE(sanitized_text);
        VIR_FREE(ctext);
    }

    return res;

 error:
    VIR_FREE(const_tkdata);
    VIR_FREE(sanitized_text);
    VIR_FREE(ctext);
    return NULL;

}

static char **
vshReadlineCompletion(const char *text,
                      int start ATTRIBUTE_UNUSED,
                      int end ATTRIBUTE_UNUSED)
{
    char **matches = (char **) NULL;

    matches = rl_completion_matches(text, vshReadlineParse);
    return matches;
}

# define HISTSIZE_MAX 500000

static int
vshReadlineInit(vshControl *ctl)
{
    char *userdir = NULL;
    int max_history = 500;
    int ret = -1;
    char *histsize_env = NULL;
    const char *histsize_str = NULL;

    /* Opaque data for autocomplete callbacks. */
    autoCompleteOpaque = ctl;

    /* Allow conditional parsing of the ~/.inputrc file.
     * Work around ancient readline 4.1 (hello Mac OS X),
     * which declared it as 'char *' instead of 'const char *'.
     */
    rl_readline_name = ctl->name;

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = vshReadlineCompletion;

    rl_basic_word_break_characters = " \t\n\\`@$><=;|&{(";

    if (virAsprintf(&histsize_env, "%s_HISTSIZE", ctl->env_prefix) < 0)
        goto cleanup;

    /* Limit the total size of the history buffer */
    if ((histsize_str = virGetEnvBlockSUID(histsize_env))) {
        if (virStrToLong_i(histsize_str, NULL, 10, &max_history) < 0) {
            vshError(ctl, _("Bad $%s value."), histsize_env);
            goto cleanup;
        } else if (max_history > HISTSIZE_MAX || max_history < 0) {
            vshError(ctl, _("$%s value should be between 0 "
                            "and %d"),
                     histsize_env, HISTSIZE_MAX);
            goto cleanup;
        }
    }
    stifle_history(max_history);

    /* Prepare to read/write history from/to the
     * $XDG_CACHE_HOME/virtshell/history file
     */
    userdir = virGetUserCacheDirectory();

    if (userdir == NULL) {
        vshError(ctl, "%s", _("Could not determine home directory"));
        goto cleanup;
    }

    if (virAsprintf(&ctl->historydir, "%s/%s", userdir, ctl->name) < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    if (virAsprintf(&ctl->historyfile, "%s/history", ctl->historydir) < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    read_history(ctl->historyfile);
    ret = 0;

 cleanup:
    VIR_FREE(userdir);
    VIR_FREE(histsize_env);
    return ret;
}

static void
vshReadlineDeinit(vshControl *ctl)
{
    if (ctl->historyfile != NULL) {
        if (virFileMakePathWithMode(ctl->historydir, 0755) < 0 &&
            errno != EEXIST) {
            char ebuf[1024];
            vshError(ctl, _("Failed to create '%s': %s"),
                     ctl->historydir, virStrerror(errno, ebuf, sizeof(ebuf)));
        } else {
            write_history(ctl->historyfile);
        }
    }

    VIR_FREE(ctl->historydir);
    VIR_FREE(ctl->historyfile);
}

char *
vshReadline(vshControl *ctl ATTRIBUTE_UNUSED, const char *prompt)
{
    return readline(prompt);
}

#else /* !WITH_READLINE */

static int
vshReadlineInit(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* empty */
    return 0;
}

static void
vshReadlineDeinit(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* empty */
}

char *
vshReadline(vshControl *ctl, const char *prompt)
{
    char line[1024];
    char *r;
    int len;

    fputs(prompt, stdout);
    r = fgets(line, sizeof(line), stdin);
    if (r == NULL) return NULL; /* EOF */

    /* Chomp trailing \n */
    len = strlen(r);
    if (len > 0 && r[len-1] == '\n')
        r[len-1] = '\0';

    return vshStrdup(ctl, r);
}

#endif /* !WITH_READLINE */

/*
 * Initialize debug settings.
 */
static int
vshInitDebug(vshControl *ctl)
{
    const char *debugEnv;
    char *env = NULL;

    if (ctl->debug == VSH_DEBUG_DEFAULT) {
        if (virAsprintf(&env, "%s_DEBUG", ctl->env_prefix) < 0)
            return -1;

        /* log level not set from commandline, check env variable */
        debugEnv = virGetEnvAllowSUID(env);
        if (debugEnv) {
            int debug;
            if (virStrToLong_i(debugEnv, NULL, 10, &debug) < 0 ||
                debug < VSH_ERR_DEBUG || debug > VSH_ERR_ERROR) {
                vshError(ctl, _("%s_DEBUG not set with a valid numeric value"),
                         ctl->env_prefix);
            } else {
                ctl->debug = debug;
            }
        }
        VIR_FREE(env);
    }

    if (ctl->logfile == NULL) {
        if (virAsprintf(&env, "%s_LOG_FILE", ctl->env_prefix) < 0)
            return -1;

        /* log file not set from cmdline */
        debugEnv = virGetEnvBlockSUID(env);
        if (debugEnv && *debugEnv) {
            ctl->logfile = vshStrdup(ctl, debugEnv);
            vshOpenLogFile(ctl);
        }
        VIR_FREE(env);
    }

    return 0;
}


/*
 * Initialize global data
 */
bool
vshInit(vshControl *ctl, const vshCmdGrp *groups, const vshCmdDef *set)
{
    if (!ctl->hooks) {
        vshError(ctl, "%s", _("client hooks cannot be NULL"));
        return false;
    }

    if (!groups && !set) {
        vshError(ctl, "%s", _("command groups and command set "
                              "cannot both be NULL"));
        return false;
    }

    cmdGroups = groups;
    cmdSet = set;

    if (vshInitDebug(ctl) < 0 ||
        (ctl->imode && vshReadlineInit(ctl) < 0))
        return false;

    return true;
}

bool
vshInitReload(vshControl *ctl)
{
    if (!cmdGroups && !cmdSet) {
        vshError(ctl, "%s", _("command groups and command are both NULL "
                              "run vshInit before reloading"));
        return false;
    }

    if (vshInitDebug(ctl) < 0)
        return false;

    if (ctl->imode)
        vshReadlineDeinit(ctl);
    if (ctl->imode && vshReadlineInit(ctl) < 0)
        return false;

    return true;
}

void
vshDeinit(vshControl *ctl)
{
    /* NB: Don't make calling of vshReadlineDeinit conditional on active
     * interactive mode. */
    vshReadlineDeinit(ctl);
    vshCloseLogFile(ctl);
}

/* -----------------------------------------------
 * Generic commands available to use by any client
 * -----------------------------------------------
 */
const vshCmdOptDef opts_help[] = {
    {.name = "command",
     .type = VSH_OT_STRING,
     .help = N_("Prints global help, command specific help, or help for a group of related commands")
    },
    {.name = NULL}
};

const vshCmdInfo info_help[] = {
    {.name = "help",
     .data = N_("print help")
    },
    {.name = "desc",
     .data = N_("Prints global help, command specific help, or help for a\n"
                "    group of related commands")
    },
    {.name = NULL}
};

bool
cmdHelp(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "command", &name) <= 0) {
        const vshCmdGrp *grp;
        const vshCmdDef *def;

        vshPrint(ctl, "%s", _("Grouped commands:\n\n"));

        for (grp = cmdGroups; grp->name; grp++) {
            vshPrint(ctl, _(" %s (help keyword '%s'):\n"), grp->name,
                     grp->keyword);

            for (def = grp->commands; def->name; def++) {
                if (def->flags & VSH_CMD_FLAG_ALIAS)
                    continue;
                vshPrint(ctl, "    %-30s %s\n", def->name,
                         _(vshCmddefGetInfo(def, "help")));
            }

            vshPrint(ctl, "\n");
        }

        return true;
    }

    if (vshCmddefSearch(name)) {
        return vshCmddefHelp(ctl, name);
    } else if (vshCmdGrpSearch(name)) {
        return vshCmdGrpHelp(ctl, name);
    } else {
        vshError(ctl, _("command or command group '%s' doesn't exist"), name);
        return false;
    }
}

const vshCmdOptDef opts_cd[] = {
    {.name = "dir",
     .type = VSH_OT_STRING,
     .help = N_("directory to switch to (default: home or else root)")
    },
    {.name = NULL}
};

const vshCmdInfo info_cd[] = {
    {.name = "help",
     .data = N_("change the current directory")
    },
    {.name = "desc",
     .data = N_("Change the current directory.")
    },
    {.name = NULL}
};

bool
cmdCd(vshControl *ctl, const vshCmd *cmd)
{
    const char *dir = NULL;
    char *dir_malloced = NULL;
    bool ret = true;
    char ebuf[1024];

    if (!ctl->imode) {
        vshError(ctl, "%s", _("cd: command valid only in interactive mode"));
        return false;
    }

    if (vshCommandOptStringQuiet(ctl, cmd, "dir", &dir) <= 0)
        dir = dir_malloced = virGetUserDirectory();
    if (!dir)
        dir = "/";

    if (chdir(dir) == -1) {
        vshError(ctl, _("cd: %s: %s"),
                 virStrerror(errno, ebuf, sizeof(ebuf)), dir);
        ret = false;
    }

    VIR_FREE(dir_malloced);
    return ret;
}

const vshCmdOptDef opts_echo[] = {
    {.name = "shell",
     .type = VSH_OT_BOOL,
     .help = N_("escape for shell use")
    },
    {.name = "xml",
     .type = VSH_OT_BOOL,
     .help = N_("escape for XML use")
    },
    {.name = "str",
     .type = VSH_OT_ALIAS,
     .help = "string"
    },
    {.name = "hi",
     .type = VSH_OT_ALIAS,
     .help = "string=hello"
    },
    {.name = "string",
     .type = VSH_OT_ARGV,
     .help = N_("arguments to echo")
    },
    {.name = NULL}
};

const vshCmdInfo info_echo[] = {
    {.name = "help",
     .data = N_("echo arguments")
    },
    {.name = "desc",
     .data = N_("Echo back arguments, possibly with quoting.")
    },
    {.name = NULL}
};

/* Exists mainly for debugging virsh, but also handy for adding back
 * quotes for later evaluation.
 */
bool
cmdEcho(vshControl *ctl, const vshCmd *cmd)
{
    bool shell = false;
    bool xml = false;
    int count = 0;
    const vshCmdOpt *opt = NULL;
    char *arg;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (vshCommandOptBool(cmd, "shell"))
        shell = true;
    if (vshCommandOptBool(cmd, "xml"))
        xml = true;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        char *str;
        virBuffer xmlbuf = VIR_BUFFER_INITIALIZER;

        arg = opt->data;

        if (count)
            virBufferAddChar(&buf, ' ');

        if (xml) {
            virBufferEscapeString(&xmlbuf, "%s", arg);
            if (virBufferError(&xmlbuf)) {
                vshError(ctl, "%s", _("Failed to allocate XML buffer"));
                return false;
            }
            str = virBufferContentAndReset(&xmlbuf);
        } else {
            str = vshStrdup(ctl, arg);
        }

        if (shell)
            virBufferEscapeShell(&buf, str);
        else
            virBufferAdd(&buf, str, -1);
        count++;
        VIR_FREE(str);
    }

    if (virBufferError(&buf)) {
        vshError(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }
    arg = virBufferContentAndReset(&buf);
    if (arg)
        vshPrint(ctl, "%s", arg);
    VIR_FREE(arg);
    return true;
}

const vshCmdInfo info_pwd[] = {
    {.name = "help",
     .data = N_("print the current directory")
    },
    {.name = "desc",
     .data = N_("Print the current directory.")
    },
    {.name = NULL}
};

bool
cmdPwd(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *cwd;
    bool ret = true;
    char ebuf[1024];

    cwd = getcwd(NULL, 0);
    if (!cwd) {
        vshError(ctl, _("pwd: cannot get current directory: %s"),
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        ret = false;
    } else {
        vshPrint(ctl, _("%s\n"), cwd);
        VIR_FREE(cwd);
    }

    return ret;
}

const vshCmdInfo info_quit[] = {
    {.name = "help",
     .data = N_("quit this interactive terminal")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

bool
cmdQuit(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    ctl->imode = false;
    return true;
}

/* -----------------
 * Command self-test
 * ----------------- */

const vshCmdInfo info_selftest[] = {
    {.name = "help",
     .data = N_("internal command for testing virt shells")
    },
    {.name = "desc",
     .data = N_("internal use only")
    },
    {.name = NULL}
};

/* Prints help for every command.
 * That runs vshCmddefOptParse which validates
 * the per-command options structure. */
bool
cmdSelfTest(vshControl *ctl ATTRIBUTE_UNUSED,
            const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const vshCmdGrp *grp;
    const vshCmdDef *def;

    for (grp = cmdGroups; grp->name; grp++) {
        for (def = grp->commands; def->name; def++) {
            if (vshCmddefCheckInternals(def) < 0)
                return false;
        }
    }

    return true;
}
