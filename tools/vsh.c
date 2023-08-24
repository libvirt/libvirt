/*
 * vsh.c: common data to be used by clients to exercise the libvirt API
 *
 * Copyright (C) 2005-2019 Red Hat, Inc.
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
#include "vsh.h"

#include <assert.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#if WITH_READLINE
/* In order to have proper rl_message declaration with older
 * versions of readline, we have to declare this. See 9ea3424a178
 * for more info. */
# define HAVE_STDARG_H
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virthread.h"
#include "vircommand.h"
#include "virstring.h"
#include "virutil.h"

#ifdef WITH_READLINE
/* For autocompletion */
vshControl *autoCompleteOpaque;
#endif

/* NOTE: It would be much nicer to have these two as part of vshControl
 * structure, unfortunately readline doesn't support passing opaque data
 * and only relies on static data accessible from the user-side callback
 */
const vshCmdGrp *cmdGroups;
const vshCmdDef *cmdSet;


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
 * the array using g_strfreev or a similar method.
 *
 * Returns the length of the filled array on success, or -1
 * on error.
 */
int
vshStringToArray(const char *str,
                 char ***array)
{
    g_auto(GStrv) tmp = NULL;
    GStrv n;
    size_t ntoks = 0;
    bool concat = false;

    tmp = g_strsplit(str, ",", 0);

    *array = g_new0(char *, g_strv_length(tmp) + 1);
    (*array)[ntoks++] = g_strdup(tmp[0]);

    /* undo splitting of comma escape (',,') by concatenating back on empty strings */
    for (n = tmp + 1; n[0]; n++) {
        if (concat) {
            g_autofree char *old = (*array)[ntoks - 1];

            (*array)[ntoks - 1] = g_strconcat(old, ",", n[0], NULL);
            concat = false;
            continue;
        }

        if (strlen(n[0]) == 0) {
            concat = true;
        } else {
            (*array)[ntoks++] = g_strdup(n[0]);
        }
    }

    /* corner case of ending with a single comma */
    if (concat)
        (*array)[ntoks++] = g_strdup("");

    return ntoks;
}

virErrorPtr last_error;

/*
 * Quieten libvirt until we're done with the command.
 */
void
vshErrorHandler(void *opaque G_GNUC_UNUSED,
                virErrorPtr error G_GNUC_UNUSED)
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

    if (virGetLastErrorCode() == VIR_ERR_OK)
        return;

    vshSaveLibvirtError();
}


/*
 * Reset libvirt error on graceful fallback paths
 */
void
vshResetLibvirtError(void)
{
    g_clear_pointer(&last_error, virFreeError);
    virResetLastError();
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
vshCmddefCheckInternals(vshControl *ctl,
                        const vshCmdDef *cmd,
                        bool missingCompleters)
{
    size_t i;
    const char *help = NULL;
    bool seenOptionalOption = false;
    g_auto(virBuffer) complbuf = VIR_BUFFER_INITIALIZER;

    /* in order to perform the validation resolve the alias first */
    if (cmd->flags & VSH_CMD_FLAG_ALIAS) {
        const vshCmdDef *alias;

        if (!cmd->alias) {
            vshError(ctl, _("command '%1$s' has inconsistent alias"), cmd->name);
            return -1;
        }

        if (!(alias = vshCmddefSearch(cmd->alias))) {
            vshError(ctl, _("command alias '%1$s' is pointing to a non-existent command '%2$s'"),
                     cmd->name, cmd->alias);
            return -1;
        }

        if (alias->flags & VSH_CMD_FLAG_ALIAS) {
            vshError(ctl, _("command alias '%1$s' is pointing to another command alias '%2$s'"),
                     cmd->name, cmd->alias);
            return -1;
        }

        if (cmd->handler) {
            vshError(ctl, _("command '%1$s' has handler set"), cmd->name);
            return -1;
        }

        if (cmd->opts) {
            vshError(ctl, _("command '%1$s' has options set"), cmd->name);
            return -1;
        }

        if (cmd->info) {
            vshError(ctl, _("command '%1$s' has info set"), cmd->name);
            return -1;
        }

        if (cmd->flags & ~VSH_CMD_FLAG_ALIAS) {
            vshError(ctl, _("command '%1$s' has multiple flags set"), cmd->name);
            return -1;
        }

        /* we don't need to continue as the real command will be checked separately */
        return 0;
    }

    /* Each command has to provide a non-empty help string. */
    if (!(help = vshCmddefGetInfo(cmd, "help")) || !*help) {
        vshError(ctl, _("command '%1$s' lacks help"), cmd->name);
        return -1;
    }

    if (!cmd->opts)
        return 0;

    for (i = 0; cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (i > 63) {
            vshError(ctl, _("command '%1$s' has too many options"), cmd->name);
            return -1; /* too many options */
        }

        if (missingCompleters &&
            (opt->type == VSH_OT_STRING || opt->type == VSH_OT_DATA) &&
            !opt->completer)
            virBufferStrcat(&complbuf, opt->name, ", ", NULL);

        switch (opt->type) {
        case VSH_OT_BOOL:
            if (opt->completer || opt->completer_flags) {
                vshError(ctl, _("bool parameter '%1$s' of command '%2$s' has completer set"),
                         opt->name, cmd->name);
                return -1;
            }

            G_GNUC_FALLTHROUGH;

        case VSH_OT_STRING:
            if (opt->flags & VSH_OFLAG_REQ) {
                vshError(ctl, _("parameter '%1$s' of command '%2$s' misused VSH_OFLAG_REQ"),
                         opt->name, cmd->name);
                return -1; /* neither bool nor string options can be mandatory */
            }

            seenOptionalOption = true;
            break;

        case VSH_OT_ALIAS: {
            size_t j;
            g_autofree char *name = NULL;
            char *p;

            if (opt->flags || !opt->help) {
                vshError(ctl, _("parameter '%1$s' of command '%2$s' has incorrect alias option"),
                         opt->name, cmd->name);
                return -1; /* alias options are tracked by the original name */
            }
            if ((p = strchr(opt->help, '=')))
                name = g_strndup(opt->help, p - opt->help);
            else
                name = g_strdup(opt->help);
            for (j = i + 1; cmd->opts[j].name; j++) {
                if (STREQ(name, cmd->opts[j].name) &&
                    cmd->opts[j].type != VSH_OT_ALIAS)
                    break;
            }
            if (p) {
                /* If alias comes with value, replacement must not be bool */
                if (cmd->opts[j].type == VSH_OT_BOOL) {
                    vshError(ctl, _("alias '%1$s' of command '%2$s' has mismatched alias type"),
                             opt->name, cmd->name);
                    return -1;
                }
            }
            if (!cmd->opts[j].name) {
                vshError(ctl, _("alias '%1$s' of command '%2$s' has missing alias option"),
                         opt->name, cmd->name);
                return -1; /* alias option must map to a later option name */
            }
        }
            break;
        case VSH_OT_ARGV:
            if (cmd->opts[i + 1].name) {
                vshError(ctl, _("parameter '%1$s' of command '%2$s' must be listed last"),
                         opt->name, cmd->name);
                return -1; /* argv option must be listed last */
            }
            break;

        case VSH_OT_DATA:
            if (!(opt->flags & VSH_OFLAG_REQ)) {
                vshError(ctl, _("parameter '%1$s' of command '%2$s' must use VSH_OFLAG_REQ flag"),
                         opt->name, cmd->name);
                return -1; /* OT_DATA should always be required. */
            }

            if (seenOptionalOption) {
                vshError(ctl, _("parameter '%1$s' of command '%2$s' must be listed before optional parameters"),
                         opt->name, cmd->name);
                return -1;  /* mandatory options must be listed first */
            }
            break;

        case VSH_OT_INT:
            if (opt->flags & VSH_OFLAG_REQ) {
                if (seenOptionalOption) {
                    vshError(ctl, _("parameter '%1$s' of command '%2$s' must be listed before optional parameters"),
                             opt->name, cmd->name);
                    return -1;  /* mandatory options must be listed first */
                }
            } else {
                seenOptionalOption = true;
            }

            break;
        }
    }

    virBufferTrim(&complbuf, ", ");

    if (missingCompleters && virBufferUse(&complbuf) > 0)
        vshPrintExtra(ctl, "%s: %s\n", cmd->name, virBufferCurrentContent(&complbuf));

    return 0;
}

/* Parse the options associated with @cmd, i.e. test whether options are
 * required or need an argument and fill the appropriate caller-provided bitmaps
 */
static void
vshCmddefOptParse(const vshCmdDef *cmd,
                  uint64_t *opts_need_arg,
                  uint64_t *opts_required)
{
    size_t i;

    *opts_need_arg = 0;
    *opts_required = 0;

    if (!cmd->opts)
        return;

    for (i = 0; cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (opt->type == VSH_OT_BOOL)
            continue;

        if (opt->type == VSH_OT_ALIAS)
            continue; /* skip the alias option */

        if (!(opt->flags & VSH_OFLAG_REQ_OPT))
            *opts_need_arg |= 1ULL << i;

        if (opt->flags & VSH_OFLAG_REQ)
            *opts_required |= 1ULL << i;
    }
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
    g_autofree char *alias = NULL;

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
                alias = g_strdup(opt->help);
                name = alias;
                if ((value = strchr(name, '='))) {
                    *value = '\0';
                    if (*optstr) {
                        if (report)
                            vshError(ctl, _("invalid '=' after option --%1$s"),
                                     opt->name);
                        return NULL;
                    }
                    *optstr = g_strdup(value + 1);
                }
                continue;
            }
            if ((*opts_seen & (1ULL << i)) && opt->type != VSH_OT_ARGV) {
                if (report)
                    vshError(ctl, _("option --%1$s already seen"), name);
                return NULL;
            }
            *opts_seen |= 1ULL << i;
            *opt_index = i;
            return opt;
        }
    }

    if (STRNEQ(cmd->name, "help") && report) {
        vshError(ctl, _("command '%1$s' doesn't support option --%2$s"),
                 cmd->name, name);
    }
    return NULL;
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
    i = __builtin_ffsl(*opts_need_arg) - 1;
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
                     _("command '%1$s' requires <%2$s> option") :
                     _("command '%1$s' requires --%2$s option"),
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
vshCmdGrpHelp(vshControl *ctl, const vshCmdGrp *grp)
{
    const vshCmdDef *cmd = NULL;

    vshPrint(ctl, _(" %1$s (help keyword '%2$s'):\n"), grp->name,
             grp->keyword);

    for (cmd = grp->commands; cmd->name; cmd++) {
        if (cmd->flags & VSH_CMD_FLAG_ALIAS ||
            cmd->flags & VSH_CMD_FLAG_HIDDEN)
            continue;
        vshPrint(ctl, "    %-30s %s\n", cmd->name,
                 _(vshCmddefGetInfo(cmd, "help")));
    }

    return true;
}

static bool
vshCmddefHelp(const vshCmdDef *def)
{
    const char *desc = NULL;
    char buf[256];
    bool shortopt = false; /* true if 'arg' works instead of '--opt arg' */

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
                       : _("[--%1$s <number>]"));
                if (!(opt->flags & VSH_OFLAG_REQ_OPT))
                    shortopt = true;
                break;
            case VSH_OT_STRING:
                /* xgettext:c-format */
                fmt = _("[--%1$s <string>]");
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
                        ? _("{[--%1$s] <string>}...")
                        : _("[[--%1$s] <string>]...");
                } else {
                    fmt = (opt->flags & VSH_OFLAG_REQ) ? _("<%1$s>...")
                        : _("[<%1$s>]...");
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
    if (desc && *desc) {
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
                g_snprintf(buf, sizeof(buf), "--%s", opt->name);
                break;
            case VSH_OT_INT:
                g_snprintf(buf, sizeof(buf),
                           (opt->flags & VSH_OFLAG_REQ) ? _("[--%1$s] <number>")
                           : _("--%1$s <number>"), opt->name);
                break;
            case VSH_OT_STRING:
                g_snprintf(buf, sizeof(buf), _("--%1$s <string>"), opt->name);
                break;
            case VSH_OT_DATA:
                g_snprintf(buf, sizeof(buf), _("[--%1$s] <string>"),
                           opt->name);
                break;
            case VSH_OT_ARGV:
                g_snprintf(buf, sizeof(buf),
                           shortopt ? _("[--%1$s] <string>") : _("<%1$s>"),
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

        g_free(tmp->data);
        g_free(tmp);
    }
}

static void
vshCommandFree(vshCmd *cmd)
{
    vshCmd *c = cmd;

    while (c) {
        vshCmd *tmp = c;

        c = c->next;

        vshCommandOptFree(tmp->opts);
        g_free(tmp);
    }
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(vshCmd, vshCommandFree);

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
 * valid (which indicates a programming error) unless cmd->skipChecks
 * is set. No error messages are issued if a value is returned.
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

    while (valid && valid->name) {
        if (STREQ(name, valid->name))
            break;
        valid++;
    }

    if (!cmd->skipChecks)
        assert(valid && (!needData || valid->type != VSH_OT_BOOL));

    if (valid && valid->flags & VSH_OFLAG_REQ)
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
                 _("Numeric value '%1$s' for <%2$s> option is malformed or out of range"),
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
                 _("Numeric value '%1$s' for <%2$s> option is malformed or out of range"),
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
                 _("Numeric value '%1$s' for <%2$s> option is malformed or out of range"),
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
vshCommandOptStringQuiet(vshControl *ctl G_GNUC_UNUSED, const vshCmd *cmd,
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
    else if (arg && !*arg->data && !(arg->def->flags & VSH_OFLAG_EMPTY_OK))
        error = N_("Option argument is empty");

    if (error) {
        if (!cmd->skipChecks)
            vshError(ctl, _("Failed to get option '%1$s': %2$s"), name, _(error));
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
                 _("Numeric value '%1$s' for <%2$s> option is malformed or out of range"),
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
                 _("Numeric value '%1$s' for <%2$s> option is malformed or out of range"),
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
                 _("Scaled numeric value '%1$s' for <%2$s> option is malformed or out of range"),
                 arg->data, name);
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
vshCommandOptArgv(vshControl *ctl G_GNUC_UNUSED, const vshCmd *cmd,
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
                     _("Scaled numeric value '%1$s' for <--bandwidth> option is malformed or out of range"),
                     arg->data);
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
        gint64 before, after;
        bool enable_timing = ctl->timing;

        before = g_get_real_time();

        if ((cmd->def->flags & VSH_CMD_FLAG_NOCONNECT) ||
            (hooks && hooks->connHandler && hooks->connHandler(ctl))) {
            ret = cmd->def->handler(ctl, cmd);
        } else {
            /* connection is not usable, return error */
            ret = false;
        }

        after = g_get_real_time();

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
            double diff_ms = (after - before) / 1000.0;

            vshPrint(ctl, _("\n(Time: %1$.3f ms)\n\n"), diff_ms);
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
    const char *originalLine;
    size_t point;
    /* vshCommandArgvGetArg() */
    char **arg_pos;
    char **arg_end;
};

static bool
vshCommandParse(vshControl *ctl, vshCommandParser *parser, vshCmd **partial)
{
    char *tkdata = NULL;
    vshCmd *clast = NULL;
    vshCmdOpt *first = NULL;
    const vshCmdDef *cmd = NULL;

    if (!partial) {
        g_clear_pointer(&ctl->cmd, vshCommandFree);
    }

    while (1) {
        vshCmdOpt *last = NULL;
        vshCommandToken tk;
        bool data_only = false;
        uint64_t opts_need_arg = 0;
        uint64_t opts_required = 0;
        uint64_t opts_seen = 0;

        cmd = NULL;
        first = NULL;

        if (partial) {
            g_clear_pointer(partial, vshCommandFree);
        }

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
                /* first token must be command name or comment */
                if (*tkdata == '#') {
                    do {
                        VIR_FREE(tkdata);
                        tk = parser->getNextArg(ctl, parser, &tkdata, false);
                    } while (tk == VSH_TK_ARG);
                    VIR_FREE(tkdata);
                    break;
                } else if (!(cmd = vshCmddefSearch(tkdata))) {
                    if (!partial)
                        vshError(ctl, _("unknown command: '%1$s'"), tkdata);
                    goto syntaxError;   /* ... or ignore this command only? */
                }

                /* aliases need to be resolved to the actual commands */
                if (cmd->flags & VSH_CMD_FLAG_ALIAS) {
                    VIR_FREE(tkdata);
                    tkdata = g_strdup(cmd->alias);
                    cmd = vshCmddefSearch(tkdata);
                }

                vshCmddefOptParse(cmd, &opts_need_arg, &opts_required);
                VIR_FREE(tkdata);
            } else if (data_only) {
                goto get_data;
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       g_ascii_isalnum(tkdata[2])) {
                char *optstr = strchr(tkdata + 2, '=');
                size_t opt_index = 0;

                if (optstr) {
                    *optstr = '\0'; /* convert the '=' to '\0' */
                    optstr = g_strdup(optstr + 1);
                }
                /* Special case 'help' to ignore all spurious options */
                if (!(opt = vshCmddefGetOption(ctl, cmd, tkdata + 2,
                                               &opts_seen, &opt_index,
                                               &optstr, partial == NULL))) {
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
                        tk = parser->getNextArg(ctl, parser, &tkdata, partial == NULL);
                    if (tk == VSH_TK_ERROR)
                        goto syntaxError;
                    if (tk != VSH_TK_ARG) {
                        if (partial) {
                            vshCmdOpt *arg = g_new0(vshCmdOpt, 1);
                            arg->def = opt;
                            arg->data = g_steal_pointer(&tkdata);
                            arg->next = NULL;

                            if (parser->pos - parser->originalLine == parser->point - 1)
                                arg->completeThis = true;

                            if (!first)
                                first = arg;
                            if (last)
                                last->next = arg;
                            last = arg;
                        } else {
                            vshError(ctl,
                                     _("expected syntax: --%1$s <%2$s>"),
                                     opt->name,
                                     opt->type ==
                                     VSH_OT_INT ? _("number") : _("string"));
                        }
                        goto syntaxError;
                    }
                    if (opt->type != VSH_OT_ARGV)
                        opts_need_arg &= ~(1ULL << opt_index);
                } else {
                    tkdata = NULL;
                    if (optstr) {
                        if (!partial)
                            vshError(ctl, _("invalid '=' after option --%1$s"),
                                     opt->name);
                        VIR_FREE(optstr);
                        goto syntaxError;
                    }
                }
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       tkdata[2] == '\0') {
                VIR_FREE(tkdata);
                data_only = true;
                continue;
            } else {
 get_data:
                /* Special case 'help' to ignore spurious data */
                if (!(opt = vshCmddefGetData(cmd, &opts_need_arg,
                                             &opts_seen)) &&
                     STRNEQ(cmd->name, "help")) {
                    if (!partial)
                        vshError(ctl, _("unexpected data '%1$s'"), tkdata);
                    goto syntaxError;
                }
            }
            if (opt) {
                /* save option */
                vshCmdOpt *arg = g_new0(vshCmdOpt, 1);

                arg->def = opt;
                arg->data = g_steal_pointer(&tkdata);
                arg->next = NULL;

                if (parser->pos - parser->originalLine == parser->point)
                    arg->completeThis = true;

                if (!first)
                    first = arg;
                if (last)
                    last->next = arg;
                last = arg;

                if (!partial)
                    vshDebug(ctl, VSH_ERR_INFO, "%s: %s(%s): %s\n",
                             cmd->name,
                             opt->name,
                             opt->type != VSH_OT_BOOL ? _("optdata") : _("bool"),
                             opt->type != VSH_OT_BOOL ? arg->data : _("(none)"));
            }
        }

        /* command parsed -- allocate new struct for the command */
        if (cmd) {
            vshCmd *c = g_new0(vshCmd, 1);
            vshCmdOpt *tmpopt = first;

            /* if we encountered --help, replace parsed command with
             * 'help <cmdname>' */
            for (tmpopt = first; tmpopt; tmpopt = tmpopt->next) {
                const vshCmdDef *help;
                if (STRNEQ(tmpopt->def->name, "help"))
                    continue;

                help = vshCmddefSearch("help");
                vshCommandOptFree(first);
                first = g_new0(vshCmdOpt, 1);
                first->def = help->opts;
                first->data = g_strdup(cmd->name);
                first->next = NULL;

                cmd = help;
                opts_required = 0;
                opts_seen = 0;
                break;
            }

            c->opts = g_steal_pointer(&first);
            c->def = cmd;
            c->next = NULL;

            if (!partial &&
                vshCommandCheckOpts(ctl, c, opts_required, opts_seen) < 0) {
                vshCommandFree(c);
                goto syntaxError;
            }

            if (partial) {
                vshCommandFree(*partial);
                *partial = c;
            } else {
                if (!ctl->cmd)
                    ctl->cmd = c;
                if (clast)
                    clast->next = c;
                clast = c;
            }
        }

        if (tk == VSH_TK_END)
            break;
    }

    return true;

 syntaxError:
    if (partial) {
        vshCmd *tmp;

        tmp = g_new0(vshCmd, 1);
        tmp->opts = first;
        tmp->def = cmd;

        *partial = tmp;
    } else {
        g_clear_pointer(&ctl->cmd, vshCommandFree);
        vshCommandOptFree(first);
    }
    VIR_FREE(tkdata);
    return false;
}

/* --------------------
 * Command argv parsing
 * --------------------
 */

static vshCommandToken ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
vshCommandArgvGetArg(vshControl *ctl G_GNUC_UNUSED,
                     vshCommandParser *parser,
                     char **res,
                     bool report G_GNUC_UNUSED)
{
    if (parser->arg_pos == parser->arg_end) {
        *res = NULL;
        return VSH_TK_END;
    }

    *res = g_strdup(*parser->arg_pos);
    parser->arg_pos++;
    return VSH_TK_ARG;
}

bool
vshCommandArgvParse(vshControl *ctl, int nargs, char **argv)
{
    vshCommandParser parser = { 0 };

    if (nargs <= 0)
        return false;

    parser.arg_pos = argv;
    parser.arg_end = argv + nargs;
    parser.getNextArg = vshCommandArgvGetArg;
    return vshCommandParse(ctl, &parser, NULL);
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
    char *p = parser->pos;
    char *q = g_strdup(p);

    *res = q;

    while (*p == ' ' || *p == '\t' || (*p == '\\' && p[1] == '\n'))
        p += 1 + (*p == '\\');

    if (*p == '\0')
        return VSH_TK_END;
    if (*p == ';' || *p == '\n') {
        parser->pos = ++p;             /* = \0 or begin of next command */
        return VSH_TK_SUBCMD_END;
    }
    if (*p == '#') { /* Argument starting with # is comment to end of line */
        while (*p && *p != '\n')
            p++;
        parser->pos = p + !!*p;
        return VSH_TK_SUBCMD_END;
    }

    while (*p) {
        /* end of token is blank space or ';' */
        if (!double_quote && !single_quote &&
            (*p == ' ' || *p == '\t' || *p == ';' || *p == '\n'))
            break;

        if (!double_quote && *p == '\'') { /* single quote */
            single_quote = !single_quote;
            p++;
            continue;
        } else if (!single_quote && *p == '\\') { /* escape */
            /*
             * The same as in shell, a \ in "" is an escaper,
             * but a \ in '' is not an escaper.
             */
            p++;
            if (*p == '\0') {
                if (report)
                    vshError(ctl, "%s", _("dangling \\"));
                return VSH_TK_ERROR;
            } else if (*p == '\n') {
                /* Elide backslash-newline entirely */
                p++;
                continue;
            }
        } else if (!single_quote && *p == '"') { /* double quote */
            double_quote = !double_quote;
            p++;
            continue;
        }

        *q++ = *p++;
    }

    if (double_quote) {
        /* We have seen a double quote, but not it's companion
         * ending. It's valid though, in case when we're called
         * from completer (report = false), but it's not valid
         * when parsing real command (report= true).  */
        if (report) {
            vshError(ctl, "%s", _("missing \""));
            return VSH_TK_ERROR;
        }
    }

    *q = '\0';
    parser->pos = p;
    return VSH_TK_ARG;
}


/**
 * vshCommandStringParse:
 * @ctl virsh control structure
 * @cmdstr: string to parse
 * @partial: store partially parsed command here
 * @point: position of cursor (rl_point)
 *
 * Parse given string @cmdstr as a command and store it under
 * @ctl->cmd. For readline completion, if @partial is not NULL on
 * the input then errors in parsing are ignored (because user is
 * still in progress of writing the command string) and partially
 * parsed command is stored at *@partial (caller has to free it
 * afterwards). Among with @partial, caller must set @point which
 * is the position of cursor in @cmdstr (offset, numbered from 1).
 * Parser will then set @completeThis attribute to true for the
 * vshCmdOpt that appeared under the cursor.
 */
bool
vshCommandStringParse(vshControl *ctl,
                      char *cmdstr,
                      vshCmd **partial,
                      size_t point)
{
    vshCommandParser parser = { 0 };

    if (cmdstr == NULL || *cmdstr == '\0')
        return false;

    parser.pos = cmdstr;
    parser.originalLine = cmdstr;
    parser.point = point;
    parser.getNextArg = vshCommandStringGetArg;
    return vshCommandParse(ctl, &parser, partial);
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
                 _("Numeric value '%1$u' for <%2$s> option is malformed or out of range"),
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

/* Return a non-NULL string representation of a typed parameter; exit on
 * unknown type. */
char *
vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
{
    switch (item->type) {
    case VIR_TYPED_PARAM_INT:
        return g_strdup_printf("%d", item->value.i);
        break;

    case VIR_TYPED_PARAM_UINT:
        return g_strdup_printf("%u", item->value.ui);
        break;

    case VIR_TYPED_PARAM_LLONG:
        return g_strdup_printf("%lld", item->value.l);
        break;

    case VIR_TYPED_PARAM_ULLONG:
        return g_strdup_printf("%llu", item->value.ul);
        break;

    case VIR_TYPED_PARAM_DOUBLE:
        return g_strdup_printf("%f", item->value.d);
        break;

    case VIR_TYPED_PARAM_BOOLEAN:
        return g_strdup(item->value.b ? _("yes") : _("no"));
        break;

    case VIR_TYPED_PARAM_STRING:
        return g_strdup(item->value.s);
        break;

    default:
        vshError(ctl, _("unimplemented parameter type %1$d"), item->type);
        exit(EXIT_FAILURE);
    }
}

void
vshDebug(vshControl *ctl, int level, const char *format, ...)
{
    va_list ap;
    g_autofree char *str = NULL;

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
    str = g_strdup_vprintf(format, ap);
    va_end(ap);
    fputs(str, stdout);
    fflush(stdout);
}


void
vshPrintVa(vshControl *ctl G_GNUC_UNUSED,
           const char *format,
           va_list ap)
{
    g_autofree char *str = NULL;

    str = g_strdup_vprintf(format, ap);
    fputs(str, stdout);
    fflush(stdout);
}


void
vshPrintExtra(vshControl *ctl,
              const char *format,
              ...)
{
    va_list ap;

    if (ctl && ctl->quiet)
        return;

    va_start(ap, format);
    vshPrintVa(ctl, format, ap);
    va_end(ap);
}


void
vshPrint(vshControl *ctl,
         const char *format,
         ...)
{
    va_list ap;

    va_start(ap, format);
    vshPrintVa(ctl, format, ap);
    va_end(ap);
}


bool
vshTTYIsInterruptCharacter(vshControl *ctl G_GNUC_UNUSED,
                           const char chr G_GNUC_UNUSED)
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
vshTTYDisableInterrupt(vshControl *ctl G_GNUC_UNUSED)
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
vshTTYRestore(vshControl *ctl G_GNUC_UNUSED)
{
#ifndef WIN32
    if (!ctl->istty)
        return 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &ctl->termattr) < 0)
        return -1;
#endif

    return 0;
}


int
vshTTYMakeRaw(vshControl *ctl G_GNUC_UNUSED,
              bool report_errors G_GNUC_UNUSED)
{
#ifndef WIN32
    struct termios rawattr = ctl->termattr;


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
            vshError(ctl, _("unable to set tty attributes: %1$s"),
                     g_strerror(errno));
        return -1;
    }
#endif

    return 0;
}


void
vshError(vshControl *ctl, const char *format, ...)
{
    va_list ap;
    g_autofree char *str = NULL;

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
    str = g_strdup_vprintf(format, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", NULLSTR(str));
    fflush(stderr);
}


void
vshEventLoop(void *opaque)
{
    vshControl *ctl = opaque;

    while (1) {
        bool quit = false;
        VIR_WITH_MUTEX_LOCK_GUARD(&ctl->lock) {
            quit = ctl->quit;
        }

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
#ifndef WIN32
static int vshEventFd = -1;
static struct sigaction vshEventOldAction;


/* Signal handler installed in vshEventStart, removed in vshEventCleanup.  */
static void
vshEventInt(int sig G_GNUC_UNUSED,
            siginfo_t *siginfo G_GNUC_UNUSED,
            void *context G_GNUC_UNUSED)
{
    char reason = VSH_EVENT_INTERRUPT;
    if (vshEventFd >= 0)
        ignore_value(safewrite(vshEventFd, &reason, 1));
}
#endif /* !WIN32 */


/* Event loop handler used to limit length of waiting for any other event. */
void
vshEventTimeout(int timer G_GNUC_UNUSED,
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
#ifndef WIN32
    struct sigaction action;
    assert(vshEventFd == -1);
#endif /* !WIN32 */

    assert(ctl->eventPipe[0] == -1 && ctl->eventPipe[1] == -1 &&
           ctl->eventTimerId >= 0);
    if (virPipe(ctl->eventPipe) < 0) {
        vshSaveLibvirtError();
        vshReportError(ctl);
        return -1;
    }

#ifndef WIN32
    vshEventFd = ctl->eventPipe[1];

    action.sa_sigaction = vshEventInt;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, &vshEventOldAction);
#endif /* !WIN32 */

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
        if (!rv)
            errno = EPIPE;
        vshError(ctl, _("failed to determine loop exit status: %1$s"),
                 g_strerror(errno));
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
#ifndef WIN32
    if (vshEventFd >= 0) {
        sigaction(SIGINT, &vshEventOldAction, NULL);
        vshEventFd = -1;
    }
#endif /* !WIN32 */
    VIR_FORCE_CLOSE(ctl->eventPipe[0]);
    VIR_FORCE_CLOSE(ctl->eventPipe[1]);
    virEventUpdateTimeout(ctl->eventTimerId, -1);
}

#ifdef O_SYNC
# define LOGFILE_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_SYNC)
#else
# define LOGFILE_FLAGS (O_WRONLY | O_APPEND | O_CREAT)
#endif

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
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *str = NULL;
    size_t len;
    const char *lvl = "";
    g_autoptr(GDateTime) now = g_date_time_new_now_local();
    g_autofree gchar *nowstr = NULL;

    if (ctl->log_fd == -1)
        return;

    /**
     * create log format
     *
     * [YYYY.MM.DD HH:MM:SS SIGNATURE PID] LOG_LEVEL message
    */
    nowstr = g_date_time_format(now, "%Y.%m.%d %H:%M:%S");
    virBufferAsprintf(&buf, "[%s %s %d] ",
                      nowstr,
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
    virBufferTrim(&buf, "\n");
    virBufferAddChar(&buf, '\n');

    str = virBufferContentAndReset(&buf);
    len = strlen(str);

    /* write log */
    if (safewrite(ctl->log_fd, str, len) < 0)
        goto error;

    return;

 error:
    vshCloseLogFile(ctl);
    vshError(ctl, "%s", _("failed to write the log file"));
}

/**
 * vshCloseLogFile:
 *
 * Close log file.
 */
void
vshCloseLogFile(vshControl *ctl)
{
    /* log file close */
    if (VIR_CLOSE(ctl->log_fd) < 0) {
        vshError(ctl, _("%1$s: failed to write log file: %2$s"),
                 ctl->logfile ? ctl->logfile : "?",
                 g_strerror(errno));
    }

    g_clear_pointer(&ctl->logfile, g_free);
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
        c = g_ascii_tolower(getchar());

        if (c == '?') {
            vshPrintRaw(ctl,
                        "",
                        _("y - yes, start editor again"),
                        _("n - no, throw away my changes"),
                        NULL);

            if (relax_avail) {
                vshPrintRaw(ctl,
                            _("i - turn off validation and try to redefine again"),
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
             const char *msg G_GNUC_UNUSED,
             bool relax_avail G_GNUC_UNUSED)
{
    vshDebug(ctl, VSH_ERR_WARNING, "%s", _("This function is not supported on WIN32 platform"));
    return 0;
}
#endif /* WIN32 */


void
vshEditUnlinkTempfile(char *file)
{
    if (!file)
        return;

    ignore_value(unlink(file));
    g_free(file);
}


/* Common code for the edit / net-edit / pool-edit functions which follow. */
char *
vshEditWriteToTempFile(vshControl *ctl, const char *doc)
{
    g_autofree char *filename = NULL;
    g_autoptr(vshTempFile) ret = NULL;
    const char *tmpdir;
    VIR_AUTOCLOSE fd = -1;

    tmpdir = getenv("TMPDIR");
    if (!tmpdir)
        tmpdir = "/tmp";
    filename = g_strdup_printf("%s/virshXXXXXX.xml", tmpdir);
    fd = g_mkstemp_full(filename, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        vshError(ctl, _("g_mkstemp_full: failed to create temporary file: %1$s"),
                 g_strerror(errno));
        return NULL;
    }

    ret = g_steal_pointer(&filename);

    if (safewrite(fd, doc, strlen(doc)) == -1) {
        vshError(ctl, _("write: %1$s: failed to write to temporary file: %2$s"),
                 ret, g_strerror(errno));
        return NULL;
    }
    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("close: %1$s: failed to write or close temporary file: %2$s"),
                 ret, g_strerror(errno));
        return NULL;
    }

    /* Temporary filename: caller frees. */
    return g_steal_pointer(&ret);
}

/* Characters permitted in $EDITOR environment variable and temp filename. */
#define ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/_.:@"

/* Hard-code default editor used as a fallback if not configured by
 * VISUAL or EDITOR environment variables. */
#define DEFAULT_EDITOR "vi"

int
vshEditFile(vshControl *ctl, const char *filename)
{
    const char *editor;
    g_autoptr(virCommand) cmd = NULL;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    editor = getenv("VISUAL");
    if (!editor)
        editor = getenv("EDITOR");
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
                     _("%1$s: temporary filename contains shell meta or other unacceptable characters (is $TMPDIR wrong?)"),
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
        return -1;
    }
    return 0;
}

char *
vshEditReadBackFile(vshControl *ctl, const char *filename)
{
    char *ret;

    if (virFileReadAll(filename, VSH_MAX_XML_FILE, &ret) == -1) {
        vshError(ctl,
                 _("%1$s: failed to read temporary file: %2$s"),
                 filename, g_strerror(errno));
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
                     virBuffer *indent)
{
    size_t i;
    int nextlastdev = -1;
    const char *dev = (lookup)(devid, false, opaque);

    /* Print this device, with indent if not at root */
    vshPrint(ctl, "%s%s%s\n", virBufferCurrentContent(indent),
             root ? "" : "+- ", dev);

    /* Update indent to show '|' or ' ' for child devices */
    if (!root) {
        virBufferAddChar(indent, devid == lastdev ? ' ' : '|');
        virBufferAddChar(indent, ' ');
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
    for (i = 0; i < num_devices; i++) {
        const char *parent = (lookup)(i, true, opaque);

        if (parent && STREQ(parent, dev) &&
            vshTreePrintInternal(ctl, lookup, opaque,
                                 num_devices, i, nextlastdev,
                                 false, indent) < 0)
            return -1;
    }
    virBufferTrim(indent, "  ");

    /* If there was no child device, and we're the last in
     * a list of devices, then print another blank line */
    if (nextlastdev == -1 && devid == lastdev)
        vshPrint(ctl, "%s\n", virBufferCurrentContent(indent));

    if (!root)
        virBufferTrimLen(indent, 2);

    return 0;
}

int
vshTreePrint(vshControl *ctl, vshTreeLookup lookup, void *opaque,
             int num_devices, int devid)
{
    int ret;
    g_auto(virBuffer) indent = VIR_BUFFER_INITIALIZER;

    ret = vshTreePrintInternal(ctl, lookup, opaque, num_devices,
                               devid, devid, true, &indent);
    if (ret < 0)
        vshError(ctl, "%s", _("Failed to complete tree listing"));
    return ret;
}


/**
 * vshReadlineCommandGenerator:
 *
 * Generator function for command completion. Used also for completing the
 * '--command' option of the 'help' command.
 *
 * Returns a string list of all commands, or NULL on failure.
 */
static char **
vshReadlineCommandGenerator(void)
{
    size_t grp_list_index = 0;
    const vshCmdGrp *grp;
    size_t ret_size = 0;
    g_auto(GStrv) ret = NULL;

    grp = cmdGroups;

    for (grp_list_index = 0; grp[grp_list_index].name; grp_list_index++) {
        const vshCmdDef *cmds = grp[grp_list_index].commands;
        size_t cmd_list_index;

        for (cmd_list_index = 0; cmds[cmd_list_index].name; cmd_list_index++) {
            const char *name = cmds[cmd_list_index].name;

            if (cmds[cmd_list_index].flags & VSH_CMD_FLAG_ALIAS ||
                cmds[cmd_list_index].flags & VSH_CMD_FLAG_HIDDEN)
                continue;

            VIR_REALLOC_N(ret, ret_size + 2);

            ret[ret_size] = g_strdup(name);
            ret_size++;
            /* Terminate the string list properly. */
            ret[ret_size] = NULL;
        }
    }

    return g_steal_pointer(&ret);
}


#if WITH_READLINE

/* -----------------
 * Readline stuff
 * -----------------
 */


static char **
vshReadlineOptionsGenerator(const vshCmdDef *cmd,
                            vshCmd *last)
{
    size_t list_index = 0;
    size_t ret_size = 0;
    g_auto(GStrv) ret = NULL;

    if (!cmd)
        return NULL;

    if (!cmd->opts)
        return NULL;

    for (list_index = 0; cmd->opts[list_index].name; list_index++) {
        const char *name = cmd->opts[list_index].name;
        bool exists = false;
        vshCmdOpt *opt =  last->opts;

        /* Skip aliases, we do not report them in help output either. */
        if (cmd->opts[list_index].type == VSH_OT_ALIAS)
            continue;

        while (opt) {
            if (STREQ(opt->def->name, name) && opt->def->type != VSH_OT_ARGV) {
                exists = true;
                break;
            }

            opt = opt->next;
        }

        if (exists)
            continue;

        VIR_REALLOC_N(ret, ret_size + 2);

        ret[ret_size] = g_strdup_printf("--%s", name);
        ret_size++;
        /* Terminate the string list properly. */
        ret[ret_size] = NULL;
    }

    return g_steal_pointer(&ret);
}


static const vshCmdOptDef *
vshReadlineCommandFindOpt(const vshCmd *partial)
{
    const vshCmd *tmp = partial;

    while (tmp) {
        const vshCmdOpt *opt = tmp->opts;

        while (opt) {
            if (opt->completeThis)
                return opt->def;

            opt = opt->next;
        }
        tmp = tmp->next;
    }

    return NULL;
}


static int
vshCompleterFilter(char ***list,
                   const char *text)
{
    char **newList = NULL;
    size_t newList_len = 0;
    size_t list_len;
    size_t i;

    if (!list || !*list)
        return 0;

    list_len = g_strv_length(*list);
    newList = g_new0(char *, list_len + 1);

    for (i = 0; i < list_len; i++) {
        if (!STRPREFIX((*list)[i], text)) {
            g_clear_pointer(&(*list)[i], g_free);
            continue;
        }

        newList[newList_len] = g_steal_pointer(&(*list)[i]);
        newList_len++;
    }

    newList = g_renew(char *, newList, newList_len + 1);
    g_free(*list);
    *list = newList;
    return 0;
}


static char *
vshReadlineParse(const char *text, int state)
{
    static char **list;
    static size_t list_index;
    char *ret = NULL;

    /* Readline calls this function until NULL is returned. On
     * the very first call @state is zero which means we should
     * initialize those static variables above. On subsequent
     * calls @state is non zero. */
    if (!state) {
        g_autoptr(vshCmd) partial = NULL;
        const vshCmdDef *cmd = NULL;
        const vshCmdOptDef *opt = NULL;
        g_autofree char *line = g_strdup(rl_line_buffer);

        g_clear_pointer(&list, g_strfreev);
        list_index = 0;

        *(line + rl_point) = '\0';

        vshCommandStringParse(NULL, line, &partial, rl_point);

        if (partial) {
            cmd = partial->def;
            partial->skipChecks = true;
        }

        if (cmd && STREQ(cmd->name, text)) {
            /* Corner case - some commands share prefix (e.g.
             * dump and dumpxml). If user typed 'dump<TAB><TAB>',
             * then @text = "dump" and we want to offer command
             * completion. If they typed 'dump <TAB><TAB>' then
             * @text = "" (the space after the command) and we
             * want to offer options completion for dump command.
             */
            cmd = NULL;
        }

        opt = vshReadlineCommandFindOpt(partial);

        if (!cmd) {
            list = vshReadlineCommandGenerator();
        } else if (!opt || opt->type == VSH_OT_BOOL) {
            list = vshReadlineOptionsGenerator(cmd, partial);
        } else if (opt && opt->completer) {
            list = opt->completer(autoCompleteOpaque,
                                  partial,
                                  opt->completer_flags);
        }

        /* Escape completions, if needed (i.e. argument
         * we are completing wasn't started with a quote
         * character). This also enables filtering done
         * below to work properly. */
        if (list &&
            !rl_completion_quote_character) {
            size_t i;

            for (i = 0; list[i]; i++) {
                g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

                virBufferEscape(&buf, '\\', " ", "%s", list[i]);
                VIR_FREE(list[i]);
                list[i] = virBufferContentAndReset(&buf);
            }
        }

        /* For string list returned by completers we have to do
         * filtering based on @text because completers returns all
         * possible strings. */
        if (vshCompleterFilter(&list, text) < 0)
            goto cleanup;
    }

    if (list) {
        ret = g_strdup(list[list_index]);
        list_index++;
    }

 cleanup:
    if (!ret) {
        g_clear_pointer(&list, g_strfreev);
        list_index = 0;
    }

    return ret;
}

static char **
vshReadlineCompletion(const char *text,
                      int start G_GNUC_UNUSED,
                      int end G_GNUC_UNUSED)
{
    return rl_completion_matches(text, vshReadlineParse);
}


static int
vshReadlineCharIsQuoted(char *line, int idx)
{
    return idx > 0 &&
           line[idx - 1] == '\\' &&
           !vshReadlineCharIsQuoted(line, idx - 1);
}


# define HISTSIZE_MAX 500000

static int
vshReadlineInit(vshControl *ctl)
{
    g_autofree char *userdir = NULL;
    int max_history = 500;
    g_autofree char *histsize_env = NULL;
    const char *histsize_str = NULL;
    const char *break_characters = " \t\n`@$><=;|&{(";
    const char *quote_characters = "\"'";

    /* Opaque data for autocomplete callbacks. */
    autoCompleteOpaque = ctl;

    rl_readline_name = ctl->name;

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = vshReadlineCompletion;

    rl_basic_word_break_characters = break_characters;

    rl_completer_quote_characters = quote_characters;
    rl_char_is_quoted_p = vshReadlineCharIsQuoted;

    histsize_env = g_strdup_printf("%s_HISTSIZE", ctl->env_prefix);

    /* Limit the total size of the history buffer */
    if ((histsize_str = getenv(histsize_env))) {
        if (virStrToLong_i(histsize_str, NULL, 10, &max_history) < 0) {
            vshError(ctl, _("Bad $%1$s value."), histsize_env);
            return -1;
        } else if (max_history > HISTSIZE_MAX || max_history < 0) {
            vshError(ctl, _("$%1$s value should be between 0 and %2$d"),
                     histsize_env, HISTSIZE_MAX);
            return -1;
        }
    }
    stifle_history(max_history);

    /* Prepare to read/write history from/to the
     * $XDG_CACHE_HOME/virtshell/history file
     */
    userdir = virGetUserCacheDirectory();

    ctl->historydir = g_strdup_printf("%s/%s", userdir, ctl->name);

    ctl->historyfile = g_strdup_printf("%s/history", ctl->historydir);

    read_history(ctl->historyfile);
    return 0;
}

static void
vshReadlineDeinit(vshControl *ctl)
{
    if (ctl->historyfile != NULL) {
        if (g_mkdir_with_parents(ctl->historydir, 0755) < 0 &&
            errno != EEXIST) {
            vshError(ctl, _("Failed to create '%1$s': %2$s"),
                     ctl->historydir, g_strerror(errno));
        } else {
            write_history(ctl->historyfile);
        }
    }

    g_clear_pointer(&ctl->historydir, g_free);
    g_clear_pointer(&ctl->historyfile, g_free);
}

char *
vshReadline(vshControl *ctl G_GNUC_UNUSED, const char *prompt)
{
    return readline(prompt);
}

void
vshReadlineHistoryAdd(const char *cmd)
{
    return add_history(cmd);
}

#else /* !WITH_READLINE */

static int
vshReadlineInit(vshControl *ctl G_GNUC_UNUSED)
{
    /* empty */
    return 0;
}

static void
vshReadlineDeinit(vshControl *ctl G_GNUC_UNUSED)
{
    /* empty */
}

char *
vshReadline(vshControl *ctl G_GNUC_UNUSED,
            const char *prompt)
{
    char line[1024];
    char *r;
    int len;

    fputs(prompt, stdout);
    fflush(stdout);
    r = fgets(line, sizeof(line), stdin);
    if (r == NULL) return NULL; /* EOF */

    /* Chomp trailing \n */
    len = strlen(r);
    if (len > 0 && r[len-1] == '\n')
        r[len-1] = '\0';

    return g_strdup(r);
}

void
vshReadlineHistoryAdd(const char *cmd G_GNUC_UNUSED)
{
    /* empty */
}

#endif /* !WITH_READLINE */

/*
 * Initialize debug settings.
 */
static int
vshInitDebug(vshControl *ctl)
{
    const char *debugEnv;

    if (ctl->debug == VSH_DEBUG_DEFAULT) {
        g_autofree char *env = g_strdup_printf("%s_DEBUG", ctl->env_prefix);

        /* log level not set from commandline, check env variable */
        debugEnv = getenv(env);
        if (debugEnv) {
            int debug;
            if (virStrToLong_i(debugEnv, NULL, 10, &debug) < 0 ||
                debug < VSH_ERR_DEBUG || debug > VSH_ERR_ERROR) {
                vshError(ctl, _("%1$s_DEBUG not set with a valid numeric value"),
                         ctl->env_prefix);
            } else {
                ctl->debug = debug;
            }
        }
    }

    if (ctl->logfile == NULL) {
        g_autofree char *env = g_strdup_printf("%s_LOG_FILE", ctl->env_prefix);

        /* log file not set from cmdline */
        debugEnv = getenv(env);
        if (debugEnv && *debugEnv) {
            ctl->logfile = g_strdup(debugEnv);
            vshOpenLogFile(ctl);
        }
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
        vshError(ctl, "%s", _("command groups and command set cannot both be NULL"));
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
        vshError(ctl, "%s", _("command groups and command are both NULL run vshInit before reloading"));
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

static char **
vshCompleteHelpCommand(vshControl *ctl G_GNUC_UNUSED,
                       const vshCmd *cmd G_GNUC_UNUSED,
                       unsigned int completerflags G_GNUC_UNUSED)
{
    return vshReadlineCommandGenerator();
}


const vshCmdOptDef opts_help[] = {
    {.name = "command",
     .type = VSH_OT_STRING,
     .completer = vshCompleteHelpCommand,
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
    const vshCmdDef *def = NULL;
    const vshCmdGrp *grp = NULL;
    const char *name = NULL;

    if (vshCommandOptStringQuiet(ctl, cmd, "command", &name) <= 0) {
        vshPrint(ctl, "%s", _("Grouped commands:\n\n"));

        for (grp = cmdGroups; grp->name; grp++) {
            vshPrint(ctl, _(" %1$s (help keyword '%2$s'):\n"), grp->name,
                     grp->keyword);

            for (def = grp->commands; def->name; def++) {
                if (def->flags & VSH_CMD_FLAG_ALIAS ||
                    def->flags & VSH_CMD_FLAG_HIDDEN)
                    continue;
                vshPrint(ctl, "    %-30s %s\n", def->name,
                         _(vshCmddefGetInfo(def, "help")));
            }

            vshPrint(ctl, "\n");
        }

        return true;
    }

    if ((def = vshCmddefSearch(name))) {
        if (def->flags & VSH_CMD_FLAG_ALIAS)
            def = vshCmddefSearch(def->alias);
        return vshCmddefHelp(def);
    } else if ((grp = vshCmdGrpSearch(name))) {
        return vshCmdGrpHelp(ctl, grp);
    } else {
        vshError(ctl, _("command or command group '%1$s' doesn't exist"), name);
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
    g_autofree char *dir_malloced = NULL;

    if (!ctl->imode) {
        vshError(ctl, "%s", _("cd: command valid only in interactive mode"));
        return false;
    }

    if (vshCommandOptStringQuiet(ctl, cmd, "dir", &dir) <= 0)
        dir = dir_malloced = virGetUserDirectory();
    if (!dir)
        dir = "/";

    if (chdir(dir) == -1) {
        vshError(ctl, _("cd: %1$s: %2$s"),
                 g_strerror(errno), dir);
        return false;
    }

    return true;
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
    {.name = "split",
     .type = VSH_OT_BOOL,
     .help = N_("split each argument on ','; ',,' is an escape sequence")
    },
    {.name = "err",
     .type = VSH_OT_BOOL,
     .help = N_("output to stderr"),
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
     .data = N_("echo arguments. Used for internal testing.")
    },
    {.name = "desc",
     .data = N_("Echo back arguments, possibly with quoting. Used for internal testing.")
    },
    {.name = NULL}
};

/* Exists mainly for debugging virsh, but also handy for adding back
 * quotes for later evaluation.
 */
bool
cmdEcho(vshControl *ctl, const vshCmd *cmd)
{
    bool shell = vshCommandOptBool(cmd, "shell");
    bool xml = vshCommandOptBool(cmd, "xml");
    bool err = vshCommandOptBool(cmd, "err");
    bool split = vshCommandOptBool(cmd, "split");
    const vshCmdOpt *opt = NULL;
    g_autofree char *arg = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    VSH_EXCLUSIVE_OPTIONS_VAR(shell, xml);
    VSH_EXCLUSIVE_OPTIONS_VAR(shell, split);
    VSH_EXCLUSIVE_OPTIONS_VAR(xml, split);

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        const char *curr = opt->data;

        if (xml) {
            virBufferEscapeString(&buf, "%s", curr);
        } else if (shell) {
            virBufferEscapeShell(&buf, curr);
        } else if (split) {
            g_auto(GStrv) spl = NULL;
            GStrv n;

            vshStringToArray(curr, &spl);

            for (n = spl; *n; n++)
                virBufferAsprintf(&buf, "%s\n", *n);
        } else {
            virBufferAdd(&buf, curr, -1);
        }

        virBufferAddChar(&buf, ' ');
    }

    virBufferTrim(&buf, " ");

    arg = virBufferContentAndReset(&buf);
    if (arg) {
        if (err)
            vshError(ctl, "%s", arg);
        else
            vshPrint(ctl, "%s", arg);
    }
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
cmdPwd(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    g_autofree char *cwd = g_get_current_dir();

    vshPrint(ctl, _("%1$s\n"), cwd);

    return true;
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
cmdQuit(vshControl *ctl, const vshCmd *cmd G_GNUC_UNUSED)
{
    ctl->imode = false;
    return true;
}

/* -----------------
 * Command self-test
 * ----------------- */

const vshCmdOptDef opts_selftest[] = {
    {.name = "completers-missing",
     .type = VSH_OT_BOOL,
     .help = N_("output the list of options which are missing completers")
    },
    {.name = NULL}
};
const vshCmdInfo info_selftest[] = {
    {.name = "help",
     .data = N_("internal command for testing virt shells")
    },
    {.name = "desc",
     .data = N_("internal use only")
    },
    {.name = NULL}
};

bool
cmdSelfTest(vshControl *ctl, const vshCmd *cmd)
{
    const vshCmdGrp *grp;
    const vshCmdDef *def;
    bool completers = vshCommandOptBool(cmd, "completers-missing");

    for (grp = cmdGroups; grp->name; grp++) {
        for (def = grp->commands; def->name; def++) {
            if (vshCmddefCheckInternals(ctl, def, completers) < 0)
                return false;
        }
    }

    return true;
}

/* ----------------------
 * Autocompletion command
 * ---------------------- */

const vshCmdOptDef opts_complete[] = {
    {.name = "string",
     .type = VSH_OT_ARGV,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("partial string to autocomplete")
    },
    {.name = NULL}
};

const vshCmdInfo info_complete[] = {
    {.name = "help",
     .data = N_("internal command for autocompletion")
    },
    {.name = "desc",
     .data = N_("internal use only")
    },
    {.name = NULL}
};


#ifdef WITH_READLINE
bool
cmdComplete(vshControl *ctl, const vshCmd *cmd)
{
    const vshClientHooks *hooks = ctl->hooks;
    int stdin_fileno = STDIN_FILENO;
    const char *arg = "";
    const vshCmdOpt *opt = NULL;
    g_auto(GStrv) matches = NULL;
    char **iter;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (vshCommandOptStringQuiet(ctl, cmd, "string", &arg) <= 0)
        return false;

    /* This command is flagged VSH_CMD_FLAG_NOCONNECT because we
     * need to prevent auth hooks reading any input. Therefore, we
     * have to close stdin and then connect ourselves. */
    VIR_FORCE_CLOSE(stdin_fileno);

    if (!(hooks && hooks->connHandler && hooks->connHandler(ctl)))
        return false;

    while ((opt = vshCommandOptArgv(ctl, cmd, opt))) {
        if (virBufferUse(&buf) != 0)
            virBufferAddChar(&buf, ' ');
        virBufferAddStr(&buf, opt->data);
        arg = opt->data;
    }

    vshReadlineInit(ctl);

    if (!(rl_line_buffer = virBufferContentAndReset(&buf)))
        rl_line_buffer = g_strdup("");

    /* rl_point is current cursor position in rl_line_buffer.
     * In our case it's at the end of the whole line. */
    rl_point = strlen(rl_line_buffer);

    if (!(matches = vshReadlineCompletion(arg, 0, 0)))
        return false;

    for (iter = matches; *iter; iter++) {
        if (iter == matches && matches[1])
            continue;
        printf("%s\n", *iter);
    }

    return true;
}


#else /* !WITH_READLINE */


bool
cmdComplete(vshControl *ctl G_GNUC_UNUSED,
            const vshCmd *cmd G_GNUC_UNUSED)
{
    return false;
}
#endif /* !WITH_READLINE */
