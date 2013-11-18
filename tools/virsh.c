/*
 * virsh.c: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2013 Red Hat, Inc.
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
#include "virsh.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>
#include "c-ctype.h"
#include <fcntl.h>
#include <locale.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <strings.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#if WITH_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "virerror.h"
#include "base64.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virxml.h"
#include <libvirt/libvirt-qemu.h>
#include <libvirt/libvirt-lxc.h>
#include "virfile.h"
#include "configmake.h"
#include "virthread.h"
#include "vircommand.h"
#include "virkeycode.h"
#include "virnetdevbandwidth.h"
#include "virbitmap.h"
#include "conf/domain_conf.h"
#include "virtypedparam.h"
#include "virstring.h"

#include "virsh-console.h"
#include "virsh-domain.h"
#include "virsh-domain-monitor.h"
#include "virsh-host.h"
#include "virsh-interface.h"
#include "virsh-network.h"
#include "virsh-nodedev.h"
#include "virsh-nwfilter.h"
#include "virsh-pool.h"
#include "virsh-secret.h"
#include "virsh-snapshot.h"
#include "virsh-volume.h"

static char *progname;

static const vshCmdGrp cmdGroups[];

/* Bypass header poison */
#undef strdup

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

/* Poison the raw allocating identifiers in favor of our vsh variants.  */
#define strdup use_vshStrdup_instead_of_strdup

int
vshNameSorter(const void *a, const void *b)
{
    const char **sa = (const char**)a;
    const char **sb = (const char**)b;

    return vshStrcasecmp(*sa, *sb);
}

double
vshPrettyCapacity(unsigned long long val, const char **unit)
{
    if (val < 1024) {
        *unit = "B";
        return (double)val;
    } else if (val < (1024.0l * 1024.0l)) {
        *unit = "KiB";
        return (((double)val / 1024.0l));
    } else if (val < (1024.0l * 1024.0l * 1024.0l)) {
        *unit = "MiB";
        return (double)val / (1024.0l * 1024.0l);
    } else if (val < (1024.0l * 1024.0l * 1024.0l * 1024.0l)) {
        *unit = "GiB";
        return (double)val / (1024.0l * 1024.0l * 1024.0l);
    } else {
        *unit = "TiB";
        return (double)val / (1024.0l * 1024.0l * 1024.0l * 1024.0l);
    }
}

/*
 * Convert the strings separated by ',' into array. The returned
 * array is a NULL terminated string list. The caller has to free
 * the array using virStringFreeList or a similar method.
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
static void
virshErrorHandler(void *unused ATTRIBUTE_UNUSED, virErrorPtr error)
{
    virFreeError(last_error);
    last_error = virSaveLastError();
    if (virGetEnvAllowSUID("VIRSH_DEBUG") != NULL)
        virDefaultErrorFunc(error);
}

/* Store a libvirt error that is from a helper API that doesn't raise errors
 * so it doesn't get overwritten */
void
vshSaveLibvirtError(void)
{
    virFreeError(last_error);
    last_error = virSaveLastError();
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
static int disconnected = 0; /* we may have been disconnected */

/*
 * vshCatchDisconnect:
 *
 * We get here when the connection was closed.  We can't do much in the
 * handler, just save the fact it was raised.
 */
static void
vshCatchDisconnect(virConnectPtr conn ATTRIBUTE_UNUSED,
                   int reason,
                   void *opaque ATTRIBUTE_UNUSED)
{
    if (reason != VIR_CONNECT_CLOSE_REASON_CLIENT)
        disconnected++;
}

/*
 * vshReconnect:
 *
 * Reconnect after a disconnect from libvirtd
 *
 */
static void
vshReconnect(vshControl *ctl)
{
    bool connected = false;

    if (ctl->conn) {
        int ret;

        connected = true;

        virConnectUnregisterCloseCallback(ctl->conn, vshCatchDisconnect);
        ret = virConnectClose(ctl->conn);
        if (ret < 0)
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
        else if (ret > 0)
            vshError(ctl, "%s", _("One or more references were leaked after "
                                  "disconnect from the hypervisor"));
    }

    ctl->conn = virConnectOpenAuth(ctl->name,
                                   virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);
    if (!ctl->conn) {
        if (disconnected)
            vshError(ctl, "%s", _("Failed to reconnect to the hypervisor"));
        else
            vshError(ctl, "%s", _("failed to connect to the hypervisor"));
    } else {
        if (virConnectRegisterCloseCallback(ctl->conn, vshCatchDisconnect,
                                            NULL, NULL) < 0)
            vshError(ctl, "%s", _("Unable to register disconnect callback"));
        if (connected)
            vshError(ctl, "%s", _("Reconnected to the hypervisor"));
    }
    disconnected = 0;
    ctl->useGetInfo = false;
    ctl->useSnapshotOld = false;
}


/*
 * "connect" command
 */
static const vshCmdInfo info_connect[] = {
    {.name = "help",
     .data = N_("(re)connect to hypervisor")
    },
    {.name = "desc",
     .data = N_("Connect to local hypervisor. This is built-in "
                "command after shell start up.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_connect[] = {
    {.name = "name",
     .type = VSH_OT_DATA,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("hypervisor connection URI")
    },
    {.name = "readonly",
     .type = VSH_OT_BOOL,
     .help = N_("read-only connection")
    },
    {.name = NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ro = vshCommandOptBool(cmd, "readonly");
    const char *name = NULL;

    if (ctl->conn) {
        int ret;

        virConnectUnregisterCloseCallback(ctl->conn, vshCatchDisconnect);
        ret = virConnectClose(ctl->conn);
        if (ret < 0)
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
        else if (ret > 0)
            vshError(ctl, "%s", _("One or more references were leaked after "
                                  "disconnect from the hypervisor"));
        ctl->conn = NULL;
    }

    VIR_FREE(ctl->name);
    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    ctl->name = vshStrdup(ctl, name);

    ctl->useGetInfo = false;
    ctl->useSnapshotOld = false;
    ctl->readonly = ro;

    ctl->conn = virConnectOpenAuth(ctl->name, virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);

    if (!ctl->conn) {
        vshError(ctl, "%s", _("Failed to connect to the hypervisor"));
        return false;
    }

    if (virConnectRegisterCloseCallback(ctl->conn, vshCatchDisconnect,
                                        NULL, NULL) < 0)
        vshError(ctl, "%s", _("Unable to register disconnect callback"));

    return true;
}


#ifndef WIN32
static void
vshPrintRaw(vshControl *ctl, ...)
{
    va_list ap;
    char *key;

    va_start(ap, ctl);
    while ((key = va_arg(ap, char *)) != NULL) {
        vshPrint(ctl, "%s\r\n", key);
    }
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
 *         'f' if he forcibly wants to
 *         'n' if he doesn't want to
 *         -1  on error
 *          0  otherwise
 */
int
vshAskReedit(vshControl *ctl, const char *msg)
{
    int c = -1;

    if (!isatty(STDIN_FILENO))
        return -1;

    vshReportError(ctl);

    if (vshTTYMakeRaw(ctl, false) < 0)
        return -1;

    while (true) {
        /* TRANSLATORS: For now, we aren't using LC_MESSAGES, and the user
         * choices really are limited to just 'y', 'n', 'f' and '?'  */
        vshPrint(ctl, "\r%s %s", msg, _("Try again? [y,n,f,?]:"));
        c = c_tolower(getchar());

        if (c == '?') {
            vshPrintRaw(ctl,
                        "",
                        _("y - yes, start editor again"),
                        _("n - no, throw away my changes"),
                        _("f - force, try to redefine again"),
                        _("? - print this help"),
                        NULL);
            continue;
        } else if (c == 'y' || c == 'n' || c == 'f') {
            break;
        }
    }

    vshTTYRestore(ctl);

    vshPrint(ctl, "\r\n");
    return c;
}
#else /* WIN32 */
int
vshAskReedit(vshControl *ctl, const char *msg ATTRIBUTE_UNUSED)
{
    vshDebug(ctl, VSH_ERR_WARNING, "%s", _("This function is not "
                                           "supported on WIN32 platform"));
    return 0;
}
#endif /* WIN32 */

int vshStreamSink(virStreamPtr st ATTRIBUTE_UNUSED,
                  const char *bytes, size_t nbytes, void *opaque)
{
    int *fd = opaque;

    return safewrite(*fd, bytes, nbytes);
}

/* ---------------
 * Commands
 * ---------------
 */

/*
 * "help" command
 */
static const vshCmdInfo info_help[] = {
    {.name = "help",
     .data = N_("print help")
    },
    {.name = "desc",
     .data = N_("Prints global help, command specific help, or help for a\n"
                "    group of related commands")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_help[] = {
    {.name = "command",
     .type = VSH_OT_DATA,
     .help = N_("Prints global help, command specific help, or help for a group of related commands")
    },
    {.name = NULL}
};

static bool
cmdHelp(vshControl *ctl, const vshCmd *cmd)
 {
    const char *name = NULL;

    if (vshCommandOptString(cmd, "command", &name) <= 0) {
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
        editor = "vi"; /* could be cruel & default to ed(1) here */

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


/*
 * "cd" command
 */
static const vshCmdInfo info_cd[] = {
    {.name = "help",
     .data = N_("change the current directory")
    },
    {.name = "desc",
     .data = N_("Change the current directory.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_cd[] = {
    {.name = "dir",
     .type = VSH_OT_DATA,
     .help = N_("directory to switch to (default: home or else root)")
    },
    {.name = NULL}
};

static bool
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

    if (vshCommandOptString(cmd, "dir", &dir) <= 0) {
        dir = dir_malloced = virGetUserDirectory();
    }
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

/*
 * "pwd" command
 */
static const vshCmdInfo info_pwd[] = {
    {.name = "help",
     .data = N_("print the current directory")
    },
    {.name = "desc",
     .data = N_("Print the current directory.")
    },
    {.name = NULL}
};

static bool
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

/*
 * "echo" command
 */
static const vshCmdInfo info_echo[] = {
    {.name = "help",
     .data = N_("echo arguments")
    },
    {.name = "desc",
     .data = N_("Echo back arguments, possibly with quoting.")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_echo[] = {
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

/* Exists mainly for debugging virsh, but also handy for adding back
 * quotes for later evaluation.
 */
static bool
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

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        char *str;
        virBuffer xmlbuf = VIR_BUFFER_INITIALIZER;

        arg = opt->data;

        if (count)
            virBufferAddChar(&buf, ' ');

        if (xml) {
            virBufferEscapeString(&xmlbuf, "%s", arg);
            if (virBufferError(&xmlbuf)) {
                vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
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
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }
    arg = virBufferContentAndReset(&buf);
    if (arg)
        vshPrint(ctl, "%s", arg);
    VIR_FREE(arg);
    return true;
}

/*
 * "quit" command
 */
static const vshCmdInfo info_quit[] = {
    {.name = "help",
     .data = N_("quit this interactive terminal")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static bool
cmdQuit(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    ctl->imode = false;
    return true;
}

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

/* Validate that the options associated with cmd can be parsed.  */
static int
vshCmddefOptParse(const vshCmdDef *cmd, uint32_t *opts_need_arg,
                  uint32_t *opts_required)
{
    size_t i;
    bool optional = false;

    *opts_need_arg = 0;
    *opts_required = 0;

    if (!cmd->opts)
        return 0;

    for (i = 0; cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (i > 31)
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
        if (opt->flags & VSH_OFLAG_REQ_OPT) {
            if (opt->flags & VSH_OFLAG_REQ)
                *opts_required |= 1 << i;
            continue;
        }

        *opts_need_arg |= 1 << i;
        if (opt->flags & VSH_OFLAG_REQ) {
            if (optional)
                return -1; /* mandatory options must be listed first */
            *opts_required |= 1 << i;
        } else {
            optional = true;
        }

        if (opt->type == VSH_OT_ARGV && cmd->opts[i + 1].name)
            return -1; /* argv option must be listed last */
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
                   uint32_t *opts_seen, int *opt_index, char **optstr)
{
    size_t i;
    const vshCmdOptDef *ret = NULL;
    char *alias = NULL;

    if (STREQ(name, helpopt.name)) {
        return &helpopt;
    }

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
                        vshError(ctl, _("invalid '=' after option --%s"),
                                 opt->name);
                        goto cleanup;
                    }
                    if (VIR_STRDUP(*optstr, value + 1) < 0)
                        goto cleanup;
                }
                continue;
            }
            if ((*opts_seen & (1 << i)) && opt->type != VSH_OT_ARGV) {
                vshError(ctl, _("option --%s already seen"), name);
                goto cleanup;
            }
            *opts_seen |= 1 << i;
            *opt_index = i;
            ret = opt;
            goto cleanup;
        }
    }

    if (STRNEQ(cmd->name, "help")) {
        vshError(ctl, _("command '%s' doesn't support option --%s"),
                 cmd->name, name);
    }
cleanup:
    VIR_FREE(alias);
    return ret;
}

static const vshCmdOptDef *
vshCmddefGetData(const vshCmdDef *cmd, uint32_t *opts_need_arg,
                 uint32_t *opts_seen)
{
    size_t i;
    const vshCmdOptDef *opt;

    if (!*opts_need_arg)
        return NULL;

    /* Grab least-significant set bit */
    i = ffs(*opts_need_arg) - 1;
    opt = &cmd->opts[i];
    if (opt->type != VSH_OT_ARGV)
        *opts_need_arg &= ~(1 << i);
    *opts_seen |= 1 << i;
    return opt;
}

/*
 * Checks for required options
 */
static int
vshCommandCheckOpts(vshControl *ctl, const vshCmd *cmd, uint32_t opts_required,
                    uint32_t opts_seen)
{
    const vshCmdDef *def = cmd->def;
    size_t i;

    opts_required &= ~opts_seen;
    if (!opts_required)
        return 0;

    for (i = 0; def->opts[i].name; i++) {
        if (opts_required & (1 << i)) {
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

const vshCmdDef *
vshCmddefSearch(const char *cmdname)
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

    if (!def) {
        vshError(ctl, _("command '%s' doesn't exist"), cmdname);
        return false;
    } else {
        /* Don't translate desc if it is "".  */
        const char *desc = vshCmddefGetInfo(def, "desc");
        const char *help = _(vshCmddefGetInfo(def, "help"));
        char buf[256];
        uint32_t opts_need_arg;
        uint32_t opts_required;
        bool shortopt = false; /* true if 'arg' works instead of '--opt arg' */

        if (vshCmddefOptParse(def, &opts_need_arg, &opts_required)) {
            vshError(ctl, _("internal error: bad options in command: '%s'"),
                     def->name);
            return false;
        }

        fputs(_("  NAME\n"), stdout);
        fprintf(stdout, "    %s - %s\n", def->name, help);

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

        if (desc[0]) {
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
                    snprintf(buf, sizeof(buf), _("--%s <string>"), opt->name);
                    break;
                case VSH_OT_DATA:
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
    }
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
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to int
 * Return value:
 * >0 if option found and valid (@value updated)
 * 0 if option not found and not required (@value untouched)
 * <0 in all other cases (@value untouched)
 */
int
vshCommandOptInt(const vshCmd *cmd, const char *name, int *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (virStrToLong_i(arg->data, NULL, 10, value) < 0)
        return -1;
    return 1;
}


/**
 * vshCommandOptUInt:
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned int
 * See vshCommandOptInt()
 */
int
vshCommandOptUInt(const vshCmd *cmd, const char *name, unsigned int *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (virStrToLong_ui(arg->data, NULL, 10, value) < 0)
        return -1;
    return 1;
}


/*
 * vshCommandOptUL:
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Convert option to unsigned long
 * See vshCommandOptInt()
 */
int
vshCommandOptUL(const vshCmd *cmd, const char *name, unsigned long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (virStrToLong_ul(arg->data, NULL, 10, value) < 0)
        return -1;
    return 1;
}

/**
 * vshCommandOptString:
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as STRING
 * Return value:
 * >0 if option found and valid (@value updated)
 * 0 if option not found and not required (@value untouched)
 * <0 in all other cases (@value untouched)
 */
int
vshCommandOptString(const vshCmd *cmd, const char *name, const char **value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (!*arg->data && !(arg->def->flags & VSH_OFLAG_EMPTY_OK)) {
        return -1;
    }
    *value = arg->data;
    return 1;
}

/**
 * vshCommandOptStringReq:
 * @ctl virsh control structure
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
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as long long
 * See vshCommandOptInt()
 */
int
vshCommandOptLongLong(const vshCmd *cmd, const char *name,
                      long long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (virStrToLong_ll(arg->data, NULL, 10, value) < 0)
        return -1;
    return 1;
}

/**
 * vshCommandOptULongLong:
 * @cmd command reference
 * @name option name
 * @value result
 *
 * Returns option as long long
 * See vshCommandOptInt()
 */
int
vshCommandOptULongLong(const vshCmd *cmd, const char *name,
                       unsigned long long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg, true);
    if (ret <= 0)
        return ret;

    if (virStrToLong_ull(arg->data, NULL, 10, value) < 0)
        return -1;
    return 1;
}


/**
 * vshCommandOptScaledInt:
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
vshCommandOptScaledInt(const vshCmd *cmd, const char *name,
                       unsigned long long *value, int scale,
                       unsigned long long max)
{
    const char *str;
    int ret;
    char *end;

    ret = vshCommandOptString(cmd, name, &str);
    if (ret <= 0)
        return ret;
    if (virStrToLong_ull(str, &end, 10, value) < 0 ||
        virScaleInteger(value, end, scale, max) < 0)
        return -1;
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
vshCommandOptArgv(const vshCmd *cmd, const vshCmdOpt *opt)
{
    opt = opt ? opt->next : cmd->opts;

    while (opt) {
        if (opt->def->type == VSH_OT_ARGV) {
            return opt;
        }
        opt = opt->next;
    }
    return NULL;
}

/* Determine whether CMD->opts includes an option with name OPTNAME.
   If not, give a diagnostic and return false.
   If so, return true.  */
bool
vshCmdHasOption(vshControl *ctl, const vshCmd *cmd, const char *optname)
{
    /* Iterate through cmd->opts, to ensure that there is an entry
       with name OPTNAME and type VSH_OT_DATA. */
    bool found = false;
    const vshCmdOpt *opt;
    for (opt = cmd->opts; opt; opt = opt->next) {
        if (STREQ(opt->def->name, optname) && opt->def->type == VSH_OT_DATA) {
            found = true;
            break;
        }
    }

    if (!found)
        vshError(ctl, _("internal error: virsh %s: no %s VSH_OT_DATA option"),
                 cmd->def->name, optname);
    return found;
}

static bool
vshConnectionUsability(vshControl *ctl, virConnectPtr conn)
{
    if (!conn ||
        virConnectIsAlive(conn) == 0) {
        vshError(ctl, "%s", _("no valid connection"));
        return false;
    }

    /* The connection is considered dead only if
     * virConnectIsAlive() successfuly says so.
     */
    vshResetLibvirtError();

    return true;
}

/*
 * Executes command(s) and returns return code from last command
 */
static bool
vshCommandRun(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = true;

    while (cmd) {
        struct timeval before, after;
        bool enable_timing = ctl->timing;

        if ((ctl->conn == NULL || disconnected) &&
            !(cmd->def->flags & VSH_CMD_FLAG_NOCONNECT))
            vshReconnect(ctl);

        if (enable_timing)
            GETTIMEOFDAY(&before);

        if ((cmd->def->flags & VSH_CMD_FLAG_NOCONNECT) ||
            vshConnectionUsability(ctl, ctl->conn)) {
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

        if (!ret && disconnected != 0)
            vshReconnect(ctl);

        if (STREQ(cmd->def->name, "quit"))        /* hack ... */
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
                                 char **);
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
        uint32_t opts_need_arg = 0;
        uint32_t opts_required = 0;
        uint32_t opts_seen = 0;

        first = NULL;

        while (1) {
            const vshCmdOptDef *opt = NULL;

            tkdata = NULL;
            tk = parser->getNextArg(ctl, parser, &tkdata);

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
                int opt_index = 0;

                if (optstr) {
                    *optstr = '\0'; /* convert the '=' to '\0' */
                    optstr = vshStrdup(ctl, optstr + 1);
                }
                /* Special case 'help' to ignore all spurious options */
                if (!(opt = vshCmddefGetOption(ctl, cmd, tkdata + 2,
                                               &opts_seen, &opt_index,
                                               &optstr))) {
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
                        tk = parser->getNextArg(ctl, parser, &tkdata);
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
                        opts_need_arg &= ~(1 << opt_index);
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
                if (STRNEQ(tmpopt->def->name, "help"))
                    continue;

                vshCommandOptFree(first);
                first = vshMalloc(ctl, sizeof(vshCmdOpt));
                first->def = &(opts_help[0]);
                first->data = vshStrdup(ctl, cmd->name);
                first->next = NULL;

                cmd = vshCmddefSearch("help");
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
vshCommandArgvGetArg(vshControl *ctl, vshCommandParser *parser, char **res)
{
    if (parser->arg_pos == parser->arg_end) {
        *res = NULL;
        return VSH_TK_END;
    }

    *res = vshStrdup(ctl, *parser->arg_pos);
    parser->arg_pos++;
    return VSH_TK_ARG;
}

static bool
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
vshCommandStringGetArg(vshControl *ctl, vshCommandParser *parser, char **res)
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
        vshError(ctl, "%s", _("missing \""));
        return VSH_TK_ERROR;
    }

    *q = '\0';
    parser->pos = p;
    return VSH_TK_ARG;
}

static bool
vshCommandStringParse(vshControl *ctl, char *cmdstr)
{
    vshCommandParser parser;

    if (cmdstr == NULL || *cmdstr == '\0')
        return false;

    parser.pos = cmdstr;
    parser.getNextArg = vshCommandStringGetArg;
    return vshCommandParse(ctl, &parser);
}

/* ---------------
 * Misc utils
 * ---------------
 */
int
vshDomainState(vshControl *ctl, virDomainPtr dom, int *reason)
{
    virDomainInfo info;

    if (reason)
        *reason = -1;

    if (!ctl->useGetInfo) {
        int state;
        if (virDomainGetState(dom, &state, reason, 0) < 0) {
            virErrorPtr err = virGetLastError();
            if (err && err->code == VIR_ERR_NO_SUPPORT)
                ctl->useGetInfo = true;
            else
                return -1;
        } else {
            return state;
        }
    }

    /* fall back to virDomainGetInfo if virDomainGetState is not supported */
    if (virDomainGetInfo(dom, &info) < 0)
        return -1;
    else
        return info.state;
}

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
    if (virVasprintf(&str, format, ap) < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        va_end(ap);
        return;
    }
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


static void
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
 * Initialize debug settings.
 */
static void
vshInitDebug(vshControl *ctl)
{
    const char *debugEnv;

    if (ctl->debug == VSH_DEBUG_DEFAULT) {
        /* log level not set from commandline, check env variable */
        debugEnv = virGetEnvAllowSUID("VIRSH_DEBUG");
        if (debugEnv) {
            int debug;
            if (virStrToLong_i(debugEnv, NULL, 10, &debug) < 0 ||
                debug < VSH_ERR_DEBUG || debug > VSH_ERR_ERROR) {
                vshError(ctl, "%s",
                         _("VIRSH_DEBUG not set with a valid numeric value"));
            } else {
                ctl->debug = debug;
            }
        }
    }

    if (ctl->logfile == NULL) {
        /* log file not set from cmdline */
        debugEnv = virGetEnvBlockSUID("VIRSH_LOG_FILE");
        if (debugEnv && *debugEnv) {
            ctl->logfile = vshStrdup(ctl, debugEnv);
            vshOpenLogFile(ctl);
        }
    }
}

/*
 * Initialize connection.
 */
static bool
vshInit(vshControl *ctl)
{
    /* Since we have the commandline arguments parsed, we need to
     * re-initialize all the debugging to make it work properly */
    vshInitDebug(ctl);

    if (ctl->conn)
        return false;

    /* set up the library error handler */
    virSetErrorFunc(NULL, virshErrorHandler);

    if (virEventRegisterDefaultImpl() < 0)
        return false;

    if (virThreadCreate(&ctl->eventLoop, true, vshEventLoop, ctl) < 0)
        return false;
    ctl->eventLoopStarted = true;

    if (ctl->name) {
        vshReconnect(ctl);
        /* Connecting to a named connection must succeed, but we delay
         * connecting to the default connection until we need it
         * (since the first command might be 'connect' which allows a
         * non-default connection, or might be 'help' which needs no
         * connection).
         */
        if (!ctl->conn) {
            vshReportError(ctl);
            return false;
        }
    }

    return true;
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
    struct stat st;

    if (ctl->logfile == NULL)
        return;

    /* check log file */
    if (stat(ctl->logfile, &st) == -1) {
        switch (errno) {
            case ENOENT:
                break;
            default:
                vshError(ctl, "%s",
                         _("failed to get the log file information"));
                exit(EXIT_FAILURE);
        }
    } else {
        if (!S_ISREG(st.st_mode)) {
            vshError(ctl, "%s", _("the log path is not a file"));
            exit(EXIT_FAILURE);
        }
    }

    /* log file open */
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
                      SIGN_NAME,
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
    virBufferAddChar(&buf, '\n');

    if (virBufferError(&buf))
        goto error;

    str = virBufferContentAndReset(&buf);
    len = strlen(str);
    if (len > 1 && str[len - 2] == '\n') {
        str[len - 1] = '\0';
        len--;
    }

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
    static int grp_list_index, cmd_list_index, len;
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
                cmd_list_index++;

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
vshReadlineOptionsGenerator(const char *text, int state)
{
    static int list_index, len;
    static const vshCmdDef *cmd = NULL;
    const char *name;

    if (!state) {
        /* determine command name */
        char *p;
        char *cmdname;

        if (!(p = strchr(rl_line_buffer, ' ')))
            return NULL;

        cmdname = vshCalloc(NULL, (p - rl_line_buffer) + 1, 1);
        memcpy(cmdname, rl_line_buffer, p - rl_line_buffer);

        cmd = vshCmddefSearch(cmdname);
        list_index = 0;
        len = strlen(text);
        VIR_FREE(cmdname);
    }

    if (!cmd)
        return NULL;

    if (!cmd->opts)
        return NULL;

    while ((name = cmd->opts[list_index].name)) {
        const vshCmdOptDef *opt = &cmd->opts[list_index];
        char *res;

        list_index++;

        if (opt->type == VSH_OT_DATA || opt->type == VSH_OT_ARGV)
            /* ignore non --option */
            continue;

        if (len > 2) {
            if (STRNEQLEN(name, text + 2, len - 2))
                continue;
        }
        res = vshMalloc(NULL, strlen(name) + 3);
        snprintf(res, strlen(name) + 3,  "--%s", name);
        return res;
    }

    /* If no names matched, then return NULL. */
    return NULL;
}

static char **
vshReadlineCompletion(const char *text, int start,
                      int end ATTRIBUTE_UNUSED)
{
    char **matches = (char **) NULL;

    if (start == 0)
        /* command name generator */
        matches = rl_completion_matches(text, vshReadlineCommandGenerator);
    else
        /* commands options */
        matches = rl_completion_matches(text, vshReadlineOptionsGenerator);
    return matches;
}

# define VIRSH_HISTSIZE_MAX 500000

static int
vshReadlineInit(vshControl *ctl)
{
    char *userdir = NULL;
    int max_history = 500;
    const char *histsize_str;

    /* Allow conditional parsing of the ~/.inputrc file.
     * Work around ancient readline 4.1 (hello Mac OS X),
     * which declared it as 'char *' instead of 'const char *'.
     */
    rl_readline_name = (char *) "virsh";

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = vshReadlineCompletion;

    /* Limit the total size of the history buffer */
    if ((histsize_str = virGetEnvBlockSUID("VIRSH_HISTSIZE"))) {
        if (virStrToLong_i(histsize_str, NULL, 10, &max_history) < 0) {
            vshError(ctl, "%s", _("Bad $VIRSH_HISTSIZE value."));
            VIR_FREE(userdir);
            return -1;
        } else if (max_history > VIRSH_HISTSIZE_MAX || max_history < 0) {
            vshError(ctl, _("$VIRSH_HISTSIZE value should be between 0 and %d"),
                     VIRSH_HISTSIZE_MAX);
            VIR_FREE(userdir);
            return -1;
        }
    }
    stifle_history(max_history);

    /* Prepare to read/write history from/to the $XDG_CACHE_HOME/virsh/history file */
    userdir = virGetUserCacheDirectory();

    if (userdir == NULL) {
        vshError(ctl, "%s", _("Could not determine home directory"));
        return -1;
    }

    if (virAsprintf(&ctl->historydir, "%s/virsh", userdir) < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        VIR_FREE(userdir);
        return -1;
    }

    if (virAsprintf(&ctl->historyfile, "%s/history", ctl->historydir) < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        VIR_FREE(userdir);
        return -1;
    }

    VIR_FREE(userdir);

    read_history(ctl->historyfile);

    return 0;
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

static char *
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

static char *
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

static void
vshDeinitTimer(int timer ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}

/*
 * Deinitialize virsh
 */
static bool
vshDeinit(vshControl *ctl)
{
    vshReadlineDeinit(ctl);
    vshCloseLogFile(ctl);
    VIR_FREE(ctl->name);
    if (ctl->conn) {
        int ret;
        virConnectUnregisterCloseCallback(ctl->conn, vshCatchDisconnect);
        ret = virConnectClose(ctl->conn);
        if (ret < 0)
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
        else if (ret > 0)
            vshError(ctl, "%s", _("One or more references were leaked after "
                                  "disconnect from the hypervisor"));
    }
    virResetLastError();

    if (ctl->eventLoopStarted) {
        int timer;

        virMutexLock(&ctl->lock);
        ctl->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, vshDeinitTimer, NULL, NULL);
        virMutexUnlock(&ctl->lock);

        virThreadJoin(&ctl->eventLoop);

        if (timer != -1)
            virEventRemoveTimeout(timer);

        ctl->eventLoopStarted = false;
    }

    virMutexDestroy(&ctl->lock);

    return true;
}

/*
 * Print usage
 */
static void
vshUsage(void)
{
    const vshCmdGrp *grp;
    const vshCmdDef *cmd;

    fprintf(stdout, _("\n%s [options]... [<command_string>]"
                      "\n%s [options]... <command> [args...]\n\n"
                      "  options:\n"
                      "    -c | --connect=URI      hypervisor connection URI\n"
                      "    -r | --readonly         connect readonly\n"
                      "    -d | --debug=NUM        debug level [0-4]\n"
                      "    -h | --help             this help\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -t | --timing           print timing information\n"
                      "    -l | --log=FILE         output logging to file\n"
                      "    -v                      short version\n"
                      "    -V                      long version\n"
                      "         --version[=TYPE]   version, TYPE is short or long (default short)\n"
                      "    -e | --escape <char>    set escape sequence for console\n\n"
                      "  commands (non interactive mode):\n\n"), progname, progname);

    for (grp = cmdGroups; grp->name; grp++) {
        fprintf(stdout, _(" %s (help keyword '%s')\n"),
                grp->name, grp->keyword);
        for (cmd = grp->commands; cmd->name; cmd++) {
            if (cmd->flags & VSH_CMD_FLAG_ALIAS)
                continue;
            fprintf(stdout,
                    "    %-30s %s\n", cmd->name,
                    _(vshCmddefGetInfo(cmd, "help")));
        }
        fprintf(stdout, "\n");
    }

    fprintf(stdout, "%s",
            _("\n  (specify help <group> for details about the commands in the group)\n"));
    fprintf(stdout, "%s",
            _("\n  (specify help <command> for details about the command)\n\n"));
    return;
}

/*
 * Show version and options compiled in
 */
static void
vshShowVersion(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* FIXME - list a copyright blurb, as in GNU programs?  */
    vshPrint(ctl, _("Virsh command line tool of libvirt %s\n"), VERSION);
    vshPrint(ctl, _("See web site at %s\n\n"), "http://libvirt.org/");

    vshPrint(ctl, "%s", _("Compiled with support for:\n"));
    vshPrint(ctl, "%s", _(" Hypervisors:"));
#ifdef WITH_QEMU
    vshPrint(ctl, " QEMU/KVM");
#endif
#ifdef WITH_LXC
    vshPrint(ctl, " LXC");
#endif
#ifdef WITH_UML
    vshPrint(ctl, " UML");
#endif
#ifdef WITH_XEN
    vshPrint(ctl, " Xen");
#endif
#ifdef WITH_LIBXL
    vshPrint(ctl, " LibXL");
#endif
#ifdef WITH_OPENVZ
    vshPrint(ctl, " OpenVZ");
#endif
#ifdef WITH_VMWARE
    vshPrint(ctl, " VMWare");
#endif
#ifdef WITH_PHYP
    vshPrint(ctl, " PHYP");
#endif
#ifdef WITH_VBOX
    vshPrint(ctl, " VirtualBox");
#endif
#ifdef WITH_ESX
    vshPrint(ctl, " ESX");
#endif
#ifdef WITH_HYPERV
    vshPrint(ctl, " Hyper-V");
#endif
#ifdef WITH_XENAPI
    vshPrint(ctl, " XenAPI");
#endif
#ifdef WITH_TEST
    vshPrint(ctl, " Test");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Networking:"));
#ifdef WITH_REMOTE
    vshPrint(ctl, " Remote");
#endif
#ifdef WITH_NETWORK
    vshPrint(ctl, " Network");
#endif
#ifdef WITH_BRIDGE
    vshPrint(ctl, " Bridging");
#endif
#if defined(WITH_INTERFACE)
    vshPrint(ctl, " Interface");
# if defined(WITH_NETCF)
    vshPrint(ctl, " netcf");
# elif defined(WITH_UDEV)
    vshPrint(ctl, " udev");
# endif
#endif
#ifdef WITH_NWFILTER
    vshPrint(ctl, " Nwfilter");
#endif
#ifdef WITH_VIRTUALPORT
    vshPrint(ctl, " VirtualPort");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Storage:"));
#ifdef WITH_STORAGE_DIR
    vshPrint(ctl, " Dir");
#endif
#ifdef WITH_STORAGE_DISK
    vshPrint(ctl, " Disk");
#endif
#ifdef WITH_STORAGE_FS
    vshPrint(ctl, " Filesystem");
#endif
#ifdef WITH_STORAGE_SCSI
    vshPrint(ctl, " SCSI");
#endif
#ifdef WITH_STORAGE_MPATH
    vshPrint(ctl, " Multipath");
#endif
#ifdef WITH_STORAGE_ISCSI
    vshPrint(ctl, " iSCSI");
#endif
#ifdef WITH_STORAGE_LVM
    vshPrint(ctl, " LVM");
#endif
#ifdef WITH_STORAGE_RBD
    vshPrint(ctl, " RBD");
#endif
#ifdef WITH_STORAGE_SHEEPDOG
    vshPrint(ctl, " Sheepdog");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Miscellaneous:"));
#ifdef WITH_LIBVIRTD
    vshPrint(ctl, " Daemon");
#endif
#ifdef WITH_NODE_DEVICES
    vshPrint(ctl, " Nodedev");
#endif
#ifdef WITH_SECDRIVER_APPARMOR
    vshPrint(ctl, " AppArmor");
#endif
#ifdef WITH_SECDRIVER_SELINUX
    vshPrint(ctl, " SELinux");
#endif
#ifdef WITH_SECRETS
    vshPrint(ctl, " Secrets");
#endif
#ifdef ENABLE_DEBUG
    vshPrint(ctl, " Debug");
#endif
#ifdef WITH_DTRACE_PROBES
    vshPrint(ctl, " DTrace");
#endif
#if WITH_READLINE
    vshPrint(ctl, " Readline");
#endif
#ifdef WITH_DRIVER_MODULES
    vshPrint(ctl, " Modular");
#endif
    vshPrint(ctl, "\n");
}

static bool
vshAllowedEscapeChar(char c)
{
    /* Allowed escape characters:
     * a-z A-Z @ [ \ ] ^ _
     */
    return ('a' <= c && c <= 'z') ||
        ('@' <= c && c <= '_');
}

/*
 * argv[]:  virsh [options] [command]
 *
 */
static bool
vshParseArgv(vshControl *ctl, int argc, char **argv)
{
    int arg, len, debug;
    size_t i;
    int longindex = -1;
    struct option opt[] = {
        {"debug", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"quiet", no_argument, NULL, 'q'},
        {"timing", no_argument, NULL, 't'},
        {"version", optional_argument, NULL, 'v'},
        {"connect", required_argument, NULL, 'c'},
        {"readonly", no_argument, NULL, 'r'},
        {"log", required_argument, NULL, 'l'},
        {"escape", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0}
    };

    /* Standard (non-command) options. The leading + ensures that no
     * argument reordering takes place, so that command options are
     * not confused with top-level virsh options. */
    while ((arg = getopt_long(argc, argv, "+:d:hqtc:vVrl:e:", opt, &longindex)) != -1) {
        switch (arg) {
        case 'd':
            if (virStrToLong_i(optarg, NULL, 10, &debug) < 0) {
                vshError(ctl, _("option %s takes a numeric argument"),
                         longindex == -1 ? "-d" : "--debug");
                exit(EXIT_FAILURE);
            }
            if (debug < VSH_ERR_DEBUG || debug > VSH_ERR_ERROR)
                vshError(ctl, _("ignoring debug level %d out of range [%d-%d]"),
                         debug, VSH_ERR_DEBUG, VSH_ERR_ERROR);
            else
                ctl->debug = debug;
            break;
        case 'h':
            vshUsage();
            exit(EXIT_SUCCESS);
            break;
        case 'q':
            ctl->quiet = true;
            break;
        case 't':
            ctl->timing = true;
            break;
        case 'c':
            VIR_FREE(ctl->name);
            ctl->name = vshStrdup(ctl, optarg);
            break;
        case 'v':
            if (STRNEQ_NULLABLE(optarg, "long")) {
                puts(VERSION);
                exit(EXIT_SUCCESS);
            }
            /* fall through */
        case 'V':
            vshShowVersion(ctl);
            exit(EXIT_SUCCESS);
        case 'r':
            ctl->readonly = true;
            break;
        case 'l':
            vshCloseLogFile(ctl);
            ctl->logfile = vshStrdup(ctl, optarg);
            vshOpenLogFile(ctl);
            break;
        case 'e':
            len = strlen(optarg);

            if ((len == 2 && *optarg == '^' &&
                 vshAllowedEscapeChar(optarg[1])) ||
                (len == 1 && *optarg != '^')) {
                ctl->escapeChar = optarg;
            } else {
                vshError(ctl, _("Invalid string '%s' for escape sequence"),
                         optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case ':':
            for (i = 0; opt[i].name != NULL; i++) {
                if (opt[i].val == optopt)
                    break;
            }
            if (opt[i].name)
                vshError(ctl, _("option '-%c'/'--%s' requires an argument"),
                         optopt, opt[i].name);
            else
                vshError(ctl, _("option '-%c' requires an argument"), optopt);
            exit(EXIT_FAILURE);
        case '?':
            if (optopt)
                vshError(ctl, _("unsupported option '-%c'. See --help."), optopt);
            else
                vshError(ctl, _("unsupported option '%s'. See --help."), argv[optind - 1]);
            exit(EXIT_FAILURE);
        default:
            vshError(ctl, _("unknown option"));
            exit(EXIT_FAILURE);
        }
        longindex = -1;
    }

    if (argc > optind) {
        /* parse command */
        ctl->imode = false;
        if (argc - optind == 1) {
            vshDebug(ctl, VSH_ERR_INFO, "commands: \"%s\"\n", argv[optind]);
            return vshCommandStringParse(ctl, argv[optind]);
        } else {
            return vshCommandArgvParse(ctl, argc - optind, argv + optind);
        }
    }
    return true;
}

static const vshCmdDef virshCmds[] = {
    {.name = "cd",
     .handler = cmdCd,
     .opts = opts_cd,
     .info = info_cd,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "connect",
     .handler = cmdConnect,
     .opts = opts_connect,
     .info = info_connect,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "echo",
     .handler = cmdEcho,
     .opts = opts_echo,
     .info = info_echo,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "exit",
     .handler = cmdQuit,
     .opts = NULL,
     .info = info_quit,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "help",
     .handler = cmdHelp,
     .opts = opts_help,
     .info = info_help,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "pwd",
     .handler = cmdPwd,
     .opts = NULL,
     .info = info_pwd,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = "quit",
     .handler = cmdQuit,
     .opts = NULL,
     .info = info_quit,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = NULL}
};

static const vshCmdGrp cmdGroups[] = {
    {VSH_CMD_GRP_DOM_MANAGEMENT, "domain", domManagementCmds},
    {VSH_CMD_GRP_DOM_MONITORING, "monitor", domMonitoringCmds},
    {VSH_CMD_GRP_HOST_AND_HV, "host", hostAndHypervisorCmds},
    {VSH_CMD_GRP_IFACE, "interface", ifaceCmds},
    {VSH_CMD_GRP_NWFILTER, "filter", nwfilterCmds},
    {VSH_CMD_GRP_NETWORK, "network", networkCmds},
    {VSH_CMD_GRP_NODEDEV, "nodedev", nodedevCmds},
    {VSH_CMD_GRP_SECRET, "secret", secretCmds},
    {VSH_CMD_GRP_SNAPSHOT, "snapshot", snapshotCmds},
    {VSH_CMD_GRP_STORAGE_POOL, "pool", storagePoolCmds},
    {VSH_CMD_GRP_STORAGE_VOL, "volume", storageVolCmds},
    {VSH_CMD_GRP_VIRSH, "virsh", virshCmds},
    {NULL, NULL, NULL}
};

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    const char *defaultConn;
    bool ret = true;

    memset(ctl, 0, sizeof(vshControl));
    ctl->imode = true;          /* default is interactive mode */
    ctl->log_fd = -1;           /* Initialize log file descriptor */
    ctl->debug = VSH_DEBUG_DEFAULT;
    ctl->escapeChar = "^]";     /* Same default as telnet */


    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
        /* failure to setup locale is not fatal */
    }
    if (!bindtextdomain(PACKAGE, LOCALEDIR)) {
        perror("bindtextdomain");
        return EXIT_FAILURE;
    }
    if (!textdomain(PACKAGE)) {
        perror("textdomain");
        return EXIT_FAILURE;
    }

    if (isatty(STDIN_FILENO)) {
        ctl->istty = true;

#ifndef WIN32
        if (tcgetattr(STDIN_FILENO, &ctl->termattr) < 0)
            ctl->istty = false;
#endif
    }

    if (virMutexInit(&ctl->lock) < 0) {
        vshError(ctl, "%s", _("Failed to initialize mutex"));
        return EXIT_FAILURE;
    }

    if (virInitialize() < 0) {
        vshError(ctl, "%s", _("Failed to initialize libvirt"));
        return EXIT_FAILURE;
    }

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    if ((defaultConn = virGetEnvBlockSUID("VIRSH_DEFAULT_CONNECT_URI"))) {
        ctl->name = vshStrdup(ctl, defaultConn);
    }

    vshInitDebug(ctl);

    if (!vshParseArgv(ctl, argc, argv) ||
        !vshInit(ctl)) {
        vshDeinit(ctl);
        exit(EXIT_FAILURE);
    }

    if (!ctl->imode) {
        ret = vshCommandRun(ctl, ctl->cmd);
    } else {
        /* interactive mode */
        if (!ctl->quiet) {
            vshPrint(ctl,
                     _("Welcome to %s, the virtualization interactive terminal.\n\n"),
                     progname);
            vshPrint(ctl, "%s",
                     _("Type:  'help' for help with commands\n"
                       "       'quit' to quit\n\n"));
        }

        if (vshReadlineInit(ctl) < 0) {
            vshDeinit(ctl);
            exit(EXIT_FAILURE);
        }

        do {
            const char *prompt = ctl->readonly ? VSH_PROMPT_RO : VSH_PROMPT_RW;
            ctl->cmdstr =
                vshReadline(ctl, prompt);
            if (ctl->cmdstr == NULL)
                break;          /* EOF */
            if (*ctl->cmdstr) {
#if WITH_READLINE
                add_history(ctl->cmdstr);
#endif
                if (vshCommandStringParse(ctl, ctl->cmdstr))
                    vshCommandRun(ctl, ctl->cmd);
            }
            VIR_FREE(ctl->cmdstr);
        } while (ctl->imode);

        if (ctl->cmdstr == NULL)
            fputc('\n', stdout);        /* line break after alone prompt */
    }

    vshDeinit(ctl);
    exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
