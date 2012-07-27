/*
 * virsh.c: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Daniel Veillard <veillard@redhat.com>
 * Karel Zak <kzak@redhat.com>
 * Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "c-ctype.h"
#include <fcntl.h>
#include <locale.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <signal.h>
#include <poll.h>
#include <strings.h>
#include <termios.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#ifdef HAVE_READLINE_READLINE_H
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "virterror_internal.h"
#include "base64.h"
#include "buf.h"
#include "console.h"
#include "util.h"
#include "memory.h"
#include "xml.h"
#include "libvirt/libvirt-qemu.h"
#include "virfile.h"
#include "event_poll.h"
#include "configmake.h"
#include "threads.h"
#include "command.h"
#include "virkeycode.h"
#include "virnetdevbandwidth.h"
#include "util/bitmap.h"
#include "conf/domain_conf.h"
#include "virtypedparam.h"
#include "conf/virdomainlist.h"

static char *progname;

#define VIRSH_MAX_XML_FILE 10*1024*1024

#define VSH_PROMPT_RW    "virsh # "
#define VSH_PROMPT_RO    "virsh > "

#define VIR_FROM_THIS VIR_FROM_NONE

#define GETTIMEOFDAY(T) gettimeofday(T, NULL)
#define DIFF_MSEC(T, U) \
        ((((int) ((T)->tv_sec - (U)->tv_sec)) * 1000000.0 + \
          ((int) ((T)->tv_usec - (U)->tv_usec))) / 1000.0)

/* Default escape char Ctrl-] as per telnet */
#define CTRL_CLOSE_BRACKET "^]"

/**
 * The log configuration
 */
#define MSG_BUFFER    4096
#define SIGN_NAME     "virsh"
#define DIR_MODE      (S_IWUSR | S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)  /* 0755 */
#define FILE_MODE     (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)                                /* 0644 */
#define LOCK_MODE     (S_IWUSR | S_IRUSR)                                                    /* 0600 */
#define LVL_DEBUG     "DEBUG"
#define LVL_INFO      "INFO"
#define LVL_NOTICE    "NOTICE"
#define LVL_WARNING   "WARNING"
#define LVL_ERROR     "ERROR"

/**
 * vshErrorLevel:
 *
 * Indicates the level of a log message
 */
typedef enum {
    VSH_ERR_DEBUG = 0,
    VSH_ERR_INFO,
    VSH_ERR_NOTICE,
    VSH_ERR_WARNING,
    VSH_ERR_ERROR
} vshErrorLevel;

#define VSH_DEBUG_DEFAULT VSH_ERR_ERROR

/*
 * virsh command line grammar:
 *
 *    command_line    =     <command>\n | <command>; <command>; ...
 *
 *    command         =    <keyword> <option> [--] <data>
 *
 *    option          =     <bool_option> | <int_option> | <string_option>
 *    data            =     <string>
 *
 *    bool_option     =     --optionname
 *    int_option      =     --optionname <number> | --optionname=<number>
 *    string_option   =     --optionname <string> | --optionname=<string>
 *
 *    keyword         =     [a-zA-Z][a-zA-Z-]*
 *    number          =     [0-9]+
 *    string          =     ('[^']*'|"([^\\"]|\\.)*"|([^ \t\n\\'"]|\\.))+
 *
 */

/*
 * vshCmdOptType - command option type
 */
typedef enum {
    VSH_OT_BOOL,     /* optional boolean option */
    VSH_OT_STRING,   /* optional string option */
    VSH_OT_INT,      /* optional or mandatory int option */
    VSH_OT_DATA,     /* string data (as non-option) */
    VSH_OT_ARGV,     /* remaining arguments */
    VSH_OT_ALIAS,    /* alternate spelling for a later argument */
} vshCmdOptType;

/*
 * Command group types
 */
#define VSH_CMD_GRP_DOM_MANAGEMENT   "Domain Management"
#define VSH_CMD_GRP_DOM_MONITORING   "Domain Monitoring"
#define VSH_CMD_GRP_STORAGE_POOL     "Storage Pool"
#define VSH_CMD_GRP_STORAGE_VOL      "Storage Volume"
#define VSH_CMD_GRP_NETWORK          "Networking"
#define VSH_CMD_GRP_NODEDEV          "Node Device"
#define VSH_CMD_GRP_IFACE            "Interface"
#define VSH_CMD_GRP_NWFILTER         "Network Filter"
#define VSH_CMD_GRP_SECRET           "Secret"
#define VSH_CMD_GRP_SNAPSHOT         "Snapshot"
#define VSH_CMD_GRP_HOST_AND_HV      "Host and Hypervisor"
#define VSH_CMD_GRP_VIRSH            "Virsh itself"

/*
 * Command Option Flags
 */
enum {
    VSH_OFLAG_NONE     = 0,        /* without flags */
    VSH_OFLAG_REQ      = (1 << 0), /* option required */
    VSH_OFLAG_EMPTY_OK = (1 << 1), /* empty string option allowed */
    VSH_OFLAG_REQ_OPT  = (1 << 2), /* --optionname required */
};

/* dummy */
typedef struct __vshControl vshControl;
typedef struct __vshCmd vshCmd;

/*
 * vshCmdInfo -- name/value pair for information about command
 *
 * Commands should have at least the following names:
 * "name" - command name
 * "desc" - description of command, or empty string
 */
typedef struct {
    const char *name;           /* name of information, or NULL for list end */
    const char *data;           /* non-NULL information */
} vshCmdInfo;

/*
 * vshCmdOptDef - command option definition
 */
typedef struct {
    const char *name;           /* the name of option, or NULL for list end */
    vshCmdOptType type;         /* option type */
    unsigned int flags;         /* flags */
    const char *help;           /* non-NULL help string; or for VSH_OT_ALIAS
                                 * the name of a later public option */
} vshCmdOptDef;

/*
 * vshCmdOpt - command options
 *
 * After parsing a command, all arguments to the command have been
 * collected into a list of these objects.
 */
typedef struct vshCmdOpt {
    const vshCmdOptDef *def;    /* non-NULL pointer to option definition */
    char *data;                 /* allocated data, or NULL for bool option */
    struct vshCmdOpt *next;
} vshCmdOpt;

/*
 * Command Usage Flags
 */
enum {
    VSH_CMD_FLAG_NOCONNECT = (1 << 0),  /* no prior connection needed */
    VSH_CMD_FLAG_ALIAS     = (1 << 1),  /* command is an alias */
};

/*
 * vshCmdDef - command definition
 */
typedef struct {
    const char *name;           /* name of command, or NULL for list end */
    bool (*handler) (vshControl *, const vshCmd *);    /* command handler */
    const vshCmdOptDef *opts;   /* definition of command options */
    const vshCmdInfo *info;     /* details about command */
    unsigned int flags;         /* bitwise OR of VSH_CMD_FLAG */
} vshCmdDef;

/*
 * vshCmd - parsed command
 */
typedef struct __vshCmd {
    const vshCmdDef *def;       /* command definition */
    vshCmdOpt *opts;            /* list of command arguments */
    struct __vshCmd *next;      /* next command */
} __vshCmd;

/*
 * vshControl
 */
typedef struct __vshControl {
    char *name;                 /* connection name */
    virConnectPtr conn;         /* connection to hypervisor (MAY BE NULL) */
    vshCmd *cmd;                /* the current command */
    char *cmdstr;               /* string with command */
    bool imode;                 /* interactive mode? */
    bool quiet;                 /* quiet mode */
    int debug;                  /* print debug messages? */
    bool timing;                /* print timing info? */
    bool readonly;              /* connect readonly (first time only, not
                                 * during explicit connect command)
                                 */
    char *logfile;              /* log file name */
    int log_fd;                 /* log file descriptor */
    char *historydir;           /* readline history directory name */
    char *historyfile;          /* readline history file name */
    bool useGetInfo;            /* must use virDomainGetInfo, since
                                   virDomainGetState is not supported */
    bool useSnapshotOld;        /* cannot use virDomainSnapshotGetParent or
                                   virDomainSnapshotNumChildren */
    virThread eventLoop;
    virMutex lock;
    bool eventLoopStarted;
    bool quit;

    const char *escapeChar;     /* String representation of
                                   console escape character */
} __vshControl;

typedef struct vshCmdGrp {
    const char *name;    /* name of group, or NULL for list end */
    const char *keyword; /* help keyword */
    const vshCmdDef *commands;
} vshCmdGrp;

static const vshCmdGrp cmdGroups[];

static void vshError(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
static bool vshInit(vshControl *ctl);
static bool vshDeinit(vshControl *ctl);
static void vshUsage(void);
static void vshOpenLogFile(vshControl *ctl);
static void vshOutputLogFile(vshControl *ctl, int log_level, const char *format, va_list ap)
    ATTRIBUTE_FMT_PRINTF(3, 0);
static void vshCloseLogFile(vshControl *ctl);

static bool vshParseArgv(vshControl *ctl, int argc, char **argv);

static const char *vshCmddefGetInfo(const vshCmdDef *cmd, const char *info);
static const vshCmdDef *vshCmddefSearch(const char *cmdname);
static bool vshCmddefHelp(vshControl *ctl, const char *name);
static const vshCmdGrp *vshCmdGrpSearch(const char *grpname);
static bool vshCmdGrpHelp(vshControl *ctl, const char *name);

static int vshCommandOpt(const vshCmd *cmd, const char *name, vshCmdOpt **opt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptInt(const vshCmd *cmd, const char *name, int *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptUInt(const vshCmd *cmd, const char *name,
                             unsigned int *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptUL(const vshCmd *cmd, const char *name,
                           unsigned long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptString(const vshCmd *cmd, const char *name,
                               const char **value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptLongLong(const vshCmd *cmd, const char *name,
                                 long long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptULongLong(const vshCmd *cmd, const char *name,
                                  unsigned long long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static int vshCommandOptScaledInt(const vshCmd *cmd, const char *name,
                                  unsigned long long *value, int scale,
                                  unsigned long long max)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
static bool vshCommandOptBool(const vshCmd *cmd, const char *name);
static const vshCmdOpt *vshCommandOptArgv(const vshCmd *cmd,
                                          const vshCmdOpt *opt);
static char *vshGetDomainDescription(vshControl *ctl, virDomainPtr dom,
                                     bool title, unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

#define VSH_BYID     (1 << 1)
#define VSH_BYUUID   (1 << 2)
#define VSH_BYNAME   (1 << 3)
#define VSH_BYMAC    (1 << 4)

static virDomainPtr vshCommandOptDomainBy(vshControl *ctl, const vshCmd *cmd,
                                          const char **name, int flag);

/* default is lookup by Id, Name and UUID */
#define vshCommandOptDomain(_ctl, _cmd, _name)                      \
    vshCommandOptDomainBy(_ctl, _cmd, _name, VSH_BYID|VSH_BYUUID|VSH_BYNAME)

static void vshPrintExtra(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
static void vshDebug(vshControl *ctl, int level, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(3, 4);

/* XXX: add batch support */
#define vshPrint(_ctl, ...)   vshPrintExtra(NULL, __VA_ARGS__)

static int vshDomainState(vshControl *ctl, virDomainPtr dom, int *reason);
static const char *vshDomainStateToString(int state);
static const char *vshDomainStateReasonToString(int state, int reason);
static const char *vshDomainControlStateToString(int state);
static const char *vshDomainVcpuStateToString(int state);
static bool vshConnectionUsability(vshControl *ctl, virConnectPtr conn);
static virTypedParameterPtr vshFindTypedParamByName(const char *name,
                                                    virTypedParameterPtr list,
                                                    int count);
static char *vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

static char *editWriteToTempFile(vshControl *ctl, const char *doc);
static int   editFile(vshControl *ctl, const char *filename);
static char *editReadBackFile(vshControl *ctl, const char *filename);

/* Typedefs, function prototypes for job progress reporting.
 * There are used by some long lingering commands like
 * migrate, dump, save, managedsave.
 */
typedef struct __vshCtrlData {
    vshControl *ctl;
    const vshCmd *cmd;
    int writefd;
} vshCtrlData;

typedef void (*jobWatchTimeoutFunc) (vshControl *ctl, virDomainPtr dom,
                                     void *opaque);

static bool
vshWatchJob(vshControl *ctl,
            virDomainPtr dom,
            bool verbose,
            int pipe_fd,
            int timeout,
            jobWatchTimeoutFunc timeout_func,
            void *opaque,
            const char *label);

static void *_vshMalloc(vshControl *ctl, size_t sz, const char *filename, int line);
#define vshMalloc(_ctl, _sz)    _vshMalloc(_ctl, _sz, __FILE__, __LINE__)

static void *_vshCalloc(vshControl *ctl, size_t nmemb, size_t sz, const char *filename, int line);
#define vshCalloc(_ctl, _nmemb, _sz)    _vshCalloc(_ctl, _nmemb, _sz, __FILE__, __LINE__)

static char *_vshStrdup(vshControl *ctl, const char *s, const char *filename, int line);
#define vshStrdup(_ctl, _s)    _vshStrdup(_ctl, _s, __FILE__, __LINE__)

static int parseRateStr(const char *rateStr, virNetDevBandwidthRatePtr rate);

static void *
_vshMalloc(vshControl *ctl, size_t size, const char *filename, int line)
{
    char *x;

    if (VIR_ALLOC_N(x, size) == 0)
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) size);
    exit(EXIT_FAILURE);
}

static void *
_vshCalloc(vshControl *ctl, size_t nmemb, size_t size, const char *filename, int line)
{
    char *x;

    if (!xalloc_oversized(nmemb, size) &&
        VIR_ALLOC_N(x, nmemb * size) == 0)
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) (size*nmemb));
    exit(EXIT_FAILURE);
}

static char *
_vshStrdup(vshControl *ctl, const char *s, const char *filename, int line)
{
    char *x;

    if (s == NULL)
        return NULL;
    if ((x = strdup(s)))
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %lu bytes"),
             filename, line, (unsigned long)strlen(s));
    exit(EXIT_FAILURE);
}

/* Poison the raw allocating identifiers in favor of our vsh variants.  */
#undef malloc
#undef calloc
#undef realloc
#undef strdup
#define malloc use_vshMalloc_instead_of_malloc
#define calloc use_vshCalloc_instead_of_calloc
#define realloc use_vshRealloc_instead_of_realloc
#define strdup use_vshStrdup_instead_of_strdup

static int
vshNameSorter(const void *a, const void *b)
{
    const char **sa = (const char**)a;
    const char **sb = (const char**)b;

    /* User visible sort, so we want locale-specific case comparison. */
    return strcasecmp(*sa, *sb);
}

static double
prettyCapacity(unsigned long long val,
               const char **unit) {
    if (val < 1024) {
        *unit = "";
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


static virErrorPtr last_error;

/*
 * Quieten libvirt until we're done with the command.
 */
static void
virshErrorHandler(void *unused ATTRIBUTE_UNUSED, virErrorPtr error)
{
    virFreeError(last_error);
    last_error = virSaveLastError();
    if (getenv("VIRSH_DEBUG") != NULL)
        virDefaultErrorFunc(error);
}

/*
 * Reset libvirt error on graceful fallback paths
 */
static void
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
static void
virshReportError(vshControl *ctl)
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

static volatile sig_atomic_t intCaught = 0;

static void vshCatchInt(int sig ATTRIBUTE_UNUSED,
                        siginfo_t *siginfo ATTRIBUTE_UNUSED,
                        void *context ATTRIBUTE_UNUSED)
{
    intCaught = 1;
}

/*
 * Detection of disconnections and automatic reconnection support
 */
static int disconnected = 0; /* we may have been disconnected */

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

/*
 * vshCatchDisconnect:
 *
 * We get here when a SIGPIPE is being raised, we can't do much in the
 * handler, just save the fact it was raised
 */
static void vshCatchDisconnect(int sig, siginfo_t *siginfo,
                               void *context ATTRIBUTE_UNUSED) {
    if (sig == SIGPIPE ||
        (SA_SIGINFO && siginfo->si_signo == SIGPIPE))
        disconnected++;
}

/*
 * vshSetupSignals:
 *
 * Catch SIGPIPE signals which may arise when disconnection
 * from libvirtd occurs
 */
static void
vshSetupSignals(void) {
    struct sigaction sig_action;

    sig_action.sa_sigaction = vshCatchDisconnect;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGPIPE, &sig_action, NULL);
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

    if (ctl->conn != NULL) {
        connected = true;
        virConnectClose(ctl->conn);
    }

    ctl->conn = virConnectOpenAuth(ctl->name,
                                   virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);
    if (!ctl->conn)
        vshError(ctl, "%s", _("Failed to reconnect to the hypervisor"));
    else if (connected)
        vshError(ctl, "%s", _("Reconnected to the hypervisor"));
    disconnected = 0;
    ctl->useGetInfo = false;
    ctl->useSnapshotOld = false;
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
static int
vshAskReedit(vshControl *ctl, const char *msg)
{
    int c = -1;
    struct termios ttyattr;

    if (!isatty(STDIN_FILENO))
        return -1;

    virshReportError(ctl);

    if (vshMakeStdinRaw(&ttyattr, false) < 0)
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

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ttyattr);

    vshPrint(ctl, "\r\n");
    return c;
}
#else /* WIN32 */
static int
vshAskReedit(vshControl *ctl, const char *msg ATTRIBUTE_UNUSED)
{
    vshDebug(ctl, VSH_ERR_WARNING, "%s", _("This function is not "
                                           "supported on WIN32 platform"));
    return 0;
}
#endif /* WIN32 */

static int vshStreamSink(virStreamPtr st ATTRIBUTE_UNUSED,
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
    {"help", N_("print help")},
    {"desc", N_("Prints global help, command specific help, or help for a\n"
                "    group of related commands")},

    {NULL, NULL}
};

static const vshCmdOptDef opts_help[] = {
    {"command", VSH_OT_DATA, 0, N_("Prints global help, command specific help, or help for a group of related commands")},
    {NULL, 0, 0, NULL}
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

/* Given an index, return either the name of that device (non-NULL) or
 * of its parent (NULL if a root).  */
typedef const char * (*vshTreeLookup)(int devid, bool parent, void *opaque);

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
    int i;
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
    for (i = 0 ; i < num_devices ; i++) {
        const char *parent = (lookup)(i, true, opaque);

        if (parent && STREQ(parent, dev))
            nextlastdev = i;
    }

    /* If there is a child device, then print another blank line */
    if (nextlastdev != -1)
        vshPrint(ctl, "%s  |\n", virBufferCurrentContent(indent));

    /* Finally print all children */
    virBufferAddLit(indent, "  ");
    for (i = 0 ; i < num_devices ; i++) {
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

static int
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
static char *
editWriteToTempFile(vshControl *ctl, const char *doc)
{
    char *ret;
    const char *tmpdir;
    int fd;

    tmpdir = getenv ("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    if (virAsprintf(&ret, "%s/virshXXXXXX.xml", tmpdir) < 0) {
        vshError(ctl, "%s", _("out of memory"));
        return NULL;
    }
    fd = mkstemps(ret, 4);
    if (fd == -1) {
        vshError(ctl, _("mkstemps: failed to create temporary file: %s"),
                 strerror(errno));
        VIR_FREE(ret);
        return NULL;
    }

    if (safewrite(fd, doc, strlen(doc)) == -1) {
        vshError(ctl, _("write: %s: failed to write to temporary file: %s"),
                 ret, strerror(errno));
        VIR_FORCE_CLOSE(fd);
        unlink(ret);
        VIR_FREE(ret);
        return NULL;
    }
    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("close: %s: failed to write or close temporary file: %s"),
                 ret, strerror(errno));
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

static int
editFile(vshControl *ctl, const char *filename)
{
    const char *editor;
    virCommandPtr cmd;
    int ret = -1;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    editor = getenv("VISUAL");
    if (!editor)
        editor = getenv("EDITOR");
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
        virshReportError(ctl);
        goto cleanup;
    }
    ret = 0;

cleanup:
    virCommandFree(cmd);
    return ret;
}

static char *
editReadBackFile(vshControl *ctl, const char *filename)
{
    char *ret;

    if (virFileReadAll(filename, VIRSH_MAX_XML_FILE, &ret) == -1) {
        vshError(ctl,
                 _("%s: failed to read temporary file: %s"),
                 filename, strerror(errno));
        return NULL;
    }
    return ret;
}


/*
 * "cd" command
 */
static const vshCmdInfo info_cd[] = {
    {"help", N_("change the current directory")},
    {"desc", N_("Change the current directory.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cd[] = {
    {"dir", VSH_OT_DATA, 0, N_("directory to switch to (default: home or else root)")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCd(vshControl *ctl, const vshCmd *cmd)
{
    const char *dir = NULL;
    char *dir_malloced = NULL;
    bool ret = true;

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
        vshError(ctl, _("cd: %s: %s"), strerror(errno), dir);
        ret = false;
    }

    VIR_FREE(dir_malloced);
    return ret;
}

/*
 * "pwd" command
 */
static const vshCmdInfo info_pwd[] = {
    {"help", N_("print the current directory")},
    {"desc", N_("Print the current directory.")},
    {NULL, NULL}
};

static bool
cmdPwd(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *cwd;
    bool ret = true;

    cwd = getcwd(NULL, 0);
    if (!cwd) {
        vshError(ctl, _("pwd: cannot get current directory: %s"),
                 strerror(errno));
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
    {"help", N_("echo arguments")},
    {"desc", N_("Echo back arguments, possibly with quoting.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_echo[] = {
    {"shell", VSH_OT_BOOL, 0, N_("escape for shell use")},
    {"xml", VSH_OT_BOOL, 0, N_("escape for XML use")},
    {"str", VSH_OT_ALIAS, 0, "string"},
    {"string", VSH_OT_ARGV, 0, N_("arguments to echo")},
    {NULL, 0, 0, NULL}
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
            if (virBufferError(&buf)) {
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
    {"help", N_("quit this interactive terminal")},
    {"desc", ""},
    {NULL, NULL}
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
static const char *
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
    int i;
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
            int j;
            if (opt->flags || !opt->help)
                return -1; /* alias options are tracked by the original name */
            for (j = i + 1; cmd->opts[j].name; j++) {
                if (STREQ(opt->help, cmd->opts[j].name))
                    break;
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

static const vshCmdOptDef *
vshCmddefGetOption(vshControl *ctl, const vshCmdDef *cmd, const char *name,
                   uint32_t *opts_seen, int *opt_index)
{
    int i;

    for (i = 0; cmd->opts && cmd->opts[i].name; i++) {
        const vshCmdOptDef *opt = &cmd->opts[i];

        if (STREQ(opt->name, name)) {
            if (opt->type == VSH_OT_ALIAS) {
                name = opt->help;
                continue;
            }
            if ((*opts_seen & (1 << i)) && opt->type != VSH_OT_ARGV) {
                vshError(ctl, _("option --%s already seen"), name);
                return NULL;
            }
            *opts_seen |= 1 << i;
            *opt_index = i;
            return opt;
        }
    }

    vshError(ctl, _("command '%s' doesn't support option --%s"),
             cmd->name, name);
    return NULL;
}

static const vshCmdOptDef *
vshCmddefGetData(const vshCmdDef *cmd, uint32_t *opts_need_arg,
                 uint32_t *opts_seen)
{
    int i;
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
    int i;

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

static const vshCmdDef *
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

static const vshCmdGrp *
vshCmdGrpSearch(const char *grpname)
{
    const vshCmdGrp *g;

    for (g = cmdGroups; g->name; g++) {
        if (STREQ(g->name, grpname) || STREQ(g->keyword, grpname))
            return g;
    }

    return NULL;
}

static bool
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
            vshPrint(ctl, "    %-30s %s\n", cmd->name,
                     _(vshCmddefGetInfo(cmd, "help")));
        }
    }

    return true;
}

static bool
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
                default:
                    assert(0);
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

        if (def->opts) {
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
                default:
                    assert(0);
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
 *
 * Look up an option passed to CMD by NAME.  Returns 1 with *OPT set
 * to the option if found, 0 with *OPT set to NULL if the name is
 * valid and the option is not required, -1 with *OPT set to NULL if
 * the option is required but not present, and -2 if NAME is not valid
 * (-2 indicates a programming error).  No error messages are issued.
 */
static int
vshCommandOpt(const vshCmd *cmd, const char *name, vshCmdOpt **opt)
{
    vshCmdOpt *candidate = cmd->opts;
    const vshCmdOptDef *valid = cmd->def->opts;

    /* See if option is present on command line.  */
    while (candidate) {
        if (STREQ(candidate->def->name, name)) {
            *opt = candidate;
            return 1;
        }
        candidate = candidate->next;
    }

    /* Option not present, see if command requires it.  */
    *opt = NULL;
    while (valid) {
        if (!valid->name)
            break;
        if (STREQ(name, valid->name))
            return (valid->flags & VSH_OFLAG_REQ) == 0 ? 0 : -1;
        valid++;
    }
    /* If we got here, the name is unknown.  */
    return -2;
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
static int
vshCommandOptInt(const vshCmd *cmd, const char *name, int *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

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
static int
vshCommandOptUInt(const vshCmd *cmd, const char *name, unsigned int *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

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
static int
vshCommandOptUL(const vshCmd *cmd, const char *name, unsigned long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

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
static int
vshCommandOptString(const vshCmd *cmd, const char *name, const char **value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    if (!*arg->data && !(arg->def->flags & VSH_OFLAG_EMPTY_OK)) {
        return -1;
    }
    *value = arg->data;
    return 1;
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
static int
vshCommandOptLongLong(const vshCmd *cmd, const char *name,
                      long long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

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
static int
vshCommandOptULongLong(const vshCmd *cmd, const char *name,
                       unsigned long long *value)
{
    vshCmdOpt *arg;
    int ret;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

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
static int
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
static bool
vshCommandOptBool(const vshCmd *cmd, const char *name)
{
    vshCmdOpt *dummy;

    return vshCommandOpt(cmd, name, &dummy) == 1;
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
static const vshCmdOpt *
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
static bool
cmd_has_option(vshControl *ctl, const vshCmd *cmd, const char *optname)
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

static virDomainPtr
vshCommandOptDomainBy(vshControl *ctl, const vshCmd *cmd,
                      const char **name, int flag)
{
    virDomainPtr dom = NULL;
    const char *n = NULL;
    int id;
    const char *optname = "domain";
    if (!cmd_has_option(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by ID */
    if (flag & VSH_BYID) {
        if (virStrToLong_i(n, NULL, 10, &id) == 0 && id >= 0) {
            vshDebug(ctl, VSH_ERR_DEBUG,
                     "%s: <%s> seems like domain ID\n",
                     cmd->def->name, optname);
            dom = virDomainLookupByID(ctl->conn, id);
        }
    }
    /* try it by UUID */
    if (dom==NULL && (flag & VSH_BYUUID) && strlen(n)==VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as domain UUID\n",
                 cmd->def->name, optname);
        dom = virDomainLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (dom==NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as domain NAME\n",
                 cmd->def->name, optname);
        dom = virDomainLookupByName(ctl->conn, n);
    }

    if (!dom)
        vshError(ctl, _("failed to get domain '%s'"), n);

    return dom;
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

        ret = cmd->def->handler(ctl, cmd);

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
            virshReportError(ctl);

        if (!ret && disconnected != 0)
            vshReconnect(ctl);

        if (STREQ(cmd->def->name, "quit"))        /* hack ... */
            return ret;

        if (enable_timing)
            vshPrint(ctl, _("\n(Time: %.3f ms)\n\n"),
                     DIFF_MSEC(&after, &before));
        else
            vshPrintExtra(ctl, "\n");
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

typedef struct __vshCommandParser {
    vshCommandToken(*getNextArg)(vshControl *, struct __vshCommandParser *,
                                  char **);
    /* vshCommandStringGetArg() */
    char *pos;
    /* vshCommandArgvGetArg() */
    char **arg_pos;
    char **arg_end;
} vshCommandParser;

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
                int opt_index;

                if (optstr) {
                    *optstr = '\0'; /* convert the '=' to '\0' */
                    optstr = vshStrdup(ctl, optstr + 1);
                }
                if (!(opt = vshCmddefGetOption(ctl, cmd, tkdata + 2,
                                               &opts_seen, &opt_index))) {
                    VIR_FREE(optstr);
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
                if (!(opt = vshCmddefGetData(cmd, &opts_need_arg,
                                             &opts_seen))) {
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
static int
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
static char *
vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
{
    int ret = 0;
    char *str = NULL;

    switch(item->type) {
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
        ret = virAsprintf(&str, "%s", item->value.b ? _("yes") : _("no"));
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

static virTypedParameterPtr
vshFindTypedParamByName(const char *name, virTypedParameterPtr list, int count)
{
    int i = count;
    virTypedParameterPtr found = list;

    if (!list || !name)
        return NULL;

    while (i-- > 0) {
        if (STREQ(name, found->field))
            return found;

        found++; /* go to next struct in array */
    }

    /* not found */
    return NULL;
}

static bool
vshConnectionUsability(vshControl *ctl, virConnectPtr conn)
{
    /* TODO: use something like virConnectionState() to
     *       check usability of the connection
     */
    if (!conn) {
        vshError(ctl, "%s", _("no valid connection"));
        return false;
    }
    return true;
}

static void
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

static void
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


static void
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
            virshReportError(ctl);
    }
}


/*
 * Initialize connection.
 */
static bool
vshInit(vshControl *ctl)
{
    char *debugEnv;

    if (ctl->conn)
        return false;

    if (ctl->debug == VSH_DEBUG_DEFAULT) {
        /* log level not set from commandline, check env variable */
        debugEnv = getenv("VIRSH_DEBUG");
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
        debugEnv = getenv("VIRSH_LOG_FILE");
        if (debugEnv && *debugEnv) {
            ctl->logfile = vshStrdup(ctl, debugEnv);
        }
    }

    vshOpenLogFile(ctl);

    /* set up the library error handler */
    virSetErrorFunc(NULL, virshErrorHandler);

    /* set up the signals handlers to catch disconnections */
    vshSetupSignals();

    if (virEventRegisterDefaultImpl() < 0)
        return false;

    if (virThreadCreate(&ctl->eventLoop, true, vshEventLoop, ctl) < 0)
        return false;
    ctl->eventLoopStarted = true;

    if (ctl->name) {
        ctl->conn = virConnectOpenAuth(ctl->name,
                                       virConnectAuthPtrDefault,
                                       ctl->readonly ? VIR_CONNECT_RO : 0);

        /* Connecting to a named connection must succeed, but we delay
         * connecting to the default connection until we need it
         * (since the first command might be 'connect' which allows a
         * non-default connection, or might be 'help' which needs no
         * connection).
         */
        if (!ctl->conn) {
            virshReportError(ctl);
            vshError(ctl, "%s", _("failed to connect to the hypervisor"));
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
static void
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
static void
vshOutputLogFile(vshControl *ctl, int log_level, const char *msg_format,
                 va_list ap)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *str;
    size_t len;
    const char *lvl = "";
    struct timeval stTimeval;
    struct tm *stTm;

    if (ctl->log_fd == -1)
        return;

    /**
     * create log format
     *
     * [YYYY.MM.DD HH:MM:SS SIGNATURE PID] LOG_LEVEL message
    */
    gettimeofday(&stTimeval, NULL);
    stTm = localtime(&stTimeval.tv_sec);
    virBufferAsprintf(&buf, "[%d.%02d.%02d %02d:%02d:%02d %s %d] ",
                      (1900 + stTm->tm_year),
                      (1 + stTm->tm_mon),
                      stTm->tm_mday,
                      stTm->tm_hour,
                      stTm->tm_min,
                      stTm->tm_sec,
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
static void
vshCloseLogFile(vshControl *ctl)
{
    /* log file close */
    if (VIR_CLOSE(ctl->log_fd) < 0) {
        vshError(ctl, _("%s: failed to write log file: %s"),
                 ctl->logfile ? ctl->logfile : "?", strerror (errno));
    }

    if (ctl->logfile) {
        VIR_FREE(ctl->logfile);
        ctl->logfile = NULL;
    }
}

#ifdef USE_READLINE

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


static int
vshReadlineInit(vshControl *ctl)
{
    char *userdir = NULL;

    /* Allow conditional parsing of the ~/.inputrc file. */
    rl_readline_name = "virsh";

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = vshReadlineCompletion;

    /* Limit the total size of the history buffer */
    stifle_history(500);

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

#else /* !USE_READLINE */

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

#endif /* !USE_READLINE */

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
        if ((ret = virConnectClose(ctl->conn)) != 0) {
            vshError(ctl, _("Failed to disconnect from the hypervisor, %d leaked reference(s)"), ret);
        }
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
    vshPrint(ctl, " QEmu/KVM");
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
#ifdef WITH_LIBVIRTD
    vshPrint(ctl, " Daemon");
#endif
#ifdef WITH_NETWORK
    vshPrint(ctl, " Network");
#endif
#ifdef WITH_BRIDGE
    vshPrint(ctl, " Bridging");
#endif
#ifdef WITH_NETCF
    vshPrint(ctl, " Interface");
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
#ifdef USE_READLINE
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
    while ((arg = getopt_long(argc, argv, "+d:hqtc:vVrl:e:", opt, NULL)) != -1) {
        switch (arg) {
        case 'd':
            if (virStrToLong_i(optarg, NULL, 10, &debug) < 0) {
                vshError(ctl, "%s", _("option -d takes a numeric argument"));
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
            ctl->logfile = vshStrdup(ctl, optarg);
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
        default:
            vshError(ctl, _("unsupported option '-%c'. See --help."), arg);
            exit(EXIT_FAILURE);
        }
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

#include "virsh-domain.c"
#include "virsh-domain-monitor.c"
#include "virsh-pool.c"
#include "virsh-volume.c"
#include "virsh-network.c"
#include "virsh-nodedev.c"
#include "virsh-interface.c"
#include "virsh-nwfilter.c"
#include "virsh-secret.c"
#include "virsh-snapshot.c"
#include "virsh-host.c"

static const vshCmdDef virshCmds[] = {
    {"cd", cmdCd, opts_cd, info_cd, VSH_CMD_FLAG_NOCONNECT},
    {"echo", cmdEcho, opts_echo, info_echo, VSH_CMD_FLAG_NOCONNECT},
    {"exit", cmdQuit, NULL, info_quit, VSH_CMD_FLAG_NOCONNECT},
    {"help", cmdHelp, opts_help, info_help, VSH_CMD_FLAG_NOCONNECT},
    {"pwd", cmdPwd, NULL, info_pwd, VSH_CMD_FLAG_NOCONNECT},
    {"quit", cmdQuit, NULL, info_quit, VSH_CMD_FLAG_NOCONNECT},
    {NULL, NULL, NULL, NULL, 0}
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
    char *defaultConn;
    bool ret = true;

    memset(ctl, 0, sizeof(vshControl));
    ctl->imode = true;          /* default is interactive mode */
    ctl->log_fd = -1;           /* Initialize log file descriptor */
    ctl->debug = VSH_DEBUG_DEFAULT;
    ctl->escapeChar = CTRL_CLOSE_BRACKET;


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

    if ((defaultConn = getenv("VIRSH_DEFAULT_CONNECT_URI"))) {
        ctl->name = vshStrdup(ctl, defaultConn);
    }

    if (!vshParseArgv(ctl, argc, argv)) {
        vshDeinit(ctl);
        exit(EXIT_FAILURE);
    }

    if (!vshInit(ctl)) {
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
#if USE_READLINE
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
