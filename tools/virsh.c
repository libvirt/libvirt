/*
 * virsh.c: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
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

static virNWFilterPtr vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                                                  const char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptNWFilter(_ctl, _cmd, _name)                    \
    vshCommandOptNWFilterBy(_ctl, _cmd, _name,                      \
                            VSH_BYUUID|VSH_BYNAME)

static virInterfacePtr vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                                                const char *optname,
                                                const char **name, int flag);

/* default is lookup by Name and MAC */
#define vshCommandOptInterface(_ctl, _cmd, _name)                    \
    vshCommandOptInterfaceBy(_ctl, _cmd, NULL, _name,                \
                             VSH_BYMAC|VSH_BYNAME)

static virSecretPtr vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd,
                                        const char **name);

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
    virFreeError(last_error);
    last_error = NULL;
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

/*
 * "connect" command
 */
static const vshCmdInfo info_connect[] = {
    {"help", N_("(re)connect to hypervisor")},
    {"desc",
     N_("Connect to local hypervisor. This is built-in command after shell start up.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_connect[] = {
    {"name",     VSH_OT_DATA, VSH_OFLAG_EMPTY_OK,
     N_("hypervisor connection URI")},
    {"readonly", VSH_OT_BOOL, 0, N_("read-only connection")},
    {NULL, 0, 0, NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ro = vshCommandOptBool(cmd, "readonly");
    const char *name = NULL;

    if (ctl->conn) {
        int ret;
        if ((ret = virConnectClose(ctl->conn)) != 0) {
            vshError(ctl, _("Failed to disconnect from the hypervisor, %d leaked reference(s)"), ret);
            return false;
        }
        ctl->conn = NULL;
    }

    VIR_FREE(ctl->name);
    if (vshCommandOptString(cmd, "name", &name) < 0) {
        vshError(ctl, "%s", _("Please specify valid connection URI"));
        return false;
    }
    ctl->name = vshStrdup(ctl, name);

    ctl->useGetInfo = false;
    ctl->useSnapshotOld = false;
    ctl->readonly = ro;

    ctl->conn = virConnectOpenAuth(ctl->name, virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);

    if (!ctl->conn)
        vshError(ctl, "%s", _("Failed to connect to the hypervisor"));

    return !!ctl->conn;
}

/*
 * "freecell" command
 */
static const vshCmdInfo info_freecell[] = {
    {"help", N_("NUMA free memory")},
    {"desc", N_("display available free memory for the NUMA cell.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_freecell[] = {
    {"cellno", VSH_OT_INT, 0, N_("NUMA cell number")},
    {"all", VSH_OT_BOOL, 0, N_("show free memory for all NUMA cells")},
    {NULL, 0, 0, NULL}
};

static bool
cmdFreecell(vshControl *ctl, const vshCmd *cmd)
{
    bool func_ret = false;
    int ret;
    int cell = -1, cell_given;
    unsigned long long memory;
    xmlNodePtr *nodes = NULL;
    unsigned long nodes_cnt;
    unsigned long *nodes_id = NULL;
    unsigned long long *nodes_free = NULL;
    int all_given;
    int i;
    char *cap_xml = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;


    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if ( (cell_given = vshCommandOptInt(cmd, "cellno", &cell)) < 0) {
        vshError(ctl, "%s", _("cell number has to be a number"));
        goto cleanup;
    }
    all_given = vshCommandOptBool(cmd, "all");

    if (all_given && cell_given) {
        vshError(ctl, "%s", _("--cellno and --all are mutually exclusive. "
                              "Please choose only one."));
        goto cleanup;
    }

    if (all_given) {
        cap_xml = virConnectGetCapabilities(ctl->conn);
        if (!cap_xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }

        xml = virXMLParseStringCtxt(cap_xml, _("(capabilities)"), &ctxt);
        if (!xml) {
            vshError(ctl, "%s", _("unable to get node capabilities"));
            goto cleanup;
        }
        nodes_cnt = virXPathNodeSet("/capabilities/host/topology/cells/cell",
                                    ctxt, &nodes);

        if (nodes_cnt == -1) {
            vshError(ctl, "%s", _("could not get information about "
                                  "NUMA topology"));
            goto cleanup;
        }

        nodes_free = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_free));
        nodes_id = vshCalloc(ctl, nodes_cnt, sizeof(*nodes_id));

        for (i = 0; i < nodes_cnt; i++) {
            unsigned long id;
            char *val = virXMLPropString(nodes[i], "id");
            if (virStrToLong_ul(val, NULL, 10, &id)) {
                vshError(ctl, "%s", _("conversion from string failed"));
                VIR_FREE(val);
                goto cleanup;
            }
            VIR_FREE(val);
            nodes_id[i]=id;
            ret = virNodeGetCellsFreeMemory(ctl->conn, &(nodes_free[i]), id, 1);
            if (ret != 1) {
                vshError(ctl, _("failed to get free memory for NUMA node "
                                "number: %lu"), id);
                goto cleanup;
            }
        }

        memory = 0;
        for (cell = 0; cell < nodes_cnt; cell++) {
            vshPrint(ctl, "%5lu: %10llu KiB\n", nodes_id[cell],
                    (nodes_free[cell]/1024));
            memory += nodes_free[cell];
        }

        vshPrintExtra(ctl, "--------------------\n");
        vshPrintExtra(ctl, "%5s: %10llu KiB\n", _("Total"), memory/1024);
    } else {
        if (!cell_given) {
            memory = virNodeGetFreeMemory(ctl->conn);
            if (memory == 0)
                goto cleanup;
        } else {
            ret = virNodeGetCellsFreeMemory(ctl->conn, &memory, cell, 1);
            if (ret != 1)
                goto cleanup;
        }

        if (cell == -1)
            vshPrint(ctl, "%s: %llu KiB\n", _("Total"), (memory/1024));
        else
            vshPrint(ctl, "%d: %llu KiB\n", cell, (memory/1024));
    }

    func_ret = true;

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(nodes);
    VIR_FREE(nodes_free);
    VIR_FREE(nodes_id);
    VIR_FREE(cap_xml);
    return func_ret;
}

/*
 * "nodeinfo" command
 */
static const vshCmdInfo info_nodeinfo[] = {
    {"help", N_("node information")},
    {"desc", N_("Returns basic information about the node.")},
    {NULL, NULL}
};

static bool
cmdNodeinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (virNodeGetInfo(ctl->conn, &info) < 0) {
        vshError(ctl, "%s", _("failed to get node information"));
        return false;
    }
    vshPrint(ctl, "%-20s %s\n", _("CPU model:"), info.model);
    vshPrint(ctl, "%-20s %d\n", _("CPU(s):"), info.cpus);
    vshPrint(ctl, "%-20s %d MHz\n", _("CPU frequency:"), info.mhz);
    vshPrint(ctl, "%-20s %d\n", _("CPU socket(s):"), info.sockets);
    vshPrint(ctl, "%-20s %d\n", _("Core(s) per socket:"), info.cores);
    vshPrint(ctl, "%-20s %d\n", _("Thread(s) per core:"), info.threads);
    vshPrint(ctl, "%-20s %d\n", _("NUMA cell(s):"), info.nodes);
    vshPrint(ctl, "%-20s %lu KiB\n", _("Memory size:"), info.memory);

    return true;
}

/*
 * "nodecpustats" command
 */
static const vshCmdInfo info_nodecpustats[] = {
    {"help", N_("Prints cpu stats of the node.")},
    {"desc", N_("Returns cpu stats of the node, in nanoseconds.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_cpustats[] = {
    {"cpu", VSH_OT_INT, 0, N_("prints specified cpu statistics only.")},
    {"percent", VSH_OT_BOOL, 0, N_("prints by percentage during 1 second.")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeCpuStats(vshControl *ctl, const vshCmd *cmd)
{
    int i, j;
    bool flag_utilization = false;
    bool flag_percent = vshCommandOptBool(cmd, "percent");
    int cpuNum = VIR_NODE_CPU_STATS_ALL_CPUS;
    virNodeCPUStatsPtr params;
    int nparams = 0;
    bool ret = false;
    struct cpu_stats {
        unsigned long long user;
        unsigned long long sys;
        unsigned long long idle;
        unsigned long long iowait;
        unsigned long long util;
    } cpu_stats[2];
    double user_time, sys_time, idle_time, iowait_time, total_time;
    double usage;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptInt(cmd, "cpu", &cpuNum) < 0) {
        vshError(ctl, "%s", _("Invalid value of cpuNum"));
        return false;
    }

    if (virNodeGetCPUStats(ctl->conn, cpuNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of cpu stats"));
        return false;
    }
    if (nparams == 0) {
        /* nothing to output */
        return true;
    }

    memset(cpu_stats, 0, sizeof(cpu_stats));
    params = vshCalloc(ctl, nparams, sizeof(*params));

    for (i = 0; i < 2; i++) {
        if (i > 0)
            sleep(1);

        if (virNodeGetCPUStats(ctl->conn, cpuNum, params, &nparams, 0) != 0) {
            vshError(ctl, "%s", _("Unable to get node cpu stats"));
            goto cleanup;
        }

        for (j = 0; j < nparams; j++) {
            unsigned long long value = params[j].value;

            if (STREQ(params[j].field, VIR_NODE_CPU_STATS_KERNEL)) {
                cpu_stats[i].sys = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_USER)) {
                cpu_stats[i].user = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_IDLE)) {
                cpu_stats[i].idle = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_IOWAIT)) {
                cpu_stats[i].iowait = value;
            } else if (STREQ(params[j].field, VIR_NODE_CPU_STATS_UTILIZATION)) {
                cpu_stats[i].util = value;
                flag_utilization = true;
            }
        }

        if (flag_utilization || !flag_percent)
            break;
    }

    if (!flag_percent) {
        if (!flag_utilization) {
            vshPrint(ctl, "%-15s %20llu\n", _("user:"), cpu_stats[0].user);
            vshPrint(ctl, "%-15s %20llu\n", _("system:"), cpu_stats[0].sys);
            vshPrint(ctl, "%-15s %20llu\n", _("idle:"), cpu_stats[0].idle);
            vshPrint(ctl, "%-15s %20llu\n", _("iowait:"), cpu_stats[0].iowait);
        }
    } else {
        if (flag_utilization) {
            usage = cpu_stats[0].util;

            vshPrint(ctl, "%-15s %5.1lf%%\n", _("usage:"), usage);
            vshPrint(ctl, "%-15s %5.1lf%%\n", _("idle:"), 100 - usage);
        } else {
            user_time   = cpu_stats[1].user   - cpu_stats[0].user;
            sys_time    = cpu_stats[1].sys    - cpu_stats[0].sys;
            idle_time   = cpu_stats[1].idle   - cpu_stats[0].idle;
            iowait_time = cpu_stats[1].iowait - cpu_stats[0].iowait;
            total_time  = user_time + sys_time + idle_time + iowait_time;

            usage = (user_time + sys_time) / total_time * 100;

            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("usage:"), usage);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("user:"), user_time / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("system:"), sys_time  / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("idle:"), idle_time     / total_time * 100);
            vshPrint(ctl, "%-15s %5.1lf%%\n",
                     _("iowait:"), iowait_time   / total_time * 100);
        }
    }

    ret = true;

  cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodememstats" command
 */
static const vshCmdInfo info_nodememstats[] = {
    {"help", N_("Prints memory stats of the node.")},
    {"desc", N_("Returns memory stats of the node, in kilobytes.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_memstats[] = {
    {"cell", VSH_OT_INT, 0, N_("prints specified cell statistics only.")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeMemStats(vshControl *ctl, const vshCmd *cmd)
{
    int nparams = 0;
    unsigned int i = 0;
    int cellNum = VIR_NODE_MEMORY_STATS_ALL_CELLS;
    virNodeMemoryStatsPtr params = NULL;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptInt(cmd, "cell", &cellNum) < 0) {
        vshError(ctl, "%s", _("Invalid value of cellNum"));
        return false;
    }

    /* get the number of memory parameters */
    if (virNodeGetMemoryStats(ctl->conn, cellNum, NULL, &nparams, 0) != 0) {
        vshError(ctl, "%s",
                 _("Unable to get number of memory stats"));
        goto cleanup;
    }

    if (nparams == 0) {
        /* nothing to output */
        ret = true;
        goto cleanup;
    }

    /* now go get all the memory parameters */
    params = vshCalloc(ctl, nparams, sizeof(*params));
    if (virNodeGetMemoryStats(ctl->conn, cellNum, params, &nparams, 0) != 0) {
        vshError(ctl, "%s", _("Unable to get memory stats"));
        goto cleanup;
    }

    for (i = 0; i < nparams; i++)
        vshPrint(ctl, "%-7s: %20llu KiB\n", params[i].field, params[i].value);

    ret = true;

  cleanup:
    VIR_FREE(params);
    return ret;
}

/*
 * "nodesuspend" command
 */
static const vshCmdInfo info_nodesuspend[] = {
    {"help", N_("suspend the host node for a given time duration")},
    {"desc", N_("Suspend the host node for a given time duration "
                               "and attempt to resume thereafter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_suspend[] = {
    {"target", VSH_OT_DATA, VSH_OFLAG_REQ, N_("mem(Suspend-to-RAM), "
                                               "disk(Suspend-to-Disk), hybrid(Hybrid-Suspend)")},
    {"duration", VSH_OT_INT, VSH_OFLAG_REQ, N_("Suspend duration in seconds")},
    {"flags", VSH_OT_INT, VSH_OFLAG_NONE, N_("Suspend flags, 0 for default")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeSuspend(vshControl *ctl, const vshCmd *cmd)
{
    const char *target = NULL;
    unsigned int suspendTarget;
    long long duration;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "target", &target) < 0) {
        vshError(ctl, _("Invalid target argument"));
        return false;
    }

    if (vshCommandOptLongLong(cmd, "duration", &duration) < 0) {
        vshError(ctl, _("Invalid duration argument"));
        return false;
    }

    if (vshCommandOptUInt(cmd, "flags", &flags) < 0) {
        vshError(ctl, _("Invalid flags argument"));
        return false;
    }

    if (STREQ(target, "mem"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    else if (STREQ(target, "disk"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    else if (STREQ(target, "hybrid"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    else {
        vshError(ctl, "%s", _("Invalid target"));
        return false;
    }

    if (duration <= 0) {
        vshError(ctl, "%s", _("Invalid duration"));
        return false;
    }

    if (virNodeSuspendForDuration(ctl->conn, suspendTarget, duration,
                                  flags) < 0) {
        vshError(ctl, "%s", _("The host was not suspended"));
        return false;
    }
    return true;
}


/*
 * "capabilities" command
 */
static const vshCmdInfo info_capabilities[] = {
    {"help", N_("capabilities")},
    {"desc", N_("Returns capabilities of hypervisor/driver.")},
    {NULL, NULL}
};

static bool
cmdCapabilities(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if ((caps = virConnectGetCapabilities(ctl->conn)) == NULL) {
        vshError(ctl, "%s", _("failed to get capabilities"));
        return false;
    }
    vshPrint(ctl, "%s\n", caps);
    VIR_FREE(caps);

    return true;
}

/*
 * "iface-edit" command
 */
static const vshCmdInfo info_interface_edit[] = {
    {"help", N_("edit XML configuration for a physical host interface")},
    {"desc", N_("Edit the XML configuration for a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_edit[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr iface = NULL;
    virInterfacePtr iface_edited = NULL;
    unsigned int flags = VIR_INTERFACE_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    iface = vshCommandOptInterface(ctl, cmd, NULL);
    if (iface == NULL)
        goto cleanup;

#define EDIT_GET_XML virInterfaceGetXMLDesc(iface, flags)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Interface %s XML configuration not changed.\n"),   \
             virInterfaceGetName(iface));                               \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (iface_edited = virInterfaceDefineXML(ctl->conn, doc_edited, 0))
#define EDIT_FREE \
    if (iface_edited)   \
        virInterfaceFree(iface_edited);
#include "virsh-edit.c"

    vshPrint(ctl, _("Interface %s XML configuration edited.\n"),
             virInterfaceGetName(iface_edited));

    ret = true;

cleanup:
    if (iface)
        virInterfaceFree(iface);
    if (iface_edited)
        virInterfaceFree(iface_edited);

    return ret;
}

/**************************************************************************/
/*
 * "iface-list" command
 */
static const vshCmdInfo info_interface_list[] = {
    {"help", N_("list physical host interfaces")},
    {"desc", N_("Returns list of physical host interfaces.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive interfaces")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active interfaces")},
    {NULL, 0, 0, NULL}
};
static bool
cmdInterfaceList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    bool inactive = vshCommandOptBool(cmd, "inactive");
    bool all = vshCommandOptBool(cmd, "all");
    bool active = !inactive || all;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (active) {
        maxactive = virConnectNumOfInterfaces(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active interfaces"));
            return false;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListInterfaces(ctl->conn, activeNames,
                                                    maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active interfaces"));
                VIR_FREE(activeNames);
                return false;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), vshNameSorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedInterfaces(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive interfaces"));
            VIR_FREE(activeNames);
            return false;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive =
                     virConnectListDefinedInterfaces(ctl->conn, inactiveNames,
                                                     maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive interfaces"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return false;
            }

            qsort(&inactiveNames[0], maxinactive, sizeof(char*), vshNameSorter);
        }
    }
    vshPrintExtra(ctl, "%-20s %-10s %s\n", _("Name"), _("State"),
                  _("MAC Address"));
    vshPrintExtra(ctl, "--------------------------------------------\n");

    for (i = 0; i < maxactive; i++) {
        virInterfacePtr iface =
            virInterfaceLookupByName(ctl->conn, activeNames[i]);

        /* this kind of work with interfaces is not atomic */
        if (!iface) {
            VIR_FREE(activeNames[i]);
            continue;
        }

        vshPrint(ctl, "%-20s %-10s %s\n",
                 virInterfaceGetName(iface),
                 _("active"),
                 virInterfaceGetMACString(iface));
        virInterfaceFree(iface);
        VIR_FREE(activeNames[i]);
    }
    for (i = 0; i < maxinactive; i++) {
        virInterfacePtr iface =
            virInterfaceLookupByName(ctl->conn, inactiveNames[i]);

        /* this kind of work with interfaces is not atomic */
        if (!iface) {
            VIR_FREE(inactiveNames[i]);
            continue;
        }

        vshPrint(ctl, "%-20s %-10s %s\n",
                 virInterfaceGetName(iface),
                 _("inactive"),
                 virInterfaceGetMACString(iface));
        virInterfaceFree(iface);
        VIR_FREE(inactiveNames[i]);
    }
    VIR_FREE(activeNames);
    VIR_FREE(inactiveNames);
    return true;

}

/*
 * "iface-name" command
 */
static const vshCmdInfo info_interface_name[] = {
    {"help", N_("convert an interface MAC address to interface name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_name[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface mac")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceName(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL, NULL,
                                           VSH_BYMAC)))
        return false;

    vshPrint(ctl, "%s\n", virInterfaceGetName(iface));
    virInterfaceFree(iface);
    return true;
}

/*
 * "iface-mac" command
 */
static const vshCmdInfo info_interface_mac[] = {
    {"help", N_("convert an interface name to interface MAC address")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_mac[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceMAC(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL, NULL,
                                           VSH_BYNAME)))
        return false;

    vshPrint(ctl, "%s\n", virInterfaceGetMACString(iface));
    virInterfaceFree(iface);
    return true;
}

/*
 * "iface-dumpxml" command
 */
static const vshCmdInfo info_interface_dumpxml[] = {
    {"help", N_("interface information in XML")},
    {"desc", N_("Output the physical host interface information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_dumpxml[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {"inactive", VSH_OT_BOOL, 0, N_("show inactive defined XML")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    bool inactive = vshCommandOptBool(cmd, "inactive");

    if (inactive)
        flags |= VIR_INTERFACE_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(iface = vshCommandOptInterface(ctl, cmd, NULL)))
        return false;

    dump = virInterfaceGetXMLDesc(iface, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-define" command
 */
static const vshCmdInfo info_interface_define[] = {
    {"help", N_("define (but don't start) a physical host interface from an XML file")},
    {"desc", N_("Define a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML interface description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceDefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    iface = virInterfaceDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (iface != NULL) {
        vshPrint(ctl, _("Interface %s defined from %s\n"),
                 virInterfaceGetName(iface), from);
        virInterfaceFree(iface);
    } else {
        vshError(ctl, _("Failed to define interface from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "iface-undefine" command
 */
static const vshCmdInfo info_interface_undefine[] = {
    {"help", N_("undefine a physical host interface (remove it from configuration)")},
    {"desc", N_("undefine an interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_undefine[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceUndefine(iface) == 0) {
        vshPrint(ctl, _("Interface %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-start" command
 */
static const vshCmdInfo info_interface_start[] = {
    {"help", N_("start a physical host interface (enable it / \"if-up\")")},
    {"desc", N_("start a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_start[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceStart(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceCreate(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-destroy" command
 */
static const vshCmdInfo info_interface_destroy[] = {
    {"help", N_("destroy a physical host interface (disable it / \"if-down\")")},
    {"desc", N_("forcefully stop a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_destroy[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return false;

    if (virInterfaceDestroy(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy interface %s"), name);
        ret = false;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-begin" command
 */
static const vshCmdInfo info_interface_begin[] = {
    {"help", N_("create a snapshot of current interfaces settings, "
                "which can be later committed (iface-commit) or "
                "restored (iface-rollback)")},
    {"desc", N_("Create a restore point for interfaces settings")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_begin[] = {
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceBegin(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (virInterfaceChangeBegin(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to begin network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction started\n"));
    return true;
}

/*
 * "iface-commit" command
 */
static const vshCmdInfo info_interface_commit[] = {
    {"help", N_("commit changes made since iface-begin and free restore point")},
    {"desc", N_("commit changes and free restore point")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_commit[] = {
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceCommit(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (virInterfaceChangeCommit(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to commit network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction committed\n"));
    return true;
}

/*
 * "iface-rollback" command
 */
static const vshCmdInfo info_interface_rollback[] = {
    {"help", N_("rollback to previous saved configuration created via iface-begin")},
    {"desc", N_("rollback to previous restore point")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_rollback[] = {
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceRollback(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (virInterfaceChangeRollback(ctl->conn, 0) < 0) {
        vshError(ctl, "%s", _("Failed to rollback network config change transaction"));
        return false;
    }

    vshPrint(ctl, "%s", _("Network config change transaction rolled back\n"));
    return true;
}

/*
 * "iface-bridge" command
 */
static const vshCmdInfo info_interface_bridge[] = {
    {"help", N_("create a bridge device and attach an existing network device to it")},
    {"desc", N_("bridge an existing network device")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_bridge[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("existing interface name")},
    {"bridge", VSH_OT_DATA, VSH_OFLAG_REQ, N_("new bridge device name")},
    {"no-stp", VSH_OT_BOOL, 0, N_("do not enable STP for this bridge")},
    {"delay", VSH_OT_INT, 0,
     N_("number of seconds to squelch traffic on newly connected ports")},
    {"no-start", VSH_OT_BOOL, 0, N_("don't start the bridge immediately")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceBridge(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr if_handle = NULL, br_handle = NULL;
    const char *if_name, *br_name;
    char *if_type = NULL, *if2_name = NULL, *delay_str = NULL;
    bool stp = false, nostart = false;
    unsigned int delay = 0;
    char *if_xml = NULL;
    xmlChar *br_xml = NULL;
    int br_xml_size;
    xmlDocPtr xml_doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr top_node, br_node, if_node, cur;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    /* Get a handle to the original device */
    if (!(if_handle = vshCommandOptInterfaceBy(ctl, cmd, "interface",
                                               &if_name, VSH_BYNAME))) {
        goto cleanup;
    }

    /* Name for new bridge device */
    if (vshCommandOptString(cmd, "bridge", &br_name) <= 0) {
        vshError(ctl, "%s", _("Missing bridge device name in command"));
        goto cleanup;
    }

    /* make sure "new" device doesn't already exist */
    if ((br_handle = virInterfaceLookupByName(ctl->conn, br_name))) {
        vshError(ctl, _("Network device %s already exists"), br_name);
        goto cleanup;
    }

    /* use "no-stp" because we want "stp" to default true */
    stp = !vshCommandOptBool(cmd, "no-stp");

    if (vshCommandOptUInt(cmd, "delay", &delay) < 0) {
        vshError(ctl, "%s", _("Unable to parse delay parameter"));
        goto cleanup;
    }

    nostart = vshCommandOptBool(cmd, "no-start");

    /* Get the original interface into an xmlDoc */
    if (!(if_xml = virInterfaceGetXMLDesc(if_handle, VIR_INTERFACE_XML_INACTIVE)))
        goto cleanup;
    if (!(xml_doc = virXMLParseStringCtxt(if_xml,
                                          _("(interface definition)"), &ctxt))) {
        vshError(ctl, _("Failed to parse configuration of %s"), if_name);
        goto cleanup;
    }
    top_node = ctxt->node;

    /* Verify that the original device isn't already a bridge. */
    if (!(if_type = virXMLPropString(top_node, "type"))) {
        vshError(ctl, _("Existing device %s has no type"), if_name);
        goto cleanup;
    }

    if (STREQ(if_type, "bridge")) {
        vshError(ctl, _("Existing device %s is already a bridge"), if_name);
        goto cleanup;
    }

    /* verify the name in the XML matches the device name */
    if (!(if2_name = virXMLPropString(top_node, "name")) ||
        STRNEQ(if2_name, if_name)) {
        vshError(ctl, _("Interface name from config %s doesn't match given supplied name %s"),
                 if2_name, if_name);
        goto cleanup;
    }

    /* Create a <bridge> node under <interface>. */
    if (!(br_node = xmlNewChild(top_node, NULL, BAD_CAST "bridge", NULL))) {
        vshError(ctl, "%s", _("Failed to create bridge node in xml document"));
        goto cleanup;
    }

    /* Set stp and delay attributes in <bridge> according to the
     * commandline options.
     */
    if (!xmlSetProp(br_node, BAD_CAST "stp", BAD_CAST (stp ? "on" : "off"))) {
        vshError(ctl, "%s", _("Failed to set stp attribute in xml document"));
        goto cleanup;
    }

    if ((delay || stp) &&
        ((virAsprintf(&delay_str, "%d", delay) < 0) ||
         !xmlSetProp(br_node, BAD_CAST "delay", BAD_CAST delay_str))) {
        vshError(ctl, _("Failed to set bridge delay %d in xml document"), delay);
        goto cleanup;
    }

    /* Change the type of the outer/master interface to "bridge" and the
     * name to the provided bridge name.
     */
    if (!xmlSetProp(top_node, BAD_CAST "type", BAD_CAST "bridge")) {
        vshError(ctl, "%s", _("Failed to set bridge interface type to 'bridge' in xml document"));
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "name", BAD_CAST br_name)) {
        vshError(ctl, _("Failed to set master bridge interface name to '%s' in xml document"),
            br_name);
        goto cleanup;
    }

    /* Create an <interface> node under <bridge> that uses the
     * original interface's type and name.
     */
    if (!(if_node = xmlNewChild(br_node, NULL, BAD_CAST "interface", NULL))) {
        vshError(ctl, "%s", _("Failed to create interface node under bridge node in xml document"));
        goto cleanup;
    }

    /* set the type of the inner/slave interface to the original
     * if_type, and the name to the original if_name.
     */
    if (!xmlSetProp(if_node, BAD_CAST "type", BAD_CAST if_type)) {
        vshError(ctl, _("Failed to set new slave interface type to '%s' in xml document"),
                 if_name);
        goto cleanup;
    }

    if (!xmlSetProp(if_node, BAD_CAST "name", BAD_CAST if_name)) {
        vshError(ctl, _("Failed to set new slave interface name to '%s' in xml document"),
            br_name);
        goto cleanup;
    }

    /* Cycle through all the nodes under the original <interface>,
     * moving all <mac>, <bond> and <vlan> nodes down into the new
     * lower level <interface>.
     */
    cur = top_node->children;
    while (cur) {
        xmlNodePtr old = cur;

        cur = cur->next;
        if ((old->type == XML_ELEMENT_NODE) &&
            (xmlStrEqual(old->name, BAD_CAST "mac") ||  /* ethernet stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "bond") || /* bond stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "vlan"))) { /* vlan stuff to move down */
            xmlUnlinkNode(old);
            if (!xmlAddChild(if_node, old)) {
                vshError(ctl, _("Failed to move '%s' element in xml document"), old->name);
                xmlFreeNode(old);
                goto cleanup;
            }
        }
    }

    /* The document should now be fully converted; write it out to a string. */
    xmlDocDumpMemory(xml_doc, &br_xml, &br_xml_size);

    if (!br_xml || br_xml_size <= 0) {
        vshError(ctl, _("Failed to format new xml document for bridge %s"), br_name);
        goto cleanup;
    }


    /* br_xml is the new interface to define. It will automatically undefine the
     * independent original interface.
     */
    if (!(br_handle = virInterfaceDefineXML(ctl->conn, (char *) br_xml, 0))) {
        vshError(ctl, _("Failed to define new bridge interface %s"),
                 br_name);
        goto cleanup;
    }

    vshPrint(ctl, _("Created bridge %s with attached device %s\n"),
             br_name, if_name);

    /* start it up unless requested not to */
    if (!nostart) {
        if (virInterfaceCreate(br_handle, 0) < 0) {
            vshError(ctl, _("Failed to start bridge interface %s"), br_name);
            goto cleanup;
        }
        vshPrint(ctl, _("Bridge interface %s started\n"), br_name);
    }

    ret = true;
 cleanup:
    if (if_handle)
       virInterfaceFree(if_handle);
    if (br_handle)
       virInterfaceFree(br_handle);
    VIR_FREE(if_xml);
    VIR_FREE(br_xml);
    VIR_FREE(if_type);
    VIR_FREE(if2_name);
    VIR_FREE(delay_str);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml_doc);
    return ret;
}

/*
 * "iface-unbridge" command
 */
static const vshCmdInfo info_interface_unbridge[] = {
    {"help", N_("undefine a bridge device after detaching its slave device")},
    {"desc", N_("unbridge a network device")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_unbridge[] = {
    {"bridge", VSH_OT_DATA, VSH_OFLAG_REQ, N_("current bridge device name")},
    {"no-start", VSH_OT_BOOL, 0,
     N_("don't start the un-slaved interface immediately (not recommended)")},
    {NULL, 0, 0, NULL}
};

static bool
cmdInterfaceUnbridge(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr if_handle = NULL, br_handle = NULL;
    const char *br_name;
    char *if_type = NULL, *if_name = NULL;
    bool nostart = false;
    char *br_xml = NULL;
    xmlChar *if_xml = NULL;
    int if_xml_size;
    xmlDocPtr xml_doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr top_node, br_node, if_node, cur;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    /* Get a handle to the original device */
    if (!(br_handle = vshCommandOptInterfaceBy(ctl, cmd, "bridge",
                                               &br_name, VSH_BYNAME))) {
        goto cleanup;
    }

    nostart = vshCommandOptBool(cmd, "no-start");

    /* Get the bridge xml into an xmlDoc */
    if (!(br_xml = virInterfaceGetXMLDesc(br_handle, VIR_INTERFACE_XML_INACTIVE)))
        goto cleanup;
    if (!(xml_doc = virXMLParseStringCtxt(br_xml,
                                          _("(bridge interface definition)"),
                                          &ctxt))) {
        vshError(ctl, _("Failed to parse configuration of %s"), br_name);
        goto cleanup;
    }
    top_node = ctxt->node;

    /* Verify that the device really is a bridge. */
    if (!(if_type = virXMLPropString(top_node, "type"))) {
        vshError(ctl, _("Existing device %s has no type"), br_name);
        goto cleanup;
    }

    if (STRNEQ(if_type, "bridge")) {
        vshError(ctl, _("Device %s is not a bridge"), br_name);
        goto cleanup;
    }
    VIR_FREE(if_type);

    /* verify the name in the XML matches the device name */
    if (!(if_name = virXMLPropString(top_node, "name")) ||
        STRNEQ(if_name, br_name)) {
        vshError(ctl, _("Interface name from config %s doesn't match given supplied name %s"),
                 if_name, br_name);
        goto cleanup;
    }
    VIR_FREE(if_name);

    /* Find the <bridge> node under <interface>. */
    if (!(br_node = virXPathNode("./bridge", ctxt))) {
        vshError(ctl, "%s", _("No bridge node in xml document"));
        goto cleanup;
    }

    if ((if_node = virXPathNode("./bridge/interface[2]", ctxt))) {
        vshError(ctl, "%s", _("Multiple interfaces attached to bridge"));
        goto cleanup;
    }

    if (!(if_node = virXPathNode("./bridge/interface", ctxt))) {
        vshError(ctl, "%s", _("No interface attached to bridge"));
        goto cleanup;
    }

    /* Change the type and name of the outer/master interface to
     * the type/name of the attached slave interface.
     */
    if (!(if_name = virXMLPropString(if_node, "name"))) {
        vshError(ctl, _("Device attached to bridge %s has no name"), br_name);
        goto cleanup;
    }

    if (!(if_type = virXMLPropString(if_node, "type"))) {
        vshError(ctl, _("Attached device %s has no type"), if_name);
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "type", BAD_CAST if_type)) {
        vshError(ctl, _("Failed to set interface type to '%s' in xml document"),
                 if_type);
        goto cleanup;
    }

    if (!xmlSetProp(top_node, BAD_CAST "name", BAD_CAST if_name)) {
        vshError(ctl, _("Failed to set interface name to '%s' in xml document"),
                 if_name);
        goto cleanup;
    }

    /* Cycle through all the nodes under the attached <interface>,
     * moving all <mac>, <bond> and <vlan> nodes up into the toplevel
     * <interface>.
     */
    cur = if_node->children;
    while (cur) {
        xmlNodePtr old = cur;

        cur = cur->next;
        if ((old->type == XML_ELEMENT_NODE) &&
            (xmlStrEqual(old->name, BAD_CAST "mac") ||  /* ethernet stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "bond") || /* bond stuff to move down */
             xmlStrEqual(old->name, BAD_CAST "vlan"))) { /* vlan stuff to move down */
            xmlUnlinkNode(old);
            if (!xmlAddChild(top_node, old)) {
                vshError(ctl, _("Failed to move '%s' element in xml document"), old->name);
                xmlFreeNode(old);
                goto cleanup;
            }
        }
    }

    /* The document should now be fully converted; write it out to a string. */
    xmlDocDumpMemory(xml_doc, &if_xml, &if_xml_size);

    if (!if_xml || if_xml_size <= 0) {
        vshError(ctl, _("Failed to format new xml document for un-enslaved interface %s"),
                 if_name);
        goto cleanup;
    }

    /* Destroy and Undefine the bridge device, since we otherwise
     * can't safely define the unattached device.
     */
    if (virInterfaceDestroy(br_handle, 0) < 0) {
        vshError(ctl, _("Failed to destroy bridge interface %s"), br_name);
        goto cleanup;
    }
    if (virInterfaceUndefine(br_handle) < 0) {
        vshError(ctl, _("Failed to undefine bridge interface %s"), br_name);
        goto cleanup;
    }

    /* if_xml is the new interface to define.
     */
    if (!(if_handle = virInterfaceDefineXML(ctl->conn, (char *) if_xml, 0))) {
        vshError(ctl, _("Failed to define new interface %s"), if_name);
        goto cleanup;
    }

    vshPrint(ctl, _("Device %s un-attached from bridge %s\n"),
             if_name, br_name);

    /* unless requested otherwise, undefine the bridge device */
    if (!nostart) {
        if (virInterfaceCreate(if_handle, 0) < 0) {
            vshError(ctl, _("Failed to start interface %s"), if_name);
            goto cleanup;
        }
        vshPrint(ctl, _("Interface %s started\n"), if_name);
    }

    ret = true;
 cleanup:
    if (if_handle)
       virInterfaceFree(if_handle);
    if (br_handle)
       virInterfaceFree(br_handle);
    VIR_FREE(if_xml);
    VIR_FREE(br_xml);
    VIR_FREE(if_type);
    VIR_FREE(if_name);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml_doc);
    return ret;
}

/*
 * "nwfilter-define" command
 */
static const vshCmdInfo info_nwfilter_define[] = {
    {"help", N_("define or update a network filter from an XML file")},
    {"desc", N_("Define a new network filter or update an existing one.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network filter description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    nwfilter = virNWFilterDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (nwfilter != NULL) {
        vshPrint(ctl, _("Network filter %s defined from %s\n"),
                 virNWFilterGetName(nwfilter), from);
        virNWFilterFree(nwfilter);
    } else {
        vshError(ctl, _("Failed to define network filter from %s"), from);
        ret = false;
    }
    return ret;
}


/*
 * "nwfilter-undefine" command
 */
static const vshCmdInfo info_nwfilter_undefine[] = {
    {"help", N_("undefine a network filter")},
    {"desc", N_("Undefine a given network filter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_undefine[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, &name)))
        return false;

    if (virNWFilterUndefine(nwfilter) == 0) {
        vshPrint(ctl, _("Network filter %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network filter %s"), name);
        ret = false;
    }

    virNWFilterFree(nwfilter);
    return ret;
}


/*
 * "nwfilter-dumpxml" command
 */
static const vshCmdInfo info_nwfilter_dumpxml[] = {
    {"help", N_("network filter information in XML")},
    {"desc", N_("Output the network filter information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_dumpxml[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    bool ret = true;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, NULL)))
        return false;

    dump = virNWFilterGetXMLDesc(nwfilter, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virNWFilterFree(nwfilter);
    return ret;
}

/*
 * "nwfilter-list" command
 */
static const vshCmdInfo info_nwfilter_list[] = {
    {"help", N_("list network filters")},
    {"desc", N_("Returns list of network filters.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_list[] = {
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int numfilters, i;
    char **names;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    numfilters = virConnectNumOfNWFilters(ctl->conn);
    if (numfilters < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        return false;
    }

    names = vshMalloc(ctl, sizeof(char *) * numfilters);

    if ((numfilters = virConnectListNWFilters(ctl->conn, names,
                                              numfilters)) < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        VIR_FREE(names);
        return false;
    }

    qsort(&names[0], numfilters, sizeof(char *), vshNameSorter);

    vshPrintExtra(ctl, "%-36s  %-20s \n", _("UUID"), _("Name"));
    vshPrintExtra(ctl,
       "----------------------------------------------------------------\n");

    for (i = 0; i < numfilters; i++) {
        virNWFilterPtr nwfilter =
            virNWFilterLookupByName(ctl->conn, names[i]);

        /* this kind of work with networks is not atomic operation */
        if (!nwfilter) {
            VIR_FREE(names[i]);
            continue;
        }

        virNWFilterGetUUIDString(nwfilter, uuid);
        vshPrint(ctl, "%-36s  %-20s\n",
                 uuid,
                 virNWFilterGetName(nwfilter));
        virNWFilterFree(nwfilter);
        VIR_FREE(names[i]);
    }

    VIR_FREE(names);
    return true;
}


/*
 * "nwfilter-edit" command
 */
static const vshCmdInfo info_nwfilter_edit[] = {
    {"help", N_("edit XML configuration for a network filter")},
    {"desc", N_("Edit the XML configuration for a network filter.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_nwfilter_edit[] = {
    {"nwfilter", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network filter name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNWFilterEdit(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNWFilterPtr nwfilter = NULL;
    virNWFilterPtr nwfilter_edited = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    nwfilter = vshCommandOptNWFilter(ctl, cmd, NULL);
    if (nwfilter == NULL)
        goto cleanup;

#define EDIT_GET_XML virNWFilterGetXMLDesc(nwfilter, 0)
#define EDIT_NOT_CHANGED \
    vshPrint(ctl, _("Network filter %s XML "            \
                    "configuration not changed.\n"),    \
             virNWFilterGetName(nwfilter));             \
    ret = true; goto edit_cleanup;
#define EDIT_DEFINE \
    (nwfilter_edited = virNWFilterDefineXML(ctl->conn, doc_edited))
#define EDIT_FREE \
    if (nwfilter_edited)    \
        virNWFilterFree(nwfilter);
#include "virsh-edit.c"

    vshPrint(ctl, _("Network filter %s XML configuration edited.\n"),
             virNWFilterGetName(nwfilter_edited));

    ret = true;

cleanup:
    if (nwfilter)
        virNWFilterFree(nwfilter);
    if (nwfilter_edited)
        virNWFilterFree(nwfilter_edited);

    return ret;
}

/*
 * "nodedev-create" command
 */
static const vshCmdInfo info_node_device_create[] = {
    {"help", N_("create a device defined "
                          "by an XML file on the node")},
    {"desc", N_("Create a device on the node.  Note that this "
                          "command creates devices on the physical host "
                          "that can then be assigned to a virtual machine.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("file containing an XML description of the device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    dev = virNodeDeviceCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (dev != NULL) {
        vshPrint(ctl, _("Node device %s created from %s\n"),
                 virNodeDeviceGetName(dev), from);
        virNodeDeviceFree(dev);
    } else {
        vshError(ctl, _("Failed to create node device from %s"), from);
        ret = false;
    }

    return ret;
}


/*
 * "nodedev-destroy" command
 */
static const vshCmdInfo info_node_device_destroy[] = {
    {"help", N_("destroy (stop) a device on the node")},
    {"desc", N_("Destroy a device on the node.  Note that this "
                "command destroys devices on the physical host")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_destroy[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("name of the device to be destroyed")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    bool ret = true;
    const char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn)) {
        return false;
    }

    if (vshCommandOptString(cmd, "name", &name) <= 0)
        return false;

    dev = virNodeDeviceLookupByName(ctl->conn, name);

    if (virNodeDeviceDestroy(dev) == 0) {
        vshPrint(ctl, _("Destroyed node device '%s'\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy node device '%s'"), name);
        ret = false;
    }

    virNodeDeviceFree(dev);
    return ret;
}

/*
 * "secret-define" command
 */
static const vshCmdInfo info_secret_define[] = {
    {"help", N_("define or modify a secret from an XML file")},
    {"desc", N_("Define or modify a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing secret attributes in XML")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    char *buffer;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    res = virSecretDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (res == NULL) {
        vshError(ctl, _("Failed to set attributes from %s"), from);
        return false;
    }
    if (virSecretGetUUIDString(res, &(uuid[0])) < 0) {
        vshError(ctl, "%s", _("Failed to get UUID of created secret"));
        virSecretFree(res);
        return false;
    }
    vshPrint(ctl, _("Secret %s created\n"), uuid);
    virSecretFree(res);
    return true;
}

/*
 * "secret-dumpxml" command
 */
static const vshCmdInfo info_secret_dumpxml[] = {
    {"help", N_("secret attributes in XML")},
    {"desc", N_("Output attributes of a secret as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_dumpxml[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    xml = virSecretGetXMLDesc(secret, 0);
    if (xml == NULL)
        goto cleanup;
    vshPrint(ctl, "%s", xml);
    VIR_FREE(xml);
    ret = true;

cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-set-value" command
 */
static const vshCmdInfo info_secret_set_value[] = {
    {"help", N_("set a secret value")},
    {"desc", N_("Set a secret value.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_set_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {"base64", VSH_OT_DATA, VSH_OFLAG_REQ, N_("base64-encoded secret value")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretSetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    size_t value_size;
    const char *base64 = NULL;
    char *value;
    int res;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    if (vshCommandOptString(cmd, "base64", &base64) <= 0)
        goto cleanup;

    if (!base64_decode_alloc(base64, strlen(base64), &value, &value_size)) {
        vshError(ctl, "%s", _("Invalid base64 data"));
        goto cleanup;
    }
    if (value == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        return false;
    }

    res = virSecretSetValue(secret, (unsigned char *)value, value_size, 0);
    memset(value, 0, value_size);
    VIR_FREE(value);

    if (res != 0) {
        vshError(ctl, "%s", _("Failed to set secret value"));
        goto cleanup;
    }
    vshPrint(ctl, "%s", _("Secret value set\n"));
    ret = true;

cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-get-value" command
 */
static const vshCmdInfo info_secret_get_value[] = {
    {"help", N_("Output a secret value")},
    {"desc", N_("Output a secret value to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_get_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretGetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    char *base64;
    unsigned char *value;
    size_t value_size;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return false;

    value = virSecretGetValue(secret, &value_size, 0);
    if (value == NULL)
        goto cleanup;

    base64_encode_alloc((char *)value, value_size, &base64);
    memset(value, 0, value_size);
    VIR_FREE(value);

    if (base64 == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }
    vshPrint(ctl, "%s", base64);
    memset(base64, 0, strlen(base64));
    VIR_FREE(base64);
    ret = true;

cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-undefine" command
 */
static const vshCmdInfo info_secret_undefine[] = {
    {"help", N_("undefine a secret")},
    {"desc", N_("Undefine a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_undefine[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, N_("secret UUID")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSecretUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    bool ret = false;
    const char *uuid;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    secret = vshCommandOptSecret(ctl, cmd, &uuid);
    if (secret == NULL)
        return false;

    if (virSecretUndefine(secret) < 0) {
        vshError(ctl, _("Failed to delete secret %s"), uuid);
        goto cleanup;
    }
    vshPrint(ctl, _("Secret %s deleted\n"), uuid);
    ret = true;

cleanup:
    virSecretFree(secret);
    return ret;
}

/*
 * "secret-list" command
 */
static const vshCmdInfo info_secret_list[] = {
    {"help", N_("list secrets")},
    {"desc", N_("Returns a list of secrets")},
    {NULL, NULL}
};

static bool
cmdSecretList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int maxuuids = 0, i;
    char **uuids = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    maxuuids = virConnectNumOfSecrets(ctl->conn);
    if (maxuuids < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        return false;
    }
    uuids = vshMalloc(ctl, sizeof(*uuids) * maxuuids);

    maxuuids = virConnectListSecrets(ctl->conn, uuids, maxuuids);
    if (maxuuids < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        VIR_FREE(uuids);
        return false;
    }

    qsort(uuids, maxuuids, sizeof(char *), vshNameSorter);

    vshPrintExtra(ctl, "%-36s %s\n", _("UUID"), _("Usage"));
    vshPrintExtra(ctl, "-----------------------------------------------------------\n");

    for (i = 0; i < maxuuids; i++) {
        virSecretPtr sec = virSecretLookupByUUIDString(ctl->conn, uuids[i]);
        const char *usageType = NULL;

        if (!sec) {
            VIR_FREE(uuids[i]);
            continue;
        }

        switch (virSecretGetUsageType(sec)) {
        case VIR_SECRET_USAGE_TYPE_VOLUME:
            usageType = _("Volume");
            break;
        }

        if (usageType) {
            vshPrint(ctl, "%-36s %s %s\n",
                     uuids[i], usageType,
                     virSecretGetUsageID(sec));
        } else {
            vshPrint(ctl, "%-36s %s\n",
                     uuids[i], _("Unused"));
        }
        virSecretFree(sec);
        VIR_FREE(uuids[i]);
    }
    VIR_FREE(uuids);
    return true;
}


/*
 * "version" command
 */
static const vshCmdInfo info_version[] = {
    {"help", N_("show version")},
    {"desc", N_("Display the system version information.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_version[] = {
    {"daemon", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("report daemon version too")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long hvVersion;
    const char *hvType;
    unsigned long libVersion;
    unsigned long includeVersion;
    unsigned long apiVersion;
    unsigned long daemonVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    hvType = virConnectGetType(ctl->conn);
    if (hvType == NULL) {
        vshError(ctl, "%s", _("failed to get hypervisor type"));
        return false;
    }

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, _("Compiled against library: libvir %d.%d.%d\n"),
             major, minor, rel);

    ret = virGetVersion(&libVersion, hvType, &apiVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the library version"));
        return false;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, _("Using library: libvir %d.%d.%d\n"),
             major, minor, rel);

    major = apiVersion / 1000000;
    apiVersion %= 1000000;
    minor = apiVersion / 1000;
    rel = apiVersion % 1000;
    vshPrint(ctl, _("Using API: %s %d.%d.%d\n"), hvType,
             major, minor, rel);

    ret = virConnectGetVersion(ctl->conn, &hvVersion);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the hypervisor version"));
        return false;
    }
    if (hvVersion == 0) {
        vshPrint(ctl,
                 _("Cannot extract running %s hypervisor version\n"), hvType);
    } else {
        major = hvVersion / 1000000;
        hvVersion %= 1000000;
        minor = hvVersion / 1000;
        rel = hvVersion % 1000;

        vshPrint(ctl, _("Running hypervisor: %s %d.%d.%d\n"),
                 hvType, major, minor, rel);
    }

    if (vshCommandOptBool(cmd, "daemon")) {
        ret = virConnectGetLibVersion(ctl->conn, &daemonVersion);
        if (ret < 0) {
            vshError(ctl, "%s", _("failed to get the daemon version"));
        } else {
            major = daemonVersion / 1000000;
            daemonVersion %= 1000000;
            minor = daemonVersion / 1000;
            rel = daemonVersion % 1000;
            vshPrint(ctl, _("Running against daemon: %d.%d.%d\n"),
                     major, minor, rel);
        }
    }

    return true;
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

struct vshNodeList {
    char **names;
    char **parents;
};

static const char *
vshNodeListLookup(int devid, bool parent, void *opaque)
{
    struct vshNodeList *arrays = opaque;
    if (parent)
        return arrays->parents[devid];
    return arrays->names[devid];
}

/*
 * "nodedev-list" command
 */
static const vshCmdInfo info_node_list_devices[] = {
    {"help", N_("enumerate devices on this host")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_list_devices[] = {
    {"tree", VSH_OT_BOOL, 0, N_("list devices in a tree")},
    {"cap", VSH_OT_STRING, VSH_OFLAG_NONE, N_("capability name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeListDevices(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *cap = NULL;
    char **devices;
    int num_devices, i;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "cap", &cap) <= 0)
        cap = NULL;

    num_devices = virNodeNumOfDevices(ctl->conn, cap, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to count node devices"));
        return false;
    } else if (num_devices == 0) {
        return true;
    }

    devices = vshMalloc(ctl, sizeof(char *) * num_devices);
    num_devices =
        virNodeListDevices(ctl->conn, cap, devices, num_devices, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to list node devices"));
        VIR_FREE(devices);
        return false;
    }
    qsort(&devices[0], num_devices, sizeof(char*), vshNameSorter);
    if (tree) {
        char **parents = vshMalloc(ctl, sizeof(char *) * num_devices);
        struct vshNodeList arrays = { devices, parents };

        for (i = 0; i < num_devices; i++) {
            virNodeDevicePtr dev = virNodeDeviceLookupByName(ctl->conn, devices[i]);
            if (dev && STRNEQ(devices[i], "computer")) {
                const char *parent = virNodeDeviceGetParent(dev);
                parents[i] = parent ? vshStrdup(ctl, parent) : NULL;
            } else {
                parents[i] = NULL;
            }
            virNodeDeviceFree(dev);
        }
        for (i = 0 ; i < num_devices ; i++) {
            if (parents[i] == NULL &&
                vshTreePrint(ctl, vshNodeListLookup, &arrays, num_devices,
                             i) < 0)
                ret = false;
        }
        for (i = 0 ; i < num_devices ; i++) {
            VIR_FREE(devices[i]);
            VIR_FREE(parents[i]);
        }
        VIR_FREE(parents);
    } else {
        for (i = 0; i < num_devices; i++) {
            vshPrint(ctl, "%s\n", devices[i]);
            VIR_FREE(devices[i]);
        }
    }
    VIR_FREE(devices);
    return ret;
}

/*
 * "nodedev-dumpxml" command
 */
static const vshCmdInfo info_node_device_dumpxml[] = {
    {"help", N_("node device details in XML")},
    {"desc", N_("Output the node device details as an XML dump to stdout.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_dumpxml[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    xml = virNodeDeviceGetXMLDesc(device, 0);
    if (!xml) {
        virNodeDeviceFree(device);
        return false;
    }

    vshPrint(ctl, "%s\n", xml);
    VIR_FREE(xml);
    virNodeDeviceFree(device);
    return true;
}

/*
 * "nodedev-detach" command
 */
static const vshCmdInfo info_node_device_detach[] = {
    {"help", N_("detach node device from its device driver")},
    {"desc", N_("Detach node device from its device driver before assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_detach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceDetach(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    /* Yes, our public API is misspelled.  At least virsh can accept
     * either spelling.  */
    if (virNodeDeviceDettach(device) == 0) {
        vshPrint(ctl, _("Device %s detached\n"), name);
    } else {
        vshError(ctl, _("Failed to detach device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "nodedev-reattach" command
 */
static const vshCmdInfo info_node_device_reattach[] = {
    {"help", N_("reattach node device to its device driver")},
    {"desc", N_("Reattach node device to its device driver once released by the domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reattach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceReAttach(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    if (virNodeDeviceReAttach(device) == 0) {
        vshPrint(ctl, _("Device %s re-attached\n"), name);
    } else {
        vshError(ctl, _("Failed to re-attach device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "nodedev-reset" command
 */
static const vshCmdInfo info_node_device_reset[] = {
    {"help", N_("reset node device")},
    {"desc", N_("Reset node device before or after assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reset[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNodeDeviceReset(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    virNodeDevicePtr device;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (vshCommandOptString(cmd, "device", &name) <= 0)
        return false;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return false;
    }

    if (virNodeDeviceReset(device) == 0) {
        vshPrint(ctl, _("Device %s reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset device %s"), name);
        ret = false;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "hostname" command
 */
static const vshCmdInfo info_hostname[] = {
    {"help", N_("print the hypervisor hostname")},
    {"desc", ""},
    {NULL, NULL}
};

static bool
cmdHostname(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    hostname = virConnectGetHostname(ctl->conn);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        return false;
    }

    vshPrint (ctl, "%s\n", hostname);
    VIR_FREE(hostname);

    return true;
}

/*
 * "uri" command
 */
static const vshCmdInfo info_uri[] = {
    {"help", N_("print the hypervisor canonical URI")},
    {"desc", ""},
    {NULL, NULL}
};

static bool
cmdURI(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    uri = virConnectGetURI(ctl->conn);
    if (uri == NULL) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint(ctl, "%s\n", uri);
    VIR_FREE(uri);

    return true;
}

/*
 * "sysinfo" command
 */
static const vshCmdInfo info_sysinfo[] = {
    {"help", N_("print the hypervisor sysinfo")},
    {"desc",
     N_("output an XML string for the hypervisor sysinfo, if available")},
    {NULL, NULL}
};

static bool
cmdSysinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *sysinfo;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    sysinfo = virConnectGetSysinfo(ctl->conn, 0);
    if (sysinfo == NULL) {
        vshError(ctl, "%s", _("failed to get sysinfo"));
        return false;
    }

    vshPrint(ctl, "%s", sysinfo);
    VIR_FREE(sysinfo);

    return true;
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

/* Helper for snapshot-create and snapshot-create-as */
static bool
vshSnapshotCreate(vshControl *ctl, virDomainPtr dom, const char *buffer,
                  unsigned int flags, const char *from)
{
    bool ret = false;
    virDomainSnapshotPtr snapshot;
    bool halt = false;
    char *doc = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    const char *name = NULL;

    snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);

    /* Emulate --halt on older servers.  */
    if (!snapshot && last_error->code == VIR_ERR_INVALID_ARG &&
        (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        int persistent;

        virFreeError(last_error);
        last_error = NULL;
        persistent = virDomainIsPersistent(dom);
        if (persistent < 0) {
            virshReportError(ctl);
            goto cleanup;
        }
        if (!persistent) {
            vshError(ctl, "%s",
                     _("cannot halt after snapshot of transient domain"));
            goto cleanup;
        }
        if (virDomainIsActive(dom) == 1)
            halt = true;
        flags &= ~VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
        snapshot = virDomainSnapshotCreateXML(dom, buffer, flags);
    }

    if (snapshot == NULL)
        goto cleanup;

    if (halt && virDomainDestroy(dom) < 0) {
        virshReportError(ctl);
        goto cleanup;
    }

    name = virDomainSnapshotGetName(snapshot);
    if (!name) {
        vshError(ctl, "%s", _("Could not get snapshot name"));
        goto cleanup;
    }

    if (from)
        vshPrint(ctl, _("Domain snapshot %s created from '%s'"), name, from);
    else
        vshPrint(ctl, _("Domain snapshot %s created"), name);

    ret = true;

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    VIR_FREE(doc);
    return ret;
}

/*
 * "snapshot-create" command
 */
static const vshCmdInfo info_snapshot_create[] = {
    {"help", N_("Create a snapshot from XML")},
    {"desc", N_("Create a snapshot (disk and RAM) from XML")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_create[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"xmlfile", VSH_OT_DATA, 0, N_("domain snapshot XML")},
    {"redefine", VSH_OT_BOOL, 0, N_("redefine metadata for existing snapshot")},
    {"current", VSH_OT_BOOL, 0, N_("with redefine, set current snapshot")},
    {"no-metadata", VSH_OT_BOOL, 0, N_("take snapshot but create no metadata")},
    {"halt", VSH_OT_BOOL, 0, N_("halt domain after snapshot is created")},
    {"disk-only", VSH_OT_BOOL, 0, N_("capture disk state but not vm state")},
    {"reuse-external", VSH_OT_BOOL, 0, N_("reuse any existing external files")},
    {"quiesce", VSH_OT_BOOL, 0, N_("quiesce guest's file systems")},
    {"atomic", VSH_OT_BOOL, 0, N_("require atomic operation")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *from = NULL;
    char *buffer = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "redefine"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    if (vshCommandOptBool(cmd, "current"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;
    if (vshCommandOptBool(cmd, "no-metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA;
    if (vshCommandOptBool(cmd, "halt"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
    if (vshCommandOptBool(cmd, "disk-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE;
    if (vshCommandOptBool(cmd, "atomic"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "xmlfile", &from) <= 0)
        buffer = vshStrdup(ctl, "<domainsnapshot/>");
    else {
        if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
            /* we have to report the error here because during cleanup
             * we'll run through virDomainFree(), which loses the
             * last error
             */
            virshReportError(ctl);
            goto cleanup;
        }
    }
    if (buffer == NULL) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    ret = vshSnapshotCreate(ctl, dom, buffer, flags, from);

cleanup:
    VIR_FREE(buffer);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-create-as" command
 */
static int
vshParseSnapshotDiskspec(vshControl *ctl, virBufferPtr buf, const char *str)
{
    int ret = -1;
    char *name = NULL;
    char *snapshot = NULL;
    char *driver = NULL;
    char *file = NULL;
    char *spec = vshStrdup(ctl, str);
    char *tmp = spec;
    size_t len = strlen(str);

    if (*str == ',')
        goto cleanup;
    name = tmp;
    while ((tmp = strchr(tmp, ','))) {
        if (tmp[1] == ',') {
            /* Recognize ,, as an escape for a literal comma */
            memmove(&tmp[1], &tmp[2], len - (tmp - spec) - 2 + 1);
            len--;
            tmp++;
            continue;
        }
        /* Terminate previous string, look for next recognized one */
        *tmp++ = '\0';
        if (!snapshot && STRPREFIX(tmp, "snapshot="))
            snapshot = tmp + strlen("snapshot=");
        else if (!driver && STRPREFIX(tmp, "driver="))
            driver = tmp + strlen("driver=");
        else if (!file && STRPREFIX(tmp, "file="))
            file = tmp + strlen("file=");
        else
            goto cleanup;
    }

    virBufferEscapeString(buf, "    <disk name='%s'", name);
    if (snapshot)
        virBufferAsprintf(buf, " snapshot='%s'", snapshot);
    if (driver || file) {
        virBufferAddLit(buf, ">\n");
        if (driver)
            virBufferAsprintf(buf, "      <driver type='%s'/>\n", driver);
        if (file)
            virBufferEscapeString(buf, "      <source file='%s'/>\n", file);
        virBufferAddLit(buf, "    </disk>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    ret = 0;
cleanup:
    if (ret < 0)
        vshError(ctl, _("unable to parse diskspec: %s"), str);
    VIR_FREE(spec);
    return ret;
}

static const vshCmdInfo info_snapshot_create_as[] = {
    {"help", N_("Create a snapshot from a set of args")},
    {"desc", N_("Create a snapshot (disk and RAM) from arguments")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_create_as[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"name", VSH_OT_DATA, 0, N_("name of snapshot")},
    {"description", VSH_OT_DATA, 0, N_("description of snapshot")},
    {"print-xml", VSH_OT_BOOL, 0, N_("print XML document rather than create")},
    {"no-metadata", VSH_OT_BOOL, 0, N_("take snapshot but create no metadata")},
    {"halt", VSH_OT_BOOL, 0, N_("halt domain after snapshot is created")},
    {"disk-only", VSH_OT_BOOL, 0, N_("capture disk state but not vm state")},
    {"reuse-external", VSH_OT_BOOL, 0, N_("reuse any existing external files")},
    {"quiesce", VSH_OT_BOOL, 0, N_("quiesce guest's file systems")},
    {"atomic", VSH_OT_BOOL, 0, N_("require atomic operation")},
    {"diskspec", VSH_OT_ARGV, 0,
     N_("disk attributes: disk[,snapshot=type][,driver=type][,file=name]")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *buffer = NULL;
    const char *name = NULL;
    const char *desc = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;

    if (vshCommandOptBool(cmd, "no-metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_NO_METADATA;
    if (vshCommandOptBool(cmd, "halt"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_HALT;
    if (vshCommandOptBool(cmd, "disk-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
    if (vshCommandOptBool(cmd, "reuse-external"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_REUSE_EXT;
    if (vshCommandOptBool(cmd, "quiesce"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE;
    if (vshCommandOptBool(cmd, "atomic"))
        flags |= VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "name", &name) < 0 ||
        vshCommandOptString(cmd, "description", &desc) < 0) {
        vshError(ctl, _("argument must not be empty"));
        goto cleanup;
    }

    virBufferAddLit(&buf, "<domainsnapshot>\n");
    if (name)
        virBufferEscapeString(&buf, "  <name>%s</name>\n", name);
    if (desc)
        virBufferEscapeString(&buf, "  <description>%s</description>\n", desc);
    if (vshCommandOptBool(cmd, "diskspec")) {
        virBufferAddLit(&buf, "  <disks>\n");
        while ((opt = vshCommandOptArgv(cmd, opt))) {
            if (vshParseSnapshotDiskspec(ctl, &buf, opt->data) < 0) {
                virBufferFreeAndReset(&buf);
                goto cleanup;
            }
        }
        virBufferAddLit(&buf, "  </disks>\n");
    }
    virBufferAddLit(&buf, "</domainsnapshot>\n");

    buffer = virBufferContentAndReset(&buf);
    if (buffer == NULL) {
        vshError(ctl, "%s", _("Out of memory"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "print-xml")) {
        vshPrint(ctl, "%s\n",  buffer);
        ret = true;
        goto cleanup;
    }

    ret = vshSnapshotCreate(ctl, dom, buffer, flags, NULL);

cleanup:
    VIR_FREE(buffer);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/* Helper for resolving {--current | --ARG name} into a snapshot
 * belonging to DOM.  If EXCLUSIVE, fail if both --current and arg are
 * present.  On success, populate *SNAP and *NAME, before returning 0.
 * On failure, return -1 after issuing an error message.  */
static int
vshLookupSnapshot(vshControl *ctl, const vshCmd *cmd,
                  const char *arg, bool exclusive, virDomainPtr dom,
                  virDomainSnapshotPtr *snap, const char **name)
{
    bool current = vshCommandOptBool(cmd, "current");
    const char *snapname = NULL;

    if (vshCommandOptString(cmd, arg, &snapname) < 0) {
        vshError(ctl, _("invalid argument for --%s"), arg);
        return -1;
    }

    if (exclusive && current && snapname) {
        vshError(ctl, _("--%s and --current are mutually exclusive"), arg);
        return -1;
    }

    if (snapname) {
        *snap = virDomainSnapshotLookupByName(dom, snapname, 0);
    } else if (current) {
        *snap = virDomainSnapshotCurrent(dom, 0);
    } else {
        vshError(ctl, _("--%s or --current is required"), arg);
        return -1;
    }
    if (!*snap) {
        virshReportError(ctl);
        return -1;
    }

    *name = virDomainSnapshotGetName(*snap);
    return 0;
}

/*
 * "snapshot-edit" command
 */
static const vshCmdInfo info_snapshot_edit[] = {
    {"help", N_("edit XML for a snapshot")},
    {"desc", N_("Edit the domain snapshot XML for a named snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_edit[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("also set edited snapshot as current")},
    {"rename", VSH_OT_BOOL, 0, N_("allow renaming an existing snapshot")},
    {"clone", VSH_OT_BOOL, 0, N_("allow cloning to new name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotEdit(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virDomainSnapshotPtr edited = NULL;
    const char *name;
    const char *edited_name;
    bool ret = false;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    bool rename_okay = vshCommandOptBool(cmd, "rename");
    bool clone_okay = vshCommandOptBool(cmd, "clone");

    if (rename_okay && clone_okay) {
        vshError(ctl, "%s",
                 _("--rename and --clone are mutually exclusive"));
        return false;
    }

    if (vshCommandOptBool(cmd, "current") &&
        vshCommandOptBool(cmd, "snapshotname"))
        define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", false, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

#define EDIT_GET_XML \
    virDomainSnapshotGetXMLDesc(snapshot, getxml_flags)
#define EDIT_NOT_CHANGED \
    /* Depending on flags, we re-edit even if XML is unchanged.  */ \
    if (!(define_flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) {     \
        vshPrint(ctl,                                               \
                 _("Snapshot %s XML configuration not changed.\n"), \
                 name);                                             \
        ret = true;                                                 \
        goto cleanup;                                               \
    }
#define EDIT_DEFINE \
    (strstr(doc, "<state>disk-snapshot</state>") ? \
    define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY : 0), \
    edited = virDomainSnapshotCreateXML(dom, doc_edited, define_flags)
#define EDIT_FREE \
    if (edited) \
        virDomainSnapshotFree(edited);
#include "virsh-edit.c"

    edited_name = virDomainSnapshotGetName(edited);
    if (STREQ(name, edited_name)) {
        vshPrint(ctl, _("Snapshot %s edited.\n"), name);
    } else if (clone_okay) {
        vshPrint(ctl, _("Snapshot %s cloned to %s.\n"), name,
                 edited_name);
    } else {
        unsigned int delete_flags;

        delete_flags = VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;
        if (virDomainSnapshotDelete(rename_okay ? snapshot : edited,
                                    delete_flags) < 0) {
            virshReportError(ctl);
            vshError(ctl, _("Failed to clean up %s"),
                     rename_okay ? name : edited_name);
            goto cleanup;
        }
        if (!rename_okay) {
            vshError(ctl, _("Must use --rename or --clone to change %s to %s"),
                     name, edited_name);
            goto cleanup;
        }
    }

    ret = true;

cleanup:
    if (edited)
        virDomainSnapshotFree(edited);
    else
        vshError(ctl, _("Failed to update %s"), name);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "snapshot-current" command
 */
static const vshCmdInfo info_snapshot_current[] = {
    {"help", N_("Get or set the current snapshot")},
    {"desc", N_("Get or set the current snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_current[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"name", VSH_OT_BOOL, 0, N_("list the name, rather than the full xml")},
    {"security-info", VSH_OT_BOOL, 0,
     N_("include security sensitive information in XML dump")},
    {"snapshotname", VSH_OT_DATA, 0,
     N_("name of existing snapshot to make current")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotCurrent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    int current;
    virDomainSnapshotPtr snapshot = NULL;
    char *xml = NULL;
    const char *snapshotname = NULL;
    unsigned int flags = 0;
    const char *domname;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, &domname);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "snapshotname", &snapshotname) < 0) {
        vshError(ctl, _("invalid snapshotname argument '%s'"), snapshotname);
        goto cleanup;
    }
    if (snapshotname) {
        virDomainSnapshotPtr snapshot2 = NULL;
        flags = (VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
                 VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT);

        if (vshCommandOptBool(cmd, "name")) {
            vshError(ctl, "%s",
                     _("--name and snapshotname are mutually exclusive"));
            goto cleanup;
        }
        snapshot = virDomainSnapshotLookupByName(dom, snapshotname, 0);
        if (snapshot == NULL)
            goto cleanup;
        xml = virDomainSnapshotGetXMLDesc(snapshot, VIR_DOMAIN_XML_SECURE);
        if (!xml)
            goto cleanup;
        /* strstr is safe here, since xml came from libvirt API and not user */
        if (strstr(xml, "<state>disk-snapshot</state>"))
            flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;
        snapshot2 = virDomainSnapshotCreateXML(dom, xml, flags);
        if (snapshot2 == NULL)
            goto cleanup;
        virDomainSnapshotFree(snapshot2);
        vshPrint(ctl, _("Snapshot %s set as current"), snapshotname);
        ret = true;
        goto cleanup;
    }

    current = virDomainHasCurrentSnapshot(dom, 0);
    if (current < 0) {
        goto cleanup;
    } else if (!current) {
        vshError(ctl, _("domain '%s' has no current snapshot"), domname);
        goto cleanup;
    } else {
        const char *name = NULL;

        if (!(snapshot = virDomainSnapshotCurrent(dom, 0)))
            goto cleanup;

        if (vshCommandOptBool(cmd, "name")) {
            name = virDomainSnapshotGetName(snapshot);
            if (!name)
                goto cleanup;
        } else {
            xml = virDomainSnapshotGetXMLDesc(snapshot, flags);
            if (!xml)
                goto cleanup;
        }

        vshPrint(ctl, "%s", name ? name : xml);
    }

    ret = true;

cleanup:
    if (!ret)
        virshReportError(ctl);
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/* Helper function to get the name of a snapshot's parent.  Caller
 * must free the result.  Returns 0 on success (including when it was
 * proven no parent exists), and -1 on failure with error reported
 * (such as no snapshot support or domain deleted in meantime).  */
static int
vshGetSnapshotParent(vshControl *ctl, virDomainSnapshotPtr snapshot,
                     char **parent_name)
{
    virDomainSnapshotPtr parent = NULL;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    *parent_name = NULL;

    /* Try new API, since it is faster. */
    if (!ctl->useSnapshotOld) {
        parent = virDomainSnapshotGetParent(snapshot, 0);
        if (parent) {
            /* API works, and virDomainSnapshotGetName will succeed */
            *parent_name = vshStrdup(ctl, virDomainSnapshotGetName(parent));
            ret = 0;
            goto cleanup;
        }
        if (last_error->code == VIR_ERR_NO_DOMAIN_SNAPSHOT) {
            /* API works, and we found a root with no parent */
            ret = 0;
            goto cleanup;
        }
        /* API didn't work, fall back to XML scraping. */
        ctl->useSnapshotOld = true;
    }

    xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_snapshot)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    *parent_name = virXPathString("string(/domainsnapshot/parent/name)", ctxt);
    ret = 0;

cleanup:
    if (ret < 0) {
        virshReportError(ctl);
        vshError(ctl, "%s", _("unable to determine if snapshot has parent"));
    } else {
        virFreeError(last_error);
        last_error = NULL;
    }
    if (parent)
        virDomainSnapshotFree(parent);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xmldoc);
    VIR_FREE(xml);
    return ret;
}

/*
 * "snapshot-info" command
 */
static const vshCmdInfo info_snapshot_info[] = {
    {"help", N_("snapshot information")},
    {"desc", N_("Returns basic information about a snapshot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_info[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("info on current snapshot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotInfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainSnapshotPtr snapshot = NULL;
    const char *name;
    char *doc = NULL;
    char *tmp;
    char *parent = NULL;
    bool ret = false;
    int count;
    unsigned int flags;
    int current;
    int metadata;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        return false;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), name);
    vshPrint(ctl, "%-15s %s\n", _("Domain:"), virDomainGetName(dom));

    /* Determine if snapshot is current; this is useful enough that we
     * attempt a fallback.  */
    current = virDomainSnapshotIsCurrent(snapshot, 0);
    if (current < 0) {
        virDomainSnapshotPtr other = virDomainSnapshotCurrent(dom, 0);

        virResetLastError();
        current = 0;
        if (other) {
            if (STREQ(name, virDomainSnapshotGetName(other)))
                current = 1;
            virDomainSnapshotFree(other);
        }
    }
    vshPrint(ctl, "%-15s %s\n", _("Current:"),
             current > 0 ? _("yes") : _("no"));

    /* Get the XML configuration of the snapshot to determine the
     * state of the machine at the time of the snapshot.  */
    doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!doc)
        goto cleanup;

    tmp = strstr(doc, "<state>");
    if (!tmp) {
        vshError(ctl, "%s",
                 _("unexpected problem reading snapshot xml"));
        goto cleanup;
    }
    tmp += strlen("<state>");
    vshPrint(ctl, "%-15s %.*s\n", _("State:"),
             (int) (strchr(tmp, '<') - tmp), tmp);

    if (vshGetSnapshotParent(ctl, snapshot, &parent) < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %s\n", _("Parent:"), parent ? parent : "-");

    /* Children, Descendants.  After this point, the fallback to
     * compute children is too expensive, so we gracefully quit if the
     * APIs don't exist.  */
    if (ctl->useSnapshotOld) {
        ret = true;
        goto cleanup;
    }
    flags = 0;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %d\n", _("Children:"), count);
    flags = VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    count = virDomainSnapshotNumChildren(snapshot, flags);
    if (count < 0)
        goto cleanup;
    vshPrint(ctl, "%-15s %d\n", _("Descendants:"), count);

    /* Metadata; the fallback here relies on the fact that metadata
     * used to have an all-or-nothing effect on snapshot count.  */
    metadata = virDomainSnapshotHasMetadata(snapshot, 0);
    if (metadata < 0) {
        metadata = virDomainSnapshotNum(dom,
                                        VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
        virResetLastError();
    }
    if (metadata >= 0)
        vshPrint(ctl, "%-15s %s\n", _("Metadata:"),
                 metadata ? _("yes") : _("no"));

    ret = true;

cleanup:
    VIR_FREE(doc);
    VIR_FREE(parent);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    virDomainFree(dom);
    return ret;
}

/* Helpers for collecting a list of snapshots.  */
struct vshSnap {
    virDomainSnapshotPtr snap;
    char *parent;
};
struct vshSnapshotList {
    struct vshSnap *snaps;
    int nsnaps;
};
typedef struct vshSnapshotList *vshSnapshotListPtr;

static void
vshSnapshotListFree(vshSnapshotListPtr snaplist)
{
    int i;

    if (!snaplist)
        return;
    if (snaplist->snaps) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            if (snaplist->snaps[i].snap)
                virDomainSnapshotFree(snaplist->snaps[i].snap);
            VIR_FREE(snaplist->snaps[i].parent);
        }
        VIR_FREE(snaplist->snaps);
    }
    VIR_FREE(snaplist);
}

static int
vshSnapSorter(const void *a, const void *b)
{
    const struct vshSnap *sa = a;
    const struct vshSnap *sb = b;

    if (sa->snap && !sb->snap)
        return -1;
    if (!sa->snap)
        return sb->snap != NULL;

    /* User visible sort, so we want locale-specific case comparison.  */
    return strcasecmp(virDomainSnapshotGetName(sa->snap),
                      virDomainSnapshotGetName(sb->snap));
}

/* Compute a list of snapshots from DOM.  If FROM is provided, the
 * list is limited to descendants of the given snapshot.  If FLAGS is
 * given, the list is filtered.  If TREE is specified, then all but
 * FROM or the roots will also have parent information.  */
static vshSnapshotListPtr
vshSnapshotListCollect(vshControl *ctl, virDomainPtr dom,
                       virDomainSnapshotPtr from,
                       unsigned int flags, bool tree)
{
    int i;
    char **names = NULL;
    int count = -1;
    bool descendants = false;
    bool roots = false;
    virDomainSnapshotPtr *snaps;
    vshSnapshotListPtr snaplist = vshMalloc(ctl, sizeof(*snaplist));
    vshSnapshotListPtr ret = NULL;
    const char *fromname = NULL;
    int start_index = -1;
    int deleted = 0;

    /* Try the interface available in 0.9.13 and newer.  */
    if (!ctl->useSnapshotOld) {
        if (from)
            count = virDomainSnapshotListAllChildren(from, &snaps, flags);
        else
            count = virDomainListAllSnapshots(dom, &snaps, flags);
    }
    if (count >= 0) {
        /* When mixing --from and --tree, we also want a copy of from
         * in the list, but with no parent for that one entry.  */
        snaplist->snaps = vshCalloc(ctl, count + (tree && from),
                                    sizeof(*snaplist->snaps));
        snaplist->nsnaps = count;
        for (i = 0; i < count; i++)
            snaplist->snaps[i].snap = snaps[i];
        VIR_FREE(snaps);
        if (tree) {
            for (i = 0; i < count; i++) {
                if (vshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
                                         &snaplist->snaps[i].parent) < 0)
                    goto cleanup;
            }
            if (from) {
                snaps[snaplist->nsnaps++] = from;
                virDomainSnapshotRef(from);
            }
        }
        goto success;
    }

    /* Assume that if we got this far, then the --no-leaves and
     * --no-metadata flags were not supported.  Disable groups that
     * have no impact.  */
    /* XXX should we emulate --no-leaves?  */
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES &&
        flags & VIR_DOMAIN_SNAPSHOT_LIST_LEAVES)
        flags &= ~(VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES |
                   VIR_DOMAIN_SNAPSHOT_LIST_LEAVES);
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA &&
        flags & VIR_DOMAIN_SNAPSHOT_LIST_METADATA)
        flags &= ~(VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA |
                   VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
    if (flags & VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA) {
        /* We can emulate --no-metadata if --metadata was supported,
         * since it was an all-or-none attribute on old servers.  */
        count = virDomainSnapshotNum(dom,
                                     VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
        if (count < 0)
            goto cleanup;
        if (count > 0)
            return snaplist;
        flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA;
    }

    /* This uses the interfaces available in 0.8.0-0.9.6
     * (virDomainSnapshotListNames, global list only) and in
     * 0.9.7-0.9.12 (addition of virDomainSnapshotListChildrenNames
     * for child listing, and new flags), as follows, with [*] by the
     * combinations that need parent info (either for filtering
     * purposes or for the resulting tree listing):
     *                              old               new
     * list                         global as-is      global as-is
     * list --roots                *global + filter   global + flags
     * list --from                 *global + filter   child as-is
     * list --from --descendants   *global + filter   child + flags
     * list --tree                 *global as-is     *global as-is
     * list --tree --from          *global + filter  *child + flags
     *
     * Additionally, when --tree and --from are both used, from is
     * added to the final list as the only element without a parent.
     * Otherwise, --from does not appear in the final list.
     */
    if (from) {
        fromname = virDomainSnapshotGetName(from);
        if (!fromname) {
            vshError(ctl, "%s", _("Could not get snapshot name"));
            goto cleanup;
        }
        descendants = (flags & VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS) || tree;
        if (tree)
            flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;

        /* Determine if we can use the new child listing API.  */
        if (ctl->useSnapshotOld ||
            ((count = virDomainSnapshotNumChildren(from, flags)) < 0 &&
             last_error->code == VIR_ERR_NO_SUPPORT)) {
            /* We can emulate --from.  */
            /* XXX can we also emulate --leaves? */
            virFreeError(last_error);
            last_error = NULL;
            ctl->useSnapshotOld = true;
            flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
            goto global;
        }
        if (tree && count >= 0)
            count++;
    } else {
    global:
        /* Global listing (including fallback when --from failed with
         * child listing).  */
        count = virDomainSnapshotNum(dom, flags);

        /* Fall back to simulation if --roots was unsupported. */
        /* XXX can we also emulate --leaves? */
        if (!from && count < 0 && last_error->code == VIR_ERR_INVALID_ARG &&
            (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS)) {
            virFreeError(last_error);
            last_error = NULL;
            roots = true;
            flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
            count = virDomainSnapshotNum(dom, flags);
        }
    }

    if (count < 0) {
        if (!last_error)
            vshError(ctl, _("failed to collect snapshot list"));
        goto cleanup;
    }

    if (!count)
        goto success;

    names = vshCalloc(ctl, sizeof(*names), count);

    /* Now that we have a count, collect the list.  */
    if (from && !ctl->useSnapshotOld) {
        if (tree) {
            if (count)
                count = virDomainSnapshotListChildrenNames(from, names + 1,
                                                           count - 1, flags);
            if (count >= 0) {
                count++;
                names[0] = vshStrdup(ctl, fromname);
            }
        } else {
            count = virDomainSnapshotListChildrenNames(from, names,
                                                       count, flags);
        }
    } else {
        count = virDomainSnapshotListNames(dom, names, count, flags);
    }
    if (count < 0)
        goto cleanup;

    snaplist->snaps = vshCalloc(ctl, sizeof(*snaplist->snaps), count);
    snaplist->nsnaps = count;
    for (i = 0; i < count; i++) {
        snaplist->snaps[i].snap = virDomainSnapshotLookupByName(dom,
                                                                names[i], 0);
        if (!snaplist->snaps[i].snap)
            goto cleanup;
    }

    /* Collect parents when needed.  With the new API, --tree and
     * --from together put from as the first element without a parent;
     * with the old API we still need to do a post-process filtering
     * based on all parent information.  */
    if (tree || (from && ctl->useSnapshotOld) || roots) {
        for (i = (from && !ctl->useSnapshotOld); i < count; i++) {
            if (from && ctl->useSnapshotOld && STREQ(names[i], fromname)) {
                start_index = i;
                if (tree)
                    continue;
            }
            if (vshGetSnapshotParent(ctl, snaplist->snaps[i].snap,
                                     &snaplist->snaps[i].parent) < 0)
                goto cleanup;
            if ((from && ((tree && !snaplist->snaps[i].parent) ||
                          (!descendants &&
                           STRNEQ_NULLABLE(fromname,
                                           snaplist->snaps[i].parent)))) ||
                (roots && snaplist->snaps[i].parent)) {
                virDomainSnapshotFree(snaplist->snaps[i].snap);
                snaplist->snaps[i].snap = NULL;
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
            }
        }
    }
    if (tree)
        goto success;

    if (ctl->useSnapshotOld && descendants) {
        bool changed = false;
        bool remaining = false;

        /* Make multiple passes over the list - first pass finds
         * direct children and NULLs out all roots and from, remaining
         * passes NULL out any undecided entry whose parent is not
         * still in list.  We mark known descendants by clearing
         * snaps[i].parents.  Sorry, this is O(n^3) - hope your
         * hierarchy isn't huge.  XXX Is it worth making O(n^2 log n)
         * by using qsort and bsearch?  */
        if (start_index < 0) {
            vshError(ctl, _("snapshot %s disappeared from list"), fromname);
            goto cleanup;
        }
        for (i = 0; i < count; i++) {
            if (i == start_index || !snaplist->snaps[i].parent) {
                VIR_FREE(names[i]);
                virDomainSnapshotFree(snaplist->snaps[i].snap);
                snaplist->snaps[i].snap = NULL;
                VIR_FREE(snaplist->snaps[i].parent);
                deleted++;
            } else if (STREQ(snaplist->snaps[i].parent, fromname)) {
                VIR_FREE(snaplist->snaps[i].parent);
                changed = true;
            } else {
                remaining = true;
            }
        }
        if (!changed) {
            ret = vshMalloc(ctl, sizeof(*snaplist));
            goto cleanup;
        }
        while (changed && remaining) {
            changed = remaining = false;
            for (i = 0; i < count; i++) {
                bool found_parent = false;
                int j;

                if (!names[i] || !snaplist->snaps[i].parent)
                    continue;
                for (j = 0; j < count; j++) {
                    if (!names[j] || i == j)
                        continue;
                    if (STREQ(snaplist->snaps[i].parent, names[j])) {
                        found_parent = true;
                        if (!snaplist->snaps[j].parent)
                            VIR_FREE(snaplist->snaps[i].parent);
                        else
                            remaining = true;
                        break;
                    }
                }
                if (!found_parent) {
                    changed = true;
                    VIR_FREE(names[i]);
                    virDomainSnapshotFree(snaplist->snaps[i].snap);
                    snaplist->snaps[i].snap = NULL;
                    VIR_FREE(snaplist->snaps[i].parent);
                    deleted++;
                }
            }
        }
    }

success:
    qsort(snaplist->snaps, snaplist->nsnaps, sizeof(*snaplist->snaps),
          vshSnapSorter);
    snaplist->nsnaps -= deleted;

    ret = snaplist;
    snaplist = NULL;

cleanup:
    vshSnapshotListFree(snaplist);
    if (names)
        for (i = 0; i < count; i++)
            VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}

static const char *
vshSnapshotListLookup(int id, bool parent, void *opaque)
{
    vshSnapshotListPtr snaplist = opaque;
    if (parent)
        return snaplist->snaps[id].parent;
    return virDomainSnapshotGetName(snaplist->snaps[id].snap);
}

/*
 * "snapshot-list" command
 */
static const vshCmdInfo info_snapshot_list[] = {
    {"help", N_("List snapshots for a domain")},
    {"desc", N_("Snapshot List")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_list[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"parent", VSH_OT_BOOL, 0, N_("add a column showing parent snapshot")},
    {"roots", VSH_OT_BOOL, 0, N_("list only snapshots without parents")},
    {"leaves", VSH_OT_BOOL, 0, N_("list only snapshots without children")},
    {"no-leaves", VSH_OT_BOOL, 0,
     N_("list only snapshots that are not leaves (with children)")},
    {"metadata", VSH_OT_BOOL, 0,
     N_("list only snapshots that have metadata that would prevent undefine")},
    {"no-metadata", VSH_OT_BOOL, 0,
     N_("list only snapshots that have no metadata managed by libvirt")},
    {"tree", VSH_OT_BOOL, 0, N_("list snapshots in a tree")},
    {"from", VSH_OT_DATA, 0, N_("limit list to children of given snapshot")},
    {"current", VSH_OT_BOOL, 0,
     N_("limit list to children of current snapshot")},
    {"descendants", VSH_OT_BOOL, 0, N_("with --from, list all descendants")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotList(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    bool show_parent = false;
    int i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *state = NULL;
    char *parent = NULL;
    long long creation_longlong;
    time_t creation_time_t;
    char timestr[100];
    struct tm time_info;
    bool tree = vshCommandOptBool(cmd, "tree");
    bool leaves = vshCommandOptBool(cmd, "leaves");
    bool no_leaves = vshCommandOptBool(cmd, "no-leaves");
    const char *from = NULL;
    virDomainSnapshotPtr start = NULL;
    vshSnapshotListPtr snaplist = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if ((vshCommandOptBool(cmd, "from") ||
         vshCommandOptBool(cmd, "current")) &&
        vshLookupSnapshot(ctl, cmd, "from", true, dom, &start, &from) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "parent")) {
        if (vshCommandOptBool(cmd, "roots")) {
            vshError(ctl, "%s",
                     _("--parent and --roots are mutually exclusive"));
            goto cleanup;
        }
        if (tree) {
            vshError(ctl, "%s",
                     _("--parent and --tree are mutually exclusive"));
            goto cleanup;
        }
        show_parent = true;
    } else if (vshCommandOptBool(cmd, "roots")) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--roots and --tree are mutually exclusive"));
            goto cleanup;
        }
        if (from) {
            vshError(ctl, "%s",
                     _("--roots and --from are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
    }
    if (leaves) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--leaves and --tree are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_LEAVES;
    }
    if (no_leaves) {
        if (tree) {
            vshError(ctl, "%s",
                     _("--no-leaves and --tree are mutually exclusive"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES;
    }

    if (vshCommandOptBool(cmd, "metadata")) {
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_METADATA;
    }
    if (vshCommandOptBool(cmd, "no-metadata")) {
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA;
    }

    if (vshCommandOptBool(cmd, "descendants")) {
        if (!from) {
            vshError(ctl, "%s",
                     _("--descendants requires either --from or --current"));
            goto cleanup;
        }
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
    }

    if ((snaplist = vshSnapshotListCollect(ctl, dom, start, flags,
                                           tree)) == NULL)
        goto cleanup;

    if (!tree) {
        if (show_parent)
            vshPrintExtra(ctl, " %-20s %-25s %-15s %s",
                          _("Name"), _("Creation Time"), _("State"),
                          _("Parent"));
        else
            vshPrintExtra(ctl, " %-20s %-25s %s",
                          _("Name"), _("Creation Time"), _("State"));
        vshPrintExtra(ctl, "\n"
"------------------------------------------------------------\n");
    }

    if (!snaplist->nsnaps) {
        ret = true;
        goto cleanup;
    }

    if (tree) {
        for (i = 0; i < snaplist->nsnaps; i++) {
            if (!snaplist->snaps[i].parent &&
                vshTreePrint(ctl, vshSnapshotListLookup, snaplist,
                             snaplist->nsnaps, i) < 0)
                goto cleanup;
        }
        ret = true;
        goto cleanup;
    }

    for (i = 0; i < snaplist->nsnaps; i++) {
        const char *name;

        /* free up memory from previous iterations of the loop */
        VIR_FREE(parent);
        VIR_FREE(state);
        xmlXPathFreeContext(ctxt);
        xmlFreeDoc(xml);
        VIR_FREE(doc);

        snapshot = snaplist->snaps[i].snap;
        name = virDomainSnapshotGetName(snapshot);
        assert(name);

        doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
        if (!doc)
            continue;

        xml = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt);
        if (!xml)
            continue;

        if (show_parent)
            parent = virXPathString("string(/domainsnapshot/parent/name)",
                                    ctxt);

        state = virXPathString("string(/domainsnapshot/state)", ctxt);
        if (state == NULL)
            continue;
        if (virXPathLongLong("string(/domainsnapshot/creationTime)", ctxt,
                             &creation_longlong) < 0)
            continue;
        creation_time_t = creation_longlong;
        if (creation_time_t != creation_longlong) {
            vshError(ctl, "%s", _("time_t overflow"));
            continue;
        }
        localtime_r(&creation_time_t, &time_info);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z",
                 &time_info);

        if (parent)
            vshPrint(ctl, " %-20s %-25s %-15s %s\n",
                     name, timestr, state, parent);
        else
            vshPrint(ctl, " %-20s %-25s %s\n", name, timestr, state);
    }

    ret = true;

cleanup:
    /* this frees up memory from the last iteration of the loop */
    vshSnapshotListFree(snaplist);
    VIR_FREE(parent);
    VIR_FREE(state);
    if (start)
        virDomainSnapshotFree(start);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(doc);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-dumpxml" command
 */
static const vshCmdInfo info_snapshot_dumpxml[] = {
    {"help", N_("Dump XML for a domain snapshot")},
    {"desc", N_("Snapshot Dump XML")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("snapshot name")},
    {"security-info", VSH_OT_BOOL, 0,
     N_("include security sensitive information in XML dump")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshCommandOptString(cmd, "snapshotname", &name) <= 0)
        goto cleanup;

    snapshot = virDomainSnapshotLookupByName(dom, name, 0);
    if (snapshot == NULL)
        goto cleanup;

    xml = virDomainSnapshotGetXMLDesc(snapshot, flags);
    if (!xml)
        goto cleanup;

    vshPrint(ctl, "%s", xml);

    ret = true;

cleanup:
    VIR_FREE(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-parent" command
 */
static const vshCmdInfo info_snapshot_parent[] = {
    {"help", N_("Get the name of the parent of a snapshot")},
    {"desc", N_("Extract the snapshot's parent, if any")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_parent[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("find parent of snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("find parent of current snapshot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotParent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *parent = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

    if (vshGetSnapshotParent(ctl, snapshot, &parent) < 0)
        goto cleanup;
    if (!parent) {
        vshError(ctl, _("snapshot '%s' has no parent"), name);
        goto cleanup;
    }

    vshPrint(ctl, "%s", parent);

    ret = true;

cleanup:
    VIR_FREE(parent);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-revert" command
 */
static const vshCmdInfo info_snapshot_revert[] = {
    {"help", N_("Revert a domain to a snapshot")},
    {"desc", N_("Revert domain to snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_revert[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("revert to current snapshot")},
    {"running", VSH_OT_BOOL, 0, N_("after reverting, change state to running")},
    {"paused", VSH_OT_BOOL, 0, N_("after reverting, change state to paused")},
    {"force", VSH_OT_BOOL, 0, N_("try harder on risky reverts")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomainSnapshotRevert(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;
    bool force = false;
    int result;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED;
    /* We want virsh snapshot-revert --force to work even when talking
     * to older servers that did the unsafe revert by default but
     * reject the flag, so we probe without the flag, and only use it
     * when the error says it will make a difference.  */
    if (vshCommandOptBool(cmd, "force"))
        force = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

    result = virDomainRevertToSnapshot(snapshot, flags);
    if (result < 0 && force &&
        last_error->code == VIR_ERR_SNAPSHOT_REVERT_RISKY) {
        flags |= VIR_DOMAIN_SNAPSHOT_REVERT_FORCE;
        virFreeError(last_error);
        last_error = NULL;
        result = virDomainRevertToSnapshot(snapshot, flags);
    }
    if (result < 0)
        goto cleanup;

    ret = true;

cleanup:
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-delete" command
 */
static const vshCmdInfo info_snapshot_delete[] = {
    {"help", N_("Delete a domain snapshot")},
    {"desc", N_("Snapshot Delete")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_delete[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"snapshotname", VSH_OT_DATA, 0, N_("snapshot name")},
    {"current", VSH_OT_BOOL, 0, N_("delete current snapshot")},
    {"children", VSH_OT_BOOL, 0, N_("delete snapshot and all children")},
    {"children-only", VSH_OT_BOOL, 0, N_("delete children but not snapshot")},
    {"metadata", VSH_OT_BOOL, 0,
     N_("delete only libvirt metadata, leaving snapshot contents behind")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSnapshotDelete(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    const char *name = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    if (vshLookupSnapshot(ctl, cmd, "snapshotname", true, dom,
                          &snapshot, &name) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN;
    if (vshCommandOptBool(cmd, "children-only"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY;
    if (vshCommandOptBool(cmd, "metadata"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_METADATA_ONLY;

    /* XXX If we wanted, we could emulate DELETE_CHILDREN_ONLY even on
     * older servers that reject the flag, by manually computing the
     * list of descendants.  But that's a lot of code to maintain.  */
    if (virDomainSnapshotDelete(snapshot, flags) == 0) {
        if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)
            vshPrint(ctl, _("Domain snapshot %s children deleted\n"), name);
        else
            vshPrint(ctl, _("Domain snapshot %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete snapshot %s"), name);
        goto cleanup;
    }

    ret = true;

cleanup:
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "qemu-monitor-command" command
 */
static const vshCmdInfo info_qemu_monitor_command[] = {
    {"help", N_("QEMU Monitor Command")},
    {"desc", N_("QEMU Monitor Command")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_qemu_monitor_command[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"hmp", VSH_OT_BOOL, 0, N_("command is in human monitor protocol")},
    {"cmd", VSH_OT_ARGV, VSH_OFLAG_REQ, N_("command")},
    {NULL, 0, 0, NULL}
};

static bool
cmdQemuMonitorCommand(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    char *monitor_cmd = NULL;
    char *result = NULL;
    unsigned int flags = 0;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool pad = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        if (pad)
            virBufferAddChar(&buf, ' ');
        pad = true;
        virBufferAdd(&buf, opt->data, -1);
    }
    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to collect command"));
        goto cleanup;
    }
    monitor_cmd = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "hmp"))
        flags |= VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP;

    if (virDomainQemuMonitorCommand(dom, monitor_cmd, &result, flags) < 0)
        goto cleanup;

    printf("%s\n", result);

    ret = true;

cleanup:
    VIR_FREE(result);
    VIR_FREE(monitor_cmd);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "qemu-attach" command
 */
static const vshCmdInfo info_qemu_attach[] = {
    {"help", N_("QEMU Attach")},
    {"desc", N_("QEMU Attach")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_qemu_attach[] = {
    {"pid", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdQemuAttach(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    bool ret = false;
    unsigned int flags = 0;
    unsigned int pid_value; /* API uses unsigned int, not pid_t */

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (vshCommandOptUInt(cmd, "pid", &pid_value) <= 0) {
        vshError(ctl, "%s", _("missing pid value"));
        goto cleanup;
    }

    if (!(dom = virDomainQemuAttach(ctl->conn, pid_value, flags)))
        goto cleanup;

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s attached to pid %u\n"),
                 virDomainGetName(dom), pid_value);
        virDomainFree(dom);
        ret = true;
    } else {
        vshError(ctl, _("Failed to attach to pid %u"), pid_value);
    }

cleanup:
    return ret;
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

static virNWFilterPtr
vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                        const char **name, int flag)
{
    virNWFilterPtr nwfilter = NULL;
    const char *n = NULL;
    const char *optname = "nwfilter";
    if (!cmd_has_option(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && strlen(n) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter UUID\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (nwfilter == NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as nwfilter NAME\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByName(ctl->conn, n);
    }

    if (!nwfilter)
        vshError(ctl, _("failed to get nwfilter '%s'"), n);

    return nwfilter;
}

static virInterfacePtr
vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                         const char *optname,
                         const char **name, int flag)
{
    virInterfacePtr iface = NULL;
    const char *n = NULL;

    if (!optname)
       optname = "interface";
    if (!cmd_has_option(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by NAME */
    if (flag & VSH_BYNAME) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface NAME\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByName(ctl->conn, n);
    }
    /* try it by MAC */
    if (iface == NULL && (flag & VSH_BYMAC)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface MAC\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByMACString(ctl->conn, n);
    }

    if (!iface)
        vshError(ctl, _("failed to get interface '%s'"), n);

    return iface;
}

static virSecretPtr
vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, const char **name)
{
    virSecretPtr secret = NULL;
    const char *n = NULL;
    const char *optname = "secret";

    if (!cmd_has_option(ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_DEBUG,
             "%s: found option <%s>: %s\n", cmd->def->name, optname, n);

    if (name != NULL)
        *name = n;

    secret = virSecretLookupByUUIDString(ctl->conn, n);

    if (secret == NULL)
        vshError(ctl, _("failed to get secret '%s'"), n);

    return secret;
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
    int arg, len;
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
            if (virStrToLong_i(optarg, NULL, 10, &ctl->debug) < 0) {
                vshError(ctl, "%s", _("option -d takes a numeric argument"));
                exit(EXIT_FAILURE);
            }
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

static const vshCmdDef domManagementCmds[] = {
    {"attach-device", cmdAttachDevice, opts_attach_device,
     info_attach_device, 0},
    {"attach-disk", cmdAttachDisk, opts_attach_disk,
     info_attach_disk, 0},
    {"attach-interface", cmdAttachInterface, opts_attach_interface,
     info_attach_interface, 0},
    {"autostart", cmdAutostart, opts_autostart, info_autostart, 0},
    {"blkdeviotune", cmdBlkdeviotune, opts_blkdeviotune, info_blkdeviotune, 0},
    {"blkiotune", cmdBlkiotune, opts_blkiotune, info_blkiotune, 0},
    {"blockcopy", cmdBlockCopy, opts_block_copy, info_block_copy, 0},
    {"blockjob", cmdBlockJob, opts_block_job, info_block_job, 0},
    {"blockpull", cmdBlockPull, opts_block_pull, info_block_pull, 0},
    {"blockresize", cmdBlockResize, opts_block_resize, info_block_resize, 0},
    {"change-media", cmdChangeMedia, opts_change_media, info_change_media, 0},
#ifndef WIN32
    {"console", cmdConsole, opts_console, info_console, 0},
#endif
    {"cpu-baseline", cmdCPUBaseline, opts_cpu_baseline, info_cpu_baseline, 0},
    {"cpu-compare", cmdCPUCompare, opts_cpu_compare, info_cpu_compare, 0},
    {"cpu-stats", cmdCPUStats, opts_cpu_stats, info_cpu_stats, 0},
    {"create", cmdCreate, opts_create, info_create, 0},
    {"define", cmdDefine, opts_define, info_define, 0},
    {"desc", cmdDesc, opts_desc, info_desc, 0},
    {"destroy", cmdDestroy, opts_destroy, info_destroy, 0},
    {"detach-device", cmdDetachDevice, opts_detach_device,
     info_detach_device, 0},
    {"detach-disk", cmdDetachDisk, opts_detach_disk, info_detach_disk, 0},
    {"detach-interface", cmdDetachInterface, opts_detach_interface,
     info_detach_interface, 0},
    {"domdisplay", cmdDomDisplay, opts_domdisplay, info_domdisplay, 0},
    {"domhostname", cmdDomHostname, opts_domhostname, info_domhostname, 0},
    {"domid", cmdDomid, opts_domid, info_domid, 0},
    {"domif-setlink", cmdDomIfSetLink, opts_domif_setlink, info_domif_setlink, 0},
    {"domiftune", cmdDomIftune, opts_domiftune, info_domiftune, 0},
    {"domjobabort", cmdDomjobabort, opts_domjobabort, info_domjobabort, 0},
    {"domjobinfo", cmdDomjobinfo, opts_domjobinfo, info_domjobinfo, 0},
    {"domname", cmdDomname, opts_domname, info_domname, 0},
    {"dompmsuspend", cmdDomPMSuspend,
     opts_dom_pm_suspend, info_dom_pm_suspend, 0},
    {"dompmwakeup", cmdDomPMWakeup,
     opts_dom_pm_wakeup, info_dom_pm_wakeup, 0},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid, 0},
    {"domxml-from-native", cmdDomXMLFromNative, opts_domxmlfromnative,
     info_domxmlfromnative, 0},
    {"domxml-to-native", cmdDomXMLToNative, opts_domxmltonative,
     info_domxmltonative, 0},
    {"dump", cmdDump, opts_dump, info_dump, 0},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml, 0},
    {"edit", cmdEdit, opts_edit, info_edit, 0},
    {"inject-nmi", cmdInjectNMI, opts_inject_nmi, info_inject_nmi, 0},
    {"send-key", cmdSendKey, opts_send_key, info_send_key, 0},
    {"managedsave", cmdManagedSave, opts_managedsave, info_managedsave, 0},
    {"managedsave-remove", cmdManagedSaveRemove, opts_managedsaveremove,
     info_managedsaveremove, 0},
    {"maxvcpus", cmdMaxvcpus, opts_maxvcpus, info_maxvcpus, 0},
    {"memtune", cmdMemtune, opts_memtune, info_memtune, 0},
    {"migrate", cmdMigrate, opts_migrate, info_migrate, 0},
    {"migrate-setmaxdowntime", cmdMigrateSetMaxDowntime,
     opts_migrate_setmaxdowntime, info_migrate_setmaxdowntime, 0},
    {"migrate-setspeed", cmdMigrateSetMaxSpeed,
     opts_migrate_setspeed, info_migrate_setspeed, 0},
    {"migrate-getspeed", cmdMigrateGetMaxSpeed,
     opts_migrate_getspeed, info_migrate_getspeed, 0},
    {"numatune", cmdNumatune, opts_numatune, info_numatune, 0},
    {"reboot", cmdReboot, opts_reboot, info_reboot, 0},
    {"reset", cmdReset, opts_reset, info_reset, 0},
    {"restore", cmdRestore, opts_restore, info_restore, 0},
    {"resume", cmdResume, opts_resume, info_resume, 0},
    {"save", cmdSave, opts_save, info_save, 0},
    {"save-image-define", cmdSaveImageDefine, opts_save_image_define,
     info_save_image_define, 0},
    {"save-image-dumpxml", cmdSaveImageDumpxml, opts_save_image_dumpxml,
     info_save_image_dumpxml, 0},
    {"save-image-edit", cmdSaveImageEdit, opts_save_image_edit,
     info_save_image_edit, 0},
    {"schedinfo", cmdSchedinfo, opts_schedinfo, info_schedinfo, 0},
    {"screenshot", cmdScreenshot, opts_screenshot, info_screenshot, 0},
    {"setmaxmem", cmdSetmaxmem, opts_setmaxmem, info_setmaxmem, 0},
    {"setmem", cmdSetmem, opts_setmem, info_setmem, 0},
    {"setvcpus", cmdSetvcpus, opts_setvcpus, info_setvcpus, 0},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown, 0},
    {"start", cmdStart, opts_start, info_start, 0},
    {"suspend", cmdSuspend, opts_suspend, info_suspend, 0},
    {"ttyconsole", cmdTTYConsole, opts_ttyconsole, info_ttyconsole, 0},
    {"undefine", cmdUndefine, opts_undefine, info_undefine, 0},
    {"update-device", cmdUpdateDevice, opts_update_device,
     info_update_device, 0},
    {"vcpucount", cmdVcpucount, opts_vcpucount, info_vcpucount, 0},
    {"vcpuinfo", cmdVcpuinfo, opts_vcpuinfo, info_vcpuinfo, 0},
    {"vcpupin", cmdVcpuPin, opts_vcpupin, info_vcpupin, 0},
    {"vncdisplay", cmdVNCDisplay, opts_vncdisplay, info_vncdisplay, 0},
    {NULL, NULL, NULL, NULL, 0}
};

#include "virsh-domain-monitor.c"

static const vshCmdDef domMonitoringCmds[] = {
    {"domblkerror", cmdDomBlkError, opts_domblkerror, info_domblkerror, 0},
    {"domblkinfo", cmdDomblkinfo, opts_domblkinfo, info_domblkinfo, 0},
    {"domblklist", cmdDomblklist, opts_domblklist, info_domblklist, 0},
    {"domblkstat", cmdDomblkstat, opts_domblkstat, info_domblkstat, 0},
    {"domcontrol", cmdDomControl, opts_domcontrol, info_domcontrol, 0},
    {"domif-getlink", cmdDomIfGetLink, opts_domif_getlink, info_domif_getlink, 0},
    {"domiflist", cmdDomiflist, opts_domiflist, info_domiflist, 0},
    {"domifstat", cmdDomIfstat, opts_domifstat, info_domifstat, 0},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo, 0},
    {"dommemstat", cmdDomMemStat, opts_dommemstat, info_dommemstat, 0},
    {"domstate", cmdDomstate, opts_domstate, info_domstate, 0},
    {"list", cmdList, opts_list, info_list, 0},
    {NULL, NULL, NULL, NULL, 0}
};

#include "virsh-pool.c"

static const vshCmdDef storagePoolCmds[] = {
    {"find-storage-pool-sources-as", cmdPoolDiscoverSourcesAs,
     opts_find_storage_pool_sources_as, info_find_storage_pool_sources_as, 0},
    {"find-storage-pool-sources", cmdPoolDiscoverSources,
     opts_find_storage_pool_sources, info_find_storage_pool_sources, 0},
    {"pool-autostart", cmdPoolAutostart, opts_pool_autostart,
     info_pool_autostart, 0},
    {"pool-build", cmdPoolBuild, opts_pool_build, info_pool_build, 0},
    {"pool-create-as", cmdPoolCreateAs, opts_pool_X_as, info_pool_create_as, 0},
    {"pool-create", cmdPoolCreate, opts_pool_create, info_pool_create, 0},
    {"pool-define-as", cmdPoolDefineAs, opts_pool_X_as, info_pool_define_as, 0},
    {"pool-define", cmdPoolDefine, opts_pool_define, info_pool_define, 0},
    {"pool-delete", cmdPoolDelete, opts_pool_delete, info_pool_delete, 0},
    {"pool-destroy", cmdPoolDestroy, opts_pool_destroy, info_pool_destroy, 0},
    {"pool-dumpxml", cmdPoolDumpXML, opts_pool_dumpxml, info_pool_dumpxml, 0},
    {"pool-edit", cmdPoolEdit, opts_pool_edit, info_pool_edit, 0},
    {"pool-info", cmdPoolInfo, opts_pool_info, info_pool_info, 0},
    {"pool-list", cmdPoolList, opts_pool_list, info_pool_list, 0},
    {"pool-name", cmdPoolName, opts_pool_name, info_pool_name, 0},
    {"pool-refresh", cmdPoolRefresh, opts_pool_refresh, info_pool_refresh, 0},
    {"pool-start", cmdPoolStart, opts_pool_start, info_pool_start, 0},
    {"pool-undefine", cmdPoolUndefine, opts_pool_undefine,
     info_pool_undefine, 0},
    {"pool-uuid", cmdPoolUuid, opts_pool_uuid, info_pool_uuid, 0},
    {NULL, NULL, NULL, NULL, 0}
};

#include "virsh-volume.c"

static const vshCmdDef storageVolCmds[] = {
    {"vol-clone", cmdVolClone, opts_vol_clone, info_vol_clone, 0},
    {"vol-create-as", cmdVolCreateAs, opts_vol_create_as,
     info_vol_create_as, 0},
    {"vol-create", cmdVolCreate, opts_vol_create, info_vol_create, 0},
    {"vol-create-from", cmdVolCreateFrom, opts_vol_create_from,
     info_vol_create_from, 0},
    {"vol-delete", cmdVolDelete, opts_vol_delete, info_vol_delete, 0},
    {"vol-download", cmdVolDownload, opts_vol_download, info_vol_download, 0},
    {"vol-dumpxml", cmdVolDumpXML, opts_vol_dumpxml, info_vol_dumpxml, 0},
    {"vol-info", cmdVolInfo, opts_vol_info, info_vol_info, 0},
    {"vol-key", cmdVolKey, opts_vol_key, info_vol_key, 0},
    {"vol-list", cmdVolList, opts_vol_list, info_vol_list, 0},
    {"vol-name", cmdVolName, opts_vol_name, info_vol_name, 0},
    {"vol-path", cmdVolPath, opts_vol_path, info_vol_path, 0},
    {"vol-pool", cmdVolPool, opts_vol_pool, info_vol_pool, 0},
    {"vol-resize", cmdVolResize, opts_vol_resize, info_vol_resize, 0},
    {"vol-upload", cmdVolUpload, opts_vol_upload, info_vol_upload, 0},
    {"vol-wipe", cmdVolWipe, opts_vol_wipe, info_vol_wipe, 0},
    {NULL, NULL, NULL, NULL, 0}
};

#include "virsh-network.c"

static const vshCmdDef networkCmds[] = {
    {"net-autostart", cmdNetworkAutostart, opts_network_autostart,
     info_network_autostart, 0},
    {"net-create", cmdNetworkCreate, opts_network_create,
     info_network_create, 0},
    {"net-define", cmdNetworkDefine, opts_network_define,
     info_network_define, 0},
    {"net-destroy", cmdNetworkDestroy, opts_network_destroy,
     info_network_destroy, 0},
    {"net-dumpxml", cmdNetworkDumpXML, opts_network_dumpxml,
     info_network_dumpxml, 0},
    {"net-edit", cmdNetworkEdit, opts_network_edit, info_network_edit, 0},
    {"net-info", cmdNetworkInfo, opts_network_info, info_network_info, 0},
    {"net-list", cmdNetworkList, opts_network_list, info_network_list, 0},
    {"net-name", cmdNetworkName, opts_network_name, info_network_name, 0},
    {"net-start", cmdNetworkStart, opts_network_start, info_network_start, 0},
    {"net-undefine", cmdNetworkUndefine, opts_network_undefine,
     info_network_undefine, 0},
    {"net-uuid", cmdNetworkUuid, opts_network_uuid, info_network_uuid, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef nodedevCmds[] = {
    {"nodedev-create", cmdNodeDeviceCreate, opts_node_device_create,
     info_node_device_create, 0},
    {"nodedev-destroy", cmdNodeDeviceDestroy, opts_node_device_destroy,
     info_node_device_destroy, 0},
    {"nodedev-detach", cmdNodeDeviceDetach, opts_node_device_detach,
     info_node_device_detach, 0},
    {"nodedev-dettach", cmdNodeDeviceDetach, opts_node_device_detach,
     info_node_device_detach, VSH_CMD_FLAG_ALIAS},
    {"nodedev-dumpxml", cmdNodeDeviceDumpXML, opts_node_device_dumpxml,
     info_node_device_dumpxml, 0},
    {"nodedev-list", cmdNodeListDevices, opts_node_list_devices,
     info_node_list_devices, 0},
    {"nodedev-reattach", cmdNodeDeviceReAttach, opts_node_device_reattach,
     info_node_device_reattach, 0},
    {"nodedev-reset", cmdNodeDeviceReset, opts_node_device_reset,
     info_node_device_reset, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef ifaceCmds[] = {
    {"iface-begin", cmdInterfaceBegin, opts_interface_begin,
     info_interface_begin, 0},
    {"iface-bridge", cmdInterfaceBridge, opts_interface_bridge,
     info_interface_bridge, 0},
    {"iface-commit", cmdInterfaceCommit, opts_interface_commit,
     info_interface_commit, 0},
    {"iface-define", cmdInterfaceDefine, opts_interface_define,
     info_interface_define, 0},
    {"iface-destroy", cmdInterfaceDestroy, opts_interface_destroy,
     info_interface_destroy, 0},
    {"iface-dumpxml", cmdInterfaceDumpXML, opts_interface_dumpxml,
     info_interface_dumpxml, 0},
    {"iface-edit", cmdInterfaceEdit, opts_interface_edit,
     info_interface_edit, 0},
    {"iface-list", cmdInterfaceList, opts_interface_list,
     info_interface_list, 0},
    {"iface-mac", cmdInterfaceMAC, opts_interface_mac,
     info_interface_mac, 0},
    {"iface-name", cmdInterfaceName, opts_interface_name,
     info_interface_name, 0},
    {"iface-rollback", cmdInterfaceRollback, opts_interface_rollback,
     info_interface_rollback, 0},
    {"iface-start", cmdInterfaceStart, opts_interface_start,
     info_interface_start, 0},
    {"iface-unbridge", cmdInterfaceUnbridge, opts_interface_unbridge,
     info_interface_unbridge, 0},
    {"iface-undefine", cmdInterfaceUndefine, opts_interface_undefine,
     info_interface_undefine, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef nwfilterCmds[] = {
    {"nwfilter-define", cmdNWFilterDefine, opts_nwfilter_define,
     info_nwfilter_define, 0},
    {"nwfilter-dumpxml", cmdNWFilterDumpXML, opts_nwfilter_dumpxml,
     info_nwfilter_dumpxml, 0},
    {"nwfilter-edit", cmdNWFilterEdit, opts_nwfilter_edit,
     info_nwfilter_edit, 0},
    {"nwfilter-list", cmdNWFilterList, opts_nwfilter_list,
     info_nwfilter_list, 0},
    {"nwfilter-undefine", cmdNWFilterUndefine, opts_nwfilter_undefine,
     info_nwfilter_undefine, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef secretCmds[] = {
    {"secret-define", cmdSecretDefine, opts_secret_define,
     info_secret_define, 0},
    {"secret-dumpxml", cmdSecretDumpXML, opts_secret_dumpxml,
     info_secret_dumpxml, 0},
    {"secret-get-value", cmdSecretGetValue, opts_secret_get_value,
     info_secret_get_value, 0},
    {"secret-list", cmdSecretList, NULL, info_secret_list, 0},
    {"secret-set-value", cmdSecretSetValue, opts_secret_set_value,
     info_secret_set_value, 0},
    {"secret-undefine", cmdSecretUndefine, opts_secret_undefine,
     info_secret_undefine, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef virshCmds[] = {
    {"cd", cmdCd, opts_cd, info_cd, VSH_CMD_FLAG_NOCONNECT},
    {"echo", cmdEcho, opts_echo, info_echo, VSH_CMD_FLAG_NOCONNECT},
    {"exit", cmdQuit, NULL, info_quit, VSH_CMD_FLAG_NOCONNECT},
    {"help", cmdHelp, opts_help, info_help, VSH_CMD_FLAG_NOCONNECT},
    {"pwd", cmdPwd, NULL, info_pwd, VSH_CMD_FLAG_NOCONNECT},
    {"quit", cmdQuit, NULL, info_quit, VSH_CMD_FLAG_NOCONNECT},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef snapshotCmds[] = {
    {"snapshot-create", cmdSnapshotCreate, opts_snapshot_create,
     info_snapshot_create, 0},
    {"snapshot-create-as", cmdSnapshotCreateAs, opts_snapshot_create_as,
     info_snapshot_create_as, 0},
    {"snapshot-current", cmdSnapshotCurrent, opts_snapshot_current,
     info_snapshot_current, 0},
    {"snapshot-delete", cmdSnapshotDelete, opts_snapshot_delete,
     info_snapshot_delete, 0},
    {"snapshot-dumpxml", cmdSnapshotDumpXML, opts_snapshot_dumpxml,
     info_snapshot_dumpxml, 0},
    {"snapshot-edit", cmdSnapshotEdit, opts_snapshot_edit,
     info_snapshot_edit, 0},
    {"snapshot-info", cmdSnapshotInfo, opts_snapshot_info,
     info_snapshot_info, 0},
    {"snapshot-list", cmdSnapshotList, opts_snapshot_list,
     info_snapshot_list, 0},
    {"snapshot-parent", cmdSnapshotParent, opts_snapshot_parent,
     info_snapshot_parent, 0},
    {"snapshot-revert", cmdDomainSnapshotRevert, opts_snapshot_revert,
     info_snapshot_revert, 0},
    {NULL, NULL, NULL, NULL, 0}
};

static const vshCmdDef hostAndHypervisorCmds[] = {
    {"capabilities", cmdCapabilities, NULL, info_capabilities, 0},
    {"connect", cmdConnect, opts_connect, info_connect,
     VSH_CMD_FLAG_NOCONNECT},
    {"freecell", cmdFreecell, opts_freecell, info_freecell, 0},
    {"hostname", cmdHostname, NULL, info_hostname, 0},
    {"nodecpustats", cmdNodeCpuStats, opts_node_cpustats, info_nodecpustats, 0},
    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo, 0},
    {"nodememstats", cmdNodeMemStats, opts_node_memstats, info_nodememstats, 0},
    {"nodesuspend", cmdNodeSuspend, opts_node_suspend, info_nodesuspend, 0},
    {"qemu-attach", cmdQemuAttach, opts_qemu_attach, info_qemu_attach, 0},
    {"qemu-monitor-command", cmdQemuMonitorCommand, opts_qemu_monitor_command,
     info_qemu_monitor_command, 0},
    {"sysinfo", cmdSysinfo, NULL, info_sysinfo, 0},
    {"uri", cmdURI, NULL, info_uri, 0},
    {"version", cmdVersion, opts_version, info_version, 0},
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
