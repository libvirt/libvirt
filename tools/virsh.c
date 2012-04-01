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

static virNetworkPtr vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                                            const char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptNetwork(_ctl, _cmd, _name)                    \
    vshCommandOptNetworkBy(_ctl, _cmd, _name,                      \
                           VSH_BYUUID|VSH_BYNAME)

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

static virStoragePoolPtr vshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd,
                            const char *optname, const char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptPool(_ctl, _cmd, _optname, _name)           \
    vshCommandOptPoolBy(_ctl, _cmd, _optname, _name,             \
                           VSH_BYUUID|VSH_BYNAME)

static virStorageVolPtr vshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                                           const char *optname,
                                           const char *pooloptname,
                                           const char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptVol(_ctl, _cmd, _optname, _pooloptname, _name)   \
    vshCommandOptVolBy(_ctl, _cmd, _optname, _pooloptname, _name,     \
                           VSH_BYUUID|VSH_BYNAME)

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

static char *editWriteToTempFile (vshControl *ctl, const char *doc);
static int   editFile (vshControl *ctl, const char *filename);
static char *editReadBackFile (vshControl *ctl, const char *filename);

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

static int idsorter(const void *a, const void *b) {
  const int *ia = (const int *)a;
  const int *ib = (const int *)b;

  if (*ia > *ib)
    return 1;
  else if (*ia < *ib)
    return -1;
  return 0;
}
static int namesorter(const void *a, const void *b) {
  const char **sa = (const char**)a;
  const char **sb = (const char**)b;

  /* User visible sort, so we want locale-specific case comparison.  */
  return strcasecmp(*sa, *sb);
}

static double
prettyCapacity(unsigned long long val,
               const char **unit) {
    if (val < 1024) {
        *unit = "";
        return (double)val;
    } else if (val < (1024.0l * 1024.0l)) {
        *unit = "KB";
        return (((double)val / 1024.0l));
    } else if (val < (1024.0l * 1024.0l * 1024.0l)) {
        *unit = "MB";
        return (double)val / (1024.0l * 1024.0l);
    } else if (val < (1024.0l * 1024.0l * 1024.0l * 1024.0l)) {
        *unit = "GB";
        return (double)val / (1024.0l * 1024.0l * 1024.0l);
    } else {
        *unit = "TB";
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
    if ((sig == SIGPIPE) ||
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
 * "autostart" command
 */
static const vshCmdInfo info_autostart[] = {
    {"help", N_("autostart a domain")},
    {"desc",
     N_("Configure a domain to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_autostart[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"disable", VSH_OT_BOOL, 0, N_("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static bool
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virDomainSetAutostart(dom, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("Failed to mark domain %s as autostarted"), name);
        else
            vshError(ctl, _("Failed to unmark domain %s as autostarted"), name);
        virDomainFree(dom);
        return false;
    }

    if (autostart)
        vshPrint(ctl, _("Domain %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Domain %s unmarked as autostarted\n"), name);

    virDomainFree(dom);
    return true;
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

#ifndef WIN32

/*
 * "console" command
 */
static const vshCmdInfo info_console[] = {
    {"help", N_("connect to the guest console")},
    {"desc",
     N_("Connect the virtual serial console for the guest")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_console[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"devname", VSH_OT_STRING, 0, N_("character device name")},
    {"force", VSH_OT_BOOL, 0,
      N_("force console connection (disconnect already connected sessions)")},
    {"safe", VSH_OT_BOOL, 0,
      N_("only connect if safe console handling is supported")},
    {NULL, 0, 0, NULL}
};

static bool
cmdRunConsole(vshControl *ctl, virDomainPtr dom,
              const char *name,
              unsigned int flags)
{
    bool ret = false;
    int state;

    if ((state = vshDomainState(ctl, dom, NULL)) < 0) {
        vshError(ctl, "%s", _("Unable to get domain status"));
        goto cleanup;
    }

    if (state == VIR_DOMAIN_SHUTOFF) {
        vshError(ctl, "%s", _("The domain is not running"));
        goto cleanup;
    }

    if (!isatty(STDIN_FILENO)) {
        vshError(ctl, "%s", _("Cannot run interactive console without a controlling TTY"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Connected to domain %s\n"), virDomainGetName(dom));
    vshPrintExtra(ctl, _("Escape character is %s\n"), ctl->escapeChar);
    fflush(stdout);
    if (vshRunConsole(dom, name, ctl->escapeChar, flags) == 0)
        ret = true;

 cleanup:

    return ret;
}

static bool
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    bool force = vshCommandOptBool(cmd, "force");
    bool safe = vshCommandOptBool(cmd, "safe");
    unsigned int flags = 0;
    const char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "devname", &name) < 0) {
        vshError(ctl, "%s", _("Invalid devname"));
        goto cleanup;
    }

    if (force)
        flags |= VIR_DOMAIN_CONSOLE_FORCE;
    if (safe)
        flags |= VIR_DOMAIN_CONSOLE_SAFE;

    ret = cmdRunConsole(ctl, dom, name, flags);

cleanup:
    virDomainFree(dom);
    return ret;
}

#endif /* WIN32 */


/*
 * "list" command
 */
static const vshCmdInfo info_list[] = {
    {"help", N_("list domains")},
    {"desc", N_("Returns list of domains.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive domains")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active domains")},
    {"transient", VSH_OT_BOOL, 0, N_("list transient domains")},
    {"persistent", VSH_OT_BOOL, 0, N_("list persistent domains")},
    {"uuid", VSH_OT_BOOL, 0, N_("list uuid's only")},
    {"name", VSH_OT_BOOL, 0, N_("list domain names only")},
    {"table", VSH_OT_BOOL, 0, N_("list table (default)")},
    {"managed-save", VSH_OT_BOOL, 0,
     N_("mark domains with managed save state")},
    {"title", VSH_OT_BOOL, 0, N_("show short domain description")},
    {NULL, 0, 0, NULL}
};


static bool
cmdList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int *ids = NULL, maxid = 0, i;
    char **names = NULL;
    int maxname = 0;
    bool managed = vshCommandOptBool(cmd, "managed-save");
    bool optTitle = vshCommandOptBool(cmd, "title");
    bool optTable = vshCommandOptBool(cmd, "table");
    bool optUUID = vshCommandOptBool(cmd, "uuid");
    bool optName = vshCommandOptBool(cmd, "name");
    bool optPersistent = vshCommandOptBool(cmd, "persistent");
    bool optTransient = vshCommandOptBool(cmd, "transient");
    bool persistUsed = true;
    virDomainPtr dom = NULL;
    char *title;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int state;
    int persistent;
    bool ret = false;

    inactive |= all;

    /* process arguments */
    if (!optPersistent && !optTransient) {
        optPersistent = true;
        optTransient = true;
        persistUsed = false;
    }

    if (optTable + optName + optUUID > 1) {
        vshError(ctl, "%s",
                 _("Only one argument from --table, --name and --uuid "
                   "may be specified."));
        return false;
    }

    if (!optUUID && !optName)
        optTable = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (active) {
        maxid = virConnectNumOfDomains(ctl->conn);
        if (maxid < 0) {
            vshError(ctl, "%s", _("Failed to list active domains"));
            return false;
        }
        if (maxid) {
            ids = vshMalloc(ctl, sizeof(int) * maxid);

            if ((maxid = virConnectListDomains(ctl->conn, ids, maxid)) < 0) {
                vshError(ctl, "%s", _("Failed to list active domains"));
                goto cleanup;
            }

            qsort(ids, maxid, sizeof(int), idsorter);
        }
    }

    if (inactive) {
        maxname = virConnectNumOfDefinedDomains(ctl->conn);
        if (maxname < 0) {
            vshError(ctl, "%s", _("Failed to list inactive domains"));
            goto cleanup;
        }
        if (maxname) {
            names = vshMalloc(ctl, sizeof(char *) * maxname);

            if ((maxname = virConnectListDefinedDomains(ctl->conn,
                                                        names,
                                                        maxname)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive domains"));
                goto cleanup;
            }

            qsort(&names[0], maxname, sizeof(char*), namesorter);
        }
    }

    /* print table header in legacy mode */
    if (optTable) {
        if (optTitle) {
            vshPrintExtra(ctl, " %-5s %-30s %-10s %-20s\n%s\n",
                          _("Id"), _("Name"), _("State"), _("Title"),
                          "-----------------------------------------"
                          "-----------------------------------------");
        } else {
            vshPrintExtra(ctl, " %-5s %-30s %s\n%s\n",
                          _("Id"), _("Name"), _("State"),
                          "-----------------------------------------"
                          "-----------");
        }
    }

    for (i = 0; i < maxid; i++) {
         dom = virDomainLookupByID(ctl->conn, ids[i]);

        /* this kind of work with domains is not atomic operation */
        if (!dom)
            continue;

        if (persistUsed) {
            persistent = virDomainIsPersistent(dom);
            if (persistent < 0) {
                vshError(ctl, "%s",
                         _("Failed to determine domain's persistent state"));
                goto cleanup;
            }

            if ((persistent && !optPersistent) ||
                (!persistent && !optTransient)) {
                virDomainFree(dom);
                dom = NULL;
                continue;
            }
       }

       if (optTable) {
           if (optTitle) {
               if (!(title = vshGetDomainDescription(ctl, dom, true, 0)))
                   goto cleanup;

               vshPrint(ctl, " %-5d %-30s %-10s %-20s\n",
                        virDomainGetID(dom),
                        virDomainGetName(dom),
                        _(vshDomainStateToString(vshDomainState(ctl, dom, NULL))),
                        title);
               VIR_FREE(title);
           } else {
               vshPrint(ctl, " %-5d %-30s %s\n",
                        virDomainGetID(dom),
                        virDomainGetName(dom),
                        _(vshDomainStateToString(vshDomainState(ctl, dom, NULL))));
           }
       } else if (optUUID) {
           if (virDomainGetUUIDString(dom, uuid) < 0) {
               vshError(ctl, "%s",
                        _("Failed to get domain's UUID"));
               goto cleanup;
           }
           vshPrint(ctl, "%s\n", uuid);
       } else if (optName) {
           vshPrint(ctl, "%s\n", virDomainGetName(dom));
       }

       virDomainFree(dom);
       dom = NULL;
    }

    if (optPersistent) {
        for (i = 0; i < maxname; i++) {
            dom = virDomainLookupByName(ctl->conn, names[i]);

            /* this kind of work with domains is not atomic operation */
            if (!dom)
                continue;

            if (optTable) {
                state = vshDomainState(ctl, dom, NULL);
                if (managed && state == VIR_DOMAIN_SHUTOFF &&
                    virDomainHasManagedSaveImage(dom, 0) > 0)
                    state = -2;

                if (optTitle) {
                    if (!(title = vshGetDomainDescription(ctl, dom, true, 0)))
                        goto cleanup;

                    vshPrint(ctl, " %-5s %-30s %-10s %-20s\n",
                             "-",
                             names[i],
                             state == -2 ? _("saved") : _(vshDomainStateToString(state)),
                             title);
                    VIR_FREE(title);
                } else {
                    vshPrint(ctl, " %-5s %-30s %s\n",
                             "-",
                             names[i],
                             state == -2 ? _("saved") : _(vshDomainStateToString(state)));
                }
           } else if (optUUID) {
               if (virDomainGetUUIDString(dom, uuid) < 0) {
                   vshError(ctl, "%s",
                            _("Failed to get domain's UUID"));
                   goto cleanup;
               }
               vshPrint(ctl, "%s\n", uuid);
           } else if (optName) {
               vshPrint(ctl, "%s\n", names[i]);
           }

           virDomainFree(dom);
           dom = NULL;
        }
    }

    ret = true;
cleanup:
    if (dom)
        virDomainFree(dom);
    VIR_FREE(ids);
    for (i = 0; i < maxname; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);
    return ret;
}

/*
 * "desc" command for managing domain description and title
 */
static const vshCmdInfo info_desc[] = {
    {"help", N_("show or set domain's description or title")},
    {"desc", N_("Allows to show or modify description or title of a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_desc[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"live", VSH_OT_BOOL, 0, N_("modify/get running state")},
    {"config", VSH_OT_BOOL, 0, N_("modify/get persistent configuration")},
    {"current", VSH_OT_BOOL, 0, N_("modify/get current state configuration")},
    {"title", VSH_OT_BOOL, 0, N_("modify the title instead of description")},
    {"edit", VSH_OT_BOOL, 0, N_("open an editor to modify the description")},
    {"new-desc", VSH_OT_ARGV, 0, N_("message")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDesc(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virDomainPtr dom;
    bool config = vshCommandOptBool(cmd, "config");
    bool live = vshCommandOptBool(cmd, "live");
    bool current = vshCommandOptBool(cmd, "current");

    bool title = vshCommandOptBool(cmd, "title");
    bool edit = vshCommandOptBool(cmd, "edit");

    int state;
    int type;
    char *desc = NULL;
    char *desc_edited = NULL;
    char *tmp = NULL;
    char *tmpstr;
    const vshCmdOpt *opt = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool pad = false;
    bool ret = false;
    unsigned int flags = VIR_DOMAIN_AFFECT_CURRENT;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = vshDomainState(ctl, dom, NULL)) < 0)
        goto cleanup;

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        if (pad)
            virBufferAddChar(&buf, ' ');
        pad = true;
        virBufferAdd(&buf, opt->data, -1);
    }

    if (title)
        type = VIR_DOMAIN_METADATA_TITLE;
    else
        type = VIR_DOMAIN_METADATA_DESCRIPTION;

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to collect new description/title"));
        goto cleanup;
    }
    desc = virBufferContentAndReset(&buf);

    if (edit || desc) {
        if (!desc) {
                desc = vshGetDomainDescription(ctl, dom, title,
                                           config?VIR_DOMAIN_XML_INACTIVE:0);
                if (!desc)
                    goto cleanup;
        }

        if (edit) {
            /* Create and open the temporary file. */
            if (!(tmp = editWriteToTempFile(ctl, desc)))
                goto cleanup;

            /* Start the editor. */
            if (editFile(ctl, tmp) == -1)
                goto cleanup;

            /* Read back the edited file. */
            if (!(desc_edited = editReadBackFile(ctl, tmp)))
                goto cleanup;

            /* strip a possible newline at the end of file; some
             * editors enforce a newline, this makes editing the title
             * more convenient */
            if (title &&
                (tmpstr = strrchr(desc_edited, '\n')) &&
                *(tmpstr+1) == '\0')
                *tmpstr = '\0';

            /* Compare original XML with edited.  Has it changed at all? */
            if (STREQ(desc, desc_edited)) {
                vshPrint(ctl, _("Domain description not changed.\n"));
                ret = true;
                goto cleanup;
            }

            VIR_FREE(desc);
            desc = desc_edited;
            desc_edited = NULL;
        }

        if (virDomainSetMetadata(dom, type, desc, NULL, NULL, flags) < 0) {
            vshError(ctl, "%s",
                     _("Failed to set new domain description"));
            goto cleanup;
        }
        vshPrint(ctl, "%s", _("Domain description updated successfully"));
    } else {
        desc = vshGetDomainDescription(ctl, dom, title,
                                       config?VIR_DOMAIN_XML_INACTIVE:0);
        if (!desc)
            goto cleanup;

        if (strlen(desc) > 0)
            vshPrint(ctl, "%s", desc);
        else
            vshPrint(ctl, _("No description for domain: %s"),
                     virDomainGetName(dom));
    }

    ret = true;
cleanup:
    VIR_FREE(desc_edited);
    VIR_FREE(desc);
    if (tmp) {
        unlink(tmp);
        VIR_FREE(tmp);
    }
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "domstate" command
 */
static const vshCmdInfo info_domstate[] = {
    {"help", N_("domain state")},
    {"desc", N_("Returns state about a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domstate[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"reason", VSH_OT_BOOL, 0, N_("also print reason for the state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomstate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    int showReason = vshCommandOptBool(cmd, "reason");
    int state, reason;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((state = vshDomainState(ctl, dom, &reason)) < 0) {
        ret = false;
        goto cleanup;
    }

    if (showReason) {
        vshPrint(ctl, "%s (%s)\n",
                 _(vshDomainStateToString(state)),
                 vshDomainStateReasonToString(state, reason));
    } else {
        vshPrint(ctl, "%s\n",
                 _(vshDomainStateToString(state)));
    }

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "domcontrol" command
 */
static const vshCmdInfo info_domcontrol[] = {
    {"help", N_("domain control interface state")},
    {"desc", N_("Returns state of a control interface to the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domcontrol[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomControl(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    virDomainControlInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetControlInfo(dom, &info, 0) < 0) {
        ret = false;
        goto cleanup;
    }

    if (info.state != VIR_DOMAIN_CONTROL_OK &&
        info.state != VIR_DOMAIN_CONTROL_ERROR) {
        vshPrint(ctl, "%s (%0.3fs)\n",
                 _(vshDomainControlStateToString(info.state)),
                 info.stateTime / 1000.0);
    } else {
        vshPrint(ctl, "%s\n",
                 _(vshDomainControlStateToString(info.state)));
    }

cleanup:
    virDomainFree(dom);
    return ret;
}

/* "domblkstat" command
 */
static const vshCmdInfo info_domblkstat[] = {
    {"help", N_("get device block stats for a domain")},
    {"desc", N_("Get device block stats for a running domain. See man page or "
                "use --human for explanation of fields")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domblkstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {"human",  VSH_OT_BOOL, 0, N_("print a more human readable output")},
    {NULL, 0, 0, NULL}
};

struct _domblkstat_sequence {
    const char *field;  /* field name */
    const char *legacy; /* legacy name from previous releases */
    const char *human;  /* human-friendly explanation */
};

/* sequence of values for output to honor legacy format from previous
 * versions */
static const struct _domblkstat_sequence domblkstat_output[] = {
    { VIR_DOMAIN_BLOCK_STATS_READ_REQ,          "rd_req",
      N_("number of read operations:") }, /* 0 */
    { VIR_DOMAIN_BLOCK_STATS_READ_BYTES,        "rd_bytes",
      N_("number of bytes read:") }, /* 1 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_REQ,         "wr_req",
      N_("number of write operations:") }, /* 2 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_BYTES,       "wr_bytes",
      N_("number of bytes written:") }, /* 3 */
    { VIR_DOMAIN_BLOCK_STATS_ERRS,              "errs",
      N_("error count:") }, /* 4 */
    { VIR_DOMAIN_BLOCK_STATS_FLUSH_REQ,         NULL,
      N_("number of flush operations:") }, /* 5 */
    { VIR_DOMAIN_BLOCK_STATS_READ_TOTAL_TIMES,  NULL,
      N_("total duration of reads (ns):") }, /* 6 */
    { VIR_DOMAIN_BLOCK_STATS_WRITE_TOTAL_TIMES, NULL,
      N_("total duration of writes (ns):") }, /* 7 */
    { VIR_DOMAIN_BLOCK_STATS_FLUSH_TOTAL_TIMES, NULL,
      N_("total duration of flushes (ns):") }, /* 8 */
    { NULL, NULL, NULL }
};

#define DOMBLKSTAT_LEGACY_PRINT(ID, VALUE)              \
    if (VALUE >= 0)                                     \
        vshPrint(ctl, "%s %-*s %lld\n", device,         \
                 human ? 31 : 0,                        \
                 human ? _(domblkstat_output[ID].human) \
                 : domblkstat_output[ID].legacy,        \
                 VALUE);

static bool
cmdDomblkstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL;
    struct _virDomainBlockStats stats;
    virTypedParameterPtr params = NULL;
    virTypedParameterPtr par = NULL;
    char *value = NULL;
    const char *field = NULL;
    int rc, nparams = 0;
    int i = 0;
    bool ret = false;
    bool human = vshCommandOptBool(cmd, "human"); /* human readable output */

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "device", &device) <= 0)
        goto cleanup;

    rc = virDomainBlockStatsFlags(dom, device, NULL, &nparams, 0);

    /* It might fail when virDomainBlockStatsFlags is not
     * supported on older libvirt, fallback to use virDomainBlockStats
     * then.
     */
    if (rc < 0) {
        /* try older API if newer is not supported */
        if (last_error->code != VIR_ERR_NO_SUPPORT)
            goto cleanup;

        virFreeError(last_error);
        last_error = NULL;

        if (virDomainBlockStats(dom, device, &stats,
                                sizeof(stats)) == -1) {
            vshError(ctl, _("Failed to get block stats %s %s"),
                     name, device);
            goto cleanup;
        }

        /* human friendly output */
        if (human) {
            vshPrint(ctl, N_("Device: %s\n"), device);
            device = "";
        }

        DOMBLKSTAT_LEGACY_PRINT(0, stats.rd_req);
        DOMBLKSTAT_LEGACY_PRINT(1, stats.rd_bytes);
        DOMBLKSTAT_LEGACY_PRINT(2, stats.wr_req);
        DOMBLKSTAT_LEGACY_PRINT(3, stats.wr_bytes);
        DOMBLKSTAT_LEGACY_PRINT(4, stats.errs);
    } else {
        params = vshCalloc(ctl, nparams, sizeof(*params));

        if (virDomainBlockStatsFlags (dom, device, params, &nparams, 0) < 0) {
            vshError(ctl, _("Failed to get block stats %s %s"), name, device);
            goto cleanup;
        }

        /* set for prettier output */
        if (human) {
            vshPrint(ctl, N_("Device: %s\n"), device);
            device = "";
        }

        /* at first print all known values in desired order */
        for (i = 0; domblkstat_output[i].field != NULL; i++) {
            if (!(par = vshFindTypedParamByName(domblkstat_output[i].field,
                                                params,
                                                nparams)))
                continue;

            value = vshGetTypedParamValue(ctl, par);

            /* to print other not supported fields, mark the already printed */
            par->field[0] = '\0'; /* set the name to empty string */

            /* translate into human readable or legacy spelling */
            field = NULL;
            if (human)
                field = _(domblkstat_output[i].human);
            else
                field = domblkstat_output[i].legacy;

            /* use the provided spelling if no translation is available */
            if (!field)
                field = domblkstat_output[i].field;

            vshPrint(ctl, "%s %-*s %s\n", device,
                     human ? 31 : 0, field, value);

            VIR_FREE(value);
        }

        /* go through the fields again, for remaining fields */
        for (i = 0; i < nparams; i++) {
            if (!*params[i].field)
                continue;

            value = vshGetTypedParamValue(ctl, params+i);
            vshPrint(ctl, "%s %s %s\n", device, params[i].field, value);
            VIR_FREE(value);
        }
    }

    ret = true;

cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}
#undef DOMBLKSTAT_LEGACY_PRINT

/* "domifstat" command
 */
static const vshCmdInfo info_domifstat[] = {
    {"help", N_("get network interface stats for a domain")},
    {"desc", N_("Get network interface stats for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domifstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL;
    struct _virDomainInterfaceStats stats;

    if (!vshConnectionUsability (ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain (ctl, cmd, &name)))
        return false;

    if (vshCommandOptString (cmd, "interface", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainInterfaceStats (dom, device, &stats, sizeof(stats)) == -1) {
        vshError(ctl, _("Failed to get interface stats %s %s"), name, device);
        virDomainFree(dom);
        return false;
    }

    if (stats.rx_bytes >= 0)
        vshPrint (ctl, "%s rx_bytes %lld\n", device, stats.rx_bytes);

    if (stats.rx_packets >= 0)
        vshPrint (ctl, "%s rx_packets %lld\n", device, stats.rx_packets);

    if (stats.rx_errs >= 0)
        vshPrint (ctl, "%s rx_errs %lld\n", device, stats.rx_errs);

    if (stats.rx_drop >= 0)
        vshPrint (ctl, "%s rx_drop %lld\n", device, stats.rx_drop);

    if (stats.tx_bytes >= 0)
        vshPrint (ctl, "%s tx_bytes %lld\n", device, stats.tx_bytes);

    if (stats.tx_packets >= 0)
        vshPrint (ctl, "%s tx_packets %lld\n", device, stats.tx_packets);

    if (stats.tx_errs >= 0)
        vshPrint (ctl, "%s tx_errs %lld\n", device, stats.tx_errs);

    if (stats.tx_drop >= 0)
        vshPrint (ctl, "%s tx_drop %lld\n", device, stats.tx_drop);

    virDomainFree(dom);
    return true;
}

/* "domif-setlink" command
 */
static const vshCmdInfo info_domif_setlink[] = {
    {"help", N_("set link state of a virtual interface")},
    {"desc", N_("Set link state of a domain's virtual interface. This command wraps usage of update-device command.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domif_setlink[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device (MAC Address)")},
    {"state", VSH_OT_DATA, VSH_OFLAG_REQ, N_("new state of the device")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfSetLink (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface;
    const char *state;
    const char *value;
    const char *desc;
    unsigned char macaddr[VIR_MAC_BUFLEN];
    const char *element;
    const char *attr;
    bool config;
    bool ret = false;
    unsigned int flags = 0;
    int i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "interface", &iface) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "state", &state) <= 0)
        goto cleanup;

    config = vshCommandOptBool(cmd, "config");

    if (STRNEQ(state, "up") && STRNEQ(state, "down")) {
        vshError(ctl, _("invalid link state '%s'"), state);
        goto cleanup;
    }

    /* get persistent or live description of network device */
    desc = virDomainGetXMLDesc(dom, config ? VIR_DOMAIN_XML_INACTIVE : 0);
    if (desc == NULL) {
        vshError(ctl, _("Failed to get domain description xml"));
        goto cleanup;
    }

    if (config)
        flags = VIR_DOMAIN_AFFECT_CONFIG;
    else
        flags = VIR_DOMAIN_AFFECT_LIVE;

    if (virDomainIsActive(dom) == 0)
        flags = VIR_DOMAIN_AFFECT_CONFIG;

    /* extract current network device description */
    xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), &ctxt);
    VIR_FREE(desc);
    if (!xml) {
        vshError(ctl, _("Failed to parse domain description xml"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("Failed to extract interface information or no interfaces found"));
        goto cleanup;
    }

    if (virMacAddrParse(iface, macaddr) == 0) {
        element = "mac";
        attr = "address";
    } else {
        element = "target";
        attr = "dev";
    }

    /* find interface with matching mac addr */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;

        while (cur) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST element)) {
                value = virXMLPropString(cur, attr);

                if (STRCASEEQ(value, iface)) {
                    VIR_FREE(value);
                    goto hit;
                }
                VIR_FREE(value);
            }
            cur = cur->next;
        }
    }

    vshError(ctl, _("interface (%s: %s) not found"), element, iface);
    goto cleanup;

hit:
    /* find and modify/add link state node */
    /* try to find <link> element */
    cur = obj->nodesetval->nodeTab[i]->children;

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "link")) {
            /* found, just modify the property */
            xmlSetProp(cur, BAD_CAST "state", BAD_CAST state);

            break;
        }
        cur = cur->next;
    }

    if (!cur) {
        /* element <link> not found, add one */
        cur = xmlNewChild(obj->nodesetval->nodeTab[i],
                          NULL,
                          BAD_CAST "link",
                          NULL);
        if (!cur)
            goto cleanup;

        if (xmlNewProp(cur, BAD_CAST "state", BAD_CAST state) == NULL)
            goto cleanup;
    }

    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(ctl, _("Failed to allocate memory"));
        goto cleanup;
    }

    if (xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0 ) {
        vshError(ctl, _("Failed to create XML"));
        goto cleanup;
    }

    if (virDomainUpdateDeviceFlags(dom, (char *)xmlBufferContent(xml_buf), flags) < 0) {
        vshError(ctl, _("Failed to update interface link state"));
        goto cleanup;
    } else {
        vshPrint(ctl, "%s", _("Device updated successfully\n"));
        ret = true;
    }

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);

    if (dom)
        virDomainFree(dom);

    return ret;
}

/* "domif-getlink" command
 */
static const vshCmdInfo info_domif_getlink[] = {
    {"help", N_("get link state of a virtual interface")},
    {"desc", N_("Get link state of a domain's virtual interface.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domif_getlink[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device (MAC Address)")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("Get persistent interface state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIfGetLink (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *iface = NULL;
    int flags = 0;
    char *state = NULL;
    char *value = NULL;
    unsigned char macaddr[VIR_MAC_BUFLEN];
    const char *element;
    const char *attr;
    bool ret = false;
    int i;
    char *desc;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlXPathObjectPtr obj = NULL;

    if (!vshConnectionUsability (ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain (ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString (cmd, "interface", &iface) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config"))
        flags = VIR_DOMAIN_XML_INACTIVE;

    desc = virDomainGetXMLDesc(dom, flags);
    if (desc == NULL) {
        vshError(ctl, _("Failed to get domain description xml"));
        goto cleanup;
    }

    xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), &ctxt);
    VIR_FREE(desc);
    if (!xml) {
        vshError(ctl, _("Failed to parse domain description xml"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/interface", ctxt);
    if (obj == NULL || obj->type != XPATH_NODESET ||
        obj->nodesetval == NULL || obj->nodesetval->nodeNr == 0) {
        vshError(ctl, _("Failed to extract interface information or no interfaces found"));
        goto cleanup;
    }

    if (virMacAddrParse(iface, macaddr) == 0) {
        element = "mac";
        attr = "address";
    } else {
        element = "target";
        attr = "dev";
    }

    /* find interface with matching mac addr */
    for (i = 0; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;

        while (cur) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST element)) {

                value = virXMLPropString(cur, attr);

                if (STRCASEEQ(value, iface)) {
                    VIR_FREE(value);
                    goto hit;
                }
                VIR_FREE(value);
            }
            cur = cur->next;
        }
    }

    vshError(ctl, _("Interface (%s: %s) not found."), element, iface);
    goto cleanup;

hit:
    cur = obj->nodesetval->nodeTab[i]->children;
    while (cur) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "link")) {

            state = virXMLPropString(cur, "state");
            vshPrint(ctl, "%s %s", iface, state);
            VIR_FREE(state);

            goto cleanup;
        }
        cur = cur->next;
    }

    /* attribute not found */
    vshPrint(ctl, "%s default", iface);

    ret = true;
cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/* "domiftune" command
 */
static const vshCmdInfo info_domiftune[] = {
    {"help", N_("get/set parameters of a virtual interface")},
    {"desc", N_("Get/set parameters of a domain's virtual interface.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domiftune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface device")},
    {"inbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's incoming traffics")},
    {"outbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's outgoing traffics")},
    {"config", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect next boot")},
    {"live", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect running domain")},
    {"current", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomIftune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL, *device = NULL,
               *inboundStr = NULL, *outboundStr = NULL;
    unsigned int flags = 0;
    int nparams = 0;
    virTypedParameterPtr params = NULL;
    bool ret = false;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    virNetDevBandwidthRate inbound, outbound;
    int i;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "interface", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptString(cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptString(cmd, "outbound", &outboundStr) < 0) {
        vshError(ctl, "missing argument");
        goto cleanup;
    }

    memset(&inbound, 0, sizeof(inbound));
    memset(&outbound, 0, sizeof(outbound));

    if (inboundStr) {
        if (parseRateStr(inboundStr, &inbound) < 0) {
            vshError(ctl, _("inbound format is incorrect"));
            goto cleanup;
        }
        if (inbound.average == 0) {
            vshError(ctl, _("inbound average is mandatory"));
            goto cleanup;
        }
        nparams++; /* average */
        if (inbound.peak) nparams++;
        if (inbound.burst) nparams++;
    }
    if (outboundStr) {
        if (parseRateStr(outboundStr, &outbound) < 0) {
            vshError(ctl, _("outbound format is incorrect"));
            goto cleanup;
        }
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }
        nparams++; /* average */
        if (outbound.peak) nparams++;
        if (outbound.burst) nparams++;
    }

    if (nparams == 0) {
        /* get the number of interface parameters */
        if (virDomainGetInterfaceParameters(dom, device, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of interface parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* get all interface parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (!params) {
            virReportOOMError();
            goto cleanup;
        }
        if (virDomainGetInterfaceParameters(dom, device, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get interface parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        /* set the interface parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (!params) {
            virReportOOMError();
            goto cleanup;
        }

        for (i = 0; i < nparams; i++)
            params[i].type = VIR_TYPED_PARAM_UINT;

        i = 0;
        if (inbound.average && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_AVERAGE,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.average;
            i++;
        }
        if (inbound.peak && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_PEAK,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.peak;
            i++;
        }
        if (inbound.burst && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_IN_BURST,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = inbound.burst;
            i++;
        }
        if (outbound.average && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_AVERAGE,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.average;
            i++;
        }
        if (outbound.peak && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_PEAK,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.peak;
            i++;
        }
        if (outbound.burst && i < nparams) {
            if (!virStrcpy(params[i].field, VIR_DOMAIN_BANDWIDTH_OUT_BURST,
                           sizeof(params[i].field)))
                goto cleanup;
            params[i].value.ui = outbound.burst;
            i++;
        }

        if (virDomainSetInterfaceParameters(dom, device, params, nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to set interface parameters"));
            goto cleanup;
        }
    }

    ret = true;

cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "dommemstats" command
 */
static const vshCmdInfo info_dommemstat[] = {
    {"help", N_("get memory statistics for a domain")},
    {"desc", N_("Get memory statistics for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_dommemstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomMemStat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    struct _virDomainMemoryStat stats[VIR_DOMAIN_MEMORY_STAT_NR];
    unsigned int nr_stats, i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    nr_stats = virDomainMemoryStats (dom, stats, VIR_DOMAIN_MEMORY_STAT_NR, 0);
    if (nr_stats == -1) {
        vshError(ctl, _("Failed to get memory statistics for domain %s"), name);
        virDomainFree(dom);
        return false;
    }

    for (i = 0; i < nr_stats; i++) {
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_SWAP_IN)
            vshPrint (ctl, "swap_in %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_SWAP_OUT)
            vshPrint (ctl, "swap_out %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT)
            vshPrint (ctl, "major_fault %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT)
            vshPrint (ctl, "minor_fault %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_UNUSED)
            vshPrint (ctl, "unused %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_AVAILABLE)
            vshPrint (ctl, "available %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON)
            vshPrint (ctl, "actual %llu\n", stats[i].val);
        if (stats[i].tag == VIR_DOMAIN_MEMORY_STAT_RSS)
            vshPrint (ctl, "rss %llu\n", stats[i].val);
    }

    virDomainFree(dom);
    return true;
}

/*
 * "domblkinfo" command
 */
static const vshCmdInfo info_domblkinfo[] = {
    {"help", N_("domain block device size information")},
    {"desc", N_("Get block device size info for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblkinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomblkinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainBlockInfo info;
    virDomainPtr dom;
    bool ret = true;
    const char *device = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString (cmd, "device", &device) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetBlockInfo(dom, device, &info, 0) < 0) {
        virDomainFree(dom);
        return false;
    }

    vshPrint(ctl, "%-15s %llu\n", _("Capacity:"), info.capacity);
    vshPrint(ctl, "%-15s %llu\n", _("Allocation:"), info.allocation);
    vshPrint(ctl, "%-15s %llu\n", _("Physical:"), info.physical);

    virDomainFree(dom);
    return ret;
}

/*
 * "domblklist" command
 */
static const vshCmdInfo info_domblklist[] = {
    {"help", N_("list all domain blocks")},
    {"desc", N_("Get the summary of block devices for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblklist[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0,
     N_("get inactive rather than running configuration")},
    {"details", VSH_OT_BOOL, 0,
     N_("additionally display the type and device value")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomblklist(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ndisks;
    xmlNodePtr *disks = NULL;
    int i;
    bool details = false;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    details = vshCommandOptBool(cmd, "details");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    xml = virDomainGetXMLDesc(dom, flags);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_definition)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    ndisks = virXPathNodeSet("./devices/disk", ctxt, &disks);
    if (ndisks < 0)
        goto cleanup;

    if (details)
        vshPrint(ctl, "%-10s %-10s %-10s %s\n", _("Type"),
                 _("Device"), _("Target"), _("Source"));
    else
        vshPrint(ctl, "%-10s %s\n", _("Target"), _("Source"));

    vshPrint(ctl, "------------------------------------------------\n");

    for (i = 0; i < ndisks; i++) {
        char *type;
        char *device;
        char *target;
        char *source;

        ctxt->node = disks[i];

        if (details) {
            type = virXPathString("string(./@type)", ctxt);
            device = virXPathString("string(./@device)", ctxt);
        }

        target = virXPathString("string(./target/@dev)", ctxt);
        if (!target) {
            vshError(ctl, "unable to query block list");
            goto cleanup;
        }
        source = virXPathString("string(./source/@file"
                                "|./source/@dev"
                                "|./source/@dir"
                                "|./source/@name)", ctxt);
        if (details) {
            vshPrint(ctl, "%-10s %-10s %-10s %s\n", type, device,
                     target, source ? source : "-");
            VIR_FREE(type);
            VIR_FREE(device);
        } else {
            vshPrint(ctl, "%-10s %s\n", target, source ? source : "-");
        }

        VIR_FREE(target);
        VIR_FREE(source);
    }

    ret = true;

cleanup:
    VIR_FREE(disks);
    virDomainFree(dom);
    VIR_FREE(xml);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;
}

/*
 * "domiflist" command
 */
static const vshCmdInfo info_domiflist[] = {
    {"help", N_("list all domain virtual interfaces")},
    {"desc", N_("Get the summary of virtual interfaces for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domiflist[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0,
     N_("get inactive rather than running configuration")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomiflist(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;
    xmlDocPtr xmldoc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ninterfaces;
    xmlNodePtr *interfaces = NULL;
    int i;

    if (vshCommandOptBool(cmd, "inactive"))
        flags |= VIR_DOMAIN_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    xml = virDomainGetXMLDesc(dom, flags);
    if (!xml)
        goto cleanup;

    xmldoc = virXMLParseStringCtxt(xml, _("(domain_definition)"), &ctxt);
    if (!xmldoc)
        goto cleanup;

    ninterfaces = virXPathNodeSet("./devices/interface", ctxt, &interfaces);
    if (ninterfaces < 0)
        goto cleanup;

    vshPrint(ctl, "%-10s %-10s %-10s %-11s %s\n", _("Interface"), _("Type"),
             _("Source"), _("Model"), _("MAC"));
    vshPrint(ctl, "-------------------------------------------------------\n");

    for (i = 0; i < ninterfaces; i++) {
        char *type = NULL;
        char *source = NULL;
        char *target = NULL;
        char *model = NULL;
        char *mac = NULL;

        ctxt->node = interfaces[i];
        type = virXPathString("string(./@type)", ctxt);

        source = virXPathString("string(./source/@bridge"
                                "|./source/@dev"
                                "|./source/@network"
                                "|./source/@name)", ctxt);

        target = virXPathString("string(./target/@dev)", ctxt);
        model = virXPathString("string(./model/@type)", ctxt);
        mac = virXPathString("string(./mac/@address)", ctxt);

        vshPrint(ctl, "%-10s %-10s %-10s %-11s %-10s\n",
                 target ? target : "-",
                 type,
                 source ? source : "-",
                 model ? model : "-",
                 mac ? mac : "-");

        VIR_FREE(type);
        VIR_FREE(source);
        VIR_FREE(target);
        VIR_FREE(model);
        VIR_FREE(mac);
    }

    ret = true;

cleanup:
    VIR_FREE(interfaces);
    virDomainFree(dom);
    VIR_FREE(xml);
    xmlFreeDoc(xmldoc);
    xmlXPathFreeContext(ctxt);
    return ret;
}

/*
 * "suspend" command
 */
static const vshCmdInfo info_suspend[] = {
    {"help", N_("suspend a domain")},
    {"desc", N_("Suspend a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainSuspend(dom) == 0) {
        vshPrint(ctl, _("Domain %s suspended\n"), name);
    } else {
        vshError(ctl, _("Failed to suspend domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "dompmsuspend" command
 */
static const vshCmdInfo info_dom_pm_suspend[] = {
    {"help", N_("suspend a domain for a given time duration")},
    {"desc", N_("Suspend a running domain for a given time duration.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dom_pm_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"duration", VSH_OT_INT, VSH_OFLAG_REQ_OPT, N_("duration in seconds")},
    {"target", VSH_OT_STRING, VSH_OFLAG_REQ, N_("mem(Suspend-to-RAM), "
                                                "disk(Suspend-to-Disk), "
                                                "hybrid(Hybrid-Suspend)")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomPMSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    const char *target = NULL;
    unsigned int suspendTarget;
    unsigned long long duration = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptULongLong(cmd, "duration", &duration) < 0) {
        vshError(ctl, _("Invalid duration argument"));
        goto cleanup;
    }

    if (vshCommandOptString(cmd, "target", &target) < 0) {
        vshError(ctl, _("Invalid target argument"));
        goto cleanup;
    }

    if (STREQ(target, "mem"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_MEM;
    else if (STREQ(target, "disk"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_DISK;
    else if (STREQ(target, "hybrid"))
        suspendTarget = VIR_NODE_SUSPEND_TARGET_HYBRID;
    else {
        vshError(ctl, "%s", _("Invalid target"));
        goto cleanup;
    }

    if (virDomainPMSuspendForDuration(dom, suspendTarget, duration, 0) < 0) {
        vshError(ctl, _("Domain %s could not be suspended"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrint(ctl, _("Domain %s successfully suspended"),
             virDomainGetName(dom));

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "dompmwakeup" command
 */

static const vshCmdInfo info_dom_pm_wakeup[] = {
    {"help", N_("wakeup a domain suspended by dompmsuspend command")},
    {"desc", N_("Wakeup a domain previously suspended "
                "by dompmsuspend command.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dom_pm_wakeup[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomPMWakeup(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainPMWakeup(dom, flags) < 0) {
        vshError(ctl, _("Domain %s could not be woken up"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    vshPrint(ctl, _("Domain %s successfully woken up"),
             virDomainGetName(dom));

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "create" command
 */
static const vshCmdInfo info_create[] = {
    {"help", N_("create a domain from an XML file")},
    {"desc", N_("Create a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML domain description")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, N_("attach to console after creation")},
#endif
    {"paused", VSH_OT_BOOL, 0, N_("leave the guest paused after creation")},
    {"autodestroy", VSH_OT_BOOL, 0, N_("automatically destroy the guest when virsh disconnects")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = true;
    char *buffer;
#ifndef WIN32
    int console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;

    dom = virDomainCreateXML(ctl->conn, buffer, flags);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s created from %s\n"),
                 virDomainGetName(dom), from);
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom, NULL, 0);
#endif
        virDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to create domain from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "define" command
 */
static const vshCmdInfo info_define[] = {
    {"help", N_("define (but don't start) a domain from an XML file")},
    {"desc", N_("Define a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML domain description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    dom = virDomainDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s defined from %s\n"),
                 virDomainGetName(dom), from);
        virDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to define domain from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "undefine" command
 */
static const vshCmdInfo info_undefine[] = {
    {"help", N_("undefine a domain")},
    {"desc",
     N_("Undefine an inactive domain, or convert persistent to transient.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_undefine[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name or uuid")},
    {"managed-save", VSH_OT_BOOL, 0, N_("remove domain managed state file")},
    {"storage", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("remove associated storage volumes (comma separated list of targets "
        "or source paths) (see domblklist)")},
    {"remove-all-storage", VSH_OT_BOOL, 0,
     N_("remove all associated storage volumes (use with caution)")},
    {"wipe-storage", VSH_OT_BOOL, VSH_OFLAG_NONE,
     N_("wipe data on the removed volumes")},
    {"snapshots-metadata", VSH_OT_BOOL, 0,
     N_("remove all domain snapshot metadata, if inactive")},
    {NULL, 0, 0, NULL}
};

static bool
cmdUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
    const char *name = NULL;
    /* Flags to attempt.  */
    unsigned int flags = 0;
    /* User-requested actions.  */
    bool managed_save = vshCommandOptBool(cmd, "managed-save");
    bool snapshots_metadata = vshCommandOptBool(cmd, "snapshots-metadata");
    bool wipe_storage = vshCommandOptBool(cmd, "wipe-storage");
    bool remove_storage = false;
    bool remove_all_storage = vshCommandOptBool(cmd, "remove-all-storage");
    /* Positive if these items exist.  */
    int has_managed_save = 0;
    int has_snapshots_metadata = 0;
    int has_snapshots = 0;
    /* True if undefine will not strand data, even on older servers.  */
    bool managed_save_safe = false;
    bool snapshots_safe = false;
    int rc = -1;
    int running;
    /* list of volumes to remove along with this domain */
    const char *volumes_arg = NULL;
    char *volumes = NULL;
    char **volume_tokens = NULL;
    char *volume_tok = NULL;
    int nvolume_tokens = 0;
    char *def = NULL;
    char *source = NULL;
    char *target = NULL;
    int vol_i;
    int tok_i;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *vol_nodes = NULL;
    int nvolumes = 0;
    virStorageVolPtr vol = NULL;
    bool vol_del_failed = false;

    if (managed_save) {
        flags |= VIR_DOMAIN_UNDEFINE_MANAGED_SAVE;
        managed_save_safe = true;
    }
    if (snapshots_metadata) {
        flags |= VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    /* check if a string that should contain list of volumes to remove is present */
    if (vshCommandOptString(cmd, "storage", &volumes_arg) > 0) {
        volumes = vshStrdup(ctl, volumes_arg);

        if (remove_all_storage) {
            vshError(ctl, _("Specified both --storage and --remove-all-storage"));
            goto cleanup;
        }
        remove_storage = true;
   }

    /* Do some flag manipulation.  The goal here is to disable bits
     * from flags to reduce the likelihood of a server rejecting
     * unknown flag bits, as well as to track conditions which are
     * safe by default for the given hypervisor and server version.  */
    running = virDomainIsActive(dom);
    if (running < 0) {
        virshReportError(ctl);
        goto cleanup;
    }
    if (!running) {
        /* Undefine with snapshots only fails for inactive domains,
         * and managed save only exists on inactive domains; if
         * running, then we don't want to remove anything.  */
        has_managed_save = virDomainHasManagedSaveImage(dom, 0);
        if (has_managed_save < 0) {
            if (last_error->code != VIR_ERR_NO_SUPPORT) {
                virshReportError(ctl);
                goto cleanup;
            }
            virFreeError(last_error);
            last_error = NULL;
            has_managed_save = 0;
        }

        has_snapshots = virDomainSnapshotNum(dom, 0);
        if (has_snapshots < 0) {
            if (last_error->code != VIR_ERR_NO_SUPPORT) {
                virshReportError(ctl);
                goto cleanup;
            }
            virFreeError(last_error);
            last_error = NULL;
            has_snapshots = 0;
        }
        if (has_snapshots) {
            has_snapshots_metadata
                = virDomainSnapshotNum(dom, VIR_DOMAIN_SNAPSHOT_LIST_METADATA);
            if (has_snapshots_metadata < 0) {
                /* The server did not know the new flag, assume that all
                   snapshots have metadata.  */
                virFreeError(last_error);
                last_error = NULL;
                has_snapshots_metadata = has_snapshots;
            } else {
                /* The server knew the new flag, all aspects of
                 * undefineFlags are safe.  */
                managed_save_safe = snapshots_safe = true;
            }
        }
    }
    if (!has_managed_save) {
        flags &= ~VIR_DOMAIN_UNDEFINE_MANAGED_SAVE;
        managed_save_safe = true;
    }
    if (has_snapshots == 0) {
        snapshots_safe = true;
    }
    if (has_snapshots_metadata == 0) {
        flags &= ~VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA;
        snapshots_safe = true;
    }

    /* Stash domain description for later use */
    if (remove_storage || remove_all_storage) {
        if (running) {
            vshError(ctl, _("Storage volume deletion is supported only on stopped domains"));
            goto cleanup;
        }

        if (!(def = virDomainGetXMLDesc(dom, 0))) {
            vshError(ctl, _("Could not retrieve domain XML description"));
            goto cleanup;
        }
    }

    /* Generally we want to try the new API first.  However, while
     * virDomainUndefineFlags was introduced at the same time as
     * VIR_DOMAIN_UNDEFINE_MANAGED_SAVE in 0.9.4, the
     * VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA flag was not present
     * until 0.9.5; skip to piecewise emulation if we couldn't prove
     * above that the new API is safe.  */
    if (managed_save_safe && snapshots_safe) {
        rc = virDomainUndefineFlags(dom, flags);
        if (rc == 0 || (last_error->code != VIR_ERR_NO_SUPPORT &&
                        last_error->code != VIR_ERR_INVALID_ARG))
            goto out;
        virFreeError(last_error);
        last_error = NULL;
    }

    /* The new API is unsupported or unsafe; fall back to doing things
     * piecewise.  */
    if (has_managed_save) {
        if (!managed_save) {
            vshError(ctl, "%s",
                     _("Refusing to undefine while domain managed save "
                       "image exists"));
            goto cleanup;
        }
        if (virDomainManagedSaveRemove(dom, 0) < 0) {
            virshReportError(ctl);
            goto cleanup;
        }
    }

    /* No way to emulate deletion of just snapshot metadata
     * without support for the newer flags.  Oh well.  */
    if (has_snapshots_metadata) {
        vshError(ctl,
                 snapshots_metadata ?
                 _("Unable to remove metadata of %d snapshots") :
                 _("Refusing to undefine while %d snapshots exist"),
                 has_snapshots_metadata);
        goto cleanup;
    }

    rc = virDomainUndefine(dom);

out:
    if (rc == 0) {
        vshPrint(ctl, _("Domain %s has been undefined\n"), name);
        ret = true;
    } else {
        vshError(ctl, _("Failed to undefine domain %s"), name);
        goto cleanup;
    }

    /* try to undefine storage volumes associated with this domain, if it's requested */
    if (remove_storage || remove_all_storage) {
        ret = false;

        /* tokenize the string from user and save it's parts into an array */
        if (volumes) {
            /* count the delimiters */
            volume_tok = volumes;
            nvolume_tokens = 1; /* we need at least one member */
            while (*volume_tok) {
                if (*volume_tok == ',')
                    nvolume_tokens++;
                volume_tok++;
            }

            volume_tokens = vshCalloc(ctl, nvolume_tokens,  sizeof(char *));

            /* tokenize the input string */
            nvolume_tokens = 0;
            volume_tok = volumes;
            do {
                volume_tokens[nvolume_tokens] = strsep(&volume_tok, ",");
                nvolume_tokens++;
            } while (volume_tok);
        }

        doc = virXMLParseStringCtxt(def, _("(domain_definition)"), &ctxt);
        if (!doc)
            goto cleanup;

        nvolumes = virXPathNodeSet("./devices/disk", ctxt, &vol_nodes);

        if (nvolumes < 0)
            goto cleanup;

        for (vol_i = 0; vol_i < nvolumes; vol_i++) {
            ctxt->node = vol_nodes[vol_i];
            VIR_FREE(target);
            VIR_FREE(source);
            if (vol) {
                virStorageVolFree(vol);
                vol = NULL;
            }

            /* get volume source and target paths */
            if (!(target = virXPathString("string(./target/@dev)", ctxt))) {
                vshError(ctl, _("Failed to enumerate devices"));
                goto cleanup;
            }

            if (!(source = virXPathString("string("
                                          "./source/@file|"
                                          "./source/@dir|"
                                          "./source/@name|"
                                          "./source/@dev)", ctxt)) &&
                virGetLastError())
                goto cleanup;

            /* lookup if volume was selected by user */
            if (volumes) {
                volume_tok = NULL;
                for (tok_i = 0; tok_i < nvolume_tokens; tok_i++) {
                    if (volume_tokens[tok_i] &&
                        (STREQ_NULLABLE(volume_tokens[tok_i], target) ||
                         STREQ_NULLABLE(volume_tokens[tok_i], source))) {
                        volume_tok = volume_tokens[tok_i];
                        volume_tokens[tok_i] = NULL;
                        break;
                    }
                }
                if (!volume_tok)
                    continue;
            }

            if (!source)
                continue;

            if (!(vol = virStorageVolLookupByPath(ctl->conn, source))) {
                vshPrint(ctl,
                         _("Storage volume '%s'(%s) is not managed by libvirt. "
                           "Remove it manually.\n"), target, source);
                virResetLastError();
                continue;
            }

            if (wipe_storage) {
                vshPrint(ctl, _("Wiping volume '%s'(%s) ... "), target, source);
                fflush(stdout);
                if (virStorageVolWipe(vol, 0) < 0) {
                    vshError(ctl, _("Failed! Volume not removed."));
                    vol_del_failed = true;
                    continue;
                } else {
                    vshPrint(ctl, _("Done.\n"));
                }
            }

            /* delete the volume */
            if (virStorageVolDelete(vol, 0) < 0) {
                vshError(ctl, _("Failed to remove storage volume '%s'(%s)"),
                         target, source);
                vol_del_failed = true;
            }
            vshPrint(ctl, _("Volume '%s' removed.\n"), volume_tok?volume_tok:source);
        }

        /* print volumes specified by user that were not found in domain definition */
        if (volumes) {
            for (tok_i = 0; tok_i < nvolume_tokens; tok_i++) {
                if (volume_tokens[tok_i])
                    vshPrint(ctl, _("Volume '%s' was not found in domain's "
                                    "definition.\n"),
                             volume_tokens[tok_i]);
            }
        }

        if (!vol_del_failed)
            ret = true;
    }

cleanup:
    VIR_FREE(source);
    VIR_FREE(target);
    VIR_FREE(volumes);
    VIR_FREE(volume_tokens);
    VIR_FREE(def);
    VIR_FREE(vol_nodes);
    if (vol)
        virStorageVolFree(vol);
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);
    virDomainFree(dom);
    return ret;
}


/*
 * "start" command
 */
static const vshCmdInfo info_start[] = {
    {"help", N_("start a (previously defined) inactive domain")},
    {"desc", N_("Start a domain, either from the last managedsave\n"
                "    state, or via a fresh boot if no managedsave state\n"
                "    is present.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_start[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the inactive domain")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, N_("attach to console after creation")},
#endif
    {"paused", VSH_OT_BOOL, 0, N_("leave the guest paused after creation")},
    {"autodestroy", VSH_OT_BOOL, 0,
     N_("automatically destroy the guest when virsh disconnects")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when loading")},
    {"force-boot", VSH_OT_BOOL, 0,
     N_("force fresh boot by discarding any managed save")},
    {NULL, 0, 0, NULL}
};

static bool
cmdStart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = false;
#ifndef WIN32
    int console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;
    int rc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME | VSH_BYUUID)))
        return false;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;
    if (vshCommandOptBool(cmd, "autodestroy"))
        flags |= VIR_DOMAIN_START_AUTODESTROY;
    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_START_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "force-boot"))
        flags |= VIR_DOMAIN_START_FORCE_BOOT;

    /* We can emulate force boot, even for older servers that reject it.  */
    if (flags & VIR_DOMAIN_START_FORCE_BOOT) {
        if (virDomainCreateWithFlags(dom, flags) == 0)
            goto started;
        if (last_error->code != VIR_ERR_NO_SUPPORT &&
            last_error->code != VIR_ERR_INVALID_ARG) {
            virshReportError(ctl);
            goto cleanup;
        }
        virFreeError(last_error);
        last_error = NULL;
        rc = virDomainHasManagedSaveImage(dom, 0);
        if (rc < 0) {
            /* No managed save image to remove */
            virFreeError(last_error);
            last_error = NULL;
        } else if (rc > 0) {
            if (virDomainManagedSaveRemove(dom, 0) < 0) {
                virshReportError(ctl);
                goto cleanup;
            }
        }
        flags &= ~VIR_DOMAIN_START_FORCE_BOOT;
    }

    /* Prefer older API unless we have to pass a flag.  */
    if ((flags ? virDomainCreateWithFlags(dom, flags)
         : virDomainCreate(dom)) < 0) {
        vshError(ctl, _("Failed to start domain %s"), virDomainGetName(dom));
        goto cleanup;
    }

started:
    vshPrint(ctl, _("Domain %s started\n"),
             virDomainGetName(dom));
#ifndef WIN32
    if (console && !cmdRunConsole(ctl, dom, NULL, 0))
        goto cleanup;
#endif

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "save" command
 */
static const vshCmdInfo info_save[] = {
    {"help", N_("save a domain state to a file")},
    {"desc", N_("Save the RAM state of a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save[] = {
    {"bypass-cache", VSH_OT_BOOL, 0, N_("avoid file system cache when saving")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to save the data")},
    {"xml", VSH_OT_STRING, 0,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of save")},
    {NULL, 0, 0, NULL}
};

static void
doSave(void *opaque)
{
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    char ret = '1';
    virDomainPtr dom = NULL;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    char *xml = NULL;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        goto out;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        goto out;
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto out;

    if (((flags || xml)
         ? virDomainSaveFlags(dom, to, xml, flags)
         : virDomainSave(dom, to)) < 0) {
        vshError(ctl, _("Failed to save domain %s to %s"), name, to);
        goto out;
    }

    ret = '0';

out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom) virDomainFree (dom);
    VIR_FREE(xml);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virDomainPtr dom = NULL;
    int p[2] = {-1. -1};
    virThread workerThread;
    bool verbose = false;
    vshCtrlData data;
    const char *to = NULL;
    const char *name = NULL;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        goto cleanup;

    if (vshCommandOptBool (cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doSave,
                        &data) < 0)
        goto cleanup;

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Save"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s saved to %s\n"), name, to);

cleanup:
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "save-image-dumpxml" command
 */
static const vshCmdInfo info_save_image_dumpxml[] = {
    {"help", N_("saved state domain information in XML")},
    {"desc", N_("Output the domain information for a saved state file,\n"
                "as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_dumpxml[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to read")},
    {"security-info", VSH_OT_BOOL, 0, N_("include security sensitive information in XML dump")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageDumpxml(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    unsigned int flags = 0;
    char *xml = NULL;

    if (vshCommandOptBool(cmd, "security-info"))
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

    xml = virDomainSaveImageGetXMLDesc(ctl->conn, file, flags);
    if (!xml)
        goto cleanup;

    vshPrint(ctl, "%s", xml);
    ret = true;

cleanup:
    VIR_FREE(xml);
    return ret;
}

/*
 * "save-image-define" command
 */
static const vshCmdInfo info_save_image_define[] = {
    {"help", N_("redefine the XML for a domain's saved state file")},
    {"desc", N_("Replace the domain XML associated with a saved state file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to modify")},
    {"xml", VSH_OT_STRING, VSH_OFLAG_REQ,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageDefine(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    const char *xmlfile = NULL;
    char *xml = NULL;
    unsigned int flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

    if (vshCommandOptString(cmd, "xml", &xmlfile) <= 0) {
        vshError(ctl, "%s", _("malformed or missing xml argument"));
        return false;
    }

    if (virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto cleanup;

    if (virDomainSaveImageDefineXML(ctl->conn, file, xml, flags) < 0) {
        vshError(ctl, _("Failed to update %s"), file);
        goto cleanup;
    }

    vshPrint(ctl, _("State file %s updated.\n"), file);
    ret = true;

cleanup:
    VIR_FREE(xml);
    return ret;
}

/*
 * "save-image-edit" command
 */
static const vshCmdInfo info_save_image_edit[] = {
    {"help", N_("edit XML for a domain's saved state file")},
    {"desc", N_("Edit the domain XML associated with a saved state file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save_image_edit[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("saved state file to edit")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on restore")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on restore")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSaveImageEdit(vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    bool ret = false;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    unsigned int getxml_flags = VIR_DOMAIN_XML_SECURE;
    unsigned int define_flags = 0;

    if (vshCommandOptBool(cmd, "running"))
        define_flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        define_flags |= VIR_DOMAIN_SAVE_PAUSED;

    /* Normally, we let the API reject mutually exclusive flags.
     * However, in the edit cycle, we let the user retry if the define
     * step fails, but the define step will always fail on invalid
     * flags, so we reject it up front to avoid looping.  */
    if (define_flags == (VIR_DOMAIN_SAVE_RUNNING | VIR_DOMAIN_SAVE_PAUSED)) {
        vshError(ctl, "%s", _("--running and --saved are mutually exclusive"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &file) <= 0)
        return false;

    /* Get the XML configuration of the saved image.  */
    doc = virDomainSaveImageGetXMLDesc(ctl->conn, file, getxml_flags);
    if (!doc)
        goto cleanup;

    /* Create and open the temporary file.  */
    tmp = editWriteToTempFile(ctl, doc);
    if (!tmp)
        goto cleanup;

    /* Start the editor.  */
    if (editFile(ctl, tmp) == -1)
        goto cleanup;

    /* Read back the edited file.  */
    doc_edited = editReadBackFile(ctl, tmp);
    if (!doc_edited)
        goto cleanup;

    /* Compare original XML with edited.  Short-circuit if it did not
     * change, and we do not have any flags.  */
    if (STREQ(doc, doc_edited) && !define_flags) {
        vshPrint(ctl, _("Saved image %s XML configuration not changed.\n"),
                 file);
        ret = true;
        goto cleanup;
    }

    /* Everything checks out, so redefine the xml.  */
    if (virDomainSaveImageDefineXML(ctl->conn, file, doc_edited,
                                    define_flags) < 0) {
        vshError(ctl, _("Failed to update %s"), file);
        goto cleanup;
    }

    vshPrint(ctl, _("State file %s edited.\n"), file);
    ret = true;

cleanup:
    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    if (tmp) {
        unlink(tmp);
        VIR_FREE(tmp);
    }
    return ret;
}

/*
 * "managedsave" command
 */
static const vshCmdInfo info_managedsave[] = {
    {"help", N_("managed save of a domain state")},
    {"desc", N_("Save and destroy a running domain, so it can be restarted from\n"
                "    the same state at a later time.  When the virsh 'start'\n"
                "    command is next run for the domain, it will automatically\n"
                "    be started from this saved state.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_managedsave[] = {
    {"bypass-cache", VSH_OT_BOOL, 0, N_("avoid file system cache when saving")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"running", VSH_OT_BOOL, 0, N_("set domain to be running on next start")},
    {"paused", VSH_OT_BOOL, 0, N_("set domain to be paused on next start")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of save")},
    {NULL, 0, 0, NULL}
};

static void
doManagedsave(void *opaque)
{
    char ret = '1';
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virDomainPtr dom = NULL;
    const char *name;
    unsigned int flags = 0;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (virDomainManagedSave(dom, flags) < 0) {
        vshError(ctl, _("Failed to save domain %s state"), name);
        goto out;
    }

    ret = '0';
out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom)
        virDomainFree (dom);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdManagedSave(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int p[2] = { -1, -1};
    bool ret = false;
    bool verbose = false;
    const char *name = NULL;
    vshCtrlData data;
    virThread workerThread;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool (cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doManagedsave,
                        &data) < 0)
        goto cleanup;

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0,
                      NULL, NULL, _("Managedsave"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s state saved by libvirt\n"), name);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
}

/*
 * "managedsave-remove" command
 */
static const vshCmdInfo info_managedsaveremove[] = {
    {"help", N_("Remove managed save of a domain")},
    {"desc", N_("Remove an existing managed save state file from a domain")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_managedsaveremove[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdManagedSaveRemove(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name;
    bool ret = false;
    int hassave;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    hassave = virDomainHasManagedSaveImage(dom, 0);
    if (hassave < 0) {
        vshError(ctl, "%s", _("Failed to check for domain managed save image"));
        goto cleanup;
    }

    if (hassave) {
        if (virDomainManagedSaveRemove(dom, 0) < 0) {
            vshError(ctl, _("Failed to remove managed save image for domain %s"),
                     name);
            goto cleanup;
        }
        else
            vshPrint(ctl, _("Removed managedsave image for domain %s"), name);
    }
    else
        vshPrint(ctl, _("Domain %s has no manage save image; removal skipped"),
                 name);

    ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "schedinfo" command
 */
static const vshCmdInfo info_schedinfo[] = {
    {"help", N_("show/set scheduler parameters")},
    {"desc", N_("Show/Set scheduler parameters.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_schedinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"set", VSH_OT_STRING, VSH_OFLAG_NONE, N_("parameter=value")},
    {"weight", VSH_OT_INT, VSH_OFLAG_NONE, N_("weight for XEN_CREDIT")},
    {"cap", VSH_OT_INT, VSH_OFLAG_NONE, N_("cap for XEN_CREDIT")},
    {"current", VSH_OT_BOOL, 0, N_("get/set current scheduler info")},
    {"config", VSH_OT_BOOL, 0, N_("get/set value to be used on next boot")},
    {"live", VSH_OT_BOOL, 0, N_("get/set value from running domain")},
    {NULL, 0, 0, NULL}
};

static int
cmdSchedInfoUpdate(vshControl *ctl, const vshCmd *cmd,
                   virTypedParameterPtr param)
{
    const char *data = NULL;

    /* Legacy 'weight' parameter */
    if (STREQ(param->field, "weight") &&
        param->type == VIR_TYPED_PARAM_UINT &&
        vshCommandOptBool(cmd, "weight")) {
        int val;
        if (vshCommandOptInt(cmd, "weight", &val) <= 0) {
            vshError(ctl, "%s", _("Invalid value of weight"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    /* Legacy 'cap' parameter */
    if (STREQ(param->field, "cap") &&
        param->type == VIR_TYPED_PARAM_UINT &&
        vshCommandOptBool(cmd, "cap")) {
        int val;
        if (vshCommandOptInt(cmd, "cap", &val) <= 0) {
            vshError(ctl, "%s", _("Invalid value of cap"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    if (vshCommandOptString(cmd, "set", &data) > 0) {
        char *val = strchr(data, '=');
        int match = 0;
        if (!val) {
            vshError(ctl, "%s", _("Invalid syntax for --set, expecting name=value"));
            return -1;
        }
        *val = '\0';
        match = STREQ(data, param->field);
        *val = '=';
        val++;

        if (!match)
            return 0;

        switch (param->type) {
        case VIR_TYPED_PARAM_INT:
            if (virStrToLong_i(val, NULL, 10, &param->value.i) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an int"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_UINT:
            if (virStrToLong_ui(val, NULL, 10, &param->value.ui) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned int"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_LLONG:
            if (virStrToLong_ll(val, NULL, 10, &param->value.l) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting a long long"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_ULLONG:
            if (virStrToLong_ull(val, NULL, 10, &param->value.ul) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned long long"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            if (virStrToDouble(val, NULL, &param->value.d) < 0) {
                vshError(ctl, "%s", _("Invalid value for parameter, expecting a double"));
                return -1;
            }
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            param->value.b = STREQ(val, "0") ? 0 : 1;
        }
        return 1;
    }

    return 0;
}


static bool
cmdSchedinfo(vshControl *ctl, const vshCmd *cmd)
{
    char *schedulertype;
    virDomainPtr dom;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int update = 0;
    int i, ret;
    bool ret_val = false;
    unsigned int flags = 0;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* Print SchedulerType */
    schedulertype = virDomainGetSchedulerType(dom, &nparams);
    if (schedulertype != NULL) {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"),
             schedulertype);
        VIR_FREE(schedulertype);
    } else {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), _("Unknown"));
        goto cleanup;
    }

    if (nparams) {
        params = vshMalloc(ctl, sizeof(*params) * nparams);

        memset(params, 0, sizeof(*params) * nparams);
        if (flags || current) {
            /* We cannot query both live and config at once, so settle
               on current in that case.  If we are setting, then the
               two values should match when we re-query; otherwise, we
               report the error later.  */
            ret = virDomainGetSchedulerParametersFlags(dom, params, &nparams,
                                                       ((live && config) ? 0
                                                        : flags));
        } else {
            ret = virDomainGetSchedulerParameters(dom, params, &nparams);
        }
        if (ret == -1)
            goto cleanup;

        /* See if any params are being set */
        for (i = 0; i < nparams; i++) {
            ret = cmdSchedInfoUpdate(ctl, cmd, &(params[i]));
            if (ret == -1)
                goto cleanup;

            if (ret == 1)
                update = 1;
        }

        /* Update parameters & refresh data */
        if (update) {
            if (flags || current)
                ret = virDomainSetSchedulerParametersFlags(dom, params,
                                                           nparams, flags);
            else
                ret = virDomainSetSchedulerParameters(dom, params, nparams);
            if (ret == -1)
                goto cleanup;

            if (flags || current)
                ret = virDomainGetSchedulerParametersFlags(dom, params,
                                                           &nparams,
                                                           ((live && config) ? 0
                                                            : flags));
            else
                ret = virDomainGetSchedulerParameters(dom, params, &nparams);
            if (ret == -1)
                goto cleanup;
        } else {
            /* See if we've tried to --set var=val.  If so, the fact that
               we reach this point (with update == 0) means that "var" did
               not match any of the settable parameters.  Report the error.  */
            const char *var_value_pair = NULL;
            if (vshCommandOptString(cmd, "set", &var_value_pair) > 0) {
                vshError(ctl, _("invalid scheduler option: %s"),
                         var_value_pair);
                goto cleanup;
            }
            /* When not doing --set, --live and --config do not mix.  */
            if (live && config) {
                vshError(ctl, "%s",
                         _("cannot query both live and config at once"));
                goto cleanup;
            }
        }

        ret_val = true;
        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    }

 cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret_val;
}

/*
 * "restore" command
 */
static const vshCmdInfo info_restore[] = {
    {"help", N_("restore a domain from a saved state in a file")},
    {"desc", N_("Restore a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_restore[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("the state to restore")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when restoring")},
    {"xml", VSH_OT_STRING, 0,
     N_("filename containing updated XML for the target")},
    {"running", VSH_OT_BOOL, 0, N_("restore domain into running state")},
    {"paused", VSH_OT_BOOL, 0, N_("restore domain into paused state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    unsigned int flags = 0;
    const char *xmlfile = NULL;
    char *xml = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DOMAIN_SAVE_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "running"))
        flags |= VIR_DOMAIN_SAVE_RUNNING;
    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_SAVE_PAUSED;

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        return false;
    }

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0)
        goto cleanup;

    if (((flags || xml)
         ? virDomainRestoreFlags(ctl->conn, from, xml, flags)
         : virDomainRestore(ctl->conn, from)) < 0) {
        vshError(ctl, _("Failed to restore domain from %s"), from);
        goto cleanup;
    }

    vshPrint(ctl, _("Domain restored from %s\n"), from);
    ret = true;

cleanup:
    VIR_FREE(xml);
    return ret;
}

/*
 * "dump" command
 */
static const vshCmdInfo info_dump[] = {
    {"help", N_("dump the core of a domain to a file for analysis")},
    {"desc", N_("Core dump a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dump[] = {
    {"live", VSH_OT_BOOL, 0, N_("perform a live core dump if supported")},
    {"crash", VSH_OT_BOOL, 0, N_("crash the domain after core dump")},
    {"bypass-cache", VSH_OT_BOOL, 0,
     N_("avoid file system cache when saving")},
    {"reset", VSH_OT_BOOL, 0, N_("reset the domain after core dump")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to dump the core")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of dump")},
    {NULL, 0, 0, NULL}
};

static void
doDump(void *opaque)
{
    char ret = '1';
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    virDomainPtr dom = NULL;
    sigset_t sigmask, oldsigmask;
    const char *name = NULL;
    const char *to = NULL;
    unsigned int flags = 0;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto out;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        goto out;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto out;

    if (vshCommandOptBool (cmd, "live"))
        flags |= VIR_DUMP_LIVE;
    if (vshCommandOptBool (cmd, "crash"))
        flags |= VIR_DUMP_CRASH;
    if (vshCommandOptBool(cmd, "bypass-cache"))
        flags |= VIR_DUMP_BYPASS_CACHE;
    if (vshCommandOptBool(cmd, "reset"))
        flags |= VIR_DUMP_RESET;

    if (virDomainCoreDump(dom, to, flags) < 0) {
        vshError(ctl, _("Failed to core dump domain %s to %s"), name, to);
        goto out;
    }

    ret = '0';
out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom)
        virDomainFree (dom);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static bool
cmdDump(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int p[2] = { -1, -1};
    bool ret = false;
    bool verbose = false;
    const char *name = NULL;
    const char *to = NULL;
    vshCtrlData data;
    virThread workerThread;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptString(cmd, "file", &to) <= 0)
        return false;

    if (vshCommandOptBool (cmd, "verbose"))
        verbose = true;

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doDump,
                        &data) < 0)
        goto cleanup;

    ret = vshWatchJob(ctl, dom, verbose, p[0], 0, NULL, NULL, _("Dump"));

    virThreadJoin(&workerThread);

    if (ret)
        vshPrint(ctl, _("\nDomain %s dumped to %s\n"), name, to);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return ret;
}

static const vshCmdInfo info_screenshot[] = {
    {"help", N_("take a screenshot of a current domain console and store it "
                "into a file")},
    {"desc", N_("screenshot of a current domain console")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_screenshot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_NONE, N_("where to store the screenshot")},
    {"screen", VSH_OT_INT, VSH_OFLAG_NONE, N_("ID of a screen to take screenshot of")},
    {NULL, 0, 0, NULL}
};

static int vshStreamSink(virStreamPtr st ATTRIBUTE_UNUSED,
                         const char *bytes, size_t nbytes, void *opaque)
{
    int *fd = opaque;

    return safewrite(*fd, bytes, nbytes);
}

/**
 * Generate string: '<domain name>-<timestamp>[<extension>]'
 */
static char *
vshGenFileName(vshControl *ctl, virDomainPtr dom, const char *mime)
{
    char timestr[100];
    struct timeval cur_time;
    struct tm time_info;
    const char *ext = NULL;
    char *ret = NULL;

    /* We should be already connected, but doesn't
     * hurt to check */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return NULL;

    if (!dom) {
        vshError(ctl, "%s", _("Invalid domain supplied"));
        return NULL;
    }

    if (STREQ(mime, "image/x-portable-pixmap"))
        ext = ".ppm";
    else if (STREQ(mime, "image/png"))
        ext = ".png";
    /* add mime type here */

    gettimeofday(&cur_time, NULL);
    localtime_r(&cur_time.tv_sec, &time_info);
    strftime(timestr, sizeof(timestr), "%Y-%m-%d-%H:%M:%S", &time_info);

    if (virAsprintf(&ret, "%s-%s%s", virDomainGetName(dom),
                    timestr, ext ? ext : "") < 0) {
        vshError(ctl, "%s", _("Out of memory"));
        return NULL;
    }

    return ret;
}

static bool
cmdScreenshot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *name = NULL;
    char *file = NULL;
    int fd = -1;
    virStreamPtr st = NULL;
    unsigned int screen = 0;
    unsigned int flags = 0; /* currently unused */
    int ret = false;
    bool created = false;
    bool generated = false;
    char *mime = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", (const char **) &file) < 0) {
        vshError(ctl, "%s", _("file must not be empty"));
        return false;
    }

    if (vshCommandOptUInt(cmd, "screen", &screen) < 0) {
        vshError(ctl, "%s", _("invalid screen ID"));
        return false;
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    st = virStreamNew(ctl->conn, 0);

    mime = virDomainScreenshot(dom, st, screen, flags);
    if (!mime) {
        vshError(ctl, _("could not take a screenshot of %s"), name);
        goto cleanup;
    }

    if (!file) {
        if (!(file=vshGenFileName(ctl, dom, mime)))
            return false;
        generated = true;
    }

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create file %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    if (virStreamRecvAll(st, vshStreamSink, &fd) < 0) {
        vshError(ctl, _("could not receive data from domain %s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close stream on domain %s"), name);
        goto cleanup;
    }

    vshPrint(ctl, _("Screenshot saved to %s, with type of %s"), file, mime);
    ret = true;

cleanup:
    if (!ret && created)
        unlink(file);
    if (generated)
        VIR_FREE(file);
    virDomainFree(dom);
    if (st)
        virStreamFree(st);
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(mime);
    return ret;
}

/*
 * "resume" command
 */
static const vshCmdInfo info_resume[] = {
    {"help", N_("resume a domain")},
    {"desc", N_("Resume a previously suspended domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_resume[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainResume(dom) == 0) {
        vshPrint(ctl, _("Domain %s resumed\n"), name);
    } else {
        vshError(ctl, _("Failed to resume domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "shutdown" command
 */
static const vshCmdInfo info_shutdown[] = {
    {"help", N_("gracefully shutdown a domain")},
    {"desc", N_("Run shutdown in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_shutdown[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_STRING, VSH_OFLAG_NONE, N_("shutdown mode: acpi|agent")},
    {NULL, 0, 0, NULL}
};

static bool
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    const char *mode = NULL;
    int flags = 0;
    int rv;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (mode) {
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
        } else {
            vshError(ctl, _("Unknown mode %s value, expecting 'acpi' or 'agent'"), mode);
            return false;
        }
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (flags)
        rv = virDomainShutdownFlags(dom, flags);
    else
        rv = virDomainShutdown(dom);
    if (rv == 0) {
        vshPrint(ctl, _("Domain %s is being shutdown\n"), name);
    } else {
        vshError(ctl, _("Failed to shutdown domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "reboot" command
 */
static const vshCmdInfo info_reboot[] = {
    {"help", N_("reboot a domain")},
    {"desc", N_("Run a reboot command in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_reboot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_STRING, VSH_OFLAG_NONE, N_("shutdown mode: acpi|agent")},
    {NULL, 0, 0, NULL}
};

static bool
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    const char *mode = NULL;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (mode) {
        if (STREQ(mode, "acpi")) {
            flags |= VIR_DOMAIN_SHUTDOWN_ACPI_POWER_BTN;
        } else if (STREQ(mode, "agent")) {
            flags |= VIR_DOMAIN_SHUTDOWN_GUEST_AGENT;
        } else {
            vshError(ctl, _("Unknown mode %s value, expecting 'acpi' or 'agent'"), mode);
            return false;
        }
    }

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReboot(dom, flags) == 0) {
        vshPrint(ctl, _("Domain %s is being rebooted\n"), name);
    } else {
        vshError(ctl, _("Failed to reboot domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "reset" command
 */
static const vshCmdInfo info_reset[] = {
    {"help", N_("reset a domain")},
    {"desc", N_("Reset the target domain as if by power button")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_reset[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdReset(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (virDomainReset(dom, 0) == 0) {
        vshPrint(ctl, _("Domain %s was reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "destroy" command
 */
static const vshCmdInfo info_destroy[] = {
    {"help", N_("destroy (stop) a domain")},
    {"desc",
     N_("Forcefully stop a given domain, but leave its resources intact.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"graceful", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("terminate gracefully")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    const char *name;
    unsigned int flags = 0;
    int result;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return false;

    if (vshCommandOptBool(cmd, "graceful"))
       flags |= VIR_DOMAIN_DESTROY_GRACEFUL;

    if (flags)
       result = virDomainDestroyFlags(dom, VIR_DOMAIN_DESTROY_GRACEFUL);
    else
       result = virDomainDestroy(dom);

    if (result == 0) {
        vshPrint(ctl, _("Domain %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy domain %s"), name);
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "dominfo" command
 */
static const vshCmdInfo info_dominfo[] = {
    {"help", N_("domain information")},
    {"desc", N_("Returns basic information about the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dominfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDominfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virSecurityModel secmodel;
    virSecurityLabelPtr seclabel;
    int persistent = 0;
    bool ret = true;
    int autostart;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];
    int has_managed_save = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%-15s %s\n", _("Id:"), "-");
    else
        vshPrint(ctl, "%-15s %d\n", _("Id:"), id);
    vshPrint(ctl, "%-15s %s\n", _("Name:"), virDomainGetName(dom));

    if (virDomainGetUUIDString(dom, &uuid[0])==0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

    if ((str = virDomainGetOSType(dom))) {
        vshPrint(ctl, "%-15s %s\n", _("OS Type:"), str);
        VIR_FREE(str);
    }

    if (virDomainGetInfo(dom, &info) == 0) {
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 _(vshDomainStateToString(info.state)));

        vshPrint(ctl, "%-15s %d\n", _("CPU(s):"), info.nrVirtCpu);

        if (info.cpuTime != 0) {
            double cpuUsed = info.cpuTime;

            cpuUsed /= 1000000000.0;

            vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
        }

        if (info.maxMem != UINT_MAX)
            vshPrint(ctl, "%-15s %lu kB\n", _("Max memory:"),
                 info.maxMem);
        else
            vshPrint(ctl, "%-15s %s\n", _("Max memory:"),
                 _("no limit"));

        vshPrint(ctl, "%-15s %lu kB\n", _("Used memory:"),
                 info.memory);

    } else {
        ret = false;
    }

    /* Check and display whether the domain is persistent or not */
    persistent = virDomainIsPersistent(dom);
    vshDebug(ctl, VSH_ERR_DEBUG, "Domain persistent flag value: %d\n",
             persistent);
    if (persistent < 0)
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

    /* Check and display whether the domain autostarts or not */
    if (!virDomainGetAutostart(dom, &autostart)) {
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"),
                 autostart ? _("enable") : _("disable") );
    }

    has_managed_save = virDomainHasManagedSaveImage(dom, 0);
    if (has_managed_save < 0)
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Managed save:"),
                 has_managed_save ? _("yes") : _("no"));

    /* Security model and label information */
    memset(&secmodel, 0, sizeof(secmodel));
    if (virNodeGetSecurityModel(ctl->conn, &secmodel) == -1) {
        if (last_error->code != VIR_ERR_NO_SUPPORT) {
            virDomainFree(dom);
            return false;
        } else {
            virFreeError(last_error);
            last_error = NULL;
        }
    } else {
        /* Only print something if a security model is active */
        if (secmodel.model[0] != '\0') {
            vshPrint(ctl, "%-15s %s\n", _("Security model:"), secmodel.model);
            vshPrint(ctl, "%-15s %s\n", _("Security DOI:"), secmodel.doi);

            /* Security labels are only valid for active domains */
            if (VIR_ALLOC(seclabel) < 0) {
                virDomainFree(dom);
                return false;
            }

            if (virDomainGetSecurityLabel(dom, seclabel) == -1) {
                virDomainFree(dom);
                VIR_FREE(seclabel);
                return false;
            } else {
                if (seclabel->label[0] != '\0')
                    vshPrint(ctl, "%-15s %s (%s)\n", _("Security label:"),
                             seclabel->label, seclabel->enforcing ? "enforcing" : "permissive");
            }

            VIR_FREE(seclabel);
        }
    }
    virDomainFree(dom);
    return ret;
}

/*
 * "domjobinfo" command
 */
static const vshCmdInfo info_domjobinfo[] = {
    {"help", N_("domain job information")},
    {"desc", N_("Returns information about jobs running on a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};


static bool
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info;
    virDomainPtr dom;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainGetJobInfo(dom, &info) == 0) {
        const char *unit;
        double val;

        vshPrint(ctl, "%-17s ", _("Job type:"));
        switch (info.type) {
        case VIR_DOMAIN_JOB_BOUNDED:
            vshPrint(ctl, "%-12s\n", _("Bounded"));
            break;

        case VIR_DOMAIN_JOB_UNBOUNDED:
            vshPrint(ctl, "%-12s\n", _("Unbounded"));
            break;

        case VIR_DOMAIN_JOB_NONE:
        default:
            vshPrint(ctl, "%-12s\n", _("None"));
            goto cleanup;
        }

        vshPrint(ctl, "%-17s %-12llu ms\n", _("Time elapsed:"), info.timeElapsed);
        if (info.type == VIR_DOMAIN_JOB_BOUNDED)
            vshPrint(ctl, "%-17s %-12llu ms\n", _("Time remaining:"), info.timeRemaining);
        if (info.dataTotal || info.dataRemaining || info.dataProcessed) {
            val = prettyCapacity(info.dataProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data processed:"), val, unit);
            val = prettyCapacity(info.dataRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data remaining:"), val, unit);
            val = prettyCapacity(info.dataTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Data total:"), val, unit);
        }
        if (info.memTotal || info.memRemaining || info.memProcessed) {
            val = prettyCapacity(info.memProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory processed:"), val, unit);
            val = prettyCapacity(info.memRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory remaining:"), val, unit);
            val = prettyCapacity(info.memTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("Memory total:"), val, unit);
        }
        if (info.fileTotal || info.fileRemaining || info.fileProcessed) {
            val = prettyCapacity(info.fileProcessed, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File processed:"), val, unit);
            val = prettyCapacity(info.fileRemaining, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File remaining:"), val, unit);
            val = prettyCapacity(info.fileTotal, &unit);
            vshPrint(ctl, "%-17s %-.3lf %s\n", _("File total:"), val, unit);
        }
    } else {
        ret = false;
    }
cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "domjobabort" command
 */
static const vshCmdInfo info_domjobabort[] = {
    {"help", N_("abort active domain job")},
    {"desc", N_("Aborts the currently running domain job")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobabort[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainAbortJob(dom) < 0)
        ret = false;

    virDomainFree(dom);
    return ret;
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
            vshPrint(ctl, "%5lu: %10llu kB\n", nodes_id[cell],
                    (nodes_free[cell]/1024));
            memory += nodes_free[cell];
        }

        vshPrintExtra(ctl, "--------------------\n");
        vshPrintExtra(ctl, "%5s: %10llu kB\n", _("Total"), memory/1024);
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
            vshPrint(ctl, "%s: %llu kB\n", _("Total"), (memory/1024));
        else
            vshPrint(ctl, "%d: %llu kB\n", cell, (memory/1024));
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
 * "maxvcpus" command
 */
static const vshCmdInfo info_maxvcpus[] = {
    {"help", N_("connection vcpu maximum")},
    {"desc", N_("Show maximum number of virtual CPUs for guests on this connection.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_maxvcpus[] = {
    {"type", VSH_OT_STRING, 0, N_("domain type")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMaxvcpus(vshControl *ctl, const vshCmd *cmd)
{
    const char *type = NULL;
    int vcpus;

    if (vshCommandOptString(cmd, "type", &type) < 0) {
        vshError(ctl, "%s", _("Invalid type"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    vcpus = virConnectGetMaxVcpus(ctl->conn, type);
    if (vcpus < 0)
        return false;
    vshPrint(ctl, "%d\n", vcpus);

    return true;
}

/*
 * "vcpucount" command
 */
static const vshCmdInfo info_vcpucount[] = {
    {"help", N_("domain vcpu counts")},
    {"desc", N_("Returns the number of virtual CPUs used by the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpucount[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"maximum", VSH_OT_BOOL, 0, N_("get maximum cap on vcpus")},
    {"active", VSH_OT_BOOL, 0, N_("get number of currently active vcpus")},
    {"live", VSH_OT_BOOL, 0, N_("get value from running domain")},
    {"config", VSH_OT_BOOL, 0, N_("get value to be used on next boot")},
    {"current", VSH_OT_BOOL, 0,
     N_("get value according to current domain state")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpucount(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    int maximum = vshCommandOptBool(cmd, "maximum");
    int active = vshCommandOptBool(cmd, "active");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int current = vshCommandOptBool(cmd, "current");
    bool all = maximum + active + current + config + live == 0;
    int count;

    /* We want one of each pair of mutually exclusive options; that
     * is, use of flags requires exactly two options.  We reject the
     * use of more than 2 flags later on.  */
    if (maximum + active + current + config + live == 1) {
        if (maximum || active) {
            vshError(ctl,
                     _("when using --%s, one of --config, --live, or --current "
                       "must be specified"),
                     maximum ? "maximum" : "active");
        } else {
            vshError(ctl,
                     _("when using --%s, either --maximum or --active must be "
                       "specified"),
                     (current ? "current" : config ? "config" : "live"));
        }
        return false;
    }

    /* Backwards compatibility: prior to 0.9.4,
     * VIR_DOMAIN_AFFECT_CURRENT was unsupported, and --current meant
     * the opposite of --maximum.  Translate the old '--current
     * --live' into the new '--active --live', while treating the new
     * '--maximum --current' correctly rather than rejecting it as
     * '--maximum --active'.  */
    if (!maximum && !active && current) {
        current = false;
        active = true;
    }

    if (maximum && active) {
        vshError(ctl, "%s",
                 _("--maximum and --active cannot both be specified"));
        return false;
    }
    if (current + config + live > 1) {
        vshError(ctl, "%s",
                 _("--config, --live, and --current are mutually exclusive"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* In all cases, try the new API first; if it fails because we are
     * talking to an older client, generally we try a fallback API
     * before giving up.  --current requires the new API, since we
     * don't know whether the domain is running or inactive.  */
    if (current) {
        count = virDomainGetVcpusFlags(dom,
                                       maximum ? VIR_DOMAIN_VCPU_MAXIMUM : 0);
        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else {
            vshPrint(ctl, "%d\n", count);
        }
    }

    if (all || (maximum && config)) {
        count = virDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_MAXIMUM |
                                             VIR_DOMAIN_AFFECT_CONFIG));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            char *tmp;
            char *xml = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
            if (xml && (tmp = strstr(xml, "<vcpu"))) {
                tmp = strchr(tmp, '>');
                if (!tmp || virStrToLong_i(tmp + 1, &tmp, 10, &count) < 0)
                    count = -1;
            }
            virFreeError(last_error);
            last_error = NULL;
            VIR_FREE(xml);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("maximum"), _("config"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    if (all || (maximum && live)) {
        count = virDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_MAXIMUM |
                                             VIR_DOMAIN_AFFECT_LIVE));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            count = virDomainGetMaxVcpus(dom);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("maximum"), _("live"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    if (all || (active && config)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_AFFECT_CONFIG);
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            char *tmp, *end;
            char *xml = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
            if (xml && (tmp = strstr(xml, "<vcpu"))) {
                end = strchr(tmp, '>');
                if (end) {
                    *end = '\0';
                    tmp = strstr(tmp, "current=");
                    if (!tmp)
                        tmp = end + 1;
                    else {
                        tmp += strlen("current=");
                        tmp += *tmp == '\'' || *tmp == '"';
                    }
                }
                if (!tmp || virStrToLong_i(tmp, &tmp, 10, &count) < 0)
                    count = -1;
            }
            VIR_FREE(xml);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("current"), _("config"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    if (all || (active && live)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_AFFECT_LIVE);
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            virDomainInfo info;
            if (virDomainGetInfo(dom, &info) == 0)
                count = info.nrVirtCpu;
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = false;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("current"), _("live"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "vcpuinfo" command
 */
static const vshCmdInfo info_vcpuinfo[] = {
    {"help", N_("detailed domain vcpu information")},
    {"desc", N_("Returns basic information about the domain virtual CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpuinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpuinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    virVcpuInfoPtr cpuinfo;
    unsigned char *cpumaps;
    int ncpus, maxcpu;
    size_t cpumaplen;
    bool ret = true;
    int n, m;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        return false;
    }

    cpuinfo = vshMalloc(ctl, sizeof(virVcpuInfo)*info.nrVirtCpu);
    maxcpu = VIR_NODEINFO_MAXCPUS(nodeinfo);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    cpumaps = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom,
                                   cpuinfo, info.nrVirtCpu,
                                   cpumaps, cpumaplen)) >= 0) {
        for (n = 0 ; n < ncpus ; n++) {
            vshPrint(ctl, "%-15s %d\n", _("VCPU:"), n);
            vshPrint(ctl, "%-15s %d\n", _("CPU:"), cpuinfo[n].cpu);
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _(vshDomainVcpuStateToString(cpuinfo[n].state)));
            if (cpuinfo[n].cpuTime != 0) {
                double cpuUsed = cpuinfo[n].cpuTime;

                cpuUsed /= 1000000000.0;

                vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
            }
            vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
            for (m = 0; m < maxcpu; m++) {
                vshPrint(ctl, "%c", VIR_CPU_USABLE(cpumaps, cpumaplen, n, m) ? 'y' : '-');
            }
            vshPrint(ctl, "\n");
            if (n < (ncpus - 1)) {
                vshPrint(ctl, "\n");
            }
        }
    } else {
        if (info.state == VIR_DOMAIN_SHUTOFF &&
            (ncpus = virDomainGetVcpuPinInfo(dom, info.nrVirtCpu,
                                             cpumaps, cpumaplen,
                                             VIR_DOMAIN_AFFECT_CONFIG)) >= 0) {

            /* fallback plan to use virDomainGetVcpuPinInfo */

            for (n = 0; n < ncpus; n++) {
                vshPrint(ctl, "%-15s %d\n", _("VCPU:"), n);
                vshPrint(ctl, "%-15s %s\n", _("CPU:"), _("N/A"));
                vshPrint(ctl, "%-15s %s\n", _("State:"), _("N/A"));
                vshPrint(ctl, "%-15s %s\n", _("CPU time"), _("N/A"));
                vshPrint(ctl, "%-15s ", _("CPU Affinity:"));
                for (m = 0; m < maxcpu; m++) {
                    vshPrint(ctl, "%c",
                             VIR_CPU_USABLE(cpumaps, cpumaplen, n, m) ? 'y' : '-');
                }
                vshPrint(ctl, "\n");
                if (n < (ncpus - 1)) {
                    vshPrint(ctl, "\n");
                }
            }
        } else {
            ret = false;
        }
    }

    VIR_FREE(cpumaps);
    VIR_FREE(cpuinfo);
    virDomainFree(dom);
    return ret;
}

/*
 * "vcpupin" command
 */
static const vshCmdInfo info_vcpupin[] = {
    {"help", N_("control or query domain vcpu affinity")},
    {"desc", N_("Pin domain VCPUs to host physical CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpupin[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"vcpu", VSH_OT_INT, 0, N_("vcpu number")},
    {"cpulist", VSH_OT_DATA, VSH_OFLAG_EMPTY_OK,
     N_("host cpu number(s) to set, or omit option to query")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVcpuPin(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    int vcpu = -1;
    const char *cpulist = NULL;
    bool ret = true;
    unsigned char *cpumap = NULL;
    unsigned char *cpumaps = NULL;
    size_t cpumaplen;
    bool bit, lastbit, isInvert;
    int i, cpu, lastcpu, maxcpu, ncpus;
    bool unuse = false;
    const char *cur;
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int current = vshCommandOptBool(cmd, "current");
    bool query = false; /* Query mode if no cpulist */
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "cpulist", &cpulist) < 0) {
        vshError(ctl, "%s", _("vcpupin: Missing cpulist."));
        virDomainFree(dom);
        return false;
    }
    query = !cpulist;

    /* In query mode, "vcpu" is optional */
    if (vshCommandOptInt(cmd, "vcpu", &vcpu) < !query) {
        vshError(ctl, "%s",
                 _("vcpupin: Invalid or missing vCPU number."));
        virDomainFree(dom);
        return false;
    }

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return false;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        vshError(ctl, "%s", _("vcpupin: failed to get domain information."));
        virDomainFree(dom);
        return false;
    }

    if (vcpu >= info.nrVirtCpu) {
        vshError(ctl, "%s", _("vcpupin: Invalid vCPU number."));
        virDomainFree(dom);
        return false;
    }

    maxcpu = VIR_NODEINFO_MAXCPUS(nodeinfo);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);

    /* Query mode: show CPU affinity information then exit.*/
    if (query) {
        /* When query mode and neither "live", "config" nor "current"
         * is specified, set VIR_DOMAIN_AFFECT_CURRENT as flags */
        if (flags == -1)
            flags = VIR_DOMAIN_AFFECT_CURRENT;

        cpumaps = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);
        if ((ncpus = virDomainGetVcpuPinInfo(dom, info.nrVirtCpu,
                                             cpumaps, cpumaplen, flags)) >= 0) {

            vshPrint(ctl, "%s %s\n", _("VCPU:"), _("CPU Affinity"));
            vshPrint(ctl, "----------------------------------\n");
            for (i = 0; i < ncpus; i++) {

               if (vcpu != -1 && i != vcpu)
                   continue;

               bit = lastbit = isInvert = false;
               lastcpu = -1;

               vshPrint(ctl, "%4d: ", i);
               for (cpu = 0; cpu < maxcpu; cpu++) {

                   bit = VIR_CPU_USABLE(cpumaps, cpumaplen, i, cpu);

                   isInvert = (bit ^ lastbit);
                   if (bit && isInvert) {
                       if (lastcpu == -1)
                           vshPrint(ctl, "%d", cpu);
                       else
                           vshPrint(ctl, ",%d", cpu);
                       lastcpu = cpu;
                   }
                   if (!bit && isInvert && lastcpu != cpu - 1)
                       vshPrint(ctl, "-%d", cpu - 1);
                   lastbit = bit;
               }
               if (bit && !isInvert) {
                  vshPrint(ctl, "-%d", maxcpu - 1);
               }
               vshPrint(ctl, "\n");
            }

        } else {
            ret = false;
        }
        VIR_FREE(cpumaps);
        goto cleanup;
    }

    /* Pin mode: pinning specified vcpu to specified physical cpus*/

    cpumap = vshCalloc(ctl, cpumaplen, sizeof(cpumap));
    /* Parse cpulist */
    cur = cpulist;
    if (*cur == 0) {
        goto parse_error;
    } else if (*cur == 'r') {
        for (cpu = 0; cpu < maxcpu; cpu++)
            VIR_USE_CPU(cpumap, cpu);
        cur = "";
    }

    while (*cur != 0) {

        /* the char '^' denotes exclusive */
        if (*cur == '^') {
            cur++;
            unuse = true;
        }

        /* parse physical CPU number */
        if (!c_isdigit(*cur))
            goto parse_error;
        cpu  = virParseNumber(&cur);
        if (cpu < 0) {
            goto parse_error;
        }
        if (cpu >= maxcpu) {
            vshError(ctl, _("Physical CPU %d doesn't exist."), cpu);
            goto parse_error;
        }
        virSkipSpaces(&cur);

        if ((*cur == ',') || (*cur == 0)) {
            if (unuse) {
                VIR_UNUSE_CPU(cpumap, cpu);
            } else {
                VIR_USE_CPU(cpumap, cpu);
            }
        } else if (*cur == '-') {
            /* the char '-' denotes range */
            if (unuse) {
                goto parse_error;
            }
            cur++;
            virSkipSpaces(&cur);
            /* parse the end of range */
            lastcpu = virParseNumber(&cur);
            if (lastcpu < cpu) {
                goto parse_error;
            }
            if (lastcpu >= maxcpu) {
                vshError(ctl, _("Physical CPU %d doesn't exist."), maxcpu);
                goto parse_error;
            }
            for (i = cpu; i <= lastcpu; i++) {
                VIR_USE_CPU(cpumap, i);
            }
            virSkipSpaces(&cur);
        }

        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            unuse = false;
        } else if (*cur == 0) {
            break;
        } else {
            goto parse_error;
        }
    }

    if (flags == -1) {
        if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0) {
            ret = false;
        }
    } else {
        if (virDomainPinVcpuFlags(dom, vcpu, cpumap, cpumaplen, flags) != 0) {
            ret = false;
        }
    }

cleanup:
    VIR_FREE(cpumap);
    virDomainFree(dom);
    return ret;

parse_error:
    vshError(ctl, "%s", _("cpulist: Invalid format."));
    ret = false;
    goto cleanup;
}

/*
 * "setvcpus" command
 */
static const vshCmdInfo info_setvcpus[] = {
    {"help", N_("change number of virtual CPUs")},
    {"desc", N_("Change the number of virtual CPUs in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setvcpus[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"count", VSH_OT_INT, VSH_OFLAG_REQ, N_("number of virtual CPUs")},
    {"maximum", VSH_OT_BOOL, 0, N_("set maximum limit on next boot")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSetvcpus(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int count = 0;
    bool ret = true;
    int maximum = vshCommandOptBool(cmd, "maximum");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int current = vshCommandOptBool(cmd, "current");
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config && !maximum)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptInt(cmd, "count", &count) < 0) {
        vshError(ctl, "%s", _("Invalid number of virtual CPUs"));
        goto cleanup;
    }

    if (flags == -1) {
        if (virDomainSetVcpus(dom, count) != 0) {
            ret = false;
        }
    } else {
        /* If the --maximum flag was given, we need to ensure only the
           --config flag is in effect as well */
        if (maximum) {
            vshDebug(ctl, VSH_ERR_DEBUG, "--maximum flag was given\n");

            flags |= VIR_DOMAIN_VCPU_MAXIMUM;

            /* If neither the --config nor --live flags were given, OR
               if just the --live flag was given, we need to error out
               warning the user that the --maximum flag can only be used
               with the --config flag */
            if (live || !config) {

                /* Warn the user about the invalid flag combination */
                vshError(ctl, _("--maximum must be used with --config only"));
                ret = false;
                goto cleanup;
            }
        }

        /* Apply the virtual cpu changes */
        if (virDomainSetVcpusFlags(dom, count, flags) < 0) {
            ret = false;
        }
    }

  cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "cpu-stats" command
 */
static const vshCmdInfo info_cpu_stats[] = {
    {"help", N_("show domain cpu statistics")},
    {"desc",
     N_("Display per-CPU and total statistics about the domain's CPUs")},
    {NULL, NULL},
};

static const vshCmdOptDef opts_cpu_stats[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"total", VSH_OT_BOOL, 0, N_("Show total statistics only")},
    {"start", VSH_OT_INT, 0, N_("Show statistics from this CPU")},
    {"count", VSH_OT_INT, 0, N_("Number of shown CPUs at most")},
    {NULL, 0, 0, NULL},
};

static bool
cmdCPUStats(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virTypedParameterPtr params = NULL;
    int i, j, pos, max_id, cpu = -1, show_count = -1, nparams;
    bool show_total = false, show_per_cpu = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    show_total = vshCommandOptBool(cmd, "total");
    if (vshCommandOptInt(cmd, "start", &cpu) > 0)
        show_per_cpu = true;
    if (vshCommandOptInt(cmd, "count", &show_count) > 0)
        show_per_cpu = true;

    /* default show per_cpu and total */
    if (!show_total && !show_per_cpu) {
        show_total = true;
        show_per_cpu = true;
    }

    if (!show_per_cpu) /* show total stats only */
        goto do_show_total;

    /* check cpu, show_count, and ignore wrong argument */
    if (cpu < 0)
        cpu = 0;

    /* get number of cpus on the node */
    if ((max_id = virDomainGetCPUStats(dom, NULL, 0, 0, 0, 0)) < 0)
        goto failed_stats;
    if (show_count < 0 || show_count > max_id)
        show_count = max_id;

    /* get percpu information */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, 0, 1, 0)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No per-CPU stats available"));
        goto do_show_total;
    }

    if (VIR_ALLOC_N(params, nparams * MIN(show_count, 128)) < 0)
        goto failed_params;

    while (show_count) {
        int ncpus = MIN(show_count, 128);

        if (virDomainGetCPUStats(dom, params, nparams, cpu, ncpus, 0) < 0)
            goto failed_stats;

        for (i = 0; i < ncpus; i++) {
            if (params[i * nparams].type == 0) /* this cpu is not in the map */
                continue;
            vshPrint(ctl, "CPU%d:\n", cpu + i);

            for (j = 0; j < nparams; j++) {
                pos = i * nparams + j;
                vshPrint(ctl, "\t%-12s ", params[pos].field);
                if (STREQ(params[pos].field, VIR_DOMAIN_CPU_STATS_CPUTIME) &&
                    params[j].type == VIR_TYPED_PARAM_ULLONG) {
                    vshPrint(ctl, "%9lld.%09lld seconds\n",
                             params[pos].value.ul / 1000000000,
                             params[pos].value.ul % 1000000000);
                } else {
                    const char *s = vshGetTypedParamValue(ctl, &params[pos]);
                    vshPrint(ctl, _("%s\n"), s);
                    VIR_FREE(s);
                }
            }
        }
        cpu += ncpus;
        show_count -= ncpus;
        virTypedParameterArrayClear(params, nparams * ncpus);
    }
    VIR_FREE(params);

do_show_total:
    if (!show_total)
        goto cleanup;

    /* get supported num of parameter for total statistics */
    if ((nparams = virDomainGetCPUStats(dom, NULL, 0, -1, 1, 0)) < 0)
        goto failed_stats;

    if (!nparams) {
        vshPrint(ctl, "%s", _("No total stats available"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(params, nparams))
        goto failed_params;

    /* passing start_cpu == -1 gives us domain's total status */
    if ((nparams = virDomainGetCPUStats(dom, params, nparams, -1, 1, 0)) < 0)
        goto failed_stats;

    vshPrint(ctl, _("Total:\n"));
    for (i = 0; i < nparams; i++) {
        vshPrint(ctl, "\t%-12s ", params[i].field);
        if ((STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_CPUTIME) ||
             STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_USERTIME) ||
             STREQ(params[i].field, VIR_DOMAIN_CPU_STATS_SYSTEMTIME)) &&
            params[i].type == VIR_TYPED_PARAM_ULLONG) {
            vshPrint(ctl, "%9lld.%09lld seconds\n",
                     params[i].value.ul / 1000000000,
                     params[i].value.ul % 1000000000);
        } else {
            char *s = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%s\n", s);
            VIR_FREE(s);
        }
    }
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);

cleanup:
    virDomainFree(dom);
    return true;

failed_params:
    virReportOOMError();
    virDomainFree(dom);
    return false;

failed_stats:
    vshError(ctl, _("Failed to virDomainGetCPUStats()\n"));
    VIR_FREE(params);
    virDomainFree(dom);
    return false;
}

/*
 * "inject-nmi" command
 */
static const vshCmdInfo info_inject_nmi[] = {
    {"help", N_("Inject NMI to the guest")},
    {"desc", N_("Inject NMI to the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_inject_nmi[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};


static bool
cmdInjectNMI(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainInjectNMI(dom, 0) < 0)
            ret = false;

    virDomainFree(dom);
    return ret;
}

/*
 * "send-key" command
 */
static const vshCmdInfo info_send_key[] = {
    {"help", N_("Send keycodes to the guest")},
    {"desc", N_("Send keycodes (integers or symbolic names) to the guest")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_send_key[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"codeset", VSH_OT_STRING, VSH_OFLAG_REQ_OPT,
     N_("the codeset of keycodes, default:linux")},
    {"holdtime", VSH_OT_INT, VSH_OFLAG_REQ_OPT,
     N_("the time (in milliseconds) how long the keys will be held")},
    {"keycode", VSH_OT_ARGV, VSH_OFLAG_REQ, N_("the key code")},
    {NULL, 0, 0, NULL}
};

static int get_integer_keycode(const char *key_name)
{
    long val;
    char *endptr;

    val = strtol(key_name, &endptr, 0);
    if (*endptr != '\0' || val > 0xffff || val <= 0)
         return -1;

    return val;
}

static bool
cmdSendKey(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = false;
    const char *codeset_option;
    int codeset;
    int holdtime;
    int count = 0;
    const vshCmdOpt *opt = NULL;
    int keycode;
    unsigned int keycodes[VIR_DOMAIN_SEND_KEY_MAX_KEYS];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "codeset", &codeset_option) <= 0)
        codeset_option = "linux";

    if (vshCommandOptInt(cmd, "holdtime", &holdtime) <= 0)
        holdtime = 0;

    codeset = virKeycodeSetTypeFromString(codeset_option);
    if ((int)codeset < 0) {
        vshError(ctl, _("unknown codeset: '%s'"), codeset_option);
        goto cleanup;
    }

    while ((opt = vshCommandOptArgv(cmd, opt))) {
        if (count == VIR_DOMAIN_SEND_KEY_MAX_KEYS) {
            vshError(ctl, _("too many keycodes"));
            goto cleanup;
        }

        if ((keycode = get_integer_keycode(opt->data)) <= 0) {
            if ((keycode = virKeycodeValueFromString(codeset, opt->data)) <= 0) {
                vshError(ctl, _("invalid keycode: '%s'"), opt->data);
                goto cleanup;
            }
        }

        keycodes[count] = keycode;
        count++;
    }

    if (!(virDomainSendKey(dom, codeset, holdtime, keycodes, count, 0) < 0))
        ret = true;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "setmem" command
 */
static const vshCmdInfo info_setmem[] = {
    {"help", N_("change memory allocation")},
    {"desc", N_("Change the current memory allocation in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"kilobytes", VSH_OT_ALIAS, 0, "size"},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("new memory size, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSetmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool ret = true;
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int current = vshCommandOptBool(cmd, "current");
    unsigned int flags = 0;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(cmd, "size", &bytes, 1024, max) < 0) {
        vshError(ctl, "%s", _("memory size has to be a number"));
        virDomainFree(dom);
        return false;
    }
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (flags == -1) {
        if (virDomainSetMemory(dom, kibibytes) != 0) {
            ret = false;
        }
    } else {
        if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0) {
            ret = false;
        }
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "setmaxmem" command
 */
static const vshCmdInfo info_setmaxmem[] = {
    {"help", N_("change maximum memory limit")},
    {"desc", N_("Change the maximum memory allocation limit in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmaxmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"kilobytes", VSH_OT_ALIAS, 0, "size"},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("new maximum memory size, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdSetmaxmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned long long bytes = 0;
    unsigned long long max;
    unsigned long kibibytes = 0;
    bool ret = true;
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int current = vshCommandOptBool(cmd, "current");
    unsigned int flags = VIR_DOMAIN_MEM_MAXIMUM;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        /* neither option is specified */
        if (!live && !config)
            flags = -1;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    /* The API expects 'unsigned long' KiB, so depending on whether we
     * are 32-bit or 64-bit determines the maximum we can use.  */
    if (sizeof(kibibytes) < sizeof(max))
        max = 1024ull * ULONG_MAX;
    else
        max = ULONG_MAX;
    if (vshCommandOptScaledInt(cmd, "size", &bytes, 1024, max) < 0) {
        vshError(ctl, "%s", _("memory size has to be a number"));
        virDomainFree(dom);
        return false;
    }
    kibibytes = VIR_DIV_UP(bytes, 1024);

    if (flags == -1) {
        if (virDomainSetMaxMemory(dom, kibibytes) != 0) {
            vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
            ret = false;
        }
    } else {
        if (virDomainSetMemoryFlags(dom, kibibytes, flags) < 0) {
            vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
            ret = false;
        }
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "blkiotune" command
 */
static const vshCmdInfo info_blkiotune[] = {
    {"help", N_("Get or set blkio parameters")},
    {"desc", N_("Get or set the current blkio parameters for a guest" \
                " domain.\n" \
                "    To get the blkio parameters use following command: \n\n" \
                "    virsh # blkiotune <domain>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_blkiotune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"weight", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("IO Weight in range [100, 1000]")},
    {"device-weights", VSH_OT_STRING, VSH_OFLAG_NONE,
     N_("per-device IO Weights, in the form of /path/to/device,weight,...")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlkiotune(vshControl * ctl, const vshCmd * cmd)
{
    virDomainPtr dom;
    const char *device_weight = NULL;
    int weight = 0;
    int nparams = 0;
    int rv = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    bool ret = false;
    unsigned int flags = 0;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((rv = vshCommandOptInt(cmd, "weight", &weight)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    }

    if (rv > 0) {
        nparams++;
        if (weight <= 0) {
            vshError(ctl, _("Invalid value of %d for I/O weight"), weight);
            goto cleanup;
        }
    }

    rv = vshCommandOptString(cmd, "device-weights", &device_weight);
    if (rv < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse string parameter"));
        goto cleanup;
    }
    if (rv > 0) {
        nparams++;
    }

    if (nparams == 0) {
        /* get the number of blkio parameters */
        if (virDomainGetBlkioParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of blkio parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the blkio parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetBlkioParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get blkio parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }
    } else {
        /* set the blkio parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_UINT;

            if (weight) {
                temp->value.ui = weight;
                if (!virStrcpy(temp->field, VIR_DOMAIN_BLKIO_WEIGHT,
                               sizeof(temp->field)))
                    goto cleanup;
                weight = 0;
            } else if (device_weight) {
                temp->value.s = vshStrdup(ctl, device_weight);
                temp->type = VIR_TYPED_PARAM_STRING;
                if (!virStrcpy(temp->field, VIR_DOMAIN_BLKIO_DEVICE_WEIGHT,
                               sizeof(temp->field)))
                    goto cleanup;
                device_weight = NULL;
            }
        }

        if (virDomainSetBlkioParameters(dom, params, nparams, flags) < 0) {
            vshError(ctl, "%s", _("Unable to change blkio parameters"));
            goto cleanup;
        }
    }

    ret = true;

  cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "memtune" command
 */
static const vshCmdInfo info_memtune[] = {
    {"help", N_("Get or set memory parameters")},
    {"desc", N_("Get or set the current memory parameters for a guest" \
                " domain.\n" \
                "    To get the memory parameters use following command: \n\n" \
                "    virsh # memtune <domain>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_memtune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"hard-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Max memory, as scaled integer (default KiB)")},
    {"soft-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Memory during contention, as scaled integer (default KiB)")},
    {"swap-hard-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Max memory plus swap, as scaled integer (default KiB)")},
    {"min-guarantee", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Min guaranteed memory, as scaled integer (default KiB)")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static int
vshMemtuneGetSize(const vshCmd *cmd, const char *name, long long *value)
{
    int ret;
    unsigned long long tmp;
    const char *str;
    char *end;

    ret = vshCommandOptString(cmd, name, &str);
    if (ret <= 0)
        return ret;
    if (virStrToLong_ll(str, &end, 10, value) < 0)
        return -1;
    if (*value < 0) {
        *value = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 1;
    }
    tmp = *value;
    if (virScaleInteger(&tmp, end, 1024, LLONG_MAX) < 0)
        return -1;
    *value = VIR_DIV_UP(tmp, 1024);
    return 0;
}

static bool
cmdMemtune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    long long hard_limit = 0, soft_limit = 0, swap_hard_limit = 0;
    long long min_guarantee = 0;
    int nparams = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    bool ret = false;
    unsigned int flags = 0;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshMemtuneGetSize(cmd, "hard-limit", &hard_limit) < 0 ||
        vshMemtuneGetSize(cmd, "soft-limit", &soft_limit) < 0 ||
        vshMemtuneGetSize(cmd, "swap-hard-limit", &swap_hard_limit) < 0 ||
        vshMemtuneGetSize(cmd, "min-guarantee", &min_guarantee) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    }

    if (hard_limit)
        nparams++;

    if (soft_limit)
        nparams++;

    if (swap_hard_limit)
        nparams++;

    if (min_guarantee)
        nparams++;

    if (nparams == 0) {
        /* get the number of memory parameters */
        if (virDomainGetMemoryParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetMemoryParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get memory parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            if (params[i].type == VIR_TYPED_PARAM_ULLONG &&
                params[i].value.ul == VIR_DOMAIN_MEMORY_PARAM_UNLIMITED) {
                vshPrint(ctl, "%-15s: %s\n", params[i].field, _("unlimited"));
            } else {
                char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
                VIR_FREE(str);
            }
        }

        ret = true;
    } else {
        /* set the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;

            /*
             * Some magic here, this is used to fill the params structure with
             * the valid arguments passed, after filling the particular
             * argument we purposely make them 0, so on the next pass it goes
             * to the next valid argument and so on.
             */
            if (soft_limit) {
                temp->value.ul = soft_limit;
                strncpy(temp->field, VIR_DOMAIN_MEMORY_SOFT_LIMIT,
                        sizeof(temp->field));
                soft_limit = 0;
            } else if (hard_limit) {
                temp->value.ul = hard_limit;
                strncpy(temp->field, VIR_DOMAIN_MEMORY_HARD_LIMIT,
                        sizeof(temp->field));
                hard_limit = 0;
            } else if (swap_hard_limit) {
                temp->value.ul = swap_hard_limit;
                strncpy(temp->field, VIR_DOMAIN_MEMORY_SWAP_HARD_LIMIT,
                        sizeof(temp->field));
                swap_hard_limit = 0;
            } else if (min_guarantee) {
                temp->value.ul = min_guarantee;
                strncpy(temp->field, VIR_DOMAIN_MEMORY_MIN_GUARANTEE,
                        sizeof(temp->field));
                min_guarantee = 0;
            }

            /* If the user has passed -1, we interpret it as unlimited */
            if (temp->value.ul == -1)
                temp->value.ul = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        }
        if (virDomainSetMemoryParameters(dom, params, nparams, flags) != 0)
            vshError(ctl, "%s", _("Unable to change memory parameters"));
        else
            ret = true;
    }

  cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "numatune" command
 */
static const vshCmdInfo info_numatune[] = {
    {"help", N_("Get or set numa parameters")},
    {"desc", N_("Get or set the current numa parameters for a guest" \
                " domain.\n" \
                "    To get the numa parameters use following command: \n\n" \
                "    virsh # numatune <domain>")},
    {NULL, NULL}

};

static const vshCmdOptDef opts_numatune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"mode", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("NUMA mode, one of strict, preferred and interleave")},
    {"nodeset", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("NUMA node selections to set")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNumatune(vshControl * ctl, const vshCmd * cmd)
{
    virDomainPtr dom;
    int nparams = 0;
    unsigned int i = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    const char *nodeset = NULL;
    bool ret = false;
    unsigned int flags = 0;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    const char *mode = NULL;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "nodeset", &nodeset) < 0) {
        vshError(ctl, "%s", _("Unable to parse nodeset."));
        virDomainFree(dom);
        return false;
    }
    if (nodeset)
        nparams++;
    if (vshCommandOptString(cmd, "mode", &mode) < 0) {
        vshError(ctl, "%s", _("Unable to parse mode."));
        virDomainFree(dom);
        return false;
    }
    if (mode)
        nparams++;

    if (nparams == 0) {
        /* get the number of numa parameters */
        if (virDomainGetNumaParameters(dom, NULL, &nparams, flags) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = true;
            goto cleanup;
        }

        /* now go get all the numa parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetNumaParameters(dom, params, &nparams, flags) != 0) {
            vshError(ctl, "%s", _("Unable to get numa parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            if (params[i].type == VIR_TYPED_PARAM_INT &&
                STREQ(params[i].field, VIR_DOMAIN_NUMA_MODE)) {
                vshPrint(ctl, "%-15s: %s\n", params[i].field,
                         virDomainNumatuneMemModeTypeToString(params[i].value.i));
            } else {
                char *str = vshGetTypedParamValue(ctl, &params[i]);
                vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
                VIR_FREE(str);
            }
        }

        ret = true;
    } else {
        /* set the numa parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];

            /*
             * Some magic here, this is used to fill the params structure with
             * the valid arguments passed, after filling the particular
             * argument we purposely make them 0, so on the next pass it goes
             * to the next valid argument and so on.
             */
            if (mode) {
                /* Accept string or integer, in case server
                 * understands newer integer than what strings we were
                 * compiled with */
                if ((temp->value.i =
                    virDomainNumatuneMemModeTypeFromString(mode)) < 0 &&
                    virStrToLong_i(mode, NULL, 0, &temp->value.i) < 0) {
                    vshError(ctl, _("Invalid mode: %s"), mode);
                    goto cleanup;
                }
                if (!virStrcpy(temp->field, VIR_DOMAIN_NUMA_MODE,
                               sizeof(temp->field)))
                    goto cleanup;
                temp->type = VIR_TYPED_PARAM_INT;
                mode = NULL;
            } else if (nodeset) {
                temp->value.s = vshStrdup(ctl, nodeset);
                temp->type = VIR_TYPED_PARAM_STRING;
                if (!virStrcpy(temp->field, VIR_DOMAIN_NUMA_NODESET,
                               sizeof(temp->field)))
                    goto cleanup;
                nodeset = NULL;
            }
        }
        if (virDomainSetNumaParameters(dom, params, nparams, flags) != 0)
            vshError(ctl, "%s", _("Unable to change numa parameters"));
        else
            ret = true;
    }

  cleanup:
    virTypedParameterArrayClear(params, nparams);
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
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
    vshPrint(ctl, "%-20s %lu kB\n", _("Memory size:"), info.memory);

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

    i = 0;
    do {
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

        i++;
        sleep(1);
    } while (i < 2);

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
        vshPrint(ctl, "%-7s: %20llu kB\n", params[i].field, params[i].value);

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
cmdCapabilities (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if ((caps = virConnectGetCapabilities (ctl->conn)) == NULL) {
        vshError(ctl, "%s", _("failed to get capabilities"));
        return false;
    }
    vshPrint (ctl, "%s\n", caps);
    VIR_FREE(caps);

    return true;
}

/*
 * "dumpxml" command
 */
static const vshCmdInfo info_dumpxml[] = {
    {"help", N_("domain information in XML")},
    {"desc", N_("Output the domain information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0, N_("show inactive defined XML")},
    {"security-info", VSH_OT_BOOL, 0, N_("include security sensitive information in XML dump")},
    {"update-cpu", VSH_OT_BOOL, 0, N_("update guest CPU according to host CPU")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    int inactive = vshCommandOptBool(cmd, "inactive");
    int secure = vshCommandOptBool(cmd, "security-info");
    int update = vshCommandOptBool(cmd, "update-cpu");

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;
    if (secure)
        flags |= VIR_DOMAIN_XML_SECURE;
    if (update)
        flags |= VIR_DOMAIN_XML_UPDATE_CPU;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    dump = virDomainGetXMLDesc(dom, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "domxml-from-native" command
 */
static const vshCmdInfo info_domxmlfromnative[] = {
    {"help", N_("Convert native config to domain XML")},
    {"desc", N_("Convert native guest configuration format to domain XML format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmlfromnative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, N_("source config data format")},
    {"config", VSH_OT_DATA, VSH_OFLAG_REQ, N_("config data file to import from")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomXMLFromNative(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = true;
    const char *format = NULL;
    const char *configFile = NULL;
    char *configData;
    char *xmlData;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "format", &format) < 0 ||
        vshCommandOptString(cmd, "config", &configFile) < 0)
        return false;

    if (virFileReadAll(configFile, 1024*1024, &configData) < 0)
        return false;

    xmlData = virConnectDomainXMLFromNative(ctl->conn, format, configData, flags);
    if (xmlData != NULL) {
        vshPrint(ctl, "%s", xmlData);
        VIR_FREE(xmlData);
    } else {
        ret = false;
    }

    VIR_FREE(configData);
    return ret;
}

/*
 * "domxml-to-native" command
 */
static const vshCmdInfo info_domxmltonative[] = {
    {"help", N_("Convert domain XML to native config")},
    {"desc", N_("Convert domain XML config to a native guest configuration format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmltonative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, N_("target config data type format")},
    {"xml", VSH_OT_DATA, VSH_OFLAG_REQ, N_("xml data file to export from")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomXMLToNative(vshControl *ctl, const vshCmd *cmd)
{
    bool ret = true;
    const char *format = NULL;
    const char *xmlFile = NULL;
    char *configData;
    char *xmlData;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "format", &format) < 0
        || vshCommandOptString(cmd, "xml", &xmlFile) < 0)
        return false;

    if (virFileReadAll(xmlFile, 1024*1024, &xmlData) < 0)
        return false;

    configData = virConnectDomainXMLToNative(ctl->conn, format, xmlData, flags);
    if (configData != NULL) {
        vshPrint(ctl, "%s", configData);
        VIR_FREE(configData);
    } else {
        ret = false;
    }

    VIR_FREE(xmlData);
    return ret;
}

/*
 * "domname" command
 */
static const vshCmdInfo info_domname[] = {
    {"help", N_("convert a domain id or UUID to domain name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYID|VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    virDomainFree(dom);
    return true;
}

/*
 * "domid" command
 */
static const vshCmdInfo info_domid[] = {
    {"help", N_("convert a domain name or UUID to domain id")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYUUID)))
        return false;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%s\n", "-");
    else
        vshPrint(ctl, "%d\n", id);
    virDomainFree(dom);
    return true;
}

/*
 * "domuuid" command
 */
static const vshCmdInfo info_domuuid[] = {
    {"help", N_("convert a domain name or id to domain UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domuuid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain id or name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYID)))
        return false;

    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get domain UUID"));

    virDomainFree(dom);
    return true;
}

/*
 * "migrate" command
 */
static const vshCmdInfo info_migrate[] = {
    {"help", N_("migrate domain to another host")},
    {"desc", N_("Migrate domain to another host.  Add --live for live migration.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate[] = {
    {"live", VSH_OT_BOOL, 0, N_("live migration")},
    {"p2p", VSH_OT_BOOL, 0, N_("peer-2-peer migration")},
    {"direct", VSH_OT_BOOL, 0, N_("direct migration")},
    {"tunneled", VSH_OT_ALIAS, 0, "tunnelled"},
    {"tunnelled", VSH_OT_BOOL, 0, N_("tunnelled migration")},
    {"persistent", VSH_OT_BOOL, 0, N_("persist VM on destination")},
    {"undefinesource", VSH_OT_BOOL, 0, N_("undefine VM on source")},
    {"suspend", VSH_OT_BOOL, 0, N_("do not restart the domain on the destination host")},
    {"copy-storage-all", VSH_OT_BOOL, 0, N_("migration with non-shared storage with full disk copy")},
    {"copy-storage-inc", VSH_OT_BOOL, 0, N_("migration with non-shared storage with incremental copy (same base image shared between source and destination)")},
    {"change-protection", VSH_OT_BOOL, 0,
     N_("prevent any configuration changes to domain until migration ends)")},
    {"unsafe", VSH_OT_BOOL, 0, N_("force migration even if it may be unsafe")},
    {"verbose", VSH_OT_BOOL, 0, N_("display the progress of migration")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"desturi", VSH_OT_DATA, VSH_OFLAG_REQ, N_("connection URI of the destination host as seen from the client(normal migration) or source(p2p migration)")},
    {"migrateuri", VSH_OT_DATA, 0, N_("migration URI, usually can be omitted")},
    {"dname", VSH_OT_DATA, 0, N_("rename to new name during migration (if supported)")},
    {"timeout", VSH_OT_INT, 0, N_("force guest to suspend if live migration exceeds timeout (in seconds)")},
    {"xml", VSH_OT_STRING, 0, N_("filename containing updated XML for the target")},
    {NULL, 0, 0, NULL}
};

static void
doMigrate (void *opaque)
{
    char ret = '1';
    virDomainPtr dom = NULL;
    const char *desturi = NULL;
    const char *migrateuri = NULL;
    const char *dname = NULL;
    unsigned int flags = 0;
    vshCtrlData *data = opaque;
    vshControl *ctl = data->ctl;
    const vshCmd *cmd = data->cmd;
    const char *xmlfile = NULL;
    char *xml = NULL;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask) < 0)
        goto out_sig;

    if (!vshConnectionUsability (ctl, ctl->conn))
        goto out;

    if (!(dom = vshCommandOptDomain (ctl, cmd, NULL)))
        goto out;

    if (vshCommandOptString(cmd, "desturi", &desturi) <= 0 ||
        vshCommandOptString(cmd, "migrateuri", &migrateuri) < 0 ||
        vshCommandOptString(cmd, "dname", &dname) < 0) {
        vshError(ctl, "%s", _("missing argument"));
        goto out;
    }

    if (vshCommandOptString(cmd, "xml", &xmlfile) < 0) {
        vshError(ctl, "%s", _("malformed xml argument"));
        goto out;
    }

    if (vshCommandOptBool (cmd, "live"))
        flags |= VIR_MIGRATE_LIVE;
    if (vshCommandOptBool (cmd, "p2p"))
        flags |= VIR_MIGRATE_PEER2PEER;
    if (vshCommandOptBool (cmd, "tunnelled"))
        flags |= VIR_MIGRATE_TUNNELLED;

    if (vshCommandOptBool (cmd, "persistent"))
        flags |= VIR_MIGRATE_PERSIST_DEST;
    if (vshCommandOptBool (cmd, "undefinesource"))
        flags |= VIR_MIGRATE_UNDEFINE_SOURCE;

    if (vshCommandOptBool (cmd, "suspend"))
        flags |= VIR_MIGRATE_PAUSED;

    if (vshCommandOptBool (cmd, "copy-storage-all"))
        flags |= VIR_MIGRATE_NON_SHARED_DISK;

    if (vshCommandOptBool (cmd, "copy-storage-inc"))
        flags |= VIR_MIGRATE_NON_SHARED_INC;

    if (vshCommandOptBool (cmd, "change-protection"))
        flags |= VIR_MIGRATE_CHANGE_PROTECTION;

    if (vshCommandOptBool(cmd, "unsafe"))
        flags |= VIR_MIGRATE_UNSAFE;

    if (xmlfile &&
        virFileReadAll(xmlfile, 8192, &xml) < 0) {
        vshError(ctl, _("file '%s' doesn't exist"), xmlfile);
        goto out;
    }

    if ((flags & VIR_MIGRATE_PEER2PEER) ||
        vshCommandOptBool (cmd, "direct")) {
        /* For peer2peer migration or direct migration we only expect one URI
         * a libvirt URI, or a hypervisor specific URI. */

        if (migrateuri != NULL) {
            vshError(ctl, "%s", _("migrate: Unexpected migrateuri for peer2peer/direct migration"));
            goto out;
        }

        if (virDomainMigrateToURI2(dom, desturi, NULL, xml, flags, dname, 0) == 0)
            ret = '0';
    } else {
        /* For traditional live migration, connect to the destination host directly. */
        virConnectPtr dconn = NULL;
        virDomainPtr ddom = NULL;

        dconn = virConnectOpenAuth (desturi, virConnectAuthPtrDefault, 0);
        if (!dconn) goto out;

        ddom = virDomainMigrate2(dom, dconn, xml, flags, dname, migrateuri, 0);
        if (ddom) {
            virDomainFree(ddom);
            ret = '0';
        }
        virConnectClose (dconn);
    }

out:
    pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
out_sig:
    if (dom) virDomainFree (dom);
    VIR_FREE(xml);
    ignore_value(safewrite(data->writefd, &ret, sizeof(ret)));
}

static void
print_job_progress(const char *label, unsigned long long remaining,
                   unsigned long long total)
{
    int progress;

    if (total == 0)
        /* migration has not been started */
        return;

    if (remaining == 0) {
        /* migration has completed */
        progress = 100;
    } else {
        /* use float to avoid overflow */
        progress = (int)(100.0 - remaining * 100.0 / total);
        if (progress >= 100) {
            /* migration has not completed, do not print [100 %] */
            progress = 99;
        }
    }

    /* see comments in vshError about why we must flush */
    fflush(stdout);
    fprintf(stderr, "\r%s: [%3d %%]", label, progress);
    fflush(stderr);
}

static void
vshMigrationTimeout(vshControl *ctl,
                    virDomainPtr dom,
                    void *opaque ATTRIBUTE_UNUSED)
{
    vshDebug(ctl, VSH_ERR_DEBUG, "suspending the domain, "
             "since migration timed out\n");
    virDomainSuspend(dom);
}

static bool
vshWatchJob(vshControl *ctl,
            virDomainPtr dom,
            bool verbose,
            int pipe_fd,
            int timeout,
            jobWatchTimeoutFunc timeout_func,
            void *opaque,
            const char *label)
{
    struct sigaction sig_action;
    struct sigaction old_sig_action;
    struct pollfd pollfd;
    struct timeval start, curr;
    virDomainJobInfo jobinfo;
    int ret = -1;
    char retchar;
    bool functionReturn = false;
    sigset_t sigmask, oldsigmask;

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGINT);

    intCaught = 0;
    sig_action.sa_sigaction = vshCatchInt;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);
    sigaction(SIGINT, &sig_action, &old_sig_action);

    pollfd.fd = pipe_fd;
    pollfd.events = POLLIN;
    pollfd.revents = 0;

    GETTIMEOFDAY(&start);
    while (1) {
repoll:
        ret = poll(&pollfd, 1, 500);
        if (ret > 0) {
            if (pollfd.revents & POLLIN &&
                saferead(pipe_fd, &retchar, sizeof(retchar)) > 0 &&
                retchar == '0') {
                    if (verbose) {
                        /* print [100 %] */
                        print_job_progress(label, 0, 1);
                    }
                    break;
            }
            goto cleanup;
        }

        if (ret < 0) {
            if (errno == EINTR) {
                if (intCaught) {
                    virDomainAbortJob(dom);
                    intCaught = 0;
                } else
                    goto repoll;
            }
            goto cleanup;
        }

        GETTIMEOFDAY(&curr);
        if ( timeout && ((int)(curr.tv_sec - start.tv_sec)  * 1000 + \
                         (int)(curr.tv_usec - start.tv_usec) / 1000) > timeout * 1000 ) {
            /* suspend the domain when migration timeouts. */
            vshDebug(ctl, VSH_ERR_DEBUG, "%s timeout", label);
            if (timeout_func)
                (timeout_func)(ctl, dom, opaque);
            timeout = 0;
        }

        if (verbose) {
            pthread_sigmask(SIG_BLOCK, &sigmask, &oldsigmask);
            ret = virDomainGetJobInfo(dom, &jobinfo);
            pthread_sigmask(SIG_SETMASK, &oldsigmask, NULL);
            if (ret == 0)
                print_job_progress(label, jobinfo.dataRemaining,
                                   jobinfo.dataTotal);
        }
    }

    functionReturn = true;

cleanup:
    sigaction(SIGINT, &old_sig_action, NULL);
    return functionReturn;
}

static bool
cmdMigrate (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int p[2] = {-1, -1};
    virThread workerThread;
    bool verbose = false;
    bool functionReturn = false;
    int timeout = 0;
    bool live_flag = false;
    vshCtrlData data;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptBool (cmd, "verbose"))
        verbose = true;

    if (vshCommandOptBool (cmd, "live"))
        live_flag = true;
    if (vshCommandOptInt(cmd, "timeout", &timeout) > 0) {
        if (! live_flag) {
            vshError(ctl, "%s", _("migrate: Unexpected timeout for offline migration"));
            goto cleanup;
        }

        if (timeout < 1) {
            vshError(ctl, "%s", _("migrate: Invalid timeout"));
            goto cleanup;
        }

        /* Ensure that we can multiply by 1000 without overflowing. */
        if (timeout > INT_MAX / 1000) {
            vshError(ctl, "%s", _("migrate: Timeout is too big"));
            goto cleanup;
        }
    }

    if (pipe(p) < 0)
        goto cleanup;

    data.ctl = ctl;
    data.cmd = cmd;
    data.writefd = p[1];

    if (virThreadCreate(&workerThread,
                        true,
                        doMigrate,
                        &data) < 0)
        goto cleanup;
    functionReturn = vshWatchJob(ctl, dom, verbose, p[0], timeout,
                                 vshMigrationTimeout, NULL, _("Migration"));

    virThreadJoin(&workerThread);

cleanup:
    virDomainFree(dom);
    VIR_FORCE_CLOSE(p[0]);
    VIR_FORCE_CLOSE(p[1]);
    return functionReturn;
}

/*
 * "migrate-setmaxdowntime" command
 */
static const vshCmdInfo info_migrate_setmaxdowntime[] = {
    {"help", N_("set maximum tolerable downtime")},
    {"desc", N_("Set maximum tolerable downtime of a domain which is being live-migrated to another host.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_setmaxdowntime[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"downtime", VSH_OT_INT, VSH_OFLAG_REQ, N_("maximum tolerable downtime (in milliseconds) for migration")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateSetMaxDowntime(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    long long downtime = 0;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptLongLong(cmd, "downtime", &downtime) < 0 ||
        downtime < 1) {
        vshError(ctl, "%s", _("migrate: Invalid downtime"));
        goto done;
    }

    if (virDomainMigrateSetMaxDowntime(dom, downtime, 0))
        goto done;

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

/*
 * "migrate-setspeed" command
 */
static const vshCmdInfo info_migrate_setspeed[] = {
    {"help", N_("Set the maximum migration bandwidth")},
    {"desc", N_("Set the maximum migration bandwidth (in Mbps) for a domain "
                "which is being migrated to another host.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_setspeed[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"bandwidth", VSH_OT_INT, VSH_OFLAG_REQ, N_("migration bandwidth limit in Mbps")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateSetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth = 0;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptUL(cmd, "bandwidth", &bandwidth) < 0) {
        vshError(ctl, "%s", _("migrate: Invalid bandwidth"));
        goto done;
    }

    if (virDomainMigrateSetMaxSpeed(dom, bandwidth, 0) < 0)
        goto done;

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

/*
 * "migrate-getspeed" command
 */
static const vshCmdInfo info_migrate_getspeed[] = {
    {"help", N_("Get the maximum migration bandwidth")},
    {"desc", N_("Get the maximum migration bandwidth (in Mbps) for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate_getspeed[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdMigrateGetMaxSpeed(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    unsigned long bandwidth;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainMigrateGetMaxSpeed(dom, &bandwidth, 0) < 0)
        goto done;

    vshPrint(ctl, "%lu\n", bandwidth);

    ret = true;

done:
    virDomainFree(dom);
    return ret;
}

typedef enum {
    VSH_CMD_BLOCK_JOB_ABORT = 0,
    VSH_CMD_BLOCK_JOB_INFO = 1,
    VSH_CMD_BLOCK_JOB_SPEED = 2,
    VSH_CMD_BLOCK_JOB_PULL = 3,
} VSH_CMD_BLOCK_JOB_MODE;

static int
blockJobImpl(vshControl *ctl, const vshCmd *cmd,
              virDomainBlockJobInfoPtr info, int mode)
{
    virDomainPtr dom = NULL;
    const char *name, *path;
    unsigned long bandwidth = 0;
    int ret = -1;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (vshCommandOptString(cmd, "path", &path) < 0)
        goto cleanup;

    if (vshCommandOptUL(cmd, "bandwidth", &bandwidth) < 0) {
        vshError(ctl, "%s", _("bandwidth must be a number"));
        goto cleanup;
    }

    if (mode == VSH_CMD_BLOCK_JOB_ABORT) {
        ret = virDomainBlockJobAbort(dom, path, 0);
    } else if (mode == VSH_CMD_BLOCK_JOB_INFO) {
        ret = virDomainGetBlockJobInfo(dom, path, info, 0);
    } else if (mode == VSH_CMD_BLOCK_JOB_SPEED) {
        ret = virDomainBlockJobSetSpeed(dom, path, bandwidth, 0);
    } else if (mode == VSH_CMD_BLOCK_JOB_PULL) {
        const char *base = NULL;
        if (vshCommandOptString(cmd, "base", &base) < 0)
            goto cleanup;
        if (base)
            ret = virDomainBlockRebase(dom, path, base, bandwidth, 0);
        else
            ret = virDomainBlockPull(dom, path, bandwidth, 0);
    }

cleanup:
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "blockpull" command
 */
static const vshCmdInfo info_block_pull[] = {
    {"help", N_("Populate a disk from its backing image.")},
    {"desc", N_("Populate a disk from its backing image.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_pull[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("Fully-qualified path of disk")},
    {"bandwidth", VSH_OT_DATA, VSH_OFLAG_NONE, N_("Bandwidth limit in MB/s")},
    {"base", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("path of backing file in chain for a partial pull")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockPull(vshControl *ctl, const vshCmd *cmd)
{
    if (blockJobImpl(ctl, cmd, NULL, VSH_CMD_BLOCK_JOB_PULL) != 0)
        return false;
    return true;
}

/*
 * "blockjobinfo" command
 */
static const vshCmdInfo info_block_job[] = {
    {"help", N_("Manage active block operations.")},
    {"desc", N_("Manage active block operations.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_job[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("Fully-qualified path of disk")},
    {"abort", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("Abort the active job on the specified disk")},
    {"info", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("Get active job information for the specified disk")},
    {"bandwidth", VSH_OT_DATA, VSH_OFLAG_NONE, N_("Set the Bandwidth limit in MB/s")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockJob(vshControl *ctl, const vshCmd *cmd)
{
    int mode;
    virDomainBlockJobInfo info;
    const char *type;
    int ret;

    if (vshCommandOptBool (cmd, "abort")) {
        mode = VSH_CMD_BLOCK_JOB_ABORT;
    } else if (vshCommandOptBool (cmd, "info")) {
        mode = VSH_CMD_BLOCK_JOB_INFO;
    } else if (vshCommandOptBool (cmd, "bandwidth")) {
        mode = VSH_CMD_BLOCK_JOB_SPEED;
    } else {
        vshError(ctl, "%s",
                 _("One of --abort, --info, or --bandwidth is required"));
        return false;
    }

    ret = blockJobImpl(ctl, cmd, &info, mode);
    if (ret < 0)
        return false;

    if (ret == 0 || mode != VSH_CMD_BLOCK_JOB_INFO)
        return true;

    if (info.type == VIR_DOMAIN_BLOCK_JOB_TYPE_PULL)
        type = "Block Pull";
    else
        type = "Unknown job";

    print_job_progress(type, info.end - info.cur, info.end);
    if (info.bandwidth != 0)
        vshPrint(ctl, "    Bandwidth limit: %lu MB/s\n", info.bandwidth);
    return true;
}

/*
 * "blockresize" command
 */
static const vshCmdInfo info_block_resize[] = {
    {"help", N_("Resize block device of domain.")},
    {"desc", N_("Resize block device of domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_block_resize[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("Fully-qualified path of block device")},
    {"size", VSH_OT_INT, VSH_OFLAG_REQ,
     N_("New size of the block device, as scaled integer (default KiB)")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlockResize(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *path = NULL;
    unsigned long long size = 0;
    unsigned int flags = 0;
    int ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "path", (const char **) &path) < 0) {
        vshError(ctl, "%s", _("Path must not be empty"));
        return false;
    }

    if (vshCommandOptScaledInt(cmd, "size", &size, 1024, ULLONG_MAX) < 0) {
        vshError(ctl, "%s", _("Unable to parse integer"));
        return false;
    }

    /* Prefer the older interface of KiB.  */
    if (size % 1024 == 0)
        size /= 1024;
    else
        flags |= VIR_DOMAIN_BLOCK_RESIZE_BYTES;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (virDomainBlockResize(dom, path, size, flags) < 0) {
        vshError(ctl, _("Failed to resize block device '%s'"), path);
    } else {
        vshPrint(ctl, _("Block device '%s' is resized"), path);
        ret = true;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "net-autostart" command
 */
static const vshCmdInfo info_network_autostart[] = {
    {"help", N_("autostart a network")},
    {"desc",
     N_("Configure a network to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_autostart[] = {
    {"network",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {"disable", VSH_OT_BOOL, 0, N_("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virNetworkSetAutostart(network, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark network %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark network %s as autostarted"), name);
        virNetworkFree(network);
        return false;
    }

    if (autostart)
        vshPrint(ctl, _("Network %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Network %s unmarked as autostarted\n"), name);

    virNetworkFree(network);
    return true;
}

/*
 * "blkdeviotune" command
 */
static const vshCmdInfo info_blkdeviotune[] = {
    {"help", N_("Set or query a block device I/O tuning parameters.")},
    {"desc", N_("Set or query disk I/O parameters such as block throttling.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_blkdeviotune[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {"total_bytes_sec", VSH_OT_ALIAS, 0, "total-bytes-sec"},
    {"total-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("total throughput limit in bytes per second")},
    {"read_bytes_sec", VSH_OT_ALIAS, 0, "read-bytes-sec"},
    {"read-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("read throughput limit in bytes per second")},
    {"write_bytes_sec", VSH_OT_ALIAS, 0, "write-bytes-sec"},
    {"write-bytes-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("write throughput limit in bytes per second")},
    {"total_iops_sec", VSH_OT_ALIAS, 0, "total-iops-sec"},
    {"total-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("total I/O operations limit per second")},
    {"read_iops_sec", VSH_OT_ALIAS, 0, "read-iops-sec"},
    {"read-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("read I/O operations limit per second")},
    {"write_iops_sec", VSH_OT_ALIAS, 0, "write-iops-sec"},
    {"write-iops-sec", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("write I/O operations limit per second")},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"live", VSH_OT_BOOL, 0, N_("affect running domain")},
    {"current", VSH_OT_BOOL, 0, N_("affect current domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdBlkdeviotune(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *name, *disk;
    unsigned long long total_bytes_sec = 0, read_bytes_sec = 0, write_bytes_sec = 0;
    unsigned long long total_iops_sec = 0, read_iops_sec = 0, write_iops_sec = 0;
    int nparams = 0;
    virTypedParameterPtr params = NULL, temp = NULL;
    unsigned int flags = 0, i = 0;
    int rv = 0;
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    bool ret = false;

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        goto cleanup;

    if (vshCommandOptString(cmd, "device", &disk) < 0)
        goto cleanup;

    if ((rv = vshCommandOptULongLong(cmd, "total-bytes-sec",
                                     &total_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "read-bytes-sec",
                                     &read_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "write-bytes-sec",
                                     &write_bytes_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "total-iops-sec",
                                     &total_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "read-iops-sec",
                                     &read_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if ((rv = vshCommandOptULongLong(cmd, "write-iops-sec",
                                     &write_iops_sec)) < 0) {
        vshError(ctl, "%s",
                 _("Unable to parse integer parameter"));
        goto cleanup;
    } else if (rv > 0) {
        nparams++;
    }

    if (nparams == 0) {

        if ((virDomainGetBlockIoTune(dom, NULL, NULL, &nparams, flags)) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of block I/O throttle parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            ret = true;
            goto cleanup;
        }

        params = vshCalloc(ctl, nparams, sizeof(*params));

        if ((virDomainGetBlockIoTune(dom, disk, params, &nparams, flags)) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get block I/O throttle parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            char *str = vshGetTypedParamValue(ctl, &params[i]);
            vshPrint(ctl, "%-15s: %s\n", params[i].field, str);
            VIR_FREE(str);
        }

        ret = true;
        goto cleanup;
    } else {
        /* Set the block I/O throttle, match by opt since parameters can be 0 */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        i = 0;

        if ((i < nparams) && (vshCommandOptBool(cmd, "total-bytes-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_BYTES_SEC,
                    sizeof(temp->field));
            temp->value.ul = total_bytes_sec;
            i++;
        }

        if ((i < nparams) && (vshCommandOptBool(cmd, "read-bytes-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_READ_BYTES_SEC,
                    sizeof(temp->field));
            temp->value.ul = read_bytes_sec;
            i++;
        }

        if ((i < nparams) && (vshCommandOptBool(cmd, "write-bytes-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_WRITE_BYTES_SEC,
                    sizeof(temp->field));
            temp->value.ul = write_bytes_sec;
            i++;
        }

        if ((i < nparams) && (vshCommandOptBool(cmd, "total-iops-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_TOTAL_IOPS_SEC,
                    sizeof(temp->field));
            temp->value.ul = total_iops_sec;
            i++;
        }

        if ((i < nparams) && (vshCommandOptBool(cmd, "read-iops-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_READ_IOPS_SEC,
                    sizeof(temp->field));
            temp->value.ul = read_iops_sec;
            i++;
        }

        if ((i < nparams) && (vshCommandOptBool(cmd, "write-iops-sec"))) {
            temp = &params[i];
            temp->type = VIR_TYPED_PARAM_ULLONG;
            strncpy(temp->field, VIR_DOMAIN_BLOCK_IOTUNE_WRITE_IOPS_SEC,
                    sizeof(temp->field));
            temp->value.ul = write_iops_sec;
        }

        if ((virDomainSetBlockIoTune(dom, disk, params, nparams, flags)) < 0) {
            vshError(ctl, "%s",
                     _("Unable to change block I/O throttle"));
            goto cleanup;
        }
    }

    ret = true;

cleanup:
    VIR_FREE(params);
    virDomainFree(dom);
    return ret;
}

/*
 * "net-create" command
 */
static const vshCmdInfo info_network_create[] = {
    {"help", N_("create a network from an XML file")},
    {"desc", N_("Create a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    network = virNetworkCreateXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s created from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to create network from %s"), from);
        ret = false;
    }
    return ret;
}


/*
 * "net-define" command
 */
static const vshCmdInfo info_network_define[] = {
    {"help", N_("define (but don't start) a network from an XML file")},
    {"desc", N_("Define a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML network description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    network = virNetworkDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s defined from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to define network from %s"), from);
        ret = false;
    }
    return ret;
}


/*
 * "net-destroy" command
 */
static const vshCmdInfo info_network_destroy[] = {
    {"help", N_("destroy (stop) a network")},
    {"desc", N_("Forcefully stop a given network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_destroy[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkDestroy(network) == 0) {
        vshPrint(ctl, _("Network %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy network %s"), name);
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}


/*
 * "net-dumpxml" command
 */
static const vshCmdInfo info_network_dumpxml[] = {
    {"help", N_("network information in XML")},
    {"desc", N_("Output the network information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_dumpxml[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {"inactive", VSH_OT_BOOL, VSH_OFLAG_NONE, N_("network information of an inactive domain")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    char *dump;
    unsigned int flags = 0;
    int inactive;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return false;

    inactive = vshCommandOptBool (cmd, "inactive");
    if (inactive)
        flags |= VIR_NETWORK_XML_INACTIVE;

    dump = virNetworkGetXMLDesc(network, flags);

    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}

/*
 * "net-info" command
 */
static const vshCmdInfo info_network_info[] = {
    {"help", N_("network information")},
    {"desc", N_("Returns basic information about the network")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_info[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkInfo(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int autostart;
    int persistent = -1;
    int active = -1;
    char *bridge = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name"), virNetworkGetName(network));

    if (virNetworkGetUUIDString(network, uuid) == 0)
        vshPrint(ctl, "%-15s %s\n", _("UUID"), uuid);

    active = virNetworkIsActive(network);
    if (active >= 0)
        vshPrint(ctl, "%-15s %s\n", _("Active:"), active? _("yes") : _("no"));

    persistent = virNetworkIsPersistent(network);
    if (persistent < 0)
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

    if (virNetworkGetAutostart(network, &autostart) < 0)
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"), _("no autostart"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"), autostart ? _("yes") : _("no"));

    bridge = virNetworkGetBridgeName(network);
    if (bridge)
        vshPrint(ctl, "%-15s %s\n", _("Bridge:"), bridge);

    VIR_FREE(bridge);
    virNetworkFree(network);
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
cmdInterfaceEdit (vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virInterfacePtr iface = NULL;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;
    unsigned int flags = VIR_INTERFACE_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    iface = vshCommandOptInterface (ctl, cmd, NULL);
    if (iface == NULL)
        goto cleanup;

    /* Get the XML configuration of the interface. */
    doc = virInterfaceGetXMLDesc (iface, flags);
    if (!doc)
        goto cleanup;

    /* Create and open the temporary file. */
    tmp = editWriteToTempFile (ctl, doc);
    if (!tmp) goto cleanup;

    /* Start the editor. */
    if (editFile (ctl, tmp) == -1) goto cleanup;

    /* Read back the edited file. */
    doc_edited = editReadBackFile (ctl, tmp);
    if (!doc_edited) goto cleanup;

    /* Compare original XML with edited.  Has it changed at all? */
    if (STREQ (doc, doc_edited)) {
        vshPrint (ctl, _("Interface %s XML configuration not changed.\n"),
                  virInterfaceGetName (iface));
        ret = true;
        goto cleanup;
    }

    /* Now re-read the interface XML.  Did someone else change it while
     * it was being edited?  This also catches problems such as us
     * losing a connection or the interface going away.
     */
    doc_reread = virInterfaceGetXMLDesc (iface, flags);
    if (!doc_reread)
        goto cleanup;

    if (STRNEQ (doc, doc_reread)) {
        vshError(ctl, "%s",
                 _("ERROR: the XML configuration was changed by another user"));
        goto cleanup;
    }

    /* Everything checks out, so redefine the interface. */
    virInterfaceFree (iface);
    iface = virInterfaceDefineXML (ctl->conn, doc_edited, 0);
    if (!iface)
        goto cleanup;

    vshPrint (ctl, _("Interface %s XML configuration edited.\n"),
              virInterfaceGetName(iface));

    ret = true;

cleanup:
    if (iface)
        virInterfaceFree (iface);

    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    VIR_FREE(doc_reread);

    if (tmp) {
        unlink (tmp);
        VIR_FREE(tmp);
    }

    return ret;
}

/*
 * "net-list" command
 */
static const vshCmdInfo info_network_list[] = {
    {"help", N_("list networks")},
    {"desc", N_("Returns list of networks.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive networks")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active networks")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (active) {
        maxactive = virConnectNumOfNetworks(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active networks"));
            return false;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListNetworks(ctl->conn, activeNames,
                                                    maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active networks"));
                VIR_FREE(activeNames);
                return false;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedNetworks(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive networks"));
            VIR_FREE(activeNames);
            return false;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive =
                     virConnectListDefinedNetworks(ctl->conn, inactiveNames,
                                                   maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive networks"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return false;
            }

            qsort(&inactiveNames[0], maxinactive, sizeof(char*), namesorter);
        }
    }
    vshPrintExtra(ctl, "%-20s %-10s %s\n", _("Name"), _("State"),
                  _("Autostart"));
    vshPrintExtra(ctl, "-----------------------------------------\n");

    for (i = 0; i < maxactive; i++) {
        virNetworkPtr network =
            virNetworkLookupByName(ctl->conn, activeNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with networks is not atomic operation */
        if (!network) {
            VIR_FREE(activeNames[i]);
            continue;
        }

        if (virNetworkGetAutostart(network, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? _("yes") : _("no");

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 virNetworkGetName(network),
                 _("active"),
                 autostartStr);
        virNetworkFree(network);
        VIR_FREE(activeNames[i]);
    }
    for (i = 0; i < maxinactive; i++) {
        virNetworkPtr network = virNetworkLookupByName(ctl->conn, inactiveNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with networks is not atomic operation */
        if (!network) {
            VIR_FREE(inactiveNames[i]);
            continue;
        }

        if (virNetworkGetAutostart(network, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? _("yes") : _("no");

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 inactiveNames[i],
                 _("inactive"),
                 autostartStr);

        virNetworkFree(network);
        VIR_FREE(inactiveNames[i]);
    }
    VIR_FREE(activeNames);
    VIR_FREE(inactiveNames);
    return true;
}


/*
 * "net-name" command
 */
static const vshCmdInfo info_network_name[] = {
    {"help", N_("convert a network UUID to network name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_name[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virNetworkGetName(network));
    virNetworkFree(network);
    return true;
}


/*
 * "net-start" command
 */
static const vshCmdInfo info_network_start[] = {
    {"help", N_("start a (previously defined) inactive network")},
    {"desc", N_("Start a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_start[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the inactive network")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL, VSH_BYNAME)))
         return false;

    if (virNetworkCreate(network) == 0) {
        vshPrint(ctl, _("Network %s started\n"),
                 virNetworkGetName(network));
    } else {
        vshError(ctl, _("Failed to start network %s"),
                 virNetworkGetName(network));
        ret = false;
    }
    virNetworkFree(network);
    return ret;
}


/*
 * "net-undefine" command
 */
static const vshCmdInfo info_network_undefine[] = {
    {"help", N_("undefine an inactive network")},
    {"desc", N_("Undefine the configuration for an inactive network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_undefine[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return false;

    if (virNetworkUndefine(network) == 0) {
        vshPrint(ctl, _("Network %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network %s"), name);
        ret = false;
    }

    virNetworkFree(network);
    return ret;
}


/*
 * "net-uuid" command
 */
static const vshCmdInfo info_network_uuid[] = {
    {"help", N_("convert a network name to network UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_uuid[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return false;

    if (virNetworkGetUUIDString(network, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get network UUID"));

    virNetworkFree(network);
    return true;
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
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
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

            qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
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

            qsort(&inactiveNames[0], maxinactive, sizeof(char*), namesorter);
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
    int inactive = vshCommandOptBool(cmd, "inactive");

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
        virInterfaceFree (iface);
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

    qsort(&names[0], numfilters, sizeof(char *), namesorter);

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
cmdNWFilterEdit (vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virNWFilterPtr nwfilter = NULL;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    nwfilter = vshCommandOptNWFilter (ctl, cmd, NULL);
    if (nwfilter == NULL)
        goto cleanup;

    /* Get the XML configuration of the interface. */
    doc = virNWFilterGetXMLDesc (nwfilter, 0);
    if (!doc)
        goto cleanup;

    /* Create and open the temporary file. */
    tmp = editWriteToTempFile (ctl, doc);
    if (!tmp) goto cleanup;

    /* Start the editor. */
    if (editFile (ctl, tmp) == -1) goto cleanup;

    /* Read back the edited file. */
    doc_edited = editReadBackFile (ctl, tmp);
    if (!doc_edited) goto cleanup;

    /* Compare original XML with edited.  Has it changed at all? */
    if (STREQ (doc, doc_edited)) {
        vshPrint (ctl, _("Network filter %s XML configuration not changed.\n"),
                  virNWFilterGetName (nwfilter));
        ret = true;
        goto cleanup;
    }

    /* Now re-read the network filter XML.  Did someone else change it while
     * it was being edited?  This also catches problems such as us
     * losing a connection or the interface going away.
     */
    doc_reread = virNWFilterGetXMLDesc (nwfilter, 0);
    if (!doc_reread)
        goto cleanup;

    if (STRNEQ (doc, doc_reread)) {
        vshError(ctl, "%s",
                 _("ERROR: the XML configuration was changed by another user"));
        goto cleanup;
    }

    /* Everything checks out, so redefine the interface. */
    virNWFilterFree (nwfilter);
    nwfilter = virNWFilterDefineXML (ctl->conn, doc_edited);
    if (!nwfilter)
        goto cleanup;

    vshPrint (ctl, _("Network filter %s XML configuration edited.\n"),
              virNWFilterGetName(nwfilter));

    ret = true;

cleanup:
    if (nwfilter)
        virNWFilterFree (nwfilter);

    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    VIR_FREE(doc_reread);

    if (tmp) {
        unlink (tmp);
        VIR_FREE(tmp);
    }

    return ret;
}


/**************************************************************************/
/*
 * "pool-autostart" command
 */
static const vshCmdInfo info_pool_autostart[] = {
    {"help", N_("autostart a pool")},
    {"desc",
     N_("Configure a pool to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_autostart[] = {
    {"pool",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {"disable", VSH_OT_BOOL, 0, N_("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virStoragePoolSetAutostart(pool, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark pool %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark pool %s as autostarted"), name);
        virStoragePoolFree(pool);
        return false;
    }

    if (autostart)
        vshPrint(ctl, _("Pool %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Pool %s unmarked as autostarted\n"), name);

    virStoragePoolFree(pool);
    return true;
}

/*
 * "pool-create" command
 */
static const vshCmdInfo info_pool_create[] = {
    {"help", N_("create a pool from an XML file")},
    {"desc", N_("Create a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("file containing an XML pool description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    pool = virStoragePoolCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrint(ctl, _("Pool %s created from %s\n"),
                 virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to create pool from %s"), from);
        ret = false;
    }
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
 * XML Building helper for pool-define-as and pool-create-as
 */
static const vshCmdOptDef opts_pool_X_as[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the pool")},
    {"print-xml", VSH_OT_BOOL, 0, N_("print XML document, but don't define/create")},
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ, N_("type of the pool")},
    {"source-host", VSH_OT_DATA, 0, N_("source-host for underlying storage")},
    {"source-path", VSH_OT_DATA, 0, N_("source path for underlying storage")},
    {"source-dev", VSH_OT_DATA, 0, N_("source device for underlying storage")},
    {"source-name", VSH_OT_DATA, 0, N_("source name for underlying storage")},
    {"target", VSH_OT_DATA, 0, N_("target for underlying storage")},
    {"source-format", VSH_OT_STRING, 0, N_("format for underlying storage")},
    {NULL, 0, 0, NULL}
};

static int buildPoolXML(const vshCmd *cmd, const char **retname, char **xml) {

    const char *name = NULL, *type = NULL, *srcHost = NULL, *srcPath = NULL,
               *srcDev = NULL, *srcName = NULL, *srcFormat = NULL, *target = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (vshCommandOptString(cmd, "name", &name) <= 0)
        goto cleanup;
    if (vshCommandOptString(cmd, "type", &type) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "source-host", &srcHost) < 0 ||
        vshCommandOptString(cmd, "source-path", &srcPath) < 0 ||
        vshCommandOptString(cmd, "source-dev", &srcDev) < 0 ||
        vshCommandOptString(cmd, "source-name", &srcName) < 0 ||
        vshCommandOptString(cmd, "source-format", &srcFormat) < 0 ||
        vshCommandOptString(cmd, "target", &target) < 0) {
        vshError(NULL, "%s", _("missing argument"));
        goto cleanup;
    }

    virBufferAsprintf(&buf, "<pool type='%s'>\n", type);
    virBufferAsprintf(&buf, "  <name>%s</name>\n", name);
    if (srcHost || srcPath || srcDev || srcFormat || srcName) {
        virBufferAddLit(&buf, "  <source>\n");

        if (srcHost)
            virBufferAsprintf(&buf, "    <host name='%s'/>\n", srcHost);
        if (srcPath)
            virBufferAsprintf(&buf, "    <dir path='%s'/>\n", srcPath);
        if (srcDev)
            virBufferAsprintf(&buf, "    <device path='%s'/>\n", srcDev);
        if (srcFormat)
            virBufferAsprintf(&buf, "    <format type='%s'/>\n", srcFormat);
        if (srcName)
            virBufferAsprintf(&buf, "    <name>%s</name>\n", srcName);

        virBufferAddLit(&buf, "  </source>\n");
    }
    if (target) {
        virBufferAddLit(&buf, "  <target>\n");
        virBufferAsprintf(&buf, "    <path>%s</path>\n", target);
        virBufferAddLit(&buf, "  </target>\n");
    }
    virBufferAddLit(&buf, "</pool>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }

    *xml = virBufferContentAndReset(&buf);
    *retname = name;
    return true;

cleanup:
    virBufferFreeAndReset(&buf);
    return false;
}

/*
 * "pool-create-as" command
 */
static const vshCmdInfo info_pool_create_as[] = {
    {"help", N_("create a pool from a set of args")},
    {"desc", N_("Create a pool.")},
    {NULL, NULL}
};

static bool
cmdPoolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    char *xml;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!buildPoolXML(cmd, &name, &xml))
        return false;

    if (printXML) {
        vshPrint(ctl, "%s", xml);
        VIR_FREE(xml);
    } else {
        pool = virStoragePoolCreateXML(ctl->conn, xml, 0);
        VIR_FREE(xml);

        if (pool != NULL) {
            vshPrint(ctl, _("Pool %s created\n"), name);
            virStoragePoolFree(pool);
        } else {
            vshError(ctl, _("Failed to create pool %s"), name);
            return false;
        }
    }
    return true;
}


/*
 * "pool-define" command
 */
static const vshCmdInfo info_pool_define[] = {
    {"help", N_("define (but don't start) a pool from an XML file")},
    {"desc", N_("Define a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML pool description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    pool = virStoragePoolDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrint(ctl, _("Pool %s defined from %s\n"),
                 virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to define pool from %s"), from);
        ret = false;
    }
    return ret;
}


/*
 * "pool-define-as" command
 */
static const vshCmdInfo info_pool_define_as[] = {
    {"help", N_("define a pool from a set of args")},
    {"desc", N_("Define a pool.")},
    {NULL, NULL}
};

static bool
cmdPoolDefineAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    const char *name;
    char *xml;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!buildPoolXML(cmd, &name, &xml))
        return false;

    if (printXML) {
        vshPrint(ctl, "%s", xml);
        VIR_FREE(xml);
    } else {
        pool = virStoragePoolDefineXML(ctl->conn, xml, 0);
        VIR_FREE(xml);

        if (pool != NULL) {
            vshPrint(ctl, _("Pool %s defined\n"), name);
            virStoragePoolFree(pool);
        } else {
            vshError(ctl, _("Failed to define pool %s"), name);
            return false;
        }
    }
    return true;
}


/*
 * "pool-build" command
 */
static const vshCmdInfo info_pool_build[] = {
    {"help", N_("build a pool")},
    {"desc", N_("Build a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_build[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {"no-overwrite", VSH_OT_BOOL, 0, N_("do not overwrite an existing pool of this type")},
    {"overwrite", VSH_OT_BOOL, 0, N_("overwrite any existing data")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolBuild(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (vshCommandOptBool (cmd, "no-overwrite")) {
        flags |= VIR_STORAGE_POOL_BUILD_NO_OVERWRITE;
    }

    if (vshCommandOptBool (cmd, "overwrite")) {
        flags |= VIR_STORAGE_POOL_BUILD_OVERWRITE;
    }

    if (virStoragePoolBuild(pool, flags) == 0) {
        vshPrint(ctl, _("Pool %s built\n"), name);
    } else {
        vshError(ctl, _("Failed to build pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);

    return ret;
}

/*
 * "pool-destroy" command
 */
static const vshCmdInfo info_pool_destroy[] = {
    {"help", N_("destroy (stop) a pool")},
    {"desc",
     N_("Forcefully stop a given pool. Raw data in the pool is untouched")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_destroy[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolDestroy(pool) == 0) {
        vshPrint(ctl, _("Pool %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-delete" command
 */
static const vshCmdInfo info_pool_delete[] = {
    {"help", N_("delete a pool")},
    {"desc", N_("Delete a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_delete[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolDelete(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-refresh" command
 */
static const vshCmdInfo info_pool_refresh[] = {
    {"help", N_("refresh a pool")},
    {"desc", N_("Refresh a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_refresh[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolRefresh(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolRefresh(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s refreshed\n"), name);
    } else {
        vshError(ctl, _("Failed to refresh pool %s"), name);
        ret = false;
    }
    virStoragePoolFree(pool);

    return ret;
}


/*
 * "pool-dumpxml" command
 */
static const vshCmdInfo info_pool_dumpxml[] = {
    {"help", N_("pool information in XML")},
    {"desc", N_("Output the pool information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_dumpxml[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    dump = virStoragePoolGetXMLDesc(pool, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-list" command
 */
static const vshCmdInfo info_pool_list[] = {
    {"help", N_("list pools")},
    {"desc", N_("Returns list of pools.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_list[] = {
    {"inactive", VSH_OT_BOOL, 0, N_("list inactive pools")},
    {"all", VSH_OT_BOOL, 0, N_("list inactive & active pools")},
    {"details", VSH_OT_BOOL, 0, N_("display extended details for pools")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStoragePoolInfo info;
    char **poolNames = NULL;
    int i, ret;
    bool functionReturn;
    int numActivePools = 0, numInactivePools = 0, numAllPools = 0;
    size_t stringLength = 0, nameStrLength = 0;
    size_t autostartStrLength = 0, persistStrLength = 0;
    size_t stateStrLength = 0, capStrLength = 0;
    size_t allocStrLength = 0, availStrLength = 0;
    struct poolInfoText {
        char *state;
        char *autostart;
        char *persistent;
        char *capacity;
        char *allocation;
        char *available;
    };
    struct poolInfoText *poolInfoTexts = NULL;

    /* Determine the options passed by the user */
    int all = vshCommandOptBool(cmd, "all");
    int details = vshCommandOptBool(cmd, "details");
    int inactive = vshCommandOptBool(cmd, "inactive");
    int active = !inactive || all ? 1 : 0;
    inactive |= all;

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    /* Retrieve the number of active storage pools */
    if (active) {
        numActivePools = virConnectNumOfStoragePools(ctl->conn);
        if (numActivePools < 0) {
            vshError(ctl, "%s", _("Failed to list active pools"));
            return false;
        }
    }

    /* Retrieve the number of inactive storage pools */
    if (inactive) {
        numInactivePools = virConnectNumOfDefinedStoragePools(ctl->conn);
        if (numInactivePools < 0) {
            vshError(ctl, "%s", _("Failed to list inactive pools"));
            return false;
        }
    }

    /* Determine the total number of pools to list */
    numAllPools = numActivePools + numInactivePools;

    /* Allocate memory for arrays of storage pool names and info */
    poolNames = vshCalloc(ctl, numAllPools, sizeof(*poolNames));
    poolInfoTexts =
        vshCalloc(ctl, numAllPools, sizeof(*poolInfoTexts));

    /* Retrieve a list of active storage pool names */
    if (active) {
        if ((virConnectListStoragePools(ctl->conn,
                                        poolNames, numActivePools)) < 0) {
            vshError(ctl, "%s", _("Failed to list active pools"));
            VIR_FREE(poolInfoTexts);
            VIR_FREE(poolNames);
            return false;
        }
    }

    /* Add the inactive storage pools to the end of the name list */
    if (inactive) {
        if ((virConnectListDefinedStoragePools(ctl->conn,
                                               &poolNames[numActivePools],
                                               numInactivePools)) < 0) {
            vshError(ctl, "%s", _("Failed to list inactive pools"));
            VIR_FREE(poolInfoTexts);
            VIR_FREE(poolNames);
            return false;
        }
    }

    /* Sort the storage pool names */
    qsort(poolNames, numAllPools, sizeof(*poolNames), namesorter);

    /* Collect the storage pool information for display */
    for (i = 0; i < numAllPools; i++) {
        int autostart = 0, persistent = 0;

        /* Retrieve a pool object, looking it up by name */
        virStoragePoolPtr pool = virStoragePoolLookupByName(ctl->conn,
                                                            poolNames[i]);
        if (!pool) {
            VIR_FREE(poolNames[i]);
            continue;
        }

        /* Retrieve the autostart status of the pool */
        if (virStoragePoolGetAutostart(pool, &autostart) < 0)
            poolInfoTexts[i].autostart = vshStrdup(ctl, _("no autostart"));
        else
            poolInfoTexts[i].autostart = vshStrdup(ctl, autostart ?
                                                    _("yes") : _("no"));

        /* Retrieve the persistence status of the pool */
        if (details) {
            persistent = virStoragePoolIsPersistent(pool);
            vshDebug(ctl, VSH_ERR_DEBUG, "Persistent flag value: %d\n",
                     persistent);
            if (persistent < 0)
                poolInfoTexts[i].persistent = vshStrdup(ctl, _("unknown"));
            else
                poolInfoTexts[i].persistent = vshStrdup(ctl, persistent ?
                                                         _("yes") : _("no"));

            /* Keep the length of persistent string if longest so far */
            stringLength = strlen(poolInfoTexts[i].persistent);
            if (stringLength > persistStrLength)
                persistStrLength = stringLength;
        }

        /* Collect further extended information about the pool */
        if (virStoragePoolGetInfo(pool, &info) != 0) {
            /* Something went wrong retrieving pool info, cope with it */
            vshError(ctl, "%s", _("Could not retrieve pool information"));
            poolInfoTexts[i].state = vshStrdup(ctl, _("unknown"));
            if (details) {
                poolInfoTexts[i].capacity = vshStrdup(ctl, _("unknown"));
                poolInfoTexts[i].allocation = vshStrdup(ctl, _("unknown"));
                poolInfoTexts[i].available = vshStrdup(ctl, _("unknown"));
            }
        } else {
            /* Decide which state string to display */
            if (details) {
                /* --details option was specified, we're using detailed state
                 * strings */
                switch (info.state) {
                case VIR_STORAGE_POOL_INACTIVE:
                    poolInfoTexts[i].state = vshStrdup(ctl, _("inactive"));
                    break;
                case VIR_STORAGE_POOL_BUILDING:
                    poolInfoTexts[i].state = vshStrdup(ctl, _("building"));
                    break;
                case VIR_STORAGE_POOL_RUNNING:
                    poolInfoTexts[i].state = vshStrdup(ctl, _("running"));
                    break;
                case VIR_STORAGE_POOL_DEGRADED:
                    poolInfoTexts[i].state = vshStrdup(ctl, _("degraded"));
                    break;
                case VIR_STORAGE_POOL_INACCESSIBLE:
                    poolInfoTexts[i].state = vshStrdup(ctl, _("inaccessible"));
                    break;
                }

                /* Create the pool size related strings */
                if (info.state == VIR_STORAGE_POOL_RUNNING ||
                    info.state == VIR_STORAGE_POOL_DEGRADED) {
                    double val;
                    const char *unit;

                    /* Create the capacity output string */
                    val = prettyCapacity(info.capacity, &unit);
                    ret = virAsprintf(&poolInfoTexts[i].capacity,
                                      "%.2lf %s", val, unit);
                    if (ret < 0) {
                        /* An error occurred creating the string, return */
                        goto asprintf_failure;
                    }

                    /* Create the allocation output string */
                    val = prettyCapacity(info.allocation, &unit);
                    ret = virAsprintf(&poolInfoTexts[i].allocation,
                                      "%.2lf %s", val, unit);
                    if (ret < 0) {
                        /* An error occurred creating the string, return */
                        goto asprintf_failure;
                    }

                    /* Create the available space output string */
                    val = prettyCapacity(info.available, &unit);
                    ret = virAsprintf(&poolInfoTexts[i].available,
                                      "%.2lf %s", val, unit);
                    if (ret < 0) {
                        /* An error occurred creating the string, return */
                        goto asprintf_failure;
                    }
                } else {
                    /* Capacity related information isn't available */
                    poolInfoTexts[i].capacity = vshStrdup(ctl, _("-"));
                    poolInfoTexts[i].allocation = vshStrdup(ctl, _("-"));
                    poolInfoTexts[i].available = vshStrdup(ctl, _("-"));
                }

                /* Keep the length of capacity string if longest so far */
                stringLength = strlen(poolInfoTexts[i].capacity);
                if (stringLength > capStrLength)
                    capStrLength = stringLength;

                /* Keep the length of allocation string if longest so far */
                stringLength = strlen(poolInfoTexts[i].allocation);
                if (stringLength > allocStrLength)
                    allocStrLength = stringLength;

                /* Keep the length of available string if longest so far */
                stringLength = strlen(poolInfoTexts[i].available);
                if (stringLength > availStrLength)
                    availStrLength = stringLength;
            } else {
                /* --details option was not specified, only active/inactive
                * state strings are used */
                if (info.state == VIR_STORAGE_POOL_INACTIVE)
                    poolInfoTexts[i].state = vshStrdup(ctl, _("inactive"));
                else
                    poolInfoTexts[i].state = vshStrdup(ctl, _("active"));
            }
        }

        /* Keep the length of name string if longest so far */
        stringLength = strlen(poolNames[i]);
        if (stringLength > nameStrLength)
            nameStrLength = stringLength;

        /* Keep the length of state string if longest so far */
        stringLength = strlen(poolInfoTexts[i].state);
        if (stringLength > stateStrLength)
            stateStrLength = stringLength;

        /* Keep the length of autostart string if longest so far */
        stringLength = strlen(poolInfoTexts[i].autostart);
        if (stringLength > autostartStrLength)
            autostartStrLength = stringLength;

        /* Free the pool object */
        virStoragePoolFree(pool);
    }

    /* If the --details option wasn't selected, we output the pool
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        /* Output old style header */
        vshPrintExtra(ctl, "%-20s %-10s %-10s\n", _("Name"), _("State"),
                      _("Autostart"));
        vshPrintExtra(ctl, "-----------------------------------------\n");

        /* Output old style pool info */
        for (i = 0; i < numAllPools; i++) {
            vshPrint(ctl, "%-20s %-10s %-10s\n",
                 poolNames[i],
                 poolInfoTexts[i].state,
                 poolInfoTexts[i].autostart);
        }

        /* Cleanup and return */
        functionReturn = true;
        goto cleanup;
    }

    /* We only get here if the --details option was selected. */

    /* Use the length of name header string if it's longest */
    stringLength = strlen(_("Name"));
    if (stringLength > nameStrLength)
        nameStrLength = stringLength;

    /* Use the length of state header string if it's longest */
    stringLength = strlen(_("State"));
    if (stringLength > stateStrLength)
        stateStrLength = stringLength;

    /* Use the length of autostart header string if it's longest */
    stringLength = strlen(_("Autostart"));
    if (stringLength > autostartStrLength)
        autostartStrLength = stringLength;

    /* Use the length of persistent header string if it's longest */
    stringLength = strlen(_("Persistent"));
    if (stringLength > persistStrLength)
        persistStrLength = stringLength;

    /* Use the length of capacity header string if it's longest */
    stringLength = strlen(_("Capacity"));
    if (stringLength > capStrLength)
        capStrLength = stringLength;

    /* Use the length of allocation header string if it's longest */
    stringLength = strlen(_("Allocation"));
    if (stringLength > allocStrLength)
        allocStrLength = stringLength;

    /* Use the length of available header string if it's longest */
    stringLength = strlen(_("Available"));
    if (stringLength > availStrLength)
        availStrLength = stringLength;

    /* Display the string lengths for debugging. */
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest name string = %lu chars\n",
             (unsigned long) nameStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest state string = %lu chars\n",
             (unsigned long) stateStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest autostart string = %lu chars\n",
             (unsigned long) autostartStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest persistent string = %lu chars\n",
             (unsigned long) persistStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest capacity string = %lu chars\n",
             (unsigned long) capStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest allocation string = %lu chars\n",
             (unsigned long) allocStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG, "Longest available string = %lu chars\n",
             (unsigned long) availStrLength);

    /* Create the output template.  Each column is sized according to
     * the longest string.
     */
    char *outputStr;
    ret = virAsprintf(&outputStr,
              "%%-%lus  %%-%lus  %%-%lus  %%-%lus  %%%lus  %%%lus  %%%lus\n",
              (unsigned long) nameStrLength,
              (unsigned long) stateStrLength,
              (unsigned long) autostartStrLength,
              (unsigned long) persistStrLength,
              (unsigned long) capStrLength,
              (unsigned long) allocStrLength,
              (unsigned long) availStrLength);
    if (ret < 0) {
        /* An error occurred creating the string, return */
        goto asprintf_failure;
    }

    /* Display the header */
    vshPrint(ctl, outputStr, _("Name"), _("State"), _("Autostart"),
             _("Persistent"), _("Capacity"), _("Allocation"), _("Available"));
    for (i = nameStrLength + stateStrLength + autostartStrLength
                           + persistStrLength + capStrLength
                           + allocStrLength + availStrLength
                           + 12; i > 0; i--)
        vshPrintExtra(ctl, "-");
    vshPrintExtra(ctl, "\n");

    /* Display the pool info rows */
    for (i = 0; i < numAllPools; i++) {
        vshPrint(ctl, outputStr,
                 poolNames[i],
                 poolInfoTexts[i].state,
                 poolInfoTexts[i].autostart,
                 poolInfoTexts[i].persistent,
                 poolInfoTexts[i].capacity,
                 poolInfoTexts[i].allocation,
                 poolInfoTexts[i].available);
    }

    /* Cleanup and return */
    functionReturn = true;
    goto cleanup;

asprintf_failure:

    /* Display an appropriate error message then cleanup and return */
    switch (errno) {
    case ENOMEM:
        /* Couldn't allocate memory */
        vshError(ctl, "%s", _("Out of memory"));
        break;
    default:
        /* Some other error */
        vshError(ctl, _("virAsprintf failed (errno %d)"), errno);
    }
    functionReturn = false;

cleanup:

    /* Safely free the memory allocated in this function */
    for (i = 0; i < numAllPools; i++) {
        /* Cleanup the memory for one pool info structure */
        VIR_FREE(poolInfoTexts[i].state);
        VIR_FREE(poolInfoTexts[i].autostart);
        VIR_FREE(poolInfoTexts[i].persistent);
        VIR_FREE(poolInfoTexts[i].capacity);
        VIR_FREE(poolInfoTexts[i].allocation);
        VIR_FREE(poolInfoTexts[i].available);
        VIR_FREE(poolNames[i]);
    }

    /* Cleanup the memory for the initial arrays*/
    VIR_FREE(poolInfoTexts);
    VIR_FREE(poolNames);

    /* Return the desired value */
    return functionReturn;
}

/*
 * "find-storage-pool-sources-as" command
 */
static const vshCmdInfo info_find_storage_pool_sources_as[] = {
    {"help", N_("find potential storage pool sources")},
    {"desc", N_("Returns XML <sources> document.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources_as[] = {
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("type of storage pool sources to find")},
    {"host", VSH_OT_DATA, VSH_OFLAG_NONE, N_("optional host to query")},
    {"port", VSH_OT_DATA, VSH_OFLAG_NONE, N_("optional port to query")},
    {"initiator", VSH_OT_DATA, VSH_OFLAG_NONE, N_("optional initiator IQN to use for query")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDiscoverSourcesAs(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    const char *type = NULL, *host = NULL;
    char *srcSpec = NULL;
    char *srcList;
    const char *initiator = NULL;

    if (vshCommandOptString(cmd, "type", &type) <= 0 ||
        vshCommandOptString(cmd, "host", &host) < 0 ||
        vshCommandOptString(cmd, "initiator", &initiator) < 0) {
        vshError(ctl,"%s", _("missing argument"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (host) {
        const char *port = NULL;
        virBuffer buf = VIR_BUFFER_INITIALIZER;

        if (vshCommandOptString(cmd, "port", &port) < 0) {
            vshError(ctl, "%s", _("missing argument"));
            virBufferFreeAndReset(&buf);
            return false;
        }
        virBufferAddLit(&buf, "<source>\n");
        virBufferAsprintf(&buf, "  <host name='%s'", host);
        if (port)
            virBufferAsprintf(&buf, " port='%s'", port);
        virBufferAddLit(&buf, "/>\n");
        if (initiator) {
            virBufferAddLit(&buf, "  <initiator>\n");
            virBufferAsprintf(&buf, "    <iqn name='%s'/>\n", initiator);
            virBufferAddLit(&buf, "  </initiator>\n");
        }
        virBufferAddLit(&buf, "</source>\n");
        if (virBufferError(&buf)) {
            vshError(ctl, "%s", _("Out of memory"));
            return false;
        }
        srcSpec = virBufferContentAndReset(&buf);
    }

    srcList = virConnectFindStoragePoolSources(ctl->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return false;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return true;
}


/*
 * "find-storage-pool-sources" command
 */
static const vshCmdInfo info_find_storage_pool_sources[] = {
    {"help", N_("discover potential storage pool sources")},
    {"desc", N_("Returns XML <sources> document.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources[] = {
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("type of storage pool sources to discover")},
    {"srcSpec", VSH_OT_DATA, VSH_OFLAG_NONE,
     N_("optional file of source xml to query for pools")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolDiscoverSources(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    const char *type = NULL, *srcSpecFile = NULL;
    char *srcSpec = NULL, *srcList;

    if (vshCommandOptString(cmd, "type", &type) <= 0)
        return false;

    if (vshCommandOptString(cmd, "srcSpec", &srcSpecFile) < 0) {
        vshError(ctl, "%s", _("missing option"));
        return false;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (srcSpecFile && virFileReadAll(srcSpecFile, VIRSH_MAX_XML_FILE, &srcSpec) < 0)
        return false;

    srcList = virConnectFindStoragePoolSources(ctl->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return false;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return true;
}


/*
 * "pool-info" command
 */
static const vshCmdInfo info_pool_info[] = {
    {"help", N_("storage pool information")},
    {"desc", N_("Returns basic information about the storage pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_info[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolInfo info;
    virStoragePoolPtr pool;
    int autostart = 0;
    int persistent = 0;
    bool ret = true;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStoragePoolGetName(pool));

    if (virStoragePoolGetUUIDString(pool, &uuid[0])==0)
        vshPrint(ctl, "%-15s %s\n", _("UUID:"), uuid);

    if (virStoragePoolGetInfo(pool, &info) == 0) {
        double val;
        const char *unit;
        switch (info.state) {
        case VIR_STORAGE_POOL_INACTIVE:
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _("inactive"));
            break;
        case VIR_STORAGE_POOL_BUILDING:
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _("building"));
            break;
        case VIR_STORAGE_POOL_RUNNING:
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _("running"));
            break;
        case VIR_STORAGE_POOL_DEGRADED:
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _("degraded"));
            break;
        case VIR_STORAGE_POOL_INACCESSIBLE:
            vshPrint(ctl, "%-15s %s\n", _("State:"),
                     _("inaccessible"));
            break;
        }

        /* Check and display whether the pool is persistent or not */
        persistent = virStoragePoolIsPersistent(pool);
        vshDebug(ctl, VSH_ERR_DEBUG, "Pool persistent flag value: %d\n",
                 persistent);
        if (persistent < 0)
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"),  _("unknown"));
        else
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

        /* Check and display whether the pool is autostarted or not */
        virStoragePoolGetAutostart(pool, &autostart);
        vshDebug(ctl, VSH_ERR_DEBUG, "Pool autostart flag value: %d\n",
                 autostart);
        if (autostart < 0)
            vshPrint(ctl, "%-15s %s\n", _("Autostart:"), _("no autostart"));
        else
            vshPrint(ctl, "%-15s %s\n", _("Autostart:"), autostart ? _("yes") : _("no"));

        if (info.state == VIR_STORAGE_POOL_RUNNING ||
            info.state == VIR_STORAGE_POOL_DEGRADED) {
            val = prettyCapacity(info.capacity, &unit);
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

            val = prettyCapacity(info.allocation, &unit);
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);

            val = prettyCapacity(info.available, &unit);
            vshPrint(ctl, "%-15s %2.2lf %s\n", _("Available:"), val, unit);
        }
    } else {
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-name" command
 */
static const vshCmdInfo info_pool_name[] = {
    {"help", N_("convert a pool UUID to pool name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_name[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolName(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;
    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virStoragePoolGetName(pool));
    virStoragePoolFree(pool);
    return true;
}


/*
 * "pool-start" command
 */
static const vshCmdInfo info_pool_start[] = {
    {"help", N_("start a (previously defined) inactive pool")},
    {"desc", N_("Start a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_start[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the inactive pool")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolStart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL, VSH_BYNAME)))
         return false;

    if (virStoragePoolCreate(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s started\n"),
                 virStoragePoolGetName(pool));
    } else {
        vshError(ctl, _("Failed to start pool %s"), virStoragePoolGetName(pool));
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "vol-create-as" command
 */
static const vshCmdInfo info_vol_create_as[] = {
    {"help", N_("create a volume from a set of args")},
    {"desc", N_("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_as[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, N_("name of the volume")},
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("size of the vol, as scaled integer (default bytes)")},
    {"allocation", VSH_OT_STRING, 0,
     N_("initial allocation size, as scaled integer (default bytes)")},
    {"format", VSH_OT_STRING, 0,
     N_("file format type raw,bochs,qcow,qcow2,vmdk")},
    {"backing-vol", VSH_OT_STRING, 0,
     N_("the backing volume if taking a snapshot")},
    {"backing-vol-format", VSH_OT_STRING, 0,
     N_("format of backing volume if taking a snapshot")},
    {NULL, 0, 0, NULL}
};

static int
vshVolSize(const char *data, unsigned long long *val)
{
    char *end;
    if (virStrToLong_ull(data, &end, 10, val) < 0)
        return -1;
    return virScaleInteger(val, end, 1, ULLONG_MAX);
}

static bool
cmdVolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char *xml;
    const char *name, *capacityStr = NULL, *allocationStr = NULL, *format = NULL;
    const char *snapshotStrVol = NULL, *snapshotStrFormat = NULL;
    unsigned long long capacity, allocation = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                     VSH_BYNAME)))
        return false;

    if (vshCommandOptString(cmd, "name", &name) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "capacity", &capacityStr) <= 0)
        goto cleanup;
    if (vshVolSize(capacityStr, &capacity) < 0)
        vshError(ctl, _("Malformed size %s"), capacityStr);

    if ((vshCommandOptString(cmd, "allocation", &allocationStr) > 0) &&
        (vshVolSize(allocationStr, &allocation) < 0))
        vshError(ctl, _("Malformed size %s"), allocationStr);

    if (vshCommandOptString(cmd, "format", &format) < 0 ||
        vshCommandOptString(cmd, "backing-vol", &snapshotStrVol) < 0 ||
        vshCommandOptString(cmd, "backing-vol-format",
                            &snapshotStrFormat) < 0) {
        vshError(ctl, "%s", _("missing argument"));
    }


    virBufferAddLit(&buf, "<volume>\n");
    virBufferAsprintf(&buf, "  <name>%s</name>\n", name);
    virBufferAsprintf(&buf, "  <capacity>%llu</capacity>\n", capacity);
    if (allocationStr)
        virBufferAsprintf(&buf, "  <allocation>%llu</allocation>\n", allocation);

    if (format) {
        virBufferAddLit(&buf, "  <target>\n");
        virBufferAsprintf(&buf, "    <format type='%s'/>\n",format);
        virBufferAddLit(&buf, "  </target>\n");
    }

    /* Convert the snapshot parameters into backingStore XML */
    if (snapshotStrVol) {
        /* Lookup snapshot backing volume.  Try the backing-vol
         *  parameter as a name */
        vshDebug(ctl, VSH_ERR_DEBUG,
                 "%s: Look up backing store volume '%s' as name\n",
                 cmd->def->name, snapshotStrVol);
        virStorageVolPtr snapVol = virStorageVolLookupByName(pool, snapshotStrVol);
        if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as name\n",
                         cmd->def->name, snapshotStrVol);

        if (snapVol == NULL) {
            /* Snapshot backing volume not found by name.  Try the
             *  backing-vol parameter as a key */
            vshDebug(ctl, VSH_ERR_DEBUG,
                     "%s: Look up backing store volume '%s' as key\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByKey(ctl->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as key\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            /* Snapshot backing volume not found by key.  Try the
             *  backing-vol parameter as a path */
            vshDebug(ctl, VSH_ERR_DEBUG,
                     "%s: Look up backing store volume '%s' as path\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByPath(ctl->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, VSH_ERR_DEBUG,
                         "%s: Backing store volume found using '%s' as path\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            vshError(ctl, _("failed to get vol '%s'"), snapshotStrVol);
            goto cleanup;
        }

        char *snapshotStrVolPath;
        if ((snapshotStrVolPath = virStorageVolGetPath(snapVol)) == NULL) {
            virStorageVolFree(snapVol);
            goto cleanup;
        }

        /* Create XML for the backing store */
        virBufferAddLit(&buf, "  <backingStore>\n");
        virBufferAsprintf(&buf, "    <path>%s</path>\n",snapshotStrVolPath);
        if (snapshotStrFormat)
            virBufferAsprintf(&buf, "    <format type='%s'/>\n",snapshotStrFormat);
        virBufferAddLit(&buf, "  </backingStore>\n");

        /* Cleanup snapshot allocations */
        VIR_FREE(snapshotStrVolPath);
        virStorageVolFree(snapVol);
    }

    virBufferAddLit(&buf, "</volume>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }
    xml = virBufferContentAndReset(&buf);
    vol = virStorageVolCreateXML(pool, xml, 0);
    VIR_FREE(xml);
    virStoragePoolFree(pool);

    if (vol != NULL) {
        vshPrint(ctl, _("Vol %s created\n"), name);
        virStorageVolFree(vol);
        return true;
    } else {
        vshError(ctl, _("Failed to create vol %s"), name);
        return false;
    }

 cleanup:
    virBufferFreeAndReset(&buf);
    virStoragePoolFree(pool);
    return false;
}


/*
 * "pool-undefine" command
 */
static const vshCmdInfo info_pool_undefine[] = {
    {"help", N_("undefine an inactive pool")},
    {"desc", N_("Undefine the configuration for an inactive pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_undefine[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return false;

    if (virStoragePoolUndefine(pool) == 0) {
        vshPrint(ctl, _("Pool %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine pool %s"), name);
        ret = false;
    }

    virStoragePoolFree(pool);
    return ret;
}


/*
 * "pool-uuid" command
 */
static const vshCmdInfo info_pool_uuid[] = {
    {"help", N_("convert a pool name to pool UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_uuid[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {NULL, 0, 0, NULL}
};

static bool
cmdPoolUuid(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYNAME)))
        return false;

    if (virStoragePoolGetUUIDString(pool, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get pool UUID"));

    virStoragePoolFree(pool);
    return true;
}


/*
 * "vol-create" command
 */
static const vshCmdInfo info_vol_create[] = {
    {"help", N_("create a vol from an XML file")},
    {"desc", N_("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML vol description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    const char *from = NULL;
    bool ret = true;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYNAME)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virStoragePoolFree(pool);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virStoragePoolFree(pool);
        return false;
    }

    vol = virStorageVolCreateXML(pool, buffer, 0);
    VIR_FREE(buffer);
    virStoragePoolFree(pool);

    if (vol != NULL) {
        vshPrint(ctl, _("Vol %s created from %s\n"),
                 virStorageVolGetName(vol), from);
        virStorageVolFree(vol);
    } else {
        vshError(ctl, _("Failed to create vol from %s"), from);
        ret = false;
    }
    return ret;
}

/*
 * "vol-create-from" command
 */
static const vshCmdInfo info_vol_create_from[] = {
    {"help", N_("create a vol, using another volume as input")},
    {"desc", N_("Create a vol from an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_from[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML vol description")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("input vol name or key")},
    {"inputpool", VSH_OT_STRING, 0, N_("pool name or uuid of the input volume's pool")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolCreateFrom(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr newvol = NULL, inputvol = NULL;
    const char *from = NULL;
    bool ret = false;
    char *buffer = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL, VSH_BYNAME)))
        goto cleanup;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        goto cleanup;
    }

    if (!(inputvol = vshCommandOptVol(ctl, cmd, "vol", "inputpool", NULL)))
        goto cleanup;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(pool, buffer, inputvol, 0);

    if (newvol != NULL) {
        vshPrint(ctl, _("Vol %s created from input vol %s\n"),
                 virStorageVolGetName(newvol), virStorageVolGetName(inputvol));
    } else {
        vshError(ctl, _("Failed to create vol from %s"), from);
        goto cleanup;
    }

    ret = true;
cleanup:
    VIR_FREE(buffer);
    if (pool)
        virStoragePoolFree(pool);
    if (inputvol)
        virStorageVolFree(inputvol);
    if (newvol)
        virStorageVolFree(newvol);
    return ret;
}

static xmlChar *
makeCloneXML(const char *origxml, const char *newname)
{

    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlChar *newxml = NULL;
    int size;

    doc = virXMLParseStringCtxt(origxml, _("(volume_definition)"), &ctxt);
    if (!doc)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "/volume/name", ctxt);
    if ((obj == NULL) || (obj->nodesetval == NULL) ||
        (obj->nodesetval->nodeTab == NULL))
        goto cleanup;

    xmlNodeSetContent(obj->nodesetval->nodeTab[0], (const xmlChar *)newname);
    xmlDocDumpMemory(doc, &newxml, &size);

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return newxml;
}

/*
 * "vol-clone" command
 */
static const vshCmdInfo info_vol_clone[] = {
    {"help", N_("clone a volume.")},
    {"desc", N_("Clone an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_clone[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("orig vol name or key")},
    {"newname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("clone name")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolClone(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr origpool = NULL;
    virStorageVolPtr origvol = NULL, newvol = NULL;
    const char *name = NULL;
    char *origxml = NULL;
    xmlChar *newxml = NULL;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(origvol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        goto cleanup;

    origpool = virStoragePoolLookupByVolume(origvol);
    if (!origpool) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        goto cleanup;
    }

    if (vshCommandOptString(cmd, "newname", &name) <= 0)
        goto cleanup;

    origxml = virStorageVolGetXMLDesc(origvol, 0);
    if (!origxml)
        goto cleanup;

    newxml = makeCloneXML(origxml, name);
    if (!newxml) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    newvol = virStorageVolCreateXMLFrom(origpool, (char *) newxml, origvol, 0);

    if (newvol != NULL) {
        vshPrint(ctl, _("Vol %s cloned from %s\n"),
                 virStorageVolGetName(newvol), virStorageVolGetName(origvol));
    } else {
        vshError(ctl, _("Failed to clone vol from %s"),
                 virStorageVolGetName(origvol));
        goto cleanup;
    }

    ret = true;

cleanup:
    VIR_FREE(origxml);
    xmlFree(newxml);
    if (origvol)
        virStorageVolFree(origvol);
    if (newvol)
        virStorageVolFree(newvol);
    if (origpool)
        virStoragePoolFree(origpool);
    return ret;
}


/*
 * "vol-upload" command
 */
static const vshCmdInfo info_vol_upload[] = {
    {"help", N_("upload a file into a volume")},
    {"desc", N_("Upload a file into a volume")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_upload[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"offset", VSH_OT_INT, 0, N_("volume offset to upload to") },
    {"length", VSH_OT_INT, 0, N_("amount of data to upload") },
    {NULL, 0, 0, NULL}
};

static int
cmdVolUploadSource(virStreamPtr st ATTRIBUTE_UNUSED,
                   char *bytes, size_t nbytes, void *opaque)
{
    int *fd = opaque;

    return saferead(*fd, bytes, nbytes);
}

static bool
cmdVolUpload (vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    virStorageVolPtr vol = NULL;
    bool ret = false;
    int fd = -1;
    virStreamPtr st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (vshCommandOptULongLong(cmd, "offset", &offset) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (vshCommandOptULongLong(cmd, "length", &length) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (vshCommandOptString(cmd, "file", &file) < 0) {
        vshError(ctl, _("file must not be empty"));
        goto cleanup;
    }

    if ((fd = open(file, O_RDONLY)) < 0) {
        vshError(ctl, _("cannot read %s"), file);
        goto cleanup;
    }

    st = virStreamNew(ctl->conn, 0);
    if (virStorageVolUpload(vol, st, offset, length, 0) < 0) {
        vshError(ctl, _("cannot upload to volume %s"), name);
        goto cleanup;
    }

    if (virStreamSendAll(st, cmdVolUploadSource, &fd) < 0) {
        vshError(ctl, _("cannot send data to volume %s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        virStreamAbort(st);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %s"), name);
        goto cleanup;
    }

    ret = true;

cleanup:
    if (vol)
        virStorageVolFree(vol);
    if (st)
        virStreamFree(st);
    VIR_FORCE_CLOSE(fd);
    return ret;
}



/*
 * "vol-download" command
 */
static const vshCmdInfo info_vol_download[] = {
    {"help", N_("Download a volume to a file")},
    {"desc", N_("Download a volume to a file")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_download[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"offset", VSH_OT_INT, 0, N_("volume offset to download from") },
    {"length", VSH_OT_INT, 0, N_("amount of data to download") },
    {NULL, 0, 0, NULL}
};

static bool
cmdVolDownload (vshControl *ctl, const vshCmd *cmd)
{
    const char *file = NULL;
    virStorageVolPtr vol = NULL;
    bool ret = false;
    int fd = -1;
    virStreamPtr st = NULL;
    const char *name = NULL;
    unsigned long long offset = 0, length = 0;
    bool created = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptULongLong(cmd, "offset", &offset) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (vshCommandOptULongLong(cmd, "length", &length) < 0) {
        vshError(ctl, _("Unable to parse integer"));
        return false;
    }

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name)))
        return false;

    if (vshCommandOptString(cmd, "file", &file) < 0) {
        vshError(ctl, _("file must not be empty"));
        goto cleanup;
    }

    if ((fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0666)) < 0) {
        if (errno != EEXIST ||
            (fd = open(file, O_WRONLY|O_TRUNC, 0666)) < 0) {
            vshError(ctl, _("cannot create %s"), file);
            goto cleanup;
        }
    } else {
        created = true;
    }

    st = virStreamNew(ctl->conn, 0);
    if (virStorageVolDownload(vol, st, offset, length, 0) < 0) {
        vshError(ctl, _("cannot download from volume %s"), name);
        goto cleanup;
    }

    if (virStreamRecvAll(st, vshStreamSink, &fd) < 0) {
        vshError(ctl, _("cannot receive data from volume %s"), name);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("cannot close file %s"), file);
        virStreamAbort(st);
        goto cleanup;
    }

    if (virStreamFinish(st) < 0) {
        vshError(ctl, _("cannot close volume %s"), name);
        goto cleanup;
    }

    ret = true;

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (!ret && created)
        unlink(file);
    if (vol)
        virStorageVolFree(vol);
    if (st)
        virStreamFree(st);
    return ret;
}


/*
 * "vol-delete" command
 */
static const vshCmdInfo info_vol_delete[] = {
    {"help", N_("delete a vol")},
    {"desc", N_("Delete a given vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_delete[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (virStorageVolDelete(vol, 0) == 0) {
        vshPrint(ctl, _("Vol %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete vol %s"), name);
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}


/*
 * "vol-wipe" command
 */
static const vshCmdInfo info_vol_wipe[] = {
    {"help", N_("wipe a vol")},
    {"desc", N_("Ensure data previously on a volume is not accessible to future reads")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_wipe[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"algorithm", VSH_OT_STRING, 0, N_("perform selected wiping algorithm")},
    {NULL, 0, 0, NULL}
};

VIR_ENUM_DECL(virStorageVolWipeAlgorithm)
VIR_ENUM_IMPL(virStorageVolWipeAlgorithm, VIR_STORAGE_VOL_WIPE_ALG_LAST,
              "zero", "nnsa", "dod", "bsi", "gutmann", "schneier",
              "pfitzner7", "pfitzner33", "random");

static bool
cmdVolWipe(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = false;
    const char *name;
    const char *algorithm_str = NULL;
    int algorithm = VIR_STORAGE_VOL_WIPE_ALG_ZERO;
    int funcRet;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return false;
    }

    if (vshCommandOptString(cmd, "algorithm", &algorithm_str) < 0) {
        vshError(ctl, "%s", _("missing argument"));
        goto out;
    }

    if (algorithm_str &&
        (algorithm = virStorageVolWipeAlgorithmTypeFromString(algorithm_str)) < 0) {
        vshError(ctl, _("Unsupported algorithm '%s'"), algorithm_str);
        goto out;
    }

    if ((funcRet = virStorageVolWipePattern(vol, algorithm, 0)) < 0) {
        if (last_error->code == VIR_ERR_NO_SUPPORT &&
            algorithm == VIR_STORAGE_VOL_WIPE_ALG_ZERO)
            funcRet = virStorageVolWipe(vol, 0);
    }

    if (funcRet < 0) {
        vshError(ctl, _("Failed to wipe vol %s"), name);
        goto out;
    }

    vshPrint(ctl, _("Vol %s wiped\n"), name);
    ret = true;
out:
    virStorageVolFree(vol);
    return ret;
}


/*
 * "vol-info" command
 */
static const vshCmdInfo info_vol_info[] = {
    {"help", N_("storage vol information")},
    {"desc", N_("Returns basic information about the storage vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_info[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    bool ret = true;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStorageVolGetName(vol));

    if (virStorageVolGetInfo(vol, &info) == 0) {
        double val;
        const char *unit;
        switch(info.type) {
        case VIR_STORAGE_VOL_FILE:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("file"));
            break;

        case VIR_STORAGE_VOL_BLOCK:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("block"));
            break;

        case VIR_STORAGE_VOL_DIR:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("dir"));
            break;

        default:
            vshPrint(ctl, "%-15s %s\n", _("Type:"), _("unknown"));
        }

        val = prettyCapacity(info.capacity, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

        val = prettyCapacity(info.allocation, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);
    } else {
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}

/*
 * "vol-resize" command
 */
static const vshCmdInfo info_vol_resize[] = {
    {"help", N_("resize a vol")},
    {"desc", N_("Resizes a storage volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_resize[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("new capacity for the vol, as scaled integer (default bytes)")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"allocate", VSH_OT_BOOL, 0,
     N_("allocate the new capacity, rather than leaving it sparse")},
    {"delta", VSH_OT_BOOL, 0,
     N_("use capacity as a delta to current size, rather than the new size")},
    {"shrink", VSH_OT_BOOL, 0, N_("allow the resize to shrink the volume")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolResize(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    const char *capacityStr = NULL;
    unsigned long long capacity = 0;
    unsigned int flags = 0;
    bool ret = false;
    bool delta = false;

    if (vshCommandOptBool(cmd, "allocate"))
        flags |= VIR_STORAGE_VOL_RESIZE_ALLOCATE;
    if (vshCommandOptBool(cmd, "delta")) {
        delta = true;
        flags |= VIR_STORAGE_VOL_RESIZE_DELTA;
    }
    if (vshCommandOptBool(cmd, "shrink"))
        flags |= VIR_STORAGE_VOL_RESIZE_SHRINK;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    if (vshCommandOptString(cmd, "capacity", &capacityStr) <= 0)
        goto cleanup;
    virSkipSpaces(&capacityStr);
    if (*capacityStr == '-') {
        /* The API always requires a positive value; but we allow a
         * negative value for convenience.  */
        if (delta && vshCommandOptBool(cmd, "shrink")){
            capacityStr++;
        } else {
            vshError(ctl, "%s",
                     _("negative size requires --delta and --shrink"));
            goto cleanup;
        }
    }
    if (vshVolSize(capacityStr, &capacity) < 0) {
        vshError(ctl, _("Malformed size %s"), capacityStr);
        goto cleanup;
    }

    if (virStorageVolResize(vol, capacity, flags) == 0) {
        vshPrint(ctl,
                 delta ? _("Size of volume '%s' successfully changed by %s\n")
                 : _("Size of volume '%s' successfully changed to %s\n"),
                 virStorageVolGetName(vol), capacityStr);
        ret = true;
    } else {
        vshError(ctl,
                 delta ? _("Failed to change size of volume '%s' by %s\n")
                 : _("Failed to change size of volume '%s' to %s\n"),
                 virStorageVolGetName(vol), capacityStr);
        ret = false;
    }

cleanup:
    virStorageVolFree(vol);
    return ret;
}


/*
 * "vol-dumpxml" command
 */
static const vshCmdInfo info_vol_dumpxml[] = {
    {"help", N_("vol information in XML")},
    {"desc", N_("Output the vol information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_dumpxml[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    bool ret = true;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    dump = virStorageVolGetXMLDesc(vol, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = false;
    }

    virStorageVolFree(vol);
    return ret;
}


/*
 * "vol-list" command
 */
static const vshCmdInfo info_vol_list[] = {
    {"help", N_("list vols")},
    {"desc", N_("Returns list of vols by pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_list[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {"details", VSH_OT_BOOL, 0, N_("display extended details for volumes")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStorageVolInfo volumeInfo;
    virStoragePoolPtr pool;
    char **activeNames = NULL;
    char *outputStr = NULL;
    const char *unit;
    double val;
    int details = vshCommandOptBool(cmd, "details");
    int numVolumes = 0, i;
    int ret;
    bool functionReturn;
    int stringLength = 0;
    size_t allocStrLength = 0, capStrLength = 0;
    size_t nameStrLength = 0, pathStrLength = 0;
    size_t typeStrLength = 0;
    struct volInfoText {
        char *allocation;
        char *capacity;
        char *path;
        char *type;
    };
    struct volInfoText *volInfoTexts = NULL;

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    /* Look up the pool information given to us by the user */
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return false;

    /* Determine the number of volumes in the pool */
    numVolumes = virStoragePoolNumOfVolumes(pool);

    if (numVolumes < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        virStoragePoolFree(pool);
        return false;
    }

    /* Retrieve the list of volume names in the pool */
    if (numVolumes > 0) {
        activeNames = vshCalloc(ctl, numVolumes, sizeof(*activeNames));
        if ((numVolumes = virStoragePoolListVolumes(pool, activeNames,
                                                    numVolumes)) < 0) {
            vshError(ctl, "%s", _("Failed to list active vols"));
            VIR_FREE(activeNames);
            virStoragePoolFree(pool);
            return false;
        }

        /* Sort the volume names */
        qsort(&activeNames[0], numVolumes, sizeof(*activeNames), namesorter);

        /* Set aside memory for volume information pointers */
        volInfoTexts = vshCalloc(ctl, numVolumes, sizeof(*volInfoTexts));
    }

    /* Collect the rest of the volume information for display */
    for (i = 0; i < numVolumes; i++) {
        /* Retrieve volume info */
        virStorageVolPtr vol = virStorageVolLookupByName(pool,
                                                         activeNames[i]);

        /* Retrieve the volume path */
        if ((volInfoTexts[i].path = virStorageVolGetPath(vol)) == NULL) {
            /* Something went wrong retrieving a volume path, cope with it */
            volInfoTexts[i].path = vshStrdup(ctl, _("unknown"));
        }

        /* If requested, retrieve volume type and sizing information */
        if (details) {
            if (virStorageVolGetInfo(vol, &volumeInfo) != 0) {
                /* Something went wrong retrieving volume info, cope with it */
                volInfoTexts[i].allocation = vshStrdup(ctl, _("unknown"));
                volInfoTexts[i].capacity = vshStrdup(ctl, _("unknown"));
                volInfoTexts[i].type = vshStrdup(ctl, _("unknown"));
            } else {
                /* Convert the returned volume info into output strings */

                /* Volume type */
                switch (volumeInfo.type) {
                        case VIR_STORAGE_VOL_FILE:
                            volInfoTexts[i].type = vshStrdup(ctl, _("file"));
                            break;
                        case VIR_STORAGE_VOL_BLOCK:
                            volInfoTexts[i].type = vshStrdup(ctl, _("block"));
                            break;
                        case VIR_STORAGE_VOL_DIR:
                            volInfoTexts[i].type = vshStrdup(ctl, _("dir"));
                            break;
                        default:
                            volInfoTexts[i].type = vshStrdup(ctl, _("unknown"));
                }

                /* Create the capacity output string */
                val = prettyCapacity(volumeInfo.capacity, &unit);
                ret = virAsprintf(&volInfoTexts[i].capacity,
                                  "%.2lf %s", val, unit);
                if (ret < 0) {
                    /* An error occurred creating the string, return */
                    goto asprintf_failure;
                }

                /* Create the allocation output string */
                val = prettyCapacity(volumeInfo.allocation, &unit);
                ret = virAsprintf(&volInfoTexts[i].allocation,
                                  "%.2lf %s", val, unit);
                if (ret < 0) {
                    /* An error occurred creating the string, return */
                    goto asprintf_failure;
                }
            }

            /* Remember the largest length for each output string.
             * This lets us displaying header and volume information rows
             * using a single, properly sized, printf style output string.
             */

            /* Keep the length of name string if longest so far */
            stringLength = strlen(activeNames[i]);
            if (stringLength > nameStrLength)
                nameStrLength = stringLength;

            /* Keep the length of path string if longest so far */
            stringLength = strlen(volInfoTexts[i].path);
            if (stringLength > pathStrLength)
                pathStrLength = stringLength;

            /* Keep the length of type string if longest so far */
            stringLength = strlen(volInfoTexts[i].type);
            if (stringLength > typeStrLength)
                typeStrLength = stringLength;

            /* Keep the length of capacity string if longest so far */
            stringLength = strlen(volInfoTexts[i].capacity);
            if (stringLength > capStrLength)
                capStrLength = stringLength;

            /* Keep the length of allocation string if longest so far */
            stringLength = strlen(volInfoTexts[i].allocation);
            if (stringLength > allocStrLength)
                allocStrLength = stringLength;
        }

        /* Cleanup memory allocation */
        virStorageVolFree(vol);
    }

    /* If the --details option wasn't selected, we output the volume
     * info using the fixed string format from previous versions to
     * maintain backward compatibility.
     */

    /* Output basic info then return if --details option not selected */
    if (!details) {
        /* The old output format */
        vshPrintExtra(ctl, "%-20s %-40s\n", _("Name"), _("Path"));
        vshPrintExtra(ctl, "-----------------------------------------\n");
        for (i = 0; i < numVolumes; i++) {
            vshPrint(ctl, "%-20s %-40s\n", activeNames[i],
                     volInfoTexts[i].path);
        }

        /* Cleanup and return */
        functionReturn = true;
        goto cleanup;
    }

    /* We only get here if the --details option was selected. */

    /* Use the length of name header string if it's longest */
    stringLength = strlen(_("Name"));
    if (stringLength > nameStrLength)
        nameStrLength = stringLength;

    /* Use the length of path header string if it's longest */
    stringLength = strlen(_("Path"));
    if (stringLength > pathStrLength)
        pathStrLength = stringLength;

    /* Use the length of type header string if it's longest */
    stringLength = strlen(_("Type"));
    if (stringLength > typeStrLength)
        typeStrLength = stringLength;

    /* Use the length of capacity header string if it's longest */
    stringLength = strlen(_("Capacity"));
    if (stringLength > capStrLength)
        capStrLength = stringLength;

    /* Use the length of allocation header string if it's longest */
    stringLength = strlen(_("Allocation"));
    if (stringLength > allocStrLength)
        allocStrLength = stringLength;

    /* Display the string lengths for debugging */
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest name string = %zu chars\n", nameStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest path string = %zu chars\n", pathStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest type string = %zu chars\n", typeStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest capacity string = %zu chars\n", capStrLength);
    vshDebug(ctl, VSH_ERR_DEBUG,
             "Longest allocation string = %zu chars\n", allocStrLength);

    /* Create the output template */
    ret = virAsprintf(&outputStr,
                      "%%-%lus  %%-%lus  %%-%lus  %%%lus  %%%lus\n",
                      (unsigned long) nameStrLength,
                      (unsigned long) pathStrLength,
                      (unsigned long) typeStrLength,
                      (unsigned long) capStrLength,
                      (unsigned long) allocStrLength);
    if (ret < 0) {
        /* An error occurred creating the string, return */
        goto asprintf_failure;
    }

    /* Display the header */
    vshPrint(ctl, outputStr, _("Name"), _("Path"), _("Type"),
             ("Capacity"), _("Allocation"));
    for (i = nameStrLength + pathStrLength + typeStrLength
                           + capStrLength + allocStrLength
                           + 8; i > 0; i--)
        vshPrintExtra(ctl, "-");
    vshPrintExtra(ctl, "\n");

    /* Display the volume info rows */
    for (i = 0; i < numVolumes; i++) {
        vshPrint(ctl, outputStr,
                 activeNames[i],
                 volInfoTexts[i].path,
                 volInfoTexts[i].type,
                 volInfoTexts[i].capacity,
                 volInfoTexts[i].allocation);
    }

    /* Cleanup and return */
    functionReturn = true;
    goto cleanup;

asprintf_failure:

    /* Display an appropriate error message then cleanup and return */
    switch (errno) {
    case ENOMEM:
        /* Couldn't allocate memory */
        vshError(ctl, "%s", _("Out of memory"));
        break;
    default:
        /* Some other error */
        vshError(ctl, _("virAsprintf failed (errno %d)"), errno);
    }
    functionReturn = false;

cleanup:

    /* Safely free the memory allocated in this function */
    for (i = 0; i < numVolumes; i++) {
        /* Cleanup the memory for one volume info structure per loop */
        VIR_FREE(volInfoTexts[i].path);
        VIR_FREE(volInfoTexts[i].type);
        VIR_FREE(volInfoTexts[i].capacity);
        VIR_FREE(volInfoTexts[i].allocation);
        VIR_FREE(activeNames[i]);
    }

    /* Cleanup remaining memory */
    VIR_FREE(outputStr);
    VIR_FREE(volInfoTexts);
    VIR_FREE(activeNames);
    virStoragePoolFree(pool);

    /* Return the desired value */
    return functionReturn;
}


/*
 * "vol-name" command
 */
static const vshCmdInfo info_vol_name[] = {
    {"help", N_("returns the volume name for a given volume key or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_name[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume key or path")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                   VSH_BYUUID)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetName(vol));
    virStorageVolFree(vol);
    return true;
}


/*
 * "vol-pool" command
 */
static const vshCmdInfo info_vol_pool[] = {
    {"help", N_("returns the storage pool for a given volume key or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_pool[] = {
    {"uuid", VSH_OT_BOOL, 0, N_("return the pool uuid rather than pool name")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume key or path")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolPool(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char uuid[VIR_UUID_STRING_BUFLEN];

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    /* Use the supplied string to locate the volume */
    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", NULL, NULL,
                                   VSH_BYUUID))) {
        return false;
    }

    /* Look up the parent storage pool for the volume */
    pool = virStoragePoolLookupByVolume(vol);
    if (pool == NULL) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        virStorageVolFree(vol);
        return false;
    }

    /* Return the requested details of the parent storage pool */
    if (vshCommandOptBool(cmd, "uuid")) {
        /* Retrieve and return pool UUID string */
        if (virStoragePoolGetUUIDString(pool, &uuid[0]) == 0)
            vshPrint(ctl, "%s\n", uuid);
    } else {
        /* Return the storage pool name */
        vshPrint(ctl, "%s\n", virStoragePoolGetName(pool));
    }

    /* Cleanup */
    virStorageVolFree(vol);
    virStoragePoolFree(pool);
    return true;
}


/*
 * "vol-key" command
 */
static const vshCmdInfo info_vol_key[] = {
    {"help", N_("returns the volume key for a given volume name or path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_key[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or path")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return false;

    vshPrint(ctl, "%s\n", virStorageVolGetKey(vol));
    virStorageVolFree(vol);
    return true;
}



/*
 * "vol-path" command
 */
static const vshCmdInfo info_vol_path[] = {
    {"help", N_("returns the volume path for a given volume name or key")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_path[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or key")},
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char * StorageVolPath;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL))) {
        return false;
    }

    if ((StorageVolPath = virStorageVolGetPath(vol)) == NULL) {
        virStorageVolFree(vol);
        return false;
    }

    vshPrint(ctl, "%s\n", StorageVolPath);
    VIR_FREE(StorageVolPath);
    virStorageVolFree(vol);
    return true;
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

    qsort(uuids, maxuuids, sizeof(char *), namesorter);

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

#define MAX_DEPTH 100
#define INDENT_SIZE 4
#define INDENT_BUFLEN ((MAX_DEPTH * INDENT_SIZE) + 1)

static void
cmdNodeListDevicesPrint(vshControl *ctl,
                        char **devices,
                        char **parents,
                        int num_devices,
                        int devid,
                        int lastdev,
                        unsigned int depth,
                        unsigned int indentIdx,
                        char *indentBuf)
{
    int i;
    int nextlastdev = -1;

    /* Prepare indent for this device, but not if at root */
    if (depth && depth < MAX_DEPTH) {
        indentBuf[indentIdx] = '+';
        indentBuf[indentIdx+1] = '-';
        indentBuf[indentIdx+2] = ' ';
        indentBuf[indentIdx+3] = '\0';
    }

    /* Print this device */
    vshPrint(ctl, "%s", indentBuf);
    vshPrint(ctl, "%s\n", devices[devid]);


    /* Update indent to show '|' or ' ' for child devices */
    if (depth && depth < MAX_DEPTH) {
        if (devid == lastdev)
            indentBuf[indentIdx] = ' ';
        else
            indentBuf[indentIdx] = '|';
        indentBuf[indentIdx+1] = ' ';
        indentIdx+=2;
    }

    /* Determine the index of the last child device */
    for (i = 0 ; i < num_devices ; i++) {
        if (parents[i] &&
            STREQ(parents[i], devices[devid])) {
            nextlastdev = i;
        }
    }

    /* If there is a child device, then print another blank line */
    if (nextlastdev != -1) {
        vshPrint(ctl, "%s", indentBuf);
        vshPrint(ctl, " |\n");
    }

    /* Finally print all children */
    if (depth < MAX_DEPTH)
        indentBuf[indentIdx] = ' ';
    for (i = 0 ; i < num_devices ; i++) {
        if (depth < MAX_DEPTH) {
            indentBuf[indentIdx] = ' ';
            indentBuf[indentIdx+1] = ' ';
        }
        if (parents[i] &&
            STREQ(parents[i], devices[devid]))
            cmdNodeListDevicesPrint(ctl, devices, parents,
                                    num_devices, i, nextlastdev,
                                    depth + 1, indentIdx + 2, indentBuf);
        if (depth < MAX_DEPTH)
            indentBuf[indentIdx] = '\0';
    }

    /* If there was no child device, and we're the last in
     * a list of devices, then print another blank line */
    if (nextlastdev == -1 && devid == lastdev) {
        vshPrint(ctl, "%s", indentBuf);
        vshPrint(ctl, "\n");
    }
}

static bool
cmdNodeListDevices (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *cap = NULL;
    char **devices;
    int num_devices, i;
    int tree = vshCommandOptBool(cmd, "tree");

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
    qsort(&devices[0], num_devices, sizeof(char*), namesorter);
    if (tree) {
        char indentBuf[INDENT_BUFLEN];
        char **parents = vshMalloc(ctl, sizeof(char *) * num_devices);
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
            memset(indentBuf, '\0', sizeof(indentBuf));
            if (parents[i] == NULL)
                cmdNodeListDevicesPrint(ctl,
                                        devices,
                                        parents,
                                        num_devices,
                                        i,
                                        i,
                                        0,
                                        0,
                                        indentBuf);
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
    return true;
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
cmdNodeDeviceDumpXML (vshControl *ctl, const vshCmd *cmd)
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
cmdNodeDeviceDetach (vshControl *ctl, const vshCmd *cmd)
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
cmdNodeDeviceReAttach (vshControl *ctl, const vshCmd *cmd)
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
cmdNodeDeviceReset (vshControl *ctl, const vshCmd *cmd)
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
cmdHostname (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    hostname = virConnectGetHostname (ctl->conn);
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
cmdURI (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    uri = virConnectGetURI (ctl->conn);
    if (uri == NULL) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint (ctl, "%s\n", uri);
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
cmdSysinfo (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *sysinfo;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    sysinfo = virConnectGetSysinfo (ctl->conn, 0);
    if (sysinfo == NULL) {
        vshError(ctl, "%s", _("failed to get sysinfo"));
        return false;
    }

    vshPrint (ctl, "%s", sysinfo);
    VIR_FREE(sysinfo);

    return true;
}

/*
 * "vncdisplay" command
 */
static const vshCmdInfo info_vncdisplay[] = {
    {"help", N_("vnc display")},
    {"desc", N_("Output the IP address and port number for the VNC display.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vncdisplay[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdVNCDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    bool ret = false;
    int port = 0;
    char *doc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/graphics[@type='vnc']/@port)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        goto cleanup;
    }
    if (virStrToLong_i((const char *)obj->stringval, NULL, 10, &port) || port < 0)
        goto cleanup;
    xmlXPathFreeObject(obj);

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/graphics[@type='vnc']/@listen)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0) ||
        STREQ((const char*)obj->stringval, "0.0.0.0")) {
        vshPrint(ctl, ":%d\n", port-5900);
    } else {
        vshPrint(ctl, "%s:%d\n", (const char *)obj->stringval, port-5900);
    }
    xmlXPathFreeObject(obj);
    obj = NULL;
    ret = true;

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virDomainFree(dom);
    return ret;
}

/*
 * "ttyconsole" command
 */
static const vshCmdInfo info_ttyconsole[] = {
    {"help", N_("tty console")},
    {"desc", N_("Output the device for the TTY console.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_ttyconsole[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdTTYConsole(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    bool ret = false;
    char *doc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/console/@tty)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        goto cleanup;
    }
    vshPrint(ctl, "%s\n", (const char *)obj->stringval);
    ret = true;

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virDomainFree(dom);
    return ret;
}

/*
 * "attach-device" command
 */
static const vshCmdInfo info_attach_device[] = {
    {"help", N_("attach device from an XML file")},
    {"desc", N_("Attach device from an XML <file>.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdAttachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer;
    int ret;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainAttachDevice(dom, buffer);
    }
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to attach device from %s"), from);
        virDomainFree(dom);
        return false;
    } else {
        vshPrint(ctl, "%s", _("Device attached successfully\n"));
    }

    virDomainFree(dom);
    return true;
}

/**
 * Check if n1 is superset of n2, meaning n1 contains all elements and
 * attributes as n2 at least. Including children.
 * @n1 first node
 * @n2 second node
 * returns true in case n1 covers n2, false otherwise.
 */
ATTRIBUTE_UNUSED
static bool
vshNodeIsSuperset(xmlNodePtr n1, xmlNodePtr n2)
{
    xmlNodePtr child1, child2;
    xmlAttrPtr attr;
    char *prop1, *prop2;
    bool found;
    bool visited;
    bool ret = false;
    long n1_child_size, n2_child_size, n1_iter;
    virBitmapPtr bitmap;

    if (!n1 && !n2)
        return true;

    if (!n1 || !n2)
        return false;

    if (!xmlStrEqual(n1->name, n2->name))
        return false;

    /* Iterate over n2 attributes and check if n1 contains them*/
    attr = n2->properties;
    while (attr) {
        if (attr->type == XML_ATTRIBUTE_NODE) {
            prop1 = virXMLPropString(n1, (const char *) attr->name);
            prop2 = virXMLPropString(n2, (const char *) attr->name);
            if (STRNEQ_NULLABLE(prop1, prop2)) {
                xmlFree(prop1);
                xmlFree(prop2);
                return false;
            }
            xmlFree(prop1);
            xmlFree(prop2);
        }
        attr = attr->next;
    }

    n1_child_size = virXMLChildElementCount(n1);
    n2_child_size = virXMLChildElementCount(n2);
    if (n1_child_size < 0 || n2_child_size < 0 ||
        n1_child_size < n2_child_size)
        return false;

    if (n1_child_size == 0 && n2_child_size == 0)
        return true;

    if (!(bitmap = virBitmapAlloc(n1_child_size))) {
        virReportOOMError();
        return false;
    }

    child2 = n2->children;
    while (child2) {
        if (child2->type != XML_ELEMENT_NODE) {
            child2 = child2->next;
            continue;
        }

        child1 = n1->children;
        n1_iter = 0;
        found = false;
        while (child1) {
            if (child1->type != XML_ELEMENT_NODE) {
                child1 = child1->next;
                continue;
            }

            if (virBitmapGetBit(bitmap, n1_iter, &visited) < 0) {
                vshError(NULL, "%s", _("Bad child elements counting."));
                goto cleanup;
            }

            if (visited) {
                child1 = child1->next;
                n1_iter++;
                continue;
            }

            if (xmlStrEqual(child1->name, child2->name)) {
                found = true;
                if (virBitmapSetBit(bitmap, n1_iter) < 0) {
                    vshError(NULL, "%s", _("Bad child elements counting."));
                    goto cleanup;
                }

                if (!vshNodeIsSuperset(child1, child2))
                    goto cleanup;

                break;
            }

            child1 = child1->next;
            n1_iter++;
        }

        if (!found)
            goto cleanup;

        child2 = child2->next;
    }

    ret = true;

cleanup:
    virBitmapFree(bitmap);
    return ret;
}

/**
 * vshCompleteXMLFromDomain:
 * @ctl vshControl for error messages printing
 * @dom domain
 * @oldXML device XML before
 * @newXML and after completion
 *
 * For given domain and (probably incomplete) device XML specification try to
 * find such device in domain and complete missing parts. This is however
 * possible only when given device XML is sufficiently precise so it addresses
 * only one device.
 *
 * Returns -2 when no such device exists in domain, -3 when given XML selects many
 *          (is too ambiguous), 0 in case of success. Otherwise returns -1. @newXML
 *          is touched only in case of success.
 */
ATTRIBUTE_UNUSED
static int
vshCompleteXMLFromDomain(vshControl *ctl, virDomainPtr dom, char *oldXML,
                         char **newXML)
{
    int funcRet = -1;
    char *domXML = NULL;
    xmlDocPtr domDoc = NULL, devDoc = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr domCtxt = NULL, devCtxt = NULL;
    xmlNodePtr *devices = NULL;
    xmlSaveCtxtPtr sctxt = NULL;
    int devices_size;
    char *xpath = NULL;
    xmlBufferPtr buf = NULL;
    int i = 0;
    int indx = -1;

    if (!(domXML = virDomainGetXMLDesc(dom, 0))) {
        vshError(ctl, _("couldn't get XML description of domain %s"),
                 virDomainGetName(dom));
        goto cleanup;
    }

    domDoc = virXMLParseStringCtxt(domXML, _("(domain_definition)"), &domCtxt);
    if (!domDoc) {
        vshError(ctl, _("Failed to parse domain definition xml"));
        goto cleanup;
    }

    devDoc = virXMLParseStringCtxt(oldXML, _("(device_definition)"), &devCtxt);
    if (!devDoc) {
        vshError(ctl, _("Failed to parse device definition xml"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(devDoc);

    buf = xmlBufferCreate();
    if (!buf) {
        vshError(ctl, "%s", _("out of memory"));
        goto cleanup;
    }

    /* Get all possible devices */
    virAsprintf(&xpath, "/domain/devices/%s", node->name);
    if (!xpath) {
        virReportOOMError();
        goto cleanup;
    }
    devices_size = virXPathNodeSet(xpath, domCtxt, &devices);

    if (devices_size < 0) {
        /* error */
        vshError(ctl, "%s", _("error when selecting nodes"));
        goto cleanup;
    } else if (devices_size == 0) {
        /* no such device */
        funcRet = -2;
        goto cleanup;
    }

    /* and refine */
    for (i = 0; i < devices_size; i++) {
        if (vshNodeIsSuperset(devices[i], node)) {
            if (indx >= 0) {
                funcRet = -3; /* ambiguous */
                goto cleanup;
            }
            indx = i;
        }
    }

    if (indx < 0) {
        funcRet = -2; /* no such device */
        goto cleanup;
    }

    vshDebug(ctl, VSH_ERR_DEBUG, "Found device at pos %d\n", indx);

    if (newXML) {
        sctxt = xmlSaveToBuffer(buf, NULL, 0);
        if (!sctxt) {
            vshError(ctl, "%s", _("failed to create document saving context"));
            goto cleanup;
        }

        xmlSaveTree(sctxt, devices[indx]);
        xmlSaveClose(sctxt);
        *newXML = (char *) xmlBufferContent(buf);
        if (!*newXML) {
            virReportOOMError();
            goto cleanup;
        }
        buf->content = NULL;
    }

    vshDebug(ctl, VSH_ERR_DEBUG, "Old xml:\n%s\nNew xml:\n%s\n", oldXML,
             newXML ? NULLSTR(*newXML) : "(null)");

    funcRet = 0;

cleanup:
    xmlBufferFree(buf);
    VIR_FREE(devices);
    xmlXPathFreeContext(devCtxt);
    xmlXPathFreeContext(domCtxt);
    xmlFreeDoc(devDoc);
    xmlFreeDoc(domDoc);
    VIR_FREE(domXML);
    VIR_FREE(xpath);
    return funcRet;
}

/*
 * "detach-device" command
 */
static const vshCmdInfo info_detach_device[] = {
    {"help", N_("detach device from an XML file")},
    {"desc", N_("Detach device from an XML <file>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDetachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *from = NULL;
    char *buffer = NULL;
    int ret;
    bool funcRet = false;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        goto cleanup;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainDetachDevice(dom, buffer);
    }

    if (ret < 0) {
        vshError(ctl, _("Failed to detach device from %s"), from);
        goto cleanup;
    }

    vshPrint(ctl, "%s", _("Device detached successfully\n"));
    funcRet = true;

cleanup:
    VIR_FREE(buffer);
    virDomainFree(dom);
    return funcRet;
}


/*
 * "update-device" command
 */
static const vshCmdInfo info_update_device[] = {
    {"help", N_("update device from an XML file")},
    {"desc", N_("Update device from an XML <file>.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_update_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("XML file")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"force",  VSH_OT_BOOL, 0, N_("force device update")},
    {NULL, 0, 0, NULL}
};

static bool
cmdUpdateDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    const char *from = NULL;
    char *buffer;
    int ret;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0) {
        virDomainFree(dom);
        return false;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return false;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_AFFECT_LIVE;
    } else {
        flags = VIR_DOMAIN_AFFECT_LIVE;
    }

    if (vshCommandOptBool(cmd, "force"))
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    ret = virDomainUpdateDeviceFlags(dom, buffer, flags);
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to update device from %s"), from);
        virDomainFree(dom);
        return false;
    } else {
        vshPrint(ctl, "%s", _("Device updated successfully\n"));
    }

    virDomainFree(dom);
    return true;
}


/*
 * "attach-interface" command
 */
static const vshCmdInfo info_attach_interface[] = {
    {"help", N_("attach network interface")},
    {"desc", N_("Attach new network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("network interface type")},
    {"source", VSH_OT_DATA, VSH_OFLAG_REQ, N_("source of network interface")},
    {"target", VSH_OT_DATA, 0, N_("target network name")},
    {"mac",    VSH_OT_DATA, 0, N_("MAC address")},
    {"script", VSH_OT_DATA, 0, N_("script used to bridge network interface")},
    {"model", VSH_OT_DATA, 0, N_("model type")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"inbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's incoming traffics")},
    {"outbound", VSH_OT_DATA, VSH_OFLAG_NONE, N_("control domain's outgoing traffics")},
    {NULL, 0, 0, NULL}
};

/* parse inbound and outbound which are in the format of
 * 'average,peak,burst', in which peak and burst are optional,
 * thus 'average,,burst' and 'average,peak' are also legal. */
static int parseRateStr(const char *rateStr, virNetDevBandwidthRatePtr rate)
{
    const char *average = NULL;
    char *peak = NULL, *burst = NULL;

    average = rateStr;
    if (!average)
        return -1;
    if (virStrToLong_ull(average, &peak, 10, &rate->average) < 0)
        return -1;

    /* peak will be updated to point to the end of rateStr in case
     * of 'average' */
    if (peak && *peak != '\0') {
        burst = strchr(peak + 1, ',');
        if (!(burst && (burst - peak == 1))) {
            if (virStrToLong_ull(peak + 1, &burst, 10, &rate->peak) < 0)
                return -1;
        }

        /* burst will be updated to point to the end of rateStr in case
         * of 'average,peak' */
        if (burst && *burst != '\0') {
            if (virStrToLong_ull(burst + 1, NULL, 10, &rate->burst) < 0)
                return -1;
        }
    }


    return 0;
}

static bool
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *mac = NULL, *target = NULL, *script = NULL,
                *type = NULL, *source = NULL, *model = NULL,
                *inboundStr = NULL, *outboundStr = NULL;
    virNetDevBandwidthRate inbound, outbound;
    int typ;
    int ret;
    bool functionReturn = false;
    unsigned int flags;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "type", &type) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) < 0 ||
        vshCommandOptString(cmd, "target", &target) < 0 ||
        vshCommandOptString(cmd, "mac", &mac) < 0 ||
        vshCommandOptString(cmd, "script", &script) < 0 ||
        vshCommandOptString(cmd, "model", &model) < 0 ||
        vshCommandOptString(cmd, "inbound", &inboundStr) < 0 ||
        vshCommandOptString(cmd, "outbound", &outboundStr) < 0) {
        vshError(ctl, "missing argument");
        goto cleanup;
    }

    /* check interface type */
    if (STREQ(type, "network")) {
        typ = 1;
    } else if (STREQ(type, "bridge")) {
        typ = 2;
    } else {
        vshError(ctl, _("No support for %s in command 'attach-interface'"),
                 type);
        goto cleanup;
    }

    if (inboundStr) {
        memset(&inbound, 0, sizeof(inbound));
        if (parseRateStr(inboundStr, &inbound) < 0) {
            vshError(ctl, _("inbound format is incorrect"));
            goto cleanup;
        }
        if (inbound.average == 0) {
            vshError(ctl, _("inbound average is mandatory"));
            goto cleanup;
        }
    }
    if (outboundStr) {
        memset(&outbound, 0, sizeof(outbound));
        if (parseRateStr(outboundStr, &outbound) < 0) {
            vshError(ctl, _("outbound format is incorrect"));
            goto cleanup;
        }
        if (outbound.average == 0) {
            vshError(ctl, _("outbound average is mandatory"));
            goto cleanup;
        }
    }

    /* Make XML of interface */
    virBufferAsprintf(&buf, "<interface type='%s'>\n", type);

    if (typ == 1)
        virBufferAsprintf(&buf, "  <source network='%s'/>\n", source);
    else if (typ == 2)
        virBufferAsprintf(&buf, "  <source bridge='%s'/>\n", source);

    if (target != NULL)
        virBufferAsprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mac != NULL)
        virBufferAsprintf(&buf, "  <mac address='%s'/>\n", mac);
    if (script != NULL)
        virBufferAsprintf(&buf, "  <script path='%s'/>\n", script);
    if (model != NULL)
        virBufferAsprintf(&buf, "  <model type='%s'/>\n", model);

    if (inboundStr || outboundStr) {
        virBufferAsprintf(&buf, "  <bandwidth>\n");
        if (inboundStr && inbound.average > 0) {
            virBufferAsprintf(&buf, "    <inbound average='%llu'", inbound.average);
            if (inbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", inbound.peak);
            if (inbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", inbound.burst);
            virBufferAsprintf(&buf, "/>\n");
        }
        if (outboundStr && outbound.average > 0) {
            virBufferAsprintf(&buf, "    <outbound average='%llu'", outbound.average);
            if (outbound.peak > 0)
                virBufferAsprintf(&buf, " peak='%llu'", outbound.peak);
            if (outbound.burst > 0)
                virBufferAsprintf(&buf, " burst='%llu'", outbound.burst);
            virBufferAsprintf(&buf, "/>\n");
        }
        virBufferAsprintf(&buf, "  </bandwidth>\n");
    }

    virBufferAddLit(&buf, "</interface>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        goto cleanup;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach interface"));
    } else {
        vshPrint(ctl, "%s", _("Interface attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
}

/*
 * "detach-interface" command
 */
static const vshCmdInfo info_detach_interface[] = {
    {"help", N_("detach network interface")},
    {"desc", N_("Detach network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, N_("network interface type")},
    {"mac",    VSH_OT_STRING, 0, N_("MAC address")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDetachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj=NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    const char *mac =NULL, *type = NULL;
    char *doc;
    char buf[64];
    int i = 0, diff_mac;
    int ret;
    int functionReturn = false;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "type", &type) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "mac", &mac) < 0) {
        vshError(ctl, "%s", _("missing option"));
        goto cleanup;
    }

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    VIR_FREE(doc);
    if (!xml) {
        vshError(ctl, "%s", _("Failed to get interface information"));
        goto cleanup;
    }

    snprintf(buf, sizeof(buf), "/domain/devices/interface[@type='%s']", type);
    obj = xmlXPathEval(BAD_CAST buf, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr == 0)) {
        vshError(ctl, _("No found interface whose type is %s"), type);
        goto cleanup;
    }

    if ((!mac) && (obj->nodesetval->nodeNr > 1)) {
        vshError(ctl, _("Domain has %d interfaces. Please specify which one "
                        "to detach using --mac"), obj->nodesetval->nodeNr);
        goto cleanup;
    }

    if (!mac)
        goto hit;

    /* search mac */
    for (; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "mac")) {
                char *tmp_mac = virXMLPropString(cur, "address");
                diff_mac = virMacAddrCompare(tmp_mac, mac);
                VIR_FREE(tmp_mac);
                if (!diff_mac) {
                    goto hit;
                }
            }
            cur = cur->next;
        }
    }
    vshError(ctl, _("No found interface whose MAC address is %s"), mac);
    goto cleanup;

 hit:
    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }

    if (xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0) {
        vshError(ctl, "%s", _("Failed to create XML"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         (char *)xmlBufferContent(xml_buf),
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, (char *)xmlBufferContent(xml_buf));
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach interface"));
    } else {
        vshPrint(ctl, "%s", _("Interface detached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);
    return functionReturn;
}

/*
 * "attach-disk" command
 */
static const vshCmdInfo info_attach_disk[] = {
    {"help", N_("attach disk device")},
    {"desc", N_("Attach new disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_disk[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"source",  VSH_OT_DATA, VSH_OFLAG_REQ | VSH_OFLAG_EMPTY_OK,
     N_("source of disk device")},
    {"target",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("target of disk device")},
    {"driver",    VSH_OT_STRING, 0, N_("driver of disk device")},
    {"subdriver", VSH_OT_STRING, 0, N_("subdriver of disk device")},
    {"cache",     VSH_OT_STRING, 0, N_("cache mode of disk device")},
    {"type",    VSH_OT_STRING, 0, N_("target device type")},
    {"mode",    VSH_OT_STRING, 0, N_("mode of device reading and writing")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {"sourcetype", VSH_OT_STRING, 0, N_("type of source (block|file)")},
    {"serial", VSH_OT_STRING, 0, N_("serial of disk device")},
    {"shareable", VSH_OT_BOOL, 0, N_("shareable between domains")},
    {"rawio", VSH_OT_BOOL, 0, N_("needs rawio capability")},
    {"address", VSH_OT_STRING, 0, N_("address of disk device")},
    {"multifunction", VSH_OT_BOOL, 0,
     N_("use multifunction pci under specified address")},
    {NULL, 0, 0, NULL}
};

enum {
    DISK_ADDR_TYPE_INVALID,
    DISK_ADDR_TYPE_PCI,
    DISK_ADDR_TYPE_SCSI,
    DISK_ADDR_TYPE_IDE,
};

struct PCIAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
};

struct SCSIAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int unit;
};

struct IDEAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int unit;
};

struct DiskAddress {
    int type;
    union {
        struct PCIAddress pci;
        struct SCSIAddress scsi;
        struct IDEAddress ide;
    } addr;
};

static int str2PCIAddress(const char *str, struct PCIAddress *pciAddr)
{
    char *domain, *bus, *slot, *function;

    if (!pciAddr)
        return -1;
    if (!str)
        return -1;

    domain = (char *)str;

    if (virStrToLong_ui(domain, &bus, 0, &pciAddr->domain) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &slot, 0, &pciAddr->bus) != 0)
        return -1;

    slot++;
    if (virStrToLong_ui(slot, &function, 0, &pciAddr->slot) != 0)
        return -1;

    function++;
    if (virStrToLong_ui(function, NULL, 0, &pciAddr->function) != 0)
        return -1;

    return 0;
}

static int str2SCSIAddress(const char *str, struct SCSIAddress *scsiAddr)
{
    char *controller, *bus, *unit;

    if (!scsiAddr)
        return -1;
    if (!str)
        return -1;

    controller = (char *)str;

    if (virStrToLong_ui(controller, &bus, 0, &scsiAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &unit, 0, &scsiAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_ui(unit, NULL, 0, &scsiAddr->unit) != 0)
        return -1;

    return 0;
}

static int str2IDEAddress(const char *str, struct IDEAddress *ideAddr)
{
    char *controller, *bus, *unit;

    if (!ideAddr)
        return -1;
    if (!str)
        return -1;

    controller = (char *)str;

    if (virStrToLong_ui(controller, &bus, 0, &ideAddr->controller) != 0)
        return -1;

    bus++;
    if (virStrToLong_ui(bus, &unit, 0, &ideAddr->bus) != 0)
        return -1;

    unit++;
    if (virStrToLong_ui(unit, NULL, 0, &ideAddr->unit) != 0)
        return -1;

    return 0;
}

/* pci address pci:0000.00.0x0a.0 (domain:bus:slot:function)
 * ide disk address: ide:00.00.0 (controller:bus:unit)
 * scsi disk address: scsi:00.00.0 (controller:bus:unit)
 */

static int str2DiskAddress(const char *str, struct DiskAddress *diskAddr)
{
    char *type, *addr;

    if (!diskAddr)
        return -1;
    if (!str)
        return -1;

    type = (char *)str;
    addr = strchr(type, ':');
    if (!addr)
        return -1;

    if (STREQLEN(type, "pci", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_PCI;
        return str2PCIAddress(addr + 1, &diskAddr->addr.pci);
    } else if (STREQLEN(type, "scsi", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_SCSI;
        return str2SCSIAddress(addr + 1, &diskAddr->addr.scsi);
    } else if (STREQLEN(type, "ide", addr - type)) {
        diskAddr->type = DISK_ADDR_TYPE_IDE;
        return str2IDEAddress(addr + 1, &diskAddr->addr.ide);
    }

    return -1;
}

static bool
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *source = NULL, *target = NULL, *driver = NULL,
                *subdriver = NULL, *type = NULL, *mode = NULL,
                *cache = NULL, *serial = NULL, *straddr = NULL;
    struct DiskAddress diskAddr;
    bool isFile = false, functionReturn = false;
    int ret;
    unsigned int flags;
    const char *stype = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;
    struct stat st;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) <= 0)
        goto cleanup;
    /* Allow empty string as a placeholder that implies no source, for
     * use in adding a cdrom drive with no disk.  */
    if (!*source)
        source = NULL;

    if (vshCommandOptString(cmd, "target", &target) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "driver", &driver) < 0 ||
        vshCommandOptString(cmd, "subdriver", &subdriver) < 0 ||
        vshCommandOptString(cmd, "type", &type) < 0 ||
        vshCommandOptString(cmd, "mode", &mode) < 0 ||
        vshCommandOptString(cmd, "cache", &cache) < 0 ||
        vshCommandOptString(cmd, "serial", &serial) < 0 ||
        vshCommandOptString(cmd, "address", &straddr) < 0 ||
        vshCommandOptString(cmd, "sourcetype", &stype) < 0) {
        vshError(ctl, "%s", _("missing option"));
        goto cleanup;
    }

    if (!stype) {
        if (driver && (STREQ(driver, "file") || STREQ(driver, "tap"))) {
            isFile = true;
        } else {
            if (source && !stat(source, &st))
                isFile = S_ISREG(st.st_mode) ? true : false;
        }
    } else if (STREQ(stype, "file")) {
        isFile = true;
    } else if (STRNEQ(stype, "block")) {
        vshError(ctl, _("Unknown source type: '%s'"), stype);
        goto cleanup;
    }

    if (mode) {
        if (STRNEQ(mode, "readonly") && STRNEQ(mode, "shareable")) {
            vshError(ctl, _("No support for %s in command 'attach-disk'"),
                     mode);
            goto cleanup;
        }
    }

    /* Make XML of disk */
    virBufferAsprintf(&buf, "<disk type='%s'",
                      (isFile) ? "file" : "block");
    if (type)
        virBufferAsprintf(&buf, " device='%s'", type);
    if (vshCommandOptBool (cmd, "rawio"))
        virBufferAddLit(&buf, " rawio='yes'");
    virBufferAddLit(&buf, ">\n");

    if (driver || subdriver)
        virBufferAsprintf(&buf, "  <driver");

    if (driver)
        virBufferAsprintf(&buf, " name='%s'", driver);
    if (subdriver)
        virBufferAsprintf(&buf, " type='%s'", subdriver);
    if (cache)
        virBufferAsprintf(&buf, " cache='%s'", cache);

    if (driver || subdriver || cache)
        virBufferAddLit(&buf, "/>\n");

    if (source)
        virBufferAsprintf(&buf, "  <source %s='%s'/>\n",
                          (isFile) ? "file" : "dev",
                          source);
    virBufferAsprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mode)
        virBufferAsprintf(&buf, "  <%s/>\n", mode);

    if (serial)
        virBufferAsprintf(&buf, "  <serial>%s</serial>\n", serial);

    if (vshCommandOptBool(cmd, "shareable"))
        virBufferAsprintf(&buf, "  <shareable/>\n");

    if (straddr) {
        if (str2DiskAddress(straddr, &diskAddr) != 0) {
            vshError(ctl, _("Invalid address."));
            goto cleanup;
        }

        if (STRPREFIX((const char *)target, "vd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_PCI) {
                virBufferAsprintf(&buf,
                                  "  <address type='pci' domain='0x%04x'"
                                  " bus ='0x%02x' slot='0x%02x' function='0x%0x'",
                                  diskAddr.addr.pci.domain, diskAddr.addr.pci.bus,
                                  diskAddr.addr.pci.slot, diskAddr.addr.pci.function);
                if (vshCommandOptBool(cmd, "multifunction"))
                    virBufferAddLit(&buf, " multifunction='on'");
                virBufferAddLit(&buf, "/>\n");
            } else {
                vshError(ctl, "%s", _("expecting a pci:0000.00.00.00 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "sd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_SCSI) {
                virBufferAsprintf(&buf,
                                  "  <address type='drive' controller='%d'"
                                  " bus='%d' unit='%d' />\n",
                                  diskAddr.addr.scsi.controller, diskAddr.addr.scsi.bus,
                                  diskAddr.addr.scsi.unit);
            } else {
                vshError(ctl, "%s", _("expecting a scsi:00.00.00 address."));
                goto cleanup;
            }
        } else if (STRPREFIX((const char *)target, "hd")) {
            if (diskAddr.type == DISK_ADDR_TYPE_IDE) {
                virBufferAsprintf(&buf,
                                  "  <address type='drive' controller='%d'"
                                  " bus='%d' unit='%d' />\n",
                                  diskAddr.addr.ide.controller, diskAddr.addr.ide.bus,
                                  diskAddr.addr.ide.unit);
            } else {
                vshError(ctl, "%s", _("expecting an ide:00.00.00 address."));
                goto cleanup;
            }
        }
    }

    virBufferAddLit(&buf, "</disk>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return false;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach disk"));
    } else {
        vshPrint(ctl, "%s", _("Disk attached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return functionReturn;
}

typedef enum {
    VSH_FIND_DISK_NORMAL,
    VSH_FIND_DISK_CHANGEABLE,
} vshFindDiskType;

/* Helper function to find disk device in XML doc.  Returns the disk
 * node on success, or NULL on failure. Caller must free the result
 * @path: Fully-qualified path or target of disk device.
 * @type: Either VSH_FIND_DISK_NORMAL or VSH_FIND_DISK_CHANGEABLE.
 */
static xmlNodePtr
vshFindDisk(const char *doc,
            const char *path,
            int type)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj= NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlNodePtr ret = NULL;
    int i = 0;

    xml = virXMLParseStringCtxt(doc, _("(domain_definition)"), &ctxt);
    if (!xml) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if ((obj == NULL) ||
        (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) ||
        (obj->nodesetval->nodeNr == 0)) {
        vshError(NULL, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    /* search disk using @path */
    for (; i < obj->nodesetval->nodeNr; i++) {
        bool is_supported = true;

        if (type == VSH_FIND_DISK_CHANGEABLE) {
            xmlNodePtr n = obj->nodesetval->nodeTab[i];
            is_supported = false;

            /* Check if the disk is CDROM or floppy disk */
            if (xmlStrEqual(n->name, BAD_CAST "disk")) {
                char *device_value = virXMLPropString(n, "device");

                if (STREQ(device_value, "cdrom") ||
                    STREQ(device_value, "floppy"))
                    is_supported = true;

                VIR_FREE(device_value);
            }

            if (!is_supported)
                continue;
        }

        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE) {
                char *tmp = NULL;

                if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                    if ((tmp = virXMLPropString(cur, "file")) ||
                        (tmp = virXMLPropString(cur, "dev")) ||
                        (tmp = virXMLPropString(cur, "dir")) ||
                        (tmp = virXMLPropString(cur, "name"))) {
                    }
                } else if (xmlStrEqual(cur->name, BAD_CAST "target")) {
                    tmp = virXMLPropString(cur, "dev");
                }

                if (STREQ_NULLABLE(tmp, path)) {
                    ret = xmlCopyNode(obj->nodesetval->nodeTab[i], 1);
                    VIR_FREE(tmp);
                    goto cleanup;
                }
                VIR_FREE(tmp);
            }
            cur = cur->next;
        }
    }

    vshError(NULL, _("No found disk whose source path or target is %s"), path);

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return ret;
}

typedef enum {
    VSH_PREPARE_DISK_XML_NONE = 0,
    VSH_PREPARE_DISK_XML_EJECT,
    VSH_PREPARE_DISK_XML_INSERT,
    VSH_PREPARE_DISK_XML_UPDATE,
} vshPrepareDiskXMLType;

/* Helper function to prepare disk XML. Could be used for disk
 * detaching, media changing(ejecting, inserting, updating)
 * for changeable disk. Returns the processed XML as string on
 * success, or NULL on failure. Caller must free the result.
 */
static char *
vshPrepareDiskXML(xmlNodePtr disk_node,
                  const char *source,
                  const char *path,
                  int type)
{
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    const char *disk_type = NULL;
    const char *device_type = NULL;
    xmlNodePtr new_node = NULL;
    char *ret = NULL;

    if (!disk_node)
        return NULL;

    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(NULL, "%s", _("Failed to allocate memory"));
        return NULL;
    }

    device_type = virXMLPropString(disk_node, "device");

    if (STREQ_NULLABLE(device_type, "cdrom") ||
        STREQ_NULLABLE(device_type, "floppy")) {
        bool has_source = false;
        disk_type = virXMLPropString(disk_node, "type");

        cur = disk_node->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "source")) {
                has_source = true;
                break;
            }
            cur = cur->next;
        }

        if (!has_source) {
            if (type == VSH_PREPARE_DISK_XML_EJECT) {
                vshError(NULL, _("The disk device '%s' doesn't have media"),
                         path);
                goto error;
            }

            if (source) {
                new_node = xmlNewNode(NULL, BAD_CAST "source");
                xmlNewProp(new_node, (const xmlChar *)disk_type,
                           (const xmlChar *)source);
                xmlAddChild(disk_node, new_node);
            } else if (type == VSH_PREPARE_DISK_XML_INSERT) {
                vshError(NULL, _("No source is specified for inserting media"));
                goto error;
            } else if (type == VSH_PREPARE_DISK_XML_UPDATE) {
                vshError(NULL, _("No source is specified for updating media"));
                goto error;
            }
        }

        if (has_source) {
            if (type == VSH_PREPARE_DISK_XML_INSERT) {
                vshError(NULL, _("The disk device '%s' already has media"),
                         path);
                goto error;
            }

            /* Remove the source if it tends to eject/update media. */
            xmlUnlinkNode(cur);
            xmlFreeNode(cur);

            if (source && (type == VSH_PREPARE_DISK_XML_UPDATE)) {
                new_node = xmlNewNode(NULL, BAD_CAST "source");
                xmlNewProp(new_node, (const xmlChar *)disk_type,
                           (const xmlChar *)source);
                xmlAddChild(disk_node, new_node);
            }
        }
    }

    if (xmlNodeDump(xml_buf, NULL, disk_node, 0, 0) < 0) {
        vshError(NULL, "%s", _("Failed to create XML"));
        goto error;
    }

    goto cleanup;

cleanup:
    VIR_FREE(device_type);
    VIR_FREE(disk_type);
    if (xml_buf) {
        if (VIR_ALLOC_N(ret, xmlBufferLength(xml_buf)) < 0) {
            virReportOOMError();
            return NULL;
        }
        memcpy(ret, (char *)xmlBufferContent(xml_buf), xmlBufferLength(xml_buf));
        xmlBufferFree(xml_buf);
    }
    return ret;

error:
    xmlBufferFree(xml_buf);
    xml_buf = NULL;
    goto cleanup;
}

/*
 * "detach-disk" command
 */
static const vshCmdInfo info_detach_disk[] = {
    {"help", N_("detach disk device")},
    {"desc", N_("Detach disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_disk[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"target", VSH_OT_DATA, VSH_OFLAG_REQ, N_("target of disk device")},
    {"persistent", VSH_OT_ALIAS, 0, "config"},
    {"config", VSH_OT_BOOL, 0, N_("affect next boot")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDetachDisk(vshControl *ctl, const vshCmd *cmd)
{
    char *disk_xml = NULL;
    virDomainPtr dom = NULL;
    const char *target = NULL;
    char *doc = NULL;
    int ret;
    bool functionReturn = false;
    unsigned int flags;
    xmlNodePtr disk_node = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "target", &target) <= 0)
        goto cleanup;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    if (!(disk_node = vshFindDisk(doc, target, VSH_FIND_DISK_NORMAL)))
        goto cleanup;

    if (!(disk_xml = vshPrepareDiskXML(disk_node, NULL, NULL,
                                       VSH_PREPARE_DISK_XML_NONE)))
        goto cleanup;

    if (vshCommandOptBool(cmd, "config")) {
        flags = VIR_DOMAIN_AFFECT_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         disk_xml,
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, disk_xml);
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach disk"));
    } else {
        vshPrint(ctl, "%s", _("Disk detached successfully\n"));
        functionReturn = true;
    }

 cleanup:
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    VIR_FREE(doc);
    if (dom)
        virDomainFree(dom);
    return functionReturn;
}

/*
 * "change-media" command
 */
static const vshCmdInfo info_change_media[] = {
    {"help", N_("Change media of CD or floppy drive")},
    {"desc", N_("Change media of CD or floppy drive.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_change_media[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"path", VSH_OT_DATA, VSH_OFLAG_REQ, N_("Fully-qualified path or "
                                            "target of disk device")},
    {"source", VSH_OT_DATA, 0, N_("source of the media")},
    {"eject", VSH_OT_BOOL, 0, N_("Eject the media")},
    {"insert", VSH_OT_BOOL, 0, N_("Insert the media")},
    {"update", VSH_OT_BOOL, 0, N_("Update the media")},
    {"current", VSH_OT_BOOL, 0, N_("can be either or both of --live and --config, "
                                   "depends on implementation of hypervisor driver")},
    {"live", VSH_OT_BOOL, 0, N_("alter live configuration of running domain")},
    {"config", VSH_OT_BOOL, 0, N_("alter persistent configuration, effect observed on next boot")},
    {"force",  VSH_OT_BOOL, 0, N_("force media insertion")},
    {NULL, 0, 0, NULL}
};

static bool
cmdChangeMedia(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *source = NULL;
    const char *path = NULL;
    const char *doc = NULL;
    xmlNodePtr disk_node = NULL;
    const char *disk_xml = NULL;
    int flags = 0;
    bool config, live, current, force = false;
    bool eject, insert, update = false;
    bool ret = false;
    int prepare_type = 0;
    const char *action = NULL;

    config = vshCommandOptBool(cmd, "config");
    live = vshCommandOptBool(cmd, "live");
    current = vshCommandOptBool(cmd, "current");
    force = vshCommandOptBool(cmd, "force");
    eject = vshCommandOptBool(cmd, "eject");
    insert = vshCommandOptBool(cmd, "insert");
    update = vshCommandOptBool(cmd, "update");

    if (eject + insert + update > 1) {
        vshError(ctl, "%s", _("--eject, --insert, and --update must be specified "
                            "exclusively."));
        return false;
    }

    if (eject) {
        prepare_type = VSH_PREPARE_DISK_XML_EJECT;
        action = "eject";
    }

    if (insert) {
        prepare_type = VSH_PREPARE_DISK_XML_INSERT;
        action = "insert";
    }

    if (update || (!eject && !insert)) {
        prepare_type = VSH_PREPARE_DISK_XML_UPDATE;
        action = "update";
    }

    if (current) {
        if (live || config) {
            vshError(ctl, "%s", _("--current must be specified exclusively"));
            return false;
        }
        flags = VIR_DOMAIN_AFFECT_CURRENT;
    } else {
        if (config)
            flags |= VIR_DOMAIN_AFFECT_CONFIG;
        if (live)
            flags |= VIR_DOMAIN_AFFECT_LIVE;
    }

    if (force)
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (vshCommandOptString(cmd, "path", &path) <= 0)
        goto cleanup;

    if (vshCommandOptString(cmd, "source", &source) < 0)
        goto cleanup;

    if (insert && !source) {
        vshError(ctl, "%s", _("No disk source specified for inserting"));
        goto cleanup;
    }

    if (flags & VIR_DOMAIN_AFFECT_CONFIG)
        doc = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
    else
        doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    if (!(disk_node = vshFindDisk(doc, path, VSH_FIND_DISK_CHANGEABLE)))
        goto cleanup;

    if (!(disk_xml = vshPrepareDiskXML(disk_node, source, path, prepare_type)))
        goto cleanup;

    if (virDomainUpdateDeviceFlags(dom, disk_xml, flags) != 0) {
        vshError(ctl, _("Failed to complete action %s on media"), action);
        goto cleanup;
    }

    vshPrint(ctl, _("succeeded to complete action %s on media\n"), action);
    ret = true;

cleanup:
    VIR_FREE(doc);
    xmlFreeNode(disk_node);
    VIR_FREE(disk_xml);
    if (dom)
        virDomainFree(dom);
    return ret;
}

/*
 * "cpu-compare" command
 */
static const vshCmdInfo info_cpu_compare[] = {
    {"help", N_("compare host CPU with a CPU described by an XML file")},
    {"desc", N_("compare CPU with host CPU")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_compare[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing an XML CPU description")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCPUCompare(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    int result;
    const char *snippet;

    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlBufferPtr xml_buf = NULL;
    xmlNodePtr node;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        vshError(ctl, _("Failed to read file '%s' to compare"),
                 from);
        return false;
    }

    /* try to extract the CPU element from as it would appear in a domain XML*/
    if (!(xml = virXMLParseStringCtxt(buffer, from, &ctxt)))
        goto cleanup;

    if ((node = virXPathNode("/cpu|"
                             "/domain/cpu|"
                              "/capabilities/host/cpu", ctxt))) {
        if (!(xml_buf = xmlBufferCreate())) {
            vshError(ctl, _("Can't create XML buffer to extract CPU element."));
            goto cleanup;
        }

        if (xmlNodeDump(xml_buf, xml, node, 0, 0) < 0) {
            vshError(ctl, _("Failed to extract CPU element snippet from domain XML."));
            goto cleanup;
        }

        snippet = (const char *) xmlBufferContent(xml_buf);
    } else {
        vshError(ctl, _("File '%s' does not contain a <cpu> element or is not "
                        "a valid domain or capabilities XML"), from);
        goto cleanup;
    }

    result = virConnectCompareCPU(ctl->conn, snippet, 0);

    switch (result) {
    case VIR_CPU_COMPARE_INCOMPATIBLE:
        vshPrint(ctl, _("CPU described in %s is incompatible with host CPU\n"),
                 from);
        goto cleanup;
        break;

    case VIR_CPU_COMPARE_IDENTICAL:
        vshPrint(ctl, _("CPU described in %s is identical to host CPU\n"),
                 from);
        break;

    case VIR_CPU_COMPARE_SUPERSET:
        vshPrint(ctl, _("Host CPU is a superset of CPU described in %s\n"),
                 from);
        break;

    case VIR_CPU_COMPARE_ERROR:
    default:
        vshError(ctl, _("Failed to compare host CPU with %s"), from);
        goto cleanup;
    }

    ret = true;

cleanup:
    VIR_FREE(buffer);
    xmlBufferFree(xml_buf);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;
}

/*
 * "cpu-baseline" command
 */
static const vshCmdInfo info_cpu_baseline[] = {
    {"help", N_("compute baseline CPU")},
    {"desc", N_("Compute baseline CPU for a set of given CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_baseline[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("file containing XML CPU descriptions")},
    {NULL, 0, 0, NULL}
};

static bool
cmdCPUBaseline(vshControl *ctl, const vshCmd *cmd)
{
    const char *from = NULL;
    bool ret = false;
    char *buffer;
    char *result = NULL;
    const char **list = NULL;
    int count = 0;

    xmlDocPtr xml = NULL;
    xmlNodePtr *node_list = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlBufferPtr xml_buf = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (vshCommandOptString(cmd, "file", &from) <= 0)
        return false;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return false;

    /* add a separate container around the xml */
    virBufferStrcat(&buf, "<container>", buffer, "</container>", NULL);
    if (virBufferError(&buf))
        goto no_memory;

    VIR_FREE(buffer);
    buffer = virBufferContentAndReset(&buf);


    if (!(xml = virXMLParseStringCtxt(buffer, from, &ctxt)))
        goto cleanup;

    if ((count = virXPathNodeSet("//cpu[not(ancestor::cpus)]",
                                 ctxt, &node_list)) == -1)
        goto cleanup;

    if (count == 0) {
        vshError(ctl, _("No host CPU specified in '%s'"), from);
        goto cleanup;
    }

    list = vshCalloc(ctl, count, sizeof(const char *));

    if (!(xml_buf = xmlBufferCreate()))
        goto no_memory;

    for (i = 0; i < count; i++) {
        xmlBufferEmpty(xml_buf);

        if (xmlNodeDump(xml_buf, xml,  node_list[i], 0, 0) < 0) {
            vshError(ctl, _("Failed to extract <cpu> element"));
            goto cleanup;
        }

        list[i] = vshStrdup(ctl, (const char *)xmlBufferContent(xml_buf));
    }

    result = virConnectBaselineCPU(ctl->conn, list, count, 0);

    if (result) {
        vshPrint(ctl, "%s", result);
        ret = true;
    }

cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    xmlBufferFree(xml_buf);
    VIR_FREE(result);
    if ((list != NULL) && (count > 0)) {
        for (i = 0; i < count; i++)
            VIR_FREE(list[i]);
    }
    VIR_FREE(list);
    VIR_FREE(buffer);

    return ret;

no_memory:
    vshError(ctl, "%s", _("Out of memory"));
    ret = false;
    goto cleanup;
}

/* Common code for the edit / net-edit / pool-edit functions which follow. */
static char *
editWriteToTempFile (vshControl *ctl, const char *doc)
{
    char *ret;
    const char *tmpdir;
    int fd;

    ret = vshMalloc(ctl, PATH_MAX);

    tmpdir = getenv ("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    snprintf (ret, PATH_MAX, "%s/virshXXXXXX.xml", tmpdir);
    fd = mkstemps(ret, 4);
    if (fd == -1) {
        vshError(ctl, _("mkstemps: failed to create temporary file: %s"),
                 strerror(errno));
        VIR_FREE(ret);
        return NULL;
    }

    if (safewrite (fd, doc, strlen (doc)) == -1) {
        vshError(ctl, _("write: %s: failed to write to temporary file: %s"),
                 ret, strerror(errno));
        VIR_FORCE_CLOSE(fd);
        unlink (ret);
        VIR_FREE(ret);
        return NULL;
    }
    if (VIR_CLOSE(fd) < 0) {
        vshError(ctl, _("close: %s: failed to write or close temporary file: %s"),
                 ret, strerror(errno));
        unlink (ret);
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
editFile (vshControl *ctl, const char *filename)
{
    const char *editor;
    virCommandPtr cmd;
    int ret = -1;
    int outfd = STDOUT_FILENO;
    int errfd = STDERR_FILENO;

    editor = getenv ("VISUAL");
    if (!editor)
        editor = getenv ("EDITOR");
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
    if (strspn (editor, ACCEPTED_CHARS) != strlen (editor)) {
        if (strspn (filename, ACCEPTED_CHARS) != strlen (filename)) {
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
editReadBackFile (vshControl *ctl, const char *filename)
{
    char *ret;

    if (virFileReadAll (filename, VIRSH_MAX_XML_FILE, &ret) == -1) {
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
        uid_t uid = geteuid();
        dir = dir_malloced = virGetUserDirectory(uid);
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
        vshPrint (ctl, _("%s\n"), cwd);
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
cmdEcho (vshControl *ctl, const vshCmd *cmd)
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
 * "edit" command
 */
static const vshCmdInfo info_edit[] = {
    {"help", N_("edit XML configuration for a domain")},
    {"desc", N_("Edit the XML configuration for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_edit[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

/* This function also acts as a template to generate cmdNetworkEdit
 * and cmdPoolEdit functions (below) using a sed script in the Makefile.
 */
static bool
cmdEdit (vshControl *ctl, const vshCmd *cmd)
{
    bool ret = false;
    virDomainPtr dom = NULL;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;
    unsigned int flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain (ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    /* Get the XML configuration of the domain. */
    doc = virDomainGetXMLDesc (dom, flags);
    if (!doc)
        goto cleanup;

    /* Create and open the temporary file. */
    tmp = editWriteToTempFile (ctl, doc);
    if (!tmp) goto cleanup;

    /* Start the editor. */
    if (editFile (ctl, tmp) == -1) goto cleanup;

    /* Read back the edited file. */
    doc_edited = editReadBackFile (ctl, tmp);
    if (!doc_edited) goto cleanup;

    /* Compare original XML with edited.  Has it changed at all? */
    if (STREQ (doc, doc_edited)) {
        vshPrint (ctl, _("Domain %s XML configuration not changed.\n"),
                  virDomainGetName (dom));
        ret = true;
        goto cleanup;
    }

    /* Now re-read the domain XML.  Did someone else change it while
     * it was being edited?  This also catches problems such as us
     * losing a connection or the domain going away.
     */
    doc_reread = virDomainGetXMLDesc (dom, flags);
    if (!doc_reread)
        goto cleanup;

    if (STRNEQ (doc, doc_reread)) {
        vshError(ctl,
                 "%s", _("ERROR: the XML configuration was changed by another user"));
        goto cleanup;
    }

    /* Everything checks out, so redefine the domain. */
    virDomainFree (dom);
    dom = virDomainDefineXML (ctl->conn, doc_edited);
    if (!dom)
        goto cleanup;

    vshPrint (ctl, _("Domain %s XML configuration edited.\n"),
              virDomainGetName(dom));

    ret = true;

 cleanup:
    if (dom)
        virDomainFree (dom);

    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    VIR_FREE(doc_reread);

    if (tmp) {
        unlink (tmp);
        VIR_FREE(tmp);
    }

    return ret;
}


/*
 * "net-edit" command
 */
static const vshCmdInfo info_network_edit[] = {
    {"help", N_("edit XML configuration for a network")},
    {"desc", N_("Edit the XML configuration for a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_edit[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

/* This is generated from this file by a sed script in the Makefile. */
#include "virsh-net-edit.c"

/*
 * "pool-edit" command
 */
static const vshCmdInfo info_pool_edit[] = {
    {"help", N_("edit XML configuration for a storage pool")},
    {"desc", N_("Edit the XML configuration for a storage pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_edit[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

/* This is generated from this file by a sed script in the Makefile. */
#include "virsh-pool-edit.c"

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
            memmove(&tmp[1], &tmp[2], len - (tmp - spec) + 2);
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
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
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

    /* Get the XML configuration of the snapshot.  */
    doc = virDomainSnapshotGetXMLDesc(snapshot, getxml_flags);
    if (!doc)
        goto cleanup;

    /* strstr is safe here, since xml came from libvirt API and not user */
    if (strstr(doc, "<state>disk-snapshot</state>"))
        define_flags |= VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY;

    /* Create and open the temporary file.  */
    tmp = editWriteToTempFile(ctl, doc);
    if (!tmp)
        goto cleanup;

    /* Start the editor.  */
    if (editFile(ctl, tmp) == -1)
        goto cleanup;

    /* Read back the edited file.  */
    doc_edited = editReadBackFile(ctl, tmp);
    if (!doc_edited)
        goto cleanup;

    /* Compare original XML with edited.  Short-circuit if it did not
     * change, and we do not have any flags.  */
    if (STREQ(doc, doc_edited) &&
        !(define_flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)) {
        vshPrint(ctl, _("Snapshot %s XML configuration not changed.\n"),
                 name);
        ret = true;
        goto cleanup;
    }

    /* Everything checks out, so redefine the xml.  */
    edited = virDomainSnapshotCreateXML(dom, doc_edited, define_flags);
    if (!edited) {
        vshError(ctl, _("Failed to update %s"), name);
        goto cleanup;
    }

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
    VIR_FREE(doc);
    VIR_FREE(doc_edited);
    if (tmp) {
        unlink(tmp);
        VIR_FREE(tmp);
    }
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (edited)
        virDomainSnapshotFree(edited);
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
    {"metadata", VSH_OT_BOOL, 0,
     N_("list only snapshots that have metadata that would prevent undefine")},
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
    int parent_filter = 0; /* -1 for roots filtering, 0 for no parent
                              information needed, 1 for parent column */
    int numsnaps;
    char **names = NULL;
    char **parents = NULL;
    int actual = 0;
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
    const char *from = NULL;
    virDomainSnapshotPtr start = NULL;
    int start_index = -1;
    bool descendants = false;

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
        parent_filter = 1;
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

    if (vshCommandOptBool(cmd, "metadata")) {
        flags |= VIR_DOMAIN_SNAPSHOT_LIST_METADATA;
    }

    if (from) {
        descendants = vshCommandOptBool(cmd, "descendants");
        if (descendants || tree) {
            flags |= VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
        }
        numsnaps = ctl->useSnapshotOld ? -1 :
            virDomainSnapshotNumChildren(start, flags);
        if (numsnaps < 0) {
            if (ctl->useSnapshotOld ||
                last_error->code == VIR_ERR_NO_SUPPORT) {
                /* We can emulate --from.  */
                /* XXX can we also emulate --leaves? */
                virFreeError(last_error);
                last_error = NULL;
                ctl->useSnapshotOld = true;
                flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS;
                numsnaps = virDomainSnapshotNum(dom, flags);
            }
        } else if (tree) {
            numsnaps++;
        }
    } else {
        numsnaps = virDomainSnapshotNum(dom, flags);

        /* Fall back to simulation if --roots was unsupported. */
        /* XXX can we also emulate --leaves? */
        if (numsnaps < 0 && last_error->code == VIR_ERR_INVALID_ARG &&
            (flags & VIR_DOMAIN_SNAPSHOT_LIST_ROOTS)) {
            virFreeError(last_error);
            last_error = NULL;
            parent_filter = -1;
            flags &= ~VIR_DOMAIN_SNAPSHOT_LIST_ROOTS;
            numsnaps = virDomainSnapshotNum(dom, flags);
        }
    }

    if (numsnaps < 0) {
        if (!last_error)
            vshError(ctl, _("missing support"));
        goto cleanup;
    }

    if (!tree) {
        if (parent_filter > 0)
            vshPrintExtra(ctl, " %-20s %-25s %-15s %s",
                          _("Name"), _("Creation Time"), _("State"),
                          _("Parent"));
        else
            vshPrintExtra(ctl, " %-20s %-25s %s",
                          _("Name"), _("Creation Time"), _("State"));
        vshPrintExtra(ctl, "\n\
------------------------------------------------------------\n");
    }

    if (!numsnaps) {
        ret = true;
        goto cleanup;
    }

    if (VIR_ALLOC_N(names, numsnaps) < 0)
        goto cleanup;

    if (from && !ctl->useSnapshotOld) {
        /* When mixing --from and --tree, we want to start the tree at the
         * given snapshot.  Without --tree, only list the children.  */
        if (tree) {
            if (numsnaps)
                actual = virDomainSnapshotListChildrenNames(start, names + 1,
                                                            numsnaps - 1,
                                                            flags);
            if (actual >= 0) {
                actual++;
                names[0] = vshStrdup(ctl, from);
            }
        } else {
            actual = virDomainSnapshotListChildrenNames(start, names,
                                                        numsnaps, flags);
        }
    } else {
        actual = virDomainSnapshotListNames(dom, names, numsnaps, flags);
    }
    if (actual < 0)
        goto cleanup;

    qsort(&names[0], actual, sizeof(char*), namesorter);

    if (tree || ctl->useSnapshotOld) {
        parents = vshCalloc(ctl, sizeof(char *), actual);
        for (i = (from && !ctl->useSnapshotOld); i < actual; i++) {
            if (ctl->useSnapshotOld && STREQ(names[i], from)) {
                start_index = i;
                continue;
            }

            /* free up memory from previous iterations of the loop */
            if (snapshot)
                virDomainSnapshotFree(snapshot);
            snapshot = virDomainSnapshotLookupByName(dom, names[i], 0);
            if (!snapshot ||
                vshGetSnapshotParent(ctl, snapshot, &parents[i]) < 0) {
                while (--i >= 0)
                    VIR_FREE(parents[i]);
                VIR_FREE(parents);
                goto cleanup;
            }
        }
    }
    if (tree) {
        char indentBuf[INDENT_BUFLEN];
        for (i = 0 ; i < actual ; i++) {
            memset(indentBuf, '\0', sizeof(indentBuf));
            if (ctl->useSnapshotOld ? STREQ(names[i], from) : !parents[i])
                cmdNodeListDevicesPrint(ctl,
                                        names,
                                        parents,
                                        actual,
                                        i,
                                        i,
                                        0,
                                        0,
                                        indentBuf);
        }

        ret = true;
        goto cleanup;
    } else {
        if (ctl->useSnapshotOld && descendants) {
            bool changed = false;

            /* Make multiple passes over the list - first pass NULLs
             * out all roots except start, remaining passes NULL out
             * any entry whose parent is not still in list.  Also, we
             * NULL out parent when name is known to be in list.
             * Sorry, this is O(n^3) - hope your hierarchy isn't huge.  */
            if (start_index < 0) {
                vshError(ctl, _("snapshot %s disappeared from list"), from);
                goto cleanup;
            }
            for (i = 0; i < actual; i++) {
                if (i == start_index)
                    continue;
                if (!parents[i]) {
                    VIR_FREE(names[i]);
                } else if (STREQ(parents[i], from)) {
                    VIR_FREE(parents[i]);
                    changed = true;
                }
            }
            if (!changed) {
                ret = true;
                goto cleanup;
            }
            while (changed) {
                changed = false;
                for (i = 0; i < actual; i++) {
                    bool found = false;
                    int j;

                    if (!names[i] || !parents[i])
                        continue;
                    for (j = 0; j < actual; j++) {
                        if (!names[j] || i == j)
                            continue;
                        if (STREQ(parents[i], names[j])) {
                            found = true;
                            if (!parents[j])
                                VIR_FREE(parents[i]);
                            break;
                        }
                    }
                    if (!found) {
                        changed = true;
                        VIR_FREE(names[i]);
                    }
                }
            }
            VIR_FREE(names[start_index]);
        }

        for (i = 0; i < actual; i++) {
            if (ctl->useSnapshotOld &&
                (descendants ? !names[i] : STRNEQ_NULLABLE(parents[i], from)))
                continue;

            /* free up memory from previous iterations of the loop */
            VIR_FREE(parent);
            VIR_FREE(state);
            if (snapshot)
                virDomainSnapshotFree(snapshot);
            xmlXPathFreeContext(ctxt);
            xmlFreeDoc(xml);
            VIR_FREE(doc);

            snapshot = virDomainSnapshotLookupByName(dom, names[i], 0);
            if (snapshot == NULL)
                continue;

            doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
            if (!doc)
                continue;

            xml = virXMLParseStringCtxt(doc, _("(domain_snapshot)"), &ctxt);
            if (!xml)
                continue;

            if (parent_filter) {
                parent = virXPathString("string(/domainsnapshot/parent/name)",
                                        ctxt);
                if (!parent && parent_filter < 0)
                    continue;
            }

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
                         names[i], timestr, state, parent);
            else
                vshPrint(ctl, " %-20s %-25s %s\n", names[i], timestr, state);
        }
    }

    ret = true;

cleanup:
    /* this frees up memory from the last iteration of the loop */
    VIR_FREE(parent);
    VIR_FREE(state);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (start)
        virDomainSnapshotFree(start);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(doc);
    for (i = 0; i < actual; i++) {
        VIR_FREE(names[i]);
        if (parents)
            VIR_FREE(parents[i]);
    }
    VIR_FREE(names);
    VIR_FREE(parents);
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
 * "domblkerror" command
 */
static const char *
vshDomainIOErrorToString(int error)
{
    switch ((virDomainDiskErrorCode) error) {
    case VIR_DOMAIN_DISK_ERROR_NONE:
        return _("no error");
    case VIR_DOMAIN_DISK_ERROR_UNSPEC:
        return _("unspecified error");
    case VIR_DOMAIN_DISK_ERROR_NO_SPACE:
        return _("no space");
    case VIR_DOMAIN_DISK_ERROR_LAST:
        ;
    }

    return _("unknown error");
}

static const vshCmdInfo info_domblkerror[] = {
    {"help", N_("Show errors on block devices")},
    {"desc", N_("Show block device errors")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domblkerror[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id, or uuid")},
    {NULL, 0, 0, NULL}
};

static bool
cmdDomBlkError(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainDiskErrorPtr disks = NULL;
    unsigned int ndisks;
    int i;
    int count;
    bool ret = false;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return false;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return false;

    if ((count = virDomainGetDiskErrors(dom, NULL, 0, 0)) < 0)
        goto cleanup;
    ndisks = count;

    if (ndisks) {
        if (VIR_ALLOC_N(disks, ndisks) < 0)
            goto cleanup;

        if ((count = virDomainGetDiskErrors(dom, disks, ndisks, 0)) == -1)
            goto cleanup;
    }

    if (count == 0) {
        vshPrint(ctl, _("No errors found\n"));
    } else {
        for (i = 0; i < count; i++) {
            vshPrint(ctl, "%s: %s\n",
                     disks[i].disk,
                     vshDomainIOErrorToString(disks[i].error));
        }
    }

    ret = true;

cleanup:
    VIR_FREE(disks);
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
    {"blockpull", cmdBlockPull, opts_block_pull, info_block_pull, 0},
    {"blockjob", cmdBlockJob, opts_block_job, info_block_job, 0},
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
    int num;
    char *end_p = NULL;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    num = strtol(arg->data, &end_p, 10);
    if ((arg->data != end_p) && (*end_p == 0)) {
        *value = num;
        return 1;
    }
    return -1;
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
    unsigned int num;
    char *end_p = NULL;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    num = strtoul(arg->data, &end_p, 10);
    if ((arg->data != end_p) && (*end_p == 0)) {
        *value = num;
        return 1;
    }
    return -1;
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
    unsigned long num;
    char *end_p = NULL;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    num = strtoul(arg->data, &end_p, 10);
    if ((arg->data != end_p) && (*end_p == 0)) {
        *value = num;
        return 1;
    }
    return -1;
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
    long long num;
    char *end_p = NULL;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    num = strtoll(arg->data, &end_p, 10);
    if ((arg->data != end_p) && (*end_p == 0)) {
        *value = num;
        return 1;
    }
    return -1;
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
    unsigned long long num;
    char *end_p = NULL;

    ret = vshCommandOpt(cmd, name, &arg);
    if (ret <= 0)
        return ret;
    if (!arg->data) {
        /* only possible on bool, but if name is bool, this is a
         * programming bug */
        return -2;
    }

    num = strtoull(arg->data, &end_p, 10);
    if ((arg->data != end_p) && (*end_p == 0)) {
        *value = num;
        return 1;
    }
    return -1;
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
cmd_has_option (vshControl *ctl, const vshCmd *cmd, const char *optname)
{
    /* Iterate through cmd->opts, to ensure that there is an entry
       with name OPTNAME and type VSH_OT_DATA. */
    bool found = false;
    const vshCmdOpt *opt;
    for (opt = cmd->opts; opt; opt = opt->next) {
        if (STREQ (opt->def->name, optname) && opt->def->type == VSH_OT_DATA) {
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
    if (!cmd_has_option (ctl, cmd, optname))
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

static virNetworkPtr
vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                       const char **name, int flag)
{
    virNetworkPtr network = NULL;
    const char *n = NULL;
    const char *optname = "network";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network UUID\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (network==NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as network NAME\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByName(ctl->conn, n);
    }

    if (!network)
        vshError(ctl, _("failed to get network '%s'"), n);

    return network;
}


static virNWFilterPtr
vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                        const char **name, int flag)
{
    virNWFilterPtr nwfilter = NULL;
    const char *n = NULL;
    const char *optname = "nwfilter";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
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
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by NAME */
    if ((flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface NAME\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByName(ctl->conn, n);
    }
    /* try it by MAC */
    if ((iface == NULL) && (flag & VSH_BYMAC)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as interface MAC\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByMACString(ctl->conn, n);
    }

    if (!iface)
        vshError(ctl, _("failed to get interface '%s'"), n);

    return iface;
}

static virStoragePoolPtr
vshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd, const char *optname,
                    const char **name, int flag)
{
    virStoragePoolPtr pool = NULL;
    const char *n = NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as pool UUID\n",
                 cmd->def->name, optname);
        pool = virStoragePoolLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (pool == NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as pool NAME\n",
                 cmd->def->name, optname);
        pool = virStoragePoolLookupByName(ctl->conn, n);
    }

    if (!pool)
        vshError(ctl, _("failed to get pool '%s'"), n);

    return pool;
}

static virStorageVolPtr
vshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                   const char *optname,
                   const char *pooloptname,
                   const char **name, int flag)
{
    virStorageVolPtr vol = NULL;
    virStoragePoolPtr pool = NULL;
    const char *n = NULL, *p = NULL;

    if (vshCommandOptString(cmd, optname, &n) <= 0)
        return NULL;

    if (pooloptname != NULL && vshCommandOptString(cmd, pooloptname, &p) < 0) {
        vshError(ctl, "%s", _("missing option"));
        return NULL;
    }

    if (p)
        pool = vshCommandOptPoolBy(ctl, cmd, pooloptname, name, flag);

    vshDebug(ctl, VSH_ERR_DEBUG, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by name */
    if (pool && (flag & VSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol name\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    /* try it by key */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(ctl->conn, n);
    }
    /* try it by path */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <%s> trying as vol path\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByPath(ctl->conn, n);
    }

    if (!vol) {
        if (pool)
            vshError(ctl, _("failed to get vol '%s'"), n);
        else
            vshError(ctl, _("failed to get vol '%s', specifying --%s "
                            "might help"), n, pooloptname);
    }

    if (pool)
        virStoragePoolFree(pool);

    return vol;
}

static virSecretPtr
vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, const char **name)
{
    virSecretPtr secret = NULL;
    const char *n = NULL;
    const char *optname = "secret";

    if (!cmd_has_option (ctl, cmd, optname))
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
    vshCommandToken (*getNextArg)(vshControl *, struct __vshCommandParser *,
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

static const char *
vshDomainStateToString(int state)
{
    /* Can't use virDomainStateTypeToString, because we want to mark
     * strings for translation.  */
    switch ((virDomainState) state) {
    case VIR_DOMAIN_RUNNING:
        return N_("running");
    case VIR_DOMAIN_BLOCKED:
        return N_("idle");
    case VIR_DOMAIN_PAUSED:
        return N_("paused");
    case VIR_DOMAIN_SHUTDOWN:
        return N_("in shutdown");
    case VIR_DOMAIN_SHUTOFF:
        return N_("shut off");
    case VIR_DOMAIN_CRASHED:
        return N_("crashed");
    case VIR_DOMAIN_PMSUSPENDED:
        return N_("pmsuspended");
    case VIR_DOMAIN_NOSTATE:
    default:
        ;/*FALLTHROUGH*/
    }
    return N_("no state");  /* = dom0 state */
}

static const char *
vshDomainStateReasonToString(int state, int reason)
{
    switch ((virDomainState) state) {
    case VIR_DOMAIN_NOSTATE:
        switch ((virDomainNostateReason) reason) {
        case VIR_DOMAIN_NOSTATE_UNKNOWN:
        case VIR_DOMAIN_NOSTATE_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_RUNNING:
        switch ((virDomainRunningReason) reason) {
        case VIR_DOMAIN_RUNNING_BOOTED:
            return N_("booted");
        case VIR_DOMAIN_RUNNING_MIGRATED:
            return N_("migrated");
        case VIR_DOMAIN_RUNNING_RESTORED:
            return N_("restored");
        case VIR_DOMAIN_RUNNING_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_RUNNING_UNPAUSED:
            return N_("unpaused");
        case VIR_DOMAIN_RUNNING_MIGRATION_CANCELED:
            return N_("migration canceled");
        case VIR_DOMAIN_RUNNING_SAVE_CANCELED:
            return N_("save canceled");
        case VIR_DOMAIN_RUNNING_WAKEUP:
            return N_("event wakeup");
        case VIR_DOMAIN_RUNNING_UNKNOWN:
        case VIR_DOMAIN_RUNNING_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_BLOCKED:
        switch ((virDomainBlockedReason) reason) {
        case VIR_DOMAIN_BLOCKED_UNKNOWN:
        case VIR_DOMAIN_BLOCKED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_PAUSED:
        switch ((virDomainPausedReason) reason) {
        case VIR_DOMAIN_PAUSED_USER:
            return N_("user");
        case VIR_DOMAIN_PAUSED_MIGRATION:
            return N_("migrating");
        case VIR_DOMAIN_PAUSED_SAVE:
            return N_("saving");
        case VIR_DOMAIN_PAUSED_DUMP:
            return N_("dumping");
        case VIR_DOMAIN_PAUSED_IOERROR:
            return N_("I/O error");
        case VIR_DOMAIN_PAUSED_WATCHDOG:
            return N_("watchdog");
        case VIR_DOMAIN_PAUSED_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_PAUSED_SHUTTING_DOWN:
            return N_("shutting down");
        case VIR_DOMAIN_PAUSED_UNKNOWN:
        case VIR_DOMAIN_PAUSED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_SHUTDOWN:
        switch ((virDomainShutdownReason) reason) {
        case VIR_DOMAIN_SHUTDOWN_USER:
            return N_("user");
        case VIR_DOMAIN_SHUTDOWN_UNKNOWN:
        case VIR_DOMAIN_SHUTDOWN_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_SHUTOFF:
        switch ((virDomainShutoffReason) reason) {
        case VIR_DOMAIN_SHUTOFF_SHUTDOWN:
            return N_("shutdown");
        case VIR_DOMAIN_SHUTOFF_DESTROYED:
            return N_("destroyed");
        case VIR_DOMAIN_SHUTOFF_CRASHED:
            return N_("crashed");
        case VIR_DOMAIN_SHUTOFF_MIGRATED:
            return N_("migrated");
        case VIR_DOMAIN_SHUTOFF_SAVED:
            return N_("saved");
        case VIR_DOMAIN_SHUTOFF_FAILED:
            return N_("failed");
        case VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT:
            return N_("from snapshot");
        case VIR_DOMAIN_SHUTOFF_UNKNOWN:
        case VIR_DOMAIN_SHUTOFF_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_CRASHED:
        switch ((virDomainCrashedReason) reason) {
        case VIR_DOMAIN_CRASHED_UNKNOWN:
        case VIR_DOMAIN_CRASHED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_PMSUSPENDED:
        switch ((virDomainPMSuspendedReason) reason) {
        case VIR_DOMAIN_PMSUSPENDED_UNKNOWN:
        case VIR_DOMAIN_PMSUSPENDED_LAST:
            ;
        }
        break;

    case VIR_DOMAIN_LAST:
        ;
    }

    return N_("unknown");
}

/* extract description or title from domain xml */
static char *
vshGetDomainDescription(vshControl *ctl, virDomainPtr dom, bool title,
                        unsigned int flags)
{
    char *desc = NULL;
    char *domxml = NULL;
    virErrorPtr err = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int type;

    if (title)
        type = VIR_DOMAIN_METADATA_TITLE;
    else
        type = VIR_DOMAIN_METADATA_DESCRIPTION;

    if ((desc = virDomainGetMetadata(dom, type, NULL, flags))) {
        return desc;
    } else {
        err = virGetLastError();

        if (err && err->code == VIR_ERR_NO_DOMAIN_METADATA) {
            desc = vshStrdup(ctl, "");
            virResetLastError();
            return desc;
        }

        if (err && err->code != VIR_ERR_NO_SUPPORT)
            return desc;
    }

    /* fall back to xml */
    /* get domain's xml description and extract the title/description */
    if (!(domxml = virDomainGetXMLDesc(dom, flags))) {
        vshError(ctl, "%s", _("Failed to retrieve domain XML"));
        goto cleanup;
    }
    doc = virXMLParseStringCtxt(domxml, _("(domain_definition)"), &ctxt);
    if (!doc) {
        vshError(ctl, "%s", _("Couldn't parse domain XML"));
        goto cleanup;
    }
    if (title)
        desc = virXPathString("string(./title[1])", ctxt);
    else
        desc = virXPathString("string(./description[1])", ctxt);

    if (!desc)
        desc = vshStrdup(ctl, "");

cleanup:
    VIR_FREE(domxml);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);

    return desc;
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

static const char *
vshDomainControlStateToString(int state)
{
    switch ((virDomainControlState) state) {
    case VIR_DOMAIN_CONTROL_OK:
        return N_("ok");
    case VIR_DOMAIN_CONTROL_JOB:
        return N_("background job");
    case VIR_DOMAIN_CONTROL_OCCUPIED:
        return N_("occupied");
    case VIR_DOMAIN_CONTROL_ERROR:
        return N_("error");
    default:
        ;
    }

    return N_("unknown");
}

static const char *
vshDomainVcpuStateToString(int state)
{
    switch (state) {
    case VIR_VCPU_OFFLINE:
        return N_("offline");
    case VIR_VCPU_BLOCKED:
        return N_("idle");
    case VIR_VCPU_RUNNING:
        return N_("running");
    default:
        ;/*FALLTHROUGH*/
    }
    return N_("no state");
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

    /* Prepare to read/write history from/to the ~/.virsh/history file */
    userdir = virGetUserDirectory(getuid());

    if (userdir == NULL) {
        vshError(ctl, "%s", _("Could not determine home directory"));
        return -1;
    }

    if (virAsprintf(&ctl->historydir, "%s/.virsh", userdir) < 0) {
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
vshReadlineDeinit (vshControl *ctl)
{
    if (ctl->historyfile != NULL) {
        if (mkdir(ctl->historydir, 0755) < 0 && errno != EEXIST) {
            char ebuf[1024];
            vshError(ctl, _("Failed to create '%s': %s"),
                     ctl->historydir, virStrerror(errno, ebuf, sizeof(ebuf)));
        } else
            write_history(ctl->historyfile);
    }

    VIR_FREE(ctl->historydir);
    VIR_FREE(ctl->historyfile);
}

static char *
vshReadline (vshControl *ctl ATTRIBUTE_UNUSED, const char *prompt)
{
    return readline (prompt);
}

#else /* !USE_READLINE */

static int
vshReadlineInit (vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* empty */
    return 0;
}

static void
vshReadlineDeinit (vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* empty */
}

static char *
vshReadline (vshControl *ctl, const char *prompt)
{
    char line[1024];
    char *r;
    int len;

    fputs (prompt, stdout);
    r = fgets (line, sizeof(line), stdin);
    if (r == NULL) return NULL; /* EOF */

    /* Chomp trailing \n */
    len = strlen (r);
    if (len > 0 && r[len-1] == '\n')
        r[len-1] = '\0';

    return vshStrdup (ctl, r);
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
#ifdef WITH_XEN
    vshPrint(ctl, " Xen");
#endif
#ifdef WITH_QEMU
    vshPrint(ctl, " QEmu/KVM");
#endif
#ifdef WITH_UML
    vshPrint(ctl, " UML");
#endif
#ifdef WITH_OPENVZ
    vshPrint(ctl, " OpenVZ");
#endif
#ifdef WITH_VBOX
    vshPrint(ctl, " VirtualBox");
#endif
#ifdef WITH_XENAPI
    vshPrint(ctl, " XenAPI");
#endif
#ifdef WITH_LXC
    vshPrint(ctl, " LXC");
#endif
#ifdef WITH_ESX
    vshPrint(ctl, " ESX");
#endif
#ifdef WITH_PHYP
    vshPrint(ctl, " PHYP");
#endif
#ifdef WITH_ONE
    vshPrint(ctl, " ONE");
#endif
#ifdef WITH_TEST
    vshPrint(ctl, " Test");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Networking:"));
#ifdef WITH_REMOTE
    vshPrint(ctl, " Remote");
#endif
#ifdef WITH_PROXY
    vshPrint(ctl, " Proxy");
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
    vshPrint(ctl, " Netcf");
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
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Miscellaneous:"));
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
#ifdef WITH_DTRACE
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

/*
 * argv[]:  virsh [options] [command]
 *
 */
static bool
vshParseArgv(vshControl *ctl, int argc, char **argv)
{
    bool help = false;
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
            help = true;
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

            if ((len == 2 && *optarg == '^') ||
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

    if (help) {
        if (optind < argc) {
            vshError(ctl, _("extra argument '%s'. See --help."), argv[optind]);
            exit(EXIT_FAILURE);
        }

        /* list all command */
        vshUsage();
        exit(EXIT_SUCCESS);
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
