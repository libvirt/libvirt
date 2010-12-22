/*
 * virsh.c: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2010 Red Hat, Inc.
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
#include "files.h"
#include "../daemon/event.h"
#include "configmake.h"

static char *progname;

#ifndef TRUE
# define TRUE 1
# define FALSE 0
#endif

#define VIRSH_MAX_XML_FILE 10*1024*1024

#define VSH_PROMPT_RW    "virsh # "
#define VSH_PROMPT_RO    "virsh > "

#define GETTIMEOFDAY(T) gettimeofday(T, NULL)
#define DIFF_MSEC(T, U) \
        ((((int) ((T)->tv_sec - (U)->tv_sec)) * 1000000.0 + \
          ((int) ((T)->tv_usec - (U)->tv_usec))) / 1000.0)

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
    VSH_OT_ARGV      /* remaining arguments, opt->name should be "" */
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
#define VSH_OFLAG_NONE    0     /* without flags */
#define VSH_OFLAG_REQ    (1 << 1)       /* option required */

/* dummy */
typedef struct __vshControl vshControl;
typedef struct __vshCmd vshCmd;

/*
 * vshCmdInfo -- information about command
 */
typedef struct {
    const char *name;           /* name of information */
    const char *data;           /* information */
} vshCmdInfo;

/*
 * vshCmdOptDef - command option definition
 */
typedef struct {
    const char *name;           /* the name of option */
    vshCmdOptType type;         /* option type */
    int flag;                   /* flags */
    const char *help;           /* help string */
} vshCmdOptDef;

/*
 * vshCmdOpt - command options
 */
typedef struct vshCmdOpt {
    const vshCmdOptDef *def;    /* pointer to relevant option */
    char *data;                 /* allocated data */
    struct vshCmdOpt *next;
} vshCmdOpt;

/*
 * vshCmdDef - command definition
 */
typedef struct {
    const char *name;
    int (*handler) (vshControl *, const vshCmd *);    /* command handler */
    const vshCmdOptDef *opts;   /* definition of command options */
    const vshCmdInfo *info;     /* details about command */
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
    int imode;                  /* interactive mode? */
    int quiet;                  /* quiet mode */
    int debug;                  /* print debug messages? */
    int timing;                 /* print timing info? */
    int readonly;               /* connect readonly (first time only, not
                                 * during explicit connect command)
                                 */
    char *logfile;              /* log file name */
    int log_fd;                 /* log file descriptor */
    char *historydir;           /* readline history directory name */
    char *historyfile;          /* readline history file name */
} __vshControl;

typedef struct vshCmdGrp {
    const char *name;
    const char *keyword; /* help keyword */
    const vshCmdDef *commands;
} vshCmdGrp;

static const vshCmdGrp cmdGroups[];

static void vshError(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
static int vshInit(vshControl *ctl);
static int vshDeinit(vshControl *ctl);
static void vshUsage(void);
static void vshOpenLogFile(vshControl *ctl);
static void vshOutputLogFile(vshControl *ctl, int log_level, const char *format, va_list ap);
static void vshCloseLogFile(vshControl *ctl);

static int vshParseArgv(vshControl *ctl, int argc, char **argv);

static const char *vshCmddefGetInfo(const vshCmdDef *cmd, const char *info);
static const vshCmdDef *vshCmddefSearch(const char *cmdname);
static int vshCmddefHelp(vshControl *ctl, const char *name);
static const vshCmdGrp *vshCmdGrpSearch(const char *grpname);
static int vshCmdGrpHelp(vshControl *ctl, const char *name);

static vshCmdOpt *vshCommandOpt(const vshCmd *cmd, const char *name);
static int vshCommandOptInt(const vshCmd *cmd, const char *name, int *found);
static unsigned long vshCommandOptUL(const vshCmd *cmd, const char *name,
                                     int *found);
static char *vshCommandOptString(const vshCmd *cmd, const char *name,
                                 int *found);
static long long vshCommandOptLongLong(const vshCmd *cmd, const char *name,
                                       int *found);
static int vshCommandOptBool(const vshCmd *cmd, const char *name);
static char *vshCommandOptArgv(const vshCmd *cmd, int count);

#define VSH_BYID     (1 << 1)
#define VSH_BYUUID   (1 << 2)
#define VSH_BYNAME   (1 << 3)
#define VSH_BYMAC    (1 << 4)

static virDomainPtr vshCommandOptDomainBy(vshControl *ctl, const vshCmd *cmd,
                                          char **name, int flag);

/* default is lookup by Id, Name and UUID */
#define vshCommandOptDomain(_ctl, _cmd, _name)                      \
    vshCommandOptDomainBy(_ctl, _cmd, _name, VSH_BYID|VSH_BYUUID|VSH_BYNAME)

static virNetworkPtr vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                                            char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptNetwork(_ctl, _cmd, _name)                    \
    vshCommandOptNetworkBy(_ctl, _cmd, _name,                      \
                           VSH_BYUUID|VSH_BYNAME)

static virNWFilterPtr vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                                                  char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptNWFilter(_ctl, _cmd, _name)                    \
    vshCommandOptNWFilterBy(_ctl, _cmd, _name,                      \
                            VSH_BYUUID|VSH_BYNAME)

static virInterfacePtr vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                                                char **name, int flag);

/* default is lookup by Name and MAC */
#define vshCommandOptInterface(_ctl, _cmd, _name)                    \
    vshCommandOptInterfaceBy(_ctl, _cmd, _name,                      \
                           VSH_BYMAC|VSH_BYNAME)

static virStoragePoolPtr vshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd,
                            const char *optname, char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptPool(_ctl, _cmd, _optname, _name)           \
    vshCommandOptPoolBy(_ctl, _cmd, _optname, _name,             \
                           VSH_BYUUID|VSH_BYNAME)

static virStorageVolPtr vshCommandOptVolBy(vshControl *ctl, const vshCmd *cmd,
                                           const char *optname,
                                           const char *pooloptname,
                                           char **name, int flag);

/* default is lookup by Name and UUID */
#define vshCommandOptVol(_ctl, _cmd,_optname, _pooloptname, _name)   \
    vshCommandOptVolBy(_ctl, _cmd, _optname, _pooloptname, _name,     \
                           VSH_BYUUID|VSH_BYNAME)

static virSecretPtr vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd,
                                        char **name);

static void vshPrintExtra(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
static void vshDebug(vshControl *ctl, int level, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(3, 4);

/* XXX: add batch support */
#define vshPrint(_ctl, ...)   fprintf(stdout, __VA_ARGS__)

static const char *vshDomainStateToString(int state);
static const char *vshDomainVcpuStateToString(int state);
static int vshConnectionUsability(vshControl *ctl, virConnectPtr conn);

static char *editWriteToTempFile (vshControl *ctl, const char *doc);
static int   editFile (vshControl *ctl, const char *filename);
static char *editReadBackFile (vshControl *ctl, const char *filename);

static void *_vshMalloc(vshControl *ctl, size_t sz, const char *filename, int line);
#define vshMalloc(_ctl, _sz)    _vshMalloc(_ctl, _sz, __FILE__, __LINE__)

static void *_vshCalloc(vshControl *ctl, size_t nmemb, size_t sz, const char *filename, int line);
#define vshCalloc(_ctl, _nmemb, _sz)    _vshCalloc(_ctl, _nmemb, _sz, __FILE__, __LINE__)

static void *_vshRealloc(vshControl *ctl, void *ptr, size_t sz, const char *filename, int line);
#define vshRealloc(_ctl, _ptr, _sz)    _vshRealloc(_ctl, _ptr, _sz, __FILE__, __LINE__)

static char *_vshStrdup(vshControl *ctl, const char *s, const char *filename, int line);
#define vshStrdup(_ctl, _s)    _vshStrdup(_ctl, _s, __FILE__, __LINE__)

static void *
_vshMalloc(vshControl *ctl, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = malloc(size)))
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) size);
    exit(EXIT_FAILURE);
}

static void *
_vshCalloc(vshControl *ctl, size_t nmemb, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = calloc(nmemb, size)))
        return x;
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) (size*nmemb));
    exit(EXIT_FAILURE);
}

static void *
_vshRealloc(vshControl *ctl, void *ptr, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = realloc(ptr, size)))
        return x;
    VIR_FREE(ptr);
    vshError(ctl, _("%s: %d: failed to allocate %d bytes"),
             filename, line, (int) size);
    exit(EXIT_FAILURE);
}

static char *
_vshStrdup(vshControl *ctl, const char *s, const char *filename, int line)
{
    char *x;

    if (s == NULL)
        return(NULL);
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
        return ((double)val / (1024.0l * 1024.0l));
    } else if (val < (1024.0l * 1024.0l * 1024.0l * 1024.0l)) {
        *unit = "GB";
        return ((double)val / (1024.0l * 1024.0l * 1024.0l));
    } else {
        *unit = "TB";
        return ((double)val / (1024.0l * 1024.0l * 1024.0l * 1024.0l));
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

/*
 * Detection of disconnections and automatic reconnection support
 */
static int disconnected = 0; /* we may have been disconnected */

#ifdef SIGPIPE
/*
 * vshCatchDisconnect:
 *
 * We get here when a SIGPIPE is being raised, we can't do much in the
 * handler, just save the fact it was raised
 */
static void vshCatchDisconnect(int sig, siginfo_t * siginfo,
                               void* context ATTRIBUTE_UNUSED) {
    if ((sig == SIGPIPE) || (siginfo->si_signo == SIGPIPE))
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
#else
static void
vshSetupSignals(void) {}
#endif

/*
 * vshReconnect:
 *
 * Reconnect after a disconnect from libvirtd
 *
 */
static void
vshReconnect(vshControl *ctl) {
    if (ctl->conn != NULL)
        virConnectClose(ctl->conn);

    ctl->conn = virConnectOpenAuth(ctl->name,
                                   virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);
    if (!ctl->conn)
        vshError(ctl, "%s", _("Failed to reconnect to the hypervisor"));
    else
        vshError(ctl, "%s", _("Reconnected to the hypervisor"));
    disconnected = 0;
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

static int
cmdHelp(vshControl *ctl, const vshCmd *cmd)
 {
    const vshCmdDef *c;
    const vshCmdGrp *g;
    const char *name;

    name = vshCommandOptString(cmd, "command", NULL);

    if (!name) {
        const vshCmdGrp *grp;
        const vshCmdDef *def;

        vshPrint(ctl, "%s", _("Grouped commands:\n\n"));

        for (grp = cmdGroups; grp->name; grp++) {
            vshPrint(ctl, _(" %s (help keyword '%s'):\n"), grp->name,
                     grp->keyword);

            for (def = grp->commands; def->name; def++)
                vshPrint(ctl, "    %-30s %s\n", def->name,
                         _(vshCmddefGetInfo(def, "help")));

            vshPrint(ctl, "\n");
        }

        return TRUE;
    }

    if ((c = vshCmddefSearch(name))) {
        return vshCmddefHelp(ctl, name);
    } else if ((g = vshCmdGrpSearch(name))) {
        return vshCmdGrpHelp(ctl, name);
    } else {
        vshError(ctl, _("command or command group '%s' doesn't exist"), name);
        return FALSE;
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

static int
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virDomainSetAutostart(dom, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("Failed to mark domain %s as autostarted"), name);
        else
            vshError(ctl, _("Failed to unmark domain %s as autostarted"), name);
        virDomainFree(dom);
        return FALSE;
    }

    if (autostart)
        vshPrint(ctl, _("Domain %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Domain %s unmarked as autostarted\n"), name);

    virDomainFree(dom);
    return TRUE;
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
    {"name",     VSH_OT_DATA, 0, N_("hypervisor connection URI")},
    {"readonly", VSH_OT_BOOL, 0, N_("read-only connection")},
    {NULL, 0, 0, NULL}
};

static int
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    int ro = vshCommandOptBool(cmd, "readonly");
    char *name;

    if (ctl->conn) {
        int ret;
        if ((ret = virConnectClose(ctl->conn)) != 0) {
            vshError(ctl, _("Failed to disconnect from the hypervisor, %d leaked reference(s)"), ret);
            return FALSE;
        }
        ctl->conn = NULL;
    }

    VIR_FREE(ctl->name);
    name = vshCommandOptString(cmd, "name", NULL);
    if (!name)
        return FALSE;
    ctl->name = vshStrdup(ctl, name);

    if (!ro) {
        ctl->readonly = 0;
    } else {
        ctl->readonly = 1;
    }

    ctl->conn = virConnectOpenAuth(ctl->name, virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);

    if (!ctl->conn)
        vshError(ctl, "%s", _("Failed to connect to the hypervisor"));

    return ctl->conn ? TRUE : FALSE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdRunConsole(vshControl *ctl, virDomainPtr dom, const char *name)
{
    int ret = FALSE;
    virDomainInfo dominfo;

    if (virDomainGetInfo(dom, &dominfo) < 0) {
        vshError(ctl, "%s", _("Unable to get domain status"));
        goto cleanup;
    }

    if (dominfo.state == VIR_DOMAIN_SHUTOFF) {
        vshError(ctl, "%s", _("The domain is not running"));
        goto cleanup;
    }

    vshPrintExtra(ctl, _("Connected to domain %s\n"), virDomainGetName(dom));
    vshPrintExtra(ctl, "%s", _("Escape character is ^]\n"));
    if (vshRunConsole(dom, name) == 0)
        ret = TRUE;

 cleanup:

    return ret;
}

static int
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret;
    const char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    name = vshCommandOptString(cmd, "devname", NULL);

    ret = cmdRunConsole(ctl, dom, name);

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
    {NULL, 0, 0, NULL}
};


static int
cmdList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int *ids = NULL, maxid = 0, i;
    char **names = NULL;
    int maxname = 0;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (active) {
        maxid = virConnectNumOfDomains(ctl->conn);
        if (maxid < 0) {
            vshError(ctl, "%s", _("Failed to list active domains"));
            return FALSE;
        }
        if (maxid) {
            ids = vshMalloc(ctl, sizeof(int) * maxid);

            if ((maxid = virConnectListDomains(ctl->conn, &ids[0], maxid)) < 0) {
                vshError(ctl, "%s", _("Failed to list active domains"));
                VIR_FREE(ids);
                return FALSE;
            }

            qsort(&ids[0], maxid, sizeof(int), idsorter);
        }
    }
    if (inactive) {
        maxname = virConnectNumOfDefinedDomains(ctl->conn);
        if (maxname < 0) {
            vshError(ctl, "%s", _("Failed to list inactive domains"));
            VIR_FREE(ids);
            return FALSE;
        }
        if (maxname) {
            names = vshMalloc(ctl, sizeof(char *) * maxname);

            if ((maxname = virConnectListDefinedDomains(ctl->conn, names, maxname)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive domains"));
                VIR_FREE(ids);
                VIR_FREE(names);
                return FALSE;
            }

            qsort(&names[0], maxname, sizeof(char*), namesorter);
        }
    }
    vshPrintExtra(ctl, "%3s %-20s %s\n", _("Id"), _("Name"), _("State"));
    vshPrintExtra(ctl, "----------------------------------\n");

    for (i = 0; i < maxid; i++) {
        virDomainInfo info;
        virDomainPtr dom = virDomainLookupByID(ctl->conn, ids[i]);
        const char *state;

        /* this kind of work with domains is not atomic operation */
        if (!dom)
            continue;

        if (virDomainGetInfo(dom, &info) < 0)
            state = _("no state");
        else
            state = _(vshDomainStateToString(info.state));

        vshPrint(ctl, "%3d %-20s %s\n",
                 virDomainGetID(dom),
                 virDomainGetName(dom),
                 state);
        virDomainFree(dom);
    }
    for (i = 0; i < maxname; i++) {
        virDomainInfo info;
        virDomainPtr dom = virDomainLookupByName(ctl->conn, names[i]);
        const char *state;

        /* this kind of work with domains is not atomic operation */
        if (!dom) {
            VIR_FREE(names[i]);
            continue;
        }

        if (virDomainGetInfo(dom, &info) < 0)
            state = _("no state");
        else
            state = _(vshDomainStateToString(info.state));

        vshPrint(ctl, "%3s %-20s %s\n", "-", names[i], state);

        virDomainFree(dom);
        VIR_FREE(names[i]);
    }
    VIR_FREE(ids);
    VIR_FREE(names);
    return TRUE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdDomstate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (virDomainGetInfo(dom, &info) == 0)
        vshPrint(ctl, "%s\n",
                 _(vshDomainStateToString(info.state)));
    else
        ret = FALSE;

    virDomainFree(dom);
    return ret;
}

/* "domblkstat" command
 */
static const vshCmdInfo info_domblkstat[] = {
    {"help", N_("get device block stats for a domain")},
    {"desc", N_("Get device block stats for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domblkstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("block device")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomblkstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name, *device;
    struct _virDomainBlockStats stats;

    if (!vshConnectionUsability (ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain (ctl, cmd, &name)))
        return FALSE;

    if (!(device = vshCommandOptString (cmd, "device", NULL))) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainBlockStats (dom, device, &stats, sizeof stats) == -1) {
        vshError(ctl, _("Failed to get block stats %s %s"), name, device);
        virDomainFree(dom);
        return FALSE;
    }

    if (stats.rd_req >= 0)
        vshPrint (ctl, "%s rd_req %lld\n", device, stats.rd_req);

    if (stats.rd_bytes >= 0)
        vshPrint (ctl, "%s rd_bytes %lld\n", device, stats.rd_bytes);

    if (stats.wr_req >= 0)
        vshPrint (ctl, "%s wr_req %lld\n", device, stats.wr_req);

    if (stats.wr_bytes >= 0)
        vshPrint (ctl, "%s wr_bytes %lld\n", device, stats.wr_bytes);

    if (stats.errs >= 0)
        vshPrint (ctl, "%s errs %lld\n", device, stats.errs);

    virDomainFree(dom);
    return TRUE;
}

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

static int
cmdDomIfstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name, *device;
    struct _virDomainInterfaceStats stats;

    if (!vshConnectionUsability (ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain (ctl, cmd, &name)))
        return FALSE;

    if (!(device = vshCommandOptString (cmd, "interface", NULL))) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainInterfaceStats (dom, device, &stats, sizeof stats) == -1) {
        vshError(ctl, _("Failed to get interface stats %s %s"), name, device);
        virDomainFree(dom);
        return FALSE;
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
    return TRUE;
}

/*
 * "dommemstats" command
 */
static const vshCmdInfo info_dommemstat[] = {
    {"help", N_("get memory statistics for a domain")},
    {"desc", N_("Get memory statistics for a runnng domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_dommemstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomMemStat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    struct _virDomainMemoryStat stats[VIR_DOMAIN_MEMORY_STAT_NR];
    unsigned int nr_stats, i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    nr_stats = virDomainMemoryStats (dom, stats, VIR_DOMAIN_MEMORY_STAT_NR, 0);
    if (nr_stats == -1) {
        vshError(ctl, _("Failed to get memory statistics for domain %s"), name);
        virDomainFree(dom);
        return FALSE;
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
    }

    virDomainFree(dom);
    return TRUE;
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

static int
cmdDomblkinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainBlockInfo info;
    virDomainPtr dom;
    int ret = TRUE;
    const char *device;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (!(device = vshCommandOptString (cmd, "device", NULL))) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainGetBlockInfo(dom, device, &info, 0) < 0) {
        virDomainFree(dom);
        return FALSE;
    }

    vshPrint(ctl, "%-15s %llu\n", _("Capacity:"), info.capacity);
    vshPrint(ctl, "%-15s %llu\n", _("Allocation:"), info.allocation);
    vshPrint(ctl, "%-15s %llu\n", _("Physical:"), info.physical);

    virDomainFree(dom);
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

static int
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainSuspend(dom) == 0) {
        vshPrint(ctl, _("Domain %s suspended\n"), name);
    } else {
        vshError(ctl, _("Failed to suspend domain %s"), name);
        ret = FALSE;
    }

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
    {NULL, 0, 0, NULL}
};

static int
cmdCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;
#ifndef WIN32
    int console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;

    dom = virDomainCreateXML(ctl->conn, buffer, flags);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s created from %s\n"),
                 virDomainGetName(dom), from);
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom, NULL);
#endif
        virDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to create domain from %s"), from);
        ret = FALSE;
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

static int
cmdDefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    dom = virDomainDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s defined from %s\n"),
                 virDomainGetName(dom), from);
        virDomainFree(dom);
    } else {
        vshError(ctl, _("Failed to define domain from %s"), from);
        ret = FALSE;
    }
    return ret;
}

/*
 * "undefine" command
 */
static const vshCmdInfo info_undefine[] = {
    {"help", N_("undefine an inactive domain")},
    {"desc", N_("Undefine the configuration for an inactive domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_undefine[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;
    int found;
    int id;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    name = vshCommandOptString(cmd, "domain", &found);
    if (!found)
        return FALSE;

    if (name && virStrToLong_i(name, NULL, 10, &id) == 0
        && id >= 0 && (dom = virDomainLookupByID(ctl->conn, id))) {
        vshError(ctl,
                 _("a running domain like %s cannot be undefined;\n"
                   "to undefine, first shutdown then undefine"
                   " using its name or UUID"),
                 name);
        virDomainFree(dom);
        return FALSE;
    }
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, &name,
                                      VSH_BYNAME|VSH_BYUUID)))
        return FALSE;

    if (virDomainUndefine(dom) == 0) {
        vshPrint(ctl, _("Domain %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine domain %s"), name);
        ret = FALSE;
    }

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
    {NULL, 0, 0, NULL}
};

static int
cmdStart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
#ifndef WIN32
    int console = vshCommandOptBool(cmd, "console");
#endif
    unsigned int flags = VIR_DOMAIN_NONE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL, VSH_BYNAME)))
        return FALSE;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        virDomainFree(dom);
        return FALSE;
    }

    if (vshCommandOptBool(cmd, "paused"))
        flags |= VIR_DOMAIN_START_PAUSED;

    /* Prefer older API unless we have to pass a flag.  */
    if ((flags ? virDomainCreateWithFlags(dom, flags)
         : virDomainCreate(dom)) == 0) {
        vshPrint(ctl, _("Domain %s started\n"),
                 virDomainGetName(dom));
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom, NULL);
#endif
    } else {
        vshError(ctl, _("Failed to start domain %s"), virDomainGetName(dom));
        ret = FALSE;
    }
    virDomainFree(dom);
    return ret;
}

/*
 * "save" command
 */
static const vshCmdInfo info_save[] = {
    {"help", N_("save a domain state to a file")},
    {"desc", N_("Save a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to save the data")},
    {NULL, 0, 0, NULL}
};

static int
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    char *to;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(to = vshCommandOptString(cmd, "file", NULL)))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainSave(dom, to) == 0) {
        vshPrint(ctl, _("Domain %s saved to %s\n"), name, to);
    } else {
        vshError(ctl, _("Failed to save domain %s to %s"), name, to);
        ret = FALSE;
    }

    virDomainFree(dom);
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
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdManagedSave(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainManagedSave(dom, 0) == 0) {
        vshPrint(ctl, _("Domain %s state saved by libvirt\n"), name);
    } else {
        vshError(ctl, _("Failed to save domain %s state"), name);
        ret = FALSE;
    }

    virDomainFree(dom);
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

static int
cmdManagedSaveRemove(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int ret = FALSE;
    int hassave;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

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

    ret = TRUE;

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
    {NULL, 0, 0, NULL}
};

static int
cmdSchedInfoUpdate(vshControl *ctl, const vshCmd *cmd,
                   virSchedParameterPtr param)
{
    int found;
    char *data;

    /* Legacy 'weight' parameter */
    if (STREQ(param->field, "weight") &&
        param->type == VIR_DOMAIN_SCHED_FIELD_UINT &&
        vshCommandOptBool(cmd, "weight")) {
        int val;
        val = vshCommandOptInt(cmd, "weight", &found);
        if (!found) {
            vshError(ctl, "%s", _("Invalid value of weight"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    /* Legacy 'cap' parameter */
    if (STREQ(param->field, "cap") &&
        param->type == VIR_DOMAIN_SCHED_FIELD_UINT &&
        vshCommandOptBool(cmd, "cap")) {
        int val;
        val = vshCommandOptInt(cmd, "cap", &found);
        if (!found) {
            vshError(ctl, "%s", _("Invalid value of cap"));
            return -1;
        } else {
            param->value.ui = val;
        }
        return 1;
    }

    if ((data = vshCommandOptString(cmd, "set", NULL))) {
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
        case VIR_DOMAIN_SCHED_FIELD_INT:
            if (virStrToLong_i(val, NULL, 10, &param->value.i) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an int"));
                return -1;
            }
            break;
        case VIR_DOMAIN_SCHED_FIELD_UINT:
            if (virStrToLong_ui(val, NULL, 10, &param->value.ui) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned int"));
                return -1;
            }
            break;
        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            if (virStrToLong_ll(val, NULL, 10, &param->value.l) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting a long long"));
                return -1;
            }
            break;
        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            if (virStrToLong_ull(val, NULL, 10, &param->value.ul) < 0) {
                vshError(ctl, "%s",
                         _("Invalid value for parameter, expecting an unsigned long long"));
                return -1;
            }
            break;
        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            if (virStrToDouble(val, NULL, &param->value.d) < 0) {
                vshError(ctl, "%s", _("Invalid value for parameter, expecting a double"));
                return -1;
            }
            break;
        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            param->value.b = STREQ(val, "0") ? 0 : 1;
        }
        return 1;
    }

    return 0;
}


static int
cmdSchedinfo(vshControl *ctl, const vshCmd *cmd)
{
    char *schedulertype;
    virDomainPtr dom;
    virSchedParameterPtr params = NULL;
    int nparams = 0;
    int update = 0;
    int i, ret;
    int ret_val = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    /* Print SchedulerType */
    schedulertype = virDomainGetSchedulerType(dom, &nparams);
    if (schedulertype!= NULL){
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"),
             schedulertype);
        VIR_FREE(schedulertype);
    } else {
        vshPrint(ctl, "%-15s: %s\n", _("Scheduler"), _("Unknown"));
        goto cleanup;
    }

    if (nparams) {
        params = vshMalloc(ctl, sizeof(virSchedParameter)* nparams);

        memset(params, 0, sizeof(virSchedParameter)* nparams);
        ret = virDomainGetSchedulerParameters(dom, params, &nparams);
        if (ret == -1)
            goto cleanup;

        /* See if any params are being set */
        for (i = 0; i < nparams; i++){
            ret = cmdSchedInfoUpdate(ctl, cmd, &(params[i]));
            if (ret == -1)
                goto cleanup;

            if (ret == 1)
                update = 1;
        }

        /* Update parameters & refresh data */
        if (update) {
            ret = virDomainSetSchedulerParameters(dom, params, nparams);
            if (ret == -1)
                goto cleanup;

            ret = virDomainGetSchedulerParameters(dom, params, &nparams);
            if (ret == -1)
                goto cleanup;
        } else {
            /* See if we've tried to --set var=val.  If so, the fact that
               we reach this point (with update == 0) means that "var" did
               not match any of the settable parameters.  Report the error.  */
            char *var_value_pair = vshCommandOptString(cmd, "set", NULL);
            if (var_value_pair) {
                vshError(ctl, _("invalid scheduler option: %s"),
                         var_value_pair);
                goto cleanup;
            }
        }

        ret_val = TRUE;
        for (i = 0; i < nparams; i++){
            switch (params[i].type) {
            case VIR_DOMAIN_SCHED_FIELD_INT:
                 vshPrint(ctl, "%-15s: %d\n",  params[i].field, params[i].value.i);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_UINT:
                 vshPrint(ctl, "%-15s: %u\n",  params[i].field, params[i].value.ui);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_LLONG:
                 vshPrint(ctl, "%-15s: %lld\n",  params[i].field, params[i].value.l);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_ULLONG:
                 vshPrint(ctl, "%-15s: %llu\n",  params[i].field, params[i].value.ul);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
                 vshPrint(ctl, "%-15s: %f\n",  params[i].field, params[i].value.d);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
                 vshPrint(ctl, "%-15s: %d\n",  params[i].field, params[i].value.b);
                 break;
            default:
                 vshPrint(ctl, "not implemented scheduler parameter type\n");
            }
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
    {NULL, 0, 0, NULL}
};

static int
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    char *from;
    int found;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virDomainRestore(ctl->conn, from) == 0) {
        vshPrint(ctl, _("Domain restored from %s\n"), from);
    } else {
        vshError(ctl, _("Failed to restore domain from %s"), from);
        ret = FALSE;
    }
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
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, N_("where to dump the core")},
    {NULL, 0, 0, NULL}
};

static int
cmdDump(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    char *to;
    int ret = TRUE;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(to = vshCommandOptString(cmd, "file", NULL)))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (vshCommandOptBool (cmd, "live"))
        flags |= VIR_DUMP_LIVE;
    if (vshCommandOptBool (cmd, "crash"))
        flags |= VIR_DUMP_CRASH;

    if (virDomainCoreDump(dom, to, flags) == 0) {
        vshPrint(ctl, _("Domain %s dumped to %s\n"), name, to);
    } else {
        vshError(ctl, _("Failed to core dump domain %s to %s"), name, to);
        ret = FALSE;
    }

    virDomainFree(dom);
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

static int
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainResume(dom) == 0) {
        vshPrint(ctl, _("Domain %s resumed\n"), name);
    } else {
        vshError(ctl, _("Failed to resume domain %s"), name);
        ret = FALSE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainShutdown(dom) == 0) {
        vshPrint(ctl, _("Domain %s is being shutdown\n"), name);
    } else {
        vshError(ctl, _("Failed to shutdown domain %s"), name);
        ret = FALSE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainReboot(dom, 0) == 0) {
        vshPrint(ctl, _("Domain %s is being rebooted\n"), name);
    } else {
        vshError(ctl, _("Failed to reboot domain %s"), name);
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "destroy" command
 */
static const vshCmdInfo info_destroy[] = {
    {"help", N_("destroy a domain")},
    {"desc", N_("Destroy a given domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, &name)))
        return FALSE;

    if (virDomainDestroy(dom) == 0) {
        vshPrint(ctl, _("Domain %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy domain %s"), name);
        ret = FALSE;
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

static int
cmdDominfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virSecurityModel secmodel;
    virSecurityLabel seclabel;
    int persistent = 0;
    int ret = TRUE, autostart;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

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
        ret = FALSE;
    }

    /* Check and display whether the domain is persistent or not */
    persistent = virDomainIsPersistent(dom);
    vshDebug(ctl, 5, "Domain persistent flag value: %d\n", persistent);
    if (persistent < 0)
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), _("unknown"));
    else
        vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

    /* Check and display whether the domain autostarts or not */
    if (!virDomainGetAutostart(dom, &autostart)) {
        vshPrint(ctl, "%-15s %s\n", _("Autostart:"),
                 autostart ? _("enable") : _("disable") );
    }

    /* Security model and label information */
    memset(&secmodel, 0, sizeof secmodel);
    if (virNodeGetSecurityModel(ctl->conn, &secmodel) == -1) {
        if (last_error->code != VIR_ERR_NO_SUPPORT) {
            virDomainFree(dom);
            return FALSE;
        }
    } else {
        /* Only print something if a security model is active */
        if (secmodel.model[0] != '\0') {
            vshPrint(ctl, "%-15s %s\n", _("Security model:"), secmodel.model);
            vshPrint(ctl, "%-15s %s\n", _("Security DOI:"), secmodel.doi);

            /* Security labels are only valid for active domains */
            memset(&seclabel, 0, sizeof seclabel);
            if (virDomainGetSecurityLabel(dom, &seclabel) == -1) {
                virDomainFree(dom);
                return FALSE;
            } else {
                if (seclabel.label[0] != '\0')
                    vshPrint(ctl, "%-15s %s (%s)\n", _("Security label:"),
                             seclabel.label, seclabel.enforcing ? "enforcing" : "permissive");
            }
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


static int
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info;
    virDomainPtr dom;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

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
        ret = FALSE;
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

static int
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (virDomainAbortJob(dom) < 0)
        ret = FALSE;

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
    {NULL, 0, 0, NULL}
};

static int
cmdFreecell(vshControl *ctl, const vshCmd *cmd)
{
    int ret;
    int cell, cell_given;
    unsigned long long memory;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    cell = vshCommandOptInt(cmd, "cellno", &cell_given);
    if (!cell_given) {
        memory = virNodeGetFreeMemory(ctl->conn);
        if (memory == 0)
            return FALSE;
    } else {
        ret = virNodeGetCellsFreeMemory(ctl->conn, &memory, cell, 1);
        if (ret != 1)
            return FALSE;
    }

    if (cell == -1)
        vshPrint(ctl, "%s: %llu kB\n", _("Total"), (memory/1024));
    else
        vshPrint(ctl, "%d: %llu kB\n", cell, (memory/1024));

    return TRUE;
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

static int
cmdMaxvcpus(vshControl *ctl, const vshCmd *cmd)
{
    char *type;
    int vcpus;

    type = vshCommandOptString(cmd, "type", NULL);

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    vcpus = virConnectGetMaxVcpus(ctl->conn, type);
    if (vcpus < 0)
        return FALSE;
    vshPrint(ctl, "%d\n", vcpus);

    return TRUE;
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
    {"current", VSH_OT_BOOL, 0, N_("get current vcpu usage")},
    {"config", VSH_OT_BOOL, 0, N_("get value to be used on next boot")},
    {"live", VSH_OT_BOOL, 0, N_("get value from running domain")},
    {NULL, 0, 0, NULL}
};

static int
cmdVcpucount(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    int maximum = vshCommandOptBool(cmd, "maximum");
    int current = vshCommandOptBool(cmd, "current");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    bool all = maximum + current + config + live == 0;
    int count;

    if (maximum && current) {
        vshError(ctl, "%s",
                 _("--maximum and --current cannot both be specified"));
        return FALSE;
    }
    if (config && live) {
        vshError(ctl, "%s",
                 _("--config and --live cannot both be specified"));
        return FALSE;
    }
    /* We want one of each pair of mutually exclusive options; that
     * is, use of flags requires exactly two options.  */
    if (maximum + current + config + live == 1) {
        vshError(ctl,
                 _("when using --%s, either --%s or --%s must be specified"),
                 (maximum ? "maximum" : current ? "current"
                  : config ? "config" : "live"),
                 maximum + current ? "config" : "maximum",
                 maximum + current ? "live" : "current");
        return FALSE;
    }

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    /* In all cases, try the new API first; if it fails because we are
     * talking to an older client, try a fallback API before giving
     * up.  */
    if (all || (maximum && config)) {
        count = virDomainGetVcpusFlags(dom, (VIR_DOMAIN_VCPU_MAXIMUM |
                                             VIR_DOMAIN_VCPU_CONFIG));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            char *tmp;
            char *xml = virDomainGetXMLDesc(dom, VIR_DOMAIN_XML_INACTIVE);
            if (xml && (tmp = strstr(xml, "<vcpu"))) {
                tmp = strchr(tmp, '>');
                if (!tmp || virStrToLong_i(tmp + 1, &tmp, 10, &count) < 0)
                    count = -1;
            }
            VIR_FREE(xml);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = FALSE;
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
                                             VIR_DOMAIN_VCPU_LIVE));
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            count = virDomainGetMaxVcpus(dom);
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = FALSE;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("maximum"), _("live"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    if (all || (current && config)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_VCPU_CONFIG);
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
            ret = FALSE;
        } else if (all) {
            vshPrint(ctl, "%-12s %-12s %3d\n", _("current"), _("config"),
                     count);
        } else {
            vshPrint(ctl, "%d\n", count);
        }
        virFreeError(last_error);
        last_error = NULL;
    }

    if (all || (current && live)) {
        count = virDomainGetVcpusFlags(dom, VIR_DOMAIN_VCPU_LIVE);
        if (count < 0 && (last_error->code == VIR_ERR_NO_SUPPORT
                          || last_error->code == VIR_ERR_INVALID_ARG)) {
            virDomainInfo info;
            if (virDomainGetInfo(dom, &info) == 0)
                count = info.nrVirtCpu;
        }

        if (count < 0) {
            virshReportError(ctl);
            ret = FALSE;
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

static int
cmdVcpuinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    virVcpuInfoPtr cpuinfo;
    unsigned char *cpumap;
    int ncpus;
    size_t cpumaplen;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        return FALSE;
    }

    cpuinfo = vshMalloc(ctl, sizeof(virVcpuInfo)*info.nrVirtCpu);
    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    cpumap = vshMalloc(ctl, info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom,
                                   cpuinfo, info.nrVirtCpu,
                                   cpumap, cpumaplen)) >= 0) {
        int n;
        for (n = 0 ; n < ncpus ; n++) {
            unsigned int m;
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
            for (m = 0 ; m < VIR_NODEINFO_MAXCPUS(nodeinfo) ; m++) {
                vshPrint(ctl, "%c", VIR_CPU_USABLE(cpumap, cpumaplen, n, m) ? 'y' : '-');
            }
            vshPrint(ctl, "\n");
            if (n < (ncpus - 1)) {
                vshPrint(ctl, "\n");
            }
        }
    } else {
        if (info.state == VIR_DOMAIN_SHUTOFF) {
            vshError(ctl, "%s",
                     _("Domain shut off, virtual CPUs not present."));
        }
        ret = FALSE;
    }

    VIR_FREE(cpumap);
    VIR_FREE(cpuinfo);
    virDomainFree(dom);
    return ret;
}

/*
 * "vcpupin" command
 */
static const vshCmdInfo info_vcpupin[] = {
    {"help", N_("control domain vcpu affinity")},
    {"desc", N_("Pin domain VCPUs to host physical CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpupin[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"vcpu", VSH_OT_INT, VSH_OFLAG_REQ, N_("vcpu number")},
    {"cpulist", VSH_OT_DATA, VSH_OFLAG_REQ, N_("host cpu number(s) (comma separated)")},
    {NULL, 0, 0, NULL}
};

static int
cmdVcpupin(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virNodeInfo nodeinfo;
    int vcpu;
    char *cpulist;
    int ret = TRUE;
    int vcpufound = 0;
    unsigned char *cpumap;
    int cpumaplen;
    int i;
    enum { expect_num, expect_num_or_comma } state;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    vcpu = vshCommandOptInt(cmd, "vcpu", &vcpufound);
    if (!vcpufound) {
        vshError(ctl, "%s", _("vcpupin: Invalid or missing vCPU number."));
        virDomainFree(dom);
        return FALSE;
    }

    if (!(cpulist = vshCommandOptString(cmd, "cpulist", NULL))) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        vshError(ctl, "%s", _("vcpupin: failed to get domain informations."));
        virDomainFree(dom);
        return FALSE;
    }

    if (vcpu >= info.nrVirtCpu) {
        vshError(ctl, "%s", _("vcpupin: Invalid vCPU number."));
        virDomainFree(dom);
        return FALSE;
    }

    /* Check that the cpulist parameter is a comma-separated list of
     * numbers and give an intelligent error message if not.
     */
    if (cpulist[0] == '\0') {
        vshError(ctl, "%s", _("cpulist: Invalid format. Empty string."));
        virDomainFree (dom);
        return FALSE;
    }

    state = expect_num;
    for (i = 0; cpulist[i]; i++) {
        switch (state) {
        case expect_num:
          if (!c_isdigit (cpulist[i])) {
                vshError(ctl, _("cpulist: %s: Invalid format. Expecting "
                                "digit at position %d (near '%c')."),
                         cpulist, i, cpulist[i]);
                virDomainFree (dom);
                return FALSE;
            }
            state = expect_num_or_comma;
            break;
        case expect_num_or_comma:
            if (cpulist[i] == ',')
                state = expect_num;
            else if (!c_isdigit (cpulist[i])) {
                vshError(ctl, _("cpulist: %s: Invalid format. Expecting "
                                "digit or comma at position %d (near '%c')."),
                         cpulist, i, cpulist[i]);
                virDomainFree (dom);
                return FALSE;
            }
        }
    }
    if (state == expect_num) {
        vshError(ctl, _("cpulist: %s: Invalid format. Trailing comma "
                        "at position %d."),
                 cpulist, i);
        virDomainFree (dom);
        return FALSE;
    }

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    cpumap = vshCalloc(ctl, 1, cpumaplen);

    do {
        unsigned int cpu = atoi(cpulist);

        if (cpu < VIR_NODEINFO_MAXCPUS(nodeinfo)) {
            VIR_USE_CPU(cpumap, cpu);
        } else {
            vshError(ctl, _("Physical CPU %d doesn't exist."), cpu);
            VIR_FREE(cpumap);
            virDomainFree(dom);
            return FALSE;
        }
        cpulist = strchr(cpulist, ',');
        if (cpulist)
            cpulist++;
    } while (cpulist);

    if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0) {
        ret = FALSE;
    }

    VIR_FREE(cpumap);
    virDomainFree(dom);
    return ret;
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
    {NULL, 0, 0, NULL}
};

static int
cmdSetvcpus(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int count;
    int ret = TRUE;
    int maximum = vshCommandOptBool(cmd, "maximum");
    int config = vshCommandOptBool(cmd, "config");
    int live = vshCommandOptBool(cmd, "live");
    int flags = ((maximum ? VIR_DOMAIN_VCPU_MAXIMUM : 0) |
                 (config ? VIR_DOMAIN_VCPU_CONFIG : 0) |
                 (live ? VIR_DOMAIN_VCPU_LIVE : 0));

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    count = vshCommandOptInt(cmd, "count", &count);

    if (!flags) {
        if (virDomainSetVcpus(dom, count) != 0) {
            ret = FALSE;
        }
    } else {
        if (virDomainSetVcpusFlags(dom, count, flags) < 0) {
            ret = FALSE;
        }
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "setmemory" command
 */
static const vshCmdInfo info_setmem[] = {
    {"help", N_("change memory allocation")},
    {"desc", N_("Change the current memory allocation in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"kilobytes", VSH_OT_INT, VSH_OFLAG_REQ, N_("number of kilobytes of memory")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainInfo info;
    unsigned long kilobytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    kilobytes = vshCommandOptUL(cmd, "kilobytes", NULL);
    if (kilobytes <= 0) {
        virDomainFree(dom);
        vshError(ctl, _("Invalid value of %lu for memory size"), kilobytes);
        return FALSE;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        vshError(ctl, "%s", _("Unable to verify MaxMemorySize"));
        return FALSE;
    }

    if (kilobytes > info.maxMem) {
        virDomainFree(dom);
        vshError(ctl, _("Requested memory size %lu kb is larger than maximum of %lu kb"),
                 kilobytes, info.maxMem);
        return FALSE;
    }

    if (virDomainSetMemory(dom, kilobytes) != 0) {
        ret = FALSE;
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
    {"kilobytes", VSH_OT_INT, VSH_OFLAG_REQ, N_("maximum memory limit in kilobytes")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmaxmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainInfo info;
    int kilobytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    kilobytes = vshCommandOptInt(cmd, "kilobytes", &kilobytes);
    if (kilobytes <= 0) {
        virDomainFree(dom);
        vshError(ctl, _("Invalid value of %d for memory size"), kilobytes);
        return FALSE;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        vshError(ctl, "%s", _("Unable to verify current MemorySize"));
        return FALSE;
    }

    if (virDomainSetMaxMemory(dom, kilobytes) != 0) {
        vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
        virDomainFree(dom);
        return FALSE;
    }

    if (kilobytes < info.memory) {
        if (virDomainSetMemory(dom, kilobytes) != 0) {
            vshError(ctl, "%s", _("Unable to shrink current MemorySize"));
            ret = FALSE;
        }
    }

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
     N_("Max memory in kilobytes")},
    {"soft-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Memory during contention in kilobytes")},
    {"swap-hard-limit", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Max swap in kilobytes")},
    {"min-guarantee", VSH_OT_INT, VSH_OFLAG_NONE,
     N_("Min guaranteed memory in kilobytes")},
    {NULL, 0, 0, NULL}
};

static int
cmdMemtune(vshControl * ctl, const vshCmd * cmd)
{
    virDomainPtr dom;
    long long hard_limit, soft_limit, swap_hard_limit, min_guarantee;
    int nparams = 0;
    unsigned int i = 0;
    virMemoryParameterPtr params = NULL, temp = NULL;
    int ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    hard_limit =
        vshCommandOptLongLong(cmd, "hard-limit", NULL);
    if (hard_limit)
        nparams++;

    soft_limit =
        vshCommandOptLongLong(cmd, "soft-limit", NULL);
    if (soft_limit)
        nparams++;

    swap_hard_limit =
        vshCommandOptLongLong(cmd, "swap-hard-limit", NULL);
    if (swap_hard_limit)
        nparams++;

    min_guarantee =
        vshCommandOptLongLong(cmd, "min-guarantee", NULL);
    if (min_guarantee)
        nparams++;

    if (nparams == 0) {
        /* get the number of memory parameters */
        if (virDomainGetMemoryParameters(dom, NULL, &nparams, 0) != 0) {
            vshError(ctl, "%s",
                     _("Unable to get number of memory parameters"));
            goto cleanup;
        }

        if (nparams == 0) {
            /* nothing to output */
            ret = TRUE;
            goto cleanup;
        }

        /* now go get all the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));
        if (virDomainGetMemoryParameters(dom, params, &nparams, 0) != 0) {
            vshError(ctl, "%s", _("Unable to get memory parameters"));
            goto cleanup;
        }

        for (i = 0; i < nparams; i++) {
            switch (params[i].type) {
                case VIR_DOMAIN_MEMORY_PARAM_INT:
                    vshPrint(ctl, "%-15s: %d\n", params[i].field,
                             params[i].value.i);
                    break;
                case VIR_DOMAIN_MEMORY_PARAM_UINT:
                    vshPrint(ctl, "%-15s: %u\n", params[i].field,
                             params[i].value.ui);
                    break;
                case VIR_DOMAIN_MEMORY_PARAM_LLONG:
                    vshPrint(ctl, "%-15s: %lld\n", params[i].field,
                             params[i].value.l);
                    break;
                case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
                    vshPrint(ctl, "%-15s: %llu\n", params[i].field,
                             params[i].value.ul);
                    break;
                case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
                    vshPrint(ctl, "%-15s: %f\n", params[i].field,
                             params[i].value.d);
                    break;
                case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
                    vshPrint(ctl, "%-15s: %d\n", params[i].field,
                             params[i].value.b);
                    break;
                default:
                    vshPrint(ctl, "unimplemented memory parameter type\n");
            }
        }

        ret = TRUE;
    } else {
        /* set the memory parameters */
        params = vshCalloc(ctl, nparams, sizeof(*params));

        for (i = 0; i < nparams; i++) {
            temp = &params[i];
            temp->type = VIR_DOMAIN_MEMORY_PARAM_ULLONG;

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
        }
        if (virDomainSetMemoryParameters(dom, params, nparams, 0) != 0)
            vshError(ctl, "%s", _("Unable to change memory parameters"));
        else
            ret = TRUE;
    }

  cleanup:
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

static int
cmdNodeinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (virNodeGetInfo(ctl->conn, &info) < 0) {
        vshError(ctl, "%s", _("failed to get node information"));
        return FALSE;
    }
    vshPrint(ctl, "%-20s %s\n", _("CPU model:"), info.model);
    vshPrint(ctl, "%-20s %d\n", _("CPU(s):"), info.cpus);
    vshPrint(ctl, "%-20s %d MHz\n", _("CPU frequency:"), info.mhz);
    vshPrint(ctl, "%-20s %d\n", _("CPU socket(s):"), info.sockets);
    vshPrint(ctl, "%-20s %d\n", _("Core(s) per socket:"), info.cores);
    vshPrint(ctl, "%-20s %d\n", _("Thread(s) per core:"), info.threads);
    vshPrint(ctl, "%-20s %d\n", _("NUMA cell(s):"), info.nodes);
    vshPrint(ctl, "%-20s %lu kB\n", _("Memory size:"), info.memory);

    return TRUE;
}

/*
 * "capabilities" command
 */
static const vshCmdInfo info_capabilities[] = {
    {"help", N_("capabilities")},
    {"desc", N_("Returns capabilities of hypervisor/driver.")},
    {NULL, NULL}
};

static int
cmdCapabilities (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if ((caps = virConnectGetCapabilities (ctl->conn)) == NULL) {
        vshError(ctl, "%s", _("failed to get capabilities"));
        return FALSE;
    }
    vshPrint (ctl, "%s\n", caps);
    VIR_FREE(caps);

    return TRUE;
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

static int
cmdDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *dump;
    int flags = 0;
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
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    dump = virDomainGetXMLDesc(dom, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
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

static int
cmdDomXMLFromNative(vshControl *ctl, const vshCmd *cmd)
{
    int ret = TRUE;
    char *format;
    char *configFile;
    char *configData;
    char *xmlData;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    format = vshCommandOptString(cmd, "format", NULL);
    configFile = vshCommandOptString(cmd, "config", NULL);

    if (virFileReadAll(configFile, 1024*1024, &configData) < 0)
        return FALSE;

    xmlData = virConnectDomainXMLFromNative(ctl->conn, format, configData, flags);
    if (xmlData != NULL) {
        vshPrint(ctl, "%s", xmlData);
        VIR_FREE(xmlData);
    } else {
        ret = FALSE;
    }

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

static int
cmdDomXMLToNative(vshControl *ctl, const vshCmd *cmd)
{
    int ret = TRUE;
    char *format;
    char *xmlFile;
    char *configData;
    char *xmlData;
    int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    format = vshCommandOptString(cmd, "format", NULL);
    xmlFile = vshCommandOptString(cmd, "xml", NULL);

    if (virFileReadAll(xmlFile, 1024*1024, &xmlData) < 0)
        return FALSE;

    configData = virConnectDomainXMLToNative(ctl->conn, format, xmlData, flags);
    if (configData != NULL) {
        vshPrint(ctl, "%s", configData);
        VIR_FREE(configData);
    } else {
        ret = FALSE;
    }

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

static int
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYID|VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    virDomainFree(dom);
    return TRUE;
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

static int
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYUUID)))
        return FALSE;

    id = virDomainGetID(dom);
    if (id == ((unsigned int)-1))
        vshPrint(ctl, "%s\n", "-");
    else
        vshPrint(ctl, "%d\n", id);
    virDomainFree(dom);
    return TRUE;
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

static int
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL,
                                      VSH_BYNAME|VSH_BYID)))
        return FALSE;

    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get domain UUID"));

    virDomainFree(dom);
    return TRUE;
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
    {"tunnelled", VSH_OT_BOOL, 0, N_("tunnelled migration")},
    {"persistent", VSH_OT_BOOL, 0, N_("persist VM on destination")},
    {"undefinesource", VSH_OT_BOOL, 0, N_("undefine VM on source")},
    {"suspend", VSH_OT_BOOL, 0, N_("do not restart the domain on the destination host")},
    {"copy-storage-all", VSH_OT_BOOL, 0, N_("migration with non-shared storage with full disk copy")},
    {"copy-storage-inc", VSH_OT_BOOL, 0, N_("migration with non-shared storage with incremental copy (same base image shared between source and destination)")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"desturi", VSH_OT_DATA, VSH_OFLAG_REQ, N_("connection URI of the destination host")},
    {"migrateuri", VSH_OT_DATA, 0, N_("migration URI, usually can be omitted")},
    {"dname", VSH_OT_DATA, 0, N_("rename to new name during migration (if supported)")},
    {NULL, 0, 0, NULL}
};

static int
cmdMigrate (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    const char *desturi;
    const char *migrateuri;
    const char *dname;
    int flags = 0, found, ret = FALSE;

    if (!vshConnectionUsability (ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain (ctl, cmd, NULL)))
        return FALSE;

    desturi = vshCommandOptString (cmd, "desturi", &found);
    if (!found)
        goto done;

    migrateuri = vshCommandOptString (cmd, "migrateuri", NULL);

    dname = vshCommandOptString (cmd, "dname", NULL);

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

    if ((flags & VIR_MIGRATE_PEER2PEER) ||
        vshCommandOptBool (cmd, "direct")) {
        /* For peer2peer migration or direct migration we only expect one URI
         * a libvirt URI, or a hypervisor specific URI. */

        if (migrateuri != NULL) {
            vshError(ctl, "%s", _("migrate: Unexpected migrateuri for peer2peer/direct migration"));
            goto done;
        }

        if (virDomainMigrateToURI (dom, desturi, flags, dname, 0) == 0)
            ret = TRUE;
    } else {
        /* For traditional live migration, connect to the destination host directly. */
        virConnectPtr dconn = NULL;
        virDomainPtr ddom = NULL;

        dconn = virConnectOpenAuth (desturi, virConnectAuthPtrDefault, 0);
        if (!dconn) goto done;

        ddom = virDomainMigrate (dom, dconn, flags, dname, migrateuri, 0);
        if (ddom) {
            virDomainFree(ddom);
            ret = TRUE;
        }
        virConnectClose (dconn);
    }

 done:
    if (dom) virDomainFree (dom);
    return ret;
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

static int
cmdMigrateSetMaxDowntime(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    long long downtime;
    int found;
    int ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    downtime = vshCommandOptLongLong(cmd, "downtime", &found);
    if (!found || downtime < 1) {
        vshError(ctl, "%s", _("migrate: Invalid downtime"));
        goto done;
    }

    if (virDomainMigrateSetMaxDowntime(dom, downtime, 0))
        goto done;

    ret = TRUE;

done:
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

static int
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return FALSE;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virNetworkSetAutostart(network, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark network %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark network %s as autostarted"), name);
        virNetworkFree(network);
        return FALSE;
    }

    if (autostart)
        vshPrint(ctl, _("Network %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Network %s unmarked as autostarted\n"), name);

    virNetworkFree(network);
    return TRUE;
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

static int
cmdNetworkCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    network = virNetworkCreateXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s created from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to create network from %s"), from);
        ret = FALSE;
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

static int
cmdNetworkDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    network = virNetworkDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (network != NULL) {
        vshPrint(ctl, _("Network %s defined from %s\n"),
                 virNetworkGetName(network), from);
        virNetworkFree(network);
    } else {
        vshError(ctl, _("Failed to define network from %s"), from);
        ret = FALSE;
    }
    return ret;
}


/*
 * "net-destroy" command
 */
static const vshCmdInfo info_network_destroy[] = {
    {"help", N_("destroy a network")},
    {"desc", N_("Destroy a given network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_destroy[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return FALSE;

    if (virNetworkDestroy(network) == 0) {
        vshPrint(ctl, _("Network %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy network %s"), name);
        ret = FALSE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return FALSE;

    dump = virNetworkGetXMLDesc(network, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
    }

    virNetworkFree(network);
    return ret;
}

/*
 * "net-info" command
 */
static const vshCmdInfo info_network_info[] = {
    {"help", N_("network information")},
    {"desc", "Returns basic information about the network"},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_info[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, N_("network name")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkInfo(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int autostart;
    int persistent = -1;
    int active = -1;
    char *bridge = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return FALSE;

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

    virNetworkFree(network);
    return TRUE;
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

static int
cmdInterfaceEdit (vshControl *ctl, const vshCmd *cmd)
{
    int ret = FALSE;
    virInterfacePtr iface = NULL;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;
    int flags = VIR_INTERFACE_XML_INACTIVE;

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
        ret = TRUE;
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

    ret = TRUE;

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

static int
cmdNetworkList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (active) {
        maxactive = virConnectNumOfNetworks(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active networks"));
            return FALSE;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListNetworks(ctl->conn, activeNames,
                                                    maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active networks"));
                VIR_FREE(activeNames);
                return FALSE;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedNetworks(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive networks"));
            VIR_FREE(activeNames);
            return FALSE;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive =
                     virConnectListDefinedNetworks(ctl->conn, inactiveNames,
                                                   maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive networks"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return FALSE;
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
    return TRUE;
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

static int
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virNetworkGetName(network));
    virNetworkFree(network);
    return TRUE;
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

static int
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL, VSH_BYNAME)))
         return FALSE;

    if (virNetworkCreate(network) == 0) {
        vshPrint(ctl, _("Network %s started\n"),
                 virNetworkGetName(network));
    } else {
        vshError(ctl, _("Failed to start network %s"),
                 virNetworkGetName(network));
        ret = FALSE;
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

static int
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetwork(ctl, cmd, &name)))
        return FALSE;

    if (virNetworkUndefine(network) == 0) {
        vshPrint(ctl, _("Network %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network %s"), name);
        ret = FALSE;
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

static int
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(network = vshCommandOptNetworkBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return FALSE;

    if (virNetworkGetUUIDString(network, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get network UUID"));

    virNetworkFree(network);
    return TRUE;
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
static int
cmdInterfaceList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (active) {
        maxactive = virConnectNumOfInterfaces(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active interfaces"));
            return FALSE;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListInterfaces(ctl->conn, activeNames,
                                                    maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active interfaces"));
                VIR_FREE(activeNames);
                return FALSE;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedInterfaces(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive interfaces"));
            VIR_FREE(activeNames);
            return FALSE;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive =
                     virConnectListDefinedInterfaces(ctl->conn, inactiveNames,
                                                     maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive interfaces"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return FALSE;
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
    return TRUE;

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

static int
cmdInterfaceName(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL,
                                           VSH_BYMAC)))
        return FALSE;

    vshPrint(ctl, "%s\n", virInterfaceGetName(iface));
    virInterfaceFree(iface);
    return TRUE;
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

static int
cmdInterfaceMAC(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(iface = vshCommandOptInterfaceBy(ctl, cmd, NULL,
                                           VSH_BYNAME)))
        return FALSE;

    vshPrint(ctl, "%s\n", virInterfaceGetMACString(iface));
    virInterfaceFree(iface);
    return TRUE;
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

static int
cmdInterfaceDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *dump;
    int flags = 0;
    int inactive = vshCommandOptBool(cmd, "inactive");

    if (inactive)
        flags |= VIR_INTERFACE_XML_INACTIVE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, NULL)))
        return FALSE;

    dump = virInterfaceGetXMLDesc(iface, flags);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
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

static int
cmdInterfaceDefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    iface = virInterfaceDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (iface != NULL) {
        vshPrint(ctl, _("Interface %s defined from %s\n"),
                 virInterfaceGetName(iface), from);
        virInterfaceFree (iface);
    } else {
        vshError(ctl, _("Failed to define interface from %s"), from);
        ret = FALSE;
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

static int
cmdInterfaceUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return FALSE;

    if (virInterfaceUndefine(iface) == 0) {
        vshPrint(ctl, _("Interface %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine interface %s"), name);
        ret = FALSE;
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

static int
cmdInterfaceStart(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return FALSE;

    if (virInterfaceCreate(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s started\n"), name);
    } else {
        vshError(ctl, _("Failed to start interface %s"), name);
        ret = FALSE;
    }

    virInterfaceFree(iface);
    return ret;
}

/*
 * "iface-destroy" command
 */
static const vshCmdInfo info_interface_destroy[] = {
    {"help", N_("destroy a physical host interface (disable it / \"if-down\")")},
    {"desc", N_("destroy a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_destroy[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, N_("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, &name)))
        return FALSE;

    if (virInterfaceDestroy(iface, 0) == 0) {
        vshPrint(ctl, _("Interface %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy interface %s"), name);
        ret = FALSE;
    }

    virInterfaceFree(iface);
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

static int
cmdNWFilterDefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    nwfilter = virNWFilterDefineXML(ctl->conn, buffer);
    VIR_FREE(buffer);

    if (nwfilter != NULL) {
        vshPrint(ctl, _("Network filter %s defined from %s\n"),
                 virNWFilterGetName(nwfilter), from);
        virNWFilterFree(nwfilter);
    } else {
        vshError(ctl, _("Failed to define network filter from %s"), from);
        ret = FALSE;
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

static int
cmdNWFilterUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, &name)))
        return FALSE;

    if (virNWFilterUndefine(nwfilter) == 0) {
        vshPrint(ctl, _("Network filter %s undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine network filter %s"), name);
        ret = FALSE;
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

static int
cmdNWFilterDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNWFilterPtr nwfilter;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(nwfilter = vshCommandOptNWFilter(ctl, cmd, NULL)))
        return FALSE;

    dump = virNWFilterGetXMLDesc(nwfilter, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
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

static int
cmdNWFilterList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int numfilters, i;
    char **names;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    numfilters = virConnectNumOfNWFilters(ctl->conn);
    if (numfilters < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        return FALSE;
    }

    names = vshMalloc(ctl, sizeof(char *) * numfilters);

    if ((numfilters = virConnectListNWFilters(ctl->conn, names,
                                              numfilters)) < 0) {
        vshError(ctl, "%s", _("Failed to list network filters"));
        VIR_FREE(names);
        return FALSE;
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
    return TRUE;
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

static int
cmdNWFilterEdit (vshControl *ctl, const vshCmd *cmd)
{
    int ret = FALSE;
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
        ret = TRUE;
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

    ret = TRUE;

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

static int
cmdPoolAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    autostart = !vshCommandOptBool(cmd, "disable");

    if (virStoragePoolSetAutostart(pool, autostart) < 0) {
        if (autostart)
            vshError(ctl, _("failed to mark pool %s as autostarted"), name);
        else
            vshError(ctl, _("failed to unmark pool %s as autostarted"), name);
        virStoragePoolFree(pool);
        return FALSE;
    }

    if (autostart)
        vshPrint(ctl, _("Pool %s marked as autostarted\n"), name);
    else
        vshPrint(ctl, _("Pool %s unmarked as autostarted\n"), name);

    virStoragePoolFree(pool);
    return TRUE;
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

static int
cmdPoolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    pool = virStoragePoolCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrint(ctl, _("Pool %s created from %s\n"),
                 virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to create pool from %s"), from);
        ret = FALSE;
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

static int
cmdNodeDeviceCreate(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    char *from;
    int found = 0;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    dev = virNodeDeviceCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (dev != NULL) {
        vshPrint(ctl, _("Node device %s created from %s\n"),
                 virNodeDeviceGetName(dev), from);
        virNodeDeviceFree(dev);
    } else {
        vshError(ctl, _("Failed to create node device from %s"), from);
        ret = FALSE;
    }

    return ret;
}


/*
 * "nodedev-destroy" command
 */
static const vshCmdInfo info_node_device_destroy[] = {
    {"help", N_("destroy a device on the node")},
    {"desc", N_("Destroy a device on the node.  Note that this "
                          "command destroys devices on the physical host ")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_destroy[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ,
     N_("name of the device to be destroyed")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    int ret = TRUE;
    int found = 0;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn)) {
        return FALSE;
    }

    name = vshCommandOptString(cmd, "name", &found);
    if (!found) {
        return FALSE;
    }

    dev = virNodeDeviceLookupByName(ctl->conn, name);

    if (virNodeDeviceDestroy(dev) == 0) {
        vshPrint(ctl, _("Destroyed node device '%s'\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy node device '%s'"), name);
        ret = FALSE;
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

static int buildPoolXML(const vshCmd *cmd, char **retname, char **xml) {

    int found;
    char *name, *type, *srcHost, *srcPath, *srcDev, *srcName, *srcFormat, *target;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    name = vshCommandOptString(cmd, "name", &found);
    if (!found)
        goto cleanup;
    type = vshCommandOptString(cmd, "type", &found);
    if (!found)
        goto cleanup;

    srcHost = vshCommandOptString(cmd, "source-host", &found);
    srcPath = vshCommandOptString(cmd, "source-path", &found);
    srcDev = vshCommandOptString(cmd, "source-dev", &found);
    srcName = vshCommandOptString(cmd, "source-name", &found);
    srcFormat = vshCommandOptString(cmd, "source-format", &found);
    target = vshCommandOptString(cmd, "target", &found);

    virBufferVSprintf(&buf, "<pool type='%s'>\n", type);
    virBufferVSprintf(&buf, "  <name>%s</name>\n", name);
    if (srcHost || srcPath || srcDev) {
        virBufferAddLit(&buf, "  <source>\n");

        if (srcHost)
            virBufferVSprintf(&buf, "    <host name='%s'/>\n", srcHost);
        if (srcPath)
            virBufferVSprintf(&buf, "    <dir path='%s'/>\n", srcPath);
        if (srcDev)
            virBufferVSprintf(&buf, "    <device path='%s'/>\n", srcDev);
        if (srcFormat)
            virBufferVSprintf(&buf, "    <format type='%s'/>\n", srcFormat);
        if (srcName)
            virBufferVSprintf(&buf, "    <name>%s</name>\n", srcName);

        virBufferAddLit(&buf, "  </source>\n");
    }
    if (target) {
        virBufferAddLit(&buf, "  <target>\n");
        virBufferVSprintf(&buf, "    <path>%s</path>\n", target);
        virBufferAddLit(&buf, "  </target>\n");
    }
    virBufferAddLit(&buf, "</pool>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return FALSE;
    }

    *xml = virBufferContentAndReset(&buf);
    *retname = name;
    return TRUE;

cleanup:
    virBufferFreeAndReset(&buf);
    return FALSE;
}

/*
 * "pool-create-as" command
 */
static const vshCmdInfo info_pool_create_as[] = {
    {"help", N_("create a pool from a set of args")},
    {"desc", N_("Create a pool.")},
    {NULL, NULL}
};

static int
cmdPoolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *xml, *name;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!buildPoolXML(cmd, &name, &xml))
        return FALSE;

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
            return FALSE;
        }
    }
    return TRUE;
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

static int
cmdPoolDefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    pool = virStoragePoolDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (pool != NULL) {
        vshPrint(ctl, _("Pool %s defined from %s\n"),
                 virStoragePoolGetName(pool), from);
        virStoragePoolFree(pool);
    } else {
        vshError(ctl, _("Failed to define pool from %s"), from);
        ret = FALSE;
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

static int
cmdPoolDefineAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *xml, *name;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!buildPoolXML(cmd, &name, &xml))
        return FALSE;

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
            return FALSE;
        }
    }
    return TRUE;
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
    {NULL, 0, 0, NULL}
};

static int
cmdPoolBuild(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    if (virStoragePoolBuild(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s built\n"), name);
    } else {
        vshError(ctl, _("Failed to build pool %s"), name);
        ret = FALSE;
    }

    virStoragePoolFree(pool);

    return ret;
}


/*
 * "pool-destroy" command
 */
static const vshCmdInfo info_pool_destroy[] = {
    {"help", N_("destroy a pool")},
    {"desc", N_("Destroy a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_destroy[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, N_("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    if (virStoragePoolDestroy(pool) == 0) {
        vshPrint(ctl, _("Pool %s destroyed\n"), name);
    } else {
        vshError(ctl, _("Failed to destroy pool %s"), name);
        ret = FALSE;
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

static int
cmdPoolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    if (virStoragePoolDelete(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete pool %s"), name);
        ret = FALSE;
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

static int
cmdPoolRefresh(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    if (virStoragePoolRefresh(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s refreshed\n"), name);
    } else {
        vshError(ctl, _("Failed to refresh pool %s"), name);
        ret = FALSE;
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

static int
cmdPoolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return FALSE;

    dump = virStoragePoolGetXMLDesc(pool, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
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

static int
cmdPoolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStoragePoolInfo info;
    char **poolNames = NULL;
    int i, functionReturn, ret;
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
        return FALSE;

    /* Retrieve the number of active storage pools */
    if (active) {
        numActivePools = virConnectNumOfStoragePools(ctl->conn);
        if (numActivePools < 0) {
            vshError(ctl, "%s", _("Failed to list active pools"));
            return FALSE;
        }
    }

    /* Retrieve the number of inactive storage pools */
    if (inactive) {
        numInactivePools = virConnectNumOfDefinedStoragePools(ctl->conn);
        if (numInactivePools < 0) {
            vshError(ctl, "%s", _("Failed to list inactive pools"));
            return FALSE;
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
            return FALSE;
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
            return FALSE;
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
            vshDebug(ctl, 5, "Persistent flag value: %d\n", persistent);
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
        functionReturn = TRUE;
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
    vshDebug(ctl, 5, "Longest name string = %lu chars\n",
             (unsigned long) nameStrLength);
    vshDebug(ctl, 5, "Longest state string = %lu chars\n",
             (unsigned long) stateStrLength);
    vshDebug(ctl, 5, "Longest autostart string = %lu chars\n",
             (unsigned long) autostartStrLength);
    vshDebug(ctl, 5, "Longest persistent string = %lu chars\n",
             (unsigned long) persistStrLength);
    vshDebug(ctl, 5, "Longest capacity string = %lu chars\n",
             (unsigned long) capStrLength);
    vshDebug(ctl, 5, "Longest allocation string = %lu chars\n",
             (unsigned long) allocStrLength);
    vshDebug(ctl, 5, "Longest available string = %lu chars\n",
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
    functionReturn = TRUE;
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
    functionReturn = FALSE;

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

static int
cmdPoolDiscoverSourcesAs(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    char *type, *host;
    char *srcSpec = NULL;
    char *srcList;
    char *initiator;
    int found;

    type = vshCommandOptString(cmd, "type", &found);
    if (!found)
        return FALSE;
    host = vshCommandOptString(cmd, "host", &found);
    if (!found)
        host = NULL;
    initiator = vshCommandOptString(cmd, "initiator", &found);
    if (!found)
        initiator = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (host) {
        char *port = vshCommandOptString(cmd, "port", &found);
        if (!found)
            port = NULL;
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        virBufferAddLit(&buf, "<source>\n");
        virBufferVSprintf(&buf, "  <host name='%s'", host);
        if (port)
            virBufferVSprintf(&buf, " port='%s'", port);
        virBufferAddLit(&buf, "/>\n");
        if (initiator) {
            virBufferAddLit(&buf, "  <initiator>\n");
            virBufferVSprintf(&buf, "    <iqn name='%s'/>\n", initiator);
            virBufferAddLit(&buf, "  </initiator>\n");
        }
        virBufferAddLit(&buf, "</source>\n");
        if (virBufferError(&buf)) {
            vshError(ctl, "%s", _("Out of memory"));
            return FALSE;
        }
        srcSpec = virBufferContentAndReset(&buf);
    }

    srcList = virConnectFindStoragePoolSources(ctl->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return FALSE;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return TRUE;
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

static int
cmdPoolDiscoverSources(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    char *type, *srcSpecFile, *srcList;
    char *srcSpec = NULL;
    int found;

    type = vshCommandOptString(cmd, "type", &found);
    if (!found)
        return FALSE;
    srcSpecFile = vshCommandOptString(cmd, "srcSpec", &found);
    if (!found)
        srcSpecFile = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (srcSpecFile && virFileReadAll(srcSpecFile, VIRSH_MAX_XML_FILE, &srcSpec) < 0)
        return FALSE;

    srcList = virConnectFindStoragePoolSources(ctl->conn, type, srcSpec, 0);
    VIR_FREE(srcSpec);
    if (srcList == NULL) {
        vshError(ctl, _("Failed to find any %s pool sources"), type);
        return FALSE;
    }
    vshPrint(ctl, "%s", srcList);
    VIR_FREE(srcList);

    return TRUE;
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

static int
cmdPoolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolInfo info;
    virStoragePoolPtr pool;
    int autostart = 0;
    int persistent = 0;
    int ret = TRUE;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return FALSE;

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
        vshDebug(ctl, 5, "Pool persistent flag value: %d\n", persistent);
        if (persistent < 0)
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"),  _("unknown"));
        else
            vshPrint(ctl, "%-15s %s\n", _("Persistent:"), persistent ? _("yes") : _("no"));

        /* Check and display whether the pool is autostarted or not */
        virStoragePoolGetAutostart(pool, &autostart);
        vshDebug(ctl, 5, "Pool autostart flag value: %d\n", autostart);
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
        ret = FALSE;
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

static int
cmdPoolName(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virStoragePoolGetName(pool));
    virStoragePoolFree(pool);
    return TRUE;
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

static int
cmdPoolStart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL, VSH_BYNAME)))
         return FALSE;

    if (virStoragePoolCreate(pool, 0) == 0) {
        vshPrint(ctl, _("Pool %s started\n"),
                 virStoragePoolGetName(pool));
    } else {
        vshError(ctl, _("Failed to start pool %s"), virStoragePoolGetName(pool));
        ret = FALSE;
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
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ, N_("size of the vol with optional k,M,G,T suffix")},
    {"allocation", VSH_OT_STRING, 0, N_("initial allocation size with optional k,M,G,T suffix")},
    {"format", VSH_OT_STRING, 0, N_("file format type raw,bochs,qcow,qcow2,vmdk")},
    {"backing-vol", VSH_OT_STRING, 0, N_("the backing volume if taking a snapshot")},
    {"backing-vol-format", VSH_OT_STRING, 0, N_("format of backing volume if taking a snapshot")},
    {NULL, 0, 0, NULL}
};

static int cmdVolSize(const char *data, unsigned long long *val)
{
    char *end;
    if (virStrToLong_ull(data, &end, 10, val) < 0)
        return -1;

    if (end && *end) {
        /* Deliberate fallthrough cases here :-) */
        switch (*end) {
        case 'T':
            *val *= 1024;
        case 'G':
            *val *= 1024;
        case 'M':
            *val *= 1024;
        case 'k':
            *val *= 1024;
            break;
        default:
            return -1;
        }
        end++;
        if (*end)
            return -1;
    }
    return 0;
}

static int
cmdVolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    int found;
    char *xml;
    char *name, *capacityStr, *allocationStr, *format;
    char *snapshotStrVol, *snapshotStrFormat;
    unsigned long long capacity, allocation = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                     VSH_BYNAME)))
        return FALSE;

    name = vshCommandOptString(cmd, "name", &found);
    if (!found)
        goto cleanup;

    capacityStr = vshCommandOptString(cmd, "capacity", &found);
    if (!found)
        goto cleanup;
    if (cmdVolSize(capacityStr, &capacity) < 0)
        vshError(ctl, _("Malformed size %s"), capacityStr);

    allocationStr = vshCommandOptString(cmd, "allocation", &found);
    if (allocationStr &&
        cmdVolSize(allocationStr, &allocation) < 0)
        vshError(ctl, _("Malformed size %s"), allocationStr);

    format = vshCommandOptString(cmd, "format", &found);
    snapshotStrVol = vshCommandOptString(cmd, "backing-vol", &found);
    snapshotStrFormat = vshCommandOptString(cmd, "backing-vol-format", &found);

    virBufferAddLit(&buf, "<volume>\n");
    virBufferVSprintf(&buf, "  <name>%s</name>\n", name);
    virBufferVSprintf(&buf, "  <capacity>%llu</capacity>\n", capacity);
    if (allocationStr)
        virBufferVSprintf(&buf, "  <allocation>%llu</allocation>\n", allocation);

    if (format) {
        virBufferAddLit(&buf, "  <target>\n");
        virBufferVSprintf(&buf, "    <format type='%s'/>\n",format);
        virBufferAddLit(&buf, "  </target>\n");
    }

    /* Convert the snapshot parameters into backingStore XML */
    if (snapshotStrVol) {
        /* Lookup snapshot backing volume.  Try the backing-vol
         *  parameter as a name */
        vshDebug(ctl, 5, "%s: Look up backing store volume '%s' as name\n",
                 cmd->def->name, snapshotStrVol);
        virStorageVolPtr snapVol = virStorageVolLookupByName(pool, snapshotStrVol);
        if (snapVol)
                vshDebug(ctl, 5, "%s: Backing store volume found using '%s' as name\n",
                         cmd->def->name, snapshotStrVol);

        if (snapVol == NULL) {
            /* Snapshot backing volume not found by name.  Try the
             *  backing-vol parameter as a key */
            vshDebug(ctl, 5, "%s: Look up backing store volume '%s' as key\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByKey(ctl->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, 5, "%s: Backing store volume found using '%s' as key\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            /* Snapshot backing volume not found by key.  Try the
             *  backing-vol parameter as a path */
            vshDebug(ctl, 5, "%s: Look up backing store volume '%s' as path\n",
                     cmd->def->name, snapshotStrVol);
            snapVol = virStorageVolLookupByPath(ctl->conn, snapshotStrVol);
            if (snapVol)
                vshDebug(ctl, 5, "%s: Backing store volume found using '%s' as path\n",
                         cmd->def->name, snapshotStrVol);
        }
        if (snapVol == NULL) {
            vshError(ctl, _("failed to get vol '%s'"), snapshotStrVol);
            return FALSE;
        }

        char *snapshotStrVolPath;
        if ((snapshotStrVolPath = virStorageVolGetPath(snapVol)) == NULL) {
            virStorageVolFree(snapVol);
            return FALSE;
        }

        /* Create XML for the backing store */
        virBufferAddLit(&buf, "  <backingStore>\n");
        virBufferVSprintf(&buf, "    <path>%s</path>\n",snapshotStrVolPath);
        if (snapshotStrFormat)
            virBufferVSprintf(&buf, "    <format type='%s'/>\n",snapshotStrFormat);
        virBufferAddLit(&buf, "  </backingStore>\n");

        /* Cleanup snapshot allocations */
        VIR_FREE(snapshotStrVolPath);
        virStorageVolFree(snapVol);
    }

    virBufferAddLit(&buf, "</volume>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return FALSE;
    }
    xml = virBufferContentAndReset(&buf);
    vol = virStorageVolCreateXML(pool, xml, 0);
    VIR_FREE(xml);
    virStoragePoolFree(pool);

    if (vol != NULL) {
        vshPrint(ctl, _("Vol %s created\n"), name);
        virStorageVolFree(vol);
        return TRUE;
    } else {
        vshError(ctl, _("Failed to create vol %s"), name);
        return FALSE;
    }

 cleanup:
    virBufferFreeAndReset(&buf);
    virStoragePoolFree(pool);
    return FALSE;
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

static int
cmdPoolUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", &name)))
        return FALSE;

    if (virStoragePoolUndefine(pool) == 0) {
        vshPrint(ctl, _("Pool %s has been undefined\n"), name);
    } else {
        vshError(ctl, _("Failed to undefine pool %s"), name);
        ret = FALSE;
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

static int
cmdPoolUuid(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYNAME)))
        return FALSE;

    if (virStoragePoolGetUUIDString(pool, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, "%s", _("failed to get pool UUID"));

    virStoragePoolFree(pool);
    return TRUE;
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

static int
cmdVolCreate(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL,
                                           VSH_BYNAME)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        virStoragePoolFree(pool);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virStoragePoolFree(pool);
        return FALSE;
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
        ret = FALSE;
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
    {"inputpool", VSH_OT_STRING, 0, N_("pool name or uuid of the input volume's pool")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("input vol name or key")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolCreateFrom(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr newvol = NULL, inputvol = NULL;
    char *from;
    int found;
    int ret = FALSE;
    char *buffer = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(pool = vshCommandOptPoolBy(ctl, cmd, "pool", NULL, VSH_BYNAME)))
        goto cleanup;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
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

    ret = TRUE;
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
makeCloneXML(char *origxml, char *newname) {

    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlChar *newxml = NULL;
    int size;

    doc = xmlReadDoc((const xmlChar *) origxml, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET | XML_PARSE_NOWARNING);
    if (!doc)
        goto cleanup;
    ctxt = xmlXPathNewContext(doc);
    if (!ctxt)
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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("orig vol name or key")},
    {"newname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("clone name")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolClone(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr origpool = NULL;
    virStorageVolPtr origvol = NULL, newvol = NULL;
    char *name, *origxml = NULL;
    xmlChar *newxml = NULL;
    int found;
    int ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(origvol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        goto cleanup;

    origpool = virStoragePoolLookupByVolume(origvol);
    if (!origpool) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        goto cleanup;
    }

    name = vshCommandOptString(cmd, "newname", &found);
    if (!found)
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

    ret = TRUE;

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
 * "vol-delete" command
 */
static const vshCmdInfo info_vol_delete[] = {
    {"help", N_("delete a vol")},
    {"desc", N_("Delete a given vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_delete[] = {
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return FALSE;
    }

    if (virStorageVolDelete(vol, 0) == 0) {
        vshPrint(ctl, _("Vol %s deleted\n"), name);
    } else {
        vshError(ctl, _("Failed to delete vol %s"), name);
        ret = FALSE;
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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolWipe(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return FALSE;
    }

    if (virStorageVolWipe(vol, 0) == 0) {
        vshPrint(ctl, _("Vol %s wiped\n"), name);
    } else {
        vshError(ctl, _("Failed to wipe vol %s"), name);
        ret = FALSE;
    }

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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return FALSE;

    vshPrint(ctl, "%-15s %s\n", _("Name:"), virStorageVolGetName(vol));

    if (virStorageVolGetInfo(vol, &info) == 0) {
        double val;
        const char *unit;
        vshPrint(ctl, "%-15s %s\n", _("Type:"),
                 info.type == VIR_STORAGE_VOL_FILE ?
                 _("file") : _("block"));

        val = prettyCapacity(info.capacity, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Capacity:"), val, unit);

        val = prettyCapacity(info.allocation, &unit);
        vshPrint(ctl, "%-15s %2.2lf %s\n", _("Allocation:"), val, unit);
    } else {
        ret = FALSE;
    }

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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return FALSE;

    dump = virStorageVolGetXMLDesc(vol, 0);
    if (dump != NULL) {
        vshPrint(ctl, "%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
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

static int
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
    int ret, functionReturn;
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
        return FALSE;

    /* Look up the pool information given to us by the user */
    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return FALSE;

    /* Determine the number of volumes in the pool */
    numVolumes = virStoragePoolNumOfVolumes(pool);

    if (numVolumes < 0) {
        vshError(ctl, "%s", _("Failed to list storage volumes"));
        virStoragePoolFree(pool);
        return FALSE;
    }

    /* Retrieve the list of volume names in the pool */
    if (numVolumes > 0) {
        activeNames = vshCalloc(ctl, numVolumes, sizeof(*activeNames));
        if ((numVolumes = virStoragePoolListVolumes(pool, activeNames,
                                                    numVolumes)) < 0) {
            vshError(ctl, "%s", _("Failed to list active vols"));
            VIR_FREE(activeNames);
            virStoragePoolFree(pool);
            return FALSE;
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
                if (volumeInfo.type == VIR_STORAGE_VOL_FILE)
                    volInfoTexts[i].type = vshStrdup(ctl, _("file"));
                else
                    volInfoTexts[i].type = vshStrdup(ctl, _("block"));

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
        functionReturn = TRUE;
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
    vshDebug(ctl, 5, "Longest name string = %zu chars\n", nameStrLength);
    vshDebug(ctl, 5, "Longest path string = %zu chars\n", pathStrLength);
    vshDebug(ctl, 5, "Longest type string = %zu chars\n", typeStrLength);
    vshDebug(ctl, 5, "Longest capacity string = %zu chars\n", capStrLength);
    vshDebug(ctl, 5, "Longest allocation string = %zu chars\n", allocStrLength);

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
    functionReturn = TRUE;
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
    functionReturn = FALSE;

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

static int
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", "pool", NULL,
                                   VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virStorageVolGetName(vol));
    virStorageVolFree(vol);
    return TRUE;
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

static int
cmdVolPool(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    virStorageVolPtr vol;
    char uuid[VIR_UUID_STRING_BUFLEN];

    /* Check the connection to libvirtd daemon is still working */
    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    /* Use the supplied string to locate the volume */
    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", "pool", NULL,
                                   VSH_BYUUID))) {
        return FALSE;
    }

    /* Look up the parent storage pool for the volume */
    pool = virStoragePoolLookupByVolume(vol);
    if (pool == NULL) {
        vshError(ctl, "%s", _("failed to get parent pool"));
        virStorageVolFree(vol);
        return FALSE;
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
    return TRUE;
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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return FALSE;

    vshPrint(ctl, "%s\n", virStorageVolGetKey(vol));
    virStorageVolFree(vol);
    return TRUE;
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
    {"pool", VSH_OT_STRING, 0, N_("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, N_("volume name or key")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", &name))) {
        return FALSE;
    }

    vshPrint(ctl, "%s\n", virStorageVolGetPath(vol));
    virStorageVolFree(vol);
    return TRUE;
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

static int
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    char *from, *buffer;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", NULL);
    if (!from)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    res = virSecretDefineXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (res == NULL) {
        vshError(ctl, _("Failed to set attributes from %s"), from);
        return FALSE;
    }
    if (virSecretGetUUIDString(res, &(uuid[0])) < 0) {
        vshError(ctl, "%s", _("Failed to get UUID of created secret"));
        virSecretFree(res);
        return FALSE;
    }
    vshPrint(ctl, _("Secret %s created\n"), uuid);
    virSecretFree(res);
    return TRUE;
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

static int
cmdSecretDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    int ret = FALSE;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return FALSE;

    xml = virSecretGetXMLDesc(secret, 0);
    if (xml == NULL)
        goto cleanup;
    vshPrint(ctl, "%s", xml);
    VIR_FREE(xml);
    ret = TRUE;

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

static int
cmdSecretSetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    size_t value_size;
    char *base64, *value;
    int found, res, ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return FALSE;

    base64 = vshCommandOptString(cmd, "base64", &found);
    if (!base64)
        goto cleanup;

    if (!base64_decode_alloc(base64, strlen(base64), &value, &value_size)) {
        vshError(ctl, "%s", _("Invalid base64 data"));
        goto cleanup;
    }
    if (value == NULL) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        return FALSE;
    }

    res = virSecretSetValue(secret, (unsigned char *)value, value_size, 0);
    memset(value, 0, value_size);
    VIR_FREE(value);

    if (res != 0) {
        vshError(ctl, "%s", _("Failed to set secret value"));
        goto cleanup;
    }
    vshPrint(ctl, "%s", _("Secret value set\n"));
    ret = TRUE;

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

static int
cmdSecretGetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    char *base64;
    unsigned char *value;
    size_t value_size;
    int ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return FALSE;

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
    ret = TRUE;

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

static int
cmdSecretUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    int ret = FALSE;
    char *uuid;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    secret = vshCommandOptSecret(ctl, cmd, &uuid);
    if (secret == NULL)
        return FALSE;

    if (virSecretUndefine(secret) < 0) {
        vshError(ctl, _("Failed to delete secret %s"), uuid);
        goto cleanup;
    }
    vshPrint(ctl, _("Secret %s deleted\n"), uuid);
    ret = TRUE;

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

static int
cmdSecretList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int maxuuids = 0, i;
    char **uuids = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    maxuuids = virConnectNumOfSecrets(ctl->conn);
    if (maxuuids < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        return FALSE;
    }
    uuids = vshMalloc(ctl, sizeof(*uuids) * maxuuids);

    maxuuids = virConnectListSecrets(ctl->conn, uuids, maxuuids);
    if (maxuuids < 0) {
        vshError(ctl, "%s", _("Failed to list secrets"));
        VIR_FREE(uuids);
        return FALSE;
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
    return TRUE;
}


/*
 * "version" command
 */
static const vshCmdInfo info_version[] = {
    {"help", N_("show version")},
    {"desc", N_("Display the system version information.")},
    {NULL, NULL}
};


static int
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long hvVersion;
    const char *hvType;
    unsigned long libVersion;
    unsigned long includeVersion;
    unsigned long apiVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    hvType = virConnectGetType(ctl->conn);
    if (hvType == NULL) {
        vshError(ctl, "%s", _("failed to get hypervisor type"));
        return FALSE;
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
        return FALSE;
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
        return FALSE;
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
    return TRUE;
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

static int
cmdNodeListDevices (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *cap;
    char **devices;
    int found, num_devices, i;
    int tree = vshCommandOptBool(cmd, "tree");

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    cap = vshCommandOptString(cmd, "cap", &found);
    if (!found)
        cap = NULL;

    num_devices = virNodeNumOfDevices(ctl->conn, cap, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to count node devices"));
        return FALSE;
    } else if (num_devices == 0) {
        return TRUE;
    }

    devices = vshMalloc(ctl, sizeof(char *) * num_devices);
    num_devices =
        virNodeListDevices(ctl->conn, cap, devices, num_devices, 0);
    if (num_devices < 0) {
        vshError(ctl, "%s", _("Failed to list node devices"));
        VIR_FREE(devices);
        return FALSE;
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
            memset(indentBuf, '\0', sizeof indentBuf);
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
    return TRUE;
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

static int
cmdNodeDeviceDumpXML (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(name = vshCommandOptString(cmd, "device", NULL)))
        return FALSE;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return FALSE;
    }

    xml = virNodeDeviceGetXMLDesc(device, 0);
    if (!xml) {
        virNodeDeviceFree(device);
        return FALSE;
    }

    vshPrint(ctl, "%s\n", xml);
    VIR_FREE(xml);
    virNodeDeviceFree(device);
    return TRUE;
}

/*
 * "nodedev-dettach" command
 */
static const vshCmdInfo info_node_device_dettach[] = {
    {"help", N_("dettach node device from its device driver")},
    {"desc", N_("Dettach node device from its device driver before assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_dettach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, N_("device key")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceDettach (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(name = vshCommandOptString(cmd, "device", NULL)))
        return FALSE;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return FALSE;
    }

    if (virNodeDeviceDettach(device) == 0) {
        vshPrint(ctl, _("Device %s dettached\n"), name);
    } else {
        vshError(ctl, _("Failed to dettach device %s"), name);
        ret = FALSE;
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

static int
cmdNodeDeviceReAttach (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(name = vshCommandOptString(cmd, "device", NULL)))
        return FALSE;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return FALSE;
    }

    if (virNodeDeviceReAttach(device) == 0) {
        vshPrint(ctl, _("Device %s re-attached\n"), name);
    } else {
        vshError(ctl, _("Failed to re-attach device %s"), name);
        ret = FALSE;
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

static int
cmdNodeDeviceReset (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;
    if (!(name = vshCommandOptString(cmd, "device", NULL)))
        return FALSE;
    if (!(device = virNodeDeviceLookupByName(ctl->conn, name))) {
        vshError(ctl, "%s '%s'", _("Could not find matching device"), name);
        return FALSE;
    }

    if (virNodeDeviceReset(device) == 0) {
        vshPrint(ctl, _("Device %s reset\n"), name);
    } else {
        vshError(ctl, _("Failed to reset device %s"), name);
        ret = FALSE;
    }
    virNodeDeviceFree(device);
    return ret;
}

/*
 * "hostkey" command
 */
static const vshCmdInfo info_hostname[] = {
    {"help", N_("print the hypervisor hostname")},
    {"desc", ""},
    {NULL, NULL}
};

static int
cmdHostname (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    hostname = virConnectGetHostname (ctl->conn);
    if (hostname == NULL) {
        vshError(ctl, "%s", _("failed to get hostname"));
        return FALSE;
    }

    vshPrint (ctl, "%s\n", hostname);
    VIR_FREE(hostname);

    return TRUE;
}

/*
 * "uri" command
 */
static const vshCmdInfo info_uri[] = {
    {"help", N_("print the hypervisor canonical URI")},
    {"desc", ""},
    {NULL, NULL}
};

static int
cmdURI (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    uri = virConnectGetURI (ctl->conn);
    if (uri == NULL) {
        vshError(ctl, "%s", _("failed to get URI"));
        return FALSE;
    }

    vshPrint (ctl, "%s\n", uri);
    VIR_FREE(uri);

    return TRUE;
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

static int
cmdVNCDisplay(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    int ret = FALSE;
    int port = 0;
    char *doc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = xmlReadDoc((const xmlChar *) doc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOWARNING);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;
    ctxt = xmlXPathNewContext(xml);
    if (!ctxt)
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
    ret = TRUE;

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    if (xml)
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

static int
cmdTTYConsole(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virDomainPtr dom;
    int ret = FALSE;
    char *doc;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = xmlReadDoc((const xmlChar *) doc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOWARNING);
    VIR_FREE(doc);
    if (!xml)
        goto cleanup;
    ctxt = xmlXPathNewContext(xml);
    if (!ctxt)
        goto cleanup;

    obj = xmlXPathEval(BAD_CAST "string(/domain/devices/console/@tty)", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        goto cleanup;
    }
    vshPrint(ctl, "%s\n", (const char *)obj->stringval);
    ret = TRUE;

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    if (xml)
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist device attachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdAttachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *from;
    char *buffer;
    int ret = TRUE;
    int found;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return FALSE;
    }

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainAttachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainAttachDevice(dom, buffer);
    }
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to attach device from %s"), from);
        virDomainFree(dom);
        return FALSE;
    } else {
        vshPrint(ctl, "%s", _("Device attached successfully\n"));
    }

    virDomainFree(dom);
    return TRUE;
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist device detachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdDetachDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *from;
    char *buffer;
    int ret = TRUE;
    int found;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return FALSE;
    }

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainDetachDeviceFlags(dom, buffer, flags);
    } else {
        ret = virDomainDetachDevice(dom, buffer);
    }
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to detach device from %s"), from);
        virDomainFree(dom);
        return FALSE;
    } else {
        vshPrint(ctl, "%s", _("Device detached successfully\n"));
    }

    virDomainFree(dom);
    return TRUE;
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist device update")},
    {"force",  VSH_OT_BOOL, 0, N_("force device update")},
    {NULL, 0, 0, NULL}
};

static int
cmdUpdateDevice(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *from;
    char *buffer;
    int ret = TRUE;
    int found;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        virshReportError(ctl);
        virDomainFree(dom);
        return FALSE;
    }

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
           flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    } else {
        flags = VIR_DOMAIN_DEVICE_MODIFY_LIVE;
    }

    if (vshCommandOptBool(cmd, "force"))
        flags |= VIR_DOMAIN_DEVICE_MODIFY_FORCE;

    ret = virDomainUpdateDeviceFlags(dom, buffer, flags);
    VIR_FREE(buffer);

    if (ret < 0) {
        vshError(ctl, _("Failed to update device from %s"), from);
        virDomainFree(dom);
        return FALSE;
    } else {
        vshPrint(ctl, "%s", _("Device updated successfully\n"));
    }

    virDomainFree(dom);
    return TRUE;
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist interface attachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    char *mac, *target, *script, *type, *source, *model;
    int typ, ret = FALSE;
    unsigned int flags;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (!(type = vshCommandOptString(cmd, "type", NULL)))
        goto cleanup;

    source = vshCommandOptString(cmd, "source", NULL);
    target = vshCommandOptString(cmd, "target", NULL);
    mac = vshCommandOptString(cmd, "mac", NULL);
    script = vshCommandOptString(cmd, "script", NULL);
    model = vshCommandOptString(cmd, "model", NULL);

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

    /* Make XML of interface */
    virBufferVSprintf(&buf, "<interface type='%s'>\n", type);

    if (typ == 1)
        virBufferVSprintf(&buf, "  <source network='%s'/>\n", source);
    else if (typ == 2)
        virBufferVSprintf(&buf, "  <source bridge='%s'/>\n", source);

    if (target != NULL)
        virBufferVSprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mac != NULL)
        virBufferVSprintf(&buf, "  <mac address='%s'/>\n", mac);
    if (script != NULL)
        virBufferVSprintf(&buf, "  <script path='%s'/>\n", script);
    if (model != NULL)
        virBufferVSprintf(&buf, "  <model type='%s'/>\n", model);

    virBufferAddLit(&buf, "</interface>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return FALSE;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach interface"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Interface attached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return ret;
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist interface detachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdDetachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj=NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    char *doc, *mac =NULL, *type;
    char buf[64];
    int i = 0, diff_mac, ret = FALSE;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (!(type = vshCommandOptString(cmd, "type", NULL)))
        goto cleanup;

    mac = vshCommandOptString(cmd, "mac", NULL);

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = xmlReadDoc((const xmlChar *) doc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOWARNING);
    VIR_FREE(doc);
    if (!xml) {
        vshError(ctl, "%s", _("Failed to get interface information"));
        goto cleanup;
    }
    ctxt = xmlXPathNewContext(xml);
    if (!ctxt) {
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

    if (!mac)
        goto hit;

    /* search mac */
    for (; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "mac")) {
                char *tmp_mac = virXMLPropString(cur, "address");
                diff_mac = virMacAddrCompare (tmp_mac, mac);
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

    if(xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0){
        vshError(ctl, "%s", _("Failed to create XML"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         (char *)xmlBufferContent(xml_buf),
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, (char *)xmlBufferContent(xml_buf));
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach interface"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Interface detached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    if (xml_buf)
        xmlBufferFree(xml_buf);
    return ret;
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
    {"source",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("source of disk device")},
    {"target",  VSH_OT_DATA, VSH_OFLAG_REQ, N_("target of disk device")},
    {"driver",    VSH_OT_STRING, 0, N_("driver of disk device")},
    {"subdriver", VSH_OT_STRING, 0, N_("subdriver of disk device")},
    {"type",    VSH_OT_STRING, 0, N_("target device type")},
    {"mode",    VSH_OT_STRING, 0, N_("mode of device reading and writing")},
    {"persistent", VSH_OT_BOOL, 0, N_("persist disk attachment")},
    {"sourcetype", VSH_OT_STRING, 0, N_("type of source (block|file)")},
    {NULL, 0, 0, NULL}
};

static int
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    char *source, *target, *driver, *subdriver, *type, *mode;
    int isFile = 0, ret = FALSE;
    unsigned int flags;
    char *stype;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (!(source = vshCommandOptString(cmd, "source", NULL)))
        goto cleanup;

    if (!(target = vshCommandOptString(cmd, "target", NULL)))
        goto cleanup;

    driver = vshCommandOptString(cmd, "driver", NULL);
    subdriver = vshCommandOptString(cmd, "subdriver", NULL);
    type = vshCommandOptString(cmd, "type", NULL);
    mode = vshCommandOptString(cmd, "mode", NULL);
    stype = vshCommandOptString(cmd, "sourcetype", NULL);

    if (!stype) {
        if (driver && (STREQ(driver, "file") || STREQ(driver, "tap")))
            isFile = 1;
    } else if (STREQ(stype, "file")) {
        isFile = 1;
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
    virBufferVSprintf(&buf, "<disk type='%s'",
                      (isFile) ? "file" : "block");
    if (type)
        virBufferVSprintf(&buf, " device='%s'", type);
    virBufferAddLit(&buf, ">\n");

    if (driver || subdriver)
        virBufferVSprintf(&buf, "  <driver");

    if (driver)
        virBufferVSprintf(&buf, " name='%s'", driver);
    if (subdriver)
        virBufferVSprintf(&buf, " type='%s'", subdriver);

    if (driver || subdriver)
        virBufferAddLit(&buf, "/>\n");

    virBufferVSprintf(&buf, "  <source %s='%s'/>\n",
                      (isFile) ? "file" : "dev",
                      source);
    virBufferVSprintf(&buf, "  <target dev='%s'/>\n", target);
    if (mode)
        virBufferVSprintf(&buf, "  <%s/>\n", mode);

    virBufferAddLit(&buf, "</disk>\n");

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return FALSE;
    }

    xml = virBufferContentAndReset(&buf);

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainAttachDeviceFlags(dom, xml, flags);
    } else {
        ret = virDomainAttachDevice(dom, xml);
    }

    VIR_FREE(xml);

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to attach disk"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Disk attached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    virBufferFreeAndReset(&buf);
    return ret;
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
    {"persistent", VSH_OT_BOOL, 0, N_("persist disk detachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdDetachDisk(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj=NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlBufferPtr xml_buf = NULL;
    virDomainPtr dom = NULL;
    char *doc, *target;
    int i = 0, diff_tgt, ret = FALSE;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (!(target = vshCommandOptString(cmd, "target", NULL)))
        goto cleanup;

    doc = virDomainGetXMLDesc(dom, 0);
    if (!doc)
        goto cleanup;

    xml = xmlReadDoc((const xmlChar *) doc, "domain.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOWARNING);
    VIR_FREE(doc);
    if (!xml) {
        vshError(ctl, "%s", _("Failed to get disk information"));
        goto cleanup;
    }
    ctxt = xmlXPathNewContext(xml);
    if (!ctxt) {
        vshError(ctl, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    obj = xmlXPathEval(BAD_CAST "/domain/devices/disk", ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr == 0)) {
        vshError(ctl, "%s", _("Failed to get disk information"));
        goto cleanup;
    }

    /* search target */
    for (; i < obj->nodesetval->nodeNr; i++) {
        cur = obj->nodesetval->nodeTab[i]->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "target")) {
                char *tmp_tgt = virXMLPropString(cur, "dev");
                diff_tgt = STREQ(tmp_tgt, target);
                VIR_FREE(tmp_tgt);
                if (diff_tgt) {
                    goto hit;
                }
            }
            cur = cur->next;
        }
    }
    vshError(ctl, _("No found disk whose target is %s"), target);
    goto cleanup;

 hit:
    xml_buf = xmlBufferCreate();
    if (!xml_buf) {
        vshError(ctl, "%s", _("Failed to allocate memory"));
        goto cleanup;
    }

    if(xmlNodeDump(xml_buf, xml, obj->nodesetval->nodeTab[i], 0, 0) < 0){
        vshError(ctl, "%s", _("Failed to create XML"));
        goto cleanup;
    }

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainDetachDeviceFlags(dom,
                                         (char *)xmlBufferContent(xml_buf),
                                         flags);
    } else {
        ret = virDomainDetachDevice(dom, (char *)xmlBufferContent(xml_buf));
    }

    if (ret != 0) {
        vshError(ctl, "%s", _("Failed to detach disk"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Disk detached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    if (xml_buf)
        xmlBufferFree(xml_buf);
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

static int
cmdCPUCompare(vshControl *ctl, const vshCmd *cmd)
{
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;
    int result;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    result = virConnectCompareCPU(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    switch (result) {
    case VIR_CPU_COMPARE_INCOMPATIBLE:
        vshPrint(ctl, _("CPU described in %s is incompatible with host CPU\n"),
                 from);
        ret = FALSE;
        break;

    case VIR_CPU_COMPARE_IDENTICAL:
        vshPrint(ctl, _("CPU described in %s is identical to host CPU\n"),
                 from);
        ret = TRUE;
        break;

    case VIR_CPU_COMPARE_SUPERSET:
        vshPrint(ctl, _("Host CPU is a superset of CPU described in %s\n"),
                 from);
        ret = TRUE;
        break;

    case VIR_CPU_COMPARE_ERROR:
    default:
        vshError(ctl, _("Failed to compare host CPU with %s"), from);
        ret = FALSE;
    }

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

static int
cmdCPUBaseline(vshControl *ctl, const vshCmd *cmd)
{
    char *from;
    int found;
    int ret = TRUE;
    char *buffer;
    char *result = NULL;
    const char **list = NULL;
    unsigned int count = 0;
    xmlDocPtr doc = NULL;
    xmlNodePtr node_list;
    xmlXPathContextPtr ctxt = NULL;
    xmlSaveCtxtPtr sctxt = NULL;
    xmlBufferPtr buf = NULL;
    xmlXPathObjectPtr obj = NULL;
    int res, i;

    if (!vshConnectionUsability(ctl, ctl->conn))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    doc = xmlNewDoc(NULL);
    if (doc == NULL)
        goto no_memory;

    res = xmlParseBalancedChunkMemory(doc, NULL, NULL, 0,
                                      (const xmlChar *)buffer, &node_list);
    if (res != 0) {
        vshError(ctl, _("Failed to parse XML fragment %s"), from);
        ret = FALSE;
        goto cleanup;
    }

    xmlAddChildList((xmlNodePtr) doc, node_list);

    ctxt = xmlXPathNewContext(doc);
    if (!ctxt)
        goto no_memory;

    obj = xmlXPathEval(BAD_CAST "//cpu[not(ancestor::cpu)]", ctxt);
    if ((obj == NULL) || (obj->nodesetval == NULL) ||
        (obj->nodesetval->nodeTab == NULL))
        goto cleanup;

    for (i = 0;i < obj->nodesetval->nodeNr;i++) {
        buf = xmlBufferCreate();
        if (buf == NULL)
            goto no_memory;
        sctxt = xmlSaveToBuffer(buf, NULL, 0);
        if (sctxt == NULL) {
            xmlBufferFree(buf);
            goto no_memory;
        }

        xmlSaveTree(sctxt, obj->nodesetval->nodeTab[i]);
        xmlSaveClose(sctxt);

        list = vshRealloc(ctl, list, sizeof(char *) * (count + 1));
        list[count++] = (char *) buf->content;
        buf->content = NULL;
        xmlBufferFree(buf);
        buf = NULL;
    }

    if (count == 0) {
        vshError(ctl, _("No host CPU specified in '%s'"), from);
        ret = FALSE;
        goto cleanup;
    }

    result = virConnectBaselineCPU(ctl->conn, list, count, 0);

    if (result)
        vshPrint(ctl, "%s", result);
    else
        ret = FALSE;

cleanup:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    VIR_FREE(result);
    if ((list != NULL) && (count > 0)) {
        for (i = 0;i < count;i++)
            VIR_FREE(list[i]);
    }
    VIR_FREE(list);
    VIR_FREE(buffer);

    return ret;

no_memory:
    vshError(ctl, "%s", _("Out of memory"));
    ret = FALSE;
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
    char *command;
    int command_ret;

    editor = getenv ("VISUAL");
    if (!editor) editor = getenv ("EDITOR");
    if (!editor) editor = "vi"; /* could be cruel & default to ed(1) here */

    /* Check that filename doesn't contain shell meta-characters, and
     * if it does, refuse to run.  Follow the Unix conventions for
     * EDITOR: the user can intentionally specify command options, so
     * we don't protect any shell metacharacters there.  Lots more
     * than virsh will misbehave if EDITOR has bogus contents (which
     * is why sudo scrubs it by default).
     */
    if (strspn (filename, ACCEPTED_CHARS) != strlen (filename)) {
        vshError(ctl,
                 _("%s: temporary filename contains shell meta or other "
                   "unacceptable characters (is $TMPDIR wrong?)"),
                 filename);
        return -1;
    }

    if (virAsprintf(&command, "%s %s", editor, filename) == -1) {
        vshError(ctl,
                 _("virAsprintf: could not create editing command: %s"),
                 strerror(errno));
        return -1;
    }

    command_ret = system (command);
    if (command_ret == -1) {
        vshError(ctl,
                 _("%s: edit command failed: %s"), command, strerror(errno));
        VIR_FREE(command);
        return -1;
    }
    if (WEXITSTATUS(command_ret) != 0) {
        vshError(ctl,
                 _("%s: command exited with non-zero status"), command);
        VIR_FREE(command);
        return -1;
    }
    VIR_FREE(command);
    return 0;
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


#ifndef WIN32
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

static int
cmdCd(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *dir;
    int found;

    if (!ctl->imode) {
        vshError(ctl, "%s", _("cd: command valid only in interactive mode"));
        return FALSE;
    }

    dir = vshCommandOptString(cmd, "dir", &found);
    if (!found) {
        uid_t uid = geteuid();
        dir = virGetUserDirectory(uid);
    }
    if (!dir)
        dir = "/";

    if (chdir (dir) == -1) {
        vshError(ctl, _("cd: %s: %s"), strerror(errno), dir);
        return FALSE;
    }

    return TRUE;
}

#endif

#ifndef WIN32
/*
 * "pwd" command
 */
static const vshCmdInfo info_pwd[] = {
    {"help", N_("print the current directory")},
    {"desc", N_("Print the current directory.")},
    {NULL, NULL}
};

static int
cmdPwd(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *cwd;
    size_t path_max;
    int err = TRUE;

    path_max = (size_t) PATH_MAX + 2;
    cwd = vshMalloc (ctl, path_max);
    while (cwd) {
        err = getcwd (cwd, path_max) == NULL;
        if (!err || errno != ERANGE)
            break;

        path_max *= 2;
        cwd = vshRealloc (ctl, cwd, path_max);
    }

    if (err)
        vshError(ctl, _("pwd: cannot get current directory: %s"),
                 strerror(errno));
    else
        vshPrint (ctl, _("%s\n"), cwd);

    VIR_FREE(cwd);
    return !err;
}
#endif

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
    {"", VSH_OT_ARGV, 0, N_("arguments to echo")},
    {NULL, 0, 0, NULL}
};

/* Exists mainly for debugging virsh, but also handy for adding back
 * quotes for later evaluation.
 */
static int
cmdEcho (vshControl *ctl ATTRIBUTE_UNUSED, const vshCmd *cmd)
{
    bool shell = false;
    bool xml = false;
    int count = 0;
    char *arg;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (vshCommandOptBool(cmd, "shell"))
        shell = true;
    if (vshCommandOptBool(cmd, "xml"))
        xml = true;

    while ((arg = vshCommandOptArgv(cmd, count)) != NULL) {
        bool close_quote = false;
        char *q;

        if (count)
            virBufferAddChar(&buf, ' ');
        /* Add outer '' only if arg included shell metacharacters.  */
        if (shell &&
            (strpbrk(arg, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~") || !*arg)) {
            virBufferAddChar(&buf, '\'');
            close_quote = true;
        }
        if (xml) {
            virBufferEscapeString(&buf, "%s", arg);
        } else {
            if (shell && (q = strchr(arg, '\''))) {
                do {
                    virBufferAdd(&buf, arg, q - arg);
                    virBufferAddLit(&buf, "'\\''");
                    arg = q + 1;
                    q = strchr(arg, '\'');
                } while (q);
            }
            virBufferAdd(&buf, arg, strlen(arg));
        }
        if (close_quote)
            virBufferAddChar(&buf, '\'');
        count++;
    }

    if (virBufferError(&buf)) {
        vshPrint(ctl, "%s", _("Failed to allocate XML buffer"));
        return FALSE;
    }
    arg = virBufferContentAndReset(&buf);
    if (arg)
        vshPrint(ctl, "%s", arg);
    VIR_FREE(arg);
    return TRUE;
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
static int
cmdEdit (vshControl *ctl, const vshCmd *cmd)
{
    int ret = FALSE;
    virDomainPtr dom = NULL;
    char *tmp = NULL;
    char *doc = NULL;
    char *doc_edited = NULL;
    char *doc_reread = NULL;
    int flags = VIR_DOMAIN_XML_SECURE | VIR_DOMAIN_XML_INACTIVE;

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
        ret = TRUE;
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

    ret = TRUE;

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

static int
cmdQuit(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    ctl->imode = FALSE;
    return TRUE;
}

/*
 * "snapshot-create" command
 */
static const vshCmdInfo info_snapshot_create[] = {
    {"help", N_("Create a snapshot")},
    {"desc", N_("Snapshot create")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_create[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"xmlfile", VSH_OT_DATA, 0, N_("domain snapshot XML")},
    {NULL, 0, 0, NULL}
};

static int
cmdSnapshotCreate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    char *from;
    char *buffer = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    from = vshCommandOptString(cmd, "xmlfile", NULL);
    if (from == NULL)
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

    snapshot = virDomainSnapshotCreateXML(dom, buffer, 0);
    if (snapshot == NULL)
        goto cleanup;

    doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!doc)
        goto cleanup;

    xml = xmlReadDoc((const xmlChar *) doc, "domainsnapshot.xml", NULL,
                     XML_PARSE_NOENT | XML_PARSE_NONET |
                     XML_PARSE_NOWARNING);
    if (!xml)
        goto cleanup;
    ctxt = xmlXPathNewContext(xml);
    if (!ctxt)
        goto cleanup;

    name = virXPathString("string(/domainsnapshot/name)", ctxt);
    if (!name) {
        vshError(ctl, "%s",
                 _("Could not find 'name' element in domain snapshot XML"));
        goto cleanup;
    }

    vshPrint(ctl, _("Domain snapshot %s created"), name);
    if (from)
        vshPrint(ctl, _(" from '%s'"), from);
    vshPrint(ctl, "\n");

    ret = TRUE;

cleanup:
    VIR_FREE(name);
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    VIR_FREE(doc);
    VIR_FREE(buffer);
    if (dom)
        virDomainFree(dom);

    return ret;
}

/*
 * "snapshot-current" command
 */
static const vshCmdInfo info_snapshot_current[] = {
    {"help", N_("Get the current snapshot")},
    {"desc", N_("Get the current snapshot")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_snapshot_current[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdSnapshotCurrent(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    int current;
    virDomainSnapshotPtr snapshot = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    current = virDomainHasCurrentSnapshot(dom, 0);
    if (current < 0)
        goto cleanup;
    else if (current) {
        char *xml;

        if (!(snapshot = virDomainSnapshotCurrent(dom, 0)))
            goto cleanup;

        xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
        if (!xml)
            goto cleanup;

        vshPrint(ctl, "%s", xml);
        VIR_FREE(xml);
    }

    ret = TRUE;

cleanup:
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    if (dom)
        virDomainFree(dom);

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
    {NULL, 0, 0, NULL}
};

static int
cmdSnapshotList(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    int numsnaps;
    char **names = NULL;
    int actual = 0;
    int i;
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *doc = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    char *state = NULL;
    long creation;
    char timestr[100];
    struct tm time_info;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    numsnaps = virDomainSnapshotNum(dom, 0);

    if (numsnaps < 0)
        goto cleanup;

    vshPrint(ctl, " %-20s %-25s %s\n", _("Name"), _("Creation Time"), _("State"));
    vshPrint(ctl, "---------------------------------------------------\n");

    if (numsnaps) {
        if (VIR_ALLOC_N(names, numsnaps) < 0)
            goto cleanup;

        actual = virDomainSnapshotListNames(dom, names, numsnaps, 0);
        if (actual < 0)
            goto cleanup;

        qsort(&names[0], actual, sizeof(char*), namesorter);

        for (i = 0; i < actual; i++) {
            /* free up memory from previous iterations of the loop */
            VIR_FREE(state);
            if (snapshot)
                virDomainSnapshotFree(snapshot);
            xmlXPathFreeContext(ctxt);
            if (xml)
                xmlFreeDoc(xml);
            VIR_FREE(doc);

            snapshot = virDomainSnapshotLookupByName(dom, names[i], 0);
            if (snapshot == NULL)
                continue;

            doc = virDomainSnapshotGetXMLDesc(snapshot, 0);
            if (!doc)
                continue;

            xml = xmlReadDoc((const xmlChar *) doc, "domainsnapshot.xml", NULL,
                             XML_PARSE_NOENT | XML_PARSE_NONET |
                             XML_PARSE_NOWARNING);
            if (!xml)
                continue;
            ctxt = xmlXPathNewContext(xml);
            if (!ctxt)
                continue;

            state = virXPathString("string(/domainsnapshot/state)", ctxt);
            if (state == NULL)
                continue;
            if (virXPathLong("string(/domainsnapshot/creationTime)", ctxt,
                             &creation) < 0)
                continue;
            localtime_r(&creation, &time_info);
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", &time_info);

            vshPrint(ctl, " %-20s %-25s %s\n", names[i], timestr, state);
        }
    }

    ret = TRUE;

cleanup:
    /* this frees up memory from the last iteration of the loop */
    VIR_FREE(state);
    if (snapshot)
        virDomainSnapshotFree(snapshot);
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    VIR_FREE(doc);
    for (i = 0; i < actual; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);
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
    {NULL, 0, 0, NULL}
};

static int
cmdSnapshotDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    char *name;
    virDomainSnapshotPtr snapshot = NULL;
    char *xml = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    name = vshCommandOptString(cmd, "snapshotname", NULL);
    if (name == NULL)
        goto cleanup;

    snapshot = virDomainSnapshotLookupByName(dom, name, 0);
    if (snapshot == NULL)
        goto cleanup;

    xml = virDomainSnapshotGetXMLDesc(snapshot, 0);
    if (!xml)
        goto cleanup;

    vshPrint(ctl, "%s", xml);

    ret = TRUE;

cleanup:
    VIR_FREE(xml);
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
    {"snapshotname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("snapshot name")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomainSnapshotRevert(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    char *name;
    virDomainSnapshotPtr snapshot = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    name = vshCommandOptString(cmd, "snapshotname", NULL);
    if (name == NULL)
        goto cleanup;

    snapshot = virDomainSnapshotLookupByName(dom, name, 0);
    if (snapshot == NULL)
        goto cleanup;

    if (virDomainRevertToSnapshot(snapshot, 0) < 0)
        goto cleanup;

    ret = TRUE;

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
    {"snapshotname", VSH_OT_DATA, VSH_OFLAG_REQ, N_("snapshot name")},
    {"children", VSH_OT_BOOL, 0, N_("delete snapshot and all children")},
    {NULL, 0, 0, NULL}
};

static int
cmdSnapshotDelete(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    char *name;
    virDomainSnapshotPtr snapshot = NULL;
    unsigned int flags = 0;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    name = vshCommandOptString(cmd, "snapshotname", NULL);
    if (name == NULL)
        goto cleanup;

    if (vshCommandOptBool(cmd, "children"))
        flags |= VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN;

    snapshot = virDomainSnapshotLookupByName(dom, name, 0);
    if (snapshot == NULL)
        goto cleanup;

    if (virDomainSnapshotDelete(snapshot, flags) < 0)
        goto cleanup;

    ret = TRUE;

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
    {"help", N_("Qemu Monitor Command")},
    {"desc", N_("Qemu Monitor Command")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_qemu_monitor_command[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, N_("domain name, id or uuid")},
    {"cmd", VSH_OT_DATA, VSH_OFLAG_REQ, N_("command")},
    {NULL, 0, 0, NULL}
};

static int
cmdQemuMonitorCommand(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    int ret = FALSE;
    char *monitor_cmd;
    char *result = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn))
        goto cleanup;

    dom = vshCommandOptDomain(ctl, cmd, NULL);
    if (dom == NULL)
        goto cleanup;

    monitor_cmd = vshCommandOptString(cmd, "cmd", NULL);
    if (monitor_cmd == NULL) {
        vshError(ctl, "%s", _("missing monitor command"));
        goto cleanup;
    }

    if (virDomainQemuMonitorCommand(dom, monitor_cmd, &result, 0) < 0)
        goto cleanup;

    printf("%s\n", result);

    ret = TRUE;

cleanup:
    VIR_FREE(result);
    if (dom)
        virDomainFree(dom);

    return ret;
}

static const vshCmdDef domManagementCmds[] = {
    {"attach-device", cmdAttachDevice, opts_attach_device, info_attach_device},
    {"attach-disk", cmdAttachDisk, opts_attach_disk, info_attach_disk},
    {"attach-interface", cmdAttachInterface, opts_attach_interface, info_attach_interface},
    {"autostart", cmdAutostart, opts_autostart, info_autostart},
#ifndef WIN32
    {"console", cmdConsole, opts_console, info_console},
#endif
    {"cpu-baseline", cmdCPUBaseline, opts_cpu_baseline, info_cpu_baseline},
    {"cpu-compare", cmdCPUCompare, opts_cpu_compare, info_cpu_compare},
    {"create", cmdCreate, opts_create, info_create},
    {"define", cmdDefine, opts_define, info_define},
    {"destroy", cmdDestroy, opts_destroy, info_destroy},
    {"detach-device", cmdDetachDevice, opts_detach_device, info_detach_device},
    {"detach-disk", cmdDetachDisk, opts_detach_disk, info_detach_disk},
    {"detach-interface", cmdDetachInterface, opts_detach_interface, info_detach_interface},
    {"domid", cmdDomid, opts_domid, info_domid},
    {"domjobabort", cmdDomjobabort, opts_domjobabort, info_domjobabort},
    {"domjobinfo", cmdDomjobinfo, opts_domjobinfo, info_domjobinfo},
    {"domname", cmdDomname, opts_domname, info_domname},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid},
    {"domxml-from-native", cmdDomXMLFromNative, opts_domxmlfromnative, info_domxmlfromnative},
    {"domxml-to-native", cmdDomXMLToNative, opts_domxmltonative, info_domxmltonative},
    {"dump", cmdDump, opts_dump, info_dump},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml},
    {"edit", cmdEdit, opts_edit, info_edit},
    {"managedsave", cmdManagedSave, opts_managedsave, info_managedsave},
    {"managedsave-remove", cmdManagedSaveRemove, opts_managedsaveremove, info_managedsaveremove},
    {"maxvcpus", cmdMaxvcpus, opts_maxvcpus, info_maxvcpus},
    {"memtune", cmdMemtune, opts_memtune, info_memtune},
    {"migrate", cmdMigrate, opts_migrate, info_migrate},
    {"migrate-setmaxdowntime", cmdMigrateSetMaxDowntime, opts_migrate_setmaxdowntime, info_migrate_setmaxdowntime},
    {"reboot", cmdReboot, opts_reboot, info_reboot},
    {"restore", cmdRestore, opts_restore, info_restore},
    {"resume", cmdResume, opts_resume, info_resume},
    {"save", cmdSave, opts_save, info_save},
    {"schedinfo", cmdSchedinfo, opts_schedinfo, info_schedinfo},
    {"setmaxmem", cmdSetmaxmem, opts_setmaxmem, info_setmaxmem},
    {"setmem", cmdSetmem, opts_setmem, info_setmem},
    {"setvcpus", cmdSetvcpus, opts_setvcpus, info_setvcpus},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown},
    {"start", cmdStart, opts_start, info_start},
    {"suspend", cmdSuspend, opts_suspend, info_suspend},
    {"ttyconsole", cmdTTYConsole, opts_ttyconsole, info_ttyconsole},
    {"undefine", cmdUndefine, opts_undefine, info_undefine},
    {"update-device", cmdUpdateDevice, opts_update_device, info_update_device},
    {"vcpucount", cmdVcpucount, opts_vcpucount, info_vcpucount},
    {"vcpuinfo", cmdVcpuinfo, opts_vcpuinfo, info_vcpuinfo},
    {"vcpupin", cmdVcpupin, opts_vcpupin, info_vcpupin},
    {"version", cmdVersion, NULL, info_version},
    {"vncdisplay", cmdVNCDisplay, opts_vncdisplay, info_vncdisplay},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef domMonitoringCmds[] = {
    {"domblkinfo", cmdDomblkinfo, opts_domblkinfo, info_domblkinfo},
    {"domblkstat", cmdDomblkstat, opts_domblkstat, info_domblkstat},
    {"domifstat", cmdDomIfstat, opts_domifstat, info_domifstat},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo},
    {"dommemstat", cmdDomMemStat, opts_dommemstat, info_dommemstat},
    {"domstate", cmdDomstate, opts_domstate, info_domstate},
    {"list", cmdList, opts_list, info_list},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef storagePoolCmds[] = {
    {"find-storage-pool-sources-as", cmdPoolDiscoverSourcesAs,
     opts_find_storage_pool_sources_as, info_find_storage_pool_sources_as},
    {"find-storage-pool-sources", cmdPoolDiscoverSources,
     opts_find_storage_pool_sources, info_find_storage_pool_sources},
    {"pool-autostart", cmdPoolAutostart, opts_pool_autostart, info_pool_autostart},
    {"pool-build", cmdPoolBuild, opts_pool_build, info_pool_build},
    {"pool-create-as", cmdPoolCreateAs, opts_pool_X_as, info_pool_create_as},
    {"pool-create", cmdPoolCreate, opts_pool_create, info_pool_create},
    {"pool-define-as", cmdPoolDefineAs, opts_pool_X_as, info_pool_define_as},
    {"pool-define", cmdPoolDefine, opts_pool_define, info_pool_define},
    {"pool-delete", cmdPoolDelete, opts_pool_delete, info_pool_delete},
    {"pool-destroy", cmdPoolDestroy, opts_pool_destroy, info_pool_destroy},
    {"pool-dumpxml", cmdPoolDumpXML, opts_pool_dumpxml, info_pool_dumpxml},
    {"pool-edit", cmdPoolEdit, opts_pool_edit, info_pool_edit},
    {"pool-info", cmdPoolInfo, opts_pool_info, info_pool_info},
    {"pool-list", cmdPoolList, opts_pool_list, info_pool_list},
    {"pool-name", cmdPoolName, opts_pool_name, info_pool_name},
    {"pool-refresh", cmdPoolRefresh, opts_pool_refresh, info_pool_refresh},
    {"pool-start", cmdPoolStart, opts_pool_start, info_pool_start},
    {"pool-undefine", cmdPoolUndefine, opts_pool_undefine, info_pool_undefine},
    {"pool-uuid", cmdPoolUuid, opts_pool_uuid, info_pool_uuid},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef storageVolCmds[] = {
    {"vol-clone", cmdVolClone, opts_vol_clone, info_vol_clone},
    {"vol-create-as", cmdVolCreateAs, opts_vol_create_as, info_vol_create_as},
    {"vol-create", cmdVolCreate, opts_vol_create, info_vol_create},
    {"vol-create-from", cmdVolCreateFrom, opts_vol_create_from, info_vol_create_from},
    {"vol-delete", cmdVolDelete, opts_vol_delete, info_vol_delete},
    {"vol-dumpxml", cmdVolDumpXML, opts_vol_dumpxml, info_vol_dumpxml},
    {"vol-info", cmdVolInfo, opts_vol_info, info_vol_info},
    {"vol-key", cmdVolKey, opts_vol_key, info_vol_key},
    {"vol-list", cmdVolList, opts_vol_list, info_vol_list},
    {"vol-name", cmdVolName, opts_vol_name, info_vol_name},
    {"vol-path", cmdVolPath, opts_vol_path, info_vol_path},
    {"vol-pool", cmdVolPool, opts_vol_pool, info_vol_pool},
    {"vol-wipe", cmdVolWipe, opts_vol_wipe, info_vol_wipe},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef networkCmds[] = {
    {"net-autostart", cmdNetworkAutostart, opts_network_autostart, info_network_autostart},
    {"net-create", cmdNetworkCreate, opts_network_create, info_network_create},
    {"net-define", cmdNetworkDefine, opts_network_define, info_network_define},
    {"net-destroy", cmdNetworkDestroy, opts_network_destroy, info_network_destroy},
    {"net-dumpxml", cmdNetworkDumpXML, opts_network_dumpxml, info_network_dumpxml},
    {"net-edit", cmdNetworkEdit, opts_network_edit, info_network_edit},
    {"net-info", cmdNetworkInfo, opts_network_info, info_network_info},
    {"net-list", cmdNetworkList, opts_network_list, info_network_list},
    {"net-name", cmdNetworkName, opts_network_name, info_network_name},
    {"net-start", cmdNetworkStart, opts_network_start, info_network_start},
    {"net-undefine", cmdNetworkUndefine, opts_network_undefine, info_network_undefine},
    {"net-uuid", cmdNetworkUuid, opts_network_uuid, info_network_uuid},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef nodedevCmds[] = {
    {"nodedev-create", cmdNodeDeviceCreate, opts_node_device_create, info_node_device_create},
    {"nodedev-destroy", cmdNodeDeviceDestroy, opts_node_device_destroy, info_node_device_destroy},
    {"nodedev-dettach", cmdNodeDeviceDettach, opts_node_device_dettach, info_node_device_dettach},
    {"nodedev-dumpxml", cmdNodeDeviceDumpXML, opts_node_device_dumpxml, info_node_device_dumpxml},
    {"nodedev-list", cmdNodeListDevices, opts_node_list_devices, info_node_list_devices},
    {"nodedev-reattach", cmdNodeDeviceReAttach, opts_node_device_reattach, info_node_device_reattach},
    {"nodedev-reset", cmdNodeDeviceReset, opts_node_device_reset, info_node_device_reset},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef ifaceCmds[] = {
    {"iface-define", cmdInterfaceDefine, opts_interface_define, info_interface_define},
    {"iface-destroy", cmdInterfaceDestroy, opts_interface_destroy, info_interface_destroy},
    {"iface-dumpxml", cmdInterfaceDumpXML, opts_interface_dumpxml, info_interface_dumpxml},
    {"iface-edit", cmdInterfaceEdit, opts_interface_edit, info_interface_edit},
    {"iface-list", cmdInterfaceList, opts_interface_list, info_interface_list},
    {"iface-mac", cmdInterfaceMAC, opts_interface_mac, info_interface_mac},
    {"iface-name", cmdInterfaceName, opts_interface_name, info_interface_name},
    {"iface-start", cmdInterfaceStart, opts_interface_start, info_interface_start},
    {"iface-undefine", cmdInterfaceUndefine, opts_interface_undefine, info_interface_undefine},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef nwfilterCmds[] = {
    {"nwfilter-define", cmdNWFilterDefine, opts_nwfilter_define, info_nwfilter_define},
    {"nwfilter-dumpxml", cmdNWFilterDumpXML, opts_nwfilter_dumpxml, info_nwfilter_dumpxml},
    {"nwfilter-edit", cmdNWFilterEdit, opts_nwfilter_edit, info_nwfilter_edit},
    {"nwfilter-list", cmdNWFilterList, opts_nwfilter_list, info_nwfilter_list},
    {"nwfilter-undefine", cmdNWFilterUndefine, opts_nwfilter_undefine, info_nwfilter_undefine},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef secretCmds[] = {
    {"secret-define", cmdSecretDefine, opts_secret_define, info_secret_define},
    {"secret-dumpxml", cmdSecretDumpXML, opts_secret_dumpxml, info_secret_dumpxml},
    {"secret-get-value", cmdSecretGetValue, opts_secret_get_value, info_secret_get_value},
    {"secret-list", cmdSecretList, NULL, info_secret_list},
    {"secret-set-value", cmdSecretSetValue, opts_secret_set_value, info_secret_set_value},
    {"secret-undefine", cmdSecretUndefine, opts_secret_undefine, info_secret_undefine},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef virshCmds[] = {
#ifndef WIN32
    {"cd", cmdCd, opts_cd, info_cd},
#endif
    {"echo", cmdEcho, opts_echo, info_echo},
    {"exit", cmdQuit, NULL, info_quit},
    {"help", cmdHelp, opts_help, info_help},
#ifndef WIN32
    {"pwd", cmdPwd, NULL, info_pwd},
#endif
    {"quit", cmdQuit, NULL, info_quit},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef snapshotCmds[] = {
    {"snapshot-create", cmdSnapshotCreate, opts_snapshot_create, info_snapshot_create},
    {"snapshot-current", cmdSnapshotCurrent, opts_snapshot_current, info_snapshot_current},
    {"snapshot-delete", cmdSnapshotDelete, opts_snapshot_delete, info_snapshot_delete},
    {"snapshot-dumpxml", cmdSnapshotDumpXML, opts_snapshot_dumpxml, info_snapshot_dumpxml},
    {"snapshot-list", cmdSnapshotList, opts_snapshot_list, info_snapshot_list},
    {"snapshot-revert", cmdDomainSnapshotRevert, opts_snapshot_revert, info_snapshot_revert},
    {NULL, NULL, NULL, NULL}
};

static const vshCmdDef hostAndHypervisorCmds[] = {
    {"capabilities", cmdCapabilities, NULL, info_capabilities},
    {"connect", cmdConnect, opts_connect, info_connect},
    {"freecell", cmdFreecell, opts_freecell, info_freecell},
    {"hostname", cmdHostname, NULL, info_hostname},
    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo},
    {"qemu-monitor-command", cmdQemuMonitorCommand, opts_qemu_monitor_command, info_qemu_monitor_command},
    {"uri", cmdURI, NULL, info_uri},
    {NULL, NULL, NULL, NULL}
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

static const vshCmdOptDef *
vshCmddefGetOption(const vshCmdDef * cmd, const char *name)
{
    const vshCmdOptDef *opt;

    for (opt = cmd->opts; opt && opt->name; opt++)
        if (STREQ(opt->name, name))
            return opt;
    return NULL;
}

static const vshCmdOptDef *
vshCmddefGetData(const vshCmdDef * cmd, int data_ct)
{
    const vshCmdOptDef *opt;

    for (opt = cmd->opts; opt && opt->name; opt++) {
        if (opt->type >= VSH_OT_DATA ||
            (opt->type == VSH_OT_INT && (opt->flag & VSH_OFLAG_REQ))) {
            if (data_ct == 0 || opt->type == VSH_OT_ARGV)
                return opt;
            else
                data_ct--;
        }
    }
    return NULL;
}

/*
 * Checks for required options
 */
static int
vshCommandCheckOpts(vshControl *ctl, const vshCmd *cmd)
{
    const vshCmdDef *def = cmd->def;
    const vshCmdOptDef *d;
    int err = 0;

    for (d = def->opts; d && d->name; d++) {
        if (d->flag & VSH_OFLAG_REQ) {
            vshCmdOpt *o = cmd->opts;
            int ok = 0;

            while (o && ok == 0) {
                if (o->def == d)
                    ok = 1;
                o = o->next;
            }
            if (!ok) {
                vshError(ctl,
                         d->type == VSH_OT_DATA ?
                         _("command '%s' requires <%s> option") :
                         _("command '%s' requires --%s option"),
                         def->name, d->name);
                err = 1;
            }

        }
    }
    return !err;
}

static const vshCmdDef *
vshCmddefSearch(const char *cmdname)
{
    const vshCmdGrp *g;
    const vshCmdDef *c;

    for (g = cmdGroups; g->name; g++) {
        for (c = g->commands; c->name; c++) {
            if(STREQ(c->name, cmdname))
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
        if(STREQ(g->name, grpname) || STREQ(g->keyword, grpname))
            return g;
    }

    return NULL;
}

static int
vshCmdGrpHelp(vshControl *ctl, const char *grpname)
{
    const vshCmdGrp *grp = vshCmdGrpSearch(grpname);
    const vshCmdDef *cmd = NULL;

    if (!grp) {
        vshError(ctl, _("command group '%s' doesn't exist"), grpname);
        return FALSE;
    } else {
        vshPrint(ctl, _(" %s (help keyword '%s'):\n"), grp->name,
                 grp->keyword);

        for (cmd = grp->commands; cmd->name; cmd++) {
            vshPrint(ctl, "    %-30s %s\n", cmd->name,
                     _(vshCmddefGetInfo(cmd, "help")));
        }
    }

    return TRUE;
}

static int
vshCmddefHelp(vshControl *ctl, const char *cmdname)
{
    const vshCmdDef *def = vshCmddefSearch(cmdname);

    if (!def) {
        vshError(ctl, _("command '%s' doesn't exist"), cmdname);
        return FALSE;
    } else {
        const char *desc = _(vshCmddefGetInfo(def, "desc"));
        const char *help = _(vshCmddefGetInfo(def, "help"));
        char buf[256];

        fputs(_("  NAME\n"), stdout);
        fprintf(stdout, "    %s - %s\n", def->name, help);

        fputs(_("\n  SYNOPSIS\n"), stdout);
        fprintf(stdout, "    %s", def->name);
        if (def->opts) {
            const vshCmdOptDef *opt;
            for (opt = def->opts; opt->name; opt++) {
                const char *fmt;
                switch (opt->type) {
                case VSH_OT_BOOL:
                    fmt = "[--%s]";
                    break;
                case VSH_OT_INT:
                    /* xgettext:c-format */
                    fmt = ((opt->flag & VSH_OFLAG_REQ) ? "<%s>"
                           : _("[--%s <number>]"));
                    break;
                case VSH_OT_STRING:
                    /* xgettext:c-format */
                    fmt = _("[--%s <string>]");
                    break;
                case VSH_OT_DATA:
                    fmt = ((opt->flag & VSH_OFLAG_REQ) ? "<%s>" : "[<%s>]");
                    break;
                case VSH_OT_ARGV:
                    /* xgettext:c-format */
                    fmt = _("[<string>]...");
                    break;
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
            fprintf(stdout, "    %s\n", desc);
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
                             (opt->flag & VSH_OFLAG_REQ) ? _("[--%s] <number>")
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
                    /* Not really an option. */
                    continue;
                default:
                    assert(0);
                }

                fprintf(stdout, "    %-15s  %s\n", buf, _(opt->help));
            }
        }
        fputc('\n', stdout);
    }
    return TRUE;
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

/*
 * Returns option by name
 */
static vshCmdOpt *
vshCommandOpt(const vshCmd *cmd, const char *name)
{
    vshCmdOpt *opt = cmd->opts;

    while (opt) {
        if (opt->def && STREQ(opt->def->name, name))
            return opt;
        opt = opt->next;
    }
    return NULL;
}

/*
 * Returns option as INT
 */
static int
vshCommandOptInt(const vshCmd *cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);
    int res = 0, num_found = FALSE;
    char *end_p = NULL;

    if ((arg != NULL) && (arg->data != NULL)) {
        res = strtol(arg->data, &end_p, 10);
        if ((arg->data == end_p) || (*end_p!= 0))
            num_found = FALSE;
        else
            num_found = TRUE;
    }
    if (found)
        *found = num_found;
    return res;
}

static unsigned long
vshCommandOptUL(const vshCmd *cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);
    unsigned long res = 0;
    int num_found = FALSE;
    char *end_p = NULL;

    if ((arg != NULL) && (arg->data != NULL)) {
        res = strtoul(arg->data, &end_p, 10);
        if ((arg->data == end_p) || (*end_p!= 0))
            num_found = FALSE;
        else
            num_found = TRUE;
    }
    if (found)
        *found = num_found;
    return res;
}

/*
 * Returns option as STRING
 */
static char *
vshCommandOptString(const vshCmd *cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);

    if (found)
        *found = arg ? TRUE : FALSE;

    if (arg && arg->data && *arg->data)
        return arg->data;

    if (arg && arg->def && ((arg->def->flag) & VSH_OFLAG_REQ))
        vshError(NULL, _("Missing required option '%s'"), name);

    return NULL;
}

/*
 * Returns option as long long
 */
static long long
vshCommandOptLongLong(const vshCmd *cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);
    int num_found = FALSE;
    long long res = 0;
    char *end_p = NULL;

    if ((arg != NULL) && (arg->data != NULL))
        num_found = !virStrToLong_ll(arg->data, &end_p, 10, &res);
    if (found)
        *found = num_found;
    return res;
}

/*
 * Returns TRUE/FALSE if the option exists
 */
static int
vshCommandOptBool(const vshCmd *cmd, const char *name)
{
    return vshCommandOpt(cmd, name) ? TRUE : FALSE;
}

/*
 * Returns the COUNT argv argument, or NULL after last argument.
 *
 * Requires that a VSH_OT_ARGV option with the name "" be last in the
 * list of supported options in CMD->def->opts.
 */
static char *
vshCommandOptArgv(const vshCmd *cmd, int count)
{
    vshCmdOpt *opt = cmd->opts;

    while (opt) {
        if (opt->def && opt->def->type == VSH_OT_ARGV) {
            if (count-- == 0)
                return opt->data;
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
                      char **name, int flag)
{
    virDomainPtr dom = NULL;
    char *n;
    int id;
    const char *optname = "domain";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by ID */
    if (flag & VSH_BYID) {
        if (virStrToLong_i(n, NULL, 10, &id) == 0 && id >= 0) {
            vshDebug(ctl, 5, "%s: <%s> seems like domain ID\n",
                     cmd->def->name, optname);
            dom = virDomainLookupByID(ctl->conn, id);
        }
    }
    /* try it by UUID */
    if (dom==NULL && (flag & VSH_BYUUID) && strlen(n)==VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, 5, "%s: <%s> trying as domain UUID\n",
                 cmd->def->name, optname);
        dom = virDomainLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (dom==NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as domain NAME\n",
                 cmd->def->name, optname);
        dom = virDomainLookupByName(ctl->conn, n);
    }

    if (!dom)
        vshError(ctl, _("failed to get domain '%s'"), n);

    return dom;
}

static virNetworkPtr
vshCommandOptNetworkBy(vshControl *ctl, const vshCmd *cmd,
                       char **name, int flag)
{
    virNetworkPtr network = NULL;
    char *n;
    const char *optname = "network";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
        vshDebug(ctl, 5, "%s: <%s> trying as network UUID\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (network==NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as network NAME\n",
                 cmd->def->name, optname);
        network = virNetworkLookupByName(ctl->conn, n);
    }

    if (!network)
        vshError(ctl, _("failed to get network '%s'"), n);

    return network;
}


static virNWFilterPtr
vshCommandOptNWFilterBy(vshControl *ctl, const vshCmd *cmd,
                        char **name, int flag)
{
    virNWFilterPtr nwfilter = NULL;
    char *n;
    const char *optname = "nwfilter";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
        vshDebug(ctl, 5, "%s: <%s> trying as nwfilter UUID\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (nwfilter == NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as nwfilter NAME\n",
                 cmd->def->name, optname);
        nwfilter = virNWFilterLookupByName(ctl->conn, n);
    }

    if (!nwfilter)
        vshError(ctl, _("failed to get nwfilter '%s'"), n);

    return nwfilter;
}

static virInterfacePtr
vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                         char **name, int flag)
{
    virInterfacePtr iface = NULL;
    char *n;
    const char *optname = "interface";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by NAME */
    if ((flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as interface NAME\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByName(ctl->conn, n);
    }
    /* try it by MAC */
    if ((iface == NULL) && (flag & VSH_BYMAC)) {
        vshDebug(ctl, 5, "%s: <%s> trying as interface MAC\n",
                 cmd->def->name, optname);
        iface = virInterfaceLookupByMACString(ctl->conn, n);
    }

    if (!iface)
        vshError(ctl, _("failed to get interface '%s'"), n);

    return iface;
}

static virStoragePoolPtr
vshCommandOptPoolBy(vshControl *ctl, const vshCmd *cmd, const char *optname,
                    char **name, int flag)
{
    virStoragePoolPtr pool = NULL;
    char *n;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by UUID */
    if ((flag & VSH_BYUUID) && (strlen(n) == VIR_UUID_STRING_BUFLEN-1)) {
        vshDebug(ctl, 5, "%s: <%s> trying as pool UUID\n",
                 cmd->def->name, optname);
        pool = virStoragePoolLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (pool == NULL && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as pool NAME\n",
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
                   char **name, int flag)
{
    virStorageVolPtr vol = NULL;
    virStoragePoolPtr pool = NULL;
    char *n, *p;
    int found;

    if (!(n = vshCommandOptString(cmd, optname, NULL)))
        return NULL;

    if (!(p = vshCommandOptString(cmd, pooloptname, &found)) && found)
        return NULL;

    if (p)
        pool = vshCommandOptPoolBy(ctl, cmd, pooloptname, name, flag);

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by name */
    if (pool && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as vol name\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    /* try it by key */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, 5, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(ctl->conn, n);
    }
    /* try it by path */
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, 5, "%s: <%s> trying as vol path\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByPath(ctl->conn, n);
    }

    if (!vol)
        vshError(ctl, _("failed to get vol '%s'"), n);

    if (pool)
        virStoragePoolFree(pool);

    return vol;
}

static virSecretPtr
vshCommandOptSecret(vshControl *ctl, const vshCmd *cmd, char **name)
{
    virSecretPtr secret = NULL;
    char *n;
    const char *optname = "secret";

    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    n = vshCommandOptString(cmd, optname, NULL);
    if (n == NULL)
        return NULL;

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n", cmd->def->name, optname, n);

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
static int
vshCommandRun(vshControl *ctl, const vshCmd *cmd)
{
    int ret = TRUE;

    while (cmd) {
        struct timeval before, after;
        bool enable_timing = ctl->timing;

        if ((ctl->conn == NULL) || (disconnected != 0))
            vshReconnect(ctl);

        if (enable_timing)
            GETTIMEOFDAY(&before);

        ret = cmd->def->handler(ctl, cmd);

        if (enable_timing)
            GETTIMEOFDAY(&after);

        if (ret == FALSE)
            virshReportError(ctl);

        /* try to automatically catch disconnections */
        if ((ret == FALSE) &&
            ((disconnected != 0) ||
             ((last_error != NULL) &&
              (((last_error->code == VIR_ERR_SYSTEM_ERROR) &&
                (last_error->domain == VIR_FROM_REMOTE)) ||
               (last_error->code == VIR_ERR_RPC) ||
               (last_error->code == VIR_ERR_NO_CONNECT) ||
               (last_error->code == VIR_ERR_INVALID_CONN)))))
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

static int
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
        int data_ct = 0;

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
                VIR_FREE(tkdata);
            } else if (data_only) {
                goto get_data;
            } else if (tkdata[0] == '-' && tkdata[1] == '-' &&
                       c_isalnum(tkdata[2])) {
                char *optstr = strchr(tkdata + 2, '=');
                if (optstr) {
                    *optstr = '\0'; /* convert the '=' to '\0' */
                    optstr = vshStrdup(ctl, optstr + 1);
                }
                if (!(opt = vshCmddefGetOption(cmd, tkdata + 2))) {
                    vshError(ctl,
                             _("command '%s' doesn't support option --%s"),
                             cmd->name, tkdata + 2);
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
                if (!(opt = vshCmddefGetData(cmd, data_ct++))) {
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

                vshDebug(ctl, 4, "%s: %s(%s): %s\n",
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

            if (!vshCommandCheckOpts(ctl, c)) {
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

    return TRUE;

 syntaxError:
    if (ctl->cmd) {
        vshCommandFree(ctl->cmd);
        ctl->cmd = NULL;
    }
    if (first)
        vshCommandOptFree(first);
    VIR_FREE(tkdata);
    return FALSE;
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

static int vshCommandArgvParse(vshControl *ctl, int nargs, char **argv)
{
    vshCommandParser parser;

    if (nargs <= 0)
        return FALSE;

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

static int vshCommandStringParse(vshControl *ctl, char *cmdstr)
{
    vshCommandParser parser;

    if (cmdstr == NULL || *cmdstr == '\0')
        return FALSE;

    parser.pos = cmdstr;
    parser.getNextArg = vshCommandStringGetArg;
    return vshCommandParse(ctl, &parser);
}

/* ---------------
 * Misc utils
 * ---------------
 */
static const char *
vshDomainStateToString(int state)
{
    switch (state) {
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
    default:
        ;/*FALLTHROUGH*/
    }
    return N_("no state");  /* = dom0 state */
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

static int
vshConnectionUsability(vshControl *ctl, virConnectPtr conn)
{
    /* TODO: use something like virConnectionState() to
     *       check usability of the connection
     */
    if (!conn) {
        vshError(ctl, "%s", _("no valid connection"));
        return FALSE;
    }
    return TRUE;
}

static void
vshDebug(vshControl *ctl, int level, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    vshOutputLogFile(ctl, VSH_ERR_DEBUG, format, ap);
    va_end(ap);

    if (level > ctl->debug)
        return;

    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

static void
vshPrintExtra(vshControl *ctl, const char *format, ...)
{
    va_list ap;

    if (ctl->quiet == TRUE)
        return;

    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}


static void
vshError(vshControl *ctl, const char *format, ...)
{
    va_list ap;

    if (ctl != NULL) {
        va_start(ap, format);
        vshOutputLogFile(ctl, VSH_ERR_ERROR, format, ap);
        va_end(ap);
    }

    fputs(_("error: "), stderr);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);
}

/*
 * Initialize connection.
 */
static int
vshInit(vshControl *ctl)
{
    if (ctl->conn)
        return FALSE;

    vshOpenLogFile(ctl);

    /* set up the library error handler */
    virSetErrorFunc(NULL, virshErrorHandler);

    /* set up the signals handlers to catch disconnections */
    vshSetupSignals();

    virEventRegisterImpl(virEventAddHandleImpl,
                         virEventUpdateHandleImpl,
                         virEventRemoveHandleImpl,
                         virEventAddTimeoutImpl,
                         virEventUpdateTimeoutImpl,
                         virEventRemoveTimeoutImpl);
    virEventInit();

    ctl->conn = virConnectOpenAuth(ctl->name,
                                   virConnectAuthPtrDefault,
                                   ctl->readonly ? VIR_CONNECT_RO : 0);


    /* This is not necessarily fatal.  All the individual commands check
     * vshConnectionUsability, except ones which don't need a connection
     * such as "help".
     */
    if (!ctl->conn) {
        virshReportError(ctl);
        vshError(ctl, "%s", _("failed to connect to the hypervisor"));
        return FALSE;
    }

    return TRUE;
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
vshOutputLogFile(vshControl *ctl, int log_level, const char *msg_format, va_list ap)
{
    char msg_buf[MSG_BUFFER];
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
    snprintf(msg_buf, sizeof(msg_buf),
             "[%d.%02d.%02d %02d:%02d:%02d ",
             (1900 + stTm->tm_year),
             (1 + stTm->tm_mon),
             (stTm->tm_mday),
             (stTm->tm_hour),
             (stTm->tm_min),
             (stTm->tm_sec));
    snprintf(msg_buf + strlen(msg_buf), sizeof(msg_buf) - strlen(msg_buf),
             "%s] ", SIGN_NAME);
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
    snprintf(msg_buf + strlen(msg_buf), sizeof(msg_buf) - strlen(msg_buf),
             "%s ", lvl);
    vsnprintf(msg_buf + strlen(msg_buf), sizeof(msg_buf) - strlen(msg_buf),
              msg_format, ap);

    if (msg_buf[strlen(msg_buf) - 1] != '\n')
        snprintf(msg_buf + strlen(msg_buf), sizeof(msg_buf) - strlen(msg_buf), "\n");

    /* write log */
    if (safewrite(ctl->log_fd, msg_buf, strlen(msg_buf)) < 0) {
        vshCloseLogFile(ctl);
        vshError(ctl, "%s", _("failed to write the log file"));
    }
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

        if (opt->type == VSH_OT_DATA)
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

    if (userdir == NULL)
        return -1;

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
                     ctl->historydir, virStrerror(errno, ebuf, sizeof ebuf));
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
    r = fgets (line, sizeof line, stdin);
    if (r == NULL) return NULL; /* EOF */

    /* Chomp trailing \n */
    len = strlen (r);
    if (len > 0 && r[len-1] == '\n')
        r[len-1] = '\0';

    return vshStrdup (ctl, r);
}

#endif /* !USE_READLINE */

/*
 * Deinitialize virsh
 */
static int
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

    return TRUE;
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
                      "    -c | --connect <uri>    hypervisor connection URI\n"
                      "    -r | --readonly         connect readonly\n"
                      "    -d | --debug <num>      debug level [0-5]\n"
                      "    -h | --help             this help\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -t | --timing           print timing information\n"
                      "    -l | --log <file>       output logging to file\n"
                      "    -v | --version[=short]  program version\n"
                      "    -V | --version=long     version and full options\n\n"
                      "  commands (non interactive mode):\n\n"), progname, progname);

    for (grp = cmdGroups; grp->name; grp++) {
        fprintf(stdout, _(" %s (help keyword '%s')\n"), grp->name, grp->keyword);

        for (cmd = grp->commands; cmd->name; cmd++)
            fprintf(stdout,
                    "    %-30s %s\n", cmd->name, _(vshCmddefGetInfo(cmd, "help")));

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
#ifdef ENABLE_SECDRIVER_APPARMOR
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
static int
vshParseArgv(vshControl *ctl, int argc, char **argv)
{
    bool help = false;
    int arg;
    struct option opt[] = {
        {"debug", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"quiet", no_argument, NULL, 'q'},
        {"timing", no_argument, NULL, 't'},
        {"version", optional_argument, NULL, 'v'},
        {"connect", required_argument, NULL, 'c'},
        {"readonly", no_argument, NULL, 'r'},
        {"log", required_argument, NULL, 'l'},
        {NULL, 0, NULL, 0}
    };

    /* Standard (non-command) options. The leading + ensures that no
     * argument reordering takes place, so that command options are
     * not confused with top-level virsh options. */
    while ((arg = getopt_long(argc, argv, "+d:hqtc:vVrl:", opt, NULL)) != -1) {
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
            ctl->quiet = TRUE;
            break;
        case 't':
            ctl->timing = TRUE;
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
            ctl->readonly = TRUE;
            break;
        case 'l':
            ctl->logfile = vshStrdup(ctl, optarg);
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
        ctl->imode = FALSE;
        if (argc - optind == 1) {
            vshDebug(ctl, 2, "commands: \"%s\"\n", argv[optind]);
            return vshCommandStringParse(ctl, argv[optind]);
        } else {
            return vshCommandArgvParse(ctl, argc - optind, argv + optind);
        }
    }
    return TRUE;
}

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    char *defaultConn;
    int ret = TRUE;

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

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    memset(ctl, 0, sizeof(vshControl));
    ctl->imode = TRUE;          /* default is interactive mode */
    ctl->log_fd = -1;           /* Initialize log file descriptor */

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
