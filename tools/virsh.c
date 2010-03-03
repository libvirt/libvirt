/*
 * virsh.c: a Xen shell used to exercise the libvirt API
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
#include "c-ctype.h"
#include <fcntl.h>
#include <locale.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <inttypes.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlsave.h>

#ifdef HAVE_READLINE_READLINE_H
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "internal.h"
#include "virterror_internal.h"
#include "base64.h"
#include "buf.h"
#include "console.h"
#include "util.h"
#include "memory.h"

static char *progname;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
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

#ifndef WEXITSTATUS
# define WEXITSTATUS(x) ((x) & 0xff)
#endif
/**
 * vshErrorLevel:
 *
 * Indicates the level of an log message
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
 *    command         =    <keyword> <option> <data>
 *
 *    option          =     <bool_option> | <int_option> | <string_option>
 *    data            =     <string>
 *
 *    bool_option     =     --optionname
 *    int_option      =     --optionname <number>
 *    string_option   =     --optionname <string>
 *
 *    keyword         =     [a-zA-Z]
 *    number          =     [0-9]+
 *    string          =     [^[:blank:]] | "[[:alnum:]]"$
 *
 */

/*
 * vshCmdOptType - command option type
 */
typedef enum {
    VSH_OT_NONE = 0,            /* none */
    VSH_OT_BOOL,                /* boolean option */
    VSH_OT_STRING,              /* string option */
    VSH_OT_INT,                 /* int option */
    VSH_OT_DATA                 /* string data (as non-option) */
} vshCmdOptType;

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


static const vshCmdDef commands[];

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

static vshCmdOpt *vshCommandOpt(const vshCmd *cmd, const char *name);
static int vshCommandOptInt(const vshCmd *cmd, const char *name, int *found);
static char *vshCommandOptString(const vshCmd *cmd, const char *name,
                                 int *found);
#if 0
static int vshCommandOptStringList(const vshCmd *cmd, const char *name, char ***data);
#endif
static int vshCommandOptBool(const vshCmd *cmd, const char *name);

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
static int vshConnectionUsability(vshControl *ctl, virConnectPtr conn,
                                  int showerror);

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
            return;
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


/* ---------------
 * Commands
 * ---------------
 */

/*
 * "help" command
 */
static const vshCmdInfo info_help[] = {
    {"help", gettext_noop("print help")},
    {"desc", gettext_noop("Prints global help or command specific help.")},

    {NULL, NULL}
};

static const vshCmdOptDef opts_help[] = {
    {"command", VSH_OT_DATA, 0, gettext_noop("name of command")},
    {NULL, 0, 0, NULL}
};

static int
cmdHelp(vshControl *ctl, const vshCmd *cmd)
{
    const char *cmdname = vshCommandOptString(cmd, "command", NULL);

    if (!cmdname) {
        const vshCmdDef *def;

        vshPrint(ctl, "%s", _("Commands:\n\n"));
        for (def = commands; def->name; def++)
            vshPrint(ctl, "    %-15s %s\n", def->name,
                     N_(vshCmddefGetInfo(def, "help")));
        return TRUE;
    }
    return vshCmddefHelp(ctl, cmdname);
}

/*
 * "autostart" command
 */
static const vshCmdInfo info_autostart[] = {
    {"help", gettext_noop("autostart a domain")},
    {"desc",
     gettext_noop("Configure a domain to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_autostart[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"disable", VSH_OT_BOOL, 0, gettext_noop("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static int
cmdAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("(re)connect to hypervisor")},
    {"desc",
     gettext_noop("Connect to local hypervisor. This is built-in command after shell start up.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_connect[] = {
    {"name",     VSH_OT_DATA, 0, gettext_noop("hypervisor connection URI")},
    {"readonly", VSH_OT_BOOL, 0, gettext_noop("read-only connection")},
    {NULL, 0, 0, NULL}
};

static int
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    int ro = vshCommandOptBool(cmd, "readonly");

    if (ctl->conn) {
        if (virConnectClose(ctl->conn) != 0) {
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
            return FALSE;
        }
        ctl->conn = NULL;
    }

    VIR_FREE(ctl->name);
    ctl->name = vshStrdup(ctl, vshCommandOptString(cmd, "name", NULL));

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
    {"help", gettext_noop("connect to the guest console")},
    {"desc",
     gettext_noop("Connect the virtual serial console for the guest")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_console[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdRunConsole(vshControl *ctl, virDomainPtr dom)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = FALSE;
    char *doc;
    char *thatHost = NULL;
    char *thisHost = NULL;
    virDomainInfo dominfo;

    if (!(thisHost = virGetHostname(ctl->conn))) {
        vshError(ctl, "%s", _("Failed to get local hostname"));
        goto cleanup;
    }

    if (!(thatHost = virConnectGetHostname(ctl->conn))) {
        vshError(ctl, "%s", _("Failed to get connection hostname"));
        goto cleanup;
    }

    if (STRNEQ(thisHost, thatHost)) {
        vshError(ctl, "%s", _("Cannot connect to a remote console device"));
        goto cleanup;
    }

    if (virDomainGetInfo(dom, &dominfo) < 0) {
        vshError(ctl, "%s", _("Unable to get domain status"));
        goto cleanup;
    }

    if (dominfo.state == VIR_DOMAIN_SHUTOFF) {
        vshError(ctl, "%s", _("The domain is not running"));
        goto cleanup;
    }

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
    if ((obj != NULL) && ((obj->type == XPATH_STRING) &&
                          (obj->stringval != NULL) && (obj->stringval[0] != 0))) {
        vshPrintExtra(ctl, _("Connected to domain %s\n"), virDomainGetName(dom));
        vshPrintExtra(ctl, "%s", _("Escape character is ^]\n"));
        if (vshRunConsole((const char *)obj->stringval) == 0)
            ret = TRUE;
    } else {
        vshPrintExtra(ctl, "%s", _("No console available for domain\n"));
    }
    xmlXPathFreeObject(obj);

 cleanup:
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    VIR_FREE(thisHost);
    VIR_FREE(thatHost);

    return ret;
}

static int
cmdConsole(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    ret = cmdRunConsole(ctl, dom);

    virDomainFree(dom);
    return ret;
}

#endif /* WIN32 */


/*
 * "list" command
 */
static const vshCmdInfo info_list[] = {
    {"help", gettext_noop("list domains")},
    {"desc", gettext_noop("Returns list of domains.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_list[] = {
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("list inactive domains")},
    {"all", VSH_OT_BOOL, 0, gettext_noop("list inactive & active domains")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
            state = N_(vshDomainStateToString(info.state));

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
            state = N_(vshDomainStateToString(info.state));

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
    {"help", gettext_noop("domain state")},
    {"desc", gettext_noop("Returns state about a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domstate[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomstate(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (virDomainGetInfo(dom, &info) == 0)
        vshPrint(ctl, "%s\n",
                 N_(vshDomainStateToString(info.state)));
    else
        ret = FALSE;

    virDomainFree(dom);
    return ret;
}

/* "domblkstat" command
 */
static const vshCmdInfo info_domblkstat[] = {
    {"help", gettext_noop("get device block stats for a domain")},
    {"desc", gettext_noop("Get device block stats for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domblkstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("block device")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomblkstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name, *device;
    struct _virDomainBlockStats stats;

    if (!vshConnectionUsability (ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("get network interface stats for a domain")},
    {"desc", gettext_noop("Get network interface stats for a running domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_domifstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface device")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomIfstat (vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name, *device;
    struct _virDomainInterfaceStats stats;

    if (!vshConnectionUsability (ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("get memory statistics for a domain")},
    {"desc", gettext_noop("Get memory statistics for a runnng domain.")},
    {NULL,NULL}
};

static const vshCmdOptDef opts_dommemstat[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomMemStat(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    struct _virDomainMemoryStat stats[VIR_DOMAIN_MEMORY_STAT_NR];
    unsigned int nr_stats, i;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
 * "suspend" command
 */
static const vshCmdInfo info_suspend[] = {
    {"help", gettext_noop("suspend a domain")},
    {"desc", gettext_noop("Suspend a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdSuspend(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a domain from an XML file")},
    {"desc", gettext_noop("Create a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML domain description")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, gettext_noop("attach to console after creation")},
#endif
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    dom = virDomainCreateXML(ctl->conn, buffer, 0);
    VIR_FREE(buffer);

    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s created from %s\n"),
                 virDomainGetName(dom), from);
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom);
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
    {"help", gettext_noop("define (but don't start) a domain from an XML file")},
    {"desc", gettext_noop("Define a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML domain description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("undefine an inactive domain")},
    {"desc", gettext_noop("Undefine the configuration for an inactive domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_undefine[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name or uuid")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("start a (previously defined) inactive domain")},
    {"desc", gettext_noop("Start a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_start[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the inactive domain")},
#ifndef WIN32
    {"console", VSH_OT_BOOL, 0, gettext_noop("attach to console after creation")},
#endif
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomainBy(ctl, cmd, NULL, VSH_BYNAME)))
        return FALSE;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, "%s", _("Domain is already active"));
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainCreate(dom) == 0) {
        vshPrint(ctl, _("Domain %s started\n"),
                 virDomainGetName(dom));
#ifndef WIN32
        if (console)
            cmdRunConsole(ctl, dom);
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
    {"help", gettext_noop("save a domain state to a file")},
    {"desc", gettext_noop("Save a running domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_save[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("where to save the data")},
    {NULL, 0, 0, NULL}
};

static int
cmdSave(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char *name;
    char *to;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
 * "schedinfo" command
 */
static const vshCmdInfo info_schedinfo[] = {
    {"help", gettext_noop("show/set scheduler parameters")},
    {"desc", gettext_noop("Show/Set scheduler parameters.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_schedinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"set", VSH_OT_STRING, VSH_OFLAG_NONE, gettext_noop("parameter=value")},
    {"weight", VSH_OT_INT, VSH_OFLAG_NONE, gettext_noop("weight for XEN_CREDIT")},
    {"cap", VSH_OT_INT, VSH_OFLAG_NONE, gettext_noop("cap for XEN_CREDIT")},
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
                         _("Invalid value for parameter, expecting an long long"));
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
        if (params == NULL)
            goto cleanup;

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
        }

        ret_val = TRUE;
        for (i = 0; i < nparams; i++){
            switch (params[i].type) {
            case VIR_DOMAIN_SCHED_FIELD_INT:
                 printf("%-15s: %d\n",  params[i].field, params[i].value.i);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_UINT:
                 printf("%-15s: %u\n",  params[i].field, params[i].value.ui);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_LLONG:
                 printf("%-15s: %lld\n",  params[i].field, params[i].value.l);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_ULLONG:
                 printf("%-15s: %llu\n",  params[i].field, params[i].value.ul);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
                 printf("%-15s: %f\n",  params[i].field, params[i].value.d);
                 break;
            case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
                 printf("%-15s: %d\n",  params[i].field, params[i].value.b);
                 break;
            default:
                 printf("not implemented scheduler parameter type\n");
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
    {"help", gettext_noop("restore a domain from a saved state in a file")},
    {"desc", gettext_noop("Restore a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_restore[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("the state to restore")},
    {NULL, 0, 0, NULL}
};

static int
cmdRestore(vshControl *ctl, const vshCmd *cmd)
{
    char *from;
    int found;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("dump the core of a domain to a file for analysis")},
    {"desc", gettext_noop("Core dump a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dump[] = {
    {"live", VSH_OT_BOOL, 0, gettext_noop("perform a live core dump if supported")},
    {"crash", VSH_OT_BOOL, 0, gettext_noop("crash the domain after core dump")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("where to dump the core")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("resume a domain")},
    {"desc", gettext_noop("Resume a previously suspended domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_resume[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdResume(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("gracefully shutdown a domain")},
    {"desc", gettext_noop("Run shutdown in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_shutdown[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdShutdown(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("reboot a domain")},
    {"desc", gettext_noop("Run a reboot command in the target domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_reboot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdReboot(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("destroy a domain")},
    {"desc", gettext_noop("Destroy a given domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("domain information")},
    {"desc", gettext_noop("Returns basic information about the domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dominfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDominfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    virSecurityModel secmodel;
    virSecurityLabel seclabel;
    int ret = TRUE, autostart;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
                 N_(vshDomainStateToString(info.state)));

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
    {"help", gettext_noop("domain job information")},
    {"desc", gettext_noop("Returns information about jobs running on a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};


static int
cmdDomjobinfo(vshControl *ctl, const vshCmd *cmd)
{
    virDomainJobInfo info;
    virDomainPtr dom;
    int ret = TRUE, autostart;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("abort active domain job")},
    {"desc", gettext_noop("Aborts the currently running domain job")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domjobabort[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomjobabort(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    unsigned int id;
    char *str, uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    if (virDomainAbortJob(dom) < 0)
        ret = FALSE;

cleanup:
    virDomainFree(dom);
    return ret;
}

/*
 * "freecell" command
 */
static const vshCmdInfo info_freecell[] = {
    {"help", gettext_noop("NUMA free memory")},
    {"desc", gettext_noop("display available free memory for the NUMA cell.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_freecell[] = {
    {"cellno", VSH_OT_DATA, 0, gettext_noop("NUMA cell number")},
    {NULL, 0, 0, NULL}
};

static int
cmdFreecell(vshControl *ctl, const vshCmd *cmd)
{
    int ret;
    int cell, cell_given;
    unsigned long long memory;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
 * "vcpuinfo" command
 */
static const vshCmdInfo info_vcpuinfo[] = {
    {"help", gettext_noop("domain vcpu information")},
    {"desc", gettext_noop("Returns basic information about the domain virtual CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpuinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
                     N_(vshDomainVcpuStateToString(cpuinfo[n].state)));
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
    {"help", gettext_noop("control domain vcpu affinity")},
    {"desc", gettext_noop("Pin domain VCPUs to host physical CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vcpupin[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"vcpu", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vcpu number")},
    {"cpulist", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("host cpu number(s) (comma separated)")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
        vshError(ctl, "%s", _("vcpupin: Missing cpulist"));
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
    {"help", gettext_noop("change number of virtual CPUs")},
    {"desc", gettext_noop("Change the number of virtual CPUs in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setvcpus[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"count", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("number of virtual CPUs")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetvcpus(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    int count;
    int maxcpu;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    count = vshCommandOptInt(cmd, "count", &count);
    if (count <= 0) {
        vshError(ctl, "%s", _("Invalid number of virtual CPUs."));
        virDomainFree(dom);
        return FALSE;
    }

    maxcpu = virDomainGetMaxVcpus(dom);
    if (maxcpu <= 0) {
        virDomainFree(dom);
        return FALSE;
    }

    if (count > maxcpu) {
        vshError(ctl, "%s", _("Too many virtual CPUs."));
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainSetVcpus(dom, count) != 0) {
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "setmemory" command
 */
static const vshCmdInfo info_setmem[] = {
    {"help", gettext_noop("change memory allocation")},
    {"desc", gettext_noop("Change the current memory allocation in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"kilobytes", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("number of kilobytes of memory")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainInfo info;
    int kilobytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
        vshError(ctl, "%s", _("Unable to verify MaxMemorySize"));
        return FALSE;
    }

    if (kilobytes > info.maxMem) {
        virDomainFree(dom);
        vshError(ctl, _("Invalid value of %d for memory size"), kilobytes);
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
    {"help", gettext_noop("change maximum memory limit")},
    {"desc", gettext_noop("Change the maximum memory allocation limit in the guest domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_setmaxmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"kilobytes", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("maximum memory limit in kilobytes")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmaxmem(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    virDomainInfo info;
    int kilobytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

    if (kilobytes < info.memory) {
        if (virDomainSetMemory(dom, kilobytes) != 0) {
            virDomainFree(dom);
            vshError(ctl, "%s", _("Unable to shrink current MemorySize"));
            return FALSE;
        }
    }

    if (virDomainSetMaxMemory(dom, kilobytes) != 0) {
        vshError(ctl, "%s", _("Unable to change MaxMemorySize"));
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "nodeinfo" command
 */
static const vshCmdInfo info_nodeinfo[] = {
    {"help", gettext_noop("node information")},
    {"desc", gettext_noop("Returns basic information about the node.")},
    {NULL, NULL}
};

static int
cmdNodeinfo(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("capabilities")},
    {"desc", gettext_noop("Returns capabilities of hypervisor/driver.")},
    {NULL, NULL}
};

static int
cmdCapabilities (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *caps;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("domain information in XML")},
    {"desc", gettext_noop("Output the domain information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("show inactive defined XML")},
    {"security-info", VSH_OT_BOOL, 0, gettext_noop("include security sensitive information in XML dump")},
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

    if (inactive)
        flags |= VIR_DOMAIN_XML_INACTIVE;
    if (secure)
        flags |= VIR_DOMAIN_XML_SECURE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    dump = virDomainGetXMLDesc(dom, flags);
    if (dump != NULL) {
        printf("%s", dump);
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
    {"help", gettext_noop("Convert native config to domain XML")},
    {"desc", gettext_noop("Convert native guest configuration format to domain XML format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmlfromnative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("source config data format")},
    {"config", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("config data file to import from")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    format = vshCommandOptString(cmd, "format", NULL);
    configFile = vshCommandOptString(cmd, "config", NULL);

    if (virFileReadAll(configFile, 1024*1024, &configData) < 0) {
        return FALSE;
    }

    xmlData = virConnectDomainXMLFromNative(ctl->conn, format, configData, flags);
    if (xmlData != NULL) {
        printf("%s", xmlData);
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
    {"help", gettext_noop("Convert domain XML to native config")},
    {"desc", gettext_noop("Convert domain XML config to a native guest configuration format.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domxmltonative[] = {
    {"format", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("target config data type format")},
    {"xml", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("xml data file to export from")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    format = vshCommandOptString(cmd, "format", NULL);
    xmlFile = vshCommandOptString(cmd, "xml", NULL);

    if (virFileReadAll(xmlFile, 1024*1024, &xmlData) < 0) {
        return FALSE;
    }

    configData = virConnectDomainXMLToNative(ctl->conn, format, xmlData, flags);
    if (configData != NULL) {
        printf("%s", configData);
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
    {"help", gettext_noop("convert a domain id or UUID to domain name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomname(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert a domain name or UUID to domain id")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert a domain name or id to domain UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_domuuid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain id or name")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomuuid(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("migrate domain to another host")},
    {"desc", gettext_noop("Migrate domain to another host.  Add --live for live migration.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_migrate[] = {
    {"live", VSH_OT_BOOL, 0, gettext_noop("live migration")},
    {"p2p", VSH_OT_BOOL, 0, gettext_noop("peer-2-peer migration")},
    {"direct", VSH_OT_BOOL, 0, gettext_noop("direct migration")},
    {"tunnelled", VSH_OT_BOOL, 0, gettext_noop("tunnelled migration")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist VM on destination")},
    {"undefinesource", VSH_OT_BOOL, 0, gettext_noop("undefine VM on source")},
    {"suspend", VSH_OT_BOOL, 0, gettext_noop("do not restart the domain on the destination host")},
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"desturi", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("connection URI of the destination host")},
    {"migrateuri", VSH_OT_DATA, 0, gettext_noop("migration URI, usually can be omitted")},
    {"dname", VSH_OT_DATA, 0, gettext_noop("rename to new name during migration (if supported)")},
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

    if (!vshConnectionUsability (ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain (ctl, cmd, NULL)))
        return FALSE;

    desturi = vshCommandOptString (cmd, "desturi", &found);
    if (!found) {
        vshError(ctl, "%s", _("migrate: Missing desturi"));
        goto done;
    }

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
 * "net-autostart" command
 */
static const vshCmdInfo info_network_autostart[] = {
    {"help", gettext_noop("autostart a network")},
    {"desc",
     gettext_noop("Configure a network to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_autostart[] = {
    {"network",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name or uuid")},
    {"disable", VSH_OT_BOOL, 0, gettext_noop("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a network from an XML file")},
    {"desc", gettext_noop("Create a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML network description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("define (but don't start) a network from an XML file")},
    {"desc", gettext_noop("Define a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML network description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("destroy a network")},
    {"desc", gettext_noop("Destroy a given network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_destroy[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("network information in XML")},
    {"desc", gettext_noop("Output the network information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_dumpxml[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(network = vshCommandOptNetwork(ctl, cmd, NULL)))
        return FALSE;

    dump = virNetworkGetXMLDesc(network, 0);
    if (dump != NULL) {
        printf("%s", dump);
        VIR_FREE(dump);
    } else {
        ret = FALSE;
    }

    virNetworkFree(network);
    return ret;
}


/*
 * "iface-edit" command
 */
static const vshCmdInfo info_interface_edit[] = {
    {"help", gettext_noop("edit XML configuration for a physical host interface")},
    {"desc", gettext_noop("Edit the XML configuration for a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_edit[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name or MAC address")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

    unlink (tmp);
    tmp = NULL;

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
    {"help", gettext_noop("list networks")},
    {"desc", gettext_noop("Returns list of networks.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_list[] = {
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("list inactive networks")},
    {"all", VSH_OT_BOOL, 0, gettext_noop("list inactive & active networks")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
            autostartStr = autostart ? "yes" : "no";

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
            autostartStr = autostart ? "yes" : "no";

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
    {"help", gettext_noop("convert a network UUID to network name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_name[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkName(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("start a (previously defined) inactive network")},
    {"desc", gettext_noop("Start a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_start[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the inactive network")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkStart(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("undefine an inactive network")},
    {"desc", gettext_noop("Undefine the configuration for an inactive network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_undefine[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert a network name to network UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_uuid[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name")},
    {NULL, 0, 0, NULL}
};

static int
cmdNetworkUuid(vshControl *ctl, const vshCmd *cmd)
{
    virNetworkPtr network;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("list physical host interfaces")},
    {"desc", gettext_noop("Returns list of physical host interfaces.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_list[] = {
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("list inactive interfaces")},
    {"all", VSH_OT_BOOL, 0, gettext_noop("list inactive & active interfaces")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert an interface MAC address to interface name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_name[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface mac")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceName(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert an interface name to interface MAC address")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_mac[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceMAC(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("interface information in XML")},
    {"desc", gettext_noop("Output the physical host interface information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_dumpxml[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name or MAC address")},
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("show inactive defined XML")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(iface = vshCommandOptInterface(ctl, cmd, NULL)))
        return FALSE;

    dump = virInterfaceGetXMLDesc(iface, flags);
    if (dump != NULL) {
        printf("%s", dump);
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
    {"help", gettext_noop("define (but don't start) a physical host interface from an XML file")},
    {"desc", gettext_noop("Define a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML interface description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("undefine a physical host interface (remove it from configuration)")},
    {"desc", gettext_noop("undefine an interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_undefine[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("start a physical host interface (enable it / \"if-up\")")},
    {"desc", gettext_noop("start a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_start[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceStart(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("destroy a physical host interface (disable it / \"if-down\")")},
    {"desc", gettext_noop("destroy a physical host interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_interface_destroy[] = {
    {"interface", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("interface name or MAC address")},
    {NULL, 0, 0, NULL}
};

static int
cmdInterfaceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virInterfacePtr iface;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

/**************************************************************************/
/*
 * "pool-autostart" command
 */
static const vshCmdInfo info_pool_autostart[] = {
    {"help", gettext_noop("autostart a pool")},
    {"desc",
     gettext_noop("Configure a pool to be automatically started at boot.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_autostart[] = {
    {"pool",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {"disable", VSH_OT_BOOL, 0, gettext_noop("disable autostarting")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolAutostart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *name;
    int autostart;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a pool from an XML file")},
    {"desc", gettext_noop("Create a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ,
     gettext_noop("file containing an XML pool description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a device defined "
                          "by an XML file on the node")},
    {"desc", gettext_noop("Create a device on the node.  Note that this "
                          "command creates devices on the physical host "
                          "that can then be assigned to a virtual machine.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ,
     gettext_noop("file containing an XML description of the device")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
        return FALSE;
    }

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
    {"help", gettext_noop("destroy a device on the node")},
    {"desc", gettext_noop("Destroy a device on the node.  Note that this "
                          "command destroys devices on the physical host ")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_device_destroy[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ,
     gettext_noop("name of the device to be destroyed")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virNodeDevicePtr dev = NULL;
    int ret = TRUE;
    int found = 0;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE)) {
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
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the pool")},
    {"print-xml", VSH_OT_BOOL, 0, gettext_noop("print XML document, but don't define/create")},
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("type of the pool")},
    {"source-host", VSH_OT_DATA, 0, gettext_noop("source-host for underlying storage")},
    {"source-path", VSH_OT_DATA, 0, gettext_noop("source path for underlying storage")},
    {"source-dev", VSH_OT_DATA, 0, gettext_noop("source device for underlying storage")},
    {"source-name", VSH_OT_DATA, 0, gettext_noop("source name for underlying storage")},
    {"target", VSH_OT_DATA, 0, gettext_noop("target for underlying storage")},
    {NULL, 0, 0, NULL}
};

static int buildPoolXML(const vshCmd *cmd, char **retname, char **xml) {

    int found;
    char *name, *type, *srcHost, *srcPath, *srcDev, *srcName, *target;
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
    {"help", gettext_noop("create a pool from a set of args")},
    {"desc", gettext_noop("Create a pool.")},
    {NULL, NULL}
};

static int
cmdPoolCreateAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *xml, *name;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!buildPoolXML(cmd, &name, &xml))
        return FALSE;

    if (printXML) {
        printf("%s", xml);
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
    {"help", gettext_noop("define (but don't start) a pool from an XML file")},
    {"desc", gettext_noop("Define a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML pool description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("define a pool from a set of args")},
    {"desc", gettext_noop("Define a pool.")},
    {NULL, NULL}
};

static int
cmdPoolDefineAs(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char *xml, *name;
    int printXML = vshCommandOptBool(cmd, "print-xml");

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!buildPoolXML(cmd, &name, &xml))
        return FALSE;

    if (printXML) {
        printf("%s", xml);
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
    {"help", gettext_noop("build a pool")},
    {"desc", gettext_noop("Build a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_build[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolBuild(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("destroy a pool")},
    {"desc", gettext_noop("Destroy a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_destroy[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolDestroy(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("delete a pool")},
    {"desc", gettext_noop("Delete a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_delete[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("refresh a pool")},
    {"desc", gettext_noop("Refresh a given pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_refresh[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolRefresh(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("pool information in XML")},
    {"desc", gettext_noop("Output the pool information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_dumpxml[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return FALSE;

    dump = virStoragePoolGetXMLDesc(pool, 0);
    if (dump != NULL) {
        printf("%s", dump);
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
    {"help", gettext_noop("list pools")},
    {"desc", gettext_noop("Returns list of pools.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_list[] = {
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("list inactive pools")},
    {"all", VSH_OT_BOOL, 0, gettext_noop("list inactive & active pools")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int maxactive = 0, maxinactive = 0, i;
    char **activeNames = NULL, **inactiveNames = NULL;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (active) {
        maxactive = virConnectNumOfStoragePools(ctl->conn);
        if (maxactive < 0) {
            vshError(ctl, "%s", _("Failed to list active pools"));
            return FALSE;
        }
        if (maxactive) {
            activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

            if ((maxactive = virConnectListStoragePools(ctl->conn, activeNames,
                                                        maxactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list active pools"));
                VIR_FREE(activeNames);
                return FALSE;
            }

            qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
        }
    }
    if (inactive) {
        maxinactive = virConnectNumOfDefinedStoragePools(ctl->conn);
        if (maxinactive < 0) {
            vshError(ctl, "%s", _("Failed to list inactive pools"));
            VIR_FREE(activeNames);
            return FALSE;
        }
        if (maxinactive) {
            inactiveNames = vshMalloc(ctl, sizeof(char *) * maxinactive);

            if ((maxinactive = virConnectListDefinedStoragePools(ctl->conn, inactiveNames, maxinactive)) < 0) {
                vshError(ctl, "%s", _("Failed to list inactive pools"));
                VIR_FREE(activeNames);
                VIR_FREE(inactiveNames);
                return FALSE;
            }

            qsort(&inactiveNames[0], maxinactive, sizeof(char*), namesorter);
        }
    }
    vshPrintExtra(ctl, "%-20s %-10s %-10s\n", _("Name"), _("State"), _("Autostart"));
    vshPrintExtra(ctl, "-----------------------------------------\n");

    for (i = 0; i < maxactive; i++) {
        virStoragePoolPtr pool = virStoragePoolLookupByName(ctl->conn, activeNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with pools is not atomic operation */
        if (!pool) {
            VIR_FREE(activeNames[i]);
            continue;
        }

        if (virStoragePoolGetAutostart(pool, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? "yes" : "no";

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 virStoragePoolGetName(pool),
                 _("active"),
                 autostartStr);
        virStoragePoolFree(pool);
        VIR_FREE(activeNames[i]);
    }
    for (i = 0; i < maxinactive; i++) {
        virStoragePoolPtr pool = virStoragePoolLookupByName(ctl->conn, inactiveNames[i]);
        const char *autostartStr;
        int autostart = 0;

        /* this kind of work with pools is not atomic operation */
        if (!pool) {
            VIR_FREE(inactiveNames[i]);
            continue;
        }

        if (virStoragePoolGetAutostart(pool, &autostart) < 0)
            autostartStr = _("no autostart");
        else
            autostartStr = autostart ? "yes" : "no";

        vshPrint(ctl, "%-20s %-10s %-10s\n",
                 inactiveNames[i],
                 _("inactive"),
                 autostartStr);

        virStoragePoolFree(pool);
        VIR_FREE(inactiveNames[i]);
    }
    VIR_FREE(activeNames);
    VIR_FREE(inactiveNames);
    return TRUE;
}

/*
 * "find-storage-pool-sources-as" command
 */
static const vshCmdInfo info_find_storage_pool_sources_as[] = {
    {"help", gettext_noop("find potential storage pool sources")},
    {"desc", gettext_noop("Returns XML <sources> document.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources_as[] = {
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ,
     gettext_noop("type of storage pool sources to find")},
    {"host", VSH_OT_DATA, VSH_OFLAG_NONE, gettext_noop("optional host to query")},
    {"port", VSH_OT_DATA, VSH_OFLAG_NONE, gettext_noop("optional port to query")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolDiscoverSourcesAs(vshControl * ctl, const vshCmd * cmd ATTRIBUTE_UNUSED)
{
    char *type, *host;
    char *srcSpec = NULL;
    char *srcList;
    int found;

    type = vshCommandOptString(cmd, "type", &found);
    if (!found)
        return FALSE;
    host = vshCommandOptString(cmd, "host", &found);
    if (!found)
        host = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (host) {
        size_t hostlen = strlen(host);
        char *port = vshCommandOptString(cmd, "port", &found);
        int ret;
        if (!found) {
            port = strrchr(host, ':');
            if (port) {
                if (*(++port))
                    hostlen = port - host - 1;
                else
                    port = NULL;
            }
        }
        ret = port ?
            virAsprintf(&srcSpec,
                        "<source><host name='%.*s' port='%s'/></source>",
                        (int)hostlen, host, port) :
            virAsprintf(&srcSpec,
                        "<source><host name='%.*s'/></source>",
                        (int)hostlen, host);
        if (ret < 0) {
            switch (errno) {
            case ENOMEM:
                vshError(ctl, "%s", _("Out of memory"));
                break;
            default:
                vshError(ctl, _("virAsprintf failed (errno %d)"), errno);
            }
            return FALSE;
        }
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
    {"help", gettext_noop("discover potential storage pool sources")},
    {"desc", gettext_noop("Returns XML <sources> document.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_find_storage_pool_sources[] = {
    {"type", VSH_OT_DATA, VSH_OFLAG_REQ,
     gettext_noop("type of storage pool sources to discover")},
    {"srcSpec", VSH_OT_DATA, VSH_OFLAG_NONE,
     gettext_noop("optional file of source xml to query for pools")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("storage pool information")},
    {"desc", gettext_noop("Returns basic information about the storage pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_info[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolInfo info;
    virStoragePoolPtr pool;
    int ret = TRUE;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
        }

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
    {"help", gettext_noop("convert a pool UUID to pool name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_name[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolName(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("start a (previously defined) inactive pool")},
    {"desc", gettext_noop("Start a pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_start[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the inactive pool")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolStart(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a volume from a set of args")},
    {"desc", gettext_noop("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_as[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name")},
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the volume")},
    {"capacity", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("size of the vol with optional k,M,G,T suffix")},
    {"allocation", VSH_OT_STRING, 0, gettext_noop("initial allocation size with optional k,M,G,T suffix")},
    {"format", VSH_OT_STRING, 0, gettext_noop("file format type raw,bochs,qcow,qcow2,vmdk")},
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
    unsigned long long capacity, allocation = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("undefine an inactive pool")},
    {"desc", gettext_noop("Undefine the configuration for an inactive pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_undefine[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("convert a pool name to pool UUID")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_uuid[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name")},
    {NULL, 0, 0, NULL}
};

static int
cmdPoolUuid(vshControl *ctl, const vshCmd *cmd)
{
    virStoragePoolPtr pool;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a vol from an XML file")},
    {"desc", gettext_noop("Create a vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML vol description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("create a vol, using another volume as input")},
    {"desc", gettext_noop("Create a vol from an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_create_from[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML vol description")},
    {"inputpool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid of the input volume's pool")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("input vol name or key")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("clone a volume.")},
    {"desc", gettext_noop("Clone an existing volume.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_clone[] = {
    {"pool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("orig vol name or key")},
    {"newname", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("clone name")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("delete a vol")},
    {"desc", gettext_noop("Delete a given vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_delete[] = {
    {"pool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolDelete(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
 * "vol-info" command
 */
static const vshCmdInfo info_vol_info[] = {
    {"help", gettext_noop("storage vol information")},
    {"desc", gettext_noop("Returns basic information about the storage vol.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_info[] = {
    {"pool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolInfo(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolInfo info;
    virStorageVolPtr vol;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("vol information in XML")},
    {"desc", gettext_noop("Output the vol information as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_dumpxml[] = {
    {"pool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol name, key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(vol = vshCommandOptVol(ctl, cmd, "vol", "pool", NULL)))
        return FALSE;

    dump = virStorageVolGetXMLDesc(vol, 0);
    if (dump != NULL) {
        printf("%s", dump);
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
    {"help", gettext_noop("list vols")},
    {"desc", gettext_noop("Returns list of vols by pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_list[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    virStoragePoolPtr pool;
    int maxactive = 0, i;
    char **activeNames = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(pool = vshCommandOptPool(ctl, cmd, "pool", NULL)))
        return FALSE;

    maxactive = virStoragePoolNumOfVolumes(pool);
    if (maxactive < 0) {
        virStoragePoolFree(pool);
        vshError(ctl, "%s", _("Failed to list active vols"));
        return FALSE;
    }
    if (maxactive) {
        activeNames = vshMalloc(ctl, sizeof(char *) * maxactive);

        if ((maxactive = virStoragePoolListVolumes(pool, activeNames,
                                                   maxactive)) < 0) {
            vshError(ctl, "%s", _("Failed to list active vols"));
            VIR_FREE(activeNames);
            virStoragePoolFree(pool);
            return FALSE;
        }

        qsort(&activeNames[0], maxactive, sizeof(char *), namesorter);
    }
    vshPrintExtra(ctl, "%-20s %-40s\n", _("Name"), _("Path"));
    vshPrintExtra(ctl, "-----------------------------------------\n");

    for (i = 0; i < maxactive; i++) {
        virStorageVolPtr vol = virStorageVolLookupByName(pool, activeNames[i]);
        char *path;

        /* this kind of work with vols is not atomic operation */
        if (!vol) {
            VIR_FREE(activeNames[i]);
            continue;
        }

        if ((path = virStorageVolGetPath(vol)) == NULL) {
            virStorageVolFree(vol);
            continue;
        }


        vshPrint(ctl, "%-20s %-40s\n",
                 virStorageVolGetName(vol),
                 path);
        VIR_FREE(path);
        virStorageVolFree(vol);
        VIR_FREE(activeNames[i]);
    }
    VIR_FREE(activeNames);
    virStoragePoolFree(pool);
    return TRUE;
}


/*
 * "vol-name" command
 */
static const vshCmdInfo info_vol_name[] = {
    {"help", gettext_noop("convert a vol UUID to vol name")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_name[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol key or path")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolName(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", "pool", NULL,
                                   VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virStorageVolGetName(vol));
    virStorageVolFree(vol);
    return TRUE;
}



/*
 * "vol-key" command
 */
static const vshCmdInfo info_vol_key[] = {
    {"help", gettext_noop("convert a vol UUID to vol key")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_key[] = {
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolKey(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(vol = vshCommandOptVolBy(ctl, cmd, "vol", "pool", NULL,
                                   VSH_BYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virStorageVolGetKey(vol));
    virStorageVolFree(vol);
    return TRUE;
}



/*
 * "vol-path" command
 */
static const vshCmdInfo info_vol_path[] = {
    {"help", gettext_noop("convert a vol UUID to vol path")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vol_path[] = {
    {"pool", VSH_OT_STRING, 0, gettext_noop("pool name or uuid")},
    {"vol", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vol name or key")},
    {NULL, 0, 0, NULL}
};

static int
cmdVolPath(vshControl *ctl, const vshCmd *cmd)
{
    virStorageVolPtr vol;
    char *name = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("define or modify a secret from an XML file")},
    {"desc", gettext_noop("Define or modify a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing secret attributes in XML")},
    {NULL, 0, 0, NULL}
};

static int
cmdSecretDefine(vshControl *ctl, const vshCmd *cmd)
{
    char *from, *buffer;
    virSecretPtr res;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("secret attributes in XML")},
    {"desc", gettext_noop("Output attributes of a secret as an XML dump to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_dumpxml[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("secret UUID")},
    {NULL, 0, 0, NULL}
};

static int
cmdSecretDumpXML(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    int ret = FALSE;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    secret = vshCommandOptSecret(ctl, cmd, NULL);
    if (secret == NULL)
        return FALSE;

    xml = virSecretGetXMLDesc(secret, 0);
    if (xml == NULL)
        goto cleanup;
    printf("%s", xml);
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
    {"help", gettext_noop("set a secret value")},
    {"desc", gettext_noop("Set a secret value.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_set_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("secret UUID")},
    {"base64", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("base64-encoded secret value")},
    {NULL, 0, 0, NULL}
};

static int
cmdSecretSetValue(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    size_t value_size;
    char *base64, *value;
    int found, res, ret = FALSE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("Output a secret value")},
    {"desc", gettext_noop("Output a secret value to stdout.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_get_value[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("secret UUID")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    printf("%s", base64);
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
    {"help", gettext_noop("undefine a secret")},
    {"desc", gettext_noop("Undefine a secret.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_secret_undefine[] = {
    {"secret", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("secret UUID")},
    {NULL, 0, 0, NULL}
};

static int
cmdSecretUndefine(vshControl *ctl, const vshCmd *cmd)
{
    virSecretPtr secret;
    int ret = FALSE;
    char *uuid;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("list secrets")},
    {"desc", gettext_noop("Returns a list of secrets")},
    {NULL, NULL}
};

static int
cmdSecretList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int maxuuids = 0, i;
    char **uuids = NULL;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("show version")},
    {"desc", gettext_noop("Display the system version information.")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("enumerate devices on this host")},
    {"desc", ""},
    {NULL, NULL}
};

static const vshCmdOptDef opts_node_list_devices[] = {
    {"tree", VSH_OT_BOOL, 0, gettext_noop("list devices in a tree")},
    {"cap", VSH_OT_STRING, VSH_OFLAG_NONE, gettext_noop("capability name")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
                parents[i] = parent ? strdup(parent) : NULL;
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
    {"help", gettext_noop("node device details in XML")},
    {"desc", gettext_noop("Output the node device details as an XML dump to stdout.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_dumpxml[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("device key")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceDumpXML (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    char *xml;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("dettach node device from its device driver")},
    {"desc", gettext_noop("Dettach node device from its device driver before assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_dettach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("device key")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceDettach (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("reattach node device to its device driver")},
    {"desc", gettext_noop("Reattach node device to its device driver once released by the domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reattach[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("device key")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceReAttach (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("reset node device")},
    {"desc", gettext_noop("Reset node device before or after assigning to a domain.")},
    {NULL, NULL}
};


static const vshCmdOptDef opts_node_device_reset[] = {
    {"device", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("device key")},
    {NULL, 0, 0, NULL}
};

static int
cmdNodeDeviceReset (vshControl *ctl, const vshCmd *cmd)
{
    const char *name;
    virNodeDevicePtr device;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("print the hypervisor hostname")},
    {"desc", ""},
    {NULL, NULL}
};

static int
cmdHostname (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *hostname;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("print the hypervisor canonical URI")},
    {"desc", ""},
    {NULL, NULL}
};

static int
cmdURI (vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("vnc display")},
    {"desc", gettext_noop("Output the IP address and port number for the VNC display.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_vncdisplay[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("tty console")},
    {"desc", gettext_noop("Output the device for the TTY console.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_ttyconsole[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("attach device from an XML file")},
    {"desc", gettext_noop("Attach device from an XML <file>.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("XML file")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist device attachment")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        vshError(ctl, "%s", _("attach-device: Missing <file> option"));
        virDomainFree(dom);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
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
    {"help", gettext_noop("detach device from an XML file")},
    {"desc", gettext_noop("Detach device from an XML <file>")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_device[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file",   VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("XML file")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist device detachment")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found) {
        vshError(ctl, "%s", _("detach-device: Missing <file> option"));
        virDomainFree(dom);
        return FALSE;
    }

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0) {
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
 * "attach-interface" command
 */
static const vshCmdInfo info_attach_interface[] = {
    {"help", gettext_noop("attach network interface")},
    {"desc", gettext_noop("Attach new network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network interface type")},
    {"source", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("source of network interface")},
    {"target", VSH_OT_DATA, 0, gettext_noop("target network name")},
    {"mac",    VSH_OT_DATA, 0, gettext_noop("MAC address")},
    {"script", VSH_OT_DATA, 0, gettext_noop("script used to bridge network interface")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist interface attachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdAttachInterface(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    char *mac, *target, *script, *type, *source;
    int typ, ret = FALSE;
    char *buf = NULL, *tmp = NULL;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        goto cleanup;

    if (!(dom = vshCommandOptDomain(ctl, cmd, NULL)))
        goto cleanup;

    if (!(type = vshCommandOptString(cmd, "type", NULL)))
        goto cleanup;

    source = vshCommandOptString(cmd, "source", NULL);
    target = vshCommandOptString(cmd, "target", NULL);
    mac = vshCommandOptString(cmd, "mac", NULL);
    script = vshCommandOptString(cmd, "script", NULL);

    /* check interface type */
    if (STREQ(type, "network")) {
        typ = 1;
    } else if (STREQ(type, "bridge")) {
        typ = 2;
    } else {
        vshError(ctl, _("No support %s in command 'attach-interface'"), type);
        goto cleanup;
    }

    /* Make XML of interface */
    tmp = vshMalloc(ctl, 1);
    if (!tmp) goto cleanup;
    buf = vshMalloc(ctl, strlen(type) + 25);
    if (!buf) goto cleanup;
    sprintf(buf, "    <interface type='%s'>\n" , type);

    tmp = vshRealloc(ctl, tmp, strlen(source) + 28);
    if (!tmp) goto cleanup;
    if (typ == 1) {
        sprintf(tmp, "      <source network='%s'/>\n", source);
    } else if (typ == 2) {
        sprintf(tmp, "      <source bridge='%s'/>\n", source);
    }
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    if (target != NULL) {
        tmp = vshRealloc(ctl, tmp, strlen(target) + 24);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <target dev='%s'/>\n", target);
        buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
        if (!buf) goto cleanup;
        strcat(buf, tmp);
    }

    if (mac != NULL) {
        tmp = vshRealloc(ctl, tmp, strlen(mac) + 25);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <mac address='%s'/>\n", mac);
        buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
        if (!buf) goto cleanup;
        strcat(buf, tmp);
    }

    if (script != NULL) {
        tmp = vshRealloc(ctl, tmp, strlen(script) + 25);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <script path='%s'/>\n", script);
        buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
        if (!buf) goto cleanup;
        strcat(buf, tmp);
    }

    buf = vshRealloc(ctl, buf, strlen(buf) + 19);
    if (!buf) goto cleanup;
    strcat(buf, "    </interface>\n");

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainAttachDeviceFlags(dom, buf, flags);
    } else {
        ret = virDomainAttachDevice(dom, buf);
    }

    if (ret != 0) {
        vshError(ctl, _("Failed to attach interface"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Interface attached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    VIR_FREE(buf);
    VIR_FREE(tmp);
    return ret;
}

/*
 * "detach-interface" command
 */
static const vshCmdInfo info_detach_interface[] = {
    {"help", gettext_noop("detach network interface")},
    {"desc", gettext_noop("Detach network interface.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_interface[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"type",   VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network interface type")},
    {"mac",    VSH_OT_STRING, 0, gettext_noop("MAC address")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist interface detachment")},
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
    xmlChar *tmp_mac = NULL;
    xmlBufferPtr xml_buf = NULL;
    char *doc, *mac =NULL, *type;
    char buf[64];
    int i = 0, diff_mac, ret = FALSE;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

    sprintf(buf, "/domain/devices/interface[@type='%s']", type);
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
            if (cur->type == XML_ELEMENT_NODE && xmlStrEqual(cur->name, BAD_CAST "mac")) {
                tmp_mac = xmlGetProp(cur, BAD_CAST "address");
                diff_mac = virMacAddrCompare ((char *) tmp_mac, mac);
                xmlFree(tmp_mac);
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
        vshError(ctl, _("Failed to detach interface"));
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
    {"help", gettext_noop("attach disk device")},
    {"desc", gettext_noop("Attach new disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_attach_disk[] = {
    {"domain",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"source",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("source of disk device")},
    {"target",  VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("target of disk device")},
    {"driver",    VSH_OT_STRING, 0, gettext_noop("driver of disk device")},
    {"subdriver", VSH_OT_STRING, 0, gettext_noop("subdriver of disk device")},
    {"type",    VSH_OT_STRING, 0, gettext_noop("target device type")},
    {"mode",    VSH_OT_STRING, 0, gettext_noop("mode of device reading and writing")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist disk attachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdAttachDisk(vshControl *ctl, const vshCmd *cmd)
{
    virDomainPtr dom = NULL;
    char *source, *target, *driver, *subdriver, *type, *mode;
    int isFile = 0, ret = FALSE;
    char *buf = NULL, *tmp = NULL;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

    if (driver) {
        if (STREQ(driver, "file") || STREQ(driver, "tap")) {
            isFile = 1;
        } else if (STRNEQ(driver, "phy")) {
            vshError(ctl, _("No support %s in command 'attach-disk'"), driver);
            goto cleanup;
        }
    }

    if (mode) {
        if (STRNEQ(mode, "readonly") && STRNEQ(mode, "shareable")) {
            vshError(ctl, _("No support %s in command 'attach-disk'"), mode);
            goto cleanup;
        }
    }

    /* Make XML of disk */
    tmp = vshMalloc(ctl, 1);
    if (!tmp) goto cleanup;
    buf = vshMalloc(ctl, 23);
    if (!buf) goto cleanup;
    if (isFile) {
        sprintf(buf, "    <disk type='file'");
    } else {
        sprintf(buf, "    <disk type='block'");
    }

    if (type) {
        tmp = vshRealloc(ctl, tmp, strlen(type) + 13);
        if (!tmp) goto cleanup;
        sprintf(tmp, " device='%s'>\n", type);
    } else {
        tmp = vshRealloc(ctl, tmp, 3);
        if (!tmp) goto cleanup;
        sprintf(tmp, ">\n");
    }
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    if (driver) {
        tmp = vshRealloc(ctl, tmp, strlen(driver) + 22);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <driver name='%s'", driver);
    } else {
        tmp = vshRealloc(ctl, tmp, 25);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <driver name='phy'");
    }
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    if (subdriver) {
        tmp = vshRealloc(ctl, tmp, strlen(subdriver) + 12);
        if (!tmp) goto cleanup;
        sprintf(tmp, " type='%s'/>\n", subdriver);
    } else {
        tmp = vshRealloc(ctl, tmp, 4);
        if (!tmp) goto cleanup;
        sprintf(tmp, "/>\n");
    }
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    tmp = vshRealloc(ctl, tmp, strlen(source) + 25);
    if (!tmp) goto cleanup;
    if (isFile) {
        sprintf(tmp, "      <source file='%s'/>\n", source);
    } else {
        sprintf(tmp, "      <source dev='%s'/>\n", source);
    }
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    tmp = vshRealloc(ctl, tmp, strlen(target) + 24);
    if (!tmp) goto cleanup;
    sprintf(tmp, "      <target dev='%s'/>\n", target);
    buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
    if (!buf) goto cleanup;
    strcat(buf, tmp);

    if (mode != NULL) {
        tmp = vshRealloc(ctl, tmp, strlen(mode) + 11);
        if (!tmp) goto cleanup;
        sprintf(tmp, "      <%s/>\n", mode);
        buf = vshRealloc(ctl, buf, strlen(buf) + strlen(tmp) + 1);
        if (!buf) goto cleanup;
        strcat(buf, tmp);
    }

    buf = vshRealloc(ctl, buf, strlen(buf) + 13);
    if (!buf) goto cleanup;
    strcat(buf, "    </disk>\n");

    if (vshCommandOptBool(cmd, "persistent")) {
        flags = VIR_DOMAIN_DEVICE_MODIFY_CONFIG;
        if (virDomainIsActive(dom) == 1)
            flags |= VIR_DOMAIN_DEVICE_MODIFY_LIVE;
        ret = virDomainAttachDeviceFlags(dom, buf, flags);
    } else {
        ret = virDomainAttachDevice(dom, buf);
    }

    if (ret != 0) {
        vshError(ctl, _("Failed to attach disk"));
        ret = FALSE;
    } else {
        vshPrint(ctl, "%s", _("Disk attached successfully\n"));
        ret = TRUE;
    }

 cleanup:
    if (dom)
        virDomainFree(dom);
    VIR_FREE(buf);
    VIR_FREE(tmp);
    return ret;
}

/*
 * "detach-disk" command
 */
static const vshCmdInfo info_detach_disk[] = {
    {"help", gettext_noop("detach disk device")},
    {"desc", gettext_noop("Detach disk device.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_detach_disk[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"target", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("target of disk device")},
    {"persistent", VSH_OT_BOOL, 0, gettext_noop("persist disk detachment")},
    {NULL, 0, 0, NULL}
};

static int
cmdDetachDisk(vshControl *ctl, const vshCmd *cmd)
{
    xmlDocPtr xml = NULL;
    xmlXPathObjectPtr obj=NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr cur = NULL;
    xmlChar *tmp_tgt = NULL;
    xmlBufferPtr xml_buf = NULL;
    virDomainPtr dom = NULL;
    char *doc, *target;
    int i = 0, diff_tgt, ret = FALSE;
    unsigned int flags;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
            if (cur->type == XML_ELEMENT_NODE && xmlStrEqual(cur->name, BAD_CAST "target")) {
                tmp_tgt = xmlGetProp(cur, BAD_CAST "dev");
                diff_tgt = xmlStrEqual(tmp_tgt, BAD_CAST target);
                xmlFree(tmp_tgt);
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
        vshError(ctl, _("Failed to detach disk"));
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
    {"help", gettext_noop("compare host CPU with a CPU described by an XML file")},
    {"desc", gettext_noop("compare CPU with host CPU")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_compare[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing an XML CPU description")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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
    {"help", gettext_noop("compute baseline CPU")},
    {"desc", gettext_noop("Compute baseline CPU for a set of given CPUs.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cpu_baseline[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file containing XML CPU descriptions")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    if (virFileReadAll(from, VIRSH_MAX_XML_FILE, &buffer) < 0)
        return FALSE;

    doc = xmlNewDoc(NULL);
    if (doc == NULL)
        goto no_memory;

    res = xmlParseBalancedChunkMemory(doc, NULL, NULL, 0, buffer, &node_list);
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

    ret = malloc (PATH_MAX);
    if (!ret) {
        vshError(ctl, _("malloc: failed to allocate temporary file name: %s"),
                 strerror(errno));
        return NULL;
    }

    tmpdir = getenv ("TMPDIR");
    if (!tmpdir) tmpdir = "/tmp";
    snprintf (ret, PATH_MAX, "%s/virshXXXXXX", tmpdir);
    fd = mkstemp (ret);
    if (fd == -1) {
        vshError(ctl, _("mkstemp: failed to create temporary file: %s"),
                 strerror(errno));
        VIR_FREE(ret);
        return NULL;
    }

    if (safewrite (fd, doc, strlen (doc)) == -1) {
        vshError(ctl, _("write: %s: failed to write to temporary file: %s"),
                 ret, strerror(errno));
        close (fd);
        unlink (ret);
        VIR_FREE(ret);
        return NULL;
    }
    if (close (fd) == -1) {
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

    editor = getenv ("EDITOR");
    if (!editor) editor = "vi"; /* could be cruel & default to ed(1) here */

    /* Check the editor doesn't contain shell meta-characters, and if
     * it does, refuse to run.
     */
    if (strspn (editor, ACCEPTED_CHARS) != strlen (editor)) {
        vshError(ctl,
                 _("%s: $EDITOR environment variable contains shell meta or "
                   "other unacceptable characters"),
                 editor);
        return -1;
    }
    /* Same for the filename. */
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
    if (command_ret != WEXITSTATUS (0)) {
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
    {"help", gettext_noop("change the current directory")},
    {"desc", gettext_noop("Change the current directory.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_cd[] = {
    {"dir", VSH_OT_DATA, 0, gettext_noop("directory to switch to (default: home or else root)")},
    {NULL, 0, 0, NULL}
};

static int
cmdCd(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    const char *dir;
    int found;

    if (!ctl->imode) {
        vshError(ctl, "%s", _("cd: command valid only in interactive mode"));
        return -1;
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
        return -1;
    }

    return 0;
}

#endif

#ifndef WIN32
/*
 * "pwd" command
 */
static const vshCmdInfo info_pwd[] = {
    {"help", gettext_noop("print the current directory")},
    {"desc", gettext_noop("Print the current directory.")},
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
 * "edit" command
 */
static const vshCmdInfo info_edit[] = {
    {"help", gettext_noop("edit XML configuration for a domain")},
    {"desc", gettext_noop("Edit the XML configuration for a domain.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_edit[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
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

    unlink (tmp);
    tmp = NULL;

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
    {"help", gettext_noop("edit XML configuration for a network")},
    {"desc", gettext_noop("Edit the XML configuration for a network.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_network_edit[] = {
    {"network", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("network name, id or uuid")},
    {NULL, 0, 0, NULL}
};

/* This is generated from this file by a sed script in the Makefile. */
#include "virsh-net-edit.c"

/*
 * "pool-edit" command
 */
static const vshCmdInfo info_pool_edit[] = {
    {"help", gettext_noop("edit XML configuration for a storage pool")},
    {"desc", gettext_noop("Edit the XML configuration for a storage pool.")},
    {NULL, NULL}
};

static const vshCmdOptDef opts_pool_edit[] = {
    {"pool", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("pool name or uuid")},
    {NULL, 0, 0, NULL}
};

/* This is generated from this file by a sed script in the Makefile. */
#include "virsh-pool-edit.c"

/*
 * "quit" command
 */
static const vshCmdInfo info_quit[] = {
    {"help", gettext_noop("quit this interactive terminal")},
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
 * Commands
 */
static const vshCmdDef commands[] = {
    {"help", cmdHelp, opts_help, info_help},
    {"attach-device", cmdAttachDevice, opts_attach_device, info_attach_device},
    {"attach-disk", cmdAttachDisk, opts_attach_disk, info_attach_disk},
    {"attach-interface", cmdAttachInterface, opts_attach_interface, info_attach_interface},
    {"autostart", cmdAutostart, opts_autostart, info_autostart},
    {"capabilities", cmdCapabilities, NULL, info_capabilities},
#ifndef WIN32
    {"cd", cmdCd, opts_cd, info_cd},
#endif
    {"connect", cmdConnect, opts_connect, info_connect},
#ifndef WIN32
    {"console", cmdConsole, opts_console, info_console},
#endif
    {"cpu-baseline", cmdCPUBaseline, opts_cpu_baseline, info_cpu_baseline},
    {"cpu-compare", cmdCPUCompare, opts_cpu_compare, info_cpu_compare},
    {"create", cmdCreate, opts_create, info_create},
    {"start", cmdStart, opts_start, info_start},
    {"destroy", cmdDestroy, opts_destroy, info_destroy},
    {"detach-device", cmdDetachDevice, opts_detach_device, info_detach_device},
    {"detach-disk", cmdDetachDisk, opts_detach_disk, info_detach_disk},
    {"detach-interface", cmdDetachInterface, opts_detach_interface, info_detach_interface},
    {"define", cmdDefine, opts_define, info_define},
    {"domid", cmdDomid, opts_domid, info_domid},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo},
    {"domjobinfo", cmdDomjobinfo, opts_domjobinfo, info_domjobinfo},
    {"domjobabort", cmdDomjobabort, opts_domjobabort, info_domjobabort},
    {"domname", cmdDomname, opts_domname, info_domname},
    {"domstate", cmdDomstate, opts_domstate, info_domstate},
    {"domblkstat", cmdDomblkstat, opts_domblkstat, info_domblkstat},
    {"domifstat", cmdDomIfstat, opts_domifstat, info_domifstat},
    {"dommemstat", cmdDomMemStat, opts_dommemstat, info_dommemstat},
    {"domxml-from-native", cmdDomXMLFromNative, opts_domxmlfromnative, info_domxmlfromnative},
    {"domxml-to-native", cmdDomXMLToNative, opts_domxmltonative, info_domxmltonative},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml},
    {"edit", cmdEdit, opts_edit, info_edit},
    {"find-storage-pool-sources", cmdPoolDiscoverSources,
     opts_find_storage_pool_sources, info_find_storage_pool_sources},
    {"find-storage-pool-sources-as", cmdPoolDiscoverSourcesAs,
     opts_find_storage_pool_sources_as, info_find_storage_pool_sources_as},
    {"freecell", cmdFreecell, opts_freecell, info_freecell},
    {"hostname", cmdHostname, NULL, info_hostname},
    {"list", cmdList, opts_list, info_list},
    {"migrate", cmdMigrate, opts_migrate, info_migrate},

    {"net-autostart", cmdNetworkAutostart, opts_network_autostart, info_network_autostart},
    {"net-create", cmdNetworkCreate, opts_network_create, info_network_create},
    {"net-define", cmdNetworkDefine, opts_network_define, info_network_define},
    {"net-destroy", cmdNetworkDestroy, opts_network_destroy, info_network_destroy},
    {"net-dumpxml", cmdNetworkDumpXML, opts_network_dumpxml, info_network_dumpxml},
    {"net-edit", cmdNetworkEdit, opts_network_edit, info_network_edit},
    {"net-list", cmdNetworkList, opts_network_list, info_network_list},
    {"net-name", cmdNetworkName, opts_network_name, info_network_name},
    {"net-start", cmdNetworkStart, opts_network_start, info_network_start},
    {"net-undefine", cmdNetworkUndefine, opts_network_undefine, info_network_undefine},
    {"net-uuid", cmdNetworkUuid, opts_network_uuid, info_network_uuid},

    {"iface-list", cmdInterfaceList, opts_interface_list, info_interface_list},
    {"iface-name", cmdInterfaceName, opts_interface_name, info_interface_name},
    {"iface-mac", cmdInterfaceMAC, opts_interface_mac, info_interface_mac},
    {"iface-dumpxml", cmdInterfaceDumpXML, opts_interface_dumpxml, info_interface_dumpxml},
    {"iface-define", cmdInterfaceDefine, opts_interface_define, info_interface_define},
    {"iface-undefine", cmdInterfaceUndefine, opts_interface_undefine, info_interface_undefine},
    {"iface-edit", cmdInterfaceEdit, opts_interface_edit, info_interface_edit},
    {"iface-start", cmdInterfaceStart, opts_interface_start, info_interface_start},
    {"iface-destroy", cmdInterfaceDestroy, opts_interface_destroy, info_interface_destroy},

    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo},

    {"nodedev-list", cmdNodeListDevices, opts_node_list_devices, info_node_list_devices},
    {"nodedev-dumpxml", cmdNodeDeviceDumpXML, opts_node_device_dumpxml, info_node_device_dumpxml},
    {"nodedev-dettach", cmdNodeDeviceDettach, opts_node_device_dettach, info_node_device_dettach},
    {"nodedev-reattach", cmdNodeDeviceReAttach, opts_node_device_reattach, info_node_device_reattach},
    {"nodedev-reset", cmdNodeDeviceReset, opts_node_device_reset, info_node_device_reset},
    {"nodedev-create", cmdNodeDeviceCreate, opts_node_device_create, info_node_device_create},
    {"nodedev-destroy", cmdNodeDeviceDestroy, opts_node_device_destroy, info_node_device_destroy},

    {"pool-autostart", cmdPoolAutostart, opts_pool_autostart, info_pool_autostart},
    {"pool-build", cmdPoolBuild, opts_pool_build, info_pool_build},
    {"pool-create", cmdPoolCreate, opts_pool_create, info_pool_create},
    {"pool-create-as", cmdPoolCreateAs, opts_pool_X_as, info_pool_create_as},
    {"pool-define", cmdPoolDefine, opts_pool_define, info_pool_define},
    {"pool-define-as", cmdPoolDefineAs, opts_pool_X_as, info_pool_define_as},
    {"pool-destroy", cmdPoolDestroy, opts_pool_destroy, info_pool_destroy},
    {"pool-delete", cmdPoolDelete, opts_pool_delete, info_pool_delete},
    {"pool-dumpxml", cmdPoolDumpXML, opts_pool_dumpxml, info_pool_dumpxml},
    {"pool-edit", cmdPoolEdit, opts_pool_edit, info_pool_edit},
    {"pool-info", cmdPoolInfo, opts_pool_info, info_pool_info},
    {"pool-list", cmdPoolList, opts_pool_list, info_pool_list},
    {"pool-name", cmdPoolName, opts_pool_name, info_pool_name},
    {"pool-refresh", cmdPoolRefresh, opts_pool_refresh, info_pool_refresh},
    {"pool-start", cmdPoolStart, opts_pool_start, info_pool_start},
    {"pool-undefine", cmdPoolUndefine, opts_pool_undefine, info_pool_undefine},
    {"pool-uuid", cmdPoolUuid, opts_pool_uuid, info_pool_uuid},

    {"secret-define", cmdSecretDefine, opts_secret_define, info_secret_define},
    {"secret-dumpxml", cmdSecretDumpXML, opts_secret_dumpxml, info_secret_dumpxml},
    {"secret-set-value", cmdSecretSetValue, opts_secret_set_value, info_secret_set_value},
    {"secret-get-value", cmdSecretGetValue, opts_secret_get_value, info_secret_get_value},
    {"secret-undefine", cmdSecretUndefine, opts_secret_undefine, info_secret_undefine},
    {"secret-list", cmdSecretList, NULL, info_secret_list},


#ifndef WIN32
    {"pwd", cmdPwd, NULL, info_pwd},
#endif
    {"quit", cmdQuit, NULL, info_quit},
    {"reboot", cmdReboot, opts_reboot, info_reboot},
    {"restore", cmdRestore, opts_restore, info_restore},
    {"resume", cmdResume, opts_resume, info_resume},
    {"save", cmdSave, opts_save, info_save},
    {"schedinfo", cmdSchedinfo, opts_schedinfo, info_schedinfo},
    {"dump", cmdDump, opts_dump, info_dump},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown},
    {"setmem", cmdSetmem, opts_setmem, info_setmem},
    {"setmaxmem", cmdSetmaxmem, opts_setmaxmem, info_setmaxmem},
    {"setvcpus", cmdSetvcpus, opts_setvcpus, info_setvcpus},
    {"suspend", cmdSuspend, opts_suspend, info_suspend},
    {"ttyconsole", cmdTTYConsole, opts_ttyconsole, info_ttyconsole},
    {"undefine", cmdUndefine, opts_undefine, info_undefine},
    {"uri", cmdURI, NULL, info_uri},

    {"vol-create", cmdVolCreate, opts_vol_create, info_vol_create},
    {"vol-create-from", cmdVolCreateFrom, opts_vol_create_from, info_vol_create_from},
    {"vol-create-as", cmdVolCreateAs, opts_vol_create_as, info_vol_create_as},
    {"vol-clone", cmdVolClone, opts_vol_clone, info_vol_clone},
    {"vol-delete", cmdVolDelete, opts_vol_delete, info_vol_delete},
    {"vol-dumpxml", cmdVolDumpXML, opts_vol_dumpxml, info_vol_dumpxml},
    {"vol-info", cmdVolInfo, opts_vol_info, info_vol_info},
    {"vol-list", cmdVolList, opts_vol_list, info_vol_list},
    {"vol-path", cmdVolPath, opts_vol_path, info_vol_path},
    {"vol-name", cmdVolName, opts_vol_name, info_vol_name},
    {"vol-key", cmdVolKey, opts_vol_key, info_vol_key},

    {"vcpuinfo", cmdVcpuinfo, opts_vcpuinfo, info_vcpuinfo},
    {"vcpupin", cmdVcpupin, opts_vcpupin, info_vcpupin},
    {"version", cmdVersion, NULL, info_version},
    {"vncdisplay", cmdVNCDisplay, opts_vncdisplay, info_vncdisplay},
    {NULL, NULL, NULL, NULL}
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
        if (opt->type == VSH_OT_DATA) {
            if (data_ct == 0)
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
    const vshCmdDef *c;

    for (c = commands; c->name; c++)
        if (STREQ(c->name, cmdname))
            return c;
    return NULL;
}

static int
vshCmddefHelp(vshControl *ctl, const char *cmdname)
{
    const vshCmdDef *def = vshCmddefSearch(cmdname);

    if (!def) {
        vshError(ctl, _("command '%s' doesn't exist"), cmdname);
        return FALSE;
    } else {
        const char *desc = N_(vshCmddefGetInfo(def, "desc"));
        const char *help = N_(vshCmddefGetInfo(def, "help"));
        char buf[256];

        fputs(_("  NAME\n"), stdout);
        fprintf(stdout, "    %s - %s\n", def->name, help);

        fputs(_("\n  SYNOPSIS\n"), stdout);
        fprintf(stdout, "    %s", def->name);
        if (def->opts) {
            const vshCmdOptDef *opt;
            for (opt = def->opts; opt->name; opt++) {
                const char *fmt;
                if (opt->type == VSH_OT_BOOL)
                    fmt = "[--%s]";
                else if (opt->type == VSH_OT_INT)
                    fmt = N_("[--%s <number>]");
                else if (opt->type == VSH_OT_STRING)
                    fmt = N_("[--%s <string>]");
                else if (opt->type == VSH_OT_DATA)
                    fmt = ((opt->flag & VSH_OFLAG_REQ) ? "<%s>" : "[<%s>]");
                else
                    assert(0);
                fputc(' ', stdout);
                fprintf(stdout, _(fmt), opt->name);
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
                if (opt->type == VSH_OT_BOOL)
                    snprintf(buf, sizeof(buf), "--%s", opt->name);
                else if (opt->type == VSH_OT_INT)
                    snprintf(buf, sizeof(buf), _("--%s <number>"), opt->name);
                else if (opt->type == VSH_OT_STRING)
                    snprintf(buf, sizeof(buf), _("--%s <string>"), opt->name);
                else if (opt->type == VSH_OT_DATA)
                    snprintf(buf, sizeof(buf), "<%s>", opt->name);

                fprintf(stdout, "    %-15s  %s\n", buf, N_(opt->help));
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

/*
 * Returns option as STRING
 */
static char *
vshCommandOptString(const vshCmd *cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);

    if (found)
        *found = arg ? TRUE : FALSE;

    return arg && arg->data && *arg->data ? arg->data : NULL;
}

#if 0
static int
vshCommandOptStringList(const vshCmd *cmd, const char *name, char ***data)
{
    vshCmdOpt *arg = cmd->opts;
    char **val = NULL;
    int nval = 0;

    while (arg) {
        if (arg->def && STREQ(arg->def->name, name)) {
            char **tmp = realloc(val, sizeof(*tmp) * (nval+1));
            if (!tmp) {
                VIR_FREE(val);
                return -1;
            }
            val = tmp;
            val[nval++] = arg->data;
        }
        arg = arg->next;
    }

    *data = val;
    return nval;
}
#endif

/*
 * Returns TRUE/FALSE if the option exists
 */
static int
vshCommandOptBool(const vshCmd *cmd, const char *name)
{
    return vshCommandOpt(cmd, name) ? TRUE : FALSE;
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

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, "%s", _("undefined domain name or id"));
        return NULL;
    }

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

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, "%s", _("undefined network name"));
        return NULL;
    }

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

static virInterfacePtr
vshCommandOptInterfaceBy(vshControl *ctl, const vshCmd *cmd,
                         char **name, int flag)
{
    virInterfacePtr iface = NULL;
    char *n;
    const char *optname = "interface";
    if (!cmd_has_option (ctl, cmd, optname))
        return NULL;

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, "%s", _("undefined interface identifier"));
        return NULL;
    }

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

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, "%s", _("undefined pool name"));
        return NULL;
    }

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

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, "%s", _("undefined vol name"));
        return NULL;
    }

    if (!(p = vshCommandOptString(cmd, pooloptname, &found)) && found) {
        vshError(ctl, "%s", _("undefined pool name"));
        return NULL;
    }

    if (p)
        pool = vshCommandOptPoolBy(ctl, cmd, pooloptname, name, flag);

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by PATH */
    if (pool && (flag & VSH_BYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> trying as vol UUID\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByName(pool, n);
    }
    if (vol == NULL && (flag & VSH_BYUUID)) {
        vshDebug(ctl, 5, "%s: <%s> trying as vol key\n",
                 cmd->def->name, optname);
        vol = virStorageVolLookupByKey(ctl->conn, n);
    }
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
    if (n == NULL) {
        vshError(ctl, "%s", _("undefined secret UUID"));
        return NULL;
    }

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

        if (ctl->timing)
            GETTIMEOFDAY(&before);

        ret = cmd->def->handler(ctl, cmd);

        if (ctl->timing)
            GETTIMEOFDAY(&after);

        if (ret == FALSE)
            virshReportError(ctl);

        if (STREQ(cmd->def->name, "quit"))        /* hack ... */
            return ret;

        if (ctl->timing)
            vshPrint(ctl, _("\n(Time: %.3f ms)\n\n"),
                     DIFF_MSEC(&after, &before));
        else
            vshPrintExtra(ctl, "\n");
        cmd = cmd->next;
    }
    return ret;
}

/* ---------------
 * Command string parsing
 * ---------------
 */
#define VSH_TK_ERROR    -1
#define VSH_TK_NONE    0
#define VSH_TK_OPTION    1
#define VSH_TK_DATA    2
#define VSH_TK_END    3

static int
vshCommandGetToken(vshControl *ctl, char *str, char **end, char **res)
{
    int tk = VSH_TK_NONE;
    int quote = FALSE;
    int sz = 0;
    char *p = str;
    char *tkstr = NULL;

    *end = NULL;

    while (p && *p && (*p == ' ' || *p == '\t'))
        p++;

    if (p == NULL || *p == '\0')
        return VSH_TK_END;
    if (*p == ';') {
        *end = ++p;             /* = \0 or begin of next command */
        return VSH_TK_END;
    }
    while (*p) {
        /* end of token is blank space or ';' */
        if ((quote == FALSE && (*p == ' ' || *p == '\t')) || *p == ';')
            break;

        /* end of option name could be '=' */
        if (tk == VSH_TK_OPTION && *p == '=') {
            p++;                /* skip '=' */
            break;
        }

        if (tk == VSH_TK_NONE) {
            if (*p == '-' && *(p + 1) == '-' && *(p + 2)
                && c_isalnum(*(p + 2))) {
                tk = VSH_TK_OPTION;
                p += 2;
            } else {
                tk = VSH_TK_DATA;
                if (*p == '"') {
                    quote = TRUE;
                    p++;
                } else {
                    quote = FALSE;
                }
            }
            tkstr = p;          /* begin of token */
        } else if (quote && *p == '"') {
            quote = FALSE;
            p++;
            break;              /* end of "..." token */
        }
        p++;
        sz++;
    }
    if (quote) {
        vshError(ctl, "%s", _("missing \""));
        return VSH_TK_ERROR;
    }
    if (tkstr == NULL || *tkstr == '\0' || p == NULL)
        return VSH_TK_END;
    if (sz == 0)
        return VSH_TK_END;

    *res = vshMalloc(ctl, sz + 1);
    memcpy(*res, tkstr, sz);
    *(*res + sz) = '\0';

    *end = p;
    return tk;
}

static int
vshCommandParse(vshControl *ctl, char *cmdstr)
{
    char *str;
    char *tkdata = NULL;
    vshCmd *clast = NULL;
    vshCmdOpt *first = NULL;

    if (ctl->cmd) {
        vshCommandFree(ctl->cmd);
        ctl->cmd = NULL;
    }

    if (cmdstr == NULL || *cmdstr == '\0')
        return FALSE;

    str = cmdstr;
    while (str && *str) {
        vshCmdOpt *last = NULL;
        const vshCmdDef *cmd = NULL;
        int tk = VSH_TK_NONE;
        int data_ct = 0;

        first = NULL;

        while (tk != VSH_TK_END) {
            char *end = NULL;
            const vshCmdOptDef *opt = NULL;

            tkdata = NULL;

            /* get token */
            tk = vshCommandGetToken(ctl, str, &end, &tkdata);

            str = end;

            if (tk == VSH_TK_END) {
                VIR_FREE(tkdata);
                break;
            }
            if (tk == VSH_TK_ERROR)
                goto syntaxError;

            if (cmd == NULL) {
                /* first token must be command name */
                if (tk != VSH_TK_DATA) {
                    vshError(ctl,
                             _("unexpected token (command name): '%s'"),
                             tkdata);
                    goto syntaxError;
                }
                if (!(cmd = vshCmddefSearch(tkdata))) {
                    vshError(ctl, _("unknown command: '%s'"), tkdata);
                    goto syntaxError;   /* ... or ignore this command only? */
                }
                VIR_FREE(tkdata);
            } else if (tk == VSH_TK_OPTION) {
                if (!(opt = vshCmddefGetOption(cmd, tkdata))) {
                    vshError(ctl,
                             _("command '%s' doesn't support option --%s"),
                             cmd->name, tkdata);
                    goto syntaxError;
                }
                VIR_FREE(tkdata);   /* option name */

                if (opt->type != VSH_OT_BOOL) {
                    /* option data */
                    tk = vshCommandGetToken(ctl, str, &end, &tkdata);
                    str = end;
                    if (tk == VSH_TK_ERROR)
                        goto syntaxError;
                    if (tk != VSH_TK_DATA) {
                        vshError(ctl,
                                 _("expected syntax: --%s <%s>"),
                                 opt->name,
                                 opt->type ==
                                 VSH_OT_INT ? _("number") : _("string"));
                        goto syntaxError;
                    }
                }
            } else if (tk == VSH_TK_DATA) {
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
                         tk == VSH_TK_OPTION ? _("OPTION") : _("DATA"),
                         arg->data);
            }
            if (!str)
                break;
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
    }

    return TRUE;

 syntaxError:
    if (ctl->cmd)
        vshCommandFree(ctl->cmd);
    if (first)
        vshCommandOptFree(first);
    VIR_FREE(tkdata);
    return FALSE;
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
        return gettext_noop("running");
    case VIR_DOMAIN_BLOCKED:
        return gettext_noop("idle");
    case VIR_DOMAIN_PAUSED:
        return gettext_noop("paused");
    case VIR_DOMAIN_SHUTDOWN:
        return gettext_noop("in shutdown");
    case VIR_DOMAIN_SHUTOFF:
        return gettext_noop("shut off");
    case VIR_DOMAIN_CRASHED:
        return gettext_noop("crashed");
    default:
        ;/*FALLTHROUGH*/
    }
    return gettext_noop("no state");  /* = dom0 state */
}

static const char *
vshDomainVcpuStateToString(int state)
{
    switch (state) {
    case VIR_VCPU_OFFLINE:
        return gettext_noop("offline");
    case VIR_VCPU_BLOCKED:
        return gettext_noop("idle");
    case VIR_VCPU_RUNNING:
        return gettext_noop("running");
    default:
        ;/*FALLTHROUGH*/
    }
    return gettext_noop("no state");
}

static int
vshConnectionUsability(vshControl *ctl, virConnectPtr conn, int showerror)
{
    /* TODO: use something like virConnectionState() to
     *       check usability of the connection
     */
    if (!conn) {
        if (showerror)
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

    va_start(ap, format);
    vshOutputLogFile(ctl, VSH_ERR_ERROR, format, ap);
    va_end(ap);

    fputs(_("error: "), stderr);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);
}

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

#ifndef O_SYNC
#define O_SYNC 0
#endif
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
    if (ctl->log_fd >= 0) {
        if (close(ctl->log_fd) < 0)
            vshError(ctl, _("%s: failed to write log file: %s"),
                     ctl->logfile ? ctl->logfile : "?", strerror (errno));
        ctl->log_fd = -1;
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
    static int list_index, len;
    const char *name;

    /* If this is a new word to complete, initialize now.  This
     * includes saving the length of TEXT for efficiency, and
     * initializing the index variable to 0.
     */
    if (!state) {
        list_index = 0;
        len = strlen(text);
    }

    /* Return the next name which partially matches from the
     * command list.
     */
    while ((name = commands[list_index].name)) {
        list_index++;
        if (STREQLEN(name, text, len))
            return vshStrdup(NULL, name);
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
        if (virConnectClose(ctl->conn) != 0) {
            vshError(ctl, "%s", _("failed to disconnect from the hypervisor"));
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
    const vshCmdDef *cmd;
    fprintf(stdout, _("\n%s [options] [commands]\n\n"
                      "  options:\n"
                      "    -c | --connect <uri>    hypervisor connection URI\n"
                      "    -r | --readonly         connect readonly\n"
                      "    -d | --debug <num>      debug level [0-5]\n"
                      "    -h | --help             this help\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -t | --timing           print timing information\n"
                      "    -l | --log <file>       output logging to file\n"
                      "    -v | --version          program version\n\n"
                      "  commands (non interactive mode):\n"), progname);

    for (cmd = commands; cmd->name; cmd++)
        fprintf(stdout,
                "    %-15s %s\n", cmd->name, N_(vshCmddefGetInfo(cmd,
                                                                 "help")));

    fprintf(stdout, "%s",
            _("\n  (specify help <command> for details about the command)\n\n"));
    return;
}

/*
 * argv[]:  virsh [options] [command]
 *
 */
static int
vshParseArgv(vshControl *ctl, int argc, char **argv)
{
    char *last = NULL;
    int i, end = 0, help = 0;
    int arg, idx = 0;
    struct option opt[] = {
        {"debug", 1, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"quiet", 0, 0, 'q'},
        {"timing", 0, 0, 't'},
        {"version", 0, 0, 'v'},
        {"connect", 1, 0, 'c'},
        {"readonly", 0, 0, 'r'},
        {"log", 1, 0, 'l'},
        {0, 0, 0, 0}
    };


    if (argc < 2)
        return TRUE;

    /* look for begin of the command, for example:
     *   ./virsh --debug 5 -q command --cmdoption
     *                  <--- ^ --->
     *        getopt() stuff | command suff
     */
    for (i = 1; i < argc; i++) {
        if (*argv[i] != '-') {
            int valid = FALSE;

            /* non "--option" argv, is it command? */
            if (last) {
                struct option *o;
                int sz = strlen(last);

                for (o = opt; o->name; o++) {
                    if (o->has_arg == 1){
                        if (sz == 2 && *(last + 1) == o->val)
                            /* valid virsh short option */
                            valid = TRUE;
                        else if (sz > 2 && STREQ(o->name, last + 2))
                            /* valid virsh long option */
                            valid = TRUE;
                    }
                }
            }
            if (!valid) {
                end = i;
                break;
            }
        }
        last = argv[i];
    }
    end = end ? end : argc;

    /* standard (non-command) options */
    while ((arg = getopt_long(end, argv, "d:hqtc:vrl:", opt, &idx)) != -1) {
        switch (arg) {
        case 'd':
            ctl->debug = atoi(optarg);
            break;
        case 'h':
            help = 1;
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
            fprintf(stdout, "%s\n", VERSION);
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
        if (end < argc) {
            vshError(ctl, _("extra argument '%s'. See --help."), argv[end]);
            exit(EXIT_FAILURE);
        }

        /* list all command */
        vshUsage();
        exit(EXIT_SUCCESS);
    }

    if (argc > end) {
        /* parse command */
        char *cmdstr;
        int sz = 0, ret;

        ctl->imode = FALSE;

        for (i = end; i < argc; i++)
            sz += strlen(argv[i]) + 1;  /* +1 is for blank space between items */

        cmdstr = vshCalloc(ctl, sz + 1, 1);

        for (i = end; i < argc; i++) {
            strncat(cmdstr, argv[i], sz);
            sz -= strlen(argv[i]);
            strncat(cmdstr, " ", sz--);
        }
        vshDebug(ctl, 2, "command: \"%s\"\n", cmdstr);
        ret = vshCommandParse(ctl, cmdstr);

        VIR_FREE(cmdstr);
        return ret;
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
    if (!bindtextdomain(GETTEXT_PACKAGE, LOCALEBASEDIR)) {
        perror("bindtextdomain");
        return -1;
    }
    if (!textdomain(GETTEXT_PACKAGE)) {
        perror("textdomain");
        return -1;
    }

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    memset(ctl, 0, sizeof(vshControl));
    ctl->imode = TRUE;          /* default is interactive mode */
    ctl->log_fd = -1;           /* Initialize log file descriptor */

    if ((defaultConn = getenv("VIRSH_DEFAULT_CONNECT_URI"))) {
        ctl->name = strdup(defaultConn);
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
                if (vshCommandParse(ctl, ctl->cmdstr))
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
