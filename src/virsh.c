/*
 * virsh.c: a Xen shell used to exercise the libvir API
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 * Karel Zak <kzak@redhat.com>
 * Daniel P. Berrange <berrange@redhat.com>
 *
 *
 * $Id$
 */

#define _GNU_SOURCE             /* isblank() */

#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "config.h"
#include "internal.h"

static char *progname;

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define VSH_PROMPT_RW    "virsh # "
#define VSH_PROMPT_RO    "virsh > "

#define GETTIMEOFDAY(T) gettimeofday(T, NULL)
#define DIFF_MSEC(T, U) \
        ((((int) ((T)->tv_sec - (U)->tv_sec)) * 1000000.0 + \
          ((int) ((T)->tv_usec - (U)->tv_usec))) / 1000.0)

/*
 * The error handler for virtsh
 */
static void
virshErrorHandler(void *unused, virErrorPtr error)
{
    if ((unused != NULL) || (error == NULL))
        return;

    /* Suppress the VIR_ERR_NO_XEN error which fails as non-root */
    if ((error->code == VIR_ERR_NO_XEN) || (error->code == VIR_ERR_OK))
        return;

    virDefaultErrorFunc(error);
}

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
    vshCmdOptDef *def;          /* pointer to relevant option */
    char *data;                 /* allocated data */
    struct vshCmdOpt *next;
} vshCmdOpt;

/*
 * vshCmdDef - command definition
 */
typedef struct {
    const char *name;
    int (*handler) (vshControl *, vshCmd *);    /* command handler */
    vshCmdOptDef *opts;         /* definition of command options */
    vshCmdInfo *info;           /* details about command */
} vshCmdDef;

/*
 * vshCmd - parsed command
 */
typedef struct __vshCmd {
    vshCmdDef *def;             /* command definition */
    vshCmdOpt *opts;            /* list of command arguments */
    struct __vshCmd *next;      /* next command */
} __vshCmd;

/*
 * vshControl
 */
typedef struct __vshControl {
    char *name;                 /* connection name */
    virConnectPtr conn;         /* connection to hypervisor */
    vshCmd *cmd;                /* the current command */
    char *cmdstr;               /* string with command */
    uid_t uid;                  /* process owner */
    int imode;                  /* interactive mode? */
    int quiet;                  /* quiet mode */
    int debug;                  /* print debug messages? */
    int timing;                 /* print timing info? */
} __vshControl;


static vshCmdDef commands[];

static void vshError(vshControl * ctl, int doexit, const char *format,
                     ...);
static int vshInit(vshControl * ctl);
static int vshDeinit(vshControl * ctl);
static void vshUsage(vshControl * ctl, const char *cmdname);

static int vshParseArgv(vshControl * ctl, int argc, char **argv);

static const char *vshCmddefGetInfo(vshCmdDef * cmd, const char *info);
static vshCmdDef *vshCmddefSearch(const char *cmdname);
static int vshCmddefHelp(vshControl * ctl, const char *name, int withprog);

static vshCmdOpt *vshCommandOpt(vshCmd * cmd, const char *name);
static int vshCommandOptInt(vshCmd * cmd, const char *name, int *found);
static char *vshCommandOptString(vshCmd * cmd, const char *name,
                                 int *found);
static int vshCommandOptBool(vshCmd * cmd, const char *name);

#define VSH_DOMBYID     (1 << 1)
#define VSH_DOMBYUUID   (1 << 2)
#define VSH_DOMBYNAME   (1 << 3)

static virDomainPtr vshCommandOptDomainBy(vshControl * ctl, vshCmd * cmd,
                            const char *optname, char **name, int flag);

/* default is lookup by Id, Name and UUID */
#define vshCommandOptDomain(_ctl, _cmd, _optname, _name) \
                            vshCommandOptDomainBy(_ctl, _cmd, _optname, _name,\
                                        VSH_DOMBYID|VSH_DOMBYUUID|VSH_DOMBYNAME)

static void vshPrintExtra(vshControl * ctl, const char *format, ...);
static void vshDebug(vshControl * ctl, int level, const char *format, ...);

/* XXX: add batch support */
#define vshPrint(_ctl, ...)   fprintf(stdout, __VA_ARGS__)

static const char *vshDomainStateToString(int state);
static int vshConnectionUsability(vshControl * ctl, virConnectPtr conn,
                                  int showerror);

static void *_vshMalloc(vshControl * ctl, size_t sz, const char *filename, int line);
#define vshMalloc(_ctl, _sz)    _vshMalloc(_ctl, _sz, __FILE__, __LINE__)

static void *_vshCalloc(vshControl * ctl, size_t nmemb, size_t sz, const char *filename, int line);
#define vshCalloc(_ctl, _nmemb, _sz)    _vshCalloc(_ctl, _nmemb, _sz, __FILE__, __LINE__)

static char *_vshStrdup(vshControl * ctl, const char *s, const char *filename, int line);
#define vshStrdup(_ctl, _s)    _vshStrdup(_ctl, _s, __FILE__, __LINE__)

/* ---------------
 * Commands
 * ---------------
 */

/*
 * "help" command 
 */
static vshCmdInfo info_help[] = {
    {"syntax", "help [<command>]"},
    {"help", "print help"},
    {"desc", "Prints global help or command specific help."},
    {"version", "Prints version information."},
    {NULL, NULL}
};

static vshCmdOptDef opts_help[] = {
    {"command", VSH_OT_DATA, 0, "name of command"},
    {NULL, 0, 0, NULL}
};

static int
cmdHelp(vshControl * ctl, vshCmd * cmd)
{
    const char *cmdname = vshCommandOptString(cmd, "command", NULL);

    if (!cmdname) {
        vshCmdDef *def;

        vshPrint(ctl, "Commands:\n\n");
        for (def = commands; def->name; def++)
            vshPrint(ctl, "    %-15s %s\n", def->name,
                     vshCmddefGetInfo(def, "help"));
        return TRUE;
    }
    return vshCmddefHelp(ctl, cmdname, FALSE);
}

/*
 * "connect" command 
 */
static vshCmdInfo info_connect[] = {
    {"syntax", "connect [name] [--readonly]"},
    {"help", "(re)connect to hypervisor"},
    {"desc",
     "Connect to local hypervisor. This is build-in command after shell start up."},
    {NULL, NULL}
};

static vshCmdOptDef opts_connect[] = {
    {"name",     VSH_OT_DATA, 0, "optional argument currently unused (or used for tests only)"},
    {"readonly", VSH_OT_BOOL, 0, "read-only connection"},
    {NULL, 0, 0, NULL}
};

static int
cmdConnect(vshControl * ctl, vshCmd * cmd)
{
    int ro = vshCommandOptBool(cmd, "readonly");
    
    if (ctl->conn) {
        if (virConnectClose(ctl->conn) != 0) {
            vshError(ctl, FALSE,
                     "failed to disconnect from the hypervisor");
            return FALSE;
        }
        ctl->conn = NULL;
    }
    
    if (ctl->name)
        free(ctl->name);
    ctl->name = vshCommandOptString(cmd, "name", NULL);

    if (!ro)
        ctl->conn = virConnectOpen(ctl->name);
    else
        ctl->conn = virConnectOpenReadOnly(ctl->name);

    if (!ctl->conn)
        vshError(ctl, FALSE, "failed to connect to the hypervisor");

    return ctl->conn ? TRUE : FALSE;
}

/*
 * "list" command
 */
static vshCmdInfo info_list[] = {
    {"syntax", "list"},
    {"help", "list domains"},
    {"desc", "Returns list of domains."},
    {NULL, NULL}
};



static int
cmdList(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
{
    int *ids, maxid, i;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    maxid = virConnectNumOfDomains(ctl->conn);
    if (maxid <= 0) {
        /* strange, there should be at least dom0... */
        vshError(ctl, FALSE, "failed to list active domains.");
        return FALSE;
    }
    ids = vshMalloc(ctl, sizeof(int) * maxid);

    virConnectListDomains(ctl->conn, &ids[0], maxid);

    vshPrintExtra(ctl, "%3s %-20s %s\n", "Id", "Name", "State");
    vshPrintExtra(ctl, "----------------------------------\n");

    for (i = 0; i < maxid; i++) {
        int ret;
        virDomainInfo info;
        virDomainPtr dom = virDomainLookupByID(ctl->conn, ids[i]);

        /* this kind of work with domains is not atomic operation */
        if (!dom)
            continue;
        ret = virDomainGetInfo(dom, &info);

        vshPrint(ctl, "%3d %-20s %s\n",
                 virDomainGetID(dom),
                 virDomainGetName(dom),
                 ret <
                 0 ? "no state" : vshDomainStateToString(info.state));
        virDomainFree(dom);
    }
    free(ids);
    return TRUE;
}

/*
 * "domstate" command
 */
static vshCmdInfo info_domstate[] = {
    {"syntax", "domstate <domain>"},
    {"help", "domain state"},
    {"desc", "Returns state about a running domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_domstate[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDomstate(vshControl * ctl, vshCmd * cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    if (virDomainGetInfo(dom, &info) == 0)
        vshPrint(ctl, "%s\n",
                 vshDomainStateToString(info.state));
    else
        ret = FALSE;

    virDomainFree(dom);
    return ret;
}

/*
 * "suspend" command
 */
static vshCmdInfo info_suspend[] = {
    {"syntax", "suspend <domain>"},
    {"help", "suspend a domain"},
    {"desc", "Suspend a running domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdSuspend(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *name;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainSuspend(dom) == 0) {
        vshPrint(ctl, "Domain %s suspended\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to suspend domain\n");
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "create" command
 */
static vshCmdInfo info_create[] = {
    {"syntax", "create a domain from an XML <file>"},
    {"help", "create a domain from an XML file"},
    {"desc", "Create a domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, "file conatining an XML domain description"},
    {NULL, 0, 0, NULL}
};

static int
cmdCreate(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *from;
    int found;
    int ret = TRUE;
    char buffer[4096];
    int fd, l;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    fd = open(from, O_RDONLY);
    if (fd < 0) {
        vshError(ctl, FALSE, "Failed to read description file %s\n", from);
        return(FALSE);
    }
    l = read(fd, &buffer[0], sizeof(buffer));
    if ((l <= 0) || (l >= (int) sizeof(buffer))) {
        vshError(ctl, FALSE, "Failed to read description file %s\n", from);
        close(fd);
        return(FALSE);
    }
    buffer[l] = 0;
    dom = virDomainCreateLinux(ctl->conn, &buffer[0], 0);
    if (dom != NULL) {
        vshPrint(ctl, "Domain %s created from %s\n", 
                 virDomainGetName(dom), from);
    } else {
        vshError(ctl, FALSE, "Failed to create domain\n");
        ret = FALSE;
    }
    return ret;
}

/*
 * "save" command
 */
static vshCmdInfo info_save[] = {
    {"syntax", "save <domain> <file>"},
    {"help", "save a domain state to a file"},
    {"desc", "Save a running domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_save[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, "where to save the data"},
    {NULL, 0, 0, NULL}
};

static int
cmdSave(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *name;
    char *to;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(to = vshCommandOptString(cmd, "file", NULL)))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainSave(dom, to) == 0) {
        vshPrint(ctl, "Domain %s saved\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to save domain\n");
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "restore" command
 */
static vshCmdInfo info_restore[] = {
    {"syntax", "restore a domain from <file>"},
    {"help", "restore a domain from a saved state in a file"},
    {"desc", "Restore a domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_restore[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, "the state to restore"},
    {NULL, 0, 0, NULL}
};

static int
cmdRestore(vshControl * ctl, vshCmd * cmd)
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
        vshPrint(ctl, "Domain restored from %s\n", from);
    } else {
        vshError(ctl, FALSE, "Failed to restore domain\n");
        ret = FALSE;
    }
    return ret;
}

/*
 * "resume" command
 */
static vshCmdInfo info_resume[] = {
    {"syntax", "resume <domain>"},
    {"help", "resume a domain"},
    {"desc", "Resume a previously suspended domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_resume[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdResume(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainResume(dom) == 0) {
        vshPrint(ctl, "Domain %s resumed\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to resume domain\n");
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "shutdown" command
 */
static vshCmdInfo info_shutdown[] = {
    {"syntax", "shutdown <domain>"},
    {"help", "gracefully shutdown a domain"},
    {"desc", "Run shutdown in the targetted domain"},
    {NULL, NULL}
};

static vshCmdOptDef opts_shutdown[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdShutdown(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainShutdown(dom) == 0) {
        vshPrint(ctl, "Domain %s is being shutdown\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to shutdown domain\n");
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "reboot" command
 */
static vshCmdInfo info_reboot[] = {
    {"syntax", "reboot <domain>"},
    {"help", "reboot a domain"},
    {"desc", "Run a reboot command in the targetted domain"},
    {NULL, NULL}
};

static vshCmdOptDef opts_reboot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdReboot(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainReboot(dom, 0) == 0) {
        vshPrint(ctl, "Domain %s is being rebooted\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to reboot domain\n");
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "destroy" command
 */
static vshCmdInfo info_destroy[] = {
    {"syntax", "destroy <domain>"},
    {"help", "destroy a domain"},
    {"desc", "Destroy a given domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDestroy(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainDestroy(dom) == 0) {
        vshPrint(ctl, "Domain %s destroyed\n", name);
    } else {
        vshError(ctl, FALSE, "Failed to destroy domain\n");
        ret = FALSE;
        virDomainFree(dom);
    }

    return ret;
}

/*
 * "dominfo" command
 */
static vshCmdInfo info_dominfo[] = {
    {"syntax", "dominfo <domain>"},
    {"help", "domain information"},
    {"desc", "Returns basic information about the domain."},
    {NULL, NULL}
};

static vshCmdOptDef opts_dominfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDominfo(vshControl * ctl, vshCmd * cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    int ret = TRUE;
    char *str, uuid[37];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    vshPrint(ctl, "%-15s %d\n", "Id:", virDomainGetID(dom));
    vshPrint(ctl, "%-15s %s\n", "Name:", virDomainGetName(dom));
    if (virDomainGetUUIDString(dom, &uuid[0])==0)
        vshPrint(ctl, "%-15s %s\n", "UUID:", uuid);

    if ((str = virDomainGetOSType(dom))) {
        vshPrint(ctl, "%-15s %s\n", "OS Type:", str);
        free(str);
    }

    if (virDomainGetInfo(dom, &info) == 0) {
        vshPrint(ctl, "%-15s %s\n", "State:",
                 vshDomainStateToString(info.state));

        vshPrint(ctl, "%-15s %d\n", "CPU(s):", info.nrVirtCpu);

        if (info.cpuTime != 0) {
	    double cpuUsed = info.cpuTime;

            cpuUsed /= 1000000000.0;

            vshPrint(ctl, "%-15s %.1lfs\n", "CPU time:", cpuUsed);
        }

        vshPrint(ctl, "%-15s %lu kB\n", "Max memory:",
                 info.maxMem);
        vshPrint(ctl, "%-15s %lu kB\n", "Used memory:",
                 info.memory);

    } else {
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "nodeinfo" command
 */
static vshCmdInfo info_nodeinfo[] = {
    {"syntax", "nodeinfo"},
    {"help", "node information"},
    {"desc", "Returns basic information about the node."},
    {NULL, NULL}
};

static int
cmdNodeinfo(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;
        
    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (virNodeGetInfo(ctl->conn, &info) < 0) {
        vshError(ctl, FALSE, "failed to get node information");
        return FALSE;
    }    
    vshPrint(ctl, "%-20s %s\n", "CPU model:", info.model);
    vshPrint(ctl, "%-20s %d\n", "CPU(s):", info.cpus);
    vshPrint(ctl, "%-20s %d MHz\n", "CPU frequency:", info.mhz);
    vshPrint(ctl, "%-20s %d\n", "CPU socket(s):", info.sockets);
    vshPrint(ctl, "%-20s %d\n", "Core(s) per socket:", info.cores);
    vshPrint(ctl, "%-20s %d\n", "Thread(s) per core:", info.threads);
    vshPrint(ctl, "%-20s %d\n", "NUMA cell(s):", info.nodes);
    vshPrint(ctl, "%-20s %lu kB\n", "Memory size:", info.memory);
        
    return TRUE;
}

/*
 * "dumpxml" command
 */
static vshCmdInfo info_dumpxml[] = {
    {"syntax", "dumpxml <name>"},
    {"help", "domain information in XML"},
    {"desc", "Ouput the domain information as an XML dump to stdout"},
    {NULL, NULL}
};

static vshCmdOptDef opts_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name, id, uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDumpXML(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *dump;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    dump = virDomainGetXMLDesc(dom, 0);
    if (dump != NULL) {
        printf("%s", dump);
        free(dump);
    } else {
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "domname" command
 */
static vshCmdInfo info_domname[] = {
    {"syntax", "domname <domain>"},
    {"help", "convert a domain Id or UUID to domain name"},
    {NULL, NULL}
};

static vshCmdOptDef opts_domname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain id or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDomname(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, "domain", NULL, 
                                    VSH_DOMBYID|VSH_DOMBYUUID)))
        return FALSE;

    vshPrint(ctl, "%s\n", virDomainGetName(dom));
    virDomainFree(dom);
    return TRUE;
}

/*
 * "domid" command
 */
static vshCmdInfo info_domid[] = {
    {"syntax", "domid <domain>"},
    {"help", "convert a domain name or UUID to domain Id"},
    {NULL, NULL}
};

static vshCmdOptDef opts_domid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain name or uuid"},
    {NULL, 0, 0, NULL}
};

static int
cmdDomid(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, "domain", NULL, 
                                    VSH_DOMBYNAME|VSH_DOMBYUUID)))
        return FALSE;
    
    vshPrint(ctl, "%d\n", virDomainGetID(dom));
    virDomainFree(dom);
    return TRUE;
}

/*
 * "domuuid" command
 */
static vshCmdInfo info_domuuid[] = {
    {"syntax", "domuuid <domain>"},
    {"help", "convert a domain name or id to domain UUID"},
    {NULL, NULL}
};

static vshCmdOptDef opts_domuuid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, "domain id or name"},
    {NULL, 0, 0, NULL}
};

static int
cmdDomuuid(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char uuid[37];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, "domain", NULL, 
                                    VSH_DOMBYNAME|VSH_DOMBYID)))
        return FALSE;
    
    if (virDomainGetUUIDString(dom, uuid) != -1)
        vshPrint(ctl, "%s\n", uuid);
    else
        vshError(ctl, FALSE, "failed to get domain UUID");
    
    return TRUE;
}


/*
 * "version" command
 */
static vshCmdInfo info_version[] = {
    {"syntax", "version"},
    {"help", "show versions"},
    {"desc", "Display the version information available"},
    {NULL, NULL}
};


static int
cmdVersion(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
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
        vshError(ctl, FALSE, "failed to get hypervisor type\n");
        return FALSE;
    }

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, "Compiled against library: libvir %d.%d.%d\n",
             major, minor, rel);

    ret = virGetVersion(&libVersion, hvType, &apiVersion);
    if (ret < 0) {
        vshError(ctl, FALSE, "failed to get the library version");
        return FALSE;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, "Using library: libvir %d.%d.%d\n",
             major, minor, rel);

    major = apiVersion / 1000000;
    apiVersion %= 1000000;
    minor = apiVersion / 1000;
    rel = apiVersion % 1000;
    vshPrint(ctl, "Using API: %s %d.%d.%d\n", hvType,
             major, minor, rel);

    ret = virConnectGetVersion(ctl->conn, &hvVersion);
    if (ret < 0) {
        vshError(ctl, FALSE, "failed to get the hypervisor version");
        return FALSE;
    }
    if (hvVersion == 0) {
        vshPrint(ctl,
                 "cannot extract running %s hypervisor version\n", hvType);
    } else {
        major = hvVersion / 1000000;
        hvVersion %= 1000000;
        minor = hvVersion / 1000;
        rel = hvVersion % 1000;

        vshPrint(ctl, "Running hypervisor: %s %d.%d.%d\n",
                 hvType, major, minor, rel);
    }
    return TRUE;
}

/*
 * "quit" command
 */
static vshCmdInfo info_quit[] = {
    {"syntax", "quit"},
    {"help", "quit this interactive terminal"},
    {NULL, NULL}
};

static int
cmdQuit(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
{
    ctl->imode = FALSE;
    return TRUE;
}

/*
 * Commands
 */
static vshCmdDef commands[] = {
    {"connect", cmdConnect, opts_connect, info_connect},
    {"create", cmdCreate, opts_create, info_create},
    {"destroy", cmdDestroy, opts_destroy, info_destroy},
    {"domid", cmdDomid, opts_domid, info_domid},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo},
    {"domname", cmdDomname, opts_domname, info_domname},
    {"domstate", cmdDomstate, opts_domstate, info_domstate},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml},
    {"help", cmdHelp, opts_help, info_help},
    {"list", cmdList, NULL, info_list},
    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo},
    {"quit", cmdQuit, NULL, info_quit},
    {"reboot", cmdReboot, opts_reboot, info_reboot},
    {"restore", cmdRestore, opts_restore, info_restore},
    {"resume", cmdResume, opts_resume, info_resume},
    {"save", cmdSave, opts_save, info_save},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown},
    {"suspend", cmdSuspend, opts_suspend, info_suspend},
    {"version", cmdVersion, NULL, info_version},
    {NULL, NULL, NULL, NULL}
};

/* ---------------
 * Utils for work with command definition
 * ---------------
 */
static const char *
vshCmddefGetInfo(vshCmdDef * cmd, const char *name)
{
    vshCmdInfo *info;

    for (info = cmd->info; info && info->name; info++) {
        if (strcmp(info->name, name) == 0)
            return info->data;
    }
    return NULL;
}

static vshCmdOptDef *
vshCmddefGetOption(vshCmdDef * cmd, const char *name)
{
    vshCmdOptDef *opt;

    for (opt = cmd->opts; opt && opt->name; opt++)
        if (strcmp(opt->name, name) == 0)
            return opt;
    return NULL;
}

static vshCmdOptDef *
vshCmddefGetData(vshCmdDef * cmd, int data_ct)
{
    vshCmdOptDef *opt;

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
vshCommandCheckOpts(vshControl * ctl, vshCmd * cmd)
{
    vshCmdDef *def = cmd->def;
    vshCmdOptDef *d;
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
                vshError(ctl, FALSE,
                         d->type == VSH_OT_DATA ?
                         "command '%s' requires <%s> option" :
                         "command '%s' requires --%s option",
                         def->name, d->name);
                err = 1;
            }

        }
    }
    return !err;
}

static vshCmdDef *
vshCmddefSearch(const char *cmdname)
{
    vshCmdDef *c;

    for (c = commands; c->name; c++)
        if (strcmp(c->name, cmdname) == 0)
            return c;
    return NULL;
}

static int
vshCmddefHelp(vshControl * ctl, const char *cmdname, int withprog)
{
    vshCmdDef *def = vshCmddefSearch(cmdname);

    if (!def) {
        vshError(ctl, FALSE, "command '%s' doesn't exist", cmdname);
        return FALSE;
    } else {
        vshCmdOptDef *opt;
        const char *desc = vshCmddefGetInfo(def, "desc");
        const char *help = vshCmddefGetInfo(def, "help");
        const char *syntax = vshCmddefGetInfo(def, "syntax");

        fputs("  NAME\n", stdout);
        fprintf(stdout, "    %s - %s\n", def->name, help);

        if (syntax) {
            fputs("\n  SYNOPSIS\n", stdout);
            if (!withprog)
                fprintf(stdout, "    %s\n", syntax);
            else
                fprintf(stdout, "    %s %s\n", progname, syntax);
        }
        if (desc) {
            fputs("\n  DESCRIPTION\n", stdout);
            fprintf(stdout, "    %s\n", desc);
        }
        if (def->opts) {
            fputs("\n  OPTIONS\n", stdout);
            for (opt = def->opts; opt->name; opt++) {
                char buf[256];

                if (opt->type == VSH_OT_BOOL)
                    snprintf(buf, sizeof(buf), "--%s", opt->name);
                else if (opt->type == VSH_OT_INT)
                    snprintf(buf, sizeof(buf), "--%s <number>", opt->name);
                else if (opt->type == VSH_OT_STRING)
                    snprintf(buf, sizeof(buf), "--%s <string>", opt->name);
                else if (opt->type == VSH_OT_DATA)
                    snprintf(buf, sizeof(buf), "<%s>", opt->name);

                fprintf(stdout, "    %-15s  %s\n", buf, opt->help);
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

        if (tmp->data)
            free(tmp->data);
        free(tmp);
    }
}

static void
vshCommandFree(vshCmd * cmd)
{
    vshCmd *c = cmd;

    while (c) {
        vshCmd *tmp = c;

        c = c->next;

        if (tmp->opts)
            vshCommandOptFree(tmp->opts);
        free(tmp);
    }
}

/*
 * Returns option by name
 */
static vshCmdOpt *
vshCommandOpt(vshCmd * cmd, const char *name)
{
    vshCmdOpt *opt = cmd->opts;

    while (opt) {
        if (opt->def && strcmp(opt->def->name, name) == 0)
            return opt;
        opt = opt->next;
    }
    return NULL;
}

/*
 * Returns option as INT
 */
static int
vshCommandOptInt(vshCmd * cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);
    int res = 0;

    if (arg)
        res = atoi(arg->data);
    if (found)
        *found = arg ? TRUE : FALSE;
    return res;
}

/*
 * Returns option as STRING
 */
static char *
vshCommandOptString(vshCmd * cmd, const char *name, int *found)
{
    vshCmdOpt *arg = vshCommandOpt(cmd, name);

    if (found)
        *found = arg ? TRUE : FALSE;

    return arg && arg->data && *arg->data ? arg->data : NULL;
}

/*
 * Returns TRUE/FALSE if the option exists
 */
static int
vshCommandOptBool(vshCmd * cmd, const char *name)
{
    return vshCommandOpt(cmd, name) ? TRUE : FALSE;
}


static virDomainPtr
vshCommandOptDomainBy(vshControl * ctl, vshCmd * cmd, const char *optname,
                    char **name, int flag)
{
    virDomainPtr dom = NULL;
    char *n, *end = NULL;
    int id;

    if (!(n = vshCommandOptString(cmd, optname, NULL))) {
        vshError(ctl, FALSE, "undefined domain name or id");
        return NULL;
    }

    vshDebug(ctl, 5, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    /* try it by ID */
    if (flag & VSH_DOMBYID) {
        id = (int) strtol(n, &end, 10);
        if (id >= 0 && end && *end == '\0') {
            vshDebug(ctl, 5, "%s: <%s> seems like domain ID\n",
                     cmd->def->name, optname);
            dom = virDomainLookupByID(ctl->conn, id);
        }
    }
    /* try it by UUID */
    if (dom==NULL && (flag & VSH_DOMBYUUID) && strlen(n)==36) {
        vshDebug(ctl, 5, "%s: <%s> tring as domain UUID\n",
                cmd->def->name, optname);
        dom = virDomainLookupByUUIDString(ctl->conn, n);
    }
    /* try it by NAME */
    if (dom==NULL && (flag & VSH_DOMBYNAME)) {
        vshDebug(ctl, 5, "%s: <%s> tring as domain NAME\n",
                 cmd->def->name, optname);
        dom = virDomainLookupByName(ctl->conn, n);
    }

    if (!dom)
        vshError(ctl, FALSE, "failed to get domain '%s'", n);

    return dom;
}

/*
 * Executes command(s) and returns return code from last command
 */
static int
vshCommandRun(vshControl * ctl, vshCmd * cmd)
{
    int ret = TRUE;

    while (cmd) {
        struct timeval before, after;

        if (ctl->timing)
            GETTIMEOFDAY(&before);

        ret = cmd->def->handler(ctl, cmd);

        if (ctl->timing)
            GETTIMEOFDAY(&after);

        if (strcmp(cmd->def->name, "quit") == 0)        /* hack ... */
            return ret;

        if (ctl->timing)
            vshPrint(ctl, "\n(Time: %.3f ms)\n\n",
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
vshCommandGetToken(vshControl * ctl, char *str, char **end, char **res)
{
    int tk = VSH_TK_NONE;
    int quote = FALSE;
    int sz = 0;
    char *p = str;
    char *tkstr = NULL;

    *end = NULL;

    while (p && *p && isblank((unsigned char) *p))
        p++;

    if (p == NULL || *p == '\0')
        return VSH_TK_END;
    if (*p == ';') {
        *end = ++p;             /* = \0 or begi of next command */
        return VSH_TK_END;
    }
    while (*p) {
        /* end of token is blank space or ';' */
        if ((quote == FALSE && isblank((unsigned char) *p)) || *p == ';')
            break;

        /* end of option name could be '=' */
        if (tk == VSH_TK_OPTION && *p == '=') {
            p++;                /* skip '=' */
            break;
        }

        if (tk == VSH_TK_NONE) {
            if (*p == '-' && *(p + 1) == '-' && *(p + 2)
                && isalnum((unsigned char) *(p + 2))) {
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
        vshError(ctl, FALSE, "missing \"");
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
vshCommandParse(vshControl * ctl, char *cmdstr)
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
        vshCmdDef *cmd = NULL;
        int tk = VSH_TK_NONE;
        int data_ct = 0;

        first = NULL;

        while (tk != VSH_TK_END) {
            char *end = NULL;
            vshCmdOptDef *opt = NULL;

            tkdata = NULL;

            /* get token */
            tk = vshCommandGetToken(ctl, str, &end, &tkdata);

            str = end;

            if (tk == VSH_TK_END)
                break;
            if (tk == VSH_TK_ERROR)
                goto syntaxError;

            if (cmd == NULL) {
                /* first token must be command name */
                if (tk != VSH_TK_DATA) {
                    vshError(ctl, FALSE,
                             "unexpected token (command name): '%s'",
                             tkdata);
                    goto syntaxError;
                }
                if (!(cmd = vshCmddefSearch(tkdata))) {
                    vshError(ctl, FALSE, "unknown command: '%s'", tkdata);
                    goto syntaxError;   /* ... or ignore this command only? */
                }
                free(tkdata);
            } else if (tk == VSH_TK_OPTION) {
                if (!(opt = vshCmddefGetOption(cmd, tkdata))) {
                    vshError(ctl, FALSE,
                             "command '%s' doesn't support option --%s",
                             cmd->name, tkdata);
                    goto syntaxError;
                }
                free(tkdata);   /* option name */
                tkdata = NULL;

                if (opt->type != VSH_OT_BOOL) {
                    /* option data */
                    tk = vshCommandGetToken(ctl, str, &end, &tkdata);
                    str = end;
                    if (tk == VSH_TK_ERROR)
                        goto syntaxError;
                    if (tk != VSH_TK_DATA) {
                        vshError(ctl, FALSE,
                                 "expected syntax: --%s <%s>",
                                 opt->name,
                                 opt->type ==
                                 VSH_OT_INT ? "number" : "string");
                        goto syntaxError;
                    }
                }
            } else if (tk == VSH_TK_DATA) {
                if (!(opt = vshCmddefGetData(cmd, data_ct++))) {
                    vshError(ctl, FALSE, "unexpected data '%s'", tkdata);
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
                         tk == VSH_TK_OPTION ? "OPTION" : "DATA",
                         arg->data);
            }
            if (!str)
                break;
        }

        /* commad parsed -- allocate new struct for the command */
        if (cmd) {
            vshCmd *c = vshMalloc(ctl, sizeof(vshCmd));

            c->opts = first;
            c->def = cmd;
            c->next = NULL;

            if (!vshCommandCheckOpts(ctl, c))
                goto syntaxError;

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
    if (tkdata)
        free(tkdata);
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
            return "running ";
        case VIR_DOMAIN_BLOCKED:
            return "blocked ";
        case VIR_DOMAIN_PAUSED:
            return "paused ";
        case VIR_DOMAIN_SHUTDOWN:
            return "in shutdown";
        case VIR_DOMAIN_SHUTOFF:
            return "shut off";
        case VIR_DOMAIN_CRASHED:
            return "crashed";
        default:
            return "no state";  /* = dom0 state */
    }
    return NULL;
}

static int
vshConnectionUsability(vshControl * ctl, virConnectPtr conn, int showerror)
{
    /* TODO: use something like virConnectionState() to 
     *       check usability of the connection 
     */
    if (!conn) {
        if (showerror)
            vshError(ctl, FALSE, "no valid connection.");
        return FALSE;
    }
    return TRUE;
}

static void
vshDebug(vshControl * ctl, int level, const char *format, ...)
{
    va_list ap;

    if (level > ctl->debug)
        return;

    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

static void
vshPrintExtra(vshControl * ctl, const char *format, ...)
{
    va_list ap;

    if (ctl->quiet == TRUE)
        return;

    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}


static void
vshError(vshControl * ctl, int doexit, const char *format, ...)
{
    va_list ap;

    if (doexit)
        fprintf(stderr, "%s: error: ", progname);
    else
        fputs("error: ", stderr);

    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fputc('\n', stderr);

    if (doexit) {
        if (ctl)
            vshDeinit(ctl);
        exit(EXIT_FAILURE);
    }
}

static void *
_vshMalloc(vshControl * ctl, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = malloc(size)))
        return x;
    vshError(ctl, TRUE, "%s: %d: failed to allocate %d bytes\n", 
                filename, line, (int) size);
    return NULL;
}

static void *
_vshCalloc(vshControl * ctl, size_t nmemb, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = calloc(nmemb, size)))
        return x;
    vshError(ctl, TRUE, "%s: %d: failed to allocate %d bytes\n", 
                filename, line, (int) (size*nmemb));
    return NULL;
}

static char *
_vshStrdup(vshControl * ctl, const char *s, const char *filename, int line)
{
    char *x;

    if ((x = strdup(s)))
        return x;
    vshError(ctl, TRUE, "%s: %d: failed to allocate %d bytes\n", 
                filename, line, strlen(s));
    return NULL;
}

/*
 * Initialize vistsh
 */
static int
vshInit(vshControl * ctl)
{
    if (ctl->conn)
        return FALSE;

    ctl->uid = getuid();

    /* set up the library error handler */
    virSetErrorFunc(NULL, virshErrorHandler);

    /* basic connection to hypervisor */
    if (ctl->uid == 0)
        ctl->conn = virConnectOpen(ctl->name);
    else
        ctl->conn = virConnectOpenReadOnly(ctl->name);

    if (!ctl->conn)
        vshError(ctl, TRUE, "failed to connect to the hypervisor");

    return TRUE;
}

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
        if (strncmp(name, text, len) == 0)
            return vshStrdup(NULL, name);
    }

    /* If no names matched, then return NULL. */
    return NULL;
}

static char *
vshReadlineOptionsGenerator(const char *text, int state)
{
    static int list_index, len;
    static vshCmdDef *cmd = NULL;
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
        free(cmdname);
    }

    if (!cmd)
        return NULL;

    while ((name = cmd->opts[list_index].name)) {
        vshCmdOptDef *opt = &cmd->opts[list_index];
        char *res;

        list_index++;

        if (opt->type == VSH_OT_DATA)
            /* ignore non --option */
            continue;

        if (len > 2) {
            if (strncmp(name, text + 2, len - 2))
                continue;
        }
        res = vshMalloc(NULL, strlen(name) + 3);
        sprintf(res, "--%s", name);
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


static void
vshReadlineInit(void)
{
    /* Allow conditional parsing of the ~/.inputrc file. */
    rl_readline_name = "virsh";

    /* Tell the completer that we want a crack first. */
    rl_attempted_completion_function = vshReadlineCompletion;
}

/*
 * Deinitliaze virsh
 */
static int
vshDeinit(vshControl * ctl)
{
    if (ctl->conn) {
        if (virConnectClose(ctl->conn) != 0) {
            ctl->conn = NULL;   /* prevent recursive call from vshError() */
            vshError(ctl, TRUE,
                     "failed to disconnect from the hypervisor");
        }
    }
    return TRUE;
}

/*
 * Print usage
 */
static void
vshUsage(vshControl * ctl, const char *cmdname)
{
    vshCmdDef *cmd;

    /* global help */
    if (!cmdname) {
        fprintf(stdout, "\n%s [options] [commands]\n\n"
                "  options:\n"
                "    -c | --connect <name>   optional argument currently unused (or used for tests only)\n"
                "    -d | --debug <num>      debug level [0-5]\n"
                "    -h | --help             this help\n"
                "    -q | --quiet            quiet mode\n"
                "    -t | --timing           print timing information\n"
                "    -v | --version          program version\n\n"
                "  commands (non interactive mode):\n", progname);

        for (cmd = commands; cmd->name; cmd++)
            fprintf(stdout,
                    "    %-15s %s\n", cmd->name, vshCmddefGetInfo(cmd,
                                                                  "help"));

        fprintf(stdout,
                "\n  (specify --help <command> for details about the command)\n\n");
        return;
    }
    if (!vshCmddefHelp(ctl, cmdname, TRUE))
        exit(EXIT_FAILURE);
}

/*
 * argv[]:  virsh [options] [command]
 *
 */
static int
vshParseArgv(vshControl * ctl, int argc, char **argv)
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
                    if (sz == 2 && *(last + 1) == o->val)
                        /* valid virsh short option */
                        valid = TRUE;
                    else if (sz > 2 && strcmp(o->name, last + 2) == 0)
                        /* valid virsh long option */
                        valid = TRUE;
                }
            }
            if (!valid) {
                end = i;
                break;
            }
        }
        last = argv[i];
    }
    end = end ? : argc;

    /* standard (non-command) options */
    while ((arg = getopt_long(end, argv, "d:hqtv", opt, &idx)) != -1) {
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
            default:
                vshError(ctl, TRUE,
                  "unsupported option '-%c'. See --help.", arg);
                break;
        }
    }

    if (help) {
        /* global or command specific help */
        vshUsage(ctl, argc > end ? argv[end] : NULL);
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

        free(cmdstr);
        return ret;
    }
    return TRUE;
}

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    int ret = TRUE;

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;

    memset(ctl, 0, sizeof(vshControl));
    ctl->imode = TRUE;          /* default is interactive mode */

    if (!vshParseArgv(ctl, argc, argv))
        exit(EXIT_FAILURE);

    if (!vshInit(ctl))
        exit(EXIT_FAILURE);

    if (!ctl->imode) {
        ret = vshCommandRun(ctl, ctl->cmd);
    } else {
        /* interactive mode */
        if (!ctl->quiet) {
            vshPrint(ctl,
                     "Welcome to %s, the virtualization interactive terminal.\n\n",
                     progname);
            vshPrint(ctl,
                     "Type:  'help' for help with commands\n"
                     "       'quit' to quit\n\n");
        }
        vshReadlineInit();
        do {
            ctl->cmdstr =
                readline(ctl->uid == 0 ? VSH_PROMPT_RW : VSH_PROMPT_RO);
            if (ctl->cmdstr == NULL)
                break;          /* EOF */
            if (*ctl->cmdstr) {
                add_history(ctl->cmdstr);
                if (vshCommandParse(ctl, ctl->cmdstr))
                    vshCommandRun(ctl, ctl->cmd);
            }
            free(ctl->cmdstr);
            ctl->cmdstr = NULL;
        } while (ctl->imode);

        if (ctl->cmdstr == NULL)
            fputc('\n', stdout);        /* line break after alone prompt */
    }

    vshDeinit(ctl);
    exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
