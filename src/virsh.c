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
#include <locale.h>

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
static const char *vshDomainVcpuStateToString(int state);
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
    {"help", gettext_noop("print help")},
    {"desc", gettext_noop("Prints global help or command specific help.")},

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

        vshPrint(ctl, _("Commands:\n\n"));
        for (def = commands; def->name; def++)
            vshPrint(ctl, "    %-15s %s\n", def->name,
                     _N(vshCmddefGetInfo(def, "help")));
        return TRUE;
    }
    return vshCmddefHelp(ctl, cmdname, FALSE);
}

/*
 * "connect" command 
 */
static vshCmdInfo info_connect[] = {
    {"syntax", "connect [name] [--readonly]"},
    {"help", gettext_noop("(re)connect to hypervisor")},
    {"desc",
     gettext_noop("Connect to local hypervisor. This is built-in command after shell start up.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_connect[] = {
    {"name",     VSH_OT_DATA, 0, gettext_noop("hypervisor connection URI")},
    {"readonly", VSH_OT_BOOL, 0, gettext_noop("read-only connection")},
    {NULL, 0, 0, NULL}
};

static int
cmdConnect(vshControl * ctl, vshCmd * cmd)
{
    int ro = vshCommandOptBool(cmd, "readonly");
    
    if (ctl->conn) {
        if (virConnectClose(ctl->conn) != 0) {
            vshError(ctl, FALSE,
                     _("Failed to disconnect from the hypervisor"));
            return FALSE;
        }
        ctl->conn = NULL;
    }
    
    if (ctl->name)
        free(ctl->name);
    ctl->name = vshStrdup(ctl, vshCommandOptString(cmd, "name", NULL));

    if (!ro)
        ctl->conn = virConnectOpen(ctl->name);
    else
        ctl->conn = virConnectOpenReadOnly(ctl->name);

    if (!ctl->conn)
        vshError(ctl, FALSE, _("Failed to connect to the hypervisor"));

    return ctl->conn ? TRUE : FALSE;
}

/*
 * "list" command
 */
static vshCmdInfo info_list[] = {
    {"syntax", "list [--inactive | --all]"},
    {"help", gettext_noop("list domains")},
    {"desc", gettext_noop("Returns list of domains.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_list[] = {
    {"inactive", VSH_OT_BOOL, 0, gettext_noop("list inactive domains")},
    {"all", VSH_OT_BOOL, 0, gettext_noop("list inactive & active domains")},
    {NULL, 0, 0, NULL}
};


static int domidsorter(const void *a, const void *b) {
  const int *ia = (const int *)a;
  const int *ib = (const int *)b;

  if (*ia > *ib)
    return 1;
  else if (*ia < *ib)
    return -1;
  return 0;
}
static int domnamesorter(const void *a, const void *b) {
  const char **sa = (const char**)a;
  const char **sb = (const char**)b;

  return strcasecmp(*sa, *sb);
}
static int
cmdList(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
{
    int inactive = vshCommandOptBool(cmd, "inactive");
    int all = vshCommandOptBool(cmd, "all");
    int active = !inactive || all ? 1 : 0;
    int *ids = NULL, maxid = 0, i;
    const char **names = NULL;
    int maxname = 0;
    inactive |= all;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;
    
    if (active) {
      maxid = virConnectNumOfDomains(ctl->conn);
      if (maxid < 0) {
        vshError(ctl, FALSE, _("Failed to list active domains"));
        return FALSE;
      }
      if (maxid) {
        ids = vshMalloc(ctl, sizeof(int) * maxid);
	
        if ((maxid = virConnectListDomains(ctl->conn, &ids[0], maxid)) < 0) {
	  vshError(ctl, FALSE, _("Failed to list active domains"));
	  free(ids);
	  return FALSE;
        }
	
	qsort(&ids[0], maxid, sizeof(int), domidsorter);
      }
    }
    if (inactive) {
      maxname = virConnectNumOfDefinedDomains(ctl->conn);
      if (maxname < 0) {
        vshError(ctl, FALSE, _("Failed to list inactive domains"));
	if (ids)
	  free(ids);
        return FALSE;
      }
      if (maxname) {
        names = vshMalloc(ctl, sizeof(char *) * maxname);
	
        if ((maxname = virConnectListDefinedDomains(ctl->conn, names, maxname)) < 0) {
	  vshError(ctl, FALSE, _("Failed to list inactive domains"));
	  if (ids)
	    free(ids);
	  free(names);
	  return FALSE;
        }

	qsort(&names[0], maxname, sizeof(char*), domnamesorter);
      }
    }
    vshPrintExtra(ctl, "%3s %-20s %s\n", _("Id"), _("Name"), _("State"));
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
                 0 ? _("no state") : _N(vshDomainStateToString(info.state)));
        virDomainFree(dom);
    }
    for (i = 0; i < maxname; i++) {
        int ret;
        unsigned int id;
        virDomainInfo info;
        virDomainPtr dom = virDomainLookupByName(ctl->conn, names[i]);

        /* this kind of work with domains is not atomic operation */
        if (!dom) {
	    free(names[i]);
            continue;
	}
        ret = virDomainGetInfo(dom, &info);
	id = virDomainGetID(dom);

	if (id == ((unsigned int)-1)) {
	  vshPrint(ctl, "%3s %-20s %s\n",
		   "-",
		   names[i],
		   ret <
		   0 ? "no state" : vshDomainStateToString(info.state));
	} else {
	  vshPrint(ctl, "%3d %-20s %s\n",
		   id,
		   names[i],
		   ret <
		   0 ? "no state" : vshDomainStateToString(info.state));
	}

        virDomainFree(dom);
	free(names[i]);
    }
    if (ids)
        free(ids);
    if (names)
        free(names);
    return TRUE;
}

/*
 * "domstate" command
 */
static vshCmdInfo info_domstate[] = {
    {"syntax", "domstate <domain>"},
    {"help", gettext_noop("domain state")},
    {"desc", gettext_noop("Returns state about a running domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_domstate[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
                 _N(vshDomainStateToString(info.state)));
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
    {"help", gettext_noop("suspend a domain")},
    {"desc", gettext_noop("Suspend a running domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_suspend[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
        vshPrint(ctl, _("Domain %s suspended\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to suspend domain %s"), name);
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
    {"help", gettext_noop("create a domain from an XML file")},
    {"desc", gettext_noop("Create a domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_create[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file conatining an XML domain description")},
    {NULL, 0, 0, NULL}
};

static int
cmdCreate(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *from;
    int found;
    int ret = TRUE;
    char buffer[BUFSIZ];
    int fd, l;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    fd = open(from, O_RDONLY);
    if (fd < 0) {
        vshError(ctl, FALSE, _("Failed to read description file %s"), from);
        return(FALSE);
    }
    l = read(fd, &buffer[0], sizeof(buffer));
    if ((l <= 0) || (l >= (int) sizeof(buffer))) {
        vshError(ctl, FALSE, _("Failed to read description file %s"), from);
        close(fd);
        return(FALSE);
    }
    buffer[l] = 0;
    dom = virDomainCreateLinux(ctl->conn, &buffer[0], 0);
    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s created from %s\n"),
                 virDomainGetName(dom), from);
    } else {
        vshError(ctl, FALSE, _("Failed to create domain from %s"), from);
        ret = FALSE;
    }
    return ret;
}

/*
 * "define" command
 */
static vshCmdInfo info_define[] = {
    {"syntax", "define a domain from an XML <file>"},
    {"help", gettext_noop("define (but don't start) a domain from an XML file")},
    {"desc", gettext_noop("Define a domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_define[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("file conatining an XML domain description")},
    {NULL, 0, 0, NULL}
};

static int
cmdDefine(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *from;
    int found;
    int ret = TRUE;
    char buffer[BUFSIZ];
    int fd, l;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    from = vshCommandOptString(cmd, "file", &found);
    if (!found)
        return FALSE;

    fd = open(from, O_RDONLY);
    if (fd < 0) {
        vshError(ctl, FALSE, _("Failed to read description file %s"), from);
        return(FALSE);
    }
    l = read(fd, &buffer[0], sizeof(buffer));
    if ((l <= 0) || (l >= (int) sizeof(buffer))) {
        vshError(ctl, FALSE, _("Failed to read description file %s"), from);
        close(fd);
        return(FALSE);
    }
    buffer[l] = 0;
    dom = virDomainDefineXML(ctl->conn, &buffer[0]);
    if (dom != NULL) {
        vshPrint(ctl, _("Domain %s defined from %s\n"),
                 virDomainGetName(dom), from);
    } else {
        vshError(ctl, FALSE, _("Failed to define domain from %s"), from);
        ret = FALSE;
    }
    return ret;
}

/*
 * "undefine" command
 */
static vshCmdInfo info_undefine[] = {
    {"syntax", "undefine <domain>"},
    {"help", gettext_noop("undefine an inactive domain")},
    {"desc", gettext_noop("Undefine the configuration for an inactive domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_undefine[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdUndefine(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int ret = TRUE;
    char *name;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", &name)))
        return FALSE;

    if (virDomainUndefine(dom) == 0) {
        vshPrint(ctl, _("Domain %s has been undefined\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to undefine domain %s"), name);
        ret = FALSE;
    }

    return ret;
}


/*
 * "start" command
 */
static vshCmdInfo info_start[] = {
    {"syntax", "start <domain>"},
    {"help", gettext_noop("start a (previously defined) inactive domain")},
    {"desc", gettext_noop("Start a domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_start[] = {
    {"name", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("name of the inactive domain")},
    {NULL, 0, 0, NULL}
};

static int
cmdStart(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    char *name;
    int found;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    name = vshCommandOptString(cmd, "name", &found);
    if (!found)
        return FALSE;

    dom = virDomainLookupByName(ctl->conn, name);
    if (!dom)
        return FALSE;

    if (virDomainGetID(dom) != (unsigned int)-1) {
        vshError(ctl, FALSE, _("Domain is already active"));
        return FALSE;
    }

    if (virDomainCreate(dom) == 0) {
        vshPrint(ctl, _("Domain %s started\n"),
                 name);
    } else {
      vshError(ctl, FALSE, _("Failed to start domain %s"), name);
        ret = FALSE;
    }
    return ret;
}

/*
 * "save" command
 */
static vshCmdInfo info_save[] = {
    {"syntax", "save <domain> <file>"},
    {"help", gettext_noop("save a domain state to a file")},
    {"desc", gettext_noop("Save a running domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_save[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("where to save the data")},
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
        vshPrint(ctl, _("Domain %s saved to %s\n"), name, to);
    } else {
        vshError(ctl, FALSE, _("Failed to save domain %s to %s"), name, to);
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
    {"help", gettext_noop("restore a domain from a saved state in a file")},
    {"desc", gettext_noop("Restore a domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_restore[] = {
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("the state to restore")},
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
        vshPrint(ctl, _("Domain restored from %s\n"), from);
    } else {
        vshError(ctl, FALSE, _("Failed to restore domain from %s"), from);
        ret = FALSE;
    }
    return ret;
}

/*
 * "dump" command
 */
static vshCmdInfo info_dump[] = {
    {"syntax", "dump <domain> <file>"},
    {"help", gettext_noop("dump the core of a domain to a file for analysis")},
    {"desc", gettext_noop("Core dump a domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_dump[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"file", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("where to dump the core")},
    {NULL, 0, 0, NULL}
};

static int
cmdDump(vshControl * ctl, vshCmd * cmd)
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

    if (virDomainCoreDump(dom, to, 0) == 0) {
        vshPrint(ctl, _("Domain %s dumpd to %s\n"), name, to);
    } else {
        vshError(ctl, FALSE, _("Failed to core dump domain %s to %s"),
                 name, to);
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "resume" command
 */
static vshCmdInfo info_resume[] = {
    {"syntax", "resume <domain>"},
    {"help", gettext_noop("resume a domain")},
    {"desc", gettext_noop("Resume a previously suspended domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_resume[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
        vshPrint(ctl, _("Domain %s resumed\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to resume domain %s"), name);
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
    {"help", gettext_noop("gracefully shutdown a domain")},
    {"desc", gettext_noop("Run shutdown in the target domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_shutdown[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
        vshPrint(ctl, _("Domain %s is being shutdown\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to shutdown domain %s"), name);
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
    {"help", gettext_noop("reboot a domain")},
    {"desc", gettext_noop("Run a reboot command in the target domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_reboot[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
        vshPrint(ctl, _("Domain %s is being rebooted\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to reboot domain %s"), name);
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
    {"help", gettext_noop("destroy a domain")},
    {"desc", gettext_noop("Destroy a given domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_destroy[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
        vshPrint(ctl, _("Domain %s destroyed\n"), name);
    } else {
        vshError(ctl, FALSE, _("Failed to destroy domain %s"), name);
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
    {"help", gettext_noop("domain information")},
    {"desc", gettext_noop("Returns basic information about the domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_dominfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDominfo(vshControl * ctl, vshCmd * cmd)
{
    virDomainInfo info;
    virDomainPtr dom;
    int ret = TRUE;
    unsigned int id;
    char *str, uuid[37];

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
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
        free(str);
    }

    if (virDomainGetInfo(dom, &info) == 0) {
        vshPrint(ctl, "%-15s %s\n", _("State:"),
                 _N(vshDomainStateToString(info.state)));

        vshPrint(ctl, "%-15s %d\n", _("CPU(s):"), info.nrVirtCpu);

        if (info.cpuTime != 0) {
	    double cpuUsed = info.cpuTime;

            cpuUsed /= 1000000000.0;

            vshPrint(ctl, "%-15s %.1lfs\n", _("CPU time:"), cpuUsed);
        }

        vshPrint(ctl, "%-15s %lu kB\n", _("Max memory:"),
                 info.maxMem);
	vshPrint(ctl, "%-15s %lu kB\n", _("Used memory:"),
                 info.memory);

    } else {
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "vcpuinfo" command
 */
static vshCmdInfo info_vcpuinfo[] = {
    {"syntax", "vcpuinfo <domain>"},
    {"help", gettext_noop("domain vcpu information")},
    {"desc", gettext_noop("Returns basic information about the domain virtual CPUs.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_vcpuinfo[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdVcpuinfo(vshControl * ctl, vshCmd * cmd)
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

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    if (virNodeGetInfo(ctl->conn, &nodeinfo) != 0) {
        virDomainFree(dom);
	return FALSE;
    }

    if (virDomainGetInfo(dom, &info) != 0) {
        virDomainFree(dom);
        return FALSE;
    }

    cpuinfo = malloc(sizeof(virVcpuInfo)*info.nrVirtCpu);
    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    cpumap = malloc(info.nrVirtCpu * cpumaplen);

    if ((ncpus = virDomainGetVcpus(dom, 
				   cpuinfo, info.nrVirtCpu,
				   cpumap, cpumaplen)) >= 0) {
        int n;
	for (n = 0 ; n < ncpus ; n++) {
	    unsigned int m;
	    vshPrint(ctl, "%-15s %d\n", _("VCPU:"), n);
	    vshPrint(ctl, "%-15s %d\n", _("CPU:"), cpuinfo[n].cpu);
	    vshPrint(ctl, "%-15s %s\n", _("State:"),
		     _N(vshDomainVcpuStateToString(cpuinfo[n].state)));
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
        ret = FALSE;
    }

    free(cpumap);
    free(cpuinfo);
    virDomainFree(dom);
    return ret;
}

/*
 * "vcpupin" command
 */
static vshCmdInfo info_vcpupin[] = {
    {"syntax", "vcpupin <domain>"},
    {"help", gettext_noop("control domain vcpu affinity")},
    {"desc", gettext_noop("Pin domain VCPUs to host physical CPUs.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_vcpupin[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"vcpu", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("vcpu number")},
    {"cpulist", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("host cpu number(s) (comma separated)")},
    {NULL, 0, 0, NULL}
};

static int
cmdVcpupin(vshControl * ctl, vshCmd * cmd)
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

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    vcpu = vshCommandOptInt(cmd, "vcpu", &vcpufound);
    if (!vcpufound) {
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
        virDomainFree(dom);
        return FALSE;
    }

    if (vcpu >= info.nrVirtCpu) {
        virDomainFree(dom);
        return FALSE;
    }

    cpumaplen = VIR_CPU_MAPLEN(VIR_NODEINFO_MAXCPUS(nodeinfo));
    cpumap = malloc(cpumaplen);
    memset(cpumap, 0, cpumaplen);

    do {
        unsigned int cpu = atoi(cpulist);

        if (cpu < VIR_NODEINFO_MAXCPUS(nodeinfo)) {
            VIR_USE_CPU(cpumap, cpu);
        }
        cpulist = index(cpulist, ',');
        if (cpulist)
            cpulist++;
    } while (cpulist);

    if (virDomainPinVcpu(dom, vcpu, cpumap, cpumaplen) != 0) {
        ret = FALSE;
    }

    free(cpumap);
    virDomainFree(dom);
    return ret;
}

/*
 * "setvcpus" command
 */
static vshCmdInfo info_setvcpus[] = {
    {"syntax", "setvcpus <domain> <count>"},
    {"help", gettext_noop("change number of virtual CPUs")},
    {"desc", gettext_noop("Change the number of virtual CPUs active in the guest domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_setvcpus[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"count", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("number of virtual CPUs")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetvcpus(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int count;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    count = vshCommandOptInt(cmd, "count", &count);
    if (!count) {
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
static vshCmdInfo info_setmem[] = {
    {"syntax", "setmem <domain> <bytes>"},
    {"help", gettext_noop("change memory allocation")},
    {"desc", gettext_noop("Change the current memory allocation in the guest domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_setmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"bytes", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("number of bytes of memory")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmem(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int bytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    bytes = vshCommandOptInt(cmd, "bytes", &bytes);
    if (!bytes) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainSetMemory(dom, bytes) != 0) {
        ret = FALSE;
    }

    virDomainFree(dom);
    return ret;
}

/*
 * "setmaxmem" command
 */
static vshCmdInfo info_setmaxmem[] = {
    {"syntax", "setmaxmem <domain> <bytes>"},
    {"help", gettext_noop("change maximum memory limit")},
    {"desc", gettext_noop("Change the maximum memory allocation limit in the guest domain.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_setmaxmem[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
    {"bytes", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("maxmimum memory limit in bytes")},
    {NULL, 0, 0, NULL}
};

static int
cmdSetmaxmem(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    int bytes;
    int ret = TRUE;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (!(dom = vshCommandOptDomain(ctl, cmd, "domain", NULL)))
        return FALSE;

    bytes = vshCommandOptInt(cmd, "bytes", &bytes);
    if (!bytes) {
        virDomainFree(dom);
        return FALSE;
    }

    if (virDomainSetMaxMemory(dom, bytes) != 0) {
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
    {"help", gettext_noop("node information")},
    {"desc", gettext_noop("Returns basic information about the node.")},
    {NULL, NULL}
};

static int
cmdNodeinfo(vshControl * ctl, vshCmd * cmd ATTRIBUTE_UNUSED)
{
    virNodeInfo info;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;

    if (virNodeGetInfo(ctl->conn, &info) < 0) {
        vshError(ctl, FALSE, _("failed to get node information"));
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
 * "dumpxml" command
 */
static vshCmdInfo info_dumpxml[] = {
    {"syntax", "dumpxml <name>"},
    {"help", gettext_noop("domain information in XML")},
    {"desc", gettext_noop("Ouput the domain information as an XML dump to stdout.")},
    {NULL, NULL}
};

static vshCmdOptDef opts_dumpxml[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name, id or uuid")},
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
    {"help", gettext_noop("convert a domain id or UUID to domain name")},
    {NULL, NULL}
};

static vshCmdOptDef opts_domname[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain id or uuid")},
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
    {"help", gettext_noop("convert a domain name or UUID to domain id")},
    {NULL, NULL}
};

static vshCmdOptDef opts_domid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain name or uuid")},
    {NULL, 0, 0, NULL}
};

static int
cmdDomid(vshControl * ctl, vshCmd * cmd)
{
    virDomainPtr dom;
    unsigned int id;

    if (!vshConnectionUsability(ctl, ctl->conn, TRUE))
        return FALSE;
    if (!(dom = vshCommandOptDomainBy(ctl, cmd, "domain", NULL, 
                                    VSH_DOMBYNAME|VSH_DOMBYUUID)))
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
static vshCmdInfo info_domuuid[] = {
    {"syntax", "domuuid <domain>"},
    {"help", gettext_noop("convert a domain name or id to domain UUID")},
    {NULL, NULL}
};

static vshCmdOptDef opts_domuuid[] = {
    {"domain", VSH_OT_DATA, VSH_OFLAG_REQ, gettext_noop("domain id or name")},
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
        vshError(ctl, FALSE, _("failed to get domain UUID"));

    return TRUE;
}


/*
 * "version" command
 */
static vshCmdInfo info_version[] = {
    {"syntax", "version"},
    {"help", gettext_noop("show version")},
    {"desc", gettext_noop("Display the system version information.")},
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
        vshError(ctl, FALSE, _("failed to get hypervisor type"));
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
        vshError(ctl, FALSE, _("failed to get the library version"));
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
        vshError(ctl, FALSE, _("failed to get the hypervisor version"));
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
 * "quit" command
 */
static vshCmdInfo info_quit[] = {
    {"syntax", "quit"},
    {"help", gettext_noop("quit this interactive terminal")},
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
    {"start", cmdStart, opts_start, info_start},
    {"destroy", cmdDestroy, opts_destroy, info_destroy},
    {"define", cmdDefine, opts_define, info_define},
    {"domid", cmdDomid, opts_domid, info_domid},
    {"domuuid", cmdDomuuid, opts_domuuid, info_domuuid},
    {"dominfo", cmdDominfo, opts_dominfo, info_dominfo},
    {"domname", cmdDomname, opts_domname, info_domname},
    {"domstate", cmdDomstate, opts_domstate, info_domstate},
    {"dumpxml", cmdDumpXML, opts_dumpxml, info_dumpxml},
    {"help", cmdHelp, opts_help, info_help},
    {"list", cmdList, opts_list, info_list},
    {"nodeinfo", cmdNodeinfo, NULL, info_nodeinfo},
    {"quit", cmdQuit, NULL, info_quit},
    {"reboot", cmdReboot, opts_reboot, info_reboot},
    {"restore", cmdRestore, opts_restore, info_restore},
    {"resume", cmdResume, opts_resume, info_resume},
    {"save", cmdSave, opts_save, info_save},
    {"dump", cmdDump, opts_dump, info_dump},
    {"shutdown", cmdShutdown, opts_shutdown, info_shutdown},
    {"setmem", cmdSetmem, opts_setmem, info_setmem},
    {"setmaxmem", cmdSetmaxmem, opts_setmaxmem, info_setmaxmem},
    {"setvcpus", cmdSetvcpus, opts_setvcpus, info_setvcpus},
    {"suspend", cmdSuspend, opts_suspend, info_suspend},
    {"undefine", cmdUndefine, opts_undefine, info_undefine},
    {"vcpuinfo", cmdVcpuinfo, opts_vcpuinfo, info_vcpuinfo},
    {"vcpupin", cmdVcpupin, opts_vcpupin, info_vcpupin},
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
                         _("command '%s' requires <%s> option") :
			 _("command '%s' requires --%s option"),
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
        vshError(ctl, FALSE, _("command '%s' doesn't exist"), cmdname);
        return FALSE;
    } else {
        vshCmdOptDef *opt;
        const char *desc = _N(vshCmddefGetInfo(def, "desc"));
        const char *help = _N(vshCmddefGetInfo(def, "help"));
        const char *syntax = vshCmddefGetInfo(def, "syntax");

        fputs(_("  NAME\n"), stdout);
        fprintf(stdout, "    %s - %s\n", def->name, help);

        if (syntax) {
            fputs(("\n  SYNOPSIS\n"), stdout);
            if (!withprog)
                fprintf(stdout, "    %s\n", syntax);
            else
                fprintf(stdout, "    %s %s\n", progname, syntax);
        }
        if (desc) {
            fputs(_("\n  DESCRIPTION\n"), stdout);
            fprintf(stdout, "    %s\n", desc);
        }
        if (def->opts) {
            fputs(_("\n  OPTIONS\n"), stdout);
            for (opt = def->opts; opt->name; opt++) {
                char buf[256];

                if (opt->type == VSH_OT_BOOL)
                    snprintf(buf, sizeof(buf), "--%s", opt->name);
                else if (opt->type == VSH_OT_INT)
                    snprintf(buf, sizeof(buf), _("--%s <number>"), opt->name);
                else if (opt->type == VSH_OT_STRING)
                    snprintf(buf, sizeof(buf), _("--%s <string>"), opt->name);
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
        vshError(ctl, FALSE, _("undefined domain name or id"));
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
        vshError(ctl, FALSE, _("failed to get domain '%s'"), n);

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
        vshError(ctl, FALSE, _("missing \""));
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
                             _("unexpected token (command name): '%s'"),
                             tkdata);
                    goto syntaxError;
                }
                if (!(cmd = vshCmddefSearch(tkdata))) {
                    vshError(ctl, FALSE, _("unknown command: '%s'"), tkdata);
                    goto syntaxError;   /* ... or ignore this command only? */
                }
                free(tkdata);
            } else if (tk == VSH_TK_OPTION) {
                if (!(opt = vshCmddefGetOption(cmd, tkdata))) {
                    vshError(ctl, FALSE,
                             _("command '%s' doesn't support option --%s"),
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
                                 _("expected syntax: --%s <%s>"),
                                 opt->name,
                                 opt->type ==
                                 VSH_OT_INT ? _("number") : _("string"));
                        goto syntaxError;
                    }
                }
            } else if (tk == VSH_TK_DATA) {
                if (!(opt = vshCmddefGetData(cmd, data_ct++))) {
                    vshError(ctl, FALSE, _("unexpected data '%s'"), tkdata);
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
            return gettext_noop("running");
        case VIR_DOMAIN_BLOCKED:
            return gettext_noop("blocked");
        case VIR_DOMAIN_PAUSED:
            return gettext_noop("paused");
        case VIR_DOMAIN_SHUTDOWN:
            return gettext_noop("in shutdown");
        case VIR_DOMAIN_SHUTOFF:
            return gettext_noop("shut off");
        case VIR_DOMAIN_CRASHED:
            return gettext_noop("crashed");
        default:
            return gettext_noop("no state");  /* = dom0 state */
    }
    return NULL;
}

static const char *
vshDomainVcpuStateToString(int state)
{
    switch (state) {
        case VIR_VCPU_OFFLINE:
            return gettext_noop("offline");
        case VIR_VCPU_BLOCKED:
            return gettext_noop("blocked");
        case VIR_VCPU_RUNNING:
            return gettext_noop("running");
        default:
            return gettext_noop("no state");
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
            vshError(ctl, FALSE, _("no valid connection"));
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
        fprintf(stderr, _("%s: error: "), progname);
    else
        fputs(_("error: "), stderr);

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
    vshError(ctl, TRUE, _("%s: %d: failed to allocate %d bytes"),
	     filename, line, (int) size);
    return NULL;
}

static void *
_vshCalloc(vshControl * ctl, size_t nmemb, size_t size, const char *filename, int line)
{
    void *x;

    if ((x = calloc(nmemb, size)))
        return x;
    vshError(ctl, TRUE, _("%s: %d: failed to allocate %d bytes"),
	     filename, line, (int) (size*nmemb));
    return NULL;
}

static char *
_vshStrdup(vshControl * ctl, const char *s, const char *filename, int line)
{
    char *x;

    if ((x = strdup(s)))
        return x;
    vshError(ctl, TRUE, _("%s: %d: failed to allocate %d bytes"),
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

    /* basic connection to hypervisor, for Xen connections unless
       we're root open a read only connections. Allow 'test' HV
       to be RW all the time though */
    if (ctl->uid == 0 || (ctl->name && !strncmp(ctl->name, "test", 4)))
        ctl->conn = virConnectOpen(ctl->name);
    else
        ctl->conn = virConnectOpenReadOnly(ctl->name);

    if (!ctl->conn)
        vshError(ctl, TRUE, _("failed to connect to the hypervisor"));

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
        fprintf(stdout, _("\n%s [options] [commands]\n\n"
			  "  options:\n"
			  "    -c | --connect <uri>    hypervisor connection URI\n"
			  "    -d | --debug <num>      debug level [0-5]\n"
			  "    -h | --help             this help\n"
			  "    -q | --quiet            quiet mode\n"
			  "    -t | --timing           print timing information\n"
			  "    -v | --version          program version\n\n"
			  "  commands (non interactive mode):\n"), progname);

        for (cmd = commands; cmd->name; cmd++)
            fprintf(stdout,
                    "    %-15s %s\n", cmd->name, _N(vshCmddefGetInfo(cmd,
								     "help")));

        fprintf(stdout,
                _("\n  (specify --help <command> for details about the command)\n\n"));
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
			 _("unsupported option '-%c'. See --help."), arg);
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
    char *defaultConn;
    int ret = TRUE;

    if (!setlocale(LC_ALL, "")) {
        perror("setlocale");
	return -1;
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

    if ((defaultConn = getenv("VIRSH_DEFAULT_CONNECT_URI"))) {
      ctl->name = strdup(defaultConn);
    }

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
                     _("Welcome to %s, the virtualization interactive terminal.\n\n"),
                     progname);
            vshPrint(ctl,
                     _("Type:  'help' for help with commands\n"
		       "       'quit' to quit\n\n"));
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
