/*
 * virsh.h: a shell to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2014 Red Hat, Inc.
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

#ifndef VIRSH_H
# define VIRSH_H

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdarg.h>
# include <unistd.h>
# include <sys/stat.h>
# include <inttypes.h>
# include <termios.h>

# include "internal.h"
# include "virerror.h"
# include "virthread.h"
# include "virnetdevbandwidth.h"
# include "virstring.h"

# define VSH_MAX_XML_FILE (10*1024*1024)

# define VSH_PROMPT_RW    "virsh # "
# define VSH_PROMPT_RO    "virsh > "

# define VIR_FROM_THIS VIR_FROM_NONE

# define GETTIMEOFDAY(T) gettimeofday(T, NULL)

# define VSH_MATCH(FLAG) (flags & (FLAG))

/**
 * The log configuration
 */
# define MSG_BUFFER    4096
# define SIGN_NAME     "virsh"
# define DIR_MODE      (S_IWUSR | S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)  /* 0755 */
# define FILE_MODE     (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH)                                /* 0644 */
# define LOCK_MODE     (S_IWUSR | S_IRUSR)                                                    /* 0600 */
# define LVL_DEBUG     "DEBUG"
# define LVL_INFO      "INFO"
# define LVL_NOTICE    "NOTICE"
# define LVL_WARNING   "WARNING"
# define LVL_ERROR     "ERROR"

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

# define VSH_DEBUG_DEFAULT VSH_ERR_ERROR

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
# define VSH_CMD_GRP_DOM_MANAGEMENT   "Domain Management"
# define VSH_CMD_GRP_DOM_MONITORING   "Domain Monitoring"
# define VSH_CMD_GRP_STORAGE_POOL     "Storage Pool"
# define VSH_CMD_GRP_STORAGE_VOL      "Storage Volume"
# define VSH_CMD_GRP_NETWORK          "Networking"
# define VSH_CMD_GRP_NODEDEV          "Node Device"
# define VSH_CMD_GRP_IFACE            "Interface"
# define VSH_CMD_GRP_NWFILTER         "Network Filter"
# define VSH_CMD_GRP_SECRET           "Secret"
# define VSH_CMD_GRP_SNAPSHOT         "Snapshot"
# define VSH_CMD_GRP_HOST_AND_HV      "Host and Hypervisor"
# define VSH_CMD_GRP_VIRSH            "Virsh itself"

/*
 * Command Option Flags
 */
enum {
    VSH_OFLAG_NONE     = 0,        /* without flags */
    VSH_OFLAG_REQ      = (1 << 0), /* option required */
    VSH_OFLAG_EMPTY_OK = (1 << 1), /* empty string option allowed */
    VSH_OFLAG_REQ_OPT  = (1 << 2), /* --optionname required */
};

/* forward declarations */
typedef struct _vshCmd vshCmd;
typedef struct _vshCmdDef vshCmdDef;
typedef struct _vshCmdGrp vshCmdGrp;
typedef struct _vshCmdInfo vshCmdInfo;
typedef struct _vshCmdOpt vshCmdOpt;
typedef struct _vshCmdOptDef vshCmdOptDef;
typedef struct _vshControl vshControl;
typedef struct _vshCtrlData vshCtrlData;

typedef char **(*vshCompleter)(unsigned int flags);

/*
 * vshCmdInfo -- name/value pair for information about command
 *
 * Commands should have at least the following names:
 * "name" - command name
 * "desc" - description of command, or empty string
 */
struct _vshCmdInfo {
    const char *name;           /* name of information, or NULL for list end */
    const char *data;           /* non-NULL information */
};

/*
 * vshCmdOptDef - command option definition
 */
struct _vshCmdOptDef {
    const char *name;           /* the name of option, or NULL for list end */
    vshCmdOptType type;         /* option type */
    unsigned int flags;         /* flags */
    const char *help;           /* non-NULL help string; or for VSH_OT_ALIAS
                                 * the name of a later public option */
    vshCompleter completer;         /* option completer */
    unsigned int completer_flags;   /* option completer flags */
};

/*
 * vshCmdOpt - command options
 *
 * After parsing a command, all arguments to the command have been
 * collected into a list of these objects.
 */
struct _vshCmdOpt {
    const vshCmdOptDef *def;    /* non-NULL pointer to option definition */
    char *data;                 /* allocated data, or NULL for bool option */
    vshCmdOpt *next;
};

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
struct _vshCmdDef {
    const char *name;           /* name of command, or NULL for list end */
    bool (*handler) (vshControl *, const vshCmd *);    /* command handler */
    const vshCmdOptDef *opts;   /* definition of command options */
    const vshCmdInfo *info;     /* details about command */
    unsigned int flags;         /* bitwise OR of VSH_CMD_FLAG */
};

/*
 * vshCmd - parsed command
 */
struct _vshCmd {
    const vshCmdDef *def;       /* command definition */
    vshCmdOpt *opts;            /* list of command arguments */
    vshCmd *next;      /* next command */
};

/*
 * vshControl
 */
struct _vshControl {
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
    int eventPipe[2];           /* Write-to-self pipe to end waiting for an
                                 * event to occur */
    int eventTimerId;           /* id of event loop timeout registration */

    const char *escapeChar;     /* String representation of
                                   console escape character */

    int keepalive_interval;     /* Client keepalive interval */
    int keepalive_count;        /* Client keepalive count */

# ifndef WIN32
    struct termios termattr;    /* settings of the tty terminal */
# endif
    bool istty;                 /* is the terminal a tty */
};

struct _vshCmdGrp {
    const char *name;    /* name of group, or NULL for list end */
    const char *keyword; /* help keyword */
    const vshCmdDef *commands;
};

void vshError(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
void vshOpenLogFile(vshControl *ctl);
void vshOutputLogFile(vshControl *ctl, int log_level, const char *format,
                      va_list ap)
    ATTRIBUTE_FMT_PRINTF(3, 0);
void vshCloseLogFile(vshControl *ctl);

virConnectPtr vshConnect(vshControl *ctl, const char *uri, bool readonly);

const char *vshCmddefGetInfo(const vshCmdDef *cmd, const char *info);
const vshCmdDef *vshCmddefSearch(const char *cmdname);
bool vshCmddefHelp(vshControl *ctl, const char *name);
const vshCmdGrp *vshCmdGrpSearch(const char *grpname);
bool vshCmdGrpHelp(vshControl *ctl, const char *name);

int vshCommandOptInt(const vshCmd *cmd, const char *name, int *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptUInt(const vshCmd *cmd, const char *name,
                      unsigned int *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptUL(const vshCmd *cmd, const char *name,
                    unsigned long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptString(const vshCmd *cmd, const char *name,
                        const char **value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptStringReq(vshControl *ctl, const vshCmd *cmd,
                           const char *name, const char **value)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptLongLong(const vshCmd *cmd, const char *name,
                          long long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptULongLong(const vshCmd *cmd, const char *name,
                           unsigned long long *value)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
int vshCommandOptScaledInt(const vshCmd *cmd, const char *name,
                           unsigned long long *value, int scale,
                           unsigned long long max)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;
bool vshCommandOptBool(const vshCmd *cmd, const char *name);
const vshCmdOpt *vshCommandOptArgv(const vshCmd *cmd,
                                   const vshCmdOpt *opt);
bool vshCmdHasOption(vshControl *ctl, const vshCmd *cmd, const char *optname);

int vshCommandOptTimeoutToMs(vshControl *ctl, const vshCmd *cmd, int *timeout);

/* Filter flags for various vshCommandOpt*By() functions */
typedef enum {
    VSH_BYID   = (1 << 1),
    VSH_BYUUID = (1 << 2),
    VSH_BYNAME = (1 << 3),
    VSH_BYMAC  = (1 << 4),
} vshLookupByFlags;

/* Given an index, return either the name of that device (non-NULL) or
 * of its parent (NULL if a root).  */
typedef const char * (*vshTreeLookup)(int devid, bool parent, void *opaque);
int vshTreePrint(vshControl *ctl, vshTreeLookup lookup, void *opaque,
                 int num_devices, int devid);

void vshPrintExtra(vshControl *ctl, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);
void vshDebug(vshControl *ctl, int level, const char *format, ...)
    ATTRIBUTE_FMT_PRINTF(3, 4);

/* XXX: add batch support */
# define vshPrint(_ctl, ...)   vshPrintExtra(NULL, __VA_ARGS__)

/* User visible sort, so we want locale-specific case comparison.  */
# define vshStrcasecmp(S1, S2) strcasecmp(S1, S2)
int vshNameSorter(const void *a, const void *b);

int vshDomainState(vshControl *ctl, virDomainPtr dom, int *reason);
virTypedParameterPtr vshFindTypedParamByName(const char *name,
                                             virTypedParameterPtr list,
                                             int count);
char *vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *vshEditWriteToTempFile(vshControl *ctl, const char *doc);
int vshEditFile(vshControl *ctl, const char *filename);
char *vshEditReadBackFile(vshControl *ctl, const char *filename);
int vshAskReedit(vshControl *ctl, const char *msg);
int vshStreamSink(virStreamPtr st, const char *bytes, size_t nbytes,
                  void *opaque);
double vshPrettyCapacity(unsigned long long val, const char **unit);
int vshStringToArray(const char *str, char ***array);

/* Typedefs, function prototypes for job progress reporting.
 * There are used by some long lingering commands like
 * migrate, dump, save, managedsave.
 */
struct _vshCtrlData {
    vshControl *ctl;
    const vshCmd *cmd;
    int writefd;
};

/* error handling */
extern virErrorPtr last_error;
void vshReportError(vshControl *ctl);
void vshResetLibvirtError(void);
void vshSaveLibvirtError(void);

/* terminal modifications */
bool vshTTYIsInterruptCharacter(vshControl *ctl, const char chr);
int vshTTYDisableInterrupt(vshControl *ctl);
int vshTTYRestore(vshControl *ctl);
int vshTTYMakeRaw(vshControl *ctl, bool report_errors);
bool vshTTYAvailable(vshControl *ctl);

/* waiting for events */
enum {
    VSH_EVENT_INTERRUPT,
    VSH_EVENT_TIMEOUT,
    VSH_EVENT_DONE,
};
int vshEventStart(vshControl *ctl, int timeout_ms);
void vshEventDone(vshControl *ctl);
int vshEventWait(vshControl *ctl);
void vshEventCleanup(vshControl *ctl);

/* allocation wrappers */
void *_vshMalloc(vshControl *ctl, size_t sz, const char *filename, int line);
# define vshMalloc(_ctl, _sz)    _vshMalloc(_ctl, _sz, __FILE__, __LINE__)

void *_vshCalloc(vshControl *ctl, size_t nmemb, size_t sz,
                 const char *filename, int line);
# define vshCalloc(_ctl, _nmemb, _sz) \
    _vshCalloc(_ctl, _nmemb, _sz, __FILE__, __LINE__)

char *_vshStrdup(vshControl *ctl, const char *s, const char *filename,
                 int line);
# define vshStrdup(_ctl, _s)    _vshStrdup(_ctl, _s, __FILE__, __LINE__)

/* Poison the raw allocating identifiers in favor of our vsh variants.  */
# undef malloc
# undef calloc
# undef realloc
# undef strdup
# define malloc use_vshMalloc_instead_of_malloc
# define calloc use_vshCalloc_instead_of_calloc
# define realloc use_vshRealloc_instead_of_realloc
# define strdup use_vshStrdup_instead_of_strdup

/* Macros to help dealing with mutually exclusive options. */

/* VSH_EXCLUSIVE_OPTIONS_EXPR:
 *
 * @NAME1: String containing the name of the option.
 * @EXPR1: Expression to validate the variable (boolean variable)
 * @NAME2: String containing the name of the option.
 * @EXPR2: Expression to validate the variable (boolean variable)
 *
 * Reject mutually exclusive command options in virsh. Use the
 * provided expression to check the variables.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
# define VSH_EXCLUSIVE_OPTIONS_EXPR(NAME1, EXPR1, NAME2, EXPR2)             \
    if ((EXPR1) && (EXPR2)) {                                               \
        vshError(ctl, _("Options --%s and --%s are mutually exclusive"),    \
                 NAME1, NAME2);                                             \
        return false;                                                       \
    }

/* VSH_EXCLUSIVE_OPTIONS:
 *
 * @NAME1: String containing the name of the option.
 * @NAME2: String containing the name of the option.
 *
 * Reject mutually exclusive command options in virsh. Use the
 * vshCommandOptBool call to request them.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
# define VSH_EXCLUSIVE_OPTIONS(NAME1, NAME2)                                \
    VSH_EXCLUSIVE_OPTIONS_EXPR(NAME1, vshCommandOptBool(cmd, NAME1),        \
                               NAME2, vshCommandOptBool(cmd, NAME2))

/* VSH_EXCLUSIVE_OPTIONS_VAR:
 *
 * @VARNAME1: Boolean variable containing the value of the option of same name
 * @VARNAME2: Boolean variable containing the value of the option of same name
 *
 * Reject mutually exclusive command options in virsh. Check in variables that
 * contain the value and have same name as the option.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
# define VSH_EXCLUSIVE_OPTIONS_VAR(VARNAME1, VARNAME2)                      \
    VSH_EXCLUSIVE_OPTIONS_EXPR(#VARNAME1, VARNAME1, #VARNAME2, VARNAME2)

#endif /* VIRSH_H */
