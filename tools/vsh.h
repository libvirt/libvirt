/*
 * vsh.h: common data to be used by clients to exercise the libvirt API
 *
 * Copyright (C) 2005, 2007-2015 Red Hat, Inc.
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

#pragma once

#include <stdarg.h>
#ifndef WIN32
# include <termios.h>
#endif

#include "internal.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define VSH_MAX_XML_FILE (10*1024*1024)
#define VSH_MATCH(FLAG) (flags & (FLAG))

/**
 * The log configuration
 */
#define MSG_BUFFER    4096
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
 * Command Option Flags
 */
enum {
    VSH_OFLAG_NONE     = 0,        /* without flags */
    VSH_OFLAG_REQ      = (1 << 0), /* option required */
    VSH_OFLAG_EMPTY_OK = (1 << 1), /* empty string option allowed */
    VSH_OFLAG_REQ_OPT  = (1 << 2), /* --optionname required */
};

/* forward declarations */
typedef struct _vshClientHooks vshClientHooks;
typedef struct _vshCmd vshCmd;
typedef struct _vshCmdDef vshCmdDef;
typedef struct _vshCmdGrp vshCmdGrp;
typedef struct _vshCmdInfo vshCmdInfo;
typedef struct _vshCmdOpt vshCmdOpt;
typedef struct _vshCmdOptDef vshCmdOptDef;
typedef struct _vshControl vshControl;

typedef char **(*vshCompleter)(vshControl *ctl,
                               const vshCmd *cmd,
                               unsigned int flags);

/*
 * vshCmdInfo -- name/value pair for information about command
 *
 * Commands should have at least the following names:
 * "help" - short description of command
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
    bool completeThis;          /* true if this is the option user's wishing to
                                   autocomplete */
    vshCmdOpt *next;
};

/*
 * Command Usage Flags
 */
enum {
    VSH_CMD_FLAG_NOCONNECT = (1 << 0),  /* no prior connection needed */
    VSH_CMD_FLAG_ALIAS     = (1 << 1),  /* command is an alias */
    VSH_CMD_FLAG_HIDDEN    = (1 << 2),  /* command is hidden/internal */
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
    const char *alias;          /* name of the aliased command */
};

/*
 * vshCmd - parsed command
 */
struct _vshCmd {
    const vshCmdDef *def;       /* command definition */
    vshCmdOpt *opts;            /* list of command arguments */
    vshCmd *next;               /* next command */
    bool skipChecks;            /* skip validity checks when retrieving opts */
};

/*
 * vshControl
 */
struct _vshControl {
    const char *name;           /* hardcoded name of the binary that cannot
                                 * be changed without recompilation compared
                                 * to program name */
    const char *env_prefix;     /* hardcoded environment variable prefix */
    char *connname;             /* connection name */
    char *progname;             /* program name */
    vshCmd *cmd;                /* the current command */
    char *cmdstr;               /* string with command */
    bool imode;                 /* interactive mode? */
    bool quiet;                 /* quiet mode */
    bool timing;                /* print timing info? */
    int debug;                  /* print debug messages? */
    char *logfile;              /* log file name */
    int log_fd;                 /* log file descriptor */
    char *historydir;           /* readline history directory name */
    char *historyfile;          /* readline history file name */
    virThread eventLoop;
    virMutex lock;
    bool eventLoopStarted;
    bool quit;
    int eventPipe[2];           /* Write-to-self pipe to end waiting for an
                                 * event to occur */
    int eventTimerId;           /* id of event loop timeout registration */

    int keepalive_interval;     /* Client keepalive interval */
    int keepalive_count;        /* Client keepalive count */

#ifndef WIN32
    struct termios termattr;    /* settings of the tty terminal */
#endif
    bool istty;                 /* is the terminal a tty */

    const vshClientHooks *hooks;/* mandatory client specific hooks */
    void *privData;             /* client specific data */
};

typedef void *
(*vshConnectionHook)(vshControl *ctl);

struct _vshClientHooks {
    vshConnectionHook connHandler;
};

struct _vshCmdGrp {
    const char *name;    /* name of group, or NULL for list end */
    const char *keyword; /* help keyword */
    const vshCmdDef *commands;
};

void vshError(vshControl *ctl, const char *format, ...)
    G_GNUC_PRINTF(2, 3);
void vshOpenLogFile(vshControl *ctl);
void vshOutputLogFile(vshControl *ctl, int log_level, const char *format,
                      va_list ap)
    G_GNUC_PRINTF(3, 0);
void vshCloseLogFile(vshControl *ctl);

const char *vshCmddefGetInfo(const vshCmdDef *cmd, const char *info);
const vshCmdDef *vshCmddefSearch(const char *cmdname);
const vshCmdGrp *vshCmdGrpSearch(const char *grpname);
bool vshCmdGrpHelp(vshControl *ctl, const vshCmdGrp *grp);

int vshCommandOptInt(vshControl *ctl, const vshCmd *cmd,
                     const char *name, int *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptUInt(vshControl *ctl, const vshCmd *cmd,
                      const char *name, unsigned int *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptUIntWrap(vshControl *ctl, const vshCmd *cmd,
                          const char *name, unsigned int *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptUL(vshControl *ctl, const vshCmd *cmd,
                    const char *name, unsigned long *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptULWrap(vshControl *ctl, const vshCmd *cmd,
                        const char *name, unsigned long *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptStringQuiet(vshControl *ctl, const vshCmd *cmd,
                             const char *name, const char **value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptStringReq(vshControl *ctl, const vshCmd *cmd,
                           const char *name, const char **value)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptLongLong(vshControl *ctl, const vshCmd *cmd,
                          const char *name, long long *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptULongLong(vshControl *ctl, const vshCmd *cmd,
                           const char *name, unsigned long long *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptULongLongWrap(vshControl *ctl, const vshCmd *cmd,
                               const char *name, unsigned long long *value)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshCommandOptScaledInt(vshControl *ctl, const vshCmd *cmd,
                           const char *name, unsigned long long *value,
                           int scale, unsigned long long max)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
int vshBlockJobOptionBandwidth(vshControl *ctl,
                               const vshCmd *cmd,
                               bool bytes,
                               unsigned long *bandwidth);
bool vshCommandOptBool(const vshCmd *cmd, const char *name);
bool vshCommandRun(vshControl *ctl, const vshCmd *cmd);
bool vshCommandStringParse(vshControl *ctl, char *cmdstr,
                           vshCmd **partial, size_t point);

const vshCmdOpt *vshCommandOptArgv(vshControl *ctl, const vshCmd *cmd,
                                   const vshCmdOpt *opt);
bool vshCommandArgvParse(vshControl *ctl, int nargs, char **argv);
int vshCommandOptTimeoutToMs(vshControl *ctl, const vshCmd *cmd, int *timeout);

void vshPrintVa(vshControl *ctl,
                const char *format,
                va_list ap)
    G_GNUC_PRINTF(2, 0);
void vshPrint(vshControl *ctl, const char *format, ...)
    G_GNUC_PRINTF(2, 3);
void vshPrintExtra(vshControl *ctl, const char *format, ...)
    G_GNUC_PRINTF(2, 3);
bool vshInit(vshControl *ctl, const vshCmdGrp *groups, const vshCmdDef *set);
bool vshInitReload(vshControl *ctl);
void vshDeinit(vshControl *ctl);
void vshDebug(vshControl *ctl, int level, const char *format, ...)
    G_GNUC_PRINTF(3, 4);

/* User visible sort, so we want locale-specific case comparison.  */
#define vshStrcasecmp(S1, S2) strcasecmp(S1, S2)
int vshNameSorter(const void *a, const void *b);

virTypedParameterPtr vshFindTypedParamByName(const char *name,
                                             virTypedParameterPtr list,
                                             int count);
char *vshGetTypedParamValue(vshControl *ctl, virTypedParameterPtr item)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

double vshPrettyCapacity(unsigned long long val, const char **unit);
int vshStringToArray(const char *str, char ***array);

/* Given an index, return either the name of that device (non-NULL) or
 * of its parent (NULL if a root).  */
typedef const char * (*vshTreeLookup)(int devid, bool parent, void *opaque);
int vshTreePrint(vshControl *ctl, vshTreeLookup lookup, void *opaque,
                 int num_devices, int devid);

/* error handling */
extern virErrorPtr last_error;
void vshErrorHandler(void *opaque, virErrorPtr error);
void vshReportError(vshControl *ctl);
void vshResetLibvirtError(void);
void vshSaveLibvirtError(void);
void vshSaveLibvirtHelperError(void);

/* file handling */
void vshEditUnlinkTempfile(char *file);
typedef char vshTempFile;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(vshTempFile, vshEditUnlinkTempfile);
char *vshEditWriteToTempFile(vshControl *ctl, const char *doc);
int vshEditFile(vshControl *ctl, const char *filename);
char *vshEditReadBackFile(vshControl *ctl, const char *filename);
int vshAskReedit(vshControl *ctl, const char *msg, bool relax_avail);

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
void vshEventCleanup(vshControl *ctl);
void vshEventDone(vshControl *ctl);
void vshEventLoop(void *opaque);
int vshEventStart(vshControl *ctl, int timeout_ms);
void vshEventTimeout(int timer, void *opaque);
int vshEventWait(vshControl *ctl);

/* generic commands */
extern const vshCmdOptDef opts_help[];
extern const vshCmdInfo info_help[];
extern const vshCmdOptDef opts_cd[];
extern const vshCmdInfo info_cd[];
extern const vshCmdOptDef opts_echo[];
extern const vshCmdInfo info_echo[];
extern const vshCmdInfo info_pwd[];
extern const vshCmdInfo info_quit[];
extern const vshCmdOptDef opts_selftest[];
extern const vshCmdInfo info_selftest[];
extern const vshCmdOptDef opts_complete[];
extern const vshCmdInfo info_complete[];

bool cmdHelp(vshControl *ctl, const vshCmd *cmd);
bool cmdCd(vshControl *ctl, const vshCmd *cmd);
bool cmdEcho(vshControl *ctl, const vshCmd *cmd);
bool cmdPwd(vshControl *ctl, const vshCmd *cmd);
bool cmdQuit(vshControl *ctl, const vshCmd *cmd);
bool cmdSelfTest(vshControl *ctl, const vshCmd *cmd);
bool cmdComplete(vshControl *ctl, const vshCmd *cmd);

#define VSH_CMD_CD \
    { \
        .name = "cd", \
        .handler = cmdCd, \
        .opts = opts_cd, \
        .info = info_cd, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_ECHO \
    { \
        .name = "echo", \
        .handler = cmdEcho, \
        .opts = opts_echo, \
        .info = info_echo, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_EXIT \
    { \
        .name = "exit", \
        .handler = cmdQuit, \
        .opts = NULL, \
        .info = info_quit, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_HELP \
    { \
        .name = "help", \
        .handler = cmdHelp, \
        .opts = opts_help, \
        .info = info_help, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_PWD \
    { \
        .name = "pwd", \
        .handler = cmdPwd, \
        .opts = NULL, \
        .info = info_pwd, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_QUIT \
    { \
        .name = "quit", \
        .handler = cmdQuit, \
        .opts = NULL, \
        .info = info_quit, \
        .flags = VSH_CMD_FLAG_NOCONNECT \
    }

#define VSH_CMD_SELF_TEST \
    { \
        .name = "self-test", \
        .handler = cmdSelfTest, \
        .opts = opts_selftest, \
        .info = info_selftest, \
        .flags = VSH_CMD_FLAG_NOCONNECT | VSH_CMD_FLAG_HIDDEN, \
    }

#define VSH_CMD_COMPLETE \
    { \
        .name = "complete", \
        .handler = cmdComplete, \
        .opts = opts_complete, \
        .info = info_complete, \
        .flags = VSH_CMD_FLAG_NOCONNECT | VSH_CMD_FLAG_HIDDEN, \
    }



/* readline */
char * vshReadline(vshControl *ctl, const char *prompt);

void vshReadlineHistoryAdd(const char *cmd);

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
#define VSH_EXCLUSIVE_OPTIONS_EXPR(NAME1, EXPR1, NAME2, EXPR2) \
    if ((EXPR1) && (EXPR2)) { \
        vshError(ctl, _("Options --%1$s and --%2$s are mutually exclusive"), \
                 NAME1, NAME2); \
        return false; \
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
#define VSH_EXCLUSIVE_OPTIONS(NAME1, NAME2) \
    VSH_EXCLUSIVE_OPTIONS_EXPR(NAME1, vshCommandOptBool(cmd, NAME1), \
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
#define VSH_EXCLUSIVE_OPTIONS_VAR(VARNAME1, VARNAME2) \
    VSH_EXCLUSIVE_OPTIONS_EXPR(#VARNAME1, VARNAME1, #VARNAME2, VARNAME2)

/* Macros to help dealing with alternative mutually exclusive options. */

/* VSH_ALTERNATIVE_OPTIONS_EXPR:
 *
 * @NAME1: String containing the name of the option.
 * @EXPR1: Expression to validate the variable (must evaluate to bool).
 * @NAME2: String containing the name of the option.
 * @EXPR2: Expression to validate the variable (must evaluate to bool).
 *
 * Require exactly one of the command options in virsh. Use the provided
 * expression to check the variables.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VSH_ALTERNATIVE_OPTIONS_EXPR(NAME1, EXPR1, NAME2, EXPR2) \
    do { \
        bool _expr1 = EXPR1; \
        bool _expr2 = EXPR2; \
        VSH_EXCLUSIVE_OPTIONS_EXPR(NAME1, _expr1, NAME2, _expr2); \
        if (!_expr1 && !_expr2) { \
           vshError(ctl, _("Either --%1$s or --%2$s must be provided"), \
                    NAME1, NAME2); \
           return false; \
        } \
    } while (0)

/* Macros to help dealing with required options. */

/* VSH_REQUIRE_OPTION_EXPR:
 *
 * @NAME1: String containing the name of the option.
 * @EXPR1: Expression to validate the variable (boolean variable).
 * @NAME2: String containing the name of required option.
 * @EXPR2: Expression to validate the variable (boolean variable).
 *
 * Check if required command options in virsh was set.  Use the
 * provided expression to check the variables.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VSH_REQUIRE_OPTION_EXPR(NAME1, EXPR1, NAME2, EXPR2) \
    do { \
        if ((EXPR1) && !(EXPR2)) { \
            vshError(ctl, _("Option --%1$s is required by option --%2$s"), \
                     NAME2, NAME1); \
            return false; \
        } \
    } while (0)

/* VSH_REQUIRE_OPTION:
 *
 * @NAME1: String containing the name of the option.
 * @NAME2: String containing the name of required option.
 *
 * Check if required command options in virsh was set.  Use the
 * vshCommandOptBool call to request them.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VSH_REQUIRE_OPTION(NAME1, NAME2) \
    VSH_REQUIRE_OPTION_EXPR(NAME1, vshCommandOptBool(cmd, NAME1), \
                            NAME2, vshCommandOptBool(cmd, NAME2))

/* VSH_REQUIRE_OPTION_VAR:
 *
 * @VARNAME1: Boolean variable containing the value of the option of same name.
 * @VARNAME2: Boolean variable containing the value of required option of
 *            same name.
 *
 * Check if required command options in virsh was set.  Check in variables
 * that contain the value and have same name as the option.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VSH_REQUIRE_OPTION_VAR(VARNAME1, VARNAME2) \
    VSH_REQUIRE_OPTION_EXPR(#VARNAME1, VARNAME1, #VARNAME2, VARNAME2)
