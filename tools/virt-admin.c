/*
 * virt-admin.c: a shell to exercise the libvirt admin API
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
 * Authors:
 *     Erik Skultety <eskultet@redhat.com>
 */

#include <config.h>
#include "virt-admin.h"

#include <errno.h>
#include <getopt.h>
#include <locale.h>

#if WITH_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "configmake.h"
#include "internal.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "virthread.h"

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#define VIRT_ADMIN_PROMPT "virt-admin # "

static char *progname;

static const vshCmdGrp cmdGroups[];
static const vshClientHooks hooks;

/*
 * vshAdmCatchDisconnect:
 *
 * We get here when the connection was closed. Unlike virsh, we do not save
 * the fact that the event was raised, sice there is virAdmConnectIsAlive to
 * check if the communication channel has not been closed by remote party.
 */
static void
vshAdmCatchDisconnect(virAdmConnectPtr conn ATTRIBUTE_UNUSED,
                      int reason,
                      void *opaque)
{
    vshControl *ctl = opaque;
    const char *str = "unknown reason";
    virErrorPtr error;
    char *uri = NULL;

    if (reason == VIR_CONNECT_CLOSE_REASON_CLIENT)
        return;

    error = virSaveLastError();
    uri = virAdmConnectGetURI(conn);

    switch ((virConnectCloseReason) reason) {
    case VIR_CONNECT_CLOSE_REASON_ERROR:
        str = N_("Disconnected from %s due to I/O error");
        break;
    case VIR_CONNECT_CLOSE_REASON_EOF:
        str = N_("Disconnected from %s due to end of file");
        break;
    case VIR_CONNECT_CLOSE_REASON_KEEPALIVE:
        str = N_("Disconnected from %s due to keepalive timeout");
        break;
        /* coverity[dead_error_condition] */
    case VIR_CONNECT_CLOSE_REASON_CLIENT:
    case VIR_CONNECT_CLOSE_REASON_LAST:
        break;
    }

    vshError(ctl, _(str), NULLSTR(uri));

    if (error) {
        virSetError(error);
        virFreeError(error);
    }
}

static int
vshAdmConnect(vshControl *ctl, unsigned int flags)
{
    vshAdmControlPtr priv = ctl->privData;

    priv->conn = virAdmConnectOpen(ctl->connname, flags);

    if (!priv->conn) {
        if (priv->wantReconnect)
            vshError(ctl, "%s", _("Failed to reconnect to the admin server"));
        else
            vshError(ctl, "%s", _("Failed to connect to the admin server"));
        return -1;
    } else {
        if (virAdmConnectRegisterCloseCallback(priv->conn, vshAdmCatchDisconnect,
                                               NULL, NULL) < 0)
            vshError(ctl, "%s", _("Unable to register disconnect callback"));

        if (priv->wantReconnect)
            vshPrint(ctl, "%s\n", _("Reconnected to the admin server"));
        else
            vshPrint(ctl, "%s\n", _("Connected to the admin server"));
    }

    return 0;
}

static int
vshAdmDisconnect(vshControl *ctl)
{
    int ret = 0;
    vshAdmControlPtr priv = ctl->privData;

    if (!priv->conn)
        return ret;

    virAdmConnectUnregisterCloseCallback(priv->conn, vshAdmCatchDisconnect);
    ret = virAdmConnectClose(priv->conn);
    if (ret < 0)
        vshError(ctl, "%s", _("Failed to disconnect from the admin server"));
    else if (ret > 0)
        vshError(ctl, "%s", _("One or more references were leaked after "
                              "disconnect from the hypervisor"));
    priv->conn = NULL;
    return ret;
}

/*
 * vshAdmReconnect:
 *
 * Reconnect to a daemon's admin server
 *
 */
static void
vshAdmReconnect(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;
    if (priv->conn)
        priv->wantReconnect = true;

    vshAdmDisconnect(ctl);
    vshAdmConnect(ctl, 0);

    priv->wantReconnect = false;
}

/*
 * 'uri' command
 */

static const vshCmdInfo info_uri[] = {
    {.name = "help",
     .data = N_("print the admin server URI")
    },
    {.name = "desc",
     .data = ""
    },
    {.name = NULL}
};

static bool
cmdURI(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    char *uri;
    vshAdmControlPtr priv = ctl->privData;

    uri = virAdmConnectGetURI(priv->conn);
    if (!uri) {
        vshError(ctl, "%s", _("failed to get URI"));
        return false;
    }

    vshPrint(ctl, "%s\n", uri);
    VIR_FREE(uri);

    return true;
}

/*
 * "version" command
 */

static const vshCmdInfo info_version[] = {
    {.name = "help",
     .data = N_("show version")
    },
    {.name = "desc",
     .data = N_("Display the system and also the daemon version information.")
    },
    {.name = NULL}
};

static bool
cmdVersion(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    unsigned long libVersion;
    unsigned long long includeVersion;
    unsigned long long daemonVersion;
    int ret;
    unsigned int major;
    unsigned int minor;
    unsigned int rel;
    vshAdmControlPtr priv = ctl->privData;

    includeVersion = LIBVIR_VERSION_NUMBER;
    major = includeVersion / 1000000;
    includeVersion %= 1000000;
    minor = includeVersion / 1000;
    rel = includeVersion % 1000;
    vshPrint(ctl, _("Compiled against library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    ret = virGetVersion(&libVersion, NULL, NULL);
    if (ret < 0) {
        vshError(ctl, "%s", _("failed to get the library version"));
        return false;
    }
    major = libVersion / 1000000;
    libVersion %= 1000000;
    minor = libVersion / 1000;
    rel = libVersion % 1000;
    vshPrint(ctl, _("Using library: libvirt %d.%d.%d\n"),
             major, minor, rel);

    ret = virAdmConnectGetLibVersion(priv->conn, &daemonVersion);
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

    return true;
}


/* ---------------
 * Command Connect
 * ---------------
 */

static const vshCmdOptDef opts_connect[] = {
    {.name = "name",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("daemon's admin server connection URI")
    },
    {.name = NULL}
};

static const vshCmdInfo info_connect[] = {
    {.name = "help",
     .data = N_("connect to daemon's admin server")
    },
    {.name = "desc",
     .data = N_("Connect to a daemon's administrating server.")
    },
    {.name = NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    const char *name = NULL;
    vshAdmControlPtr priv = ctl->privData;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    VIR_FREE(ctl->connname);
    ctl->connname = vshStrdup(ctl, name);

    vshAdmReconnect(ctl);

    return !!priv->conn;
}


/* ---------------
 * Command srv-list
 * ---------------
 */

static const vshCmdInfo info_srv_list[] = {
    {.name = "help",
     .data = N_("list available servers on a daemon")
    },
    {.name = "desc",
     .data = N_("List all manageable servers on a daemon.")
    },
    {.name = NULL}
};

static bool
cmdSrvList(vshControl *ctl, const vshCmd *cmd ATTRIBUTE_UNUSED)
{
    int nsrvs = 0;
    size_t i;
    bool ret = false;
    const char *uri = NULL;
    virAdmServerPtr *srvs = NULL;
    vshAdmControlPtr priv = ctl->privData;

    /* Obtain a list of available servers on the daemon */
    if ((nsrvs = virAdmConnectListServers(priv->conn, &srvs, 0)) < 0) {
        uri = virAdmConnectGetURI(priv->conn);
        vshError(ctl, _("failed to obtain list of available servers from %s"),
                 NULLSTR(uri));
        goto cleanup;
    }

    printf(" %-5s %-15s\n", "Id", "Name");
    printf("---------------\n");
    for (i = 0; i < nsrvs; i++)
        vshPrint(ctl, " %-5zu %-15s\n", i, virAdmServerGetName(srvs[i]));

    ret = true;
 cleanup:
    if (srvs) {
        for (i = 0; i < nsrvs; i++)
            virAdmServerFree(srvs[i]);
        VIR_FREE(srvs);
    }

    return ret;
}

static void *
vshAdmConnectionHandler(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    if (!virAdmConnectIsAlive(priv->conn))
        vshAdmReconnect(ctl);

    if (!virAdmConnectIsAlive(priv->conn)) {
        vshError(ctl, "%s", _("no valid connection"));
        return NULL;
    }

    return priv->conn;
}

/*
 * Initialize connection.
 */
static bool
vshAdmInit(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    /* Since we have the commandline arguments parsed, we need to
     * reload our initial settings to make debugging and readline
     * work properly */
    vshInitReload(ctl);

    if (priv->conn)
        return false;

    /* set up the library error handler */
    virSetErrorFunc(NULL, vshErrorHandler);

    if (virEventRegisterDefaultImpl() < 0)
        return false;

    if (virThreadCreate(&ctl->eventLoop, true, vshEventLoop, ctl) < 0)
        return false;
    ctl->eventLoopStarted = true;

    if (ctl->connname) {
        vshAdmReconnect(ctl);
        /* Connecting to a named connection must succeed, but we delay
         * connecting to the default connection until we need it
         * (since the first command might be 'connect' which allows a
         * non-default connection, or might be 'help' which needs no
         * connection).
         */
        if (!priv->conn) {
            vshReportError(ctl);
            return false;
        }
    }

    return true;
}

static void
vshAdmDeinitTimer(int timer ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}

/*
 * Deinitialize virt-admin
 */
static void
vshAdmDeinit(vshControl *ctl)
{
    vshAdmControlPtr priv = ctl->privData;

    vshDeinit(ctl);
    VIR_FREE(ctl->connname);

    if (priv->conn)
        vshAdmDisconnect(ctl);

    virResetLastError();

    if (ctl->eventLoopStarted) {
        int timer;

        virMutexLock(&ctl->lock);
        ctl->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, vshAdmDeinitTimer, NULL, NULL);
        virMutexUnlock(&ctl->lock);

        virThreadJoin(&ctl->eventLoop);

        if (timer != -1)
            virEventRemoveTimeout(timer);

        ctl->eventLoopStarted = false;
    }

    virMutexDestroy(&ctl->lock);
}

/*
 * Print usage
 */
static void
vshAdmUsage(void)
{
    const vshCmdGrp *grp;
    const vshCmdDef *cmd;

    fprintf(stdout, _("\n%s [options]... [<command_string>]"
                      "\n%s [options]... <command> [args...]\n\n"
                      "  options:\n"
                      "    -c | --connect=URI      daemon admin connection URI\n"
                      "    -d | --debug=NUM        debug level [0-4]\n"
                      "    -h | --help             this help\n"
                      "    -l | --log=FILE         output logging to file\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -v                      short version\n"
                      "    -V                      long version\n"
                      "         --version[=TYPE]   version, TYPE is short or long (default short)\n"
                      "  commands (non interactive mode):\n\n"), progname,
            progname);

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
vshAdmShowVersion(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* FIXME - list a copyright blurb, as in GNU programs?  */
    vshPrint(ctl, _("Virt-admin command line tool of libvirt %s\n"), VERSION);
    vshPrint(ctl, _("See web site at %s\n\n"), "http://libvirt.org/");

    vshPrint(ctl, "%s", _("Compiled with support for:"));
#ifdef WITH_LIBVIRTD
    vshPrint(ctl, " Daemon");
#endif
#ifdef ENABLE_DEBUG
    vshPrint(ctl, " Debug");
#endif
#if WITH_READLINE
    vshPrint(ctl, " Readline");
#endif
    vshPrint(ctl, "\n");
}

static bool
vshAdmParseArgv(vshControl *ctl, int argc, char **argv)
{
    int arg, debug;
    size_t i;
    int longindex = -1;
    struct option opt[] = {
        {"connect", required_argument, NULL, 'c'},
        {"debug", required_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"log", required_argument, NULL, 'l'},
        {"quiet", no_argument, NULL, 'q'},
        {"version", optional_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };

    /* Standard (non-command) options. The leading + ensures that no
     * argument reordering takes place, so that command options are
     * not confused with top-level virt-admin options. */
    while ((arg = getopt_long(argc, argv, "+:c:d:hl:qvV", opt, &longindex)) != -1) {
        switch (arg) {
        case 'c':
            VIR_FREE(ctl->connname);
            ctl->connname = vshStrdup(ctl, optarg);
            break;
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
            vshAdmUsage();
            exit(EXIT_SUCCESS);
            break;
        case 'l':
            vshCloseLogFile(ctl);
            ctl->logfile = vshStrdup(ctl, optarg);
            vshOpenLogFile(ctl);
            break;
        case 'q':
            ctl->quiet = true;
            break;
        case 'v':
            if (STRNEQ_NULLABLE(optarg, "long")) {
                puts(VERSION);
                exit(EXIT_SUCCESS);
            }
            /* fall through */
        case 'V':
            vshAdmShowVersion(ctl);
            exit(EXIT_SUCCESS);
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

    if (argc == optind) {
        ctl->imode = true;
    } else {
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

static const vshCmdDef vshAdmCmds[] = {
    VSH_CMD_CD,
    VSH_CMD_ECHO,
    VSH_CMD_EXIT,
    VSH_CMD_HELP,
    VSH_CMD_PWD,
    VSH_CMD_QUIT,
    {.name = "uri",
     .handler = cmdURI,
     .opts = NULL,
     .info = info_uri,
     .flags = 0
    },
    {.name = "version",
     .handler = cmdVersion,
     .opts = NULL,
     .info = info_version,
     .flags = 0
    },
    {.name = "connect",
     .handler = cmdConnect,
     .opts = opts_connect,
     .info = info_connect,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = NULL}
};

static const vshCmdDef monitoringCmds[] = {
    {.name = "srv-list",
     .handler = cmdSrvList,
     .opts = NULL,
     .info = info_srv_list,
     .flags = 0
    },
    {.name = NULL}
};

static const vshCmdGrp cmdGroups[] = {
    {"Virt-admin itself", "virt-admin", vshAdmCmds},
    {"Monitoring commands", "monitor", monitoringCmds},
    {NULL, NULL, NULL}
};

static const vshClientHooks hooks = {
    .connHandler = vshAdmConnectionHandler
};

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    vshAdmControl virtAdminCtl;
    const char *defaultConn;
    bool ret = true;

    memset(ctl, 0, sizeof(vshControl));
    memset(&virtAdminCtl, 0, sizeof(vshAdmControl));
    ctl->name = "virt-admin";        /* hardcoded name of the binary */
    ctl->log_fd = -1;                /* Initialize log file descriptor */
    ctl->debug = VSH_DEBUG_DEFAULT;
    ctl->hooks = &hooks;

    ctl->eventPipe[0] = -1;
    ctl->eventPipe[1] = -1;
    ctl->privData = &virtAdminCtl;

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;
    ctl->progname = progname;

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

    virFileActivateDirOverride(argv[0]);

    if ((defaultConn = virGetEnvBlockSUID("LIBVIRT_DEFAULT_ADMIN_URI")))
        ctl->connname = vshStrdup(ctl, defaultConn);

    if (!vshInit(ctl, cmdGroups, NULL))
        exit(EXIT_FAILURE);

    if (!vshAdmParseArgv(ctl, argc, argv) ||
        !vshAdmInit(ctl)) {
        vshAdmDeinit(ctl);
        exit(EXIT_FAILURE);
    }

    if (!ctl->imode) {
        ret = vshCommandRun(ctl, ctl->cmd);
    } else {
        /* interactive mode */
        if (!ctl->quiet) {
            vshPrint(ctl,
                     _("Welcome to %s, the administrating virtualization "
                       "interactive terminal.\n\n"),
                     progname);
            vshPrint(ctl, "%s",
                     _("Type:  'help' for help with commands\n"
                       "       'quit' to quit\n\n"));
        }

        do {
            ctl->cmdstr = vshReadline(ctl, VIRT_ADMIN_PROMPT);
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

    vshAdmDeinit(ctl);
    exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
