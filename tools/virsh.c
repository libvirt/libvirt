/*
 * virsh.c: a shell to exercise the libvirt API
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
 *
 * Daniel Veillard <veillard@redhat.com>
 * Karel Zak <kzak@redhat.com>
 * Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "virsh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <signal.h>

#if WITH_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#endif

#include "internal.h"
#include "virerror.h"
#include "virbuffer.h"
#include "viralloc.h"
#include <libvirt/libvirt-qemu.h>
#include <libvirt/libvirt-lxc.h>
#include "virfile.h"
#include "virthread.h"
#include "vircommand.h"
#include "conf/domain_conf.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virgettext.h"

#include "virsh-console.h"
#include "virsh-domain.h"
#include "virsh-domain-monitor.h"
#include "virsh-host.h"
#include "virsh-interface.h"
#include "virsh-network.h"
#include "virsh-nodedev.h"
#include "virsh-nwfilter.h"
#include "virsh-pool.h"
#include "virsh-secret.h"
#include "virsh-snapshot.h"
#include "virsh-volume.h"

/* Gnulib doesn't guarantee SA_SIGINFO support.  */
#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

static char *progname;

static const vshCmdGrp cmdGroups[];
static const vshClientHooks hooks;

/*
 * Detection of disconnections and automatic reconnection support
 */
static int disconnected; /* we may have been disconnected */

/*
 * virshCatchDisconnect:
 *
 * We get here when the connection was closed.  We can't do much in the
 * handler, just save the fact it was raised.
 */
static void
virshCatchDisconnect(virConnectPtr conn,
                     int reason,
                     void *opaque)
{
    if (reason != VIR_CONNECT_CLOSE_REASON_CLIENT) {
        vshControl *ctl = opaque;
        const char *str = "unknown reason";
        virErrorPtr error;
        char *uri;

        error = virSaveLastError();
        uri = virConnectGetURI(conn);

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
        VIR_FREE(uri);

        if (error) {
            virSetError(error);
            virFreeError(error);
        }
        disconnected++;
        vshEventDone(ctl);
    }
}

/* Main Function which should be used for connecting.
 * This function properly handles keepalive settings. */
virConnectPtr
virshConnect(vshControl *ctl, const char *uri, bool readonly)
{
    virConnectPtr c = NULL;
    int interval = 5; /* Default */
    int count = 6;    /* Default */
    bool keepalive_forced = false;
    virPolkitAgentPtr pkagent = NULL;
    int authfail = 0;

    if (ctl->keepalive_interval >= 0) {
        interval = ctl->keepalive_interval;
        keepalive_forced = true;
    }
    if (ctl->keepalive_count >= 0) {
        count = ctl->keepalive_count;
        keepalive_forced = true;
    }

    do {
        virErrorPtr err;

        if ((c = virConnectOpenAuth(uri, virConnectAuthPtrDefault,
                                    readonly ? VIR_CONNECT_RO : 0)))
            break;

        if (readonly)
            goto cleanup;

        err = virGetLastError();
        if (err && err->domain == VIR_FROM_POLKIT &&
            err->code == VIR_ERR_AUTH_UNAVAILABLE) {
            if (!pkagent && !(pkagent = virPolkitAgentCreate()))
                goto cleanup;
        } else if (err && err->domain == VIR_FROM_POLKIT &&
                   err->code == VIR_ERR_AUTH_FAILED) {
            authfail++;
        } else {
            goto cleanup;
        }
        virResetLastError();
        /* Failure to authenticate 5 times should be enough.
         * No sense prolonging the agony.
         */
    } while (authfail < 5);

    if (!c)
        goto cleanup;

    if (interval > 0 &&
        virConnectSetKeepAlive(c, interval, count) != 0) {
        if (keepalive_forced) {
            vshError(ctl, "%s",
                     _("Cannot setup keepalive on connection "
                       "as requested, disconnecting"));
            virConnectClose(c);
            c = NULL;
            goto cleanup;
        }
        vshDebug(ctl, VSH_ERR_INFO, "%s",
                 _("Failed to setup keepalive on connection\n"));
    }

 cleanup:
    virPolkitAgentDestroy(pkagent);
    return c;
}

/*
 * virshReconnect:
 *
 * Reconnect after a disconnect from libvirtd
 *
 */
static int
virshReconnect(vshControl *ctl, const char *name, bool readonly, bool force)
{
    bool connected = false;
    virshControlPtr priv = ctl->privData;
    bool ro = name ? readonly : priv->readonly;

    if (priv->conn) {
        int ret;
        connected = true;

        virConnectUnregisterCloseCallback(priv->conn, virshCatchDisconnect);
        ret = virConnectClose(priv->conn);
        if (ret < 0)
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
        else if (ret > 0)
            vshError(ctl, "%s", _("One or more references were leaked after "
                                  "disconnect from the hypervisor"));
    }

    priv->conn = virshConnect(ctl, name ? name : ctl->connname, ro);

    if (!priv->conn) {
        if (disconnected)
            vshError(ctl, "%s", _("Failed to reconnect to the hypervisor"));
        else
            vshError(ctl, "%s", _("failed to connect to the hypervisor"));
        return -1;
    } else {
        if (name) {
            VIR_FREE(ctl->connname);
            ctl->connname = vshStrdup(ctl, name);
            priv->readonly = readonly;
        }
        if (virConnectRegisterCloseCallback(priv->conn, virshCatchDisconnect,
                                            ctl, NULL) < 0)
            vshError(ctl, "%s", _("Unable to register disconnect callback"));
        if (connected && !force)
            vshError(ctl, "%s", _("Reconnected to the hypervisor"));
    }
    disconnected = 0;
    priv->useGetInfo = false;
    priv->useSnapshotOld = false;
    priv->blockJobNoBytes = false;
    return 0;
}

/* ---------------
 * Command Connect
 * ---------------
 */

static const vshCmdOptDef opts_connect[] = {
    {.name = "name",
     .type = VSH_OT_STRING,
     .flags = VSH_OFLAG_EMPTY_OK,
     .help = N_("hypervisor connection URI")
    },
    {.name = "readonly",
     .type = VSH_OT_BOOL,
     .help = N_("read-only connection")
    },
    {.name = NULL}
};

static const vshCmdInfo info_connect[] = {
    {.name = "help",
     .data = N_("(re)connect to hypervisor")
    },
    {.name = "desc",
     .data = N_("Connect to local hypervisor. This is built-in "
                "command after shell start up.")
    },
    {.name = NULL}
};

static bool
cmdConnect(vshControl *ctl, const vshCmd *cmd)
{
    bool ro = vshCommandOptBool(cmd, "readonly");
    const char *name = NULL;

    if (vshCommandOptStringReq(ctl, cmd, "name", &name) < 0)
        return false;

    if (virshReconnect(ctl, name, ro, true) < 0)
        return false;

    return true;
}

/* ---------------
 * Utils for work with runtime commands data
 * ---------------
 */

static bool
virshConnectionUsability(vshControl *ctl, virConnectPtr conn)
{
    if (!conn ||
        virConnectIsAlive(conn) == 0) {
        vshError(ctl, "%s", _("no valid connection"));
        return false;
    }

    /* The connection is considered dead only if
     * virConnectIsAlive() successfuly says so.
     */
    vshResetLibvirtError();

    return true;
}

static void *
virshConnectionHandler(vshControl *ctl)
{
    virshControlPtr priv = ctl->privData;

    if ((!priv->conn || disconnected) &&
        virshReconnect(ctl, NULL, false, false) < 0)
        return NULL;

    if (virshConnectionUsability(ctl, priv->conn))
        return priv->conn;

    return NULL;
}


/*
 * Initialize connection.
 */
static bool
virshInit(vshControl *ctl)
{
    virshControlPtr priv = ctl->privData;

    /* Since we have the commandline arguments parsed, we need to
     * reload our initial settings to make debugging and readline
     * work properly */
    vshInitReload(ctl);

    if (priv->conn)
        return false;

    /* set up the library error handler */
    virSetErrorFunc(NULL, vshErrorHandler);

    if (virEventRegisterDefaultImpl() < 0) {
        vshReportError(ctl);
        return false;
    }

    if (virThreadCreate(&ctl->eventLoop, true, vshEventLoop, ctl) < 0) {
        vshReportError(ctl);
        return false;
    }
    ctl->eventLoopStarted = true;

    if ((ctl->eventTimerId = virEventAddTimeout(-1, vshEventTimeout, ctl,
                                                NULL)) < 0) {
        vshReportError(ctl);
        return false;
    }

    if (ctl->connname) {
        /* Connecting to a named connection must succeed, but we delay
         * connecting to the default connection until we need it
         * (since the first command might be 'connect' which allows a
         * non-default connection, or might be 'help' which needs no
         * connection).
         */
        if (virshReconnect(ctl, NULL, false, false) < 0) {
            vshReportError(ctl);
            return false;
        }
    }

    return true;
}

static void
virshDeinitTimer(int timer ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}

/*
 * Deinitialize virsh
 */
static bool
virshDeinit(vshControl *ctl)
{
    virshControlPtr priv = ctl->privData;

    vshDeinit(ctl);
    VIR_FREE(ctl->connname);
    if (priv->conn) {
        int ret;
        virConnectUnregisterCloseCallback(priv->conn, virshCatchDisconnect);
        ret = virConnectClose(priv->conn);
        if (ret < 0)
            vshError(ctl, "%s", _("Failed to disconnect from the hypervisor"));
        else if (ret > 0)
            vshError(ctl, "%s", _("One or more references were leaked after "
                                  "disconnect from the hypervisor"));
    }
    virResetLastError();

    if (ctl->eventLoopStarted) {
        int timer;

        virMutexLock(&ctl->lock);
        ctl->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, virshDeinitTimer, NULL, NULL);
        virMutexUnlock(&ctl->lock);

        virThreadJoin(&ctl->eventLoop);

        if (timer != -1)
            virEventRemoveTimeout(timer);

        if (ctl->eventTimerId != -1)
            virEventRemoveTimeout(ctl->eventTimerId);

        ctl->eventLoopStarted = false;
    }

    virMutexDestroy(&ctl->lock);

    return true;
}

/*
 * Print usage
 */
static void
virshUsage(void)
{
    const vshCmdGrp *grp;
    const vshCmdDef *cmd;

    fprintf(stdout, _("\n%s [options]... [<command_string>]"
                      "\n%s [options]... <command> [args...]\n\n"
                      "  options:\n"
                      "    -c | --connect=URI      hypervisor connection URI\n"
                      "    -d | --debug=NUM        debug level [0-4]\n"
                      "    -e | --escape <char>    set escape sequence for console\n"
                      "    -h | --help             this help\n"
                      "    -k | --keepalive-interval=NUM\n"
                      "                            keepalive interval in seconds, 0 for disable\n"
                      "    -K | --keepalive-count=NUM\n"
                      "                            number of possible missed keepalive messages\n"
                      "    -l | --log=FILE         output logging to file\n"
                      "    -q | --quiet            quiet mode\n"
                      "    -r | --readonly         connect readonly\n"
                      "    -t | --timing           print timing information\n"
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
virshShowVersion(vshControl *ctl ATTRIBUTE_UNUSED)
{
    /* FIXME - list a copyright blurb, as in GNU programs?  */
    vshPrint(ctl, _("Virsh command line tool of libvirt %s\n"), VERSION);
    vshPrint(ctl, _("See web site at %s\n\n"), "http://libvirt.org/");

    vshPrint(ctl, "%s", _("Compiled with support for:\n"));
    vshPrint(ctl, "%s", _(" Hypervisors:"));
#ifdef WITH_QEMU
    vshPrint(ctl, " QEMU/KVM");
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
#ifdef WITH_VZ
    vshPrint(ctl, " Virtuozzo");
#endif
#ifdef WITH_VMWARE
    vshPrint(ctl, " VMware");
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
#ifdef WITH_BHYVE
    vshPrint(ctl, " Bhyve");
#endif
#ifdef WITH_TEST
    vshPrint(ctl, " Test");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Networking:"));
#ifdef WITH_REMOTE
    vshPrint(ctl, " Remote");
#endif
#ifdef WITH_NETWORK
    vshPrint(ctl, " Network");
#endif
#ifdef WITH_BRIDGE
    vshPrint(ctl, " Bridging");
#endif
#if defined(WITH_INTERFACE)
    vshPrint(ctl, " Interface");
# if defined(WITH_NETCF)
    vshPrint(ctl, " netcf");
# elif defined(WITH_UDEV)
    vshPrint(ctl, " udev");
# endif
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
#ifdef WITH_STORAGE_GLUSTER
    vshPrint(ctl, " Gluster");
#endif
#ifdef WITH_STORAGE_ZFS
    vshPrint(ctl, " ZFS");
#endif
#ifdef WITH_STORAGE_VSTORAGE
    vshPrint(ctl, "Virtuozzo Storage");
#endif
    vshPrint(ctl, "\n");

    vshPrint(ctl, "%s", _(" Miscellaneous:"));
#ifdef WITH_LIBVIRTD
    vshPrint(ctl, " Daemon");
#endif
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
#if WITH_READLINE
    vshPrint(ctl, " Readline");
#endif
#ifdef WITH_DRIVER_MODULES
    vshPrint(ctl, " Modular");
#endif
    vshPrint(ctl, "\n");
}

static bool
virshAllowedEscapeChar(char c)
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
virshParseArgv(vshControl *ctl, int argc, char **argv)
{
    int arg, len, debug, keepalive;
    size_t i;
    int longindex = -1;
    virshControlPtr priv = ctl->privData;
    struct option opt[] = {
        {"connect", required_argument, NULL, 'c'},
        {"debug", required_argument, NULL, 'd'},
        {"escape", required_argument, NULL, 'e'},
        {"help", no_argument, NULL, 'h'},
        {"keepalive-interval", required_argument, NULL, 'k'},
        {"keepalive-count", required_argument, NULL, 'K'},
        {"log", required_argument, NULL, 'l'},
        {"quiet", no_argument, NULL, 'q'},
        {"readonly", no_argument, NULL, 'r'},
        {"timing", no_argument, NULL, 't'},
        {"version", optional_argument, NULL, 'v'},
        {NULL, 0, NULL, 0}
    };

    /* Standard (non-command) options. The leading + ensures that no
     * argument reordering takes place, so that command options are
     * not confused with top-level virsh options. */
    while ((arg = getopt_long(argc, argv, "+:c:d:e:hk:K:l:qrtvV", opt, &longindex)) != -1) {
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
        case 'e':
            len = strlen(optarg);

            if ((len == 2 && *optarg == '^' &&
                 virshAllowedEscapeChar(optarg[1])) ||
                (len == 1 && *optarg != '^')) {
                priv->escapeChar = optarg;
            } else {
                vshError(ctl, _("Invalid string '%s' for escape sequence"),
                         optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            virshUsage();
            exit(EXIT_SUCCESS);
            break;
        case 'k':
            if (virStrToLong_i(optarg, NULL, 0, &keepalive) < 0) {
                vshError(ctl,
                         _("Invalid value for option %s"),
                         longindex == -1 ? "-k" : "--keepalive-interval");
                exit(EXIT_FAILURE);
            }

            if (keepalive < 0) {
                vshError(ctl,
                         _("option %s requires a positive integer argument"),
                         longindex == -1 ? "-k" : "--keepalive-interval");
                exit(EXIT_FAILURE);
            }
            ctl->keepalive_interval = keepalive;
            break;
        case 'K':
            if (virStrToLong_i(optarg, NULL, 0, &keepalive) < 0) {
                vshError(ctl,
                         _("Invalid value for option %s"),
                         longindex == -1 ? "-K" : "--keepalive-count");
                exit(EXIT_FAILURE);
            }

            if (keepalive < 0) {
                vshError(ctl,
                         _("option %s requires a positive integer argument"),
                         longindex == -1 ? "-K" : "--keepalive-count");
                exit(EXIT_FAILURE);
            }
            ctl->keepalive_count = keepalive;
            break;
        case 'l':
            vshCloseLogFile(ctl);
            ctl->logfile = vshStrdup(ctl, optarg);
            vshOpenLogFile(ctl);
            break;
        case 'q':
            ctl->quiet = true;
            break;
        case 't':
            ctl->timing = true;
            break;
        case 'r':
            priv->readonly = true;
            break;
        case 'v':
            if (STRNEQ_NULLABLE(optarg, "long")) {
                puts(VERSION);
                exit(EXIT_SUCCESS);
            }
            /* fall through */
        case 'V':
            virshShowVersion(ctl);
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

static const vshCmdDef virshCmds[] = {
    VSH_CMD_CD,
    VSH_CMD_ECHO,
    VSH_CMD_EXIT,
    VSH_CMD_HELP,
    VSH_CMD_PWD,
    VSH_CMD_QUIT,
    VSH_CMD_SELF_TEST,
    {.name = "connect",
     .handler = cmdConnect,
     .opts = opts_connect,
     .info = info_connect,
     .flags = VSH_CMD_FLAG_NOCONNECT
    },
    {.name = NULL}
};

static const vshCmdGrp cmdGroups[] = {
    {VIRSH_CMD_GRP_DOM_MANAGEMENT, "domain", domManagementCmds},
    {VIRSH_CMD_GRP_DOM_MONITORING, "monitor", domMonitoringCmds},
    {VIRSH_CMD_GRP_HOST_AND_HV, "host", hostAndHypervisorCmds},
    {VIRSH_CMD_GRP_IFACE, "interface", ifaceCmds},
    {VIRSH_CMD_GRP_NWFILTER, "filter", nwfilterCmds},
    {VIRSH_CMD_GRP_NETWORK, "network", networkCmds},
    {VIRSH_CMD_GRP_NODEDEV, "nodedev", nodedevCmds},
    {VIRSH_CMD_GRP_SECRET, "secret", secretCmds},
    {VIRSH_CMD_GRP_SNAPSHOT, "snapshot", snapshotCmds},
    {VIRSH_CMD_GRP_STORAGE_POOL, "pool", storagePoolCmds},
    {VIRSH_CMD_GRP_STORAGE_VOL, "volume", storageVolCmds},
    {VIRSH_CMD_GRP_VIRSH, "virsh", virshCmds},
    {NULL, NULL, NULL}
};

static const vshClientHooks hooks = {
    .connHandler = virshConnectionHandler
};

int
main(int argc, char **argv)
{
    vshControl _ctl, *ctl = &_ctl;
    virshControl virshCtl;
    bool ret = true;

    memset(ctl, 0, sizeof(vshControl));
    memset(&virshCtl, 0, sizeof(virshControl));
    ctl->name = "virsh";        /* hardcoded name of the binary */
    ctl->env_prefix = "VIRSH";
    ctl->log_fd = -1;           /* Initialize log file descriptor */
    ctl->debug = VSH_DEBUG_DEFAULT;
    ctl->hooks = &hooks;

    /* In order to distinguish default from setting to 0 */
    ctl->keepalive_interval = -1;
    ctl->keepalive_count = -1;

    ctl->eventPipe[0] = -1;
    ctl->eventPipe[1] = -1;
    ctl->eventTimerId = -1;
    virshCtl.escapeChar = "^]";     /* Same default as telnet */
    ctl->privData = &virshCtl;

    if (!(progname = strrchr(argv[0], '/')))
        progname = argv[0];
    else
        progname++;
    ctl->progname = progname;

    if (virGettextInitialize() < 0)
        return EXIT_FAILURE;

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

    if (virInitialize() < 0) {
        vshError(ctl, "%s", _("Failed to initialize libvirt"));
        return EXIT_FAILURE;
    }

    virFileActivateDirOverride(argv[0]);

    if (!vshInit(ctl, cmdGroups, NULL))
        exit(EXIT_FAILURE);

    if (!virshParseArgv(ctl, argc, argv) ||
        !virshInit(ctl)) {
        virshDeinit(ctl);
        exit(EXIT_FAILURE);
    }

    if (!ctl->connname)
        ctl->connname = vshStrdup(ctl,
                                  virGetEnvBlockSUID("VIRSH_DEFAULT_CONNECT_URI"));

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

        do {
            const char *prompt = virshCtl.readonly ? VIRSH_PROMPT_RO
                : VIRSH_PROMPT_RW;
            ctl->cmdstr =
                vshReadline(ctl, prompt);
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

    virshDeinit(ctl);
    exit(ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
