/*
 * lock_daemon.c: lock management daemon
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>


#include "lock_daemon.h"
#include "lock_daemon_config.h"
#include "admin/admin_server_dispatch.h"
#include "virutil.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "rpc/virnetdaemon.h"
#include "rpc/virnetserver.h"
#include "virhash.h"
#include "viruuid.h"
#include "virstring.h"
#include "virgettext.h"
#include "virdaemon.h"

#include "locking/lock_daemon_dispatch.h"
#include "locking/lock_protocol.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_daemon");

struct _virLockDaemon {
    GMutex lock;
    virNetDaemon *dmn;
    GHashTable *lockspaces;
    virLockSpace *defaultLockspace;
};

virLockDaemon *lockDaemon = NULL;

static bool execRestart;

static void *
virLockDaemonClientNew(virNetServerClient *client,
                       void *opaque);
static void
virLockDaemonClientFree(void *opaque);

static void *
virLockDaemonClientNewPostExecRestart(virNetServerClient *client,
                                      virJSONValue *object,
                                      void *opaque);
static virJSONValue *
virLockDaemonClientPreExecRestart(virNetServerClient *client,
                                  void *opaque);

static void
virLockDaemonFree(virLockDaemon *lockd)
{
    if (!lockd)
        return;

    g_mutex_clear(&lockd->lock);
    virObjectUnref(lockd->dmn);
    g_clear_pointer(&lockd->lockspaces, g_hash_table_unref);
    virLockSpaceFree(lockd->defaultLockspace);

    g_free(lockd);
}

static inline void
virLockDaemonLock(virLockDaemon *lockd)
{
    g_mutex_lock(&lockd->lock);
}

static inline void
virLockDaemonUnlock(virLockDaemon *lockd)
{
    g_mutex_unlock(&lockd->lock);
}

static void virLockDaemonLockSpaceDataFree(void *data)
{
    virLockSpaceFree(data);
}

static virLockDaemon *
virLockDaemonNew(virLockDaemonConfig *config, bool privileged)
{
    virLockDaemon *lockd;
    virNetServer *srv = NULL;

    lockd = g_new0(virLockDaemon, 1);

    g_mutex_init(&lockd->lock);

    if (!(lockd->dmn = virNetDaemonNew()))
        goto error;

    if (!(srv = virNetServerNew("virtlockd", 1,
                                0, 0, 0, config->max_clients,
                                config->max_clients, -1, 0,
                                virLockDaemonClientNew,
                                virLockDaemonClientPreExecRestart,
                                virLockDaemonClientFree,
                                (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (virNetDaemonAddServer(lockd->dmn, srv) < 0)
        goto error;
    g_clear_pointer(&srv, virObjectUnref);

    if (!(srv = virNetServerNew("admin", 1,
                                0, 0, 0, config->admin_max_clients,
                                config->admin_max_clients, -1, 0,
                                remoteAdmClientNew,
                                remoteAdmClientPreExecRestart,
                                remoteAdmClientFree,
                                lockd->dmn)))
        goto error;

    if (virNetDaemonAddServer(lockd->dmn, srv) < 0)
         goto error;
    g_clear_pointer(&srv, virObjectUnref);

    lockd->lockspaces = virHashNew(virLockDaemonLockSpaceDataFree);

    if (!(lockd->defaultLockspace = virLockSpaceNew(NULL)))
        goto error;

    return lockd;

 error:
    virObjectUnref(srv);
    virLockDaemonFree(lockd);
    return NULL;
}


static virNetServer *
virLockDaemonNewServerPostExecRestart(virNetDaemon *dmn G_GNUC_UNUSED,
                                      const char *name,
                                      virJSONValue *object,
                                      void *opaque)
{
    if (STREQ(name, "virtlockd")) {
        return virNetServerNewPostExecRestart(object,
                                              name,
                                              virLockDaemonClientNew,
                                              virLockDaemonClientNewPostExecRestart,
                                              virLockDaemonClientPreExecRestart,
                                              virLockDaemonClientFree,
                                              opaque);
    } else if (STREQ(name, "admin")) {
        return virNetServerNewPostExecRestart(object,
                                              name,
                                              remoteAdmClientNew,
                                              remoteAdmClientNewPostExecRestart,
                                              remoteAdmClientPreExecRestart,
                                              remoteAdmClientFree,
                                              dmn);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected server name '%1$s' during restart"),
                       name);
        return NULL;
    }
}


static virLockDaemon *
virLockDaemonNewPostExecRestart(virJSONValue *object, bool privileged)
{
    virLockDaemon *lockd;
    virJSONValue *child;
    virJSONValue *lockspaces;
    size_t i;
    const char *serverNames[] = { "virtlockd" };

    lockd = g_new0(virLockDaemon, 1);

    g_mutex_init(&lockd->lock);

    lockd->lockspaces = virHashNew(virLockDaemonLockSpaceDataFree);

    if (!(child = virJSONValueObjectGet(object, "defaultLockspace"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing defaultLockspace data from JSON file"));
        goto error;
    }

    if (!(lockd->defaultLockspace =
          virLockSpaceNewPostExecRestart(child)))
        goto error;

    if (!(lockspaces = virJSONValueObjectGet(object, "lockspaces"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing lockspaces data from JSON file"));
        goto error;
    }

    if (!virJSONValueIsArray(lockspaces)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed lockspaces array"));
        goto error;
    }

    for (i = 0; i < virJSONValueArraySize(lockspaces); i++) {
        virLockSpace *lockspace;

        child = virJSONValueArrayGet(lockspaces, i);

        if (!(lockspace = virLockSpaceNewPostExecRestart(child)))
            goto error;

        if (virHashAddEntry(lockd->lockspaces,
                            virLockSpaceGetDirectory(lockspace),
                            lockspace) < 0) {
            virLockSpaceFree(lockspace);
        }
    }

    if (virJSONValueObjectHasKey(object, "daemon")) {
        if (!(child = virJSONValueObjectGet(object, "daemon"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed daemon data from JSON file"));
            goto error;
        }
    } else {
        if (!(child = virJSONValueObjectGet(object, "server"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing server data from JSON file"));
            goto error;
        }
    }

    if (!(lockd->dmn = virNetDaemonNewPostExecRestart(child,
                                                      G_N_ELEMENTS(serverNames),
                                                      serverNames,
                                                      virLockDaemonNewServerPostExecRestart,
                                                      (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    return lockd;

 error:
    virLockDaemonFree(lockd);
    return NULL;
}


int virLockDaemonAddLockSpace(virLockDaemon *lockd,
                              const char *path,
                              virLockSpace *lockspace)
{
    int ret;
    virLockDaemonLock(lockd);
    ret = virHashAddEntry(lockd->lockspaces, path, lockspace);
    virLockDaemonUnlock(lockd);
    return ret;
}

virLockSpace *virLockDaemonFindLockSpace(virLockDaemon *lockd,
                                           const char *path)
{
    virLockSpace *lockspace;
    virLockDaemonLock(lockd);
    if (path && STRNEQ(path, ""))
        lockspace = virHashLookup(lockd->lockspaces, path);
    else
        lockspace = lockd->defaultLockspace;
    virLockDaemonUnlock(lockd);
    return lockspace;
}


static void
virLockDaemonErrorHandler(void *opaque G_GNUC_UNUSED,
                          virErrorPtr err G_GNUC_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}


/* Display version information. */
static void
virLockDaemonVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

static void
virLockDaemonShutdownHandler(virNetDaemon *dmn,
                             siginfo_t *sig G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED)
{
    virNetDaemonQuit(dmn);
}

static void
virLockDaemonExecRestartHandler(virNetDaemon *dmn,
                                siginfo_t *sig G_GNUC_UNUSED,
                                void *opaque G_GNUC_UNUSED)
{
    execRestart = true;
    virNetDaemonQuitExecRestart(dmn);
}

static int
virLockDaemonSetupSignals(virNetDaemon *dmn)
{
    if (virNetDaemonAddSignalHandler(dmn, SIGINT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGQUIT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGTERM, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGUSR1, virLockDaemonExecRestartHandler, NULL) < 0)
        return -1;
    return 0;
}


struct virLockDaemonClientReleaseData {
    virLockDaemonClient *client;
    bool hadSomeLeases;
    bool gotError;
};

static int
virLockDaemonClientReleaseLockspace(void *payload,
                                    const char *name G_GNUC_UNUSED,
                                    void *opaque)
{
    virLockSpace *lockspace = payload;
    struct virLockDaemonClientReleaseData *data = opaque;
    int rc;

    rc = virLockSpaceReleaseResourcesForOwner(lockspace,
                                              data->client->clientPid);
    if (rc > 0)
        data->hadSomeLeases = true;
    else if (rc < 0)
        data->gotError = true;
    return 0;
}


static void
virLockDaemonClientFree(void *opaque)
{
    virLockDaemonClient *priv = opaque;

    if (!priv)
        return;

    VIR_DEBUG("priv=%p client=%lld owner=%lld",
              priv,
              (unsigned long long)priv->clientPid,
              (unsigned long long)priv->ownerPid);

    /* If client & owner match, this is the lock holder */
    if (priv->clientPid == priv->ownerPid) {
        size_t i;
        struct virLockDaemonClientReleaseData data = {
            .client = priv, .hadSomeLeases = false, .gotError = false
        };

        /* Release all locks associated with this
         * owner in all lockspaces */
        virLockDaemonLock(lockDaemon);
        virHashForEach(lockDaemon->lockspaces,
                       virLockDaemonClientReleaseLockspace,
                       &data);
        virLockDaemonClientReleaseLockspace(lockDaemon->defaultLockspace,
                                            "",
                                            &data);
        virLockDaemonUnlock(lockDaemon);

        /* If the client had some active leases when it
         * closed the connection, we must kill it off
         * to make sure it doesn't do nasty stuff */
        if (data.gotError || data.hadSomeLeases) {
            for (i = 0; i < 15; i++) {
                int signum;
                if (i == 0)
                    signum = SIGTERM;
                else if (i == 8)
                    signum = SIGKILL;
                else
                    signum = 0;
                if (priv->clientPid != 0 && virProcessKill(priv->clientPid, signum) < 0) {
                    if (errno == ESRCH)
                        break;

                    VIR_WARN("Failed to kill off pid %lld",
                             (unsigned long long)priv->clientPid);
                }
                g_usleep(200 * 1000);
            }
        }
    }

    g_mutex_clear(&priv->lock);
    g_free(priv->ownerName);
    g_free(priv);
}


static void *
virLockDaemonClientNew(virNetServerClient *client,
                       void *opaque)
{
    virLockDaemonClient *priv;
    uid_t clientuid;
    gid_t clientgid;
    unsigned long long timestamp;
    bool privileged = opaque != NULL;

    priv = g_new0(virLockDaemonClient, 1);

    g_mutex_init(&priv->lock);

    if (virNetServerClientGetUNIXIdentity(client,
                                          &clientuid,
                                          &clientgid,
                                          &priv->clientPid,
                                          &timestamp) < 0)
        goto error;

    VIR_DEBUG("New client pid %llu uid %llu",
              (unsigned long long)priv->clientPid,
              (unsigned long long)clientuid);

    if (!privileged) {
        if (geteuid() != clientuid) {
            virReportRestrictedError(_("Disallowing client %1$llu with uid %2$llu"),
                                     (unsigned long long)priv->clientPid,
                                     (unsigned long long)clientuid);
            goto error;
        }
    } else {
        if (clientuid != 0) {
            virReportRestrictedError(_("Disallowing client %1$llu with uid %2$llu"),
                                     (unsigned long long)priv->clientPid,
                                     (unsigned long long)clientuid);
            goto error;
        }
    }

    /* there's no closing handshake in the locking protocol */
    virNetServerClientSetQuietEOF(client);

    return priv;

 error:
    g_mutex_clear(&priv->lock);
    VIR_FREE(priv);
    return NULL;
}


static void *
virLockDaemonClientNewPostExecRestart(virNetServerClient *client,
                                      virJSONValue *object,
                                      void *opaque)
{
    virLockDaemonClient *priv = virLockDaemonClientNew(client, opaque);
    unsigned int ownerPid;
    const char *ownerUUID;
    const char *ownerName;

    if (!priv)
        return NULL;

    if (virJSONValueObjectGetBoolean(object, "restricted", &priv->restricted) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing restricted data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "ownerPid", &ownerPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerPid data in JSON document"));
        goto error;
    }
    priv->ownerPid = (pid_t)ownerPid;
    if (virJSONValueObjectGetNumberUint(object, "ownerId", &priv->ownerId) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerId data in JSON document"));
        goto error;
    }
    if (!(ownerName = virJSONValueObjectGetString(object, "ownerName"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerName data in JSON document"));
        goto error;
    }
    priv->ownerName = g_strdup(ownerName);
    if (!(ownerUUID = virJSONValueObjectGetString(object, "ownerUUID"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerUUID data in JSON document"));
        goto error;
    }
    if (virUUIDParse(ownerUUID, priv->ownerUUID) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerUUID data in JSON document"));
        goto error;
    }
    return priv;

 error:
    virLockDaemonClientFree(priv);
    return NULL;
}


static virJSONValue *
virLockDaemonClientPreExecRestart(virNetServerClient *client G_GNUC_UNUSED,
                                  void *opaque)
{
    virLockDaemonClient *priv = opaque;
    virJSONValue *object = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(priv->ownerUUID, uuidstr);

    if (virJSONValueObjectAdd(&object,
                              "b:restricted", priv->restricted,
                              "u:ownerPid", priv->ownerPid,
                              "u:ownerId", priv->ownerId,
                              "s:ownerName", priv->ownerName,
                              "s:ownerUUID", uuidstr,
                              NULL) < 0)
        return NULL;

    return object;
}


static int
virLockDaemonExecRestartStatePath(bool privileged,
                                  char **state_file)
{
    if (privileged) {
        *state_file = g_strdup(RUNSTATEDIR "/virtlockd-restart-exec.json");
    } else {
        g_autofree char *rundir = NULL;
        mode_t old_umask;

        rundir = virGetUserRuntimeDirectory();

        old_umask = umask(077);
        if (g_mkdir_with_parents(rundir, 0777) < 0) {
            umask(old_umask);
            return -1;
        }
        umask(old_umask);

        *state_file = g_strdup_printf("%s/virtlockd-restart-exec.json", rundir);
    }

    return 0;
}


static char *
virLockDaemonGetExecRestartMagic(void)
{
    return g_strdup_printf("%lld", (long long int)getpid());
}


static int
virLockDaemonPostExecRestart(const char *state_file,
                             const char *pid_file,
                             int *pid_file_fd,
                             bool privileged)
{
    const char *gotmagic;
    g_autofree char *wantmagic = NULL;
    g_autofree char *state = NULL;
    g_autoptr(virJSONValue) object = NULL;
    int rc;

    VIR_DEBUG("Running post-restart exec");

    if (!virFileExists(state_file)) {
        VIR_DEBUG("No restart state file %s present",
                  state_file);
        return 0;
    }

    rc = virFileReadAll(state_file,
                        1024 * 1024 * 10, /* 10 MB */
                        &state);

    unlink(state_file);

    if (rc < 0)
        return -1;

    VIR_DEBUG("Loading state %s", state);

    if (!(object = virJSONValueFromString(state)))
        return -1;

    gotmagic = virJSONValueObjectGetString(object, "magic");
    if (!gotmagic) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing magic data in JSON document"));
        return -1;
    }

    if (!(wantmagic = virLockDaemonGetExecRestartMagic()))
        return -1;

    if (STRNEQ(gotmagic, wantmagic)) {
        VIR_WARN("Found restart exec file with old magic %s vs wanted %s",
                 gotmagic, wantmagic);
        return 0;
    }

    /* Re-claim PID file now as we will not be daemonizing */
    if (pid_file &&
        (*pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0)
        return -1;

    if (!(lockDaemon = virLockDaemonNewPostExecRestart(object, privileged)))
        return -1;

    return 1;
}


static int
virLockDaemonPreExecRestart(const char *state_file,
                            virNetDaemon *dmn,
                            char **argv)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) lockspaces = virJSONValueNewArray();
    g_autoptr(virJSONValue) defaultLockspace = NULL;
    g_autoptr(virJSONValue) daemon = NULL;
    g_autofree char *state = NULL;
    g_autofree char *magic = NULL;
    g_autofree virHashKeyValuePair *pairs = NULL;
    virHashKeyValuePair *tmp;

    VIR_DEBUG("Running pre-restart exec");

    if (!(daemon = virNetDaemonPreExecRestart(dmn)))
        return -1;

    if (virJSONValueObjectAppend(object, "daemon", &daemon) < 0)
        return -1;

    if (!(defaultLockspace = virLockSpacePreExecRestart(lockDaemon->defaultLockspace)))
        return -1;

    if (virJSONValueObjectAppend(object, "defaultLockspace", &defaultLockspace) < 0)
        return -1;

    tmp = pairs = virHashGetItems(lockDaemon->lockspaces, NULL, false);
    while (tmp && tmp->key) {
        virLockSpace *lockspace = (virLockSpace *)tmp->value;
        g_autoptr(virJSONValue) child = NULL;

        if (!(child = virLockSpacePreExecRestart(lockspace)))
            return -1;

        if (virJSONValueArrayAppend(lockspaces, &child) < 0)
            return -1;

        tmp++;
    }

    if (virJSONValueObjectAppend(object, "lockspaces", &lockspaces) < 0)
        return -1;

    if (!(magic = virLockDaemonGetExecRestartMagic()))
        return -1;

    if (virJSONValueObjectAppendString(object, "magic", magic) < 0)
        return -1;

    if (!(state = virJSONValueToString(object, true)))
        return -1;

    VIR_DEBUG("Saving state %s", state);

    if (virFileWriteStr(state_file, state, 0700) < 0) {
        virReportSystemError(errno,
                             _("Unable to save state file %1$s"), state_file);
        return -1;
    }

    if (execvp(argv[0], argv) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to restart self"));
        return -1;
    }

    abort(); /* This should be impossible to reach */

    return 0;
}


static void
virLockDaemonUsage(const char *argv0, bool privileged)
{
    fprintf(stderr,
            _("\n"
              "Usage:\n"
              "  %1$s [options]\n"
              "\n"
              "Options:\n"
              "  -h | --help            Display program help:\n"
              "  -v | --verbose         Verbose messages.\n"
              "  -d | --daemon          Run as a daemon & write PID file.\n"
              "  -t | --timeout <secs>  Exit after timeout period.\n"
              "  -f | --config <file>   Configuration file.\n"
              "  -V | --version         Display version information.\n"
              "  -p | --pid-file <file> Change name of PID file.\n"
              "\n"
              "libvirt lock management daemon:\n"), argv0);

    if (privileged) {
        fprintf(stderr,
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      %1$s/libvirt/virtlockd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      %2$s/libvirt/virtlockd-sock\n"
                  "\n"
                  "    PID file (unless overridden by -p):\n"
                  "      %3$s/virtlockd.pid\n"
                  "\n"),
                SYSCONFDIR,
                RUNSTATEDIR,
                RUNSTATEDIR);
    } else {
        fprintf(stderr, "%s",
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      $XDG_CONFIG_HOME/libvirt/virtlockd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlockd-sock\n"
                  "\n"
                  "    PID file:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlockd.pid\n"
                  "\n"));
    }
}

int main(int argc, char **argv) {
    virNetServer *lockSrv = NULL;
    virNetServer *adminSrv = NULL;
    virNetServerProgram *lockProgram = NULL;
    virNetServerProgram *adminProgram = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int verbose = 0;
    int godaemon = 0;
    char *run_dir = NULL;
    char *pid_file = NULL;
    int pid_file_fd = -1;
    char *sock_file = NULL;
    char *admin_sock_file = NULL;
    int timeout = 0;         /* -t: Shutdown timeout */
    char *state_file = NULL;
    bool implicit_conf = false;
    mode_t old_umask;
    bool privileged = false;
    virLockDaemonConfig *config = NULL;
    int rv;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 'v' },
        { "daemon", no_argument, &godaemon, 'd' },
        { "config", required_argument, NULL, 'f' },
        { "timeout", required_argument, NULL, 't' },
        { "pid-file", required_argument, NULL, 'p' },
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 },
    };

    privileged = geteuid() == 0;

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int optidx = 0;
        int c;
        char *tmp;

        c = getopt_long(argc, argv, "df:p:t:vVh", opts, &optidx);

        if (c == -1)
            break;

        switch (c) {
        case 0:
            /* Got one of the flags */
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            godaemon = 1;
            break;

        case 't':
            if (virStrToLong_i(optarg, &tmp, 10, &timeout) != 0
                || timeout < 0
                /* Ensure that we can multiply by 1000 without overflowing.  */
                || timeout > INT_MAX / 1000) {
                VIR_ERROR(_("Invalid value for timeout"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'p':
            VIR_FREE(pid_file);
            pid_file = g_strdup(optarg);
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            remote_config_file = g_strdup(optarg);
            break;

        case 'V':
            virLockDaemonVersion(argv[0]);
            exit(EXIT_SUCCESS);

        case 'h':
            virLockDaemonUsage(argv[0], privileged);
            exit(EXIT_SUCCESS);

        case '?':
        default:
            virLockDaemonUsage(argv[0], privileged);
            exit(EXIT_FAILURE);
        }
    }

    virFileActivateDirOverrideForProg(argv[0]);

    if (!(config = virLockDaemonConfigNew(privileged))) {
        VIR_ERROR(_("Can't create initial configuration"));
        exit(EXIT_FAILURE);
    }

    /* No explicit config, so try and find a default one */
    if (remote_config_file == NULL) {
        implicit_conf = true;
        if (virLockDaemonConfigFilePath(privileged,
                                        &remote_config_file) < 0) {
            VIR_ERROR(_("Can't determine config path"));
            exit(EXIT_FAILURE);
        }
    }

    /* Read the config file if it exists */
    if (remote_config_file &&
        virLockDaemonConfigLoadFile(config, remote_config_file, implicit_conf) < 0) {
        VIR_ERROR(_("Can't load config file: %1$s: %2$s"),
                  virGetLastErrorMessage(), remote_config_file);
        exit(EXIT_FAILURE);
    }
    VIR_FREE(remote_config_file);

    if (virDaemonSetupLogging("virtlockd",
                              config->log_level,
                              config->log_filters,
                              config->log_outputs,
                              privileged,
                              verbose,
                              godaemon) < 0) {
        virDispatchError(NULL);
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        virPidFileConstructPath(privileged,
                                RUNSTATEDIR,
                                "virtlockd",
                                &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on pid file path '%s'", NULLSTR(pid_file));

    if (virDaemonUnixSocketPaths("virtlockd",
                                 privileged,
                                 NULL,
                                 &sock_file,
                                 NULL,
                                 &admin_sock_file) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on socket paths '%s' and '%s'",
              sock_file, admin_sock_file);

    if (virLockDaemonExecRestartStatePath(privileged,
                                          &state_file) < 0) {
        VIR_ERROR(_("Can't determine restart state file path"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on restart state file path '%s'",
              state_file);

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (privileged) {
        run_dir = g_strdup(RUNSTATEDIR "/libvirt");
    } else {
        run_dir = virGetUserRuntimeDirectory();
    }

    if (privileged)
        old_umask = umask(022);
    else
        old_umask = umask(077);
    VIR_DEBUG("Ensuring run dir '%s' exists", run_dir);
    if (g_mkdir_with_parents(run_dir, 0777) < 0) {
        VIR_ERROR(_("unable to create rundir %1$s: %2$s"), run_dir,
                  g_strerror(errno));
        ret = VIR_DAEMON_ERR_RUNDIR;
        umask(old_umask);
        goto cleanup;
    }
    umask(old_umask);

    if ((rv = virLockDaemonPostExecRestart(state_file,
                                           pid_file,
                                           &pid_file_fd,
                                           privileged)) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* rv == 1 means we successfully restored from the saved internal state
     * (but still need to add @lockProgram into @srv). rv == 0 means that no
     * saved state is present, therefore initialize from scratch here. */
    if (rv == 0) {
        g_autoptr(virSystemdActivation) act = NULL;

        if (godaemon) {
            if (chdir("/") < 0) {
                VIR_ERROR(_("cannot change to root directory: %1$s"),
                          g_strerror(errno));
                goto cleanup;
            }

            if ((statuswrite = virDaemonForkIntoBackground(argv[0])) < 0) {
                VIR_ERROR(_("Failed to fork as daemon: %1$s"),
                          g_strerror(errno));
                goto cleanup;
            }
        }

        /* If we have a pidfile set, claim it now, exiting if already taken */
        if ((pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0) {
            ret = VIR_DAEMON_ERR_PIDFILE;
            goto cleanup;
        }

        if (!(lockDaemon = virLockDaemonNew(config, privileged))) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }

        if (virSystemdGetActivation(&act) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        lockSrv = virNetDaemonGetServer(lockDaemon->dmn, "virtlockd");
        adminSrv = virNetDaemonGetServer(lockDaemon->dmn, "admin");

        if (virNetServerAddServiceUNIX(lockSrv,
                                       act, "virtlockd.socket",
                                       sock_file, 0700, 0, 0,
                                       NULL,
                                       false, 0, 1) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
        if (virNetServerAddServiceUNIX(adminSrv,
                                       act, "virtlockd-admin.socket",
                                       admin_sock_file, 0700, 0, 0,
                                       NULL,
                                       false, 0, 1) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        if (act &&
            virSystemdActivationComplete(act) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
    } else {
        lockSrv = virNetDaemonGetServer(lockDaemon->dmn, "virtlockd");
        /* If exec-restarting from old virtlockd, we won't have an
         * admin server present */
        if (virNetDaemonHasServer(lockDaemon->dmn, "admin"))
            adminSrv = virNetDaemonGetServer(lockDaemon->dmn, "admin");
    }

    if (timeout > 0) {
        if (virNetDaemonAutoShutdown(lockDaemon->dmn, timeout) < 0)
            goto cleanup;
    }

    if ((virLockDaemonSetupSignals(lockDaemon->dmn)) < 0) {
        ret = VIR_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (!(lockProgram = virNetServerProgramNew(VIR_LOCK_SPACE_PROTOCOL_PROGRAM,
                                               VIR_LOCK_SPACE_PROTOCOL_PROGRAM_VERSION,
                                               virLockSpaceProtocolProcs,
                                               virLockSpaceProtocolNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (virNetServerAddProgram(lockSrv, lockProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (adminSrv != NULL) {
        if (!(adminProgram = virNetServerProgramNew(ADMIN_PROGRAM,
                                                    ADMIN_PROTOCOL_VERSION,
                                                    adminProcs,
                                                    adminNProcs))) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }
        if (virNetServerAddProgram(adminSrv, adminProgram) < 0) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, virLockDaemonErrorHandler);


    /* Tell parent of daemon that basic initialization is complete
     * In particular we're ready to accept net connections & have
     * written the pidfile
     */
    if (statuswrite != -1) {
        char status = 0;
        while (write(statuswrite, &status, 1) == -1 && /* sc_avoid_write */
               errno == EINTR)
            ;
        VIR_FORCE_CLOSE(statuswrite);
    }

    /* Start accepting new clients from network */

    virNetDaemonUpdateServices(lockDaemon->dmn, true);
    virNetDaemonRun(lockDaemon->dmn);

    if (execRestart &&
        virLockDaemonPreExecRestart(state_file,
                                    lockDaemon->dmn,
                                    argv) < 0)
        ret = VIR_DAEMON_ERR_REEXEC;
    else
        ret = 0;

 cleanup:
    virObjectUnref(lockProgram);
    virObjectUnref(adminProgram);
    virObjectUnref(lockSrv);
    virObjectUnref(adminSrv);
    virLockDaemonFree(lockDaemon);
    if (statuswrite != -1) {
        if (ret != 0) {
            /* Tell parent of daemon what failed */
            char status = ret;
            while (write(statuswrite, &status, 1) == -1 && /* sc_avoid_write */
                   errno == EINTR)
                ;
        }
        VIR_FORCE_CLOSE(statuswrite);
    }
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);
    VIR_FREE(pid_file);
    VIR_FREE(sock_file);
    VIR_FREE(admin_sock_file);
    VIR_FREE(state_file);
    VIR_FREE(run_dir);
    virLockDaemonConfigFree(config);
    return ret;
}
