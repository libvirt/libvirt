/*
 * virsystemd.c: helpers for using systemd APIs
 *
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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
 */

#include <config.h>

#define LIBVIRT_VIRSYSTEMDPRIV_H_ALLOW
#include "virsystemdpriv.h"

#include "virsystemd.h"
#include "virbuffer.h"
#include "virgdbus.h"
#include "virstring.h"
#include "viralloc.h"
#include "virutil.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virsocketaddr.h"

#define VIR_FROM_THIS VIR_FROM_SYSTEMD

VIR_LOG_INIT("util.systemd");

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

struct _virSystemdActivation {
    GHashTable *fds;
};

typedef struct _virSystemdActivationEntry virSystemdActivationEntry;
struct _virSystemdActivationEntry {
    int *fds;
    size_t nfds;
};

static void virSystemdEscapeName(virBuffer *buf,
                                 const char *name)
{
    static const char hextable[16] = "0123456789abcdef";

#define ESCAPE(c) \
    do { \
        virBufferAddChar(buf, '\\'); \
        virBufferAddChar(buf, 'x'); \
        virBufferAddChar(buf, hextable[(c >> 4) & 15]); \
        virBufferAddChar(buf, hextable[c & 15]); \
    } while (0)

#define VALID_CHARS \
        "0123456789" \
        "abcdefghijklmnopqrstuvwxyz" \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
        ":-_.\\"

    if (*name == '.') {
        ESCAPE(*name);
        name++;
    }

    while (*name) {
        if (*name == '/')
            virBufferAddChar(buf, '-');
        else if (*name == '-' ||
                 *name == '\\' ||
                 !strchr(VALID_CHARS, *name))
            ESCAPE(*name);
        else
            virBufferAddChar(buf, *name);
        name++;
    }

#undef ESCAPE
#undef VALID_CHARS
}

char *virSystemdMakeScopeName(const char *name,
                              const char *drivername,
                              bool legacy_behaviour)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "machine-");
    if (legacy_behaviour) {
        virSystemdEscapeName(&buf, drivername);
        virBufferAddLit(&buf, "\\x2d");
    }
    virSystemdEscapeName(&buf, name);
    virBufferAddLit(&buf, ".scope");

    return virBufferContentAndReset(&buf);
}


char *virSystemdMakeSliceName(const char *partition)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (*partition == '/')
        partition++;

    virSystemdEscapeName(&buf, partition);
    virBufferAddLit(&buf, ".slice");

    return virBufferContentAndReset(&buf);
}

static int virSystemdHasMachinedCachedValue = -1;
static int virSystemdHasLogindCachedValue = -1;

/* Reset the cache from tests for testing the underlying dbus calls
 * as well */
void virSystemdHasMachinedResetCachedValue(void)
{
    virSystemdHasMachinedCachedValue = -1;
}

void virSystemdHasLogindResetCachedValue(void)
{
    virSystemdHasLogindCachedValue = -1;
}


/* -2 = machine1 is not supported on this machine
 * -1 = error
 *  0 = machine1 is available
 */
int
virSystemdHasMachined(void)
{
    int ret;
    int val;

    val = g_atomic_int_get(&virSystemdHasMachinedCachedValue);
    if (val != -1)
        return val;

    if ((ret = virGDBusIsServiceEnabled("org.freedesktop.machine1")) < 0) {
        if (ret == -2)
            g_atomic_int_set(&virSystemdHasMachinedCachedValue, -2);
        return ret;
    }

    if ((ret = virGDBusIsServiceRegistered("org.freedesktop.systemd1")) == -1)
        return ret;
    g_atomic_int_set(&virSystemdHasMachinedCachedValue, ret);
    return ret;
}

int
virSystemdHasLogind(void)
{
    int ret;
    int val;

    val = g_atomic_int_get(&virSystemdHasLogindCachedValue);
    if (val != -1)
        return val;

    ret = virGDBusIsServiceEnabled("org.freedesktop.login1");
    if (ret < 0) {
        if (ret == -2)
            g_atomic_int_set(&virSystemdHasLogindCachedValue, -2);
        return ret;
    }

    /*
     * Want to use logind if:
     *   - logind is already running
     * Or
     *   - logind is not running, but this is a systemd host
     *     (rely on dbus activation)
     */
    if ((ret = virGDBusIsServiceRegistered("org.freedesktop.login1")) == -1)
        return ret;

    if (ret == -2) {
        if ((ret = virGDBusIsServiceRegistered("org.freedesktop.systemd1")) == -1)
            return ret;
    }

    g_atomic_int_set(&virSystemdHasLogindCachedValue, ret);
    return ret;
}


/**
 * virSystemdGetMachineByPID:
 * @conn: dbus connection
 * @pid: pid of running VM
 *
 * Returns dbus object path to VM registered with machined.
 * On error returns NULL.
 */
static char *
virSystemdGetMachineByPID(GDBusConnection *conn,
                          pid_t pid)
{
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    char *object = NULL;

    message = g_variant_new("(u)", pid);

    if (virGDBusCallMethod(conn,
                           &reply,
                           G_VARIANT_TYPE("(o)"),
                           NULL,
                           "org.freedesktop.machine1",
                           "/org/freedesktop/machine1",
                           "org.freedesktop.machine1.Manager",
                           "GetMachineByPID",
                           message) < 0)
        return NULL;

    g_variant_get(reply, "(o)", &object);

    VIR_DEBUG("Domain with pid %lld has object path '%s'",
              (long long) pid, object);

    return object;
}


char *
virSystemdGetMachineNameByPID(pid_t pid)
{
    GDBusConnection *conn;
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) gvar = NULL;
    g_autofree char *object = NULL;
    char *name = NULL;

    if (virSystemdHasMachined() < 0)
        return NULL;

    if (!(conn = virGDBusGetSystemBus()))
        return NULL;

    object = virSystemdGetMachineByPID(conn, pid);
    if (!object)
        return NULL;

    message = g_variant_new("(ss)",
                            "org.freedesktop.machine1.Machine", "Name");

    if (virGDBusCallMethod(conn,
                           &reply,
                           G_VARIANT_TYPE("(v)"),
                           NULL,
                           "org.freedesktop.machine1",
                           object,
                           "org.freedesktop.DBus.Properties",
                           "Get",
                           message) < 0)
        return NULL;

    g_variant_get(reply, "(v)", &gvar);
    g_variant_get(gvar, "s", &name);

    VIR_DEBUG("Domain with pid %lld has machine name '%s'",
              (long long) pid, name);

    return name;
}


/**
 * virSystemdGetMachineUnitByPID:
 * @pid: pid of running VM
 *
 * Returns systemd Unit name of a running VM registered with machined.
 * On error returns NULL.
 */
char *
virSystemdGetMachineUnitByPID(pid_t pid)
{
    GDBusConnection *conn;
    g_autoptr(GVariant) message = NULL;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) gvar = NULL;
    g_autofree char *object = NULL;
    char *unit = NULL;

    if (virSystemdHasMachined() < 0)
        return NULL;

    if (!(conn = virGDBusGetSystemBus()))
        return NULL;

    object = virSystemdGetMachineByPID(conn, pid);
    if (!object)
        return NULL;

    message = g_variant_new("(ss)",
                            "org.freedesktop.machine1.Machine", "Unit");

    if (virGDBusCallMethod(conn,
                           &reply,
                           G_VARIANT_TYPE("(v)"),
                           NULL,
                           "org.freedesktop.machine1",
                           object,
                           "org.freedesktop.DBus.Properties",
                           "Get",
                           message) < 0)
        return NULL;

    g_variant_get(reply, "(v)", &gvar);
    g_variant_get(gvar, "s", &unit);

    VIR_DEBUG("Domain with pid %lld has unit name '%s'",
              (long long) pid, unit);

    return unit;
}


/**
 * virSystemdCreateMachine:
 * @name: driver unique name of the machine
 * @drivername: name of the virt driver
 * @privileged: whether driver is running privileged or per user
 * @uuid: globally unique UUID of the machine
 * @rootdir: root directory of machine filesystem
 * @pidleader: PID of the leader process
 * @iscontainer: true if a container, false if a VM
 * @nnicindexes: number of network interface indexes in list
 * @nicindexes: list of network interface indexes
 * @partition: name of the slice to place the machine in
 *
 * Returns 0 on success, -1 on fatal error, or -2 if systemd-machine is not available
 */
int virSystemdCreateMachine(const char *name,
                            const char *drivername,
                            const unsigned char *uuid,
                            const char *rootdir,
                            pid_t pidleader,
                            bool iscontainer,
                            size_t nnicindexes,
                            int *nicindexes,
                            const char *partition,
                            unsigned int maxthreads)
{
    int rc;
    GDBusConnection *conn;
    GVariant *guuid;
    GVariant *gnicindexes;
    GVariant *gprops;
    GVariant *message;
    g_autofree char *creatorname = NULL;
    g_autofree char *slicename = NULL;
    g_autofree char *scopename = NULL;
    g_autofree char *servicename = NULL;
    static int hasCreateWithNetwork = 1;

    if ((rc = virSystemdHasMachined()) < 0)
        return rc;

    if (!(conn = virGDBusGetSystemBus()))
        return -1;

    creatorname = g_strdup_printf("libvirt-%s", drivername);
    servicename = g_strdup_printf("virt%sd.service", drivername);

    if (partition) {
        if (!(slicename = virSystemdMakeSliceName(partition)))
             return -1;
    } else {
        slicename = g_strdup("");
    }

    /*
     * The systemd DBus APIs we're invoking have the
     * following signature(s)
     *
     * CreateMachineWithNetwork(in  s name,
     *                          in  ay id,
     *                          in  s service,
     *                          in  s class,
     *                          in  u leader,
     *                          in  s root_directory,
     *                          in  ai nicindexes
     *                          in  a(sv) scope_properties,
     *                          out o path);
     *
     * CreateMachine(in  s name,
     *               in  ay id,
     *               in  s service,
     *               in  s class,
     *               in  u leader,
     *               in  s root_directory,
     *               in  a(sv) scope_properties,
     *               out o path);
     *
     * @name a host unique name for the machine. shows up
     * in 'ps' listing & similar
     *
     * @id: a UUID of the machine, ideally matching /etc/machine-id
     * for containers
     *
     * @service: identifier of the client ie "libvirt-lxc"
     *
     * @class: either the string "container" or "vm" depending
     * on the type of machine
     *
     * @leader: main PID of the machine, either the host emulator
     * process, or the 'init' PID of the container
     *
     * @root_directory: the root directory of the container, if
     * this is known & visible in the host filesystem, or empty string
     *
     * @nicindexes: list of network interface indexes for the
     * host end of the VETH device pairs.
     *
     * @scope_properties:an array (not a dict!) of properties that are
     * passed on to PID 1 when creating a scope unit for your machine.
     * Will allow initial settings for the cgroup & similar.
     *
     * @path: a bus path returned for the machine object created, to
     * allow further API calls to be made against the object.
     *
     */

    VIR_DEBUG("Attempting to create machine via systemd");
    if (g_atomic_int_get(&hasCreateWithNetwork)) {
        g_autoptr(virError) error = NULL;

        error = g_new0(virError, 1);

        guuid = g_variant_new_fixed_array(G_VARIANT_TYPE("y"),
                                          uuid, 16, sizeof(unsigned char));
        gnicindexes = g_variant_new_fixed_array(G_VARIANT_TYPE("i"),
                                                nicindexes, nnicindexes, sizeof(int));
        gprops = g_variant_new_parsed("[('Slice', <%s>),"
                                      " ('After', <['libvirtd.service', %s]>),"
                                      " ('Before', <['virt-guest-shutdown.target']>)]",
                                      slicename,
                                      servicename);
        message = g_variant_new("(s@ayssus@ai@a(sv))",
                                name,
                                guuid,
                                creatorname,
                                iscontainer ? "container" : "vm",
                                (unsigned int)pidleader,
                                NULLSTR_EMPTY(rootdir),
                                gnicindexes,
                                gprops);

        rc = virGDBusCallMethod(conn,
                                NULL,
                                NULL,
                                error,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "CreateMachineWithNetwork",
                                message);

        g_variant_unref(message);

        if (rc < 0)
            return -1;

        if (error->level == VIR_ERR_ERROR) {
            if (virGDBusErrorIsUnknownMethod(error)) {
                VIR_INFO("CreateMachineWithNetwork isn't supported, switching "
                         "to legacy CreateMachine method for systemd-machined");
                virResetError(error);
                g_atomic_int_set(&hasCreateWithNetwork, 0);
                /* Could re-structure without Using goto, but this
                 * avoids another atomic read which would trigger
                 * another memory barrier */
                goto fallback;
            }
            virReportErrorObject(error);
            virResetError(error);
            return -1;
        }
    } else {
    fallback:
        guuid = g_variant_new_fixed_array(G_VARIANT_TYPE("y"),
                                          uuid, 16, sizeof(unsigned char));
        gprops = g_variant_new_parsed("[('Slice', <%s>),"
                                      " ('After', <['libvirtd.service', %s]>),"
                                      " ('Before', <['virt-guest-shutdown.target']>)]",
                                      slicename,
                                      servicename);
        message = g_variant_new("(s@ayssus@a(sv))",
                                name,
                                guuid,
                                creatorname,
                                iscontainer ? "container" : "vm",
                                (unsigned int)pidleader,
                                NULLSTR_EMPTY(rootdir),
                                gprops);

        rc = virGDBusCallMethod(conn,
                                NULL,
                                NULL,
                                NULL,
                                "org.freedesktop.machine1",
                                "/org/freedesktop/machine1",
                                "org.freedesktop.machine1.Manager",
                                "CreateMachine",
                                message);

        g_variant_unref(message);

        if (rc < 0)
            return -1;
    }

    if (maxthreads > 0) {
        uint64_t max = maxthreads;

        if (!(scopename = virSystemdMakeScopeName(name, drivername, false)))
            return -1;

        gprops = g_variant_new_parsed("[('TasksMax', <%t>)]", max);

        message = g_variant_new("(sb@a(sv))",
                                scopename,
                                true,
                                gprops);

        rc = virGDBusCallMethod(conn,
                                NULL,
                                NULL,
                                NULL,
                                "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1",
                                "org.freedesktop.systemd1.Manager",
                                "SetUnitProperties",
                                message);

        g_variant_unref(message);

        if (rc < 0)
            return -1;
    }

    return 0;
}

int virSystemdTerminateMachine(const char *name)
{
    int rc;
    GDBusConnection *conn;
    g_autoptr(GVariant) message = NULL;
    g_autoptr(virError) error = NULL;

    if (!name)
        return 0;

    if ((rc = virSystemdHasMachined()) < 0)
        return rc;

    if (!(conn = virGDBusGetSystemBus()))
        return -1;

    error = g_new0(virError, 1);

    /*
     * The systemd DBus API we're invoking has the
     * following signature
     *
     * TerminateMachine(in  s name);
     *
     * @name a host unique name for the machine. shows up
     * in 'ps' listing & similar
     */

    message = g_variant_new("(s)", name);

    VIR_DEBUG("Attempting to terminate machine via systemd");
    if (virGDBusCallMethod(conn,
                           NULL,
                           NULL,
                           error,
                           "org.freedesktop.machine1",
                           "/org/freedesktop/machine1",
                           "org.freedesktop.machine1.Manager",
                           "TerminateMachine",
                           message) < 0)
        return -1;

    if (error->level == VIR_ERR_ERROR &&
        STRNEQ_NULLABLE("org.freedesktop.machine1.NoSuchMachine",
                        error->str1)) {
        virReportErrorObject(error);
        return -1;
    }

    return 0;
}

void
virSystemdNotifyStartup(void)
{
#ifndef WIN32
    const char *path;
    const char *msg = "READY=1";
    int fd;
    struct sockaddr_un un = {
        .sun_family = AF_UNIX,
    };
    struct iovec iov = {
        .iov_base = (char *)msg,
        .iov_len = strlen(msg),
    };
    struct msghdr mh = {
        .msg_name = &un,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    if (!(path = getenv("NOTIFY_SOCKET"))) {
        VIR_DEBUG("Skipping systemd notify, not requested");
        return;
    }

    /* NB sun_path field is *not* NUL-terminated, hence >, not >= */
    if (strlen(path) > sizeof(un.sun_path)) {
        VIR_WARN("Systemd notify socket path '%s' too long", path);
        return;
    }

    memcpy(un.sun_path, path, strlen(path));
    if (un.sun_path[0] == '@')
        un.sun_path[0] = '\0';

    mh.msg_namelen = offsetof(struct sockaddr_un, sun_path) + strlen(path);

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        VIR_WARN("Unable to create socket FD");
        return;
    }

    if (sendmsg(fd, &mh, MSG_NOSIGNAL) < 0)
        VIR_WARN("Failed to notify systemd");

    VIR_FORCE_CLOSE(fd);
#endif /* !WIN32 */
}

static int
virSystemdPMSupportTarget(const char *methodName, bool *result)
{
    int rc;
    GDBusConnection *conn;
    g_autoptr(GVariant) reply = NULL;
    char *response;

    if ((rc = virSystemdHasLogind()) < 0)
        return rc;

    if (!(conn = virGDBusGetSystemBus()))
        return -1;

    if (virGDBusCallMethod(conn,
                           &reply,
                           G_VARIANT_TYPE("(s)"),
                           NULL,
                           "org.freedesktop.login1",
                           "/org/freedesktop/login1",
                           "org.freedesktop.login1.Manager",
                           methodName,
                           NULL) < 0)
        return -1;

    g_variant_get(reply, "(&s)", &response);

    *result = STREQ("yes", response) || STREQ("challenge", response);

    return 0;
}

int virSystemdCanSuspend(bool *result)
{
    return virSystemdPMSupportTarget("CanSuspend", result);
}

int virSystemdCanHibernate(bool *result)
{
    return virSystemdPMSupportTarget("CanHibernate", result);
}

int virSystemdCanHybridSleep(bool *result)
{
    return virSystemdPMSupportTarget("CanHybridSleep", result);
}


static void
virSystemdActivationEntryFree(void *data)
{
    virSystemdActivationEntry *ent = data;
    size_t i;

    VIR_DEBUG("Closing activation FDs");
    for (i = 0; i < ent->nfds; i++) {
        VIR_DEBUG("Closing activation FD %d", ent->fds[i]);
        VIR_FORCE_CLOSE(ent->fds[i]);
    }

    g_free(ent->fds);
    g_free(ent);
}


static int
virSystemdActivationAddFD(virSystemdActivation *act,
                          const char *name,
                          int fd)
{
    virSystemdActivationEntry *ent = virHashLookup(act->fds, name);

    if (!ent) {
        ent = g_new0(virSystemdActivationEntry, 1);
        ent->fds = g_new0(int, 1);
        ent->fds[ent->nfds++] = fd;

        VIR_DEBUG("Record first FD %d with name %s", fd, name);
        if (virHashAddEntry(act->fds, name, ent) < 0) {
            virSystemdActivationEntryFree(ent);
            return -1;
        }

        return 0;
    }

    VIR_EXPAND_N(ent->fds, ent->nfds, 1);

    VIR_DEBUG("Record extra FD %d with name %s", fd, name);
    ent->fds[ent->nfds - 1] = fd;

    return 0;
}


static int
virSystemdActivationInitFromNames(virSystemdActivation *act,
                                  int nfds,
                                  const char *fdnames)
{
    g_auto(GStrv) fdnamelistptr = NULL;
    char **fdnamelist;
    size_t i;
    int nextfd = STDERR_FILENO + 1;

    VIR_DEBUG("FD names %s", fdnames);

    if (!(fdnamelistptr = g_strsplit(fdnames, ":", 0)))
        goto error;

    if (g_strv_length(fdnamelistptr) != nfds) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting %1$d FD names but got %2$u"),
                       nfds, g_strv_length(fdnamelistptr));
        goto error;
    }

    fdnamelist = fdnamelistptr;
    while (nfds) {
        if (virSystemdActivationAddFD(act, *fdnamelist, nextfd) < 0)
            goto error;

        fdnamelist++;
        nextfd++;
        nfds--;
    }

    return 0;

 error:
    for (i = 0; i < nfds; i++) {
        int fd = nextfd + i;
        VIR_FORCE_CLOSE(fd);
    }
    return -1;
}


#ifndef WIN32

/**
 * virSystemdGetListenFDs:
 *
 * Parse LISTEN_PID and LISTEN_FDS passed from caller.
 *
 * Returns number of passed FDs.
 */
static unsigned int
virSystemdGetListenFDs(void)
{
    const char *pidstr;
    const char *fdstr;
    size_t i = 0;
    unsigned long long procid;
    unsigned int nfds;

    VIR_DEBUG("Setting up networking from caller");

    if (!(pidstr = getenv("LISTEN_PID"))) {
        VIR_DEBUG("No LISTEN_PID from caller");
        return 0;
    }

    if (virStrToLong_ull(pidstr, NULL, 10, &procid) < 0) {
        VIR_DEBUG("Malformed LISTEN_PID from caller %s", pidstr);
        return 0;
    }

    if ((pid_t)procid != getpid()) {
        VIR_DEBUG("LISTEN_PID %s is not for us %lld",
                  pidstr, (long long) getpid());
        return 0;
    }

    if (!(fdstr = getenv("LISTEN_FDS"))) {
        VIR_DEBUG("No LISTEN_FDS from caller");
        return 0;
    }

    if (virStrToLong_ui(fdstr, NULL, 10, &nfds) < 0) {
        VIR_DEBUG("Malformed LISTEN_FDS from caller %s", fdstr);
        return 0;
    }

    g_unsetenv("LISTEN_PID");
    g_unsetenv("LISTEN_FDS");

    VIR_DEBUG("Got %u file descriptors", nfds);

    for (i = 0; i < nfds; i++) {
        int fd = STDERR_FILENO + i + 1;

        VIR_DEBUG("Disabling inheritance of passed FD %d", fd);

        if (virSetInherit(fd, false) < 0)
            VIR_WARN("Couldn't disable inheritance of passed FD %d", fd);
    }

    return nfds;
}

#else /* WIN32 */

static unsigned int
virSystemdGetListenFDs(void)
{
    return 0;
}

#endif /* WIN32 */

static virSystemdActivation *
virSystemdActivationNew(int nfds)
{
    g_autoptr(virSystemdActivation) act = g_new0(virSystemdActivation, 1);
    const char *fdnames;

    VIR_DEBUG("Activated with %d FDs", nfds);

    act->fds = virHashNew(virSystemdActivationEntryFree);

    fdnames = getenv("LISTEN_FDNAMES");
    if (!fdnames) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing LISTEN_FDNAMES env from systemd socket activation"));
        return NULL;
    }

    if (virSystemdActivationInitFromNames(act, nfds, fdnames) < 0)
        return NULL;

    VIR_DEBUG("Created activation object for %d FDs", nfds);
    return g_steal_pointer(&act);
}


/**
 * virSystemdGetActivation:
 * @act: filled with allocated activation object
 *
 * Acquire an object for handling systemd activation.
 * If no activation FDs have been provided the returned object
 * will be NULL, indicating normal service setup can be performed
 * If the returned object is non-NULL then at least one file
 * descriptor will be present. No normal service setup should
 * be performed.
 *
 * Returns: 0 on success, -1 on failure
 */
int
virSystemdGetActivation(virSystemdActivation **act)
{
    int nfds = 0;

    if ((nfds = virSystemdGetListenFDs()) < 0)
        return -1;

    if (nfds == 0) {
        VIR_DEBUG("No activation FDs present");
        *act = NULL;
        return 0;
    }

    *act = virSystemdActivationNew(nfds);
    return 0;
}


/**
 * virSystemdActivationHasName:
 * @act: the activation object
 * @name: the file descriptor name
 *
 * Check whether there is a file descriptor present
 * for the requested name.
 *
 * Returns: true if a FD is present, false otherwise
 */
bool
virSystemdActivationHasName(virSystemdActivation *act,
                            const char *name)
{
    return virHashLookup(act->fds, name) != NULL;
}


/**
 * virSystemdActivationComplete:
 * @act: the activation object
 *
 * Indicate that processing of activation has been
 * completed. All provided file descriptors should
 * have been claimed. If any are unclaimed then
 * an error will be reported
 *
 * Returns: 0 on success, -1 if some FDs are unclaimed
 */
int
virSystemdActivationComplete(virSystemdActivation *act)
{
    if (virHashSize(act->fds) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Some activation file descriptors are unclaimed"));
        return -1;
    }

    return 0;
}


/**
 * virSystemdActivationClaimFDs:
 * @act: the activation object
 * @name: the file descriptor name
 * @fds: to be filled with claimed FDs
 * @nfds: to be filled with number of FDs in @fds
 *
 * Claims the file descriptors associated with
 * @name.
 *
 * The caller is responsible for closing all
 * returned file descriptors when they are no
 * longer required. The caller must also free
 * the array memory in @fds.
 */
void
virSystemdActivationClaimFDs(virSystemdActivation *act,
                             const char *name,
                             int **fds,
                             size_t *nfds)
{
    virSystemdActivationEntry *ent = virHashSteal(act->fds, name);

    if (!ent) {
        *fds = NULL;
        *nfds = 0;
        VIR_DEBUG("No FD with name %s", name);
        return;
    }

    VIR_DEBUG("Found %zu FDs with name %s", ent->nfds, name);
    *fds = ent->fds;
    *nfds = ent->nfds;

    VIR_FREE(ent);
}


/**
 * virSystemdActivationFree:
 * @act: the activation object
 *
 * Free memory and close unclaimed file descriptors
 * associated with the activation object
 */
void
virSystemdActivationFree(virSystemdActivation *act)
{
    if (!act)
        return;

    g_clear_pointer(&act->fds, g_hash_table_unref);

    g_free(act);
}
