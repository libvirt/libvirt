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

#include <sys/socket.h>
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#define LIBVIRT_VIRSYSTEMDPRIV_H_ALLOW
#include "virsystemdpriv.h"

#include "virsystemd.h"
#include "viratomic.h"
#include "virbuffer.h"
#include "virdbus.h"
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
    virHashTablePtr fds;
};

typedef struct _virSystemdActivationEntry virSystemdActivationEntry;
typedef virSystemdActivationEntry *virSystemdActivationEntryPtr;

struct _virSystemdActivationEntry {
    int *fds;
    size_t nfds;
};

static void virSystemdEscapeName(virBufferPtr buf,
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
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "machine-");
    if (legacy_behaviour) {
        virSystemdEscapeName(&buf, drivername);
        virBufferAddLit(&buf, "\\x2d");
    }
    virSystemdEscapeName(&buf, name);
    virBufferAddLit(&buf, ".scope");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *virSystemdMakeSliceName(const char *partition)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (*partition == '/')
        partition++;

    virSystemdEscapeName(&buf, partition);
    virBufferAddLit(&buf, ".slice");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

static int virSystemdHasMachinedCachedValue = -1;

/* Reset the cache from tests for testing the underlying dbus calls
 * as well */
void virSystemdHasMachinedResetCachedValue(void)
{
    virSystemdHasMachinedCachedValue = -1;
}

/* -2 = machine1 is not supported on this machine
 * -1 = error
 *  0 = machine1 is available
 */
static int
virSystemdHasMachined(void)
{
    int ret;
    int val;

    val = virAtomicIntGet(&virSystemdHasMachinedCachedValue);
    if (val != -1)
        return val;

    if ((ret = virDBusIsServiceEnabled("org.freedesktop.machine1")) < 0) {
        if (ret == -2)
            virAtomicIntSet(&virSystemdHasMachinedCachedValue, -2);
        return ret;
    }

    if ((ret = virDBusIsServiceRegistered("org.freedesktop.systemd1")) == -1)
        return ret;
    virAtomicIntSet(&virSystemdHasMachinedCachedValue, ret);
    return ret;
}


char *
virSystemdGetMachineNameByPID(pid_t pid)
{
    DBusConnection *conn;
    DBusMessage *reply = NULL;
    char *name = NULL, *object = NULL;

    if (virSystemdHasMachined() < 0)
        goto cleanup;

    if (!(conn = virDBusGetSystemBus()))
        goto cleanup;

    if (virDBusCallMethod(conn, &reply, NULL,
                          "org.freedesktop.machine1",
                          "/org/freedesktop/machine1",
                          "org.freedesktop.machine1.Manager",
                          "GetMachineByPID",
                          "u", pid) < 0)
        goto cleanup;

    if (virDBusMessageDecode(reply, "o", &object) < 0)
        goto cleanup;

    virDBusMessageUnref(reply);
    reply = NULL;

    VIR_DEBUG("Domain with pid %lld has object path '%s'",
              (long long) pid, object);

    if (virDBusCallMethod(conn, &reply, NULL,
                          "org.freedesktop.machine1",
                          object,
                          "org.freedesktop.DBus.Properties",
                          "Get",
                          "ss",
                          "org.freedesktop.machine1.Machine",
                          "Name") < 0)
        goto cleanup;

    if (virDBusMessageDecode(reply, "v", "s", &name) < 0)
        goto cleanup;

    VIR_DEBUG("Domain with pid %lld has machine name '%s'",
              (long long) pid, name);

 cleanup:
    VIR_FREE(object);
    virDBusMessageUnref(reply);

    return name;
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
    int ret;
    DBusConnection *conn;
    char *creatorname = NULL;
    char *slicename = NULL;
    char *scopename = NULL;
    static int hasCreateWithNetwork = 1;

    if ((ret = virSystemdHasMachined()) < 0)
        return ret;

    if (!(conn = virDBusGetSystemBus()))
        return -1;

    ret = -1;

    if (virAsprintf(&creatorname, "libvirt-%s", drivername) < 0)
        goto cleanup;

    if (partition) {
        if (!(slicename = virSystemdMakeSliceName(partition)))
             goto cleanup;
    } else {
        if (VIR_STRDUP(slicename, "") < 0)
            goto cleanup;
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
    if (virAtomicIntGet(&hasCreateWithNetwork)) {
        virError error;
        memset(&error, 0, sizeof(error));

        if (virDBusCallMethod(conn,
                              NULL,
                              &error,
                              "org.freedesktop.machine1",
                              "/org/freedesktop/machine1",
                              "org.freedesktop.machine1.Manager",
                              "CreateMachineWithNetwork",
                              "sayssusa&ia(sv)",
                              name,
                              16,
                              uuid[0], uuid[1], uuid[2], uuid[3],
                              uuid[4], uuid[5], uuid[6], uuid[7],
                              uuid[8], uuid[9], uuid[10], uuid[11],
                              uuid[12], uuid[13], uuid[14], uuid[15],
                              creatorname,
                              iscontainer ? "container" : "vm",
                              (unsigned int)pidleader,
                              NULLSTR_EMPTY(rootdir),
                              nnicindexes, nicindexes,
                              3,
                              "Slice", "s", slicename,
                              "After", "as", 1, "libvirtd.service",
                              "Before", "as", 1, "virt-guest-shutdown.target") < 0)
            goto cleanup;

        if (error.level == VIR_ERR_ERROR) {
            if (virDBusErrorIsUnknownMethod(&error)) {
                VIR_INFO("CreateMachineWithNetwork isn't supported, switching "
                         "to legacy CreateMachine method for systemd-machined");
                virResetError(&error);
                virAtomicIntSet(&hasCreateWithNetwork, 0);
                /* Could re-structure without Using goto, but this
                 * avoids another atomic read which would trigger
                 * another memory barrier */
                goto fallback;
            }
            virReportErrorObject(&error);
            virResetError(&error);
            goto cleanup;
        }
    } else {
    fallback:
        if (virDBusCallMethod(conn,
                              NULL,
                              NULL,
                              "org.freedesktop.machine1",
                              "/org/freedesktop/machine1",
                              "org.freedesktop.machine1.Manager",
                              "CreateMachine",
                              "sayssusa(sv)",
                              name,
                              16,
                              uuid[0], uuid[1], uuid[2], uuid[3],
                              uuid[4], uuid[5], uuid[6], uuid[7],
                              uuid[8], uuid[9], uuid[10], uuid[11],
                              uuid[12], uuid[13], uuid[14], uuid[15],
                              creatorname,
                              iscontainer ? "container" : "vm",
                              (unsigned int)pidleader,
                              NULLSTR_EMPTY(rootdir),
                              3,
                              "Slice", "s", slicename,
                              "After", "as", 1, "libvirtd.service",
                              "Before", "as", 1, "virt-guest-shutdown.target") < 0)
            goto cleanup;
    }

    if (maxthreads > 0) {
        if (!(scopename = virSystemdMakeScopeName(name, drivername, false)))
            goto cleanup;

        if (virDBusCallMethod(conn,
                              NULL,
                              NULL,
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "SetUnitProperties",
                              "sba(sv)",
                              scopename,
                              true,
                              1,
                              "TasksMax", "t", (uint64_t)maxthreads) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(creatorname);
    VIR_FREE(slicename);
    VIR_FREE(scopename);
    return ret;
}

int virSystemdTerminateMachine(const char *name)
{
    int ret;
    DBusConnection *conn;
    virError error;

    if (!name)
        return 0;

    memset(&error, 0, sizeof(error));

    if ((ret = virSystemdHasMachined()) < 0)
        goto cleanup;

    ret = -1;

    if (!(conn = virDBusGetSystemBus()))
        goto cleanup;

    /*
     * The systemd DBus API we're invoking has the
     * following signature
     *
     * TerminateMachine(in  s name);
     *
     * @name a host unique name for the machine. shows up
     * in 'ps' listing & similar
     */

    VIR_DEBUG("Attempting to terminate machine via systemd");
    if (virDBusCallMethod(conn,
                          NULL,
                          &error,
                          "org.freedesktop.machine1",
                          "/org/freedesktop/machine1",
                          "org.freedesktop.machine1.Manager",
                          "TerminateMachine",
                          "s",
                          name) < 0)
        goto cleanup;

    if (error.level == VIR_ERR_ERROR &&
        STRNEQ_NULLABLE("org.freedesktop.machine1.NoSuchMachine",
                        error.str1)) {
        virReportErrorObject(&error);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virResetError(&error);

    return ret;
}

void
virSystemdNotifyStartup(void)
{
#ifdef HAVE_SYS_UN_H
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
#endif /* HAVE_SYS_UN_H */
}

static int
virSystemdPMSupportTarget(const char *methodName, bool *result)
{
    int ret;
    DBusConnection *conn;
    DBusMessage *message = NULL;
    char *response;

    ret = virDBusIsServiceEnabled("org.freedesktop.login1");
    if (ret < 0)
        return ret;

    if ((ret = virDBusIsServiceRegistered("org.freedesktop.login1")) < 0)
        return ret;

    if (!(conn = virDBusGetSystemBus()))
        return -1;

    ret = -1;

    if (virDBusCallMethod(conn,
                          &message,
                          NULL,
                          "org.freedesktop.login1",
                          "/org/freedesktop/login1",
                          "org.freedesktop.login1.Manager",
                          methodName,
                          NULL) < 0)
        return ret;

    if ((ret = virDBusMessageDecode(message, "s", &response)) < 0)
        goto cleanup;

    *result = STREQ("yes", response) || STREQ("challenge", response);

    ret = 0;

 cleanup:
    virDBusMessageUnref(message);
    VIR_FREE(response);

    return ret;
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
virSystemdActivationEntryFree(void *data, const void *name)
{
    virSystemdActivationEntryPtr ent = data;
    size_t i;

    VIR_DEBUG("Closing activation FDs for %s", (const char *)name);
    for (i = 0; i < ent->nfds; i++) {
        VIR_DEBUG("Closing activation FD %d", ent->fds[i]);
        VIR_FORCE_CLOSE(ent->fds[i]);
    }

    VIR_FREE(ent->fds);
    VIR_FREE(ent);
}


static int
virSystemdActivationAddFD(virSystemdActivationPtr act,
                          const char *name,
                          int fd)
{
    virSystemdActivationEntryPtr ent = virHashLookup(act->fds, name);

    if (!ent) {
        if (VIR_ALLOC(ent) < 0)
            return -1;

        if (VIR_ALLOC_N(ent->fds, 1) < 0) {
            virSystemdActivationEntryFree(ent, name);
            return -1;
        }

        ent->fds[ent->nfds++] = fd;

        VIR_DEBUG("Record first FD %d with name %s", fd, name);
        if (virHashAddEntry(act->fds, name, ent) < 0) {
            virSystemdActivationEntryFree(ent, name);
            return -1;
        }

        return 0;
    }

    if (VIR_EXPAND_N(ent->fds, ent->nfds, 1) < 0)
        return -1;

    VIR_DEBUG("Record extra FD %d with name %s", fd, name);
    ent->fds[ent->nfds - 1] = fd;

    return 0;
}


static int
virSystemdActivationInitFromNames(virSystemdActivationPtr act,
                                  int nfds,
                                  const char *fdnames)
{
    VIR_AUTOSTRINGLIST fdnamelistptr = NULL;
    char **fdnamelist;
    size_t nfdnames;
    size_t i;
    int nextfd = STDERR_FILENO + 1;

    VIR_DEBUG("FD names %s", fdnames);

    if (!(fdnamelistptr = virStringSplitCount(fdnames, ":", 0, &nfdnames)))
        goto error;

    if (nfdnames != nfds) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Expecting %d FD names but got %zu"),
                       nfds, nfdnames);
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


/*
 * Back compat for systemd < v227 which lacks LISTEN_FDNAMES.
 * Delete when min systemd is increased ie RHEL7 dropped
 */
static int
virSystemdActivationInitFromMap(virSystemdActivationPtr act,
                                int nfds,
                                virSystemdActivationMap *map,
                                size_t nmap)
{
    int nextfd = STDERR_FILENO + 1;
    size_t i;

    while (nfds) {
        virSocketAddr addr;
        const char *name = NULL;

        memset(&addr, 0, sizeof(addr));

        addr.len = sizeof(addr.data);
        if (getsockname(nextfd, &addr.data.sa, &addr.len) < 0) {
            virReportSystemError(errno, "%s", _("Unable to get local socket name"));
            goto error;
        }

        for (i = 0; i < nmap && !name; i++) {
            if (map[i].name == NULL)
                continue;

            if (addr.data.sa.sa_family == AF_INET) {
                if (map[i].family == AF_INET &&
                    addr.data.inet4.sin_port == htons(map[i].port))
                    name = map[i].name;
            } else if (addr.data.sa.sa_family == AF_INET6) {
                /* NB use of AF_INET here is correct. The "map" struct
                 * only refers to AF_INET. The socket may be AF_INET
                 * or AF_INET6
                 */
                if (map[i].family == AF_INET &&
                    addr.data.inet6.sin6_port == htons(map[i].port))
                    name = map[i].name;
#ifndef WIN32
            } else if (addr.data.sa.sa_family == AF_UNIX) {
                if (map[i].family == AF_UNIX &&
                    STREQLEN(map[i].path,
                             addr.data.un.sun_path,
                             sizeof(addr.data.un.sun_path)))
                    name = map[i].name;
#endif
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected socket family %d"),
                               addr.data.sa.sa_family);
                goto error;
            }
        }

        if (!name) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find name for FD %d socket family %d"),
                           nextfd, addr.data.sa.sa_family);
            goto error;
        }

        if (virSystemdActivationAddFD(act, name, nextfd) < 0)
            goto error;

        nfds--;
        nextfd++;
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

    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");

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

static virSystemdActivationPtr
virSystemdActivationNew(virSystemdActivationMap *map,
                        size_t nmap,
                        int nfds)
{
    virSystemdActivationPtr act;
    const char *fdnames;

    VIR_DEBUG("Activated with %d FDs", nfds);
    if (VIR_ALLOC(act) < 0)
        return NULL;

    if (!(act->fds = virHashCreate(10, virSystemdActivationEntryFree)))
        goto error;

    fdnames = getenv("LISTEN_FDNAMES");
    if (fdnames) {
        if (virSystemdActivationInitFromNames(act, nfds, fdnames) < 0)
            goto error;
    } else {
        if (virSystemdActivationInitFromMap(act, nfds, map, nmap) < 0)
            goto error;
    }

    VIR_DEBUG("Created activation object for %d FDs", nfds);
    return act;

 error:
    virSystemdActivationFree(&act);
    return NULL;
}


/**
 * virSystemdGetActivation:
 * @map: mapping of socket addresses to names
 * @nmap: number of entries in @map
 * @act: filled with allocated activation object
 *
 * Acquire an object for handling systemd activation.
 * If no activation FDs have been provided the returned object
 * will be NULL, indicating normal sevice setup can be performed
 * If the returned object is non-NULL then at least one file
 * descriptor will be present. No normal service setup should
 * be performed.
 *
 * Returns: 0 on success, -1 on failure
 */
int
virSystemdGetActivation(virSystemdActivationMap *map,
                        size_t nmap,
                        virSystemdActivationPtr *act)
{
    int nfds = 0;

    if ((nfds = virSystemdGetListenFDs()) < 0)
        return -1;

    if (nfds == 0) {
        VIR_DEBUG("No activation FDs present");
        *act = NULL;
        return 0;
    }

    *act = virSystemdActivationNew(map, nmap, nfds);
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
virSystemdActivationHasName(virSystemdActivationPtr act,
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
virSystemdActivationComplete(virSystemdActivationPtr act)
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
virSystemdActivationClaimFDs(virSystemdActivationPtr act,
                             const char *name,
                             int **fds,
                             size_t *nfds)
{
    virSystemdActivationEntryPtr ent = virHashSteal(act->fds, name);

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
virSystemdActivationFree(virSystemdActivationPtr *act)
{
    if (!*act)
        return;

    virHashFree((*act)->fds);

    VIR_FREE(*act);
}
