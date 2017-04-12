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

#define __VIR_SYSTEMD_PRIV_H_ALLOW__ 1
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

#define VIR_FROM_THIS VIR_FROM_SYSTEMD

VIR_LOG_INIT("util.systemd");

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif

static void virSystemdEscapeName(virBufferPtr buf,
                                 const char *name)
{
    static const char hextable[16] = "0123456789abcdef";

#define ESCAPE(c)                                                       \
    do {                                                                \
        virBufferAddChar(buf, '\\');                                    \
        virBufferAddChar(buf, 'x');                                     \
        virBufferAddChar(buf, hextable[(c >> 4) & 15]);                 \
        virBufferAddChar(buf, hextable[c & 15]);                        \
    } while (0)

#define VALID_CHARS                             \
        "0123456789"                            \
        "abcdefghijklmnopqrstuvwxyz"            \
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"            \
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

#define HOSTNAME_CHARS                                                  \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

static void
virSystemdAppendValidMachineName(virBufferPtr buf,
                                 const char *name)
{
    bool skip_dot = false;

    for (; *name; name++) {
        if (virBufferError(buf))
            break;
        if (strlen(virBufferCurrentContent(buf)) >= 64)
            break;

        if (*name == '.') {
            if (!skip_dot)
                virBufferAddChar(buf, *name);
            skip_dot = true;
            continue;
        }

        skip_dot = false;

        if (!strchr(HOSTNAME_CHARS, *name))
            continue;

        virBufferAddChar(buf, *name);
    }
}

#undef HOSTNAME_CHARS

char *
virSystemdMakeMachineName(const char *drivername,
                          int id,
                          const char *name,
                          bool privileged)
{
    char *machinename = NULL;
    char *username = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (privileged) {
        virBufferAsprintf(&buf, "%s-", drivername);
    } else {
        if (!(username = virGetUserName(geteuid())))
            goto cleanup;

        virBufferAsprintf(&buf, "%s-%s-", username, drivername);
    }

    virBufferAsprintf(&buf, "%d-", id);
    virSystemdAppendValidMachineName(&buf, name);

    machinename = virBufferContentAndReset(&buf);
 cleanup:
    VIR_FREE(username);

    return machinename;
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

    if (virDBusMessageRead(reply, "o", &object) < 0)
        goto cleanup;

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

    if (virDBusMessageRead(reply, "v", "s", &name) < 0)
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
                            const char *partition)
{
    int ret;
    DBusConnection *conn;
    char *creatorname = NULL;
    char *slicename = NULL;
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
                              rootdir ? rootdir : "",
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
                              rootdir ? rootdir : "",
                              3,
                              "Slice", "s", slicename,
                              "After", "as", 1, "libvirtd.service",
                              "Before", "as", 1, "virt-guest-shutdown.target") < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(creatorname);
    VIR_FREE(slicename);
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

    if (!(path = virGetEnvBlockSUID("NOTIFY_SOCKET"))) {
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

    if ((ret = virDBusMessageRead(message, "s", &response)) < 0)
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
