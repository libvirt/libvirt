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

#ifdef WITH_SYSTEMD_DAEMON
# include <systemd/sd-daemon.h>
#endif

#include "virsystemd.h"
#include "viratomic.h"
#include "virdbus.h"
#include "virstring.h"
#include "viralloc.h"
#include "virutil.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_SYSTEMD

VIR_LOG_INIT("util.systemd");

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
                              const char *drivername)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "machine-");
    virSystemdEscapeName(&buf, drivername);
    virBufferAddLit(&buf, "\\x2d");
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

char *virSystemdMakeMachineName(const char *name,
                                const char *drivername,
                                bool privileged)
{
    char *machinename = NULL;
    char *username = NULL;
    if (privileged) {
        if (virAsprintf(&machinename, "%s-%s", drivername, name) < 0)
            goto cleanup;
    } else {
        if (!(username = virGetUserName(geteuid())))
            goto cleanup;
        if (virAsprintf(&machinename, "%s-%s-%s", username, drivername, name) < 0)
            goto cleanup;
    }

 cleanup:
    VIR_FREE(username);

    return machinename;
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
                            bool privileged,
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
    char *machinename = NULL;
    char *creatorname = NULL;
    char *slicename = NULL;
    static int hasCreateWithNetwork = 1;

    ret = virDBusIsServiceEnabled("org.freedesktop.machine1");
    if (ret < 0)
        return ret;

    if ((ret = virDBusIsServiceRegistered("org.freedesktop.systemd1")) < 0)
        return ret;

    if (!(conn = virDBusGetSystemBus()))
        return -1;

    ret = -1;
    if (!(machinename = virSystemdMakeMachineName(name, drivername, privileged)))
        goto cleanup;

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
                              machinename,
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
                              "Before", "as", 1, "libvirt-guests.service") < 0)
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
                              machinename,
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
                              "Before", "as", 1, "libvirt-guests.service") < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(creatorname);
    VIR_FREE(machinename);
    VIR_FREE(slicename);
    return ret;
}

int virSystemdTerminateMachine(const char *name,
                               const char *drivername,
                               bool privileged)
{
    int ret;
    DBusConnection *conn;
    char *machinename = NULL;
    virError error;

    memset(&error, 0, sizeof(error));

    ret = virDBusIsServiceEnabled("org.freedesktop.machine1");
    if (ret < 0)
        goto cleanup;

    if ((ret = virDBusIsServiceRegistered("org.freedesktop.systemd1")) < 0)
        goto cleanup;

    ret = -1;

    if (!(conn = virDBusGetSystemBus()))
        goto cleanup;

    if (!(machinename = virSystemdMakeMachineName(name, drivername, privileged)))
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
                          machinename) < 0)
        goto cleanup;

    if (error.code == VIR_ERR_ERROR &&
        STRNEQ_NULLABLE("org.freedesktop.machine1.NoSuchMachine",
                        error.str1)) {
        virReportErrorObject(&error);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virResetError(&error);

    VIR_FREE(machinename);
    return ret;
}

void
virSystemdNotifyStartup(void)
{
#ifdef WITH_SYSTEMD_DAEMON
    sd_notify(0, "READY=1");
#endif
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
