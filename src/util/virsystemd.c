/*
 * virsystemd.c: helpers for using systemd APIs
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#include "virsystemd.h"
#include "virdbus.h"
#include "virstring.h"
#include "viralloc.h"
#include "virutil.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_SYSTEMD

/**
 * virSystemdCreateMachine:
 * @name: driver unique name of the machine
 * @drivername: name of the virt driver
 * @privileged: whether driver is running privileged or per user
 * @uuid: globally unique UUID of the machine
 * @rootdir: root directory of machine filesystem
 * @pidleader: PID of the leader process
 * @slice: name of the slice to place the machine in
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
                            const char *partition)
{
    int ret = -1;
    DBusConnection *conn;
    char *machinename = NULL;
    char *creatorname = NULL;
    char *username = NULL;
    char *slicename = NULL;

    if (!(conn = virDBusGetSystemBus()))
        return -1;

    if (privileged) {
        if (virAsprintf(&machinename, "%s-%s", drivername, name) < 0)
            goto cleanup;
    } else {
        if (!(username = virGetUserName(geteuid())))
            goto cleanup;
        if (virAsprintf(&machinename, "%s-%s-%s", username, drivername, name) < 0)
            goto cleanup;
    }

    if (virAsprintf(&creatorname, "libvirt-%s", drivername) < 0)
        goto cleanup;

    if (partition) {
        if (virAsprintf(&slicename, "%s.slice", partition) < 0)
            goto cleanup;
    } else {
        if (VIR_STRDUP(slicename, "") < 0)
            goto cleanup;
    }

    /*
     * The systemd DBus API we're invoking has the
     * following signature
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
     * @scope_properties:an array (not a dict!) of properties that are
     * passed on to PID 1 when creating a scope unit for your machine.
     * Will allow initial settings for the cgroup & similar.
     *
     * @path: a bus path returned for the machine object created, to
     * allow further API calls to be made against the object.
     */

    VIR_DEBUG("Attempting to create machine via systemd");
    if (virDBusCallMethod(conn,
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
                          1, "Slice", "s",
                          slicename) < 0) {
        virErrorPtr err = virGetLastError();
        if (err->code == VIR_ERR_DBUS_SERVICE &&
            STREQ(err->str2, "org.freedesktop.DBus.Error.ServiceUnknown")) {
            virResetLastError();
            ret = -2;
        }
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(username);
    VIR_FREE(creatorname);
    VIR_FREE(machinename);
    return ret;
}
