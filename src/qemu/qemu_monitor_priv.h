/*
 * qemu_monitor_priv.h: interaction with QEMU monitor console (private)
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

#ifndef LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
# error "qemu_monitor_priv.h may only be included by qemu_monitor.c or test suites"
#endif /* LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW */

#pragma once

#include "qemu_monitor.h"

#include <gio/gio.h>


struct _qemuMonitorMessage {
    int txFD;

    const char *txBuffer;
    int txOffset;
    int txLength;

    /* Used by the JSON monitor to hold reply / error */
    void *rxObject;

    /* True if rxObject is ready, or a fatal error occurred on the monitor channel */
    bool finished;
};


struct _qemuMonitor {
    virObjectLockable parent;

    virCond notify;

    int fd;

    GMainContext *context;
    GSocket *socket;
    GSource *watch;

    virDomainObj *vm;
    char *domainName;

    qemuMonitorCallbacks *cb;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuMonitorMessage *msg;

    /* Buffer incoming data ready for Text/QMP monitor
     * code to process & find message boundaries */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer;

    /* If anything went wrong, this will be fed back
     * the next monitor msg */
    virError lastError;

    /* Set to true when EOF is detected on the monitor */
    bool goteof;

    int nextSerial;

    bool waitGreeting;

    /* If found, path to the virtio memballoon driver */
    char *balloonpath;
    bool ballooninit;

    /* Log file context of the qemu process to dig for usable info */
    qemuMonitorReportDomainLogError logFunc;
    void *logOpaque;
    virFreeCallback logDestroy;

    /* true if qemu no longer wants 'props' sub-object of object-add */
    bool objectAddNoWrap;
    /* query-named-block-nodes supports the 'flat' option */
    bool queryNamedBlockNodesFlat;
};


void
qemuMonitorResetCommandID(qemuMonitor *mon);

int
qemuMonitorIOWriteWithFD(qemuMonitor *mon,
                         const char *data,
                         size_t len,
                         int fd)
    G_NO_INLINE;
