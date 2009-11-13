/*
 * qemu_monitor.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_monitor.h"
#include "qemu_monitor_text.h"
#include "qemu_conf.h"
#include "event.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

struct _qemuMonitor {
    virMutex lock;
    virCond notify;

    virDomainObjPtr dom;

    int fd;
    int watch;
    int hasSendFD;

    virDomainObjPtr vm;

    qemuMonitorEOFNotify eofCB;
    qemuMonitorDiskSecretLookup secretCB;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuMonitorMessagePtr msg;

    /* Buffer incoming data ready for Text/QMP monitor
     * code to process & find message boundaries */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer;

    /* If anything went wrong, this will be fed back
     * the next monitor msg */
    int lastErrno;

    /* If the monitor callback is currently active */
    unsigned eofcb: 1;
    /* If the monitor callback should free the closed monitor */
    unsigned closed: 1;
};

void qemuMonitorLock(qemuMonitorPtr mon)
{
    virMutexLock(&mon->lock);
}

void qemuMonitorUnlock(qemuMonitorPtr mon)
{
    virMutexUnlock(&mon->lock);
}


static void qemuMonitorFree(qemuMonitorPtr mon, int lockDomain)
{
    VIR_DEBUG("mon=%p, lockDomain=%d", mon, lockDomain);
    if (mon->vm) {
        if (lockDomain)
            virDomainObjLock(mon->vm);
        if (!virDomainObjUnref(mon->vm) && lockDomain)
            virDomainObjUnlock(mon->vm);
    }
    if (virCondDestroy(&mon->notify) < 0)
    {}
    virMutexDestroy(&mon->lock);
    VIR_FREE(mon);
}


static int
qemuMonitorOpenUnix(const char *monitor)
{
    struct sockaddr_un addr;
    int monfd;
    int timeout = 3; /* In seconds */
    int ret, i = 0;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(NULL, errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Monitor path %s too big for destination"), monitor);
        goto error;
    }

    do {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));

        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        virReportSystemError(NULL, errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;

    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if (ret != 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("monitor socket did not show up."));
        goto error;
    }

    return monfd;

error:
    close(monfd);
    return -1;
}

static int
qemuMonitorOpenPty(const char *monitor)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    return monfd;
}


static int
qemuMonitorIOProcess(qemuMonitorPtr mon)
{
    int len;
    qemuMonitorMessagePtr msg = NULL;

    /* See if there's a message & whether its ready for its reply
     * ie whether its completed writing all its data */
    if (mon->msg && mon->msg->txOffset == mon->msg->txLength)
        msg = mon->msg;

    VIR_DEBUG("Process %d", (int)mon->bufferOffset);
    len = qemuMonitorTextIOProcess(mon,
                                   mon->buffer, mon->bufferOffset,
                                   msg);

    if (len < 0) {
        mon->lastErrno = errno;
        return -1;
    }

    if (len < mon->bufferOffset) {
        memmove(mon->buffer, mon->buffer + len, mon->bufferOffset - len);
        mon->bufferOffset -= len;
    } else {
        VIR_FREE(mon->buffer);
        mon->bufferOffset = mon->bufferLength = 0;
    }
    VIR_DEBUG("Process done %d used %d", (int)mon->bufferOffset, len);
    if (msg && msg->finished)
        virCondBroadcast(&mon->notify);
    return len;
}


static int
qemuMonitorIOWriteWithFD(qemuMonitorPtr mon,
                         const char *data,
                         size_t len,
                         int fd)
{
    struct msghdr msg;
    struct iovec iov[1];
    int ret;
    char control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    if (!mon->hasSendFD) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));

    iov[0].iov_base = (void *)data;
    iov[0].iov_len = len;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    do {
        ret = sendmsg(mon->fd, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

/* Called when the monitor is able to write data */
static int
qemuMonitorIOWrite(qemuMonitorPtr mon)
{
    int done;

    /* If no active message, or fully transmitted, the no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    if (mon->msg->txFD == -1)
        done = write(mon->fd,
                     mon->msg->txBuffer + mon->msg->txOffset,
                     mon->msg->txLength - mon->msg->txOffset);
    else
        done = qemuMonitorIOWriteWithFD(mon,
                                        mon->msg->txBuffer + mon->msg->txOffset,
                                        mon->msg->txLength - mon->msg->txOffset,
                                        mon->msg->txFD);

    if (done < 0) {
        if (errno == EAGAIN)
            return 0;

        mon->lastErrno = errno;
        return -1;
    }
    mon->msg->txOffset += done;
    return done;
}

/*
 * Called when the monitor has incoming data to read
 *
 * Returns -1 on error, or number of bytes read
 */
static int
qemuMonitorIORead(qemuMonitorPtr mon)
{
    size_t avail = mon->bufferLength - mon->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (VIR_REALLOC_N(mon->buffer,
                          mon->bufferLength + 1024) < 0) {
            errno = ENOMEM;
            return -1;
        }
        mon->bufferLength += 1024;
        avail += 1024;
    }

    /* Read as much as we can get into our buffer,
       until we block on EAGAIN, or hit EOF */
    while (avail > 1) {
        int got;
        got = read(mon->fd,
                   mon->buffer + mon->bufferOffset,
                   avail - 1);
        if (got < 0) {
            if (errno == EAGAIN)
                break;
            mon->lastErrno = errno;
            ret = -1;
            break;
        }
        if (got == 0)
            break;

        ret += got;
        avail -= got;
        mon->bufferOffset += got;
        mon->buffer[mon->bufferOffset] = '\0';
    }

    VIR_DEBUG("Now read %d bytes of data", (int)mon->bufferOffset);

    return ret;
}


static void qemuMonitorUpdateWatch(qemuMonitorPtr mon)
{
    int events =
        VIR_EVENT_HANDLE_HANGUP |
        VIR_EVENT_HANDLE_ERROR;

    if (!mon->lastErrno) {
        events |= VIR_EVENT_HANDLE_READABLE;

        if (mon->msg && mon->msg->txOffset < mon->msg->txLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;
    }

    virEventUpdateHandle(mon->watch, events);
}


static void
qemuMonitorIO(int watch, int fd, int events, void *opaque) {
    qemuMonitorPtr mon = opaque;
    int quit = 0, failed = 0;

    qemuMonitorLock(mon);
    VIR_DEBUG("Monitor %p I/O on watch %d fd %d events %d", mon, watch, fd, events);

    if (mon->fd != fd || mon->watch != watch) {
        VIR_ERROR("event from unexpected fd %d!=%d / watch %d!=%d", mon->fd, fd, mon->watch, watch);
        failed = 1;
    } else {
        if (!mon->lastErrno &&
            events & VIR_EVENT_HANDLE_WRITABLE) {
            int done = qemuMonitorIOWrite(mon);
            if (done < 0)
                failed = 1;
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }
        if (!mon->lastErrno &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuMonitorIORead(mon);
            if (got < 0)
                failed = 1;
            /* Ignore hangup/error events if we read some data, to
             * give time for that data to be consumed */
            if (got > 0) {
                events = 0;

                if (qemuMonitorIOProcess(mon) < 0)
                    failed = 1;
            } else
                events &= ~VIR_EVENT_HANDLE_READABLE;
        }

        /* If IO process resulted in an error & we have a message,
         * then wakeup that waiter */
        if (mon->lastErrno && mon->msg && !mon->msg->finished) {
            mon->msg->lastErrno = mon->lastErrno;
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }

        qemuMonitorUpdateWatch(mon);

        if (events & VIR_EVENT_HANDLE_HANGUP) {
            /* If IO process resulted in EOF & we have a message,
             * then wakeup that waiter */
            if (mon->msg && !mon->msg->finished) {
                mon->msg->finished = 1;
                mon->msg->lastErrno = EIO;
                virCondSignal(&mon->notify);
            }
            quit = 1;
        } else if (events) {
            VIR_ERROR(_("unhandled fd event %d for monitor fd %d"),
                      events, mon->fd);
            failed = 1;
        }
    }

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (failed || quit) {
        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        mon->eofcb = 1;
        qemuMonitorUnlock(mon);
        VIR_DEBUG("Triggering EOF callback error? %d", failed);
        mon->eofCB(mon, mon->vm, failed);

        qemuMonitorLock(mon);
        if (mon->closed) {
            qemuMonitorUnlock(mon);
            VIR_DEBUG("Delayed free of monitor %p", mon);
            qemuMonitorFree(mon, 1);
        } else {
            qemuMonitorUnlock(mon);
        }
    } else {
        qemuMonitorUnlock(mon);
    }
}


qemuMonitorPtr
qemuMonitorOpen(virDomainObjPtr vm,
                qemuMonitorEOFNotify eofCB)
{
    qemuMonitorPtr mon;

    if (VIR_ALLOC(mon) < 0) {
        virReportOOMError(NULL);
        return NULL;
    }

    if (virMutexInit(&mon->lock) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("cannot initialize monitor mutex"));
        VIR_FREE(mon);
        return NULL;
    }
    if (virCondInit(&mon->notify) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("cannot initialize monitor condition"));
        virMutexDestroy(&mon->lock);
        VIR_FREE(mon);
        return NULL;
    }
    mon->fd = -1;
    mon->vm = vm;
    mon->eofCB = eofCB;
    qemuMonitorLock(mon);
    virDomainObjRef(vm);

    switch (vm->monitor_chr->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        mon->hasSendFD = 1;
        mon->fd = qemuMonitorOpenUnix(vm->monitor_chr->data.nix.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        mon->fd = qemuMonitorOpenPty(vm->monitor_chr->data.file.path);
        break;

    default:
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to handle monitor type: %s"),
                         virDomainChrTypeToString(vm->monitor_chr->type));
        goto cleanup;
    }

    if (mon->fd == -1) goto cleanup;

    if (virSetCloseExec(mon->fd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to set monitor close-on-exec flag"));
        goto cleanup;
    }
    if (virSetNonBlock(mon->fd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to put monitor into non-blocking mode"));
        goto cleanup;
    }


    if ((mon->watch = virEventAddHandle(mon->fd,
                                        VIR_EVENT_HANDLE_HANGUP |
                                        VIR_EVENT_HANDLE_ERROR |
                                        VIR_EVENT_HANDLE_READABLE,
                                        qemuMonitorIO,
                                        mon, NULL)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("unable to register monitor events"));
        goto cleanup;
    }

    VIR_DEBUG("New mon %p fd =%d watch=%d", mon, mon->fd, mon->watch);
    qemuMonitorUnlock(mon);

    return mon;

cleanup:
    qemuMonitorUnlock(mon);
    qemuMonitorClose(mon);
    return NULL;
}


void qemuMonitorClose(qemuMonitorPtr mon)
{
    if (!mon)
        return;

    qemuMonitorLock(mon);
    if (!mon->closed) {
        if (mon->watch)
            virEventRemoveHandle(mon->watch);
        if (mon->fd != -1)
            close(mon->fd);
        /* NB: don't reset  fd / watch fields, since active
         * callback may still want them */
        mon->closed = 1;
    }

    if (mon->eofcb) {
        VIR_DEBUG("Mark monitor to be deleted %p", mon);
        qemuMonitorUnlock(mon);
    } else {
        VIR_DEBUG("Delete monitor now %p", mon);
        qemuMonitorFree(mon, 0);
    }
}


void qemuMonitorRegisterDiskSecretLookup(qemuMonitorPtr mon,
                                         qemuMonitorDiskSecretLookup secretCB)
{
    mon->secretCB = secretCB;
}


int qemuMonitorSend(qemuMonitorPtr mon,
                    qemuMonitorMessagePtr msg)
{
    int ret = -1;

    if (mon->eofcb) {
        msg->lastErrno = EIO;
        qemuMonitorUnlock(mon);
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->lock) < 0)
            goto cleanup;
    }

    if (mon->lastErrno == 0)
        ret = 0;

cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}


int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                             virConnectPtr conn,
                             const char *path,
                             char **secret,
                             size_t *secretLen)
{
    *secret = NULL;
    *secretLen = 0;

    return mon->secretCB(mon, conn, mon->vm, path, secret, secretLen);
}


int
qemuMonitorStartCPUs(qemuMonitorPtr mon,
                     virConnectPtr conn)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextStartCPUs(mon, conn);
}


int
qemuMonitorStopCPUs(qemuMonitorPtr mon)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextStopCPUs(mon);
}


int qemuMonitorSystemPowerdown(qemuMonitorPtr mon)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextSystemPowerdown(mon);
}


int qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                          int **pids)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextGetCPUInfo(mon, pids);
}

int qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long *currmem)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextGetBalloonInfo(mon, currmem);
}


int qemuMonitorGetBlockStatsInfo(qemuMonitorPtr mon,
                                 const char *devname,
                                 long long *rd_req,
                                 long long *rd_bytes,
                                 long long *wr_req,
                                 long long *wr_bytes,
                                 long long *errs)
{
    DEBUG("mon=%p, fd=%d dev=%s", mon, mon->fd, devname);

    return qemuMonitorTextGetBlockStatsInfo(mon, devname,
                                            rd_req, rd_bytes,
                                            wr_req, wr_bytes,
                                            errs);
}


int qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                              const char *password)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextSetVNCPassword(mon, password);
}


int qemuMonitorSetBalloon(qemuMonitorPtr mon,
                          unsigned long newmem)
{
    DEBUG("mon=%p, fd=%d newmem=%lu", mon, mon->fd, newmem);

    return qemuMonitorTextSetBalloon(mon, newmem);
}

int qemuMonitorEjectMedia(qemuMonitorPtr mon,
                          const char *devname)
{
    DEBUG("mon=%p, fd=%d devname=%s", mon, mon->fd, devname);

    return qemuMonitorTextEjectMedia(mon, devname);
}


int qemuMonitorChangeMedia(qemuMonitorPtr mon,
                           const char *devname,
                           const char *newmedia)
{
    DEBUG("mon=%p, fd=%d devname=%s newmedia=%s",
          mon, mon->fd, devname, newmedia);

    return qemuMonitorTextChangeMedia(mon, devname, newmedia);
}


int qemuMonitorSaveVirtualMemory(qemuMonitorPtr mon,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path)
{
    DEBUG("mon=%p, fd=%d offset=%llu length=%zu path=%s",
          mon, mon->fd, offset, length, path);

    return qemuMonitorTextSaveVirtualMemory(mon, offset, length, path);
}

int qemuMonitorSavePhysicalMemory(qemuMonitorPtr mon,
                                  unsigned long long offset,
                                  size_t length,
                                  const char *path)
{
    DEBUG("mon=%p, fd=%d offset=%llu length=%zu path=%s",
          mon, mon->fd, offset, length, path);

    return qemuMonitorTextSavePhysicalMemory(mon, offset, length, path);
}


int qemuMonitorSetMigrationSpeed(qemuMonitorPtr mon,
                                 unsigned long bandwidth)
{
    DEBUG("mon=%p, fd=%d bandwidth=%lu", mon, mon->fd, bandwidth);

    return qemuMonitorTextSetMigrationSpeed(mon, bandwidth);
}

int qemuMonitorGetMigrationStatus(qemuMonitorPtr mon,
                                  int *status,
                                  unsigned long long *transferred,
                                  unsigned long long *remaining,
                                  unsigned long long *total)
{
    DEBUG("mon=%p, fd=%d", mon, mon->fd);

    return qemuMonitorTextGetMigrationStatus(mon, status,
                                             transferred,
                                             remaining,
                                             total);
}


int qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                             int background,
                             const char *hostname,
                             int port)
{
    DEBUG("mon=%p, fd=%d hostname=%s port=%d",
          mon, mon->fd, hostname, port);

    return qemuMonitorTextMigrateToHost(mon, background, hostname, port);
}


int qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                                int background,
                                const char * const *argv,
                                const char *target)
{
    DEBUG("mon=%p, fd=%d argv=%p target=%s",
          mon, mon->fd, argv, target);

    return qemuMonitorTextMigrateToCommand(mon, background, argv, target);
}

int qemuMonitorMigrateToUnix(qemuMonitorPtr mon,
                             int background,
                             const char *unixfile)
{
    DEBUG("mon=%p fd=%d unixfile=%s",
          mon, mon->fd, unixfile);

    return qemuMonitorTextMigrateToUnix(mon, background, unixfile);
}

int qemuMonitorMigrateCancel(qemuMonitorPtr mon)
{
    DEBUG("mon=%p fd=%d", mon, mon->fd);

    return qemuMonitorTextMigrateCancel(mon);
}

int qemuMonitorAddUSBDisk(qemuMonitorPtr mon,
                          const char *path)
{
    DEBUG("mon=%p, fd=%d path=%s", mon, mon->fd, path);

    return qemuMonitorTextAddUSBDisk(mon, path);
}


int qemuMonitorAddUSBDeviceExact(qemuMonitorPtr mon,
                                 int bus,
                                 int dev)
{
    DEBUG("mon=%p, fd=%d bus=%d dev=%d", mon, mon->fd, bus, dev);

    return qemuMonitorTextAddUSBDeviceExact(mon, bus, dev);
}

int qemuMonitorAddUSBDeviceMatch(qemuMonitorPtr mon,
                                 int vendor,
                                 int product)
{
    DEBUG("mon=%p, fd=%d vendor=%d product=%d",
          mon, mon->fd, vendor, product);

    return qemuMonitorTextAddUSBDeviceMatch(mon, vendor, product);
}


int qemuMonitorAddPCIHostDevice(qemuMonitorPtr mon,
                                unsigned hostDomain,
                                unsigned hostBus,
                                unsigned hostSlot,
                                unsigned hostFunction,
                                unsigned *guestDomain,
                                unsigned *guestBus,
                                unsigned *guestSlot)
{
    DEBUG("mon=%p, fd=%d domain=%d bus=%d slot=%d function=%d",
          mon, mon->fd,
          hostDomain, hostBus, hostSlot, hostFunction);

    return qemuMonitorTextAddPCIHostDevice(mon, hostDomain,
                                           hostBus, hostSlot,
                                           hostFunction,
                                           guestDomain,
                                           guestBus,
                                           guestSlot);
}


int qemuMonitorAddPCIDisk(qemuMonitorPtr mon,
                          const char *path,
                          const char *bus,
                          unsigned *guestDomain,
                          unsigned *guestBus,
                          unsigned *guestSlot)
{
    DEBUG("mon=%p, fd=%d path=%s bus=%s",
          mon, mon->fd, path, bus);

    return qemuMonitorTextAddPCIDisk(mon, path, bus,
                                     guestDomain, guestBus, guestSlot);
}


int qemuMonitorAddPCINetwork(qemuMonitorPtr mon,
                             const char *nicstr,
                             unsigned *guestDomain,
                             unsigned *guestBus,
                             unsigned *guestSlot)
{
    DEBUG("mon=%p, fd=%d nicstr=%s", mon, mon->fd, nicstr);

    return qemuMonitorTextAddPCINetwork(mon, nicstr, guestDomain,
                                        guestBus, guestSlot);
}


int qemuMonitorRemovePCIDevice(qemuMonitorPtr mon,
                               unsigned guestDomain,
                               unsigned guestBus,
                               unsigned guestSlot)
{
    DEBUG("mon=%p, fd=%d domain=%d bus=%d slot=%d",
          mon, mon->fd, guestDomain, guestBus, guestSlot);

    return qemuMonitorTextRemovePCIDevice(mon, guestDomain,
                                          guestBus, guestSlot);
}


int qemuMonitorSendFileHandle(qemuMonitorPtr mon,
                              const char *fdname,
                              int fd)
{
    DEBUG("mon=%p, fd=%d fdname=%s fd=%d",
          mon, mon->fd, fdname, fd);

    return qemuMonitorTextSendFileHandle(mon, fdname, fd);
}


int qemuMonitorCloseFileHandle(qemuMonitorPtr mon,
                               const char *fdname)
{
    DEBUG("mon=%p, fd=%d fdname=%s",
          mon, mon->fd, fdname);

    return qemuMonitorTextCloseFileHandle(mon, fdname);
}


int qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                              const char *netstr)
{
    DEBUG("mon=%p, fd=%d netstr=%s",
          mon, mon->fd, netstr);

    return qemuMonitorTextAddHostNetwork(mon, netstr);
}


int qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                                 int vlan,
                                 const char *netname)
{
    DEBUG("mon=%p, fd=%d netname=%s",
          mon, mon->fd, netname);

    return qemuMonitorTextRemoveHostNetwork(mon, vlan, netname);
}
