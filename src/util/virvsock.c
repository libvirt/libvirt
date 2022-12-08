/*
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

#ifdef WITH_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef __linux__
# include <linux/vhost.h>
#endif

#include "virvsock.h"

#include "virerror.h"
#include "virlog.h"


#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.vsock");

#ifdef __linux__
static int
virVsockSetGuestCidQuiet(int fd,
                         unsigned int guest_cid)
{
    uint64_t val = guest_cid;

    return ioctl(fd, VHOST_VSOCK_SET_GUEST_CID, &val);
}

#else
static int
virVsockSetGuestCidQuiet(int fd G_GNUC_UNUSED,
                         unsigned int guest_cid G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif


/**
 * virVsockSetGuestCid:
 * @fd: file descriptor of a vsock interface
 * @guest_cid: guest CID to be set
 *
 * Wrapper for VHOST_VSOCK_SET_GUEST_CID ioctl.
 * Returns: 0 on success, -1 on error.
 */
int
virVsockSetGuestCid(int fd,
                    unsigned int guest_cid)
{
    if (virVsockSetGuestCidQuiet(fd, guest_cid) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to set guest cid"));
        return -1;
    }

    return 0;
}

#define VIR_VSOCK_GUEST_CID_MIN 3

/**
 * virVsockAcquireGuestCid:
 * @fd: file descriptor of a vsock interface
 * @guest_cid: where to store the guest CID
 *
 * Iterates over usable CIDs until a free one is found.
 * Returns: 0 on success, with the acquired CID stored in guest_cid
 *         -1 on error.
 */
int
virVsockAcquireGuestCid(int fd,
                        unsigned int *guest_cid)
{
    unsigned int cid = VIR_VSOCK_GUEST_CID_MIN;

    for (; virVsockSetGuestCidQuiet(fd, cid) < 0; cid++) {
        if (errno != EADDRINUSE) {
            virReportSystemError(errno, "%s",
                                 _("failed to acquire guest cid"));
            return -1;
        }
    }
    *guest_cid = cid;

    return 0;
}
