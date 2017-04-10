/*
 * virsh-util.c: helpers for virsh
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

#include <config.h>

#include "virsh-util.h"

#include "virfile.h"

int
virshDomainState(vshControl *ctl,
                 virDomainPtr dom,
                 int *reason)
{
    virDomainInfo info;
    virshControlPtr priv = ctl->privData;

    if (reason)
        *reason = -1;

    if (!priv->useGetInfo) {
        int state;
        if (virDomainGetState(dom, &state, reason, 0) < 0) {
            virErrorPtr err = virGetLastError();
            if (err && err->code == VIR_ERR_NO_SUPPORT)
                priv->useGetInfo = true;
            else
                return -1;
        } else {
            return state;
        }
    }

    /* fall back to virDomainGetInfo if virDomainGetState is not supported */
    if (virDomainGetInfo(dom, &info) < 0)
        return -1;
    else
        return info.state;
}


int
virshStreamSink(virStreamPtr st ATTRIBUTE_UNUSED,
                const char *bytes,
                size_t nbytes,
                void *opaque)
{
    int *fd = opaque;

    return safewrite(*fd, bytes, nbytes);
}
