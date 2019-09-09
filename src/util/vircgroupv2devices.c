/*
 * vircgroupv2devices.c: methods for cgroups v2 BPF devices
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

#if HAVE_DECL_BPF_CGROUP_DEVICE
# include <fcntl.h>
# include <linux/bpf.h>
# include <sys/stat.h>
# include <sys/syscall.h>
# include <sys/types.h>
#endif /* !HAVE_DECL_BPF_CGROUP_DEVICE */

#include "internal.h"

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "virbpf.h"
#include "vircgroup.h"
#include "vircgroupv2devices.h"
#include "virfile.h"
#include "virlog.h"

VIR_LOG_INIT("util.cgroup");

#define VIR_FROM_THIS VIR_FROM_CGROUP

#if HAVE_DECL_BPF_CGROUP_DEVICE
bool
virCgroupV2DevicesAvailable(virCgroupPtr group)
{
    VIR_AUTOCLOSE cgroupfd = -1;
    unsigned int progCnt = 0;

    cgroupfd = open(group->unified.mountPoint, O_RDONLY);
    if (cgroupfd < 0) {
        VIR_DEBUG("failed to open cgroup '%s'", group->unified.mountPoint);
        return false;
    }

    if (virBPFQueryProg(cgroupfd, 0, BPF_CGROUP_DEVICE, &progCnt, NULL) < 0) {
        VIR_DEBUG("failed to query cgroup progs");
        return false;
    }

    return true;
}
#else /* !HAVE_DECL_BPF_CGROUP_DEVICE */
bool
virCgroupV2DevicesAvailable(virCgroupPtr group G_GNUC_UNUSED)
{
    return false;
}
#endif /* !HAVE_DECL_BPF_CGROUP_DEVICE */
