/*
 * qemu_rdp.h: QEMU RDP support
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

#pragma once

#include "qemu_conf.h"
#include "virbitmap.h"
#include "virenum.h"

typedef enum {
    QEMU_RDP_FEATURE_NONE = 0,

    QEMU_RDP_FEATURE_DBUS_ADDRESS,
    QEMU_RDP_FEATURE_REMOTEFX,
    QEMU_RDP_FEATURE_LAST,
} qemuRdpFeature;

VIR_ENUM_DECL(qemuRdpFeature);

typedef struct _qemuRdp qemuRdp;
struct _qemuRdp {
    int fd[2];
    virBitmap *features;
    pid_t pid;
    guint name_watch;
    bool name_appeared;
    guint leaving_id;
};

qemuRdp *qemuRdpNew(void);

qemuRdp *qemuRdpNewForHelper(const char *helper);

void qemuRdpFree(qemuRdp *rdp);

void qemuRdpSetFeature(qemuRdp *rdp,
                       qemuRdpFeature feature);

bool qemuRdpHasFeature(const qemuRdp *rdp,
                       qemuRdpFeature feature);

int qemuRdpStart(virDomainObj *vm,
                 virDomainGraphicsDef *gfx);

void qemuRdpStop(virDomainObj *vm,
                 virDomainGraphicsDef *gfx);

int qemuRdpSetupCgroup(qemuRdp *rdp,
                       virCgroup *cgroup);

int qemuRdpSetCredentials(virDomainObj *vm,
                          const char *username,
                          const char *password,
                          const char *domain);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuRdp, qemuRdpFree);
