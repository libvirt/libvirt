/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "qemu_conf.h"

typedef struct _qemuVnc qemuVnc;
struct _qemuVnc {
    pid_t pid;
    guint name_watch;
    bool name_appeared;
    guint leaving_id;
};

bool
qemuVncAvailable(const char *helper);

qemuVnc *
qemuVncNew(void);

void
qemuVncFree(qemuVnc *vnc);

int
qemuVncStart(virDomainObj *vm,
             virDomainGraphicsDef *gfx);

void
qemuVncStop(virDomainObj *vm,
            virDomainGraphicsDef *gfx);

int
qemuVncSetupCgroup(qemuVnc *vnc,
                   virCgroup *cgroup);

int
qemuVncSetPassword(virDomainObj *vm,
                   const char *password);

int
qemuVncReloadCertificates(virDomainObj *vm);

int
qemuVncAddClient(virDomainObj *vm,
                 int fd,
                 bool skipauth);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuVnc, qemuVncFree);
