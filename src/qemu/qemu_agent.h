/*
 * qemu_agent.h: interaction with QEMU guest agent
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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


#ifndef __QEMU_AGENT_H__
# define __QEMU_AGENT_H__

# include "internal.h"
# include "domain_conf.h"

typedef struct _qemuAgent qemuAgent;
typedef qemuAgent *qemuAgentPtr;

typedef struct _qemuAgentCallbacks qemuAgentCallbacks;
typedef qemuAgentCallbacks *qemuAgentCallbacksPtr;
struct _qemuAgentCallbacks {
    void (*destroy)(qemuAgentPtr mon,
                    virDomainObjPtr vm);
    void (*eofNotify)(qemuAgentPtr mon,
                      virDomainObjPtr vm);
    void (*errorNotify)(qemuAgentPtr mon,
                        virDomainObjPtr vm);
};


qemuAgentPtr qemuAgentOpen(virDomainObjPtr vm,
                           virDomainChrSourceDefPtr config,
                           qemuAgentCallbacksPtr cb);

void qemuAgentLock(qemuAgentPtr mon);
void qemuAgentUnlock(qemuAgentPtr mon);

int qemuAgentRef(qemuAgentPtr mon);
int qemuAgentUnref(qemuAgentPtr mon) ATTRIBUTE_RETURN_CHECK;

void qemuAgentClose(qemuAgentPtr mon);

typedef enum {
    QEMU_AGENT_SHUTDOWN_POWERDOWN,
    QEMU_AGENT_SHUTDOWN_REBOOT,
    QEMU_AGENT_SHUTDOWN_HALT,

    QEMU_AGENT_SHUTDOWN_LAST,
} qemuAgentShutdownMode;

int qemuAgentShutdown(qemuAgentPtr mon,
                      qemuAgentShutdownMode mode);

int qemuAgentFSFreeze(qemuAgentPtr mon);
int qemuAgentFSThaw(qemuAgentPtr mon);

int qemuAgentSuspend(qemuAgentPtr mon,
                     unsigned int target);
#endif /* __QEMU_AGENT_H__ */
