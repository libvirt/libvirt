/*
 * xenapi_utils.h: Xen API driver -- utils header
 * Copyright (C) 2009, 2010 Citrix Ltd.
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
 * Author: Sharadha Prabhakar <sharadha.prabhakar@citrix.com>
 */

#ifndef __VIR_XENAPI_UTILS__
# define __VIR_XENAPI_UTILS__

# include <stdint.h>
# include <xen/api/xen_all.h>
# include "internal.h"
# include "viruri.h"
# include "domain_conf.h"

# define NETWORK_DEVID_SIZE  (12)

typedef uint64_t cpumap_t;

void
xenSessionFree(xen_session *session);

char *
xenapiUtil_RequestPassword(virConnectAuthPtr auth, const char *username,
                           const char *hostname);

int
xenapiUtil_ParseQuery(virConnectPtr conn, virURIPtr uri, int *noVerify);

enum xen_on_normal_exit
actionShutdownLibvirt2XenapiEnum(enum virDomainLifecycleAction action);

enum xen_on_crash_behaviour
actionCrashLibvirt2XenapiEnum(enum virDomainLifecycleCrashAction action);

char *
createXenAPIBootOrderString(int nboot, int *bootDevs);

enum virDomainBootOrder map2LibvirtBootOrder(char c);

enum virDomainLifecycleAction
xenapiNormalExitEnum2virDomainLifecycle(enum xen_on_normal_exit action);

enum virDomainLifecycleCrashAction
xenapiCrashExitEnum2virDomainLifecycle(enum xen_on_crash_behaviour action);

void getCpuBitMapfromString(char *mask, unsigned char *cpumap, int maplen);

int getStorageVolumeType(char *type);

char *returnErrorFromSession(xen_session *session);

virDomainState
mapPowerState(enum xen_vm_power_state state);

char *
mapDomainPinVcpu(unsigned char *cpumap, int maplen);

int
createVMRecordFromXml (virConnectPtr conn, virDomainDefPtr defPtr,
                       xen_vm_record **record, xen_vm *vm);

int
allocStringMap (xen_string_string_map **strings, char *key, char *val);

#endif /* __VIR_XENAPI_UTILS__ */
