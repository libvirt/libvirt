/*
 * openvz_config.h: config information for OpenVZ VPSs
 *
 * Copyright (C) 2006, 2007 Binary Karma.
 * Copyright (C) 2006 Shuveb Hussain
 * Copyright (C) 2007 Anoop Joe Cyriac
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
 * Authors:
 * Shuveb Hussain <shuveb@binarykarma.com>
 * Anoop Joe Cyriac <anoop@binarykarma.com>
 *
 */

#ifndef OPENVZ_CONF_H
#define OPENVZ_CONF_H

#include "internal.h"
#include "domain_conf.h"
#include "threads.h"

enum { OPENVZ_WARN, OPENVZ_ERR };

#define openvzError(conn, code, fmt...)                                      \
        virReportErrorHelper(conn, VIR_FROM_OPENVZ, code, __FILE__,        \
                               __FUNCTION__, __LINE__, fmt)


/* OpenVZ commands - Replace with wrapper scripts later? */
#define VZLIST  "/usr/sbin/vzlist"
#define VZCTL   "/usr/sbin/vzctl"

#define VZCTL_BRIDGE_MIN_VERSION ((3 * 1000 * 1000) + (0 * 1000) + 22 + 1)

struct openvz_driver {
    virMutex lock;

    virCapsPtr caps;
    virDomainObjList domains;
    int version;
};

int openvz_readline(int fd, char *ptr, int maxlen);
int openvzExtractVersion(virConnectPtr conn,
                         struct openvz_driver *driver);
int openvzReadConfigParam(int vpsid ,const char * param, char *value, int maxlen);
int openvzWriteConfigParam(int vpsid, const char *param, const char *value);
virCapsPtr openvzCapsInit(void);
int openvzLoadDomains(struct openvz_driver *driver);
void openvzFreeDriver(struct openvz_driver *driver);
int strtoI(const char *str);
int openvzSetDefinedUUID(int vpsid, unsigned char *uuid);
unsigned int openvzGetNodeCPUs(void);

#endif /* OPENVZ_CONF_H */
