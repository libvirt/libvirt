/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_domain.h: LXC domain helpers
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


#ifndef __LXC_DOMAIN_H__
# define __LXC_DOMAIN_H__

# include "vircgroup.h"
# include "lxc_conf.h"
# include "lxc_monitor.h"

typedef enum {
    VIR_LXC_DOMAIN_NAMESPACE_SHARENET = 0,
    VIR_LXC_DOMAIN_NAMESPACE_SHAREIPC,
    VIR_LXC_DOMAIN_NAMESPACE_SHAREUTS,
    VIR_LXC_DOMAIN_NAMESPACE_LAST,
} virLXCDomainNamespace;

typedef enum {
    VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NONE,
    VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NAME,
    VIR_LXC_DOMAIN_NAMESPACE_SOURCE_PID,
    VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NETNS,

    VIR_LXC_DOMAIN_NAMESPACE_SOURCE_LAST,
} virLXCDomainNamespaceSource;

VIR_ENUM_DECL(virLXCDomainNamespace)
VIR_ENUM_DECL(virLXCDomainNamespaceSource)

typedef struct _lxcDomainDef lxcDomainDef;
typedef lxcDomainDef *lxcDomainDefPtr;
struct _lxcDomainDef {
    int ns_source[VIR_LXC_DOMAIN_NAMESPACE_LAST]; /* virLXCDomainNamespaceSource */
    char *ns_val[VIR_LXC_DOMAIN_NAMESPACE_LAST];
};

typedef struct _virLXCDomainObjPrivate virLXCDomainObjPrivate;
typedef virLXCDomainObjPrivate *virLXCDomainObjPrivatePtr;
struct _virLXCDomainObjPrivate {
    virLXCMonitorPtr monitor;
    bool doneStopEvent;
    int stopReason;
    bool wantReboot;

    pid_t initpid;

    virCgroupPtr cgroup;
};

extern virDomainXMLNamespace virLXCDriverDomainXMLNamespace;
extern virDomainXMLPrivateDataCallbacks virLXCDriverPrivateDataCallbacks;
extern virDomainDefParserConfig virLXCDriverDomainDefParserConfig;

#endif /* __LXC_DOMAIN_H__ */
