/*
 * bridge_driver.h: core driver methods for managing networks
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef __VIR_NETWORK__DRIVER_H
# define __VIR_NETWORK__DRIVER_H

# include "internal.h"
# include "network_conf.h"
# include "domain_conf.h"
# include "vircommand.h"
# include "virdnsmasq.h"

int networkRegister(void);

# if WITH_NETWORK
int networkAllocateActualDevice(virDomainDefPtr dom,
                                virDomainNetDefPtr iface)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int networkNotifyActualDevice(virDomainDefPtr dom,
                              virDomainNetDefPtr iface)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int networkReleaseActualDevice(virDomainDefPtr dom,
                               virDomainNetDefPtr iface)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int networkGetNetworkAddress(const char *netname, char **netaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int networkDnsmasqConfContents(virNetworkObjPtr network,
                        const char *pidfile,
                        char **configstr,
                        dnsmasqContext *dctx,
                        dnsmasqCapsPtr caps);
# else
/* Define no-op replacements that don't drag in any link dependencies.  */
#  define networkAllocateActualDevice(dom, iface) 0
#  define networkNotifyActualDevice(dom, iface) (dom=dom, iface=iface, 0)
#  define networkReleaseActualDevice(dom, iface) (dom=dom, iface=iface, 0)
#  define networkGetNetworkAddress(netname, netaddr) (-2)
#  define networkDnsmasqConfContents(network, pidfile, configstr, \
                    dctx, caps) 0
# endif

typedef char *(*networkDnsmasqLeaseFileNameFunc)(const char *netname);

/* this allows the testsuite to replace the lease filename resolver function */
extern networkDnsmasqLeaseFileNameFunc networkDnsmasqLeaseFileName;

#endif /* __VIR_NETWORK__DRIVER_H */
