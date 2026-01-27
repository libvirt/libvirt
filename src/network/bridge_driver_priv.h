/*
 * bridge_driver_priv.h: private declarations for network driver
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef LIBVIRT_BRIDGE_DRIVER_PRIV_H_ALLOW
# error "bridge_driver_priv.h may only be included by bridge_driver.c or test suites"
#endif /* LIBVIRT_BRIDGE_DRIVER_PRIV_H_ALLOW */

#pragma once

#include "virdnsmasq.h"
#include "virnetworkobj.h"

virNetworkXMLOption *
networkDnsmasqCreateXMLConf(void);

int
networkDnsmasqConfContents(virNetworkObj *obj,
                           const char *pidfile,
                           char **configstr,
                           char **hostsfilestr,
                           dnsmasqContext *dctx,
                           dnsmasqCaps *caps);

bool
networkNeedsDnsmasq(const virNetworkDef* def);

int
networkValidateTests(virNetworkDef *def);
