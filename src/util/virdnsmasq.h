/*
 * virdnsmasq.h: Helper APIs for managing dnsmasq
 *
 * Copyright (C) 2007-2012 Red Hat, Inc.
 * Copyright (C) 2010 Satoru SATOH <satoru.satoh@gmail.com>
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
 * based on iptables.h
 */

#pragma once

#include "virobject.h"
#include "virsocketaddr.h"

typedef struct
{
    /*
     * Each entry holds a string, "<mac_addr>,<hostname>,<ip_addr>" such as
     * "01:23:45:67:89:0a,foo,10.0.0.3".
     */
    char *host;

} dnsmasqDhcpHost;

typedef struct
{
    unsigned int     nhosts;
    dnsmasqDhcpHost *hosts;

    char            *path;  /* Absolute path of dnsmasq's hostsfile. */
} dnsmasqHostsfile;

typedef struct
{
    unsigned int    nhostnames;
    char            *ip;
    char            **hostnames;

} dnsmasqAddnHost;

typedef struct
{
    unsigned int     nhosts;
    dnsmasqAddnHost *hosts;

    char            *path;  /* Absolute path of dnsmasq's hostsfile. */
} dnsmasqAddnHostsfile;

typedef struct
{
    char                 *config_dir;
    dnsmasqHostsfile     *hostsfile;
    dnsmasqAddnHostsfile *addnhostsfile;
} dnsmasqContext;

typedef enum {
   DNSMASQ_CAPS_BIND_DYNAMIC = 0, /* support for --bind-dynamic */
   DNSMASQ_CAPS_BINDTODEVICE = 1, /* uses SO_BINDTODEVICE for --bind-interfaces */
   DNSMASQ_CAPS_RA_PARAM = 2,     /* support for --ra-param */

   DNSMASQ_CAPS_LAST,             /* this must always be the last item */
} dnsmasqCapsFlags;

typedef struct _dnsmasqCaps dnsmasqCaps;
typedef dnsmasqCaps *dnsmasqCapsPtr;


dnsmasqContext * dnsmasqContextNew(const char *network_name,
                                   const char *config_dir);
void             dnsmasqContextFree(dnsmasqContext *ctx);
int              dnsmasqAddDhcpHost(dnsmasqContext *ctx,
                                    const char *mac,
                                    virSocketAddr *ip,
                                    const char *name,
                                    const char *id,
                                    bool ipv6);
int              dnsmasqAddHost(dnsmasqContext *ctx,
                                virSocketAddr *ip,
                                const char *name);
int              dnsmasqSave(const dnsmasqContext *ctx);
int              dnsmasqDelete(const dnsmasqContext *ctx);
int              dnsmasqReload(pid_t pid);

dnsmasqCapsPtr dnsmasqCapsNewFromBuffer(const char *buf,
                                        const char *binaryPath);
dnsmasqCapsPtr dnsmasqCapsNewFromFile(const char *dataPath,
                                      const char *binaryPath);
dnsmasqCapsPtr dnsmasqCapsNewFromBinary(const char *binaryPath);
int dnsmasqCapsRefresh(dnsmasqCapsPtr *caps, const char *binaryPath);
bool dnsmasqCapsGet(dnsmasqCapsPtr caps, dnsmasqCapsFlags flag);
const char *dnsmasqCapsGetBinaryPath(dnsmasqCapsPtr caps);
unsigned long dnsmasqCapsGetVersion(dnsmasqCapsPtr caps);

#define DNSMASQ_DHCPv6_MAJOR_REQD 2
#define DNSMASQ_DHCPv6_MINOR_REQD 64
#define DNSMASQ_RA_MAJOR_REQD 2
#define DNSMASQ_RA_MINOR_REQD 64

#define DNSMASQ_DHCPv6_SUPPORT(CAPS) \
    (dnsmasqCapsGetVersion(CAPS) >= \
     (DNSMASQ_DHCPv6_MAJOR_REQD * 1000000) + \
     (DNSMASQ_DHCPv6_MINOR_REQD * 1000))
#define DNSMASQ_RA_SUPPORT(CAPS) \
    (dnsmasqCapsGetVersion(CAPS) >= \
     (DNSMASQ_RA_MAJOR_REQD * 1000000) + \
     (DNSMASQ_RA_MINOR_REQD * 1000))
