/*
 * libvirt.h: publically exported APIs, not for public use
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
 */

#ifndef __LIBVIRT_H_
#define __LIBVIRT_H_

#include "internal.h"


#ifdef WITH_LIBVIRTD
int __virStateInitialize(void);
int __virStateCleanup(void);
int __virStateReload(void);
int __virStateActive(void);
#define virStateInitialize() __virStateInitialize()
#define virStateCleanup() __virStateCleanup()
#define virStateReload() __virStateReload()
#define virStateActive() __virStateActive()
#endif

int __virDrvSupportsFeature (virConnectPtr conn, int feature);

int __virDomainMigratePrepare (virConnectPtr dconn,
                               char **cookie,
                               int *cookielen,
                               const char *uri_in,
                               char **uri_out,
                               unsigned long flags,
                               const char *dname,
                               unsigned long bandwidth);
int __virDomainMigratePerform (virDomainPtr domain,
                               const char *cookie,
                               int cookielen,
                               const char *uri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long bandwidth);
virDomainPtr __virDomainMigrateFinish (virConnectPtr dconn,
                                       const char *dname,
                                       const char *cookie,
                                       int cookielen,
                                       const char *uri,
                                       unsigned long flags);
int __virDomainMigratePrepare2 (virConnectPtr dconn,
                                char **cookie,
                                int *cookielen,
                                const char *uri_in,
                                char **uri_out,
                                unsigned long flags,
                                const char *dname,
                                unsigned long bandwidth,
                                const char *dom_xml);
virDomainPtr __virDomainMigrateFinish2 (virConnectPtr dconn,
                                        const char *dname,
                                        const char *cookie,
                                        int cookielen,
                                        const char *uri,
                                        unsigned long flags,
                                        int retcode);


#endif
