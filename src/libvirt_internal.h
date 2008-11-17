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
int virStateInitialize(void);
int virStateCleanup(void);
int virStateReload(void);
int virStateActive(void);
#endif

int virDrvSupportsFeature (virConnectPtr conn, int feature);

int virDomainMigratePrepare (virConnectPtr dconn,
                             char **cookie,
                             int *cookielen,
                             const char *uri_in,
                             char **uri_out,
                             unsigned long flags,
                             const char *dname,
                             unsigned long bandwidth);
int virDomainMigratePerform (virDomainPtr domain,
                             const char *cookie,
                             int cookielen,
                             const char *uri,
                             unsigned long flags,
                             const char *dname,
                             unsigned long bandwidth);
virDomainPtr virDomainMigrateFinish (virConnectPtr dconn,
                                     const char *dname,
                                     const char *cookie,
                                     int cookielen,
                                     const char *uri,
                                     unsigned long flags);
int virDomainMigratePrepare2 (virConnectPtr dconn,
                              char **cookie,
                              int *cookielen,
                              const char *uri_in,
                              char **uri_out,
                              unsigned long flags,
                              const char *dname,
                              unsigned long bandwidth,
                              const char *dom_xml);
virDomainPtr virDomainMigrateFinish2 (virConnectPtr dconn,
                                      const char *dname,
                                      const char *cookie,
                                      int cookielen,
                                      const char *uri,
                                      unsigned long flags,
                                      int retcode);


#endif
