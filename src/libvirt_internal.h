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
 * NB This file is ABI sensitive. Things here impact the wire
 * protocol ABI in the remote driver. Same rules as for things
 * include/libvirt/libvirt.h apply. ie this file is *append* only
 */

#ifndef __LIBVIRT_H_
# define __LIBVIRT_H_

# include "internal.h"

# ifdef WITH_LIBVIRTD
int virStateInitialize(int privileged);
int virStateCleanup(void);
int virStateReload(void);
int virStateActive(void);
# endif

/* Feature detection.  This is a libvirt-private interface for determining
 * what features are supported by the driver.
 *
 * The remote driver passes features through to the real driver at the
 * remote end unmodified, except if you query a VIR_DRV_FEATURE_REMOTE*
 * feature.
 *
 */
enum {
    /* Driver supports V1-style virDomainMigrate, ie. domainMigratePrepare/
     * domainMigratePerform/domainMigrateFinish.
     */
    VIR_DRV_FEATURE_MIGRATION_V1 = 1,

    /* Driver is not local. */
    VIR_DRV_FEATURE_REMOTE = 2,

    /* Driver supports V2-style virDomainMigrate, ie. domainMigratePrepare2/
     * domainMigratePerform/domainMigrateFinish2.
     */
    VIR_DRV_FEATURE_MIGRATION_V2 = 3,

    /* Driver supports peer-2-peer virDomainMigrate ie source host
     * does all the prepare/perform/finish steps directly
     */
    VIR_DRV_FEATURE_MIGRATION_P2P = 4,

    /* Driver supports migration with only the source host involved,
     * no libvirtd connetions on the destination at all, only the
     * perform step is used.
     */
    VIR_DRV_FEATURE_MIGRATION_DIRECT = 5,
};


int virDrvSupportsFeature (virConnectPtr conn, int feature);

int virDomainMigratePrepare (virConnectPtr dconn,
                             char **cookie,
                             int *cookielen,
                             const char *uri_in,
                             char **uri_out,
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource);
int virDomainMigratePerform (virDomainPtr domain,
                             const char *cookie,
                             int cookielen,
                             const char *uri,
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource);
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
                              unsigned long resource,
                              const char *dom_xml);
virDomainPtr virDomainMigrateFinish2 (virConnectPtr dconn,
                                      const char *dname,
                                      const char *cookie,
                                      int cookielen,
                                      const char *uri,
                                      unsigned long flags,
                                      int retcode);
int virDomainMigratePrepareTunnel(virConnectPtr dconn,
                                  virStreamPtr st,
                                  unsigned long flags,
                                  const char *dname,
                                  unsigned long resource,
                                  const char *dom_xml);

#endif
