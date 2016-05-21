/*
 * libvirt_internal.h: internally exported APIs, not for public use
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * NB This file is ABI sensitive. Things here impact the wire
 * protocol ABI in the remote driver. Same rules as for things
 * include/libvirt/libvirt.h apply. ie this file is *append* only
 */

#ifndef __LIBVIRT_H_
# define __LIBVIRT_H_

# include "internal.h"

typedef void (*virStateInhibitCallback)(bool inhibit,
                                        void *opaque);

int virStateInitialize(bool privileged,
                       virStateInhibitCallback inhibit,
                       void *opaque);
int virStateCleanup(void);
int virStateReload(void);
int virStateStop(void);

/* Feature detection.  This is a libvirt-private interface for determining
 * what features are supported by the driver.
 *
 * The remote driver passes features through to the real driver at the
 * remote end unmodified, except if you query a VIR_DRV_FEATURE_REMOTE*
 * feature.  Queries for VIR_DRV_FEATURE_PROGRAM* features are answered
 * directly by the RPC layer and not by the real driver.
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

    /*
     * Driver supports V3-style virDomainMigrate, ie domainMigrateBegin3/
     * domainMigratePrepare3/domainMigratePerform3/domainMigrateFinish3/
     * domainMigrateConfirm3.
     */
    VIR_DRV_FEATURE_MIGRATION_V3 = 6,

    /*
     * Driver supports protecting the whole V3-style migration against changes
     * to domain configuration, i.e., starting from Begin3 and not Perform3.
     */
    VIR_DRV_FEATURE_MIGRATE_CHANGE_PROTECTION = 7,

    /*
     * Support for file descriptor passing
     */
    VIR_DRV_FEATURE_FD_PASSING = 8,

    /*
     * Support for VIR_TYPED_PARAM_STRING
     */
    VIR_DRV_FEATURE_TYPED_PARAM_STRING = 9,

    /*
     * Remote party supports keepalive program (i.e., sending keepalive
     * messages).
     */
    VIR_DRV_FEATURE_PROGRAM_KEEPALIVE = 10,

    /*
     * Support for VIR_DOMAIN_XML_MIGRATABLE flag in domainGetXMLDesc
     */
    VIR_DRV_FEATURE_XML_MIGRATABLE = 11,

    /*
     * Support for offline migration.
     */
    VIR_DRV_FEATURE_MIGRATION_OFFLINE = 12,

    /*
     * Support for migration parameters.
     */
    VIR_DRV_FEATURE_MIGRATION_PARAMS = 13,

    /*
     * Support for server-side event filtering via callback ids in events.
     */
    VIR_DRV_FEATURE_REMOTE_EVENT_CALLBACK = 14,

    /*
     * Support for driver close callback rpc
     */
    VIR_DRV_FEATURE_REMOTE_CLOSE_CALLBACK = 15,
};


int virConnectSupportsFeature(virConnectPtr conn, int feature);

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


char *virDomainMigrateBegin3(virDomainPtr domain,
                             const char *xmlin,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource);

int virDomainMigratePrepare3(virConnectPtr dconn,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             const char *uri_in,
                             char **uri_out,
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource,
                             const char *dom_xml);

int virDomainMigratePrepareTunnel3(virConnectPtr dconn,
                                   virStreamPtr st,
                                   const char *cookiein,
                                   int cookieinlen,
                                   char **cookieout,
                                   int *cookieoutlen,
                                   unsigned long flags,
                                   const char *dname,
                                   unsigned long resource,
                                   const char *dom_xml);


int virDomainMigratePerform3(virDomainPtr dom,
                             const char *xmlin,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             const char *dconnuri, /* libvirtd URI if Peer2Peer, NULL otherwise */
                             const char *uri, /* VM Migration URI */
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource);

virDomainPtr virDomainMigrateFinish3(virConnectPtr dconn,
                                     const char *dname,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     const char *dconnuri, /* libvirtd URI if Peer2Peer, NULL otherwise */
                                     const char *uri, /* VM Migration URI, NULL in tunnelled case */
                                     unsigned long flags,
                                     int cancelled); /* Kill the dst VM */

int virDomainMigrateConfirm3(virDomainPtr domain,
                             const char *cookiein,
                             int cookieinlen,
                             unsigned long flags,
                             int restart); /* Restart the src VM */

char *virDomainMigrateBegin3Params(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   char **cookieout,
                                   int *cookieoutlen,
                                   unsigned int flags);

int virDomainMigratePrepare3Params(virConnectPtr dconn,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   const char *cookiein,
                                   int cookieinlen,
                                   char **cookieout,
                                   int *cookieoutlen,
                                   char **uri_out,
                                   unsigned int flags);

int virDomainMigratePrepareTunnel3Params(virConnectPtr conn,
                                         virStreamPtr st,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         const char *cookiein,
                                         int cookieinlen,
                                         char **cookieout,
                                         int *cookieoutlen,
                                         unsigned int flags);

int virDomainMigratePerform3Params(virDomainPtr domain,
                                   const char *dconnuri,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   const char *cookiein,
                                   int cookieinlen,
                                   char **cookieout,
                                   int *cookieoutlen,
                                   unsigned int flags);

virDomainPtr virDomainMigrateFinish3Params(virConnectPtr dconn,
                                           virTypedParameterPtr params,
                                           int nparams,
                                           const char *cookiein,
                                           int cookieinlen,
                                           char **cookieout,
                                           int *cookieoutlen,
                                           unsigned int flags,
                                           int cancelled);

int virDomainMigrateConfirm3Params(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   const char *cookiein,
                                   int cookieinlen,
                                   unsigned int flags,
                                   int cancelled);

int
virTypedParameterValidateSet(virConnectPtr conn,
                             virTypedParameterPtr params,
                             int nparams);

int virStreamInData(virStreamPtr stream,
                    int *data,
                    long long *length);

#endif
