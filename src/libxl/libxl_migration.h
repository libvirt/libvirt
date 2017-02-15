/*
 * libxl_migration.h: methods for handling migration with libxenlight
 *
 * Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Authors:
 *     Jim Fehlig <jfehlig@suse.com>
 */

#ifndef LIBXL_MIGRATION_H
# define LIBXL_MIGRATION_H

# include "libxl_conf.h"

# define LIBXL_MIGRATION_FLAGS                  \
    (VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_PEER2PEER |                    \
     VIR_MIGRATE_TUNNELLED |                    \
     VIR_MIGRATE_PERSIST_DEST |                 \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_PAUSED)

/* All supported migration parameters and their types. */
# define LIBXL_MIGRATION_PARAMETERS                             \
    VIR_MIGRATE_PARAM_URI,              VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_NAME,        VIR_TYPED_PARAM_STRING, \
    VIR_MIGRATE_PARAM_DEST_XML,         VIR_TYPED_PARAM_STRING, \
    NULL

char *
libxlDomainMigrationBegin(virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *xmlin,
                          char **cookieout,
                          int *cookieoutlen);

virDomainDefPtr
libxlDomainMigrationPrepareDef(libxlDriverPrivatePtr driver,
                               const char *dom_xml,
                               const char *dname);

int
libxlDomainMigrationPrepareTunnel3(virConnectPtr dconn,
                                   virStreamPtr st,
                                   virDomainDefPtr *def,
                                   const char *cookiein,
                                   int cookieinlen,
                                   unsigned int flags);

int
libxlDomainMigrationPrepare(virConnectPtr dconn,
                            virDomainDefPtr *def,
                            const char *uri_in,
                            char **uri_out,
                            const char *cookiein,
                            int cookieinlen,
                            unsigned int flags);

int
libxlDomainMigrationPerformP2P(libxlDriverPrivatePtr driver,
                               virDomainObjPtr vm,
                               virConnectPtr sconn,
                               const char *dom_xml,
                               const char *dconnuri,
                               const char *uri_str,
                               const char *dname,
                               unsigned int flags);

int
libxlDomainMigrationPerform(libxlDriverPrivatePtr driver,
                            virDomainObjPtr vm,
                            const char *dom_xml,
                            const char *dconnuri,
                            const char *uri_str,
                            const char *dname,
                            unsigned int flags);

virDomainPtr
libxlDomainMigrationFinish(virConnectPtr dconn,
                           virDomainObjPtr vm,
                           unsigned int flags,
                           int cancelled);

int
libxlDomainMigrationConfirm(libxlDriverPrivatePtr driver,
                            virDomainObjPtr vm,
                            unsigned int flags,
                            int cancelled);

#endif /* LIBXL_DRIVER_H */
