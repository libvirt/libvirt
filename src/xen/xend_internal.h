/*
 * xend_internal.h
 *
 * Copyright (C) 2006-2008, 2010-2013 Red Hat, Inc.
 * Copyright (C) 2005,2006 Anthony Liguori <aliguori@us.ibm.com>
 *  and Daniel Veillard <veillard@redhat.com>
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

#ifndef __XEND_INTERNAL_H_
# define __XEND_INTERNAL_H_

# include <sys/types.h>
# include <stdint.h>

# include "internal.h"
# include "capabilities.h"
# include "domain_conf.h"
# include "driver.h"
# include "virbuffer.h"
# include "viruri.h"

int
xenDaemonOpen_unix(virConnectPtr conn, const char *path);

/**
 * \brief Blocks until a domain's devices are initialized
 * \param xend A xend instance
 * \param name The domain's name
 * \return 0 for success; -1 (with errno) on error
 *
 * xen_create() returns after a domain has been allocated including
 * its memory.  This does not guarantee, though, that the devices
 * have come up properly.  For instance, if you create a VBD with an
 * invalid filename, the error won't occur until after this function
 * returns.
 */
    int xend_wait_for_devices(virConnectPtr xend, const char *name);


/**
 * \brief Create a new domain
 * \param xend A xend instance
 * \param sexpr An S-Expr defining the domain
 * \return 0 for success; -1 (with errno) on error
 *
 * This method will create a domain based the passed in description.  The
 * domain will be paused after creation and must be unpaused with
 * xenDaemonResumeDomain() to begin execution.
 */
int xenDaemonDomainCreateXML(virConnectPtr xend, const char *sexpr);

/**
 * \brief Lookup the id of a domain
 * \param xend A xend instance
 * \param name The name of the domain
 * \param uuid pointer to store a copy of the uuid
 * \return the id number on success; -1 (with errno) on error
 *
 * This method looks up the ids of a domain
 */
int xenDaemonDomainLookupByName_ids(virConnectPtr xend,
                            const char *name, unsigned char *uuid);



virDomainDefPtr
xenDaemonDomainFetch(virConnectPtr xend,
                     int domid,
                     const char *name,
                     const char *cpus);


/* refactored ones */
int xenDaemonOpen(virConnectPtr conn, virConnectAuthPtr auth,
                  unsigned int flags);
int xenDaemonClose(virConnectPtr conn);
int xenDaemonNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);
int xenDaemonNodeGetTopology(virConnectPtr conn, virCapsPtr caps);
int xenDaemonDomainSuspend(virConnectPtr conn, virDomainDefPtr def);
int xenDaemonDomainResume(virConnectPtr conn, virDomainDefPtr def);
int xenDaemonDomainShutdown(virConnectPtr conn, virDomainDefPtr def);
int xenDaemonDomainReboot(virConnectPtr conn, virDomainDefPtr def);
int xenDaemonDomainDestroy(virConnectPtr conn, virDomainDefPtr def);
int xenDaemonDomainSave(virConnectPtr conn,
                        virDomainDefPtr def,
                        const char *filename);
int xenDaemonDomainCoreDump(virConnectPtr conn,
                            virDomainDefPtr def,
                            const char *filename,
                            unsigned int flags);
int xenDaemonDomainRestore(virConnectPtr conn, const char *filename);
int xenDaemonDomainSetMemory(virConnectPtr conn,
                             virDomainDefPtr def,
                             unsigned long memory);
int xenDaemonDomainSetMaxMemory(virConnectPtr conn,
                                virDomainDefPtr def,
                                unsigned long memory);
int xenDaemonDomainGetInfo(virConnectPtr conn,
                           virDomainDefPtr def,
                           virDomainInfoPtr info);
int xenDaemonDomainGetState(virConnectPtr conn,
                            virDomainDefPtr def,
                            int *state,
                            int *reason);
virDomainDefPtr xenDaemonDomainGetXMLDesc(virConnectPtr conn,
                                          virDomainDefPtr def,
                                          const char *cpus);
unsigned long long xenDaemonDomainGetMaxMemory(virConnectPtr conn,
                                               virDomainDefPtr def);
char **xenDaemonListDomainsOld(virConnectPtr xend);

char *xenDaemonDomainGetOSType(virConnectPtr conn,
                               virDomainDefPtr def);

int xenDaemonNumOfDefinedDomains(virConnectPtr conn);
int xenDaemonListDefinedDomains(virConnectPtr conn,
                                char **const names,
                                int maxnames);

int xenDaemonAttachDeviceFlags(virConnectPtr conn,
                               virDomainDefPtr def,
                               const char *xml,
                               unsigned int flags);
int xenDaemonDetachDeviceFlags(virConnectPtr conn,
                               virDomainDefPtr def,
                               const char *xml,
                               unsigned int flags);

int xenDaemonDomainDefineXML(virConnectPtr conn,
                             virDomainDefPtr def);
int xenDaemonDomainCreate(virConnectPtr conn,
                          virDomainDefPtr def);
int xenDaemonDomainUndefine(virConnectPtr conn,
                            virDomainDefPtr def);

int	xenDaemonDomainSetVcpus		(virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned int vcpus);
int	xenDaemonDomainSetVcpusFlags	(virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned int vcpus,
                                         unsigned int flags);
int	xenDaemonDomainPinVcpu		(virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen);
int     xenDaemonDomainGetVcpusFlags    (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned int flags);
int	xenDaemonDomainGetVcpus		(virConnectPtr conn,
                                         virDomainDefPtr def,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen);
int xenDaemonUpdateDeviceFlags(virConnectPtr conn,
                               virDomainDefPtr def,
                               const char *xml,
                               unsigned int flags);
int xenDaemonDomainGetAutostart(virConnectPtr conn,
                                virDomainDefPtr def,
                                int *autostart);
int xenDaemonDomainSetAutostart(virConnectPtr conn,
                                virDomainDefPtr def,
                                int autostart);

int xenDaemonCreateXML(virConnectPtr conn, virDomainDefPtr def);
virDomainDefPtr xenDaemonLookupByUUID(virConnectPtr conn, const unsigned char *uuid);
virDomainDefPtr xenDaemonLookupByName(virConnectPtr conn, const char *domname);
int xenDaemonDomainMigratePrepare (virConnectPtr dconn,
                                   char **cookie, int *cookielen,
                                   const char *uri_in, char **uri_out,
                                   unsigned long flags, const char *dname, unsigned long resource);
int xenDaemonDomainMigratePerform (virConnectPtr conn,
                                   virDomainDefPtr def,
                                   const char *cookie, int cookielen,
                                   const char *uri, unsigned long flags,
                                   const char *dname, unsigned long resource);

int xenDaemonDomainBlockPeek(virConnectPtr conn,
                             virDomainDefPtr def,
                             const char *path,
                             unsigned long long offset,
                             size_t size,
                             void *buffer);

char * xenDaemonGetSchedulerType(virConnectPtr conn,
                                 int *nparams);
int xenDaemonGetSchedulerParameters(virConnectPtr conn,
                                    virDomainDefPtr def,
                                    virTypedParameterPtr params,
                                    int *nparams);
int xenDaemonSetSchedulerParameters(virConnectPtr conn,
                                    virDomainDefPtr def,
                                    virTypedParameterPtr params,
                                    int nparams);

#endif /* __XEND_INTERNAL_H_ */
