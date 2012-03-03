/*
 * xend_internal.h
 *
 * Copyright (C) 2006-2008, 2010-2012 Red Hat, Inc.
 * Copyright (C) 2005,2006
 *
 *      Anthony Liguori <aliguori@us.ibm.com>
 *	Daniel Veillard <veillard@redhat.com>
 *
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING in the main directory of this archive
 *  for more details.
 */

#ifndef __XEND_INTERNAL_H_
# define __XEND_INTERNAL_H_

# include <sys/types.h>
# include <stdint.h>

# include "internal.h"
# include "capabilities.h"
# include "domain_conf.h"
# include "driver.h"
# include "buf.h"
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


/**
 * \brief Lookup the name of a domain
 * \param xend A xend instance
 * \param id The id of the domain
 * \param name pointer to store a copy of the name
 * \param uuid pointer to store a copy of the uuid
 *
 * This method looks up the name/uuid of a domain
 */
int xenDaemonDomainLookupByID(virConnectPtr xend,
                              int id,
                              char **name, unsigned char *uuid);


virDomainDefPtr
xenDaemonDomainFetch(virConnectPtr xend,
                     int domid,
                     const char *name,
                     const char *cpus);


  int is_sound_model_valid(const char *model);
  int is_sound_model_conflict(const char *model, const char *soundstr);


/* refactored ones */
virDrvOpenStatus xenDaemonOpen(virConnectPtr conn, virConnectAuthPtr auth,
                               unsigned int flags);
int xenDaemonClose(virConnectPtr conn);
int xenDaemonGetVersion(virConnectPtr conn, unsigned long *hvVer);
int xenDaemonNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);
int xenDaemonNodeGetTopology(virConnectPtr conn, virCapsPtr caps);
int xenDaemonDomainSuspend(virDomainPtr domain);
int xenDaemonDomainResume(virDomainPtr domain);
int xenDaemonDomainShutdown(virDomainPtr domain);
int xenDaemonDomainReboot(virDomainPtr domain, unsigned int flags);
int xenDaemonDomainDestroyFlags(virDomainPtr domain, unsigned int flags);
int xenDaemonDomainSave(virDomainPtr domain, const char *filename);
int xenDaemonDomainCoreDump(virDomainPtr domain, const char *filename,
                            unsigned int flags);
int xenDaemonDomainRestore(virConnectPtr conn, const char *filename);
int xenDaemonDomainSetMemory(virDomainPtr domain, unsigned long memory);
int xenDaemonDomainSetMaxMemory(virDomainPtr domain, unsigned long memory);
int xenDaemonDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
int xenDaemonDomainGetState(virDomainPtr domain,
                            int *state,
                            int *reason,
                            unsigned int flags);
char *xenDaemonDomainGetXMLDesc(virDomainPtr domain, unsigned int flags,
                                const char *cpus);
unsigned long long xenDaemonDomainGetMaxMemory(virDomainPtr domain);
char **xenDaemonListDomainsOld(virConnectPtr xend);

virDomainPtr xenDaemonDomainDefineXML(virConnectPtr xend, const char *sexpr);
int xenDaemonDomainCreate(virDomainPtr domain);
int xenDaemonDomainUndefine(virDomainPtr domain);

int	xenDaemonDomainSetVcpus		(virDomainPtr domain,
                                         unsigned int vcpus);
int	xenDaemonDomainSetVcpusFlags	(virDomainPtr domain,
                                         unsigned int vcpus,
                                         unsigned int flags);
int	xenDaemonDomainPinVcpu		(virDomainPtr domain,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen);
int     xenDaemonDomainGetVcpusFlags    (virDomainPtr domain,
                                         unsigned int flags);
int	xenDaemonDomainGetVcpus		(virDomainPtr domain,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen);
int xenDaemonUpdateDeviceFlags(virDomainPtr domain, const char *xml,
                               unsigned int flags);
int xenDaemonDomainGetAutostart          (virDomainPtr dom,
                                          int *autostart);
int xenDaemonDomainSetAutostart          (virDomainPtr domain,
                                          int autostart);

/* xen_unified calls through here. */
extern struct xenUnifiedDriver xenDaemonDriver;
int xenDaemonInit (void);

virDomainPtr xenDaemonCreateXML(virConnectPtr conn, const char *xmlDesc,
                                unsigned int flags);
virDomainPtr xenDaemonLookupByID(virConnectPtr conn, int id);
virDomainPtr xenDaemonLookupByUUID(virConnectPtr conn, const unsigned char *uuid);
virDomainPtr xenDaemonLookupByName(virConnectPtr conn, const char *domname);
int xenDaemonDomainMigratePrepare (virConnectPtr dconn, char **cookie, int *cookielen, const char *uri_in, char **uri_out, unsigned long flags, const char *dname, unsigned long resource);
int xenDaemonDomainMigratePerform (virDomainPtr domain, const char *cookie, int cookielen, const char *uri, unsigned long flags, const char *dname, unsigned long resource);

int xenDaemonDomainBlockPeek (virDomainPtr domain, const char *path, unsigned long long offset, size_t size, void *buffer);
int xenDaemonListDomains(virConnectPtr conn, int *ids, int maxids);
int xenDaemonNumOfDomains(virConnectPtr conn);

#endif /* __XEND_INTERNAL_H_ */
