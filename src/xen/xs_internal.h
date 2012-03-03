/*
 * xs_internal.h: internal API for access to XenStore
 *
 * Copyright (C) 2006, 2010-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XS_INTERNAL_H__
# define __VIR_XS_INTERNAL_H__

# include "internal.h"
# include "driver.h"

extern struct xenUnifiedDriver xenStoreDriver;
int xenStoreInit (void);

virDrvOpenStatus	xenStoreOpen	(virConnectPtr conn,
                                         virConnectAuthPtr auth,
                                         unsigned int flags);
int		xenStoreClose		(virConnectPtr conn);
int		xenStoreGetDomainInfo	(virDomainPtr domain,
                                         virDomainInfoPtr info);
int		xenStoreDomainGetState	(virDomainPtr domain,
                                         int *state,
                                         int *reason,
                                         unsigned int flags);
int		xenStoreNumOfDomains	(virConnectPtr conn);
int		xenStoreListDomains	(virConnectPtr conn,
                                         int *ids,
                                         int maxids);
virDomainPtr	xenStoreLookupByName(virConnectPtr conn,
                                         const char *name);
unsigned long	xenStoreGetMaxMemory	(virDomainPtr domain);
int		xenStoreDomainSetMemory	(virDomainPtr domain,
                                         unsigned long memory);
unsigned long long xenStoreDomainGetMaxMemory(virDomainPtr domain);
int		xenStoreDomainShutdown	(virDomainPtr domain);
int		xenStoreDomainReboot	(virDomainPtr domain,
                                         unsigned int flags);

int             xenStoreDomainGetVNCPort(virConnectPtr conn,
                                         int domid);
char *          xenStoreDomainGetConsolePath(virConnectPtr conn,
                                         int domid);
char *          xenStoreDomainGetSerialConsolePath(virConnectPtr conn,
                                         int domid);
char *		xenStoreDomainGetNetworkID(virConnectPtr conn,
                                         int id,
                                         const char *mac);
char *		xenStoreDomainGetDiskID(virConnectPtr conn,
                                         int id,
                                         const char *dev);
char *		xenStoreDomainGetPCIID(virConnectPtr conn,
                                   int domid,
                                   const char *bdf);
char *          xenStoreDomainGetName(virConnectPtr conn,
                                      int id);
int             xenStoreDomainGetUUID(virConnectPtr conn,
                                      int id,
                                      unsigned char *uuid);

typedef int (*xenStoreWatchCallback)(virConnectPtr conn,
                                     const char *path,
                                     const char *token,
                                     void *opaque);

struct _xenStoreWatch {
    char *path;
    char *token;
    xenStoreWatchCallback cb;
    void *opaque;
};
typedef struct _xenStoreWatch xenStoreWatch;
typedef xenStoreWatch *xenStoreWatchPtr;

struct _xenStoreWatchList {
    unsigned int count;
    xenStoreWatchPtr *watches;
};
typedef struct _xenStoreWatchList xenStoreWatchList;
typedef xenStoreWatchList *xenStoreWatchListPtr;


int             xenStoreAddWatch(virConnectPtr conn,
                                 const char *path,
                                 const char *token,
                                 xenStoreWatchCallback cb,
                                 void *opaque);
int             xenStoreRemoveWatch(virConnectPtr conn,
                                    const char *path,
                                    const char *token);

/* domain events */
int xenStoreDomainIntroduced(virConnectPtr conn,
                             const char *path,
                             const char *token,
                             void *opaque);
int xenStoreDomainReleased(virConnectPtr conn,
                            const char *path,
                            const char *token,
                            void *opaque);

int xenStoreDomainEventEmitted(virDomainEventType evt);
#endif /* __VIR_XS_INTERNAL_H__ */
