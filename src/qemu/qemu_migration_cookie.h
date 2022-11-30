/*
 * qemu_migration_cookie.h: QEMU migration cookie handling
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

#pragma once

#include "qemu_domain.h"
#include "qemu_migration_params.h"
#include "virenum.h"

typedef enum {
    QEMU_MIGRATION_COOKIE_FLAG_GRAPHICS,
    QEMU_MIGRATION_COOKIE_FLAG_LOCKSTATE,
    QEMU_MIGRATION_COOKIE_FLAG_PERSISTENT,
    QEMU_MIGRATION_COOKIE_FLAG_NETWORK,
    QEMU_MIGRATION_COOKIE_FLAG_NBD,
    QEMU_MIGRATION_COOKIE_FLAG_STATS,
    QEMU_MIGRATION_COOKIE_FLAG_MEMORY_HOTPLUG,
    QEMU_MIGRATION_COOKIE_FLAG_CPU_HOTPLUG,
    QEMU_MIGRATION_COOKIE_FLAG_CPU,
    QEMU_MIGRATION_COOKIE_FLAG_ALLOW_REBOOT,
    QEMU_MIGRATION_COOKIE_FLAG_CAPS,
    QEMU_MIGRATION_COOKIE_FLAG_BLOCK_DIRTY_BITMAPS,

    QEMU_MIGRATION_COOKIE_FLAG_LAST
} qemuMigrationCookieFlags;

VIR_ENUM_DECL(qemuMigrationCookieFlag);

typedef enum {
    QEMU_MIGRATION_COOKIE_GRAPHICS  = (1 << QEMU_MIGRATION_COOKIE_FLAG_GRAPHICS),
    QEMU_MIGRATION_COOKIE_LOCKSTATE = (1 << QEMU_MIGRATION_COOKIE_FLAG_LOCKSTATE),
    QEMU_MIGRATION_COOKIE_PERSISTENT = (1 << QEMU_MIGRATION_COOKIE_FLAG_PERSISTENT),
    QEMU_MIGRATION_COOKIE_NETWORK = (1 << QEMU_MIGRATION_COOKIE_FLAG_NETWORK),
    QEMU_MIGRATION_COOKIE_NBD = (1 << QEMU_MIGRATION_COOKIE_FLAG_NBD),
    QEMU_MIGRATION_COOKIE_STATS = (1 << QEMU_MIGRATION_COOKIE_FLAG_STATS),
    QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG = (1 << QEMU_MIGRATION_COOKIE_FLAG_MEMORY_HOTPLUG),
    QEMU_MIGRATION_COOKIE_CPU_HOTPLUG = (1 << QEMU_MIGRATION_COOKIE_FLAG_CPU_HOTPLUG),
    QEMU_MIGRATION_COOKIE_CPU = (1 << QEMU_MIGRATION_COOKIE_FLAG_CPU),
    QEMU_MIGRATION_COOKIE_CAPS = (1 << QEMU_MIGRATION_COOKIE_FLAG_CAPS),
    QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS = (1 << QEMU_MIGRATION_COOKIE_FLAG_BLOCK_DIRTY_BITMAPS),
} qemuMigrationCookieFeatures;

typedef struct _qemuMigrationCookieGraphics qemuMigrationCookieGraphics;
struct _qemuMigrationCookieGraphics {
    int type;
    int port;
    int tlsPort;
    char *listen;
    char *tlsSubject;
};

typedef struct _qemuMigrationCookieNetData qemuMigrationCookieNetData;
struct _qemuMigrationCookieNetData {
    int vporttype; /* enum virNetDevVPortProfile */

    /*
     * Array of pointers to saved data. Each VIF will have its own
     * data to transfer.
     */
    char *portdata;
};

typedef struct _qemuMigrationCookieNetwork qemuMigrationCookieNetwork;
struct _qemuMigrationCookieNetwork {
    /* How many virtual NICs are we saving data for? */
    int nnets;

    qemuMigrationCookieNetData *net;
};

struct qemuMigrationCookieNBDDisk {
    char *target;                   /* Disk target */
    unsigned long long capacity;    /* And its capacity */
};

typedef struct _qemuMigrationCookieNBD qemuMigrationCookieNBD;
struct _qemuMigrationCookieNBD {
    int port; /* on which port does NBD server listen for incoming data */

    size_t ndisks;  /* Number of items in @disk array */
    struct qemuMigrationCookieNBDDisk *disks;
};

typedef struct _qemuMigrationCookieCaps qemuMigrationCookieCaps;
struct _qemuMigrationCookieCaps {
    virBitmap *supported;
    virBitmap *automatic;
};

typedef struct _qemuMigrationBlockDirtyBitmapsDiskBitmap qemuMigrationBlockDirtyBitmapsDiskBitmap;
struct _qemuMigrationBlockDirtyBitmapsDiskBitmap {
    /* config */
    char *bitmapname;
    char *alias;

    /* runtime */
    virTristateBool persistent; /* force persisting of the bitmap */
    char *sourcebitmap; /* optional, actual bitmap to migrate in case we needed
                           to create a temporary one by merging */
    bool skip; /* omit this bitmap */
};


typedef struct _qemuMigrationBlockDirtyBitmapsDisk qemuMigrationBlockDirtyBitmapsDisk;
struct _qemuMigrationBlockDirtyBitmapsDisk {
    char *target;

    GSList *bitmaps;

    /* runtime data */
    virDomainDiskDef *disk; /* disk object corresponding to 'target' */
    const char *nodename; /* nodename of the top level source of 'disk' */
    bool skip; /* omit this disk */
};


typedef struct _qemuMigrationCookie qemuMigrationCookie;
struct _qemuMigrationCookie {
    unsigned int flags;
    unsigned int flagsMandatory;

    /* Host properties */
    unsigned char localHostuuid[VIR_UUID_BUFLEN];
    unsigned char remoteHostuuid[VIR_UUID_BUFLEN];
    char *localHostname;
    char *remoteHostname;

    /* Guest properties */
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;

    /* If (flags & QEMU_MIGRATION_COOKIE_LOCKSTATE) */
    char *lockState;
    char *lockDriver;

    /* If (flags & QEMU_MIGRATION_COOKIE_GRAPHICS) */
    qemuMigrationCookieGraphics *graphics;

    /* If (flags & QEMU_MIGRATION_COOKIE_PERSISTENT) */
    virDomainDef *persistent;

    /* If (flags & QEMU_MIGRATION_COOKIE_NETWORK) */
    qemuMigrationCookieNetwork *network;

    /* If (flags & QEMU_MIGRATION_COOKIE_NBD) */
    qemuMigrationCookieNBD *nbd;

    /* If (flags & QEMU_MIGRATION_COOKIE_STATS) */
    virDomainJobData *jobData;

    /* If flags & QEMU_MIGRATION_COOKIE_CPU */
    virCPUDef *cpu;

    /* If flags & QEMU_MIGRATION_COOKIE_CAPS */
    qemuMigrationCookieCaps *caps;

    /* If flags & QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS */
    GSList *blockDirtyBitmaps;
};


qemuMigrationCookie *
qemuMigrationCookieNew(const virDomainDef *def,
                       const char *origname);

int
qemuMigrationCookieFormat(qemuMigrationCookie *mig,
                          virQEMUDriver *driver,
                          virDomainObj *dom,
                          qemuMigrationParty party,
                          char **cookieout,
                          int *cookieoutlen,
                          unsigned int flags);

qemuMigrationCookie *
qemuMigrationCookieParse(virQEMUDriver *driver,
                         virDomainObj *vm,
                         const virDomainDef *def,
                         const char *origname,
                         virQEMUCaps *qemuCaps,
                         const char *cookiein,
                         int cookieinlen,
                         unsigned int flags);

void
qemuMigrationCookieFree(qemuMigrationCookie *mig);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMigrationCookie, qemuMigrationCookieFree);

int
qemuMigrationCookieAddPersistent(qemuMigrationCookie *mig,
                                 virDomainDef **def);

virDomainDef *
qemuMigrationCookieGetPersistent(qemuMigrationCookie *mig);

/* qemuMigrationCookieXMLFormat is exported for test use only! */
int
qemuMigrationCookieXMLFormat(virQEMUDriver *driver,
                             virQEMUCaps *qemuCaps,
                             virBuffer *buf,
                             qemuMigrationCookie *mig);

int
qemuMigrationCookieBlockDirtyBitmapsMatchDisks(virDomainDef *def,
                                               GSList *disks);

int
qemuMigrationCookieBlockDirtyBitmapsToParams(GSList *disks,
                                             virJSONValue **mapping);
