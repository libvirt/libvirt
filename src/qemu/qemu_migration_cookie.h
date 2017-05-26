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

#ifndef __QEMU_MIGRATION_COOKIE_H__
# define __QEMU_MIGRATION_COOKIE_H__

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
} qemuMigrationCookieFeatures;

typedef struct _qemuMigrationCookieGraphics qemuMigrationCookieGraphics;
typedef qemuMigrationCookieGraphics *qemuMigrationCookieGraphicsPtr;
struct _qemuMigrationCookieGraphics {
    int type;
    int port;
    int tlsPort;
    char *listen;
    char *tlsSubject;
};

typedef struct _qemuMigrationCookieNetData qemuMigrationCookieNetData;
typedef qemuMigrationCookieNetData *qemuMigrationCookieNetDataPtr;
struct _qemuMigrationCookieNetData {
    int vporttype; /* enum virNetDevVPortProfile */

    /*
     * Array of pointers to saved data. Each VIF will have its own
     * data to transfer.
     */
    char *portdata;
};

typedef struct _qemuMigrationCookieNetwork qemuMigrationCookieNetwork;
typedef qemuMigrationCookieNetwork *qemuMigrationCookieNetworkPtr;
struct _qemuMigrationCookieNetwork {
    /* How many virtual NICs are we saving data for? */
    int nnets;

    qemuMigrationCookieNetDataPtr net;
};

typedef struct _qemuMigrationCookieNBD qemuMigrationCookieNBD;
typedef qemuMigrationCookieNBD *qemuMigrationCookieNBDPtr;
struct _qemuMigrationCookieNBD {
    int port; /* on which port does NBD server listen for incoming data */

    size_t ndisks;  /* Number of items in @disk array */
    struct {
        char *target;                   /* Disk target */
        unsigned long long capacity;    /* And its capacity */
    } *disks;
};

typedef struct _qemuMigrationCookie qemuMigrationCookie;
typedef qemuMigrationCookie *qemuMigrationCookiePtr;
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
    qemuMigrationCookieGraphicsPtr graphics;

    /* If (flags & QEMU_MIGRATION_COOKIE_PERSISTENT) */
    virDomainDefPtr persistent;

    /* If (flags & QEMU_MIGRATION_COOKIE_NETWORK) */
    qemuMigrationCookieNetworkPtr network;

    /* If (flags & QEMU_MIGRATION_COOKIE_NBD) */
    qemuMigrationCookieNBDPtr nbd;

    /* If (flags & QEMU_MIGRATION_COOKIE_STATS) */
    qemuDomainJobInfoPtr jobInfo;

    /* If flags & QEMU_MIGRATION_COOKIE_CPU */
    virCPUDefPtr cpu;
};


int
qemuMigrationBakeCookie(qemuMigrationCookiePtr mig,
                        virQEMUDriverPtr driver,
                        virDomainObjPtr dom,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned int flags);

qemuMigrationCookiePtr
qemuMigrationEatCookie(virQEMUDriverPtr driver,
                       virDomainObjPtr dom,
                       const char *cookiein,
                       int cookieinlen,
                       unsigned int flags);

void
qemuMigrationCookieFree(qemuMigrationCookiePtr mig);

int
qemuMigrationCookieAddPersistent(qemuMigrationCookiePtr mig,
                                 virDomainDefPtr *def);

virDomainDefPtr
qemuMigrationCookieGetPersistent(qemuMigrationCookiePtr mig);

#endif /* __QEMU_MIGRATION_COOKIE_H__ */
