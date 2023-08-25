/*
 * lock_driver_sanlock.c: A lock driver for Sanlock
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
 */

#include <config.h>

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sanlock.h>
#include <sanlock_resource.h>
#include <sanlock_admin.h>

#include "lock_driver.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "vircrypto.h"
#include "virfile.h"
#include "virconf.h"
#include "virstring.h"
#include "virutil.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_driver_sanlock");

#define VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE "__LIBVIRT__DISKS__"
#define VIR_LOCK_MANAGER_SANLOCK_KILLPATH LIBEXECDIR "/libvirt_sanlock_helper"

/*
 * temporary fix for the case where the sanlock devel package is
 * too old to provide that define, and probably the functionality too
 */
#ifndef SANLK_RES_SHARED
# define SANLK_RES_SHARED    0x4
#endif

typedef struct _virLockManagerSanlockDriver virLockManagerSanlockDriver;

typedef struct _virLockManagerSanlockPrivate virLockManagerSanlockPrivate;

struct _virLockManagerSanlockDriver {
    bool requireLeaseForDisks;
    unsigned int hostID;
    bool autoDiskLease;
    char *autoDiskLeasePath;
    unsigned int io_timeout;

    /* under which permissions does sanlock run */
    uid_t user;
    gid_t group;
};

static virLockManagerSanlockDriver *sanlockDriver;

struct _virLockManagerSanlockPrivate {
    const char *vm_uri;
    char *vm_name;
    unsigned char vm_uuid[VIR_UUID_BUFLEN];
    unsigned int vm_id;
    int vm_pid;
    unsigned int flags;
    bool hasRWDisks;
    int res_count;
    struct sanlk_resource *res_args[SANLK_MAX_RESOURCES];

    /* whether the VM was registered or not */
    bool registered;
};


static bool
ATTRIBUTE_NONNULL(2)
virLockManagerSanlockError(int err,
                           char **message)
{
    if (err <= -200) {
#if WITH_SANLOCK_STRERROR
        *message = g_strdup(sanlock_strerror(err));
#else
        *message = g_strdup_printf(_("sanlock error %1$d"), err);
#endif
        return true;
    } else {
        return false;
    }
}


/*
 * sanlock plugin for the libvirt virLockManager API
 */
static int
virLockManagerSanlockLoadConfig(virLockManagerSanlockDriver *driver,
                                const char *configFile)
{
    g_autoptr(virConf) conf = NULL;
    g_autofree char *user = NULL;
    g_autofree char *group = NULL;

    if (access(configFile, R_OK) == -1) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to access config file %1$s"),
                                 configFile);
            return -1;
        }
        return 0;
    }

    if (!(conf = virConfReadFile(configFile, 0)))
        return -1;

    if (virConfGetValueBool(conf, "auto_disk_leases", &driver->autoDiskLease) < 0)
        return -1;

    if (virConfGetValueString(conf, "disk_lease_dir", &driver->autoDiskLeasePath) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "host_id", &driver->hostID) < 0)
        return -1;

    driver->requireLeaseForDisks = !driver->autoDiskLease;
    if (virConfGetValueBool(conf, "require_lease_for_disks", &driver->requireLeaseForDisks) < 0)
        return -1;

    if (virConfGetValueUInt(conf, "io_timeout", &driver->io_timeout) < 0)
        return -1;

    if (virConfGetValueString(conf, "user", &user) < 0)
        return -1;
    if (user &&
        virGetUserID(user, &driver->user) < 0)
        return -1;

    if (virConfGetValueString(conf, "group", &group) < 0)
        return -1;
    if (group &&
        virGetGroupID(group, &driver->group) < 0)
        return -1;

    return 0;
}

static int
virLockManagerSanlockInitLockspace(virLockManagerSanlockDriver *driver,
                                   struct sanlk_lockspace *ls)
{
    const int max_hosts = 0; /* defaults used in sanlock_init() implementation */
    const unsigned int lockspaceFlags = 0;

    return sanlock_write_lockspace(ls, max_hosts, lockspaceFlags,
                                   driver->io_timeout);
}

/* How many times try adding a lockspace? */
#define LOCKSPACE_RETRIES 10

static int
virLockManagerSanlockSetupLockspace(virLockManagerSanlockDriver *driver)
{
    int fd = -1;
    struct stat st;
    int rv;
    struct sanlk_lockspace ls;
    char *path = NULL;
    char *dir = NULL;
    int retries = LOCKSPACE_RETRIES;

    path = g_strdup_printf("%s/%s", driver->autoDiskLeasePath,
                           VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE);

    if (virStrcpyStatic(ls.name,
                        VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace path '%1$s' exceeded %2$d characters"),
                       VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE,
                       SANLK_PATH_LEN);
        goto error;
    }
    ls.host_id = 0; /* Doesn't matter for initialization */
    ls.flags = 0;
    if (virStrcpy(ls.host_id_disk.path, path, SANLK_PATH_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lockspace path '%1$s' exceeded %2$d characters"),
                       path, SANLK_PATH_LEN);
        goto error;
    }
    ls.host_id_disk.offset = 0;

    /* Stage 1: Ensure the lockspace file exists on disk, has
     * space allocated for it and is initialized with lease
     */
    if (stat(path, &st) < 0) {
        int perms = 0600;
        VIR_DEBUG("Lockspace %s does not yet exist", path);

        dir = g_path_get_dirname(path);
        if (stat(dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to create lockspace %1$s: parent directory does not exist or is not a directory"),
                           path);
            goto error;
        }

        if (driver->group != (gid_t) -1)
            perms |= 0060;

        if ((fd = open(path, O_WRONLY|O_CREAT|O_EXCL, perms)) < 0) {
            if (errno != EEXIST) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %1$s"),
                                     path);
                goto error;
            }
            VIR_DEBUG("Someone else just created lockspace %s", path);
        } else {
            /* chown() the path to make sure sanlock can access it */
            if ((driver->user != (uid_t) -1 || driver->group != (gid_t) -1) &&
                (fchown(fd, driver->user, driver->group) < 0)) {
                virReportSystemError(errno,
                                     _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                     path,
                                     (unsigned int) driver->user,
                                     (unsigned int) driver->group);
                goto error_unlink;
            }

            if ((rv = sanlock_align(&ls.host_id_disk)) < 0) {
                char *err = NULL;
                if (virLockManagerSanlockError(rv, &err)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to query sector size %1$s: %2$s"),
                                   path, NULLSTR(err));
                    VIR_FREE(err);
                } else {
                    virReportSystemError(-rv,
                                         _("Unable to query sector size %1$s"),
                                         path);
                }
                goto error_unlink;
            }

            /*
             * Pre allocate enough data for 1 block of leases at preferred alignment
             */
            if (safezero(fd, 0, rv) < 0) {
                virReportSystemError(errno,
                                     _("Unable to allocate lockspace %1$s"),
                                     path);
                goto error_unlink;
            }

            if (VIR_CLOSE(fd) < 0) {
                virReportSystemError(errno,
                                     _("Unable to save lockspace %1$s"),
                                     path);
                goto error_unlink;
            }

            if ((rv = virLockManagerSanlockInitLockspace(driver, &ls)) < 0) {
                char *err = NULL;
                if (virLockManagerSanlockError(rv, &err)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to initialize lockspace %1$s: %2$s"),
                                   path, NULLSTR(err));
                    VIR_FREE(err);
                } else {
                    virReportSystemError(-rv,
                                         _("Unable to initialize lockspace %1$s"),
                                         path);
                }
                goto error_unlink;
            }
            VIR_DEBUG("Lockspace %s has been initialized", path);
        }
    } else if (S_ISREG(st.st_mode)) {
        /* okay, the lease file exists. Check the permissions */
        if (((driver->user != (uid_t) -1 && driver->user != st.st_uid) ||
             (driver->group != (gid_t) -1 && driver->group != st.st_gid)) &&
            (chown(path, driver->user, driver->group) < 0)) {
            virReportSystemError(errno,
                                 _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                 path,
                                 (unsigned int) driver->user,
                                 (unsigned int) driver->group);
            goto error;
        }

        if ((driver->group != (gid_t) -1 && (st.st_mode & 0060) != 0060) &&
            chmod(path, 0660) < 0) {
            virReportSystemError(errno,
                                 _("cannot chmod '%1$s' to 0660"),
                                 path);
            goto error;
        }
    }

    ls.host_id = driver->hostID;
    /* Stage 2: Try to register the lockspace with the daemon.  If the lockspace
     * is already registered, we should get EEXIST back in which case we can
     * just carry on with life. If EINPROGRESS is returned, we have two options:
     * either call a sanlock API that blocks us until lockspace changes state,
     * or we can fallback to polling.
     */
 retry:
    rv = sanlock_add_lockspace_timeout(&ls, 0, driver->io_timeout);
    if (rv < 0) {
        if (-rv == EINPROGRESS && --retries) {
            /* we have this function which blocks until lockspace change the
             * state. It returns 0 if lockspace has been added, -ENOENT if it
             * hasn't. */
            VIR_DEBUG("Inquiring lockspace");
            if (sanlock_inq_lockspace(&ls, SANLK_INQ_WAIT) < 0)
                VIR_DEBUG("Unable to inquire lockspace");
            VIR_DEBUG("Retrying to add lockspace (left %d)", retries);
            goto retry;
        }
        if (-rv != EEXIST) {
            char *err = NULL;
            if (virLockManagerSanlockError(rv, &err)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to add lockspace %1$s: %2$s"),
                               path, NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-rv,
                                     _("Unable to add lockspace %1$s"),
                                     path);
            }
            goto error;
        } else {
            VIR_DEBUG("Lockspace %s is already registered", path);
        }
    } else {
        VIR_DEBUG("Lockspace %s has been registered", path);
    }

    VIR_FREE(path);
    VIR_FREE(dir);
    return 0;

 error_unlink:
    unlink(path);
 error:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(path);
    VIR_FREE(dir);
    return -1;
}


static int virLockManagerSanlockDeinit(void);
static int virLockManagerSanlockInit(unsigned int version,
                                     const char *configFile,
                                     unsigned int flags)
{
    virLockManagerSanlockDriver *driver;

    VIR_DEBUG("version=%u configFile=%s flags=0x%x",
              version, NULLSTR(configFile), flags);
    virCheckFlags(0, -1);

    if (sanlockDriver)
        return 0;

    sanlockDriver = g_new0(virLockManagerSanlockDriver, 1);

    driver = sanlockDriver;

    driver->requireLeaseForDisks = true;
    driver->hostID = 0;
    driver->autoDiskLease = false;
    driver->io_timeout = 0;
    driver->user = (uid_t) -1;
    driver->group = (gid_t) -1;
    driver->autoDiskLeasePath = g_strdup(LOCALSTATEDIR "/lib/libvirt/sanlock");

    if (virLockManagerSanlockLoadConfig(driver, configFile) < 0)
        goto error;

    if (driver->autoDiskLease && !driver->hostID) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Automatic disk lease mode enabled, but no host ID is set"));
        goto error;
    }

    if (driver->autoDiskLease) {
        if (virLockManagerSanlockSetupLockspace(driver) < -1)
            goto error;
    }

    return 0;

 error:
    virLockManagerSanlockDeinit();
    return -1;
}

static int virLockManagerSanlockDeinit(void)
{
    if (!sanlockDriver)
        return 0;

    VIR_FREE(sanlockDriver->autoDiskLeasePath);
    VIR_FREE(sanlockDriver);

    return 0;
}


static int virLockManagerSanlockNew(virLockManager *lock,
                                    unsigned int type,
                                    size_t nparams,
                                    virLockManagerParam *params,
                                    unsigned int flags)
{
    virLockManagerParam *param;
    virLockManagerSanlockPrivate *priv;
    size_t i;
    int resCount = 0;

    virCheckFlags(VIR_LOCK_MANAGER_NEW_STARTED, -1);

    if (!sanlockDriver) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Sanlock plugin is not initialized"));
        return -1;
    }

    if (type != VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unsupported object type %1$d"), type);
        return -1;
    }

    priv = g_new0(virLockManagerSanlockPrivate,
                  1);

    priv->flags = flags;

    for (i = 0; i < nparams; i++) {
        param = &params[i];

        if (STREQ(param->key, "uuid")) {
            memcpy(priv->vm_uuid, param->value.uuid, 16);
        } else if (STREQ(param->key, "name")) {
            priv->vm_name = g_strdup(param->value.str);
        } else if (STREQ(param->key, "pid")) {
            priv->vm_pid = param->value.iv;
        } else if (STREQ(param->key, "id")) {
            priv->vm_id = param->value.ui;
        } else if (STREQ(param->key, "uri")) {
            priv->vm_uri = param->value.cstr;
        }
    }

    /* Sanlock needs process registration, but the only way how to probe
     * whether a process has been registered is to inquire the lock.  If
     * sanlock_inquire() returns -ESRCH, then it is not registered, but
     * if it returns any other error (rv < 0), then we cannot fail due
     * to back-compat.  So this whole call is non-fatal, because it's
     * called from all over the place (it will usually fail).  It merely
     * updates privateData.
     * If the process has just been started, we are pretty sure it is not
     * registered. */
    if (!(flags & VIR_LOCK_MANAGER_NEW_STARTED) &&
        sanlock_inquire(-1, priv->vm_pid, 0, &resCount, NULL) >= 0)
        priv->registered = true;

    lock->privateData = priv;
    return 0;
}

static void virLockManagerSanlockFree(virLockManager *lock)
{
    virLockManagerSanlockPrivate *priv = lock->privateData;
    size_t i;

    if (!priv)
        return;

    g_free(priv->vm_name);
    for (i = 0; i < priv->res_count; i++)
        g_free(priv->res_args[i]);
    g_free(priv);
    lock->privateData = NULL;
}


static int virLockManagerSanlockAddLease(virLockManager *lock,
                                         const char *name,
                                         size_t nparams,
                                         virLockManagerParam *params,
                                         bool shared)
{
    virLockManagerSanlockPrivate *priv = lock->privateData;
    g_autofree struct sanlk_resource *res = NULL;
    size_t i;

    res = g_malloc0(sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk));

    res->flags = shared ? SANLK_RES_SHARED : 0;
    res->num_disks = 1;
    if (virStrcpy(res->name, name, SANLK_NAME_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Resource name '%1$s' exceeds %2$d characters"),
                       name, SANLK_NAME_LEN);
        return -1;
    }

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].key, "path")) {
            if (virStrcpy(res->disks[0].path, params[i].value.str, SANLK_PATH_LEN) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Lease path '%1$s' exceeds %2$d characters"),
                               params[i].value.str, SANLK_PATH_LEN);
                return -1;
            }
        } else if (STREQ(params[i].key, "offset")) {
            res->disks[0].offset = params[i].value.ul;
        } else if (STREQ(params[i].key, "lockspace")) {
            if (virStrcpy(res->lockspace_name, params[i].value.str, SANLK_NAME_LEN) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Resource lockspace '%1$s' exceeds %2$d characters"),
                               params[i].value.str, SANLK_NAME_LEN);
                return -1;
            }
        }
    }

    priv->res_args[priv->res_count] = g_steal_pointer(&res);
    priv->res_count++;

    return 0;
}




static int
virLockManagerSanlockAddDisk(virLockManagerSanlockDriver *driver,
                             virLockManager *lock,
                             const char *name,
                             size_t nparams,
                             virLockManagerParam *params G_GNUC_UNUSED,
                             bool shared)
{
    virLockManagerSanlockPrivate *priv = lock->privateData;
    g_autofree struct sanlk_resource *res = NULL;
    g_autofree char *path = NULL;
    g_autofree char *hash = NULL;

    if (nparams) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected lock parameters for disk resource"));
        return -1;
    }

    res = g_malloc0(sizeof(struct sanlk_resource) + sizeof(struct sanlk_disk));

    res->flags = shared ? SANLK_RES_SHARED : 0;
    res->num_disks = 1;
    if (virCryptoHashString(VIR_CRYPTO_HASH_MD5, name, &hash) < 0)
        return -1;
    if (virStrcpy(res->name, hash, SANLK_NAME_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("MD5 hash '%1$s' unexpectedly larger than %2$d characters"),
                       hash, (SANLK_NAME_LEN - 1));
        return -1;
    }

    path = g_strdup_printf("%s/%s", driver->autoDiskLeasePath, res->name);
    if (virStrcpy(res->disks[0].path, path, SANLK_PATH_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Lease path '%1$s' exceeds %2$d characters"),
                       path, SANLK_PATH_LEN);
        return -1;
    }

    if (virStrcpy(res->lockspace_name,
                  VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE,
                  SANLK_NAME_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Resource lockspace '%1$s' exceeds %2$d characters"),
                       VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE, SANLK_NAME_LEN);
        return -1;
    }

    priv->res_args[priv->res_count] = g_steal_pointer(&res);
    priv->res_count++;

    return 0;
}


static int
virLockManagerSanlockCreateLease(virLockManagerSanlockDriver *driver,
                                 struct sanlk_resource *res)
{
    int fd = -1;
    struct stat st;
    int rv;

    if (stat(res->disks[0].path, &st) < 0) {
        VIR_DEBUG("Lockspace %s does not yet exist", res->disks[0].path);
        if ((fd = open(res->disks[0].path, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
            if (errno != EEXIST) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %1$s"),
                                     res->disks[0].path);
                return -1;
            }
            VIR_DEBUG("Someone else just created lockspace %s", res->disks[0].path);
        } else {
            /* chown() the path to make sure sanlock can access it */
            if ((driver->user != (uid_t) -1 || driver->group != (gid_t) -1) &&
                (fchown(fd, driver->user, driver->group) < 0)) {
                virReportSystemError(errno,
                                     _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                     res->disks[0].path,
                                     (unsigned int) driver->user,
                                     (unsigned int) driver->group);
                goto error_unlink;
            }

            if ((rv = sanlock_align(&res->disks[0])) < 0) {
                char *err = NULL;
                if (virLockManagerSanlockError(rv, &err)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to query sector size %1$s: %2$s"),
                                   res->disks[0].path, NULLSTR(err));
                    VIR_FREE(err);
                } else {
                    virReportSystemError(-rv,
                                         _("Unable to query sector size %1$s"),
                                         res->disks[0].path);
                }
                goto error_unlink;
            }

            /*
             * Pre allocate enough data for 1 block of leases at preferred alignment
             */
            if (safezero(fd, 0, rv) < 0) {
                virReportSystemError(errno,
                                     _("Unable to allocate lease %1$s"),
                                     res->disks[0].path);
                goto error_unlink;
            }

            if (VIR_CLOSE(fd) < 0) {
                virReportSystemError(errno,
                                     _("Unable to save lease %1$s"),
                                     res->disks[0].path);
                goto error_unlink;
            }

            if ((rv = sanlock_init(NULL, res, 0, 0)) < 0) {
                char *err = NULL;
                if (virLockManagerSanlockError(rv, &err)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Unable to initialize lease %1$s: %2$s"),
                                   res->disks[0].path, NULLSTR(err));
                    VIR_FREE(err);
                } else {
                    virReportSystemError(-rv,
                                         _("Unable to initialize lease %1$s"),
                                         res->disks[0].path);
                }
                goto error_unlink;
            }
            VIR_DEBUG("Lease %s has been initialized", res->disks[0].path);
        }
    }

    return 0;

 error_unlink:
    unlink(res->disks[0].path);
    VIR_FORCE_CLOSE(fd);
    return -1;
}


static int virLockManagerSanlockAddResource(virLockManager *lock,
                                            unsigned int type,
                                            const char *name,
                                            size_t nparams,
                                            virLockManagerParam *params,
                                            unsigned int flags)
{
    virLockManagerSanlockDriver *driver = sanlockDriver;
    virLockManagerSanlockPrivate *priv = lock->privateData;

    virCheckFlags(VIR_LOCK_MANAGER_RESOURCE_READONLY |
                  VIR_LOCK_MANAGER_RESOURCE_SHARED, -1);

    if (priv->res_count == SANLK_MAX_RESOURCES) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Too many resources %1$d for object"),
                       SANLK_MAX_RESOURCES);
        return -1;
    }

    /* Treat R/O resources as a no-op lock request */
    if (flags & VIR_LOCK_MANAGER_RESOURCE_READONLY)
        return 0;

    switch (type) {
    case VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK:
        if (driver->autoDiskLease) {
            if (virLockManagerSanlockAddDisk(driver, lock, name, nparams, params,
                                             !!(flags & VIR_LOCK_MANAGER_RESOURCE_SHARED)) < 0)
                return -1;

            if (virLockManagerSanlockCreateLease(driver,
                                                 priv->res_args[priv->res_count-1]) < 0)
                return -1;
        } else {
            if (!(flags & (VIR_LOCK_MANAGER_RESOURCE_SHARED |
                           VIR_LOCK_MANAGER_RESOURCE_READONLY)))
                priv->hasRWDisks = true;
            /* Ignore disk resources without error */
        }
        break;

    case VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE:
        if (virLockManagerSanlockAddLease(lock, name, nparams, params,
                                          !!(flags & VIR_LOCK_MANAGER_RESOURCE_SHARED)) < 0)
            return -1;
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown lock manager object type %1$d for domain lock object"),
                       type);
        return -1;
    }

    return 0;
}

static int
virLockManagerSanlockRegisterKillscript(int sock,
                                        const char *vmuri,
                                        const char *uuidstr,
                                        virDomainLockFailureAction action)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char *path;
    g_autofree char *args = NULL;
    int rv;

    switch (action) {
    case VIR_DOMAIN_LOCK_FAILURE_DEFAULT:
        return 0;

    case VIR_DOMAIN_LOCK_FAILURE_POWEROFF:
    case VIR_DOMAIN_LOCK_FAILURE_PAUSE:
        break;

    case VIR_DOMAIN_LOCK_FAILURE_RESTART:
    case VIR_DOMAIN_LOCK_FAILURE_IGNORE:
    case VIR_DOMAIN_LOCK_FAILURE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Failure action %1$s is not supported by sanlock"),
                       virDomainLockFailureTypeToString(action));
        return -1;
    }

    virBufferEscape(&buf, '\\', "\\ ", "%s", vmuri);
    virBufferAddLit(&buf, " ");
    virBufferEscape(&buf, '\\', "\\ ", "%s", uuidstr);
    virBufferAddLit(&buf, " ");
    virBufferEscape(&buf, '\\', "\\ ", "%s",
                    virDomainLockFailureTypeToString(action));

    /* Unfortunately, sanlock_killpath() does not use const for either
     * path or args even though it will just copy them into its own
     * buffers.
     */
    path = (char *) VIR_LOCK_MANAGER_SANLOCK_KILLPATH;
    args = virBufferContentAndReset(&buf);

    VIR_DEBUG("Register sanlock killpath: %s %s", path, args);

    /* sanlock_killpath() would just crop the strings */
    if (strlen(path) >= SANLK_HELPER_PATH_LEN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Sanlock helper path is longer than %1$d: '%2$s'"),
                       SANLK_HELPER_PATH_LEN - 1, path);
        return -1;
    }
    if (strlen(args) >= SANLK_HELPER_ARGS_LEN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Sanlock helper arguments are longer than %1$d: '%2$s'"),
                       SANLK_HELPER_ARGS_LEN - 1, args);
        return -1;
    }

    if ((rv = sanlock_killpath(sock, 0, path, args)) < 0) {
        char *err = NULL;
        if (virLockManagerSanlockError(rv, &err)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to register lock failure action: %1$s"),
                           NULLSTR(err));
            VIR_FREE(err);
        } else {
            virReportSystemError(-rv, "%s",
                                 _("Failed to register lock failure action"));
        }
        return -1;
    }

    return 0;
}

static int virLockManagerSanlockAcquire(virLockManager *lock,
                                        const char *state,
                                        unsigned int flags,
                                        virDomainLockFailureAction action,
                                        int *fd)
{
    virLockManagerSanlockDriver *driver = sanlockDriver;
    virLockManagerSanlockPrivate *priv = lock->privateData;
    struct sanlk_options *opt = NULL;
    struct sanlk_resource **res_args;
    int res_count;
    bool res_free = false;
    int sock = -1;
    int rv;
    size_t i;

    virCheckFlags(VIR_LOCK_MANAGER_ACQUIRE_RESTRICT |
                  VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY, -1);

    if (priv->res_count == 0 &&
        priv->hasRWDisks &&
        driver->requireLeaseForDisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Read/write, exclusive access, disks were present, but no leases specified"));
        return -1;
    }

    /* We only initialize 'sock' if we are in the real
     * child process and we need it to be inherited
     *
     * If sock == -1, then sanlock auto-open/closes a
     * temporary sock
     */
    if (priv->vm_pid == getpid()) {
        VIR_DEBUG("Register sanlock %d", flags);
        if ((sock = sanlock_register()) < 0) {
            char *err = NULL;
            if (virLockManagerSanlockError(sock, &err)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to open socket to sanlock daemon: %1$s"),
                               NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-sock, "%s",
                                     _("Failed to open socket to sanlock daemon"));
            }
            goto error;
        }

        /* Mark the pid as registered */
        priv->registered = true;

        if (action != VIR_DOMAIN_LOCK_FAILURE_DEFAULT) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(priv->vm_uuid, uuidstr);
            if (virLockManagerSanlockRegisterKillscript(sock, priv->vm_uri,
                                                        uuidstr, action) < 0)
                goto error;
        }
    } else if (!priv->registered) {
        VIR_DEBUG("Process not registered, not acquiring lock");
        return 0;
    }

    opt = g_new0(struct sanlk_options, 1);

    /* sanlock doesn't use owner_name for anything, so it's safe to take just
     * the first SANLK_NAME_LEN - 1 characters from vm_name */
    virStrcpy(opt->owner_name, priv->vm_name, SANLK_NAME_LEN);

    if (state && STRNEQ(state, "")) {
        if ((rv = sanlock_state_to_args((char *)state,
                                        &res_count,
                                        &res_args)) < 0) {
            char *err = NULL;
            if (virLockManagerSanlockError(rv, &err)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to parse lock state %1$s: %2$s"),
                               state, NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-rv,
                                     _("Unable to parse lock state %1$s"),
                                     state);
            }
            goto error;
        }
        res_free = true;
    } else {
        res_args = priv->res_args;
        res_count = priv->res_count;
    }

    if (!(flags & VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY)) {
        VIR_DEBUG("Acquiring object %u", priv->res_count);
        if ((rv = sanlock_acquire(sock, priv->vm_pid, 0,
                                  priv->res_count, priv->res_args,
                                  opt)) < 0) {
            char *err = NULL;
            if (virLockManagerSanlockError(rv, &err)) {
                virReportError(VIR_ERR_RESOURCE_BUSY,
                               _("Failed to acquire lock: %1$s"),
                               NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-rv, "%s",
                                     _("Failed to acquire lock"));
            }
            goto error;
        }
    }

    VIR_FREE(opt);

    /*
     * We are *intentionally* "leaking" sock file descriptor
     * because we want it to be inherited by QEMU. When the
     * sock FD finally closes upon QEMU exit (or crash) then
     * sanlock will notice EOF and release the lock
     */
    if (sock != -1 &&
        virSetInherit(sock, true) < 0)
        goto error;

    if (flags & VIR_LOCK_MANAGER_ACQUIRE_RESTRICT) {
        if ((rv = sanlock_restrict(sock, SANLK_RESTRICT_ALL)) < 0) {
            char *err = NULL;
            if (virLockManagerSanlockError(rv, &err)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to restrict process: %1$s"),
                               NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-rv, "%s",
                                     _("Failed to restrict process"));
            }
            goto error;
        }
    }

    VIR_DEBUG("Acquire completed fd=%d", sock);

    if (res_free) {
        for (i = 0; i < res_count; i++)
            VIR_FREE(res_args[i]);
        VIR_FREE(res_args);
    }

    if (fd)
        *fd = sock;

    return 0;

 error:
    if (res_free) {
        for (i = 0; i < res_count; i++)
            VIR_FREE(res_args[i]);
        VIR_FREE(res_args);
    }
    VIR_FREE(opt);
    VIR_FORCE_CLOSE(sock);
    return -1;
}


static int virLockManagerSanlockRelease(virLockManager *lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivate *priv = lock->privateData;
    int res_count = priv->res_count;
    int rv;

    virCheckFlags(0, -1);

    if (!priv->registered) {
        VIR_DEBUG("Process not registered, skipping release");
        return 0;
    }

    if (state) {
        if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
            char *err = NULL;
            if (virLockManagerSanlockError(rv, &err)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to inquire lock: %1$s"),
                               NULLSTR(err));
                VIR_FREE(err);
            } else {
                virReportSystemError(-rv, "%s",
                                     _("Failed to inquire lock"));
            }
            return -1;
        }

        if (STREQ_NULLABLE(*state, ""))
            VIR_FREE(*state);
    }

    if ((rv = sanlock_release(-1, priv->vm_pid, 0, res_count,
                              priv->res_args)) < 0) {
        char *err = NULL;
        if (virLockManagerSanlockError(rv, &err)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to release lock: %1$s"),
                           NULLSTR(err));
            VIR_FREE(err);
        } else {
            virReportSystemError(-rv, "%s",
                                 _("Failed to release lock"));
        }
        return -1;
    }

    return 0;
}

static int virLockManagerSanlockInquire(virLockManager *lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivate *priv = lock->privateData;
    int rv, res_count;

    virCheckFlags(0, -1);

    if (!state) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }

    VIR_DEBUG("pid=%d", priv->vm_pid);

    if (!priv->registered) {
        VIR_DEBUG("Process not registered, skipping inquiry");
        VIR_FREE(*state);
        return 0;
    }

    if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
        char *err;
        if (virLockManagerSanlockError(rv, &err)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to inquire lock: %1$s"),
                           NULLSTR(err));
            VIR_FREE(err);
        } else {
            virReportSystemError(-rv, "%s",
                                 _("Failed to inquire lock"));
        }
        return -1;
    }

    if (STREQ_NULLABLE(*state, ""))
        VIR_FREE(*state);

    return 0;
}

virLockDriver virLockDriverImpl =
{
    .version = VIR_LOCK_MANAGER_VERSION,

    .flags = VIR_LOCK_MANAGER_USES_STATE,

    .drvInit = virLockManagerSanlockInit,
    .drvDeinit = virLockManagerSanlockDeinit,

    .drvNew = virLockManagerSanlockNew,
    .drvFree = virLockManagerSanlockFree,

    .drvAddResource = virLockManagerSanlockAddResource,

    .drvAcquire = virLockManagerSanlockAcquire,
    .drvRelease = virLockManagerSanlockRelease,
    .drvInquire = virLockManagerSanlockInquire,
};
