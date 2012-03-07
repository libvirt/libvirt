/*
 * lock_driver_sanlock.c: A lock driver for Sanlock
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include <config.h>

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sanlock.h>
#include <sanlock_resource.h>
#include <sanlock_admin.h>

#include "lock_driver.h"
#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "virfile.h"
#include "md5.h"
#include "conf.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

#define virLockError(code, ...)                                     \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,             \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


#define VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE "__LIBVIRT__DISKS__"

typedef struct _virLockManagerSanlockDriver virLockManagerSanlockDriver;
typedef virLockManagerSanlockDriver *virLockManagerSanlockDriverPtr;

typedef struct _virLockManagerSanlockPrivate virLockManagerSanlockPrivate;
typedef virLockManagerSanlockPrivate *virLockManagerSanlockPrivatePtr;

struct _virLockManagerSanlockDriver {
    bool requireLeaseForDisks;
    int hostID;
    bool autoDiskLease;
    char *autoDiskLeasePath;
};

static virLockManagerSanlockDriver *driver = NULL;

struct _virLockManagerSanlockPrivate {
    char vm_name[SANLK_NAME_LEN];
    char vm_uuid[VIR_UUID_BUFLEN];
    unsigned int vm_id;
    unsigned int vm_pid;
    unsigned int flags;
    bool hasRWDisks;
    int res_count;
    struct sanlk_resource *res_args[SANLK_MAX_RESOURCES];
};

/*
 * sanlock plugin for the libvirt virLockManager API
 */
static int virLockManagerSanlockLoadConfig(const char *configFile)
{
    virConfPtr conf;
    virConfValuePtr p;

    if (access(configFile, R_OK) == -1) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to access config file %s"),
                                 configFile);
            return -1;
        }
        return 0;
    }

    if (!(conf = virConfReadFile(configFile, 0)))
        return -1;

#define CHECK_TYPE(name,typ) if (p && p->type != (typ)) {               \
        virLockError(VIR_ERR_INTERNAL_ERROR,                            \
                     "%s: %s: expected type " #typ,                     \
                     configFile, (name));                               \
        virConfFree(conf);                                              \
        return -1;                                                      \
    }

    p = virConfGetValue(conf, "auto_disk_leases");
    CHECK_TYPE("auto_disk_leases", VIR_CONF_LONG);
    if (p) driver->autoDiskLease = p->l;

    p = virConfGetValue(conf, "disk_lease_dir");
    CHECK_TYPE("disk_lease_dir", VIR_CONF_STRING);
    if (p && p->str) {
        VIR_FREE(driver->autoDiskLeasePath);
        if (!(driver->autoDiskLeasePath = strdup(p->str))) {
            virReportOOMError();
            virConfFree(conf);
            return -1;
        }
    }

    p = virConfGetValue(conf, "host_id");
    CHECK_TYPE("host_id", VIR_CONF_LONG);
    if (p) driver->hostID = p->l;

    p = virConfGetValue(conf, "require_lease_for_disks");
    CHECK_TYPE("require_lease_for_disks", VIR_CONF_LONG);
    if (p)
        driver->requireLeaseForDisks = p->l;
    else
        driver->requireLeaseForDisks = !driver->autoDiskLease;

    virConfFree(conf);
    return 0;
}

static int virLockManagerSanlockSetupLockspace(void)
{
    int fd = -1;
    struct stat st;
    int rv;
    struct sanlk_lockspace ls;
    char *path = NULL;

    if (virAsprintf(&path, "%s/%s",
                    driver->autoDiskLeasePath,
                    VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE) < 0) {
        virReportOOMError();
        goto error;
    }

    memcpy(ls.name, VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE, SANLK_NAME_LEN);
    ls.host_id = 0; /* Doesn't matter for initialization */
    ls.flags = 0;
    if (!virStrcpy(ls.host_id_disk.path, path, SANLK_PATH_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Lockspace path '%s' exceeded %d characters"),
                     path, SANLK_PATH_LEN);
        goto error;
    }
    ls.host_id_disk.offset = 0;

    /* Stage 1: Ensure the lockspace file exists on disk, has
     * space allocated for it and is initialized with lease
     */
    if (stat(path, &st) < 0) {
        VIR_DEBUG("Lockspace %s does not yet exist", path);
        if ((fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
            if (errno != EEXIST) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %s"),
                                     path);
                goto error;
            }
            VIR_DEBUG("Someone else just created lockspace %s", path);
        } else {
            if ((rv = sanlock_align(&ls.host_id_disk)) < 0) {
                if (rv <= -200)
                    virLockError(VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to query sector size %s: error %d"),
                                 path, rv);
                else
                    virReportSystemError(-rv,
                                         _("Unable to query sector size %s"),
                                         path);
                goto error_unlink;
            }

            /*
             * Pre allocate enough data for 1 block of leases at preferred alignment
             */
            if (safezero(fd, 0, rv) < 0) {
                virReportSystemError(errno,
                                     _("Unable to allocate lockspace %s"),
                                     path);
                goto error_unlink;
            }

            if (VIR_CLOSE(fd) < 0) {
                virReportSystemError(errno,
                                     _("Unable to save lockspace %s"),
                                     path);
                goto error_unlink;
            }

            if ((rv = sanlock_init(&ls, NULL, 0, 0)) < 0) {
                if (rv <= -200)
                    virLockError(VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to initialize lockspace %s: error %d"),
                                 path, rv);
                else
                    virReportSystemError(-rv,
                                         _("Unable to initialize lockspace %s"),
                                         path);
                goto error_unlink;
            }
            VIR_DEBUG("Lockspace %s has been initialized", path);
        }
    }

    ls.host_id = driver->hostID;
    /* Stage 2: Try to register the lockspace with the daemon.
     * If the lockspace is already registered, we should get EEXIST back
     * in which case we can just carry on with life
     */
    if ((rv = sanlock_add_lockspace(&ls, 0)) < 0) {
        if (-rv != EEXIST) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to add lockspace %s: error %d"),
                             path, rv);
            else
                virReportSystemError(-rv,
                                     _("Unable to add lockspace %s"),
                                     path);
            goto error_unlink;
        } else {
            VIR_DEBUG("Lockspace %s is already registered", path);
        }
    } else {
        VIR_DEBUG("Lockspace %s has been registered", path);
    }

    return 0;

error_unlink:
    unlink(path);
error:
    VIR_FORCE_CLOSE(fd);
    VIR_FREE(path);
    return -1;
}


static int virLockManagerSanlockDeinit(void);
static int virLockManagerSanlockInit(unsigned int version,
                                     const char *configFile,
                                     unsigned int flags)
{
    VIR_DEBUG("version=%u configFile=%s flags=%x",
              version, NULLSTR(configFile), flags);
    virCheckFlags(0, -1);

    if (driver)
        return 0;

    if (VIR_ALLOC(driver) < 0) {
        virReportOOMError();
        return -1;
    }

    driver->requireLeaseForDisks = true;
    driver->hostID = 0;
    driver->autoDiskLease = false;
    if (!(driver->autoDiskLeasePath = strdup(LOCALSTATEDIR "/lib/libvirt/sanlock"))) {
        VIR_FREE(driver);
        virReportOOMError();
        goto error;
    }

    if (virLockManagerSanlockLoadConfig(configFile) < 0)
        goto error;

    if (driver->autoDiskLease && !driver->hostID) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Automatic disk lease mode enabled, but no host ID is set"));
        goto error;
    }

    if (driver->autoDiskLease) {
        if (virLockManagerSanlockSetupLockspace() < 0)
            goto error;
    }

    return 0;

error:
    virLockManagerSanlockDeinit();
    return -1;
}

static int virLockManagerSanlockDeinit(void)
{
    if (!driver)
        return 0;

    VIR_FREE(driver->autoDiskLeasePath);
    VIR_FREE(driver);

    return 0;
}


static int virLockManagerSanlockNew(virLockManagerPtr lock,
                                    unsigned int type,
                                    size_t nparams,
                                    virLockManagerParamPtr params,
                                    unsigned int flags)
{
    virLockManagerParamPtr param;
    virLockManagerSanlockPrivatePtr priv;
    int i;

    virCheckFlags(0, -1);

    if (!driver) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Sanlock plugin is not initialized"));
        return -1;
    }

    if (type != VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Unsupported object type %d"), type);
        return -1;
    }

    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return -1;
    }

    priv->flags = flags;

    for (i = 0; i < nparams; i++) {
        param = &params[i];

        if (STREQ(param->key, "uuid")) {
            memcpy(priv->vm_uuid, param->value.uuid, 16);
        } else if (STREQ(param->key, "name")) {
            if (!virStrcpy(priv->vm_name, param->value.str, SANLK_NAME_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Domain name '%s' exceeded %d characters"),
                             param->value.str, SANLK_NAME_LEN);
                goto error;
            }
        } else if (STREQ(param->key, "pid")) {
            priv->vm_pid = param->value.ui;
        } else if (STREQ(param->key, "id")) {
            priv->vm_id = param->value.ui;
        }
    }

    lock->privateData = priv;
    return 0;

error:
    VIR_FREE(priv);
    return -1;
}

static void virLockManagerSanlockFree(virLockManagerPtr lock)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int i;

    if (!priv)
        return;

    for (i = 0; i < priv->res_count; i++)
        VIR_FREE(priv->res_args[i]);
    VIR_FREE(priv);
    lock->privateData = NULL;
}


static const char hex[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

static int virLockManagerSanlockDiskLeaseName(const char *path,
                                              char *str,
                                              size_t strbuflen)
{
    unsigned char buf[MD5_DIGEST_SIZE];
    int i;

    if (strbuflen < ((MD5_DIGEST_SIZE * 2) + 1)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("String length too small to store md5 checksum"));
        return -1;
    }

    if (!(md5_buffer(path, strlen(path), buf))) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Unable to compute md5 checksum"));
        return -1;
    }

    for (i = 0 ; i < MD5_DIGEST_SIZE ; i++) {
        str[i*2] = hex[(buf[i] >> 4) & 0xf];
        str[(i*2)+1] = hex[buf[i] & 0xf];
    }
    str[(MD5_DIGEST_SIZE*2)+1] = '\0';
    return 0;
}

static int virLockManagerSanlockAddLease(virLockManagerPtr lock,
                                         const char *name,
                                         size_t nparams,
                                         virLockManagerParamPtr params)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int ret = -1;
    struct sanlk_resource *res = NULL;
    int i;

    if (VIR_ALLOC_VAR(res, struct sanlk_disk, 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    res->num_disks = 1;
    if (!virStrcpy(res->name, name, SANLK_NAME_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Resource name '%s' exceeds %d characters"),
                     name, SANLK_NAME_LEN);
        goto cleanup;
    }

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].key, "path")) {
            if (!virStrcpy(res->disks[0].path, params[i].value.str, SANLK_PATH_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Lease path '%s' exceeds %d characters"),
                             params[i].value.str, SANLK_PATH_LEN);
                goto cleanup;
            }
        } else if (STREQ(params[i].key, "offset")) {
            res->disks[0].offset = params[i].value.ul;
        } else if (STREQ(params[i].key, "lockspace")) {
            if (!virStrcpy(res->lockspace_name, params[i].value.str, SANLK_NAME_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Resource lockspace '%s' exceeds %d characters"),
                             params[i].value.str, SANLK_NAME_LEN);
                goto cleanup;
            }
        }
    }

    priv->res_args[priv->res_count] = res;
    priv->res_count++;

    ret = 0;

cleanup:
    if (ret == -1)
        VIR_FREE(res);
    return ret;
}




static int virLockManagerSanlockAddDisk(virLockManagerPtr lock,
                                        const char *name,
                                        size_t nparams,
                                        virLockManagerParamPtr params ATTRIBUTE_UNUSED)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int ret = -1;
    struct sanlk_resource *res = NULL;
    char *path = NULL;

    if (nparams) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Unexpected lock parameters for disk resource"));
        return -1;
    }

    if (VIR_ALLOC_VAR(res, struct sanlk_disk, 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    res->num_disks = 1;
    if (virLockManagerSanlockDiskLeaseName(name, res->name, SANLK_NAME_LEN) < 0)
        goto cleanup;

    if (virAsprintf(&path, "%s/%s",
                    driver->autoDiskLeasePath, res->name) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (!virStrcpy(res->disks[0].path, path, SANLK_PATH_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Lease path '%s' exceeds %d characters"),
                     path, SANLK_PATH_LEN);
        goto cleanup;
    }

    if (!virStrcpy(res->lockspace_name,
                   VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE,
                   SANLK_NAME_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Resource lockspace '%s' exceeds %d characters"),
                     VIR_LOCK_MANAGER_SANLOCK_AUTO_DISK_LOCKSPACE, SANLK_NAME_LEN);
        goto cleanup;
    }

    priv->res_args[priv->res_count] = res;
    priv->res_count++;

    ret = 0;

cleanup:
    if (ret == -1)
        VIR_FREE(res);
    VIR_FREE(path);
    return ret;
}


static int virLockManagerSanlockCreateLease(struct sanlk_resource *res)
{
    int fd = -1;
    struct stat st;
    int rv;

    if (stat(res->disks[0].path, &st) < 0) {
        VIR_DEBUG("Lockspace %s does not yet exist", res->disks[0].path);
        if ((fd = open(res->disks[0].path, O_WRONLY|O_CREAT|O_EXCL, 0600)) < 0) {
            if (errno != EEXIST) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %s"),
                                     res->disks[0].path);
                return -1;
            }
            VIR_DEBUG("Someone else just created lockspace %s", res->disks[0].path);
        } else {
            if ((rv = sanlock_align(&res->disks[0])) < 0) {
                if (rv <= -200)
                    virLockError(VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to query sector size %s: error %d"),
                                 res->disks[0].path, rv);
                else
                    virReportSystemError(-rv,
                                         _("Unable to query sector size %s"),
                                         res->disks[0].path);
                goto error_unlink;
            }

            /*
             * Pre allocate enough data for 1 block of leases at preferred alignment
             */
            if (safezero(fd, 0, rv) < 0) {
                virReportSystemError(errno,
                                     _("Unable to allocate lease %s"),
                                     res->disks[0].path);
                goto error_unlink;
            }

            if (VIR_CLOSE(fd) < 0) {
                virReportSystemError(errno,
                                     _("Unable to save lease %s"),
                                     res->disks[0].path);
                goto error_unlink;
            }

            if ((rv = sanlock_init(NULL, res, 0, 0)) < 0) {
                if (rv <= -200)
                    virLockError(VIR_ERR_INTERNAL_ERROR,
                                 _("Unable to initialize lease %s: error %d"),
                                 res->disks[0].path, rv);
                else
                    virReportSystemError(-rv,
                                         _("Unable to initialize lease %s"),
                                         res->disks[0].path);
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


static int virLockManagerSanlockAddResource(virLockManagerPtr lock,
                                            unsigned int type,
                                            const char *name,
                                            size_t nparams,
                                            virLockManagerParamPtr params,
                                            unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;

    virCheckFlags(VIR_LOCK_MANAGER_RESOURCE_READONLY |
                  VIR_LOCK_MANAGER_RESOURCE_SHARED, -1);

    if (priv->res_count == SANLK_MAX_RESOURCES) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Too many resources %d for object"),
                     SANLK_MAX_RESOURCES);
        return -1;
    }

    if (flags & VIR_LOCK_MANAGER_RESOURCE_READONLY) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Readonly leases are not supported"));
        return -1;
    }
    if (flags & VIR_LOCK_MANAGER_RESOURCE_SHARED) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Shareable leases are not supported"));
        return -1;
    }

    switch (type) {
    case VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK:
        if (driver->autoDiskLease) {
            if (virLockManagerSanlockAddDisk(lock, name, nparams, params) < 0)
                return -1;

            if (virLockManagerSanlockCreateLease(priv->res_args[priv->res_count-1]) < 0)
                return -1;
        } else {
            if (!(flags & (VIR_LOCK_MANAGER_RESOURCE_SHARED |
                           VIR_LOCK_MANAGER_RESOURCE_READONLY)))
                priv->hasRWDisks = true;
            /* Ignore disk resources without error */
        }
        break;

    case VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE:
        if (virLockManagerSanlockAddLease(lock, name, nparams, params) < 0)
            return -1;
        break;

    default:
        /* Ignore other resources, without error */
        break;
    }

    return 0;
}

static int virLockManagerSanlockAcquire(virLockManagerPtr lock,
                                        const char *state,
                                        unsigned int flags,
                                        int *fd)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    struct sanlk_options *opt;
    struct sanlk_resource **res_args;
    int res_count;
    bool res_free = false;
    int sock = -1;
    int rv;
    int i;

    virCheckFlags(VIR_LOCK_MANAGER_ACQUIRE_RESTRICT |
                  VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY, -1);

    if (priv->res_count == 0 &&
        priv->hasRWDisks &&
        driver->requireLeaseForDisks) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Read/write, exclusive access, disks were present, but no leases specified"));
        return -1;
    }

    if (VIR_ALLOC(opt) < 0) {
        virReportOOMError();
        return -1;
    }

    if (!virStrcpy(opt->owner_name, priv->vm_name, SANLK_NAME_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Domain name '%s' exceeded %d characters"),
                     priv->vm_name, SANLK_NAME_LEN);
        goto error;
    }

    if (state && STRNEQ(state, "")) {
        if ((rv = sanlock_state_to_args((char *)state,
                                        &res_count,
                                        &res_args)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to parse lock state %s: error %d"),
                             state, rv);
            else
                virReportSystemError(-rv,
                                     _("Unable to parse lock state %s"),
                                     state);
            goto error;
        }
        res_free = true;
    } else {
        res_args = priv->res_args;
        res_count = priv->res_count;
    }

    VIR_DEBUG("Register sanlock %d", flags);
    /* We only initialize 'sock' if we are in the real
     * child process and we need it to be inherited
     *
     * If sock==-1, then sanlock auto-open/closes a
     * temporary sock
     */
    if (priv->vm_pid == getpid() &&
        (sock = sanlock_register()) < 0) {
        if (sock <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to open socket to sanlock daemon: error %d"),
                         sock);
        else
            virReportSystemError(-sock, "%s",
                                 _("Failed to open socket to sanlock daemon"));
        goto error;
    }

    if (!(flags & VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY)) {
        VIR_DEBUG("Acquiring object %u", priv->res_count);
        if ((rv = sanlock_acquire(sock, priv->vm_pid, 0,
                                  priv->res_count, priv->res_args,
                                  opt)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to acquire lock: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to acquire lock"));
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
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to restrict process: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to restrict process"));
            goto error;
        }
    }

    VIR_DEBUG("Acquire completed fd=%d", sock);

    if (res_free) {
        for (i = 0 ; i < res_count ; i++) {
            VIR_FREE(res_args[i]);
        }
        VIR_FREE(res_args);
    }

    if (fd)
        *fd = sock;

    return 0;

error:
    if (res_free) {
        for (i = 0 ; i < res_count ; i++) {
            VIR_FREE(res_args[i]);
        }
        VIR_FREE(res_args);
    }
    VIR_FREE(opt);
    VIR_FORCE_CLOSE(sock);
    return -1;
}


static int virLockManagerSanlockRelease(virLockManagerPtr lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int res_count;
    int rv;

    virCheckFlags(0, -1);

    if (state) {
        if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to inquire lock: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to inquire lock"));
            return -1;
        }

        if (STREQ_NULLABLE(*state, ""))
            VIR_FREE(*state);
    }

    if ((rv = sanlock_release(-1, priv->vm_pid, SANLK_REL_ALL, 0, NULL)) < 0) {
        if (rv <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to release lock: error %d"), rv);
        else
            virReportSystemError(-rv, "%s",
                                 _("Failed to release lock"));
        return -1;
    }

    return 0;
}

static int virLockManagerSanlockInquire(virLockManagerPtr lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int rv, res_count;

    virCheckFlags(0, -1);

    if (!state) {
        virLockError(VIR_ERR_INVALID_ARG, "state");
        return -1;
    }

    VIR_DEBUG("pid=%d", priv->vm_pid);

    if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
        if (rv <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to inquire lock: error %d"), rv);
        else
            virReportSystemError(-rv, "%s",
                                 _("Failed to inquire lock"));
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
