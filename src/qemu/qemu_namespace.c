/*
 * qemu_namespace.c: QEMU domain namespace helpers
 *
 * Copyright (C) 2006-2020 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <config.h>

#ifdef __linux__
# include <sys/sysmacros.h>
#endif
#if defined(HAVE_SYS_MOUNT_H)
# include <sys/mount.h>
#endif
#ifdef WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "qemu_namespace.h"
#include "qemu_domain.h"
#include "qemu_cgroup.h"
#include "qemu_security.h"
#include "qemu_hostdev.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virdevmapper.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_domain");


VIR_ENUM_IMPL(qemuDomainNamespace,
              QEMU_DOMAIN_NS_LAST,
              "mount",
);


/**
 * qemuDomainGetPreservedMountPath:
 * @cfg: driver configuration data
 * @vm: domain object
 * @mountpoint: mount point path to convert
 *
 * For given @mountpoint return new path where the mount point
 * should be moved temporarily whilst building the namespace.
 *
 * Returns: allocated string on success which the caller must free,
 *          NULL on failure.
 */
static char *
qemuDomainGetPreservedMountPath(virQEMUDriverConfigPtr cfg,
                                virDomainObjPtr vm,
                                const char *mountpoint)
{
    char *path = NULL;
    char *tmp;
    const char *suffix = mountpoint + strlen(QEMU_DEVPREFIX);
    g_autofree char *domname = virDomainDefGetShortName(vm->def);
    size_t off;

    if (!domname)
        return NULL;

    if (STREQ(mountpoint, "/dev"))
        suffix = "dev";

    path = g_strdup_printf("%s/%s.%s", cfg->stateDir, domname, suffix);

    /* Now consider that @mountpoint is "/dev/blah/blah2".
     * @suffix then points to "blah/blah2". However, caller
     * expects all the @paths to be the same depth. The
     * caller doesn't always do `mkdir -p` but sometimes bare
     * `touch`. Therefore fix all the suffixes. */
    off = strlen(path) - strlen(suffix);

    tmp = path + off;
    while (*tmp) {
        if (*tmp == '/')
            *tmp = '.';
        tmp++;
    }

    return path;
}


/**
 * qemuDomainGetPreservedMounts:
 *
 * Process list of mounted filesystems and:
 * a) save all FSs mounted under /dev to @devPath
 * b) generate backup path for all the entries in a)
 *
 * Any of the return pointers can be NULL.
 *
 * Returns 0 on success, -1 otherwise (with error reported)
 */
static int
qemuDomainGetPreservedMounts(virQEMUDriverConfigPtr cfg,
                             virDomainObjPtr vm,
                             char ***devPath,
                             char ***devSavePath,
                             size_t *ndevPath)
{
    char **paths = NULL, **mounts = NULL;
    size_t i, j, nmounts;

    if (virFileGetMountSubtree(QEMU_PROC_MOUNTS, "/dev",
                               &mounts, &nmounts) < 0)
        goto error;

    if (!nmounts) {
        if (ndevPath)
            *ndevPath = 0;
        return 0;
    }

    /* There can be nested mount points. For instance
     * /dev/shm/blah can be a mount point and /dev/shm too. It
     * doesn't make much sense to return the former path because
     * caller preserves the latter (and with that the former
     * too). Therefore prune nested mount points.
     * NB mounts[0] is "/dev". Should we start the outer loop
     * from the beginning of the array all we'd be left with is
     * just the first element. Think about it.
     */
    for (i = 1; i < nmounts; i++) {
        j = i + 1;
        while (j < nmounts) {
            char *c = STRSKIP(mounts[j], mounts[i]);

            if (c && (*c == '/' || *c == '\0')) {
                VIR_DEBUG("Dropping path %s because of %s", mounts[j], mounts[i]);
                VIR_DELETE_ELEMENT(mounts, j, nmounts);
            } else {
                j++;
            }
        }
    }

    if (VIR_ALLOC_N(paths, nmounts) < 0)
        goto error;

    for (i = 0; i < nmounts; i++) {
        if (!(paths[i] = qemuDomainGetPreservedMountPath(cfg, vm, mounts[i])))
            goto error;
    }

    if (devPath)
        *devPath = mounts;
    else
        virStringListFreeCount(mounts, nmounts);

    if (devSavePath)
        *devSavePath = paths;
    else
        virStringListFreeCount(paths, nmounts);

    if (ndevPath)
        *ndevPath = nmounts;

    return 0;

 error:
    virStringListFreeCount(mounts, nmounts);
    virStringListFreeCount(paths, nmounts);
    return -1;
}


struct qemuDomainCreateDeviceData {
    const char *path;     /* Path to temp new /dev location */
    char * const *devMountsPath;
    size_t ndevMountsPath;
};


static int
qemuDomainCreateDeviceRecursive(const char *device,
                                const struct qemuDomainCreateDeviceData *data,
                                bool allow_noent,
                                unsigned int ttl)
{
    g_autofree char *devicePath = NULL;
    g_autofree char *target = NULL;
    GStatBuf sb;
    int ret = -1;
    bool isLink = false;
    bool isDev = false;
    bool isReg = false;
    bool isDir = false;
    bool create = false;
#ifdef WITH_SELINUX
    char *tcon = NULL;
#endif

    if (!ttl) {
        virReportSystemError(ELOOP,
                             _("Too many levels of symbolic links: %s"),
                             device);
        return ret;
    }

    if (g_lstat(device, &sb) < 0) {
        if (errno == ENOENT && allow_noent) {
            /* Ignore non-existent device. */
            return 0;
        }
        virReportSystemError(errno, _("Unable to stat %s"), device);
        return ret;
    }

    isLink = S_ISLNK(sb.st_mode);
    isDev = S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode);
    isReg = S_ISREG(sb.st_mode) || S_ISFIFO(sb.st_mode) || S_ISSOCK(sb.st_mode);
    isDir = S_ISDIR(sb.st_mode);

    /* Here, @device might be whatever path in the system. We
     * should create the path in the namespace iff it's "/dev"
     * prefixed. However, if it is a symlink, we need to traverse
     * it too (it might point to something in "/dev"). Just
     * consider:
     *
     *   /var/sym1 -> /var/sym2 -> /dev/sda  (because users can)
     *
     * This means, "/var/sym1" is not created (it's shared with
     * the parent namespace), nor "/var/sym2", but "/dev/sda".
     *
     * TODO Remove all `.' and `..' from the @device path.
     * Otherwise we might get fooled with `/dev/../var/my_image'.
     * For now, lets hope callers play nice.
     */
    if (STRPREFIX(device, QEMU_DEVPREFIX)) {
        size_t i;

        for (i = 0; i < data->ndevMountsPath; i++) {
            if (STREQ(data->devMountsPath[i], "/dev"))
                continue;
            if (STRPREFIX(device, data->devMountsPath[i]))
                break;
        }

        if (i == data->ndevMountsPath) {
            /* Okay, @device is in /dev but not in any mount point under /dev.
             * Create it. */
            devicePath = g_strdup_printf("%s/%s", data->path,
                                         device + strlen(QEMU_DEVPREFIX));

            if (virFileMakeParentPath(devicePath) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create %s"),
                                     devicePath);
                goto cleanup;
            }
            VIR_DEBUG("Creating dev %s", device);
            create = true;
        } else {
            VIR_DEBUG("Skipping dev %s because of %s mount point",
                      device, data->devMountsPath[i]);
        }
    }

    if (isLink) {
        g_autoptr(GError) gerr = NULL;

        /* We are dealing with a symlink. Create a dangling symlink and descend
         * down one level which hopefully creates the symlink's target. */
        if (!(target = g_file_read_link(device, &gerr))) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to resolve symlink %s: %s"), device, gerr->message);
            goto cleanup;
        }

        if (create &&
            symlink(target, devicePath) < 0) {
            if (errno == EEXIST) {
                ret = 0;
            } else {
                virReportSystemError(errno,
                                     _("unable to create symlink %s"),
                                     devicePath);
            }
            goto cleanup;
        }

        /* Tricky part. If the target starts with a slash then we need to take
         * it as it is. Otherwise we need to replace the last component in the
         * original path with the link target:
         * /dev/rtc -> rtc0 (want /dev/rtc0)
         * /dev/disk/by-id/ata-SanDisk_SDSSDXPS480G_161101402485 -> ../../sda
         *   (want /dev/disk/by-id/../../sda)
         * /dev/stdout -> /proc/self/fd/1 (no change needed)
         */
        if (!g_path_is_absolute(target)) {
            g_autofree char *devTmp = g_strdup(device);
            char *c = NULL, *tmp = NULL;

            if ((c = strrchr(devTmp, '/')))
                *(c + 1) = '\0';

            tmp = g_strdup_printf("%s%s", devTmp, target);
            VIR_FREE(target);
            target = g_steal_pointer(&tmp);
        }

        if (qemuDomainCreateDeviceRecursive(target, data,
                                            allow_noent, ttl - 1) < 0)
            goto cleanup;
    } else if (isDev) {
        if (create) {
            unlink(devicePath);
            if (mknod(devicePath, sb.st_mode, sb.st_rdev) < 0) {
                virReportSystemError(errno,
                                     _("Failed to make device %s"),
                                     devicePath);
                goto cleanup;
            }
        }
    } else if (isReg) {
        if (create &&
            virFileTouch(devicePath, sb.st_mode) < 0)
            goto cleanup;
        /* Just create the file here so that code below sets
         * proper owner and mode. Bind mount only after that. */
    } else if (isDir) {
        if (create &&
            virFileMakePathWithMode(devicePath, sb.st_mode) < 0) {
            virReportSystemError(errno,
                                 _("Unable to make dir %s"),
                                 devicePath);
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unsupported device type %s 0%o"),
                       device, sb.st_mode);
        goto cleanup;
    }

    if (!create) {
        ret = 0;
        goto cleanup;
    }

    if (lchown(devicePath, sb.st_uid, sb.st_gid) < 0) {
        virReportSystemError(errno,
                             _("Failed to chown device %s"),
                             devicePath);
        goto cleanup;
    }

    /* Symlinks don't have mode */
    if (!isLink &&
        chmod(devicePath, sb.st_mode) < 0) {
        virReportSystemError(errno,
                             _("Failed to set permissions for device %s"),
                             devicePath);
        goto cleanup;
    }

    /* Symlinks don't have ACLs. */
    if (!isLink &&
        virFileCopyACLs(device, devicePath) < 0 &&
        errno != ENOTSUP) {
        virReportSystemError(errno,
                             _("Failed to copy ACLs on device %s"),
                             devicePath);
        goto cleanup;
    }

#ifdef WITH_SELINUX
    if (lgetfilecon_raw(device, &tcon) < 0 &&
        (errno != ENOTSUP && errno != ENODATA)) {
        virReportSystemError(errno,
                             _("Unable to get SELinux label from %s"),
                             device);
        goto cleanup;
    }

    if (tcon &&
        lsetfilecon_raw(devicePath, (const char *)tcon) < 0) {
        VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
        if (errno != EOPNOTSUPP && errno != ENOTSUP) {
        VIR_WARNINGS_RESET
            virReportSystemError(errno,
                                 _("Unable to set SELinux label on %s"),
                                 devicePath);
            goto cleanup;
        }
    }
#endif

    /* Finish mount process started earlier. */
    if ((isReg || isDir) &&
        virFileBindMountDevice(device, devicePath) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
#ifdef WITH_SELINUX
    freecon(tcon);
#endif
    return ret;
}


static int
qemuDomainCreateDevice(const char *device,
                       const struct qemuDomainCreateDeviceData *data,
                       bool allow_noent)
{
    long symloop_max = sysconf(_SC_SYMLOOP_MAX);

    return qemuDomainCreateDeviceRecursive(device, data,
                                           allow_noent, symloop_max);
}


static int
qemuDomainPopulateDevices(virQEMUDriverConfigPtr cfg,
                          virDomainObjPtr vm G_GNUC_UNUSED,
                          const struct qemuDomainCreateDeviceData *data)
{
    const char *const *devices = (const char *const *) cfg->cgroupDeviceACL;
    size_t i;

    if (!devices)
        devices = defaultDeviceACL;

    for (i = 0; devices[i]; i++) {
        if (qemuDomainCreateDevice(devices[i], data, true) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainSetupDev(virQEMUDriverConfigPtr cfg,
                   virSecurityManagerPtr mgr,
                   virDomainObjPtr vm,
                   const struct qemuDomainCreateDeviceData *data)
{
    g_autofree char *mount_options = NULL;
    g_autofree char *opts = NULL;

    VIR_DEBUG("Setting up /dev/ for domain %s", vm->def->name);

    mount_options = qemuSecurityGetMountOptions(mgr, vm->def);

    if (!mount_options)
        mount_options = g_strdup("");

    /*
     * tmpfs is limited to 64kb, since we only have device nodes in there
     * and don't want to DOS the entire OS RAM usage
     */
    opts = g_strdup_printf("mode=755,size=65536%s", mount_options);

    if (virFileSetupDev(data->path, opts) < 0)
        return -1;

    if (qemuDomainPopulateDevices(cfg, vm, data) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupDisk(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                    virDomainDiskDefPtr disk,
                    const struct qemuDomainCreateDeviceData *data)
{
    virStorageSourcePtr next;
    bool hasNVMe = false;

    for (next = disk->src; virStorageSourceIsBacking(next); next = next->backingStore) {
        VIR_AUTOSTRINGLIST targetPaths = NULL;
        size_t i;

        if (next->type == VIR_STORAGE_TYPE_NVME) {
            g_autofree char *nvmePath = NULL;

            hasNVMe = true;

            if (!(nvmePath = virPCIDeviceAddressGetIOMMUGroupDev(&next->nvme->pciAddr)))
                return -1;

            if (qemuDomainCreateDevice(nvmePath, data, false) < 0)
                return -1;
        } else {
            if (!next->path || !virStorageSourceIsLocalStorage(next)) {
                /* Not creating device. Just continue. */
                continue;
            }

            if (qemuDomainCreateDevice(next->path, data, false) < 0)
                return -1;

            if (virDevMapperGetTargets(next->path, &targetPaths) < 0 &&
                errno != ENOSYS) {
                virReportSystemError(errno,
                                     _("Unable to get devmapper targets for %s"),
                                     next->path);
                return -1;
            }

            for (i = 0; targetPaths && targetPaths[i]; i++) {
                if (qemuDomainCreateDevice(targetPaths[i], data, false) < 0)
                    return -1;
            }
        }
    }

    /* qemu-pr-helper might require access to /dev/mapper/control. */
    if (disk->src->pr &&
        qemuDomainCreateDevice(QEMU_DEVICE_MAPPER_CONTROL_PATH, data, true) < 0)
        return -1;

    if (hasNVMe &&
        qemuDomainCreateDevice(QEMU_DEV_VFIO, data, false) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllDisks(virQEMUDriverConfigPtr cfg,
                        virDomainObjPtr vm,
                        const struct qemuDomainCreateDeviceData *data)
{
    size_t i;
    VIR_DEBUG("Setting up disks");

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuDomainSetupDisk(cfg,
                                vm->def->disks[i],
                                data) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all disks");
    return 0;
}


static int
qemuDomainSetupHostdev(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                       virDomainHostdevDefPtr dev,
                       const struct qemuDomainCreateDeviceData *data)
{
    g_autofree char *path = NULL;

    if (qemuDomainGetHostdevPath(dev, &path, NULL) < 0)
        return -1;

    if (path && qemuDomainCreateDevice(path, data, false) < 0)
        return -1;

    if (qemuHostdevNeedsVFIO(dev) &&
        qemuDomainCreateDevice(QEMU_DEV_VFIO, data, false) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllHostdevs(virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up hostdevs");
    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (qemuDomainSetupHostdev(cfg,
                                   vm->def->hostdevs[i],
                                   data) < 0)
            return -1;
    }
    VIR_DEBUG("Setup all hostdevs");
    return 0;
}


static int
qemuDomainSetupMemory(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                      virDomainMemoryDefPtr mem,
                      const struct qemuDomainCreateDeviceData *data)
{
    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    return qemuDomainCreateDevice(mem->nvdimmPath, data, false);
}


static int
qemuDomainSetupAllMemories(virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up memories");
    for (i = 0; i < vm->def->nmems; i++) {
        if (qemuDomainSetupMemory(cfg,
                                  vm->def->mems[i],
                                  data) < 0)
            return -1;
    }
    VIR_DEBUG("Setup all memories");
    return 0;
}


static int
qemuDomainSetupChardev(virDomainDefPtr def G_GNUC_UNUSED,
                       virDomainChrDefPtr dev,
                       void *opaque)
{
    const struct qemuDomainCreateDeviceData *data = opaque;
    const char *path = NULL;

    if (!(path = virDomainChrSourceDefGetPath(dev->source)))
        return 0;

    /* Socket created by qemu. It doesn't exist upfront. */
    if (dev->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        dev->source->data.nix.listen)
        return 0;

    return qemuDomainCreateDevice(path, data, true);
}


static int
qemuDomainSetupAllChardevs(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                           virDomainObjPtr vm,
                           const struct qemuDomainCreateDeviceData *data)
{
    VIR_DEBUG("Setting up chardevs");

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuDomainSetupChardev,
                               (void *)data) < 0)
        return -1;

    VIR_DEBUG("Setup all chardevs");
    return 0;
}


static int
qemuDomainSetupTPM(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                   virDomainTPMDefPtr dev,
                   const struct qemuDomainCreateDeviceData *data)
{
    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        if (qemuDomainCreateDevice(dev->data.passthrough.source.data.file.path,
                                   data, false) < 0)
            return -1;
        break;

    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        /* nada */
        break;
    }

    return 0;
}


static int
qemuDomainSetupAllTPMs(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                       virDomainObjPtr vm,
                       const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up TPMs");

    for (i = 0; i < vm->def->ntpms; i++) {
        if (qemuDomainSetupTPM(cfg, vm->def->tpms[i], data) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all TPMs");
    return 0;
}


static int
qemuDomainSetupGraphics(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                        virDomainGraphicsDefPtr gfx,
                        const struct qemuDomainCreateDeviceData *data)
{
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);

    if (!rendernode)
        return 0;

    return qemuDomainCreateDevice(rendernode, data, false);
}


static int
qemuDomainSetupAllGraphics(virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up graphics");
    for (i = 0; i < vm->def->ngraphics; i++) {
        if (qemuDomainSetupGraphics(cfg,
                                    vm->def->graphics[i],
                                    data) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all graphics");
    return 0;
}


static int
qemuDomainSetupInput(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                     virDomainInputDefPtr input,
                     const struct qemuDomainCreateDeviceData *data)
{
    const char *path = virDomainInputDefGetPath(input);

    if (path && qemuDomainCreateDevice(path, data, false) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllInputs(virQEMUDriverConfigPtr cfg,
                         virDomainObjPtr vm,
                         const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up inputs");
    for (i = 0; i < vm->def->ninputs; i++) {
        if (qemuDomainSetupInput(cfg,
                                 vm->def->inputs[i],
                                 data) < 0)
            return -1;
    }
    VIR_DEBUG("Setup all inputs");
    return 0;
}


static int
qemuDomainSetupRNG(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                   virDomainRNGDefPtr rng,
                   const struct qemuDomainCreateDeviceData *data)
{
    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (qemuDomainCreateDevice(rng->source.file, data, false) < 0)
            return -1;
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        /* nada */
        break;
    }

    return 0;
}


static int
qemuDomainSetupAllRNGs(virQEMUDriverConfigPtr cfg,
                       virDomainObjPtr vm,
                       const struct qemuDomainCreateDeviceData *data)
{
    size_t i;

    VIR_DEBUG("Setting up RNGs");
    for (i = 0; i < vm->def->nrngs; i++) {
        if (qemuDomainSetupRNG(cfg,
                               vm->def->rngs[i],
                               data) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all RNGs");
    return 0;
}


static int
qemuDomainSetupLoader(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                      virDomainObjPtr vm,
                      const struct qemuDomainCreateDeviceData *data)
{
    virDomainLoaderDefPtr loader = vm->def->os.loader;

    VIR_DEBUG("Setting up loader");

    if (loader) {
        switch ((virDomainLoader) loader->type) {
        case VIR_DOMAIN_LOADER_TYPE_ROM:
            if (qemuDomainCreateDevice(loader->path, data, false) < 0)
                return -1;
            break;

        case VIR_DOMAIN_LOADER_TYPE_PFLASH:
            if (qemuDomainCreateDevice(loader->path, data, false) < 0)
                return -1;

            if (loader->nvram &&
                qemuDomainCreateDevice(loader->nvram, data, false) < 0)
                return -1;
            break;

        case VIR_DOMAIN_LOADER_TYPE_NONE:
        case VIR_DOMAIN_LOADER_TYPE_LAST:
            break;
        }
    }

    VIR_DEBUG("Setup loader");
    return 0;
}


static int
qemuDomainSetupLaunchSecurity(virQEMUDriverConfigPtr cfg G_GNUC_UNUSED,
                              virDomainObjPtr vm,
                              const struct qemuDomainCreateDeviceData *data)
{
    virDomainSEVDefPtr sev = vm->def->sev;

    if (!sev || sev->sectype != VIR_DOMAIN_LAUNCH_SECURITY_SEV)
        return 0;

    VIR_DEBUG("Setting up launch security");

    if (qemuDomainCreateDevice(QEMU_DEV_SEV, data, false) < 0)
        return -1;

    VIR_DEBUG("Set up launch security");
    return 0;
}


int
qemuDomainBuildNamespace(virQEMUDriverConfigPtr cfg,
                         virSecurityManagerPtr mgr,
                         virDomainObjPtr vm)
{
    struct qemuDomainCreateDeviceData data;
    const char *devPath = NULL;
    char **devMountsPath = NULL, **devMountsSavePath = NULL;
    size_t ndevMountsPath = 0, i;
    int ret = -1;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        ret = 0;
        goto cleanup;
    }

    if (qemuDomainGetPreservedMounts(cfg, vm,
                                     &devMountsPath, &devMountsSavePath,
                                     &ndevMountsPath) < 0)
        goto cleanup;

    for (i = 0; i < ndevMountsPath; i++) {
        if (STREQ(devMountsPath[i], "/dev")) {
            devPath = devMountsSavePath[i];
            break;
        }
    }

    if (!devPath) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find any /dev mount"));
        goto cleanup;
    }

    data.path = devPath;
    data.devMountsPath = devMountsPath;
    data.ndevMountsPath = ndevMountsPath;

    if (virProcessSetupPrivateMountNS() < 0)
        goto cleanup;

    if (qemuDomainSetupDev(cfg, mgr, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllDisks(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllHostdevs(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllMemories(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllChardevs(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllTPMs(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllGraphics(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllInputs(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupAllRNGs(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupLoader(cfg, vm, &data) < 0)
        goto cleanup;

    if (qemuDomainSetupLaunchSecurity(cfg, vm, &data) < 0)
        goto cleanup;

    /* Save some mount points because we want to share them with the host */
    for (i = 0; i < ndevMountsPath; i++) {
        struct stat sb;

        if (devMountsSavePath[i] == devPath)
            continue;

        if (stat(devMountsPath[i], &sb) < 0) {
            virReportSystemError(errno,
                                 _("Unable to stat: %s"),
                                 devMountsPath[i]);
            goto cleanup;
        }

        /* At this point, devMountsPath is either:
         * a file (regular or special), or
         * a directory. */
        if ((S_ISDIR(sb.st_mode) && virFileMakePath(devMountsSavePath[i]) < 0) ||
            (!S_ISDIR(sb.st_mode) && virFileTouch(devMountsSavePath[i], sb.st_mode) < 0)) {
            virReportSystemError(errno,
                                 _("Failed to create %s"),
                                 devMountsSavePath[i]);
            goto cleanup;
        }

        if (virFileMoveMount(devMountsPath[i], devMountsSavePath[i]) < 0)
            goto cleanup;
    }

    if (virFileMoveMount(devPath, "/dev") < 0)
        goto cleanup;

    for (i = 0; i < ndevMountsPath; i++) {
        struct stat sb;

        if (devMountsSavePath[i] == devPath)
            continue;

        if (stat(devMountsSavePath[i], &sb) < 0) {
            virReportSystemError(errno,
                                 _("Unable to stat: %s"),
                                 devMountsSavePath[i]);
            goto cleanup;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (virFileMakePath(devMountsPath[i]) < 0) {
                virReportSystemError(errno, _("Cannot create %s"),
                                     devMountsPath[i]);
                goto cleanup;
            }
        } else {
            if (virFileMakeParentPath(devMountsPath[i]) < 0 ||
                virFileTouch(devMountsPath[i], sb.st_mode) < 0) {
                virReportSystemError(errno, _("Cannot create %s"),
                                     devMountsPath[i]);
                goto cleanup;
            }
        }

        if (virFileMoveMount(devMountsSavePath[i], devMountsPath[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < ndevMountsPath; i++) {
#if defined(__linux__)
        umount(devMountsSavePath[i]);
#endif /* defined(__linux__) */
        /* The path can be either a regular file or a dir. */
        if (virFileIsDir(devMountsSavePath[i]))
            virFileDeleteTree(devMountsSavePath[i]);
        else
            unlink(devMountsSavePath[i]);
    }
    virStringListFreeCount(devMountsPath, ndevMountsPath);
    virStringListFreeCount(devMountsSavePath, ndevMountsPath);
    return ret;
}


bool
qemuDomainNamespaceEnabled(virDomainObjPtr vm,
                           qemuDomainNamespace ns)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    return priv->namespaces &&
        virBitmapIsBitSet(priv->namespaces, ns);
}


int
qemuDomainEnableNamespace(virDomainObjPtr vm,
                          qemuDomainNamespace ns)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->namespaces &&
        !(priv->namespaces = virBitmapNew(QEMU_DOMAIN_NS_LAST)))
        return -1;

    if (virBitmapSetBit(priv->namespaces, ns) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to enable namespace: %s"),
                       qemuDomainNamespaceTypeToString(ns));
        return -1;
    }

    return 0;
}


static void
qemuDomainDisableNamespace(virDomainObjPtr vm,
                           qemuDomainNamespace ns)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->namespaces) {
        ignore_value(virBitmapClearBit(priv->namespaces, ns));
        if (virBitmapIsAllClear(priv->namespaces)) {
            virBitmapFree(priv->namespaces);
            priv->namespaces = NULL;
        }
    }
}


void
qemuDomainDestroyNamespace(virQEMUDriverPtr driver G_GNUC_UNUSED,
                           virDomainObjPtr vm)
{
    if (qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        qemuDomainDisableNamespace(vm, QEMU_DOMAIN_NS_MOUNT);
}


bool
qemuDomainNamespaceAvailable(qemuDomainNamespace ns G_GNUC_UNUSED)
{
#if !defined(__linux__)
    /* Namespaces are Linux specific. */
    return false;

#else /* defined(__linux__) */

    switch (ns) {
    case QEMU_DOMAIN_NS_MOUNT:
# if !defined(HAVE_SYS_ACL_H) || !defined(WITH_SELINUX)
        /* We can't create the exact copy of paths if either of
         * these is not available. */
        return false;
# else
        if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_MNT) < 0)
            return false;
# endif
        break;
    case QEMU_DOMAIN_NS_LAST:
        break;
    }

    return true;
#endif /* defined(__linux__) */
}


struct qemuDomainAttachDeviceMknodData {
    virQEMUDriverPtr driver;
    virDomainObjPtr vm;
    const char *file;
    const char *target;
    GStatBuf sb;
    void *acl;
#ifdef WITH_SELINUX
    char *tcon;
#endif
};


/* Our way of creating devices is highly linux specific */
#if defined(__linux__)
static int
qemuDomainAttachDeviceMknodHelper(pid_t pid G_GNUC_UNUSED,
                                  void *opaque)
{
    struct qemuDomainAttachDeviceMknodData *data = opaque;
    int ret = -1;
    bool delDevice = false;
    bool isLink = S_ISLNK(data->sb.st_mode);
    bool isDev = S_ISCHR(data->sb.st_mode) || S_ISBLK(data->sb.st_mode);
    bool isReg = S_ISREG(data->sb.st_mode) || S_ISFIFO(data->sb.st_mode) || S_ISSOCK(data->sb.st_mode);
    bool isDir = S_ISDIR(data->sb.st_mode);

    qemuSecurityPostFork(data->driver->securityManager);

    if (virFileMakeParentPath(data->file) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %s"), data->file);
        goto cleanup;
    }

    if (isLink) {
        VIR_DEBUG("Creating symlink %s -> %s", data->file, data->target);

        /* First, unlink the symlink target. Symlinks change and
         * therefore we have no guarantees that pre-existing
         * symlink is still valid. */
        if (unlink(data->file) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove symlink %s"),
                                 data->file);
            goto cleanup;
        }

        if (symlink(data->target, data->file) < 0) {
            virReportSystemError(errno,
                                 _("Unable to create symlink %s (pointing to %s)"),
                                 data->file, data->target);
            goto cleanup;
        } else {
            delDevice = true;
        }
    } else if (isDev) {
        VIR_DEBUG("Creating dev %s (%d,%d)",
                  data->file, major(data->sb.st_rdev), minor(data->sb.st_rdev));
        unlink(data->file);
        if (mknod(data->file, data->sb.st_mode, data->sb.st_rdev) < 0) {
            virReportSystemError(errno,
                                 _("Unable to create device %s"),
                                 data->file);
            goto cleanup;
        } else {
            delDevice = true;
        }
    } else if (isReg || isDir) {
        /* We are not cleaning up disks on virDomainDetachDevice
         * because disk might be still in use by different disk
         * as its backing chain. This might however clash here.
         * Therefore do the cleanup here. */
        if (umount(data->file) < 0 &&
            errno != ENOENT && errno != EINVAL) {
            virReportSystemError(errno,
                                 _("Unable to umount %s"),
                                 data->file);
            goto cleanup;
        }
        if ((isReg && virFileTouch(data->file, data->sb.st_mode) < 0) ||
            (isDir && virFileMakePathWithMode(data->file, data->sb.st_mode) < 0))
            goto cleanup;
        delDevice = true;
        /* Just create the file here so that code below sets
         * proper owner and mode. Move the mount only after that. */
    } else {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unsupported device type %s 0%o"),
                       data->file, data->sb.st_mode);
        goto cleanup;
    }

    if (lchown(data->file, data->sb.st_uid, data->sb.st_gid) < 0) {
        virReportSystemError(errno,
                             _("Failed to chown device %s"),
                             data->file);
        goto cleanup;
    }

    /* Symlinks don't have mode */
    if (!isLink &&
        chmod(data->file, data->sb.st_mode) < 0) {
        virReportSystemError(errno,
                             _("Failed to set permissions for device %s"),
                             data->file);
        goto cleanup;
    }

    /* Symlinks don't have ACLs. */
    if (!isLink &&
        virFileSetACLs(data->file, data->acl) < 0 &&
        errno != ENOTSUP) {
        virReportSystemError(errno,
                             _("Unable to set ACLs on %s"), data->file);
        goto cleanup;
    }

# ifdef WITH_SELINUX
    if (data->tcon &&
        lsetfilecon_raw(data->file, (const char *)data->tcon) < 0) {
        VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
        if (errno != EOPNOTSUPP && errno != ENOTSUP) {
        VIR_WARNINGS_RESET
            virReportSystemError(errno,
                                 _("Unable to set SELinux label on %s"),
                                 data->file);
            goto cleanup;
        }
    }
# endif

    /* Finish mount process started earlier. */
    if ((isReg || isDir) &&
        virFileMoveMount(data->target, data->file) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0 && delDevice) {
        if (isDir)
            virFileDeleteTree(data->file);
        else
            unlink(data->file);
    }
# ifdef WITH_SELINUX
    freecon(data->tcon);
# endif
    virFileFreeACLs(&data->acl);
    return ret;
}


static int
qemuDomainAttachDeviceMknodRecursive(virQEMUDriverPtr driver,
                                     virDomainObjPtr vm,
                                     const char *file,
                                     char * const *devMountsPath,
                                     size_t ndevMountsPath,
                                     unsigned int ttl)
{
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    struct qemuDomainAttachDeviceMknodData data;
    int ret = -1;
    g_autofree char *target = NULL;
    bool isLink;
    bool isReg;
    bool isDir;

    if (!ttl) {
        virReportSystemError(ELOOP,
                             _("Too many levels of symbolic links: %s"),
                             file);
        return ret;
    }

    memset(&data, 0, sizeof(data));

    data.driver = driver;
    data.vm = vm;
    data.file = file;

    if (g_lstat(file, &data.sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), file);
        return ret;
    }

    isLink = S_ISLNK(data.sb.st_mode);
    isReg = S_ISREG(data.sb.st_mode) || S_ISFIFO(data.sb.st_mode) || S_ISSOCK(data.sb.st_mode);
    isDir = S_ISDIR(data.sb.st_mode);

    if ((isReg || isDir) && STRPREFIX(file, QEMU_DEVPREFIX)) {
        cfg = virQEMUDriverGetConfig(driver);
        if (!(target = qemuDomainGetPreservedMountPath(cfg, vm, file)))
            goto cleanup;

        if (virFileBindMountDevice(file, target) < 0)
            goto cleanup;

        data.target = target;
    } else if (isLink) {
        g_autoptr(GError) gerr = NULL;

        if (!(target = g_file_read_link(file, &gerr))) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to resolve symlink %s: %s"), file, gerr->message);
            return ret;
        }

        if (!g_path_is_absolute(target)) {
            g_autofree char *fileTmp = g_strdup(file);
            char *c = NULL, *tmp = NULL;

            if ((c = strrchr(fileTmp, '/')))
                *(c + 1) = '\0';

            tmp = g_strdup_printf("%s%s", fileTmp, target);
            VIR_FREE(target);
            target = g_steal_pointer(&tmp);
        }

        data.target = target;
    }

    /* Symlinks don't have ACLs. */
    if (!isLink &&
        virFileGetACLs(file, &data.acl) < 0 &&
        errno != ENOTSUP) {
        virReportSystemError(errno,
                             _("Unable to get ACLs on %s"), file);
        goto cleanup;
    }

# ifdef WITH_SELINUX
    if (lgetfilecon_raw(file, &data.tcon) < 0 &&
        (errno != ENOTSUP && errno != ENODATA)) {
        virReportSystemError(errno,
                             _("Unable to get SELinux label from %s"), file);
        goto cleanup;
    }
# endif

    if (STRPREFIX(file, QEMU_DEVPREFIX)) {
        size_t i;

        for (i = 0; i < ndevMountsPath; i++) {
            if (STREQ(devMountsPath[i], "/dev"))
                continue;
            if (STRPREFIX(file, devMountsPath[i]))
                break;
        }

        if (i == ndevMountsPath) {
            if (qemuSecurityPreFork(driver->securityManager) < 0)
                goto cleanup;

            if (virProcessRunInMountNamespace(vm->pid,
                                              qemuDomainAttachDeviceMknodHelper,
                                              &data) < 0) {
                qemuSecurityPostFork(driver->securityManager);
                goto cleanup;
            }
            qemuSecurityPostFork(driver->securityManager);
        } else {
            VIR_DEBUG("Skipping dev %s because of %s mount point",
                      file, devMountsPath[i]);
        }
    }

    if (isLink &&
        qemuDomainAttachDeviceMknodRecursive(driver, vm, target,
                                             devMountsPath, ndevMountsPath,
                                             ttl -1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
# ifdef WITH_SELINUX
    freecon(data.tcon);
# endif
    virFileFreeACLs(&data.acl);
    if (isReg && target)
        umount(target);
    return ret;
}


#else /* !defined(__linux__) */


static int
qemuDomainAttachDeviceMknodRecursive(virQEMUDriverPtr driver G_GNUC_UNUSED,
                                     virDomainObjPtr vm G_GNUC_UNUSED,
                                     const char *file G_GNUC_UNUSED,
                                     char * const *devMountsPath G_GNUC_UNUSED,
                                     size_t ndevMountsPath G_GNUC_UNUSED,
                                     unsigned int ttl G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform."));
    return -1;
}


#endif /* !defined(__linux__) */


static int
qemuDomainAttachDeviceMknod(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *file,
                            char * const *devMountsPath,
                            size_t ndevMountsPath)
{
    long symloop_max = sysconf(_SC_SYMLOOP_MAX);

    return qemuDomainAttachDeviceMknodRecursive(driver, vm, file,
                                                devMountsPath, ndevMountsPath,
                                                symloop_max);
}


static int
qemuDomainDetachDeviceUnlinkHelper(pid_t pid G_GNUC_UNUSED,
                                   void *opaque)
{
    const char *path = opaque;

    VIR_DEBUG("Unlinking %s", path);
    if (unlink(path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove device %s"), path);
        return -1;
    }

    return 0;
}


static int
qemuDomainDetachDeviceUnlink(virQEMUDriverPtr driver G_GNUC_UNUSED,
                             virDomainObjPtr vm,
                             const char *file,
                             char * const *devMountsPath,
                             size_t ndevMountsPath)
{
    size_t i;

    if (STRPREFIX(file, QEMU_DEVPREFIX)) {
        for (i = 0; i < ndevMountsPath; i++) {
            if (STREQ(devMountsPath[i], "/dev"))
                continue;
            if (STRPREFIX(file, devMountsPath[i]))
                break;
        }

        if (i == ndevMountsPath) {
            if (virProcessRunInMountNamespace(vm->pid,
                                              qemuDomainDetachDeviceUnlinkHelper,
                                              (void *)file) < 0)
                return -1;
        }
    }

    return 0;
}


static int
qemuDomainNamespaceMknodPaths(virDomainObjPtr vm,
                              const char **paths,
                              size_t npaths)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    char **devMountsPath = NULL;
    size_t ndevMountsPath = 0;
    int ret = -1;
    size_t i;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) ||
        !npaths)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);
    if (qemuDomainGetPreservedMounts(cfg, vm,
                                     &devMountsPath, NULL,
                                     &ndevMountsPath) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        if (qemuDomainAttachDeviceMknod(driver,
                                        vm,
                                        paths[i],
                                        devMountsPath, ndevMountsPath) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFreeCount(devMountsPath, ndevMountsPath);
    return ret;
}


static int
qemuDomainNamespaceMknodPath(virDomainObjPtr vm,
                             const char *path)
{
    const char *paths[] = { path };

    return qemuDomainNamespaceMknodPaths(vm, paths, 1);
}


static int
qemuDomainNamespaceUnlinkPaths(virDomainObjPtr vm,
                               const char **paths,
                               size_t npaths)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    char **devMountsPath = NULL;
    size_t ndevMountsPath = 0;
    size_t i;
    int ret = -1;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT) ||
        !npaths)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainGetPreservedMounts(cfg, vm,
                                     &devMountsPath, NULL,
                                     &ndevMountsPath) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        if (qemuDomainDetachDeviceUnlink(driver, vm, paths[i],
                                         devMountsPath, ndevMountsPath) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFreeCount(devMountsPath, ndevMountsPath);
    return ret;
}


static int
qemuDomainNamespaceUnlinkPath(virDomainObjPtr vm,
                              const char *path)
{
    const char *paths[] = { path };

    return qemuDomainNamespaceUnlinkPaths(vm, paths, 1);
}


int
qemuDomainNamespaceSetupDisk(virDomainObjPtr vm,
                             virStorageSourcePtr src)
{
    virStorageSourcePtr next;
    VIR_AUTOSTRINGLIST paths = NULL;
    size_t npaths = 0;
    bool hasNVMe = false;

    for (next = src; virStorageSourceIsBacking(next); next = next->backingStore) {
        g_autofree char *tmpPath = NULL;

        if (next->type == VIR_STORAGE_TYPE_NVME) {
            hasNVMe = true;

            if (!(tmpPath = virPCIDeviceAddressGetIOMMUGroupDev(&next->nvme->pciAddr)))
                return -1;
        } else {
            VIR_AUTOSTRINGLIST targetPaths = NULL;

            if (virStorageSourceIsEmpty(next) ||
                !virStorageSourceIsLocalStorage(next)) {
                /* Not creating device. Just continue. */
                continue;
            }

            tmpPath = g_strdup(next->path);

            if (virDevMapperGetTargets(next->path, &targetPaths) < 0 &&
                errno != ENOSYS) {
                virReportSystemError(errno,
                                     _("Unable to get devmapper targets for %s"),
                                     next->path);
                return -1;
            }

            if (virStringListMerge(&paths, &targetPaths) < 0)
                return -1;
        }

        if (virStringListAdd(&paths, tmpPath) < 0)
            return -1;
    }

    /* qemu-pr-helper might require access to /dev/mapper/control. */
    if (src->pr &&
        virStringListAdd(&paths, QEMU_DEVICE_MAPPER_CONTROL_PATH) < 0)
        return -1;

    if (hasNVMe &&
        virStringListAdd(&paths, QEMU_DEV_VFIO) < 0)
        return -1;

    npaths = virStringListLength((const char **) paths);
    if (qemuDomainNamespaceMknodPaths(vm, (const char **) paths, npaths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownDisk(virDomainObjPtr vm G_GNUC_UNUSED,
                                virStorageSourcePtr src G_GNUC_UNUSED)
{
    /* While in hotplug case we create the whole backing chain,
     * here we must limit ourselves. The disk we want to remove
     * might be a part of backing chain of another disk.
     * If you are reading these lines and have some spare time
     * you can come up with and algorithm that checks for that.
     * I don't, therefore: */
    return 0;
}


/**
 * qemuDomainNamespaceSetupHostdev:
 * @vm: domain object
 * @hostdev: hostdev to create in @vm's namespace
 *
 * For given @hostdev, create its devfs representation (if it has one) in
 * domain namespace. Note, @hostdev must not be in @vm's definition.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuDomainNamespaceSetupHostdev(virDomainObjPtr vm,
                                virDomainHostdevDefPtr hostdev)
{
    g_autofree char *path = NULL;

    if (qemuDomainGetHostdevPath(hostdev, &path, NULL) < 0)
        return -1;

    if (path && qemuDomainNamespaceMknodPath(vm, path) < 0)
        return -1;

    if (qemuHostdevNeedsVFIO(hostdev) &&
        !qemuDomainNeedsVFIO(vm->def) &&
        qemuDomainNamespaceMknodPath(vm, QEMU_DEV_VFIO) < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainNamespaceTeardownHostdev:
 * @vm: domain object
 * @hostdev: hostdev to remove in @vm's namespace
 *
 * For given @hostdev, remove its devfs representation (if it has one) in
 * domain namespace. Note, @hostdev must not be in @vm's definition.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
qemuDomainNamespaceTeardownHostdev(virDomainObjPtr vm,
                                   virDomainHostdevDefPtr hostdev)
{
    g_autofree char *path = NULL;

    if (qemuDomainGetHostdevPath(hostdev, &path, NULL) < 0)
        return -1;

    if (path && qemuDomainNamespaceUnlinkPath(vm, path) < 0)
        return -1;

    if (qemuHostdevNeedsVFIO(hostdev) &&
        !qemuDomainNeedsVFIO(vm->def) &&
        qemuDomainNamespaceUnlinkPath(vm, QEMU_DEV_VFIO) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupMemory(virDomainObjPtr vm,
                               virDomainMemoryDefPtr mem)
{
    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    if (qemuDomainNamespaceMknodPath(vm, mem->nvdimmPath) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownMemory(virDomainObjPtr vm,
                                  virDomainMemoryDefPtr mem)
{
    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    if (qemuDomainNamespaceUnlinkPath(vm, mem->nvdimmPath) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupChardev(virDomainObjPtr vm,
                                virDomainChrDefPtr chr)
{
    const char *path;

    if (!(path = virDomainChrSourceDefGetPath(chr->source)))
        return 0;

    /* Socket created by qemu. It doesn't exist upfront. */
    if (chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        chr->source->data.nix.listen)
        return 0;

    if (qemuDomainNamespaceMknodPath(vm, path) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownChardev(virDomainObjPtr vm,
                                   virDomainChrDefPtr chr)
{
    const char *path = NULL;

    if (chr->source->type != VIR_DOMAIN_CHR_TYPE_DEV)
        return 0;

    path = chr->source->data.file.path;

    if (qemuDomainNamespaceUnlinkPath(vm, path) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupRNG(virDomainObjPtr vm,
                            virDomainRNGDefPtr rng)
{
    const char *path = NULL;

    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        path = rng->source.file;
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    if (path && qemuDomainNamespaceMknodPath(vm, path) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownRNG(virDomainObjPtr vm,
                               virDomainRNGDefPtr rng)
{
    const char *path = NULL;

    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        path = rng->source.file;
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
    case VIR_DOMAIN_RNG_BACKEND_BUILTIN:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        break;
    }

    if (path && qemuDomainNamespaceUnlinkPath(vm, path) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupInput(virDomainObjPtr vm,
                              virDomainInputDefPtr input)
{
    const char *path = NULL;

    if (!(path = virDomainInputDefGetPath(input)))
        return 0;

    if (path && qemuDomainNamespaceMknodPath(vm, path) < 0)
        return -1;
    return 0;
}


int
qemuDomainNamespaceTeardownInput(virDomainObjPtr vm,
                                 virDomainInputDefPtr input)
{
    const char *path = NULL;

    if (!(path = virDomainInputDefGetPath(input)))
        return 0;

    if (path && qemuDomainNamespaceUnlinkPath(vm, path) < 0)
        return -1;

    return 0;
}
