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


static int
qemuDomainPopulateDevices(virQEMUDriverConfigPtr cfg,
                          char ***paths)
{
    const char *const *devices = (const char *const *) cfg->cgroupDeviceACL;
    size_t i;

    if (!devices)
        devices = defaultDeviceACL;

    for (i = 0; devices[i]; i++) {
        if (virStringListAdd(paths, devices[i]) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainSetupDev(virSecurityManagerPtr mgr,
                   virDomainObjPtr vm,
                   const char *path)
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

    if (virFileSetupDev(path, opts) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupDisk(virStorageSourcePtr src,
                    char ***paths)
{
    virStorageSourcePtr next;
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

            if (virStringListMerge(paths, &targetPaths) < 0)
                return -1;
        }

        if (virStringListAdd(paths, tmpPath) < 0)
            return -1;
    }

    /* qemu-pr-helper might require access to /dev/mapper/control. */
    if (src->pr &&
        virStringListAdd(paths, QEMU_DEVICE_MAPPER_CONTROL_PATH) < 0)
        return -1;

    if (hasNVMe &&
        virStringListAdd(paths, QEMU_DEV_VFIO) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllDisks(virDomainObjPtr vm,
                        char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up disks");

    for (i = 0; i < vm->def->ndisks; i++) {
        if (qemuDomainSetupDisk(vm->def->disks[i]->src,
                                paths) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all disks");
    return 0;
}


static int
qemuDomainSetupHostdev(virDomainObjPtr vm,
                       virDomainHostdevDefPtr hostdev,
                       bool hotplug,
                       char ***paths)
{
    g_autofree char *path = NULL;

    if (qemuDomainGetHostdevPath(hostdev, &path, NULL) < 0)
        return -1;

    if (path && virStringListAdd(paths, path) < 0)
        return -1;

    if (qemuHostdevNeedsVFIO(hostdev) &&
        (!hotplug || !qemuDomainNeedsVFIO(vm->def)) &&
        virStringListAdd(paths, QEMU_DEV_VFIO) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllHostdevs(virDomainObjPtr vm,
                           char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up hostdevs");
    for (i = 0; i < vm->def->nhostdevs; i++) {
        if (qemuDomainSetupHostdev(vm,
                                   vm->def->hostdevs[i],
                                   false,
                                   paths) < 0)
            return -1;
    }
    VIR_DEBUG("Setup all hostdevs");
    return 0;
}


static int
qemuDomainSetupMemory(virDomainMemoryDefPtr mem,
                      char ***paths)
{
    if (mem->model != VIR_DOMAIN_MEMORY_MODEL_NVDIMM)
        return 0;

    return virStringListAdd(paths, mem->nvdimmPath);
}


static int
qemuDomainSetupAllMemories(virDomainObjPtr vm,
                           char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up memories");
    for (i = 0; i < vm->def->nmems; i++) {
        if (qemuDomainSetupMemory(vm->def->mems[i],
                                  paths) < 0)
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
    char ***paths = opaque;
    const char *path = NULL;

    if (!(path = virDomainChrSourceDefGetPath(dev->source)))
        return 0;

    /* Socket created by qemu. It doesn't exist upfront. */
    if (dev->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        dev->source->data.nix.listen)
        return 0;

    return virStringListAdd(paths, path);
}


static int
qemuDomainSetupAllChardevs(virDomainObjPtr vm,
                           char ***paths)
{
    VIR_DEBUG("Setting up chardevs");

    if (virDomainChrDefForeach(vm->def,
                               true,
                               qemuDomainSetupChardev,
                               paths) < 0)
        return -1;

    VIR_DEBUG("Setup all chardevs");
    return 0;
}


static int
qemuDomainSetupTPM(virDomainTPMDefPtr dev,
                   char ***paths)
{
    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        if (virStringListAdd(paths, dev->data.passthrough.source.data.file.path) < 0)
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
qemuDomainSetupAllTPMs(virDomainObjPtr vm,
                       char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up TPMs");

    for (i = 0; i < vm->def->ntpms; i++) {
        if (qemuDomainSetupTPM(vm->def->tpms[i], paths) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all TPMs");
    return 0;
}


static int
qemuDomainSetupGraphics(virDomainGraphicsDefPtr gfx,
                        char ***paths)
{
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);

    if (!rendernode)
        return 0;

    return virStringListAdd(paths, rendernode);
}


static int
qemuDomainSetupAllGraphics(virDomainObjPtr vm,
                           char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up graphics");
    for (i = 0; i < vm->def->ngraphics; i++) {
        if (qemuDomainSetupGraphics(vm->def->graphics[i],
                                    paths) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all graphics");
    return 0;
}


static int
qemuDomainSetupInput(virDomainInputDefPtr input,
                     char ***paths)
{
    const char *path = virDomainInputDefGetPath(input);

    if (path && virStringListAdd(paths, path) < 0)
        return -1;

    return 0;
}


static int
qemuDomainSetupAllInputs(virDomainObjPtr vm,
                         char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up inputs");
    for (i = 0; i < vm->def->ninputs; i++) {
        if (qemuDomainSetupInput(vm->def->inputs[i],
                                 paths) < 0)
            return -1;
    }
    VIR_DEBUG("Setup all inputs");
    return 0;
}


static int
qemuDomainSetupRNG(virDomainRNGDefPtr rng,
                   char ***paths)
{
    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (virStringListAdd(paths, rng->source.file) < 0)
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
qemuDomainSetupAllRNGs(virDomainObjPtr vm,
                       char ***paths)
{
    size_t i;

    VIR_DEBUG("Setting up RNGs");
    for (i = 0; i < vm->def->nrngs; i++) {
        if (qemuDomainSetupRNG(vm->def->rngs[i],
                               paths) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all RNGs");
    return 0;
}


static int
qemuDomainSetupLoader(virDomainObjPtr vm,
                      char ***paths)
{
    virDomainLoaderDefPtr loader = vm->def->os.loader;

    VIR_DEBUG("Setting up loader");

    if (loader) {
        switch ((virDomainLoader) loader->type) {
        case VIR_DOMAIN_LOADER_TYPE_ROM:
            if (virStringListAdd(paths, loader->path) < 0)
                return -1;
            break;

        case VIR_DOMAIN_LOADER_TYPE_PFLASH:
            if (virStringListAdd(paths, loader->path) < 0)
                return -1;

            if (loader->nvram &&
                virStringListAdd(paths, loader->nvram) < 0)
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
qemuDomainSetupLaunchSecurity(virDomainObjPtr vm,
                              char ***paths)
{
    virDomainSEVDefPtr sev = vm->def->sev;

    if (!sev || sev->sectype != VIR_DOMAIN_LAUNCH_SECURITY_SEV)
        return 0;

    VIR_DEBUG("Setting up launch security");

    if (virStringListAdd(paths, QEMU_DEV_SEV) < 0)
        return -1;

    VIR_DEBUG("Set up launch security");
    return 0;
}


static int
qemuNamespaceMknodPaths(virDomainObjPtr vm,
                        const char **paths);


int
qemuDomainBuildNamespace(virQEMUDriverConfigPtr cfg,
                         virDomainObjPtr vm)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT)) {
        VIR_DEBUG("namespaces disabled for domain %s", vm->def->name);
        return 0;
    }

    if (qemuDomainPopulateDevices(cfg, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllDisks(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllHostdevs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllMemories(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllChardevs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllTPMs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllGraphics(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllInputs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllRNGs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupLoader(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupLaunchSecurity(vm, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainUnshareNamespace(virQEMUDriverConfigPtr cfg,
                           virSecurityManagerPtr mgr,
                           virDomainObjPtr vm)
{
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

    if (virProcessSetupPrivateMountNS() < 0)
        goto cleanup;

    if (qemuDomainSetupDev(mgr, vm, devPath) < 0)
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


typedef struct _qemuNamespaceMknodItem qemuNamespaceMknodItem;
typedef qemuNamespaceMknodItem *qemuNamespaceMknodItemPtr;
struct _qemuNamespaceMknodItem {
    const char *file;
    char *target;
    bool bindmounted;
    GStatBuf sb;
    void *acl;
    char *tcon;
};

typedef struct _qemuNamespaceMknodData qemuNamespaceMknodData;
typedef qemuNamespaceMknodData *qemuNamespaceMknodDataPtr;
struct _qemuNamespaceMknodData {
    virQEMUDriverPtr driver;
    virDomainObjPtr vm;
    qemuNamespaceMknodItemPtr items;
    size_t nitems;
};


static void
qemuNamespaceMknodItemClear(qemuNamespaceMknodItemPtr item)
{
    VIR_FREE(item->target);
    virFileFreeACLs(&item->acl);
#ifdef WITH_SELINUX
    freecon(item->tcon);
#endif
}


static void
qemuNamespaceMknodDataClear(qemuNamespaceMknodDataPtr data)
{
    size_t i;

    for (i = 0; i < data->nitems; i++) {
        qemuNamespaceMknodItemPtr item = &data->items[i];

        qemuNamespaceMknodItemClear(item);
    }

    VIR_FREE(data->items);
}


/* Our way of creating devices is highly linux specific */
#if defined(__linux__)
static int
qemuNamespaceMknodOne(qemuNamespaceMknodItemPtr data)
{
    int ret = -1;
    bool delDevice = false;
    bool isLink = S_ISLNK(data->sb.st_mode);
    bool isDev = S_ISCHR(data->sb.st_mode) || S_ISBLK(data->sb.st_mode);
    bool isReg = S_ISREG(data->sb.st_mode) || S_ISFIFO(data->sb.st_mode) || S_ISSOCK(data->sb.st_mode);
    bool isDir = S_ISDIR(data->sb.st_mode);

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
    return ret;
}


static bool
qemuNamespaceMknodItemNeedsBindMount(mode_t st_mode)
{
    /* A block device S_ISBLK() or a chardev S_ISCHR() is intentionally not
     * handled.  We want to mknod() it instead of passing in through bind
     * mounting. */
    return S_ISREG(st_mode) || S_ISFIFO(st_mode) ||
           S_ISSOCK(st_mode) || S_ISDIR(st_mode);
}


static int
qemuNamespaceMknodHelper(pid_t pid G_GNUC_UNUSED,
                         void *opaque)
{
    qemuNamespaceMknodDataPtr data = opaque;
    size_t i;
    int ret = -1;

    qemuSecurityPostFork(data->driver->securityManager);

    for (i = 0; i < data->nitems; i++) {
        if (qemuNamespaceMknodOne(&data->items[i]) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuNamespaceMknodDataClear(data);
    return ret;
}


static int
qemuNamespaceMknodItemInit(qemuNamespaceMknodItemPtr item,
                           virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           const char *file)
{
    g_autofree char *target = NULL;
    bool isLink;
    bool needsBindMount;

    item->file = file;

    if (g_lstat(file, &item->sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), file);
        return -1;
    }

    isLink = S_ISLNK(item->sb.st_mode);
    needsBindMount = qemuNamespaceMknodItemNeedsBindMount(item->sb.st_mode);

    if (needsBindMount && STRPREFIX(file, QEMU_DEVPREFIX)) {
        if (!(target = qemuDomainGetPreservedMountPath(cfg, vm, file)))
            return -1;

        item->target = g_steal_pointer(&target);
    } else if (isLink) {
        g_autoptr(GError) gerr = NULL;

        if (!(target = g_file_read_link(file, &gerr))) {
            virReportError(VIR_ERR_SYSTEM_ERROR,
                           _("failed to resolve symlink %s: %s"), file, gerr->message);
            return -1;
        }

        if (!g_path_is_absolute(target)) {
            g_autofree char *fileTmp = g_strdup(file);
            char *c = NULL;
            char *tmp = NULL;

            if ((c = strrchr(fileTmp, '/')))
                *(c + 1) = '\0';

            tmp = g_strdup_printf("%s%s", fileTmp, target);
            VIR_FREE(target);
            target = g_steal_pointer(&tmp);
        }

        item->target = g_steal_pointer(&target);
    }

    /* Symlinks don't have ACLs. */
    if (!isLink &&
        virFileGetACLs(file, &item->acl) < 0 &&
        errno != ENOTSUP) {
        virReportSystemError(errno,
                             _("Unable to get ACLs on %s"), file);
        return -1;
    }

# ifdef WITH_SELINUX
    if (lgetfilecon_raw(file, &item->tcon) < 0 &&
        (errno != ENOTSUP && errno != ENODATA)) {
        virReportSystemError(errno,
                             _("Unable to get SELinux label from %s"), file);
        return -1;
    }
# endif

    return 0;
}


static int
qemuNamespacePrepareOneItem(qemuNamespaceMknodDataPtr data,
                            virQEMUDriverConfigPtr cfg,
                            virDomainObjPtr vm,
                            const char *file,
                            char * const *devMountsPath,
                            size_t ndevMountsPath)
{
    long ttl = sysconf(_SC_SYMLOOP_MAX);
    const char *next = file;
    size_t i;

    while (1) {
        qemuNamespaceMknodItem item = { 0 };

        if (qemuNamespaceMknodItemInit(&item, cfg, vm, next) < 0)
            return -1;

        if (STRPREFIX(next, QEMU_DEVPREFIX)) {
            for (i = 0; i < ndevMountsPath; i++) {
                if (STREQ(devMountsPath[i], "/dev"))
                    continue;
                if (STRPREFIX(next, devMountsPath[i]))
                    break;
            }

            if (i == ndevMountsPath &&
                VIR_APPEND_ELEMENT_COPY(data->items, data->nitems, item) < 0)
                return -1;
        }

        if (!S_ISLNK(item.sb.st_mode))
            break;

        if (ttl-- == 0) {
            virReportSystemError(ELOOP,
                                 _("Too many levels of symbolic links: %s"),
                                 next);
            return -1;
        }

        next = item.target;
    }

    return 0;
}


static int
qemuNamespaceMknodPaths(virDomainObjPtr vm,
                        const char **paths)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    char **devMountsPath = NULL;
    size_t ndevMountsPath = 0;
    size_t npaths = 0;
    qemuNamespaceMknodData data = { 0 };
    size_t i;
    int ret = -1;

    npaths = virStringListLength(paths);
    if (npaths == 0)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);
    if (qemuDomainGetPreservedMounts(cfg, vm,
                                     &devMountsPath, NULL,
                                     &ndevMountsPath) < 0)
        return -1;

    data.driver = driver;
    data.vm = vm;

    for (i = 0; i < npaths; i++) {
        if (qemuNamespacePrepareOneItem(&data, cfg, vm, paths[i],
                                        devMountsPath, ndevMountsPath) < 0)
            goto cleanup;
    }

    for (i = 0; i < data.nitems; i++) {
        qemuNamespaceMknodItemPtr item = &data.items[i];
        if (item->target &&
            qemuNamespaceMknodItemNeedsBindMount(item->sb.st_mode)) {
            if (virFileBindMountDevice(item->file, item->target) < 0)
                goto cleanup;
            item->bindmounted = true;
        }
    }

    if (qemuSecurityPreFork(driver->securityManager) < 0)
        goto cleanup;

    if (virProcessRunInMountNamespace(vm->pid,
                                      qemuNamespaceMknodHelper,
                                      &data) < 0) {
        qemuSecurityPostFork(driver->securityManager);
        goto cleanup;
    }
    qemuSecurityPostFork(driver->securityManager);

    ret = 0;
 cleanup:
    for (i = 0; i < data.nitems; i++) {
        if (data.items[i].bindmounted &&
            umount(data.items[i].target) < 0) {
            VIR_WARN("Unable to unmount %s", data.items[i].target);
        }
    }
    qemuNamespaceMknodDataClear(&data);
    virStringListFreeCount(devMountsPath, ndevMountsPath);
    return ret;
}


#else /* !defined(__linux__) */


static int
qemuNamespaceMknodPaths(virDomainObjPtr vm G_GNUC_UNUSED,
                        const char **paths G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform."));
    return -1;
}


#endif /* !defined(__linux__) */


static int
qemuNamespaceUnlinkHelper(pid_t pid G_GNUC_UNUSED,
                          void *opaque)
{
    char **paths = opaque;
    size_t i;

    for (i = 0; paths[i]; i++) {
        const char *path = paths[i];

        VIR_DEBUG("Unlinking %s", path);
        if (unlink(path) < 0 && errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove device %s"), path);
            return -1;
        }
    }

    g_strfreev(paths);
    return 0;
}


static int
qemuNamespaceUnlinkPaths(virDomainObjPtr vm,
                         const char **paths)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverPtr driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    VIR_AUTOSTRINGLIST unlinkPaths = NULL;
    char **devMountsPath = NULL;
    size_t ndevMountsPath = 0;
    size_t npaths;
    size_t i;
    int ret = -1;

    npaths = virStringListLength(paths);
    if (!npaths)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainGetPreservedMounts(cfg, vm,
                                     &devMountsPath, NULL,
                                     &ndevMountsPath) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        const char *file = paths[i];

        if (STRPREFIX(file, QEMU_DEVPREFIX)) {
            for (i = 0; i < ndevMountsPath; i++) {
                if (STREQ(devMountsPath[i], "/dev"))
                    continue;
                if (STRPREFIX(file, devMountsPath[i]))
                    break;
            }

            if (i == ndevMountsPath &&
                virStringListAdd(&unlinkPaths, file) < 0)
                return -1;
        }
    }

    if (unlinkPaths &&
        virProcessRunInMountNamespace(vm->pid,
                                      qemuNamespaceUnlinkHelper,
                                      unlinkPaths) < 0)
        return -1;

    ret = 0;
 cleanup:
    virStringListFreeCount(devMountsPath, ndevMountsPath);
    return ret;
}


int
qemuDomainNamespaceSetupDisk(virDomainObjPtr vm,
                             virStorageSourcePtr src)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupDisk(src, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
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
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupHostdev(vm,
                               hostdev,
                               true,
                               &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
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
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupHostdev(vm,
                               hostdev,
                               true,
                               &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupMemory(virDomainObjPtr vm,
                               virDomainMemoryDefPtr mem)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupMemory(mem, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownMemory(virDomainObjPtr vm,
                                  virDomainMemoryDefPtr mem)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupMemory(mem, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupChardev(virDomainObjPtr vm,
                                virDomainChrDefPtr chr)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupChardev(vm->def, chr, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownChardev(virDomainObjPtr vm,
                                   virDomainChrDefPtr chr)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupChardev(vm->def, chr, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupRNG(virDomainObjPtr vm,
                            virDomainRNGDefPtr rng)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupRNG(rng, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownRNG(virDomainObjPtr vm,
                               virDomainRNGDefPtr rng)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupRNG(rng, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupInput(virDomainObjPtr vm,
                              virDomainInputDefPtr input)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupInput(input, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, (const char **) paths) < 0)
        return -1;
    return 0;
}


int
qemuDomainNamespaceTeardownInput(virDomainObjPtr vm,
                                 virDomainInputDefPtr input)
{
    VIR_AUTOSTRINGLIST paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupInput(input, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, (const char **) paths) < 0)
        return -1;

    return 0;
}
