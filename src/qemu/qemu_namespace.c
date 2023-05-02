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
#if defined(WITH_SYS_MOUNT_H)
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
#include "virdevmapper.h"
#include "virglibutil.h"

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
qemuDomainGetPreservedMountPath(virQEMUDriverConfig *cfg,
                                virDomainObj *vm,
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
 * Any of the return pointers can be NULL. Both arrays are NULL-terminated.
 * Get the mount table either from @vm's PID (if running), or from the
 * namespace we're in (if @vm's not running).
 *
 * Returns 0 on success, -1 otherwise (with error reported)
 */
static int
qemuDomainGetPreservedMounts(virQEMUDriverConfig *cfg,
                             virDomainObj *vm,
                             char ***devPath,
                             char ***devSavePath,
                             size_t *ndevPath)
{
    g_auto(GStrv) mounts = NULL;
    size_t nmounts = 0;
    g_auto(GStrv) paths = NULL;
    g_auto(GStrv) savePaths = NULL;
    g_autofree char *mountsPath = NULL;
    size_t i;

    if (ndevPath)
        *ndevPath = 0;

    if (vm->pid > 0)
        mountsPath = g_strdup_printf("/proc/%lld/mounts", (long long) vm->pid);
    else
        mountsPath = g_strdup(QEMU_PROC_MOUNTS);

    if (virFileGetMountSubtree(mountsPath, "/dev", &mounts, &nmounts) < 0)
        return -1;

    if (nmounts == 0)
        return 0;

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
        size_t j = i + 1;

        /* If we looked into mount table of already running VM,
         * we might have found /dev twice. Remove the other
         * occurrence as it would jeopardize the rest of the prune
         * algorithm.
         */
        if (STREQ(mounts[i], "/dev")) {
            VIR_FREE(mounts[i]);
            VIR_DELETE_ELEMENT_INPLACE(mounts, i, nmounts);
            continue;
        }

        while (j < nmounts) {
            char *c = STRSKIP(mounts[j], mounts[i]);

            if (c && (*c == '/' || *c == '\0')) {
                VIR_DEBUG("Dropping path %s because of %s", mounts[j], mounts[i]);
                VIR_FREE(mounts[j]);
                VIR_DELETE_ELEMENT_INPLACE(mounts, j, nmounts);
            } else {
                j++;
            }
        }
    }

    /* mounts may not be NULL-terminated at this point, but we convert it into
     * 'paths' which is NULL-terminated */

    paths = g_new0(char *, nmounts + 1);

    for (i = 0; i < nmounts; i++)
        paths[i] = g_steal_pointer(&mounts[i]);

    if (devSavePath) {
        savePaths = g_new0(char *, nmounts + 1);

        for (i = 0; i < nmounts; i++) {
            if (!(savePaths[i] = qemuDomainGetPreservedMountPath(cfg, vm, paths[i])))
                return -1;
        }
    }

    if (devPath)
        *devPath = g_steal_pointer(&paths);

    if (devSavePath)
        *devSavePath = g_steal_pointer(&savePaths);

    if (ndevPath)
        *ndevPath = nmounts;

    return 0;
}


static int
qemuDomainPopulateDevices(virQEMUDriverConfig *cfg,
                          GSList **paths)
{
    const char *const *devices = (const char *const *) cfg->cgroupDeviceACL;
    size_t i;

    if (!devices)
        devices = defaultDeviceACL;

    for (i = 0; devices[i]; i++) {
        *paths = g_slist_prepend(*paths, g_strdup(devices[i]));
    }

    return 0;
}


static int
qemuDomainSetupDev(virSecurityManager *mgr,
                   virDomainObj *vm,
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
qemuDomainSetupDisk(virStorageSource *src,
                    GSList **paths)
{
    virStorageSource *next;
    bool hasNVMe = false;

    for (next = src; virStorageSourceIsBacking(next); next = next->backingStore) {
        g_autofree char *tmpPath = NULL;

        if (next->type == VIR_STORAGE_TYPE_NVME) {
            hasNVMe = true;

            if (!(tmpPath = virPCIDeviceAddressGetIOMMUGroupDev(&next->nvme->pciAddr)))
                return -1;
        } else {
            GSList *targetPaths = NULL;

            if (virStorageSourceIsEmpty(next) ||
                !virStorageSourceIsLocalStorage(next)) {
                /* Not creating device. Just continue. */
                continue;
            }

            tmpPath = g_strdup(next->path);

            if (virDevMapperGetTargets(next->path, &targetPaths) < 0 &&
                errno != ENOSYS) {
                virReportSystemError(errno,
                                     _("Unable to get devmapper targets for %1$s"),
                                     next->path);
                return -1;
            }

            if (targetPaths)
                *paths = g_slist_concat(g_slist_reverse(targetPaths), *paths);
        }

        *paths = g_slist_prepend(*paths, g_steal_pointer(&tmpPath));
    }

    /* qemu-pr-helper might require access to /dev/mapper/control. */
    if (src->pr)
        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEVICE_MAPPER_CONTROL_PATH));

    if (hasNVMe)
        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_VFIO));

    return 0;
}


static int
qemuDomainSetupAllDisks(virDomainObj *vm,
                        GSList **paths)
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
qemuDomainSetupHostdev(virDomainObj *vm,
                       virDomainHostdevDef *hostdev,
                       bool hotplug,
                       GSList **paths)
{
    g_autofree char *path = NULL;

    if (qemuDomainGetHostdevPath(hostdev, &path, NULL) < 0)
        return -1;

    if (path)
        *paths = g_slist_prepend(*paths, g_steal_pointer(&path));

    if (qemuHostdevNeedsVFIO(hostdev) &&
        (!hotplug || !qemuDomainNeedsVFIO(vm->def)))
        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_VFIO));

    return 0;
}


static int
qemuDomainSetupAllHostdevs(virDomainObj *vm,
                           GSList **paths)
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
qemuDomainSetupMemory(virDomainMemoryDef *mem,
                      GSList **paths)
{
    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        *paths = g_slist_prepend(*paths, g_strdup(mem->source.nvdimm.path));
        break;
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        *paths = g_slist_prepend(*paths, g_strdup(mem->source.virtio_pmem.path));
        break;

    case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_SGX_VEPVC));
        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_SGX_PROVISION));
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        break;
    }

    return 0;
}


static int
qemuDomainSetupAllMemories(virDomainObj *vm,
                           GSList **paths)
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
qemuDomainSetupChardev(virDomainDef *def G_GNUC_UNUSED,
                       virDomainChrDef *dev,
                       void *opaque)
{
    GSList **paths = opaque;
    const char *path = NULL;

    if (!(path = virDomainChrSourceDefGetPath(dev->source)))
        return 0;

    /* Socket created by qemu. It doesn't exist upfront. */
    if (dev->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
        dev->source->data.nix.listen)
        return 0;

    *paths = g_slist_prepend(*paths, g_strdup(path));
    return 0;
}


static int
qemuDomainSetupAllChardevs(virDomainObj *vm,
                           GSList **paths)
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
qemuDomainSetupTPM(virDomainTPMDef *dev,
                   GSList **paths)
{
    switch (dev->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        *paths = g_slist_prepend(*paths, g_strdup(dev->data.passthrough.source->data.file.path));
        break;

    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
    case VIR_DOMAIN_TPM_TYPE_EXTERNAL:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        /* nada */
        break;
    }

    return 0;
}


static int
qemuDomainSetupAllTPMs(virDomainObj *vm,
                       GSList **paths)
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
qemuDomainSetupGraphics(virDomainGraphicsDef *gfx,
                        GSList **paths)
{
    const char *rendernode = virDomainGraphicsGetRenderNode(gfx);

    if (!rendernode)
        return 0;

    *paths = g_slist_prepend(*paths, g_strdup(rendernode));
    return 0;
}


static int
qemuDomainSetupAllGraphics(virDomainObj *vm,
                           GSList **paths)
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
qemuDomainSetupAllVideos(virDomainObj *vm,
                         GSList **paths)
{
    size_t i;

    VIR_DEBUG("Setting up video devices");
    for (i = 0; i < vm->def->nvideos; i++) {
        virDomainVideoDef *video = vm->def->videos[i];
        if (video->blob == VIR_TRISTATE_SWITCH_ON) {
            *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_UDMABUF));
            break;
        }
    }

    return 0;
}


static int
qemuDomainSetupInput(virDomainInputDef *input,
                     GSList **paths)
{
    const char *path = virDomainInputDefGetPath(input);

    if (!path)
        return 0;

    *paths = g_slist_prepend(*paths, g_strdup(path));

    return 0;
}


static int
qemuDomainSetupAllInputs(virDomainObj *vm,
                         GSList **paths)
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
qemuDomainSetupRNG(virDomainRNGDef *rng,
                   GSList **paths)
{
    switch (rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        *paths = g_slist_prepend(*paths, g_strdup(rng->source.file));
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
qemuDomainSetupAllRNGs(virDomainObj *vm,
                       GSList **paths)
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
qemuDomainSetupLoader(virDomainObj *vm,
                      GSList **paths)
{
    virDomainLoaderDef *loader = vm->def->os.loader;

    VIR_DEBUG("Setting up loader");

    if (loader) {
        switch ((virDomainLoader) loader->type) {
        case VIR_DOMAIN_LOADER_TYPE_ROM:
            *paths = g_slist_prepend(*paths, g_strdup(loader->path));
            break;

        case VIR_DOMAIN_LOADER_TYPE_PFLASH:
            *paths = g_slist_prepend(*paths, g_strdup(loader->path));

            if (loader->nvram &&
                qemuDomainSetupDisk(loader->nvram, paths) < 0)
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
qemuDomainSetupLaunchSecurity(virDomainObj *vm,
                              GSList **paths)
{
    virDomainSecDef *sec = vm->def->sec;

    if (!sec)
        return 0;

    switch ((virDomainLaunchSecurity) sec->sectype) {
    case VIR_DOMAIN_LAUNCH_SECURITY_SEV:
        VIR_DEBUG("Setting up launch security for SEV");

        *paths = g_slist_prepend(*paths, g_strdup(QEMU_DEV_SEV));

        VIR_DEBUG("Set up launch security for SEV");
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_PV:
        break;
    case VIR_DOMAIN_LAUNCH_SECURITY_NONE:
    case VIR_DOMAIN_LAUNCH_SECURITY_LAST:
        virReportEnumRangeError(virDomainLaunchSecurity, sec->sectype);
        return -1;
    }

    return 0;
}


static int
qemuNamespaceMknodPaths(virDomainObj *vm,
                        GSList *paths,
                        bool *created);


int
qemuDomainBuildNamespace(virQEMUDriverConfig *cfg,
                         virDomainObj *vm)
{
    g_autoptr(virGSListString) paths = NULL;

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

    if (qemuDomainSetupAllVideos(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllInputs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupAllRNGs(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupLoader(vm, &paths) < 0)
        return -1;

    if (qemuDomainSetupLaunchSecurity(vm, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, NULL) < 0)
        return -1;

    return 0;
}


int
qemuDomainUnshareNamespace(virQEMUDriverConfig *cfg,
                           virSecurityManager *mgr,
                           virDomainObj *vm)
{
    const char *devPath = NULL;
    g_auto(GStrv) devMountsPath = NULL;
    g_auto(GStrv) devMountsSavePath = NULL;
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
                                 _("Unable to stat: %1$s"),
                                 devMountsPath[i]);
            goto cleanup;
        }

        /* At this point, devMountsPath is either:
         * a file (regular or special), or
         * a directory. */
        if ((S_ISDIR(sb.st_mode) && g_mkdir_with_parents(devMountsSavePath[i], 0777) < 0) ||
            (!S_ISDIR(sb.st_mode) && virFileTouch(devMountsSavePath[i], sb.st_mode) < 0)) {
            virReportSystemError(errno,
                                 _("Failed to create %1$s"),
                                 devMountsSavePath[i]);
            goto cleanup;
        }

        if (virFileMoveMount(devMountsPath[i], devMountsSavePath[i]) < 0)
            goto cleanup;
    }

#if defined(__linux__)
    if (umount2("/dev", MNT_DETACH) < 0) {
        virReportSystemError(errno, "%s", _("failed to umount devfs on /dev"));
        goto cleanup;
    }
#endif /* !defined(__linux__) */

    if (virFileMoveMount(devPath, "/dev") < 0)
        goto cleanup;

    for (i = 0; i < ndevMountsPath; i++) {
        struct stat sb;

        if (devMountsSavePath[i] == devPath)
            continue;

        if (stat(devMountsSavePath[i], &sb) < 0) {
            virReportSystemError(errno,
                                 _("Unable to stat: %1$s"),
                                 devMountsSavePath[i]);
            goto cleanup;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (g_mkdir_with_parents(devMountsPath[i], 0777) < 0) {
                virReportSystemError(errno, _("Cannot create %1$s"),
                                     devMountsPath[i]);
                goto cleanup;
            }
        } else {
            if (virFileMakeParentPath(devMountsPath[i]) < 0 ||
                virFileTouch(devMountsPath[i], sb.st_mode) < 0) {
                virReportSystemError(errno, _("Cannot create %1$s"),
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
    return ret;
}


bool
qemuDomainNamespaceEnabled(virDomainObj *vm,
                           qemuDomainNamespace ns)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    return priv->namespaces &&
        virBitmapIsBitSet(priv->namespaces, ns);
}


int
qemuDomainEnableNamespace(virDomainObj *vm,
                          qemuDomainNamespace ns)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!priv->namespaces)
        priv->namespaces = virBitmapNew(QEMU_DOMAIN_NS_LAST);

    if (virBitmapSetBit(priv->namespaces, ns) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to enable namespace: %1$s"),
                       qemuDomainNamespaceTypeToString(ns));
        return -1;
    }

    return 0;
}


static void
qemuDomainDisableNamespace(virDomainObj *vm,
                           qemuDomainNamespace ns)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (priv->namespaces) {
        ignore_value(virBitmapClearBit(priv->namespaces, ns));
        if (virBitmapIsAllClear(priv->namespaces)) {
            g_clear_pointer(&priv->namespaces, virBitmapFree);
        }
    }
}


void
qemuDomainDestroyNamespace(virQEMUDriver *driver G_GNUC_UNUSED,
                           virDomainObj *vm)
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
# if !defined(WITH_LIBACL) || !defined(WITH_SELINUX)
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
struct _qemuNamespaceMknodItem {
    char *file;
    char *target;
    bool bindmounted;
    GStatBuf sb;
    void *acl;
    char *tcon;
};

typedef struct _qemuNamespaceMknodData qemuNamespaceMknodData;
struct _qemuNamespaceMknodData {
    virQEMUDriver *driver;
    virDomainObj *vm;
    qemuNamespaceMknodItem *items;
    size_t nitems;
};


static void
qemuNamespaceMknodItemClear(qemuNamespaceMknodItem *item)
{
    VIR_FREE(item->file);
    VIR_FREE(item->target);
    virFileFreeACLs(&item->acl);
#ifdef WITH_SELINUX
    freecon(item->tcon);
#endif
}


G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(qemuNamespaceMknodItem, qemuNamespaceMknodItemClear);

static void
qemuNamespaceMknodDataClear(qemuNamespaceMknodData *data)
{
    size_t i;

    for (i = 0; i < data->nitems; i++) {
        qemuNamespaceMknodItem *item = &data->items[i];

        qemuNamespaceMknodItemClear(item);
    }

    VIR_FREE(data->items);
}


/* Our way of creating devices is highly linux specific */
#if defined(__linux__)
static int
qemuNamespaceMknodOne(qemuNamespaceMknodItem *data)
{
    int ret = -1;
    bool delDevice = false;
    bool isLink = S_ISLNK(data->sb.st_mode);
    bool isDev = S_ISCHR(data->sb.st_mode) || S_ISBLK(data->sb.st_mode);
    bool isReg = S_ISREG(data->sb.st_mode) || S_ISFIFO(data->sb.st_mode) || S_ISSOCK(data->sb.st_mode);
    bool isDir = S_ISDIR(data->sb.st_mode);
    bool exists = false;

    if (virFileExists(data->file))
        exists = true;

    if (virFileMakeParentPath(data->file) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %1$s"), data->file);
        goto cleanup;
    }

    if (isLink) {
        g_autofree char *target = NULL;

        if ((target = g_file_read_link(data->file, NULL)) &&
            STREQ(target, data->target)) {
            VIR_DEBUG("Skipping symlink %s -> %s which exists and points to correct target",
                      data->file, data->target);
        } else {
            VIR_DEBUG("Creating symlink %s -> %s", data->file, data->target);

            /* First, unlink the symlink target. Symlinks change and
             * therefore we have no guarantees that pre-existing
             * symlink is still valid. */
            if (unlink(data->file) < 0 &&
                errno != ENOENT) {
                virReportSystemError(errno,
                                     _("Unable to remove symlink %1$s"),
                                     data->file);
                goto cleanup;
            }

            if (symlink(data->target, data->file) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create symlink %1$s (pointing to %2$s)"),
                                     data->file, data->target);
                goto cleanup;
            } else {
                delDevice = true;
            }
        }
    } else if (isDev) {
        GStatBuf sb;

        if (g_lstat(data->file, &sb) >= 0 &&
            sb.st_rdev == data->sb.st_rdev) {
            VIR_DEBUG("Skipping dev %s (%d,%d) which exists and has correct MAJ:MIN",
                       data->file, major(data->sb.st_rdev), minor(data->sb.st_rdev));
        } else {
            VIR_DEBUG("Creating dev %s (%d,%d)",
                      data->file, major(data->sb.st_rdev), minor(data->sb.st_rdev));
            unlink(data->file);
            if (mknod(data->file, data->sb.st_mode, data->sb.st_rdev) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create device %1$s"),
                                     data->file);
                goto cleanup;
            } else {
                delDevice = true;
            }
        }
    } else if (isReg || isDir) {
        /* We are not cleaning up disks on virDomainDetachDevice
         * because disk might be still in use by different disk
         * as its backing chain. This might however clash here.
         * Therefore do the cleanup here. */
        if (umount(data->file) < 0 &&
            errno != ENOENT && errno != EINVAL) {
            virReportSystemError(errno,
                                 _("Unable to umount %1$s"),
                                 data->file);
            goto cleanup;
        }
        if ((isReg && virFileTouch(data->file, data->sb.st_mode) < 0) ||
            (isDir && g_mkdir_with_parents(data->file, data->sb.st_mode) < 0))
            goto cleanup;
        delDevice = true;
        /* Just create the file here so that code below sets
         * proper owner and mode. Move the mount only after that. */
    } else {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("unsupported device type %1$s 0%2$o"),
                       data->file, data->sb.st_mode);
        goto cleanup;
    }

    if (lchown(data->file, data->sb.st_uid, data->sb.st_gid) < 0) {
        virReportSystemError(errno,
                             _("Failed to chown device %1$s"),
                             data->file);
        goto cleanup;
    }

    /* Symlinks don't have mode */
    if (!isLink &&
        chmod(data->file, data->sb.st_mode) < 0) {
        virReportSystemError(errno,
                             _("Failed to set permissions for device %1$s"),
                             data->file);
        goto cleanup;
    }

    if (data->acl &&
        virFileSetACLs(data->file, data->acl) < 0 &&
        errno != ENOTSUP) {
        virReportSystemError(errno,
                             _("Unable to set ACLs on %1$s"), data->file);
        goto cleanup;
    }

# ifdef WITH_SELINUX
    if (data->tcon &&
        lsetfilecon_raw(data->file, (const char *)data->tcon) < 0) {
        VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
        if (errno != EOPNOTSUPP && errno != ENOTSUP) {
        VIR_WARNINGS_RESET
            virReportSystemError(errno,
                                 _("Unable to set SELinux label on %1$s"),
                                 data->file);
            goto cleanup;
        }
    }
# endif

    /* Finish mount process started earlier. */
    if ((isReg || isDir) &&
        virFileMoveMount(data->target, data->file) < 0)
        goto cleanup;

    ret = exists;
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
    qemuNamespaceMknodData *data = opaque;
    size_t i;
    int ret = -1;
    bool exists = false;

    qemuSecurityPostFork(data->driver->securityManager);

    for (i = 0; i < data->nitems; i++) {
        int rc = 0;

        if ((rc = qemuNamespaceMknodOne(&data->items[i])) < 0)
            goto cleanup;

        if (rc > 0)
            exists = true;
    }

    ret = exists;
 cleanup:
    qemuNamespaceMknodDataClear(data);
    return ret;
}


static int
qemuNamespaceMknodItemInit(qemuNamespaceMknodItem *item,
                           virQEMUDriverConfig *cfg,
                           virDomainObj *vm,
                           const char *file)
{
    g_autofree char *target = NULL;
    bool isLink;
    bool needsBindMount;

    item->file = g_strdup(file);

    if (g_lstat(file, &item->sb) < 0) {
        if (errno == ENOENT)
            return -2;

        virReportSystemError(errno,
                             _("Unable to access %1$s"), file);
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
                           _("failed to resolve symlink %1$s: %2$s"), file, gerr->message);
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
                             _("Unable to get ACLs on %1$s"), file);
        return -1;
    }

# ifdef WITH_SELINUX
    if (lgetfilecon_raw(file, &item->tcon) < 0 &&
        (errno != ENOTSUP && errno != ENODATA)) {
        virReportSystemError(errno,
                             _("Unable to get SELinux label from %1$s"), file);
        return -1;
    }
# endif

    return 0;
}


static int
qemuNamespacePrepareOneItem(qemuNamespaceMknodData *data,
                            virQEMUDriverConfig *cfg,
                            virDomainObj *vm,
                            const char *file,
                            GStrv devMountsPath)
{
    long ttl = sysconf(_SC_SYMLOOP_MAX);
    g_autofree char *next = g_strdup(file);

    while (1) {
        g_auto(qemuNamespaceMknodItem) item = { 0 };
        bool isLink;
        int rc;

        rc = qemuNamespaceMknodItemInit(&item, cfg, vm, next);
        if (rc == -2) {
            /* @file doesn't exist. We can break here. */
            break;
        } else if (rc < 0) {
            /* Some other (critical) error. */
            return -1;
        }

        isLink = S_ISLNK(item.sb.st_mode);
        g_free(next);
        next = g_strdup(item.target);

        if (STRPREFIX(item.file, QEMU_DEVPREFIX)) {
            GStrv n;
            bool found = false;

            for (n = devMountsPath; n && *n; n++) {
                const char *p;

                if (STREQ(*n, "/dev"))
                    continue;
                if ((p = STRSKIP(item.file, *n)) && *p == '/') {
                    found = true;
                    break;
                }
            }

            if (!found)
                VIR_APPEND_ELEMENT(data->items, data->nitems, item);
        }

        if (!isLink)
            break;

        if (ttl-- == 0) {
            virReportSystemError(ELOOP,
                                 _("Too many levels of symbolic links: %1$s"),
                                 next);
            return -1;
        }
    }

    return 0;
}


static int
qemuNamespaceMknodPaths(virDomainObj *vm,
                        GSList *paths,
                        bool *created)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    g_auto(GStrv) devMountsPath = NULL;
    qemuNamespaceMknodData data = { 0 };
    size_t i;
    int ret = -1;
    GSList *next;

    if (!paths)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);
    if (qemuDomainGetPreservedMounts(cfg, vm, &devMountsPath, NULL, NULL) < 0)
        return -1;

    data.driver = driver;
    data.vm = vm;

    for (next = paths; next; next = next->next) {
        const char *path = next->data;

        if (qemuNamespacePrepareOneItem(&data, cfg, vm, path, devMountsPath) < 0)
            goto cleanup;
    }

    if (data.nitems == 0)
        return 0;

    for (i = 0; i < data.nitems; i++) {
        qemuNamespaceMknodItem *item = &data.items[i];
        if (item->target &&
            qemuNamespaceMknodItemNeedsBindMount(item->sb.st_mode)) {
            if (virFileBindMountDevice(item->file, item->target) < 0)
                goto cleanup;
            item->bindmounted = true;
        }
    }

    if (qemuSecurityPreFork(driver->securityManager) < 0)
        goto cleanup;

    ret = virProcessRunInMountNamespace(vm->pid, qemuNamespaceMknodHelper,
                                        &data);
    qemuSecurityPostFork(driver->securityManager);

    if (ret == 0 && created != NULL)
        *created = true;

 cleanup:
    for (i = 0; i < data.nitems; i++) {
        if (data.items[i].bindmounted &&
            umount(data.items[i].target) < 0) {
            VIR_WARN("Unable to unmount %s", data.items[i].target);
        }
    }
    qemuNamespaceMknodDataClear(&data);
    return ret;
}


#else /* !defined(__linux__) */


static int
qemuNamespaceMknodPaths(virDomainObj *vm G_GNUC_UNUSED,
                        GSList *paths G_GNUC_UNUSED,
                        bool *created G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform"));
    return -1;
}


#endif /* !defined(__linux__) */


static int
qemuNamespaceUnlinkHelper(pid_t pid G_GNUC_UNUSED,
                          void *opaque)
{
    g_autoptr(virGSListString) paths = opaque;
    GSList *next;

    for (next = paths; next; next = next->next) {
        const char *path = next->data;

        VIR_DEBUG("Unlinking %s", path);
        if (unlink(path) < 0 && errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove device %1$s"), path);
            return -1;
        }
    }

    return 0;
}


static int
qemuNamespaceUnlinkPaths(virDomainObj *vm,
                         GSList *paths)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    g_auto(GStrv) devMountsPath = NULL;
    g_autoptr(virGSListString) unlinkPaths = NULL;
    GSList *next;

    if (!paths)
        return 0;

    cfg = virQEMUDriverGetConfig(driver);

    if (qemuDomainGetPreservedMounts(cfg, vm, &devMountsPath, NULL, NULL) < 0)
        return -1;

    for (next = paths; next; next = next->next) {
        const char *path = next->data;

        if (STRPREFIX(path, QEMU_DEVPREFIX)) {
            GStrv mount;
            bool inSubmount = false;
            const char *const *devices = (const char *const *)cfg->cgroupDeviceACL;

            for (mount = devMountsPath; *mount; mount++) {
                if (STREQ(*mount, "/dev"))
                    continue;

                if (STRPREFIX(path, *mount)) {
                    inSubmount = true;
                    break;
                }
            }

            if (inSubmount)
                continue;

            if (!devices)
                devices = defaultDeviceACL;

            if (g_strv_contains(devices, path))
                continue;

            unlinkPaths = g_slist_prepend(unlinkPaths, g_strdup(path));
        }
    }

    if (unlinkPaths &&
        virProcessRunInMountNamespace(vm->pid,
                                      qemuNamespaceUnlinkHelper,
                                      unlinkPaths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupPath(virDomainObj *vm,
                             const char *path,
                             bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    paths = g_slist_prepend(paths, g_strdup(path));

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupDisk(virDomainObj *vm,
                             virStorageSource *src,
                             bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupDisk(src, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownDisk(virDomainObj *vm G_GNUC_UNUSED,
                                virStorageSource *src G_GNUC_UNUSED)
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
qemuDomainNamespaceSetupHostdev(virDomainObj *vm,
                                virDomainHostdevDef *hostdev,
                                bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupHostdev(vm,
                               hostdev,
                               true,
                               &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
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
qemuDomainNamespaceTeardownHostdev(virDomainObj *vm,
                                   virDomainHostdevDef *hostdev)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupHostdev(vm,
                               hostdev,
                               true,
                               &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupMemory(virDomainObj *vm,
                               virDomainMemoryDef *mem,
                               bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupMemory(mem, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownMemory(virDomainObj *vm,
                                  virDomainMemoryDef *mem)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupMemory(mem, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupChardev(virDomainObj *vm,
                                virDomainChrDef *chr,
                                bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupChardev(vm->def, chr, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownChardev(virDomainObj *vm,
                                   virDomainChrDef *chr)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupChardev(vm->def, chr, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupRNG(virDomainObj *vm,
                            virDomainRNGDef *rng,
                            bool *created)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupRNG(rng, &paths) < 0)
        return -1;

    if (qemuNamespaceMknodPaths(vm, paths, created) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownRNG(virDomainObj *vm,
                               virDomainRNGDef *rng)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupRNG(rng, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, paths) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceSetupInput(virDomainObj *vm,
                              virDomainInputDef *input,
                              bool *created)
{
    g_autoptr(virGSListString) paths = NULL;
    int ret = 0;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupInput(input, &paths) < 0)
        return -1;

    if ((ret = qemuNamespaceMknodPaths(vm, paths, created)) < 0)
        return -1;

    return 0;
}


int
qemuDomainNamespaceTeardownInput(virDomainObj *vm,
                                 virDomainInputDef *input)
{
    g_autoptr(virGSListString) paths = NULL;

    if (!qemuDomainNamespaceEnabled(vm, QEMU_DOMAIN_NS_MOUNT))
        return 0;

    if (qemuDomainSetupInput(input, &paths) < 0)
        return -1;

    if (qemuNamespaceUnlinkPaths(vm, paths) < 0)
        return -1;

    return 0;
}
