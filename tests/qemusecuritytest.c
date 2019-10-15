/*
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "qemusecuritytest.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "security/security_manager.h"
#include "conf/domain_conf.h"
#include "qemu/qemu_domain.h"
#include "qemu/qemu_security.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testData {
    virQEMUDriverPtr driver;
    const char *file; /* file name to load VM def XML from; qemuxml2argvdata/ */
};


static int
prepareObjects(virQEMUDriverPtr driver,
               const char *xmlname,
               virDomainObjPtr *vm_ret)
{
    qemuDomainObjPrivatePtr priv;
    VIR_AUTOUNREF(virDomainObjPtr) vm = NULL;
    g_autofree char *filename = NULL;
    g_autofree char *domxml = NULL;
    g_autofree char *latestCapsFile = NULL;

    if (virAsprintf(&filename, "%s/qemuxml2argvdata/%s.xml", abs_srcdir, xmlname) < 0)
        return -1;

    if (virTestLoadFile(filename, &domxml) < 0)
        return -1;

    if (!(vm = virDomainObjNew(driver->xmlopt)))
        return -1;

    vm->pid = -1;
    priv = vm->privateData;
    priv->chardevStdioLogd = false;
    priv->rememberOwner = true;

    if (!(latestCapsFile = testQemuGetLatestCapsForArch("x86_64", "xml")))
        return -1;

    if (!(priv->qemuCaps = qemuTestParseCapabilitiesArch(VIR_ARCH_X86_64, latestCapsFile)))
        return -1;

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, priv->qemuCaps) < 0)
        return -1;

    if (!(vm->def = virDomainDefParseString(domxml,
                                            driver->caps,
                                            driver->xmlopt,
                                            NULL,
                                            0)))
        return -1;

    VIR_STEAL_PTR(*vm_ret, vm);
    return 0;
}


static int
testDomain(const void *opaque)
{
    const struct testData *data = opaque;
    VIR_AUTOUNREF(virDomainObjPtr) vm = NULL;
    VIR_AUTOSTRINGLIST notRestored = NULL;
    size_t i;
    int ret = -1;

    if (prepareObjects(data->driver, data->file, &vm) < 0)
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        virStorageSourcePtr src = vm->def->disks[i]->src;
        virStorageSourcePtr n;

        if (!src)
            continue;

        if (virStorageSourceIsLocalStorage(src) && src->path &&
            (src->shared || src->readonly) &&
            virStringListAdd(&notRestored, src->path) < 0)
            return -1;

        for (n = src->backingStore; virStorageSourceIsBacking(n); n = n->backingStore) {
            if (virStorageSourceIsLocalStorage(n) && n->path &&
                virStringListAdd(&notRestored, n->path) < 0)
                return -1;
        }
    }

    /* Mocking is enabled only when this env variable is set.
     * See mock code for explanation. */
    if (setenv(ENVVAR, "1", 0) < 0)
        return -1;

    if (qemuSecuritySetAllLabel(data->driver, vm, NULL, false) < 0)
        goto cleanup;

    qemuSecurityRestoreAllLabel(data->driver, vm, false);

    if (checkPaths((const char **) notRestored) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    unsetenv(ENVVAR);
    freePaths();
    return ret;
}


static int
mymain(void)
{
    virQEMUDriver driver;
    int ret = 0;

    if (virInitialize() < 0 ||
        qemuTestDriverInit(&driver) < 0)
        return -1;

    /* Now fix the secdriver */
    virObjectUnref(driver.securityManager);
    if (!(driver.securityManager = virSecurityManagerNewDAC("test", 1000, 1000,
                                                            VIR_SECURITY_MANAGER_PRIVILEGED |
                                                            VIR_SECURITY_MANAGER_DYNAMIC_OWNERSHIP,
                                                            NULL))) {
        virFilePrintf(stderr, "Cannot initialize DAC security driver");
        ret = -1;
        goto cleanup;
    }

#define DO_TEST_DOMAIN(f) \
    do { \
        struct testData data = {.driver = &driver, .file = f}; \
        if (virTestRun(f, testDomain, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_DOMAIN("acpi-table");
    DO_TEST_DOMAIN("channel-unix-guestfwd");
    DO_TEST_DOMAIN("console-virtio-unix");
    DO_TEST_DOMAIN("controller-virtio-scsi");
    DO_TEST_DOMAIN("disk-aio");
    DO_TEST_DOMAIN("disk-backing-chains-noindex");
    DO_TEST_DOMAIN("disk-cache");
    DO_TEST_DOMAIN("disk-cdrom");
    DO_TEST_DOMAIN("disk-cdrom-bus-other");
    DO_TEST_DOMAIN("disk-cdrom-network");
    DO_TEST_DOMAIN("disk-cdrom-tray");
    DO_TEST_DOMAIN("disk-copy_on_read");
    DO_TEST_DOMAIN("disk-detect-zeroes");
    DO_TEST_DOMAIN("disk-error-policy");
    DO_TEST_DOMAIN("disk-floppy");
    DO_TEST_DOMAIN("disk-floppy-q35-2_11");
    DO_TEST_DOMAIN("disk-floppy-q35-2_9");
    DO_TEST_DOMAIN("disk-network-gluster");
    DO_TEST_DOMAIN("disk-network-iscsi");
    DO_TEST_DOMAIN("disk-network-nbd");
    DO_TEST_DOMAIN("disk-network-rbd");
    DO_TEST_DOMAIN("disk-network-sheepdog");
    DO_TEST_DOMAIN("disk-network-source-auth");
    DO_TEST_DOMAIN("disk-network-tlsx509");
    DO_TEST_DOMAIN("disk-readonly-disk");
    DO_TEST_DOMAIN("disk-scsi");
    DO_TEST_DOMAIN("disk-scsi-device-auto");
    DO_TEST_DOMAIN("disk-shared");
    DO_TEST_DOMAIN("disk-virtio");
    DO_TEST_DOMAIN("disk-virtio-scsi-reservations");
    DO_TEST_DOMAIN("graphics-vnc-tls-secret");
    DO_TEST_DOMAIN("hugepages-nvdimm");
    DO_TEST_DOMAIN("iothreads-virtio-scsi-pci");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm-access");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm-align");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm-label");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm-pmem");
    DO_TEST_DOMAIN("memory-hotplug-nvdimm-readonly");
    DO_TEST_DOMAIN("net-vhostuser");
    DO_TEST_DOMAIN("os-firmware-bios");
    DO_TEST_DOMAIN("os-firmware-efi");
    DO_TEST_DOMAIN("os-firmware-efi-secboot");
    DO_TEST_DOMAIN("pci-bridge-many-disks");
    DO_TEST_DOMAIN("tseg-explicit-size");
    DO_TEST_DOMAIN("usb-redir-unix");
    DO_TEST_DOMAIN("virtio-non-transitional");
    DO_TEST_DOMAIN("virtio-transitional");
    DO_TEST_DOMAIN("x86_64-pc-graphics");
    DO_TEST_DOMAIN("x86_64-pc-headless");
    DO_TEST_DOMAIN("x86_64-q35-graphics");
    DO_TEST_DOMAIN("x86_64-q35-headless");

 cleanup:
    qemuTestDriverFree(&driver);
    return ret;
}

VIR_TEST_MAIN(mymain)
