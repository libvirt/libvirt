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
               virDomainObjPtr *vm)
{
    qemuDomainObjPrivatePtr priv;
    char *filename = NULL;
    char *domxml = NULL;
    int ret = -1;

    if (virAsprintf(&filename, "%s/qemuxml2argvdata/%s.xml", abs_srcdir, xmlname) < 0)
        return -1;

    if (virTestLoadFile(filename, &domxml) < 0)
        goto cleanup;

    if (!(*vm = virDomainObjNew(driver->xmlopt)))
        goto cleanup;

    (*vm)->pid = -1;
    priv = (*vm)->privateData;
    priv->chardevStdioLogd = false;
    priv->rememberOwner = true;

    if (!(priv->qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    virQEMUCapsSetList(priv->qemuCaps,
                       QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                       QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE,
                       QEMU_CAPS_DEVICE_IOH3420,
                       QEMU_CAPS_DEVICE_PCI_BRIDGE,
                       QEMU_CAPS_DEVICE_PCI_BRIDGE,
                       QEMU_CAPS_DEVICE_VIRTIO_MMIO,
                       QEMU_CAPS_DEVICE_VIRTIO_RNG,
                       QEMU_CAPS_OBJECT_GPEX,
                       QEMU_CAPS_OBJECT_RNG_RANDOM,
                       QEMU_CAPS_VIRTIO_SCSI,
                       QEMU_CAPS_LAST);

    if (qemuTestCapsCacheInsert(driver->qemuCapsCache, priv->qemuCaps) < 0)
        goto cleanup;

    if (!((*vm)->def = virDomainDefParseString(domxml,
                                               driver->caps,
                                               driver->xmlopt,
                                               NULL,
                                               0)))
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0) {
        virObjectUnref(*vm);
        *vm = NULL;
    }
    VIR_FREE(domxml);
    VIR_FREE(filename);
    return ret;
}


static int
testDomain(const void *opaque)
{
    const struct testData *data = opaque;
    virDomainObjPtr vm = NULL;
    int ret = -1;

    if (prepareObjects(data->driver, data->file, &vm) < 0)
        return -1;

    /* Mocking is enabled only when this env variable is set.
     * See mock code for explanation. */
    if (setenv(ENVVAR, "1", 0) < 0)
        goto cleanup;

    if (qemuSecuritySetAllLabel(data->driver, vm, NULL) < 0)
        goto cleanup;

    qemuSecurityRestoreAllLabel(data->driver, vm, false);

    if (checkPaths() < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    unsetenv(ENVVAR);
    virObjectUnref(vm);
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

    DO_TEST_DOMAIN("disk-virtio");
    DO_TEST_DOMAIN("pci-bridge-many-disks");
    DO_TEST_DOMAIN("arm-virt-virtio");
    DO_TEST_DOMAIN("aarch64-virtio-pci-manual-addresses");
    DO_TEST_DOMAIN("acpi-table");

 cleanup:
    qemuTestDriverFree(&driver);
    return ret;
}

VIR_TEST_MAIN(mymain)
