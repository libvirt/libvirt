/*
 * qemu_command.c: QEMU command generation
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_command.h"
#include "qemu_hostdev.h"
#include "qemu_capabilities.h"
#include "cpu/cpu.h"
#include "dirname.h"
#include "passfd.h"
#include "viralloc.h"
#include "virlog.h"
#include "virarch.h"
#include "virerror.h"
#include "virfile.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virstring.h"
#include "virtime.h"
#include "viruuid.h"
#include "c-ctype.h"
#include "domain_nwfilter.h"
#include "domain_addr.h"
#include "domain_audit.h"
#include "domain_conf.h"
#include "netdev_bandwidth_conf.h"
#include "snapshot_conf.h"
#include "storage_conf.h"
#include "secret_conf.h"
#include "network/bridge_driver.h"
#include "virnetdevtap.h"
#include "base64.h"
#include "device_conf.h"
#include "virstoragefile.h"
#include "virtpm.h"
#include "virscsi.h"
#include "virnuma.h"
#if defined(__linux__)
# include <linux/capability.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_command");

#define VIO_ADDR_NET 0x1000ul
#define VIO_ADDR_SCSI 0x2000ul
#define VIO_ADDR_SERIAL 0x30000000ul
#define VIO_ADDR_NVRAM 0x3000ul

VIR_ENUM_DECL(virDomainDiskQEMUBus)
VIR_ENUM_IMPL(virDomainDiskQEMUBus, VIR_DOMAIN_DISK_BUS_LAST,
              "ide",
              "floppy",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml",
              "sata",
              "sd")


VIR_ENUM_DECL(qemuDiskCacheV2)

VIR_ENUM_IMPL(qemuDiskCacheV2, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback",
              "directsync",
              "unsafe");

VIR_ENUM_DECL(qemuVideo)

VIR_ENUM_IMPL(qemuVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "std",
              "cirrus",
              "vmware",
              "", /* no arg needed for xen */
              "", /* don't support vbox */
              "qxl",
              "", /* don't support parallels */
              "" /* no need for virtio */);

VIR_ENUM_DECL(qemuDeviceVideo)

VIR_ENUM_IMPL(qemuDeviceVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "VGA",
              "cirrus-vga",
              "vmware-svga",
              "", /* no device for xen */
              "", /* don't support vbox */
              "qxl-vga",
              "", /* don't support parallels */
              "virtio-vga");

VIR_ENUM_DECL(qemuSoundCodec)

VIR_ENUM_IMPL(qemuSoundCodec, VIR_DOMAIN_SOUND_CODEC_TYPE_LAST,
              "hda-duplex",
              "hda-micro");

VIR_ENUM_DECL(qemuControllerModelUSB)

VIR_ENUM_IMPL(qemuControllerModelUSB, VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST,
              "piix3-usb-uhci",
              "piix4-usb-uhci",
              "usb-ehci",
              "ich9-usb-ehci1",
              "ich9-usb-uhci1",
              "ich9-usb-uhci2",
              "ich9-usb-uhci3",
              "vt82c686b-usb-uhci",
              "pci-ohci",
              "nec-usb-xhci",
              "none");

VIR_ENUM_DECL(qemuDomainFSDriver)
VIR_ENUM_IMPL(qemuDomainFSDriver, VIR_DOMAIN_FS_DRIVER_TYPE_LAST,
              "local",
              "local",
              "handle",
              NULL,
              NULL,
              NULL);

VIR_ENUM_DECL(qemuNumaPolicy)
VIR_ENUM_IMPL(qemuNumaPolicy, VIR_DOMAIN_NUMATUNE_MEM_LAST,
              "bind",
              "preferred",
              "interleave");

/**
 * qemuVirCommandGetFDSet:
 * @cmd: the command to modify
 * @fd: fd to reassign to the child
 *
 * Get the parameters for the QEMU -add-fd command line option
 * for the given file descriptor. The file descriptor must previously
 * have been 'transferred' in a virCommandPassFD() call.
 * This function for example returns "set=10,fd=20".
 */
static char *
qemuVirCommandGetFDSet(virCommandPtr cmd, int fd)
{
    char *result = NULL;
    int idx = virCommandPassFDGetFDIndex(cmd, fd);

    if (idx >= 0) {
        ignore_value(virAsprintf(&result, "set=%d,fd=%d", idx, fd));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("file descriptor %d has not been transferred"), fd);
    }

    return result;
}

/**
 * qemuVirCommandGetDevSet:
 * @cmd: the command to modify
 * @fd: fd to reassign to the child
 *
 * Get the parameters for the QEMU path= parameter where a file
 * descriptor is accessed via a file descriptor set, for example
 * /dev/fdset/10. The file descriptor must previously have been
 * 'transferred' in a virCommandPassFD() call.
 */
static char *
qemuVirCommandGetDevSet(virCommandPtr cmd, int fd)
{
    char *result = NULL;
    int idx = virCommandPassFDGetFDIndex(cmd, fd);

    if (idx >= 0) {
        ignore_value(virAsprintf(&result, "/dev/fdset/%d", idx));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("file descriptor %d has not been transferred"), fd);
    }
    return result;
}


/**
 * qemuPhysIfaceConnect:
 * @def: the definition of the VM (needed by 802.1Qbh and audit)
 * @driver: pointer to the driver instance
 * @net: pointer to the VM's interface description with direct device type
 * @tapfd: array of file descriptor return value for the new device
 * @tapfdSize: number of file descriptors in @tapfd
 * @vmop: VM operation type
 *
 * Returns 0 on success or -1 in case of error.
 */
int
qemuPhysIfaceConnect(virDomainDefPtr def,
                     virQEMUDriverPtr driver,
                     virDomainNetDefPtr net,
                     int *tapfd,
                     size_t tapfdSize,
                     virNetDevVPortProfileOp vmop)
{
    int ret = -1;
    char *res_ifname = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned int macvlan_create_flags = VIR_NETDEV_MACVLAN_CREATE_WITH_TAP;

    if (net->model && STREQ(net->model, "virtio"))
        macvlan_create_flags |= VIR_NETDEV_MACVLAN_VNET_HDR;

    if (virNetDevMacVLanCreateWithVPortProfile(net->ifname,
                                               &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               virDomainNetGetActualDirectMode(net),
                                               def->uuid,
                                               virDomainNetGetActualVirtPortProfile(net),
                                               &res_ifname,
                                               vmop, cfg->stateDir,
                                               tapfd, tapfdSize,
                                               macvlan_create_flags) < 0)
        goto cleanup;

    virDomainAuditNetDevice(def, net, res_ifname, true);
    VIR_FREE(net->ifname);
    net->ifname = res_ifname;
    ret = 0;

 cleanup:
    if (ret < 0) {
        while (tapfdSize--)
            VIR_FORCE_CLOSE(tapfd[tapfdSize]);
    }
    virObjectUnref(cfg);
    return ret;
}


/**
 * qemuCreateInBridgePortWithHelper:
 * @cfg: the configuration object in which the helper name is looked up
 * @brname: the bridge name
 * @ifname: the returned interface name
 * @macaddr: the returned MAC address
 * @tapfd: file descriptor return value for the new tap device
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *
 * This function creates a new tap device on a bridge using an external
 * helper.  The final name for the bridge will be stored in @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
static int qemuCreateInBridgePortWithHelper(virQEMUDriverConfigPtr cfg,
                                            const char *brname,
                                            char **ifname,
                                            int *tapfd,
                                            unsigned int flags)
{
    virCommandPtr cmd;
    char *errbuf = NULL, *cmdstr = NULL;
    int pair[2] = { -1, -1 };

    if ((flags & ~VIR_NETDEV_TAP_CREATE_VNET_HDR) != VIR_NETDEV_TAP_CREATE_IFUP)
        return -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        virReportSystemError(errno, "%s", _("failed to create socket"));
        return -1;
    }

    if (!virFileIsExecutable(cfg->bridgeHelperName)) {
        virReportSystemError(errno, _("'%s' is not a suitable bridge helper"),
                             cfg->bridgeHelperName);
        return -1;
    }

    cmd = virCommandNew(cfg->bridgeHelperName);
    if (flags & VIR_NETDEV_TAP_CREATE_VNET_HDR)
        virCommandAddArgFormat(cmd, "--use-vnet");
    virCommandAddArgFormat(cmd, "--br=%s", brname);
    virCommandAddArgFormat(cmd, "--fd=%d", pair[1]);
    virCommandSetErrorBuffer(cmd, &errbuf);
    virCommandDoAsyncIO(cmd);
    virCommandPassFD(cmd, pair[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandClearCaps(cmd);
#ifdef CAP_NET_ADMIN
    virCommandAllowCap(cmd, CAP_NET_ADMIN);
#endif
    if (virCommandRunAsync(cmd, NULL) < 0) {
        *tapfd = -1;
        goto cleanup;
    }

    do {
        *tapfd = recvfd(pair[0], 0);
    } while (*tapfd < 0 && errno == EINTR);

    if (*tapfd < 0) {
        char ebuf[1024];
        char *errstr = NULL;

        if (!(cmdstr = virCommandToString(cmd)))
            goto cleanup;
        virCommandAbort(cmd);

        if (errbuf && *errbuf &&
            virAsprintf(&errstr, "\nstderr=%s", errbuf) < 0)
            goto cleanup;

        virReportError(VIR_ERR_INTERNAL_ERROR,
            _("%s: failed to communicate with bridge helper: %s%s"),
            cmdstr, virStrerror(errno, ebuf, sizeof(ebuf)),
            errstr ? errstr : "");
        VIR_FREE(errstr);
        goto cleanup;
    }

    if (virNetDevTapGetName(*tapfd, ifname) < 0 ||
        virCommandWait(cmd, NULL) < 0) {
        VIR_FORCE_CLOSE(*tapfd);
        *tapfd = -1;
    }

 cleanup:
    VIR_FREE(cmdstr);
    VIR_FREE(errbuf);
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(pair[0]);
    return *tapfd < 0 ? -1 : 0;
}

/* qemuNetworkIfaceConnect - *only* called if actualType is
 * VIR_DOMAIN_NET_TYPE_NETWORK or VIR_DOMAIN_NET_TYPE_BRIDGE (i.e. if
 * the connection is made with a tap device connecting to a bridge
 * device)
 */
int
qemuNetworkIfaceConnect(virDomainDefPtr def,
                        virQEMUDriverPtr driver,
                        virDomainNetDefPtr net,
                        int *tapfd,
                        size_t *tapfdSize)
{
    const char *brname;
    int ret = -1;
    unsigned int tap_create_flags = VIR_NETDEV_TAP_CREATE_IFUP;
    bool template_ifname = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *tunpath = "/dev/net/tun";

    if (net->backend.tap) {
        tunpath = net->backend.tap;
        if (!(virQEMUDriverIsPrivileged(driver))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use custom tap device in session mode"));
            goto cleanup;
        }
    }

    if (!(brname = virDomainNetGetActualBridgeName(net))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing bridge name"));
        goto cleanup;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, VIR_NET_GENERATED_PREFIX) ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (VIR_STRDUP(net->ifname, VIR_NET_GENERATED_PREFIX "%d") < 0)
            goto cleanup;
        /* avoid exposing vnet%d in getXMLDesc or error outputs */
        template_ifname = true;
    }

    if (net->model && STREQ(net->model, "virtio"))
        tap_create_flags |= VIR_NETDEV_TAP_CREATE_VNET_HDR;

    if (virQEMUDriverIsPrivileged(driver)) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, tunpath, tapfd, *tapfdSize,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           tap_create_flags) < 0) {
            virDomainAuditNetDevice(def, net, tunpath, false);
            goto cleanup;
        }
        if (virDomainNetGetActualBridgeMACTableManager(net)
            == VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
            /* libvirt is managing the FDB of the bridge this device
             * is attaching to, so we need to turn off learning and
             * unicast_flood on the device to prevent the kernel from
             * adding any FDB entries for it. We will add add an fdb
             * entry ourselves (during qemuInterfaceStartDevices(),
             * using the MAC address from the interface config.
             */
            if (virNetDevBridgePortSetLearning(brname, net->ifname, false) < 0)
                goto cleanup;
            if (virNetDevBridgePortSetUnicastFlood(brname, net->ifname, false) < 0)
                goto cleanup;
        }
    } else {
        if (qemuCreateInBridgePortWithHelper(cfg, brname,
                                             &net->ifname,
                                             tapfd, tap_create_flags) < 0) {
            virDomainAuditNetDevice(def, net, tunpath, false);
            goto cleanup;
        }
        /* qemuCreateInBridgePortWithHelper can only create a single FD */
        if (*tapfdSize > 1) {
            VIR_WARN("Ignoring multiqueue network request");
            *tapfdSize = 1;
        }
    }

    virDomainAuditNetDevice(def, net, tunpath, true);

    if (cfg->macFilter &&
        ebtablesAddForwardAllowIn(driver->ebtables,
                                  net->ifname,
                                  &net->mac) < 0)
        goto cleanup;

    if (net->filter &&
        virDomainConfNWFilterInstantiate(def->uuid, net) < 0) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        size_t i;
        for (i = 0; i < *tapfdSize && tapfd[i] >= 0; i++)
            VIR_FORCE_CLOSE(tapfd[i]);
        if (template_ifname)
            VIR_FREE(net->ifname);
    }
    virObjectUnref(cfg);

    return ret;
}

static bool
qemuDomainSupportsNicdev(virDomainDefPtr def,
                         virQEMUCapsPtr qemuCaps,
                         virDomainNetDefPtr net)
{
    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        return false;

    /* non-virtio ARM nics require legacy -net nic */
    if (((def->os.arch == VIR_ARCH_ARMV7L) ||
        (def->os.arch == VIR_ARCH_AARCH64)) &&
        net->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO &&
        net->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        return false;

    return true;
}

static bool
qemuDomainSupportsNetdev(virDomainDefPtr def,
                         virQEMUCapsPtr qemuCaps,
                         virDomainNetDefPtr net)
{
    if (!qemuDomainSupportsNicdev(def, qemuCaps, net))
        return false;
    return virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV);
}


static int
qemuBuildObjectCommandLinePropsInternal(const char *key,
                                        const virJSONValue *value,
                                        virBufferPtr buf,
                                        bool nested)
{
    virJSONValuePtr elem;
    virBitmapPtr bitmap = NULL;
    ssize_t pos = -1;
    ssize_t end;
    size_t i;

    switch ((virJSONType) value->type) {
    case VIR_JSON_TYPE_STRING:
        virBufferAsprintf(buf, ",%s=%s", key, value->data.string);
        break;

    case VIR_JSON_TYPE_NUMBER:
        virBufferAsprintf(buf, ",%s=%s", key, value->data.number);
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        if (value->data.boolean)
            virBufferAsprintf(buf, ",%s=yes", key);
        else
            virBufferAsprintf(buf, ",%s=no", key);

        break;

    case VIR_JSON_TYPE_ARRAY:
        if (nested) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("nested -object property arrays are not supported"));
            return -1;
        }

        if (virJSONValueGetArrayAsBitmap(value, &bitmap) == 0) {
            while ((pos = virBitmapNextSetBit(bitmap, pos)) > -1) {
                if ((end = virBitmapNextClearBit(bitmap, pos)) < 0)
                    end = virBitmapLastSetBit(bitmap) + 1;

                if (end - 1 > pos) {
                    virBufferAsprintf(buf, ",%s=%zd-%zd", key, pos, end - 1);
                    pos = end;
                } else {
                    virBufferAsprintf(buf, ",%s=%zd", key, pos);
                }
            }
        } else {
            /* fallback, treat the array as a non-bitmap, adding the key
             * for each member */
            for (i = 0; i < virJSONValueArraySize(value); i++) {
                elem = virJSONValueArrayGet((virJSONValuePtr)value, i);

                /* recurse to avoid duplicating code */
                if (qemuBuildObjectCommandLinePropsInternal(key, elem, buf,
                                                            true) < 0)
                    return -1;
            }
        }
        break;

    case VIR_JSON_TYPE_OBJECT:
    case VIR_JSON_TYPE_NULL:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("NULL and OBJECT JSON types can't be converted to "
                         "commandline string"));
        return -1;
    }

    virBitmapFree(bitmap);
    return 0;
}


static int
qemuBuildObjectCommandLineProps(const char *key,
                                const virJSONValue *value,
                                void *opaque)
{
    return qemuBuildObjectCommandLinePropsInternal(key, value, opaque, false);
}


char *
qemuBuildObjectCommandlineFromJSON(const char *type,
                                   const char *alias,
                                   virJSONValuePtr props)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *ret = NULL;

    virBufferAsprintf(&buf, "%s,id=%s", type, alias);

    if (virJSONValueObjectForeachKeyValue(props,
                                          qemuBuildObjectCommandLineProps,
                                          &buf) < 0)
        goto cleanup;

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}


/**
 * qemuOpenVhostNet:
 * @def: domain definition
 * @net: network definition
 * @qemuCaps: qemu binary capabilities
 * @vhostfd: array of opened vhost-net device
 * @vhostfdSize: number of file descriptors in @vhostfd array
 *
 * Open vhost-net, multiple times - if requested.
 * In case, no vhost-net is needed, @vhostfdSize is set to 0
 * and 0 is returned.
 *
 * Returns: 0 on success
 *         -1 on failure
 */
int
qemuOpenVhostNet(virDomainDefPtr def,
                 virDomainNetDefPtr net,
                 virQEMUCapsPtr qemuCaps,
                 int *vhostfd,
                 size_t *vhostfdSize)
{
    size_t i;
    const char *vhostnet_path = net->backend.vhost;

    if (!vhostnet_path)
        vhostnet_path = "/dev/vhost-net";

    /* If running a plain QEMU guest, or
     * if the config says explicitly to not use vhost, return now*/
    if (def->virtType != VIR_DOMAIN_VIRT_KVM ||
        net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_QEMU) {
        *vhostfdSize = 0;
        return 0;
    }

    /* If qemu doesn't support vhost-net mode (including the -netdev command
     * option), don't try to open the device.
     */
    if (!(virQEMUCapsGet(qemuCaps, QEMU_CAPS_VHOST_NET) &&
          qemuDomainSupportsNetdev(def, qemuCaps, net))) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("vhost-net is not supported with "
                                   "this QEMU binary"));
            return -1;
        }
        *vhostfdSize = 0;
        return 0;
    }

    /* If the nic model isn't virtio, don't try to open. */
    if (!(net->model && STREQ(net->model, "virtio"))) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("vhost-net is only supported for "
                                   "virtio network interfaces"));
            return -1;
        }
        *vhostfdSize = 0;
        return 0;
    }

    for (i = 0; i < *vhostfdSize; i++) {
        vhostfd[i] = open(vhostnet_path, O_RDWR);

        /* If the config says explicitly to use vhost and we couldn't open it,
         * report an error.
         */
        if (vhostfd[i] < 0) {
            virDomainAuditNetDevice(def, net, vhostnet_path, false);
            if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("vhost-net was requested for an interface, "
                                       "but is unavailable"));
                goto error;
            }
            VIR_WARN("Unable to open vhost-net. Opened so far %zu, requested %zu",
                     i, *vhostfdSize);
            *vhostfdSize = i;
            break;
        }
    }
    virDomainAuditNetDevice(def, net, vhostnet_path, *vhostfdSize);
    return 0;

 error:
    while (i--)
        VIR_FORCE_CLOSE(vhostfd[i]);

    return -1;
}


int
qemuNetworkPrepareDevices(virDomainDefPtr def)
{
    int ret = -1;
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];
        int actualType;

        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (networkAllocateActualDevice(def, net) < 0)
            goto cleanup;

        actualType = virDomainNetGetActualType(net);
        if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            /* Each type='hostdev' network device must also have a
             * corresponding entry in the hostdevs array. For netdevs
             * that are hardcoded as type='hostdev', this is already
             * done by the parser, but for those allocated from a
             * network / determined at runtime, we need to do it
             * separately.
             */
            virDomainHostdevDefPtr hostdev = virDomainNetGetActualHostdev(net);
            virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;

            if (virDomainHostdevFind(def, hostdev, NULL) >= 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("PCI device %04x:%02x:%02x.%x "
                                 "allocated from network %s is already "
                                 "in use by domain %s"),
                               pcisrc->addr.domain, pcisrc->addr.bus,
                               pcisrc->addr.slot, pcisrc->addr.function,
                               net->data.network.name, def->name);
                goto cleanup;
            }
            if (virDomainHostdevInsert(def, hostdev) < 0)
                goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    return ret;
}

static int qemuDomainDeviceAliasIndex(const virDomainDeviceInfo *info,
                                      const char *prefix)
{
    int idx;

    if (!info->alias)
        return -1;
    if (!STRPREFIX(info->alias, prefix))
        return -1;

    if (virStrToLong_i(info->alias + strlen(prefix), NULL, 10, &idx) < 0)
        return -1;

    return idx;
}


int qemuDomainNetVLAN(virDomainNetDefPtr def)
{
    return qemuDomainDeviceAliasIndex(&def->info, "net");
}


char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk,
                               virQEMUCapsPtr qemuCaps)
{
    char *ret;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        ignore_value(virAsprintf(&ret, "%s%s", QEMU_DRIVE_HOST_PREFIX,
                                 disk->info.alias));
    } else {
        ignore_value(VIR_STRDUP(ret, disk->info.alias));
    }
    return ret;
}


/* Names used before -drive supported the id= option */
static int qemuAssignDeviceDiskAliasFixed(virDomainDiskDefPtr disk)
{
    int busid, devid;
    int ret;
    char *dev_name;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot convert disk '%s' to bus/device index"),
                       disk->dst);
        return -1;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "ide%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "ide%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "scsi%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "scsi%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_FDC:
        ret = virAsprintf(&dev_name, "floppy%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        ret = virAsprintf(&dev_name, "virtio%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_XEN:
        ret = virAsprintf(&dev_name, "xenblk%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SD:
        ret = virAsprintf(&dev_name, "sd%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_USB:
        ret = virAsprintf(&dev_name, "usb%d", devid);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported disk name mapping for bus '%s'"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (ret == -1)
        return -1;

    disk->info.alias = dev_name;

    return 0;
}

static int
qemuSetSCSIControllerModel(virDomainDefPtr def,
                           virQEMUCapsPtr qemuCaps,
                           int *model)
{
    if (*model > 0) {
        switch (*model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "the LSI 53C895A SCSI controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "virtio scsi controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            /*TODO: need checking work here if necessary */
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_MEGASAS)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "the LSI SAS1078 controller"));
                return -1;
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller model: %s"),
                           virDomainControllerModelSCSITypeToString(*model));
            return -1;
        }
    } else {
        if (ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries")) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI;
        } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI)) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;
        } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI)) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to determine model for scsi controller"));
            return -1;
        }
    }

    return 0;
}

/* Our custom -drive naming scheme used with id= */
static int
qemuAssignDeviceDiskAliasCustom(virDomainDefPtr def,
                                virDomainDiskDefPtr disk,
                                virQEMUCapsPtr qemuCaps)
{
    const char *prefix = virDomainDiskBusTypeToString(disk->bus);
    int controllerModel = -1;

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            controllerModel =
                virDomainDeviceFindControllerModel(def, &disk->info,
                                                   VIR_DOMAIN_CONTROLLER_TYPE_SCSI);

            if ((qemuSetSCSIControllerModel(def, qemuCaps, &controllerModel)) < 0)
                return -1;
        }

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI ||
            controllerModel == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.unit) < 0)
                return -1;
        } else {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.target,
                            disk->info.addr.drive.unit) < 0)
                return -1;
        }
    } else {
        int idx = virDiskNameToIndex(disk->dst);
        if (virAsprintf(&disk->info.alias, "%s-disk%d", prefix, idx) < 0)
            return -1;
    }

    return 0;
}


int
qemuAssignDeviceDiskAlias(virDomainDefPtr vmdef,
                          virDomainDiskDefPtr def,
                          virQEMUCapsPtr qemuCaps)
{
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        return qemuAssignDeviceDiskAliasCustom(vmdef, def, qemuCaps);
    else
        return qemuAssignDeviceDiskAliasFixed(def);
}


int
qemuAssignDeviceNetAlias(virDomainDefPtr def, virDomainNetDefPtr net, int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nnets; i++) {
            int thisidx;

            if (virDomainNetGetActualType(def->nets[i])
                == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
                /* type='hostdev' interfaces have a hostdev%d alias */
               continue;
            }
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "net")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for network device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&net->info.alias, "net%d", idx) < 0)
        return -1;
    return 0;
}


int
qemuAssignDeviceHostdevAlias(virDomainDefPtr def, virDomainHostdevDefPtr hostdev, int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nhostdevs; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(def->hostdevs[i]->info, "hostdev")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for hostdev device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&hostdev->info->alias, "hostdev%d", idx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceRedirdevAlias(virDomainDefPtr def, virDomainRedirdevDefPtr redirdev, int idx)
{
    if (idx == -1) {
        size_t i;
        idx = 0;
        for (i = 0; i < def->nredirdevs; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->redirdevs[i]->info, "redir")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for redirected device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&redirdev->info.alias, "redir%d", idx) < 0)
        return -1;
    return 0;
}


int
qemuAssignDeviceControllerAlias(virDomainDefPtr domainDef,
                                virQEMUCapsPtr qemuCaps,
                                virDomainControllerDefPtr controller)
{
    const char *prefix = virDomainControllerTypeToString(controller->type);

    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
        if (!virQEMUCapsHasPCIMultiBus(qemuCaps, domainDef)) {
            /* qemus that don't support multiple PCI buses have
             * hardcoded the name of their single PCI controller as
             * "pci".
             */
            return VIR_STRDUP(controller->info.alias, "pci");
        } else if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
            /* The pcie-root controller on Q35 machinetypes uses a
             * different naming convention ("pcie.0"), because it is
             * hardcoded that way in qemu.
             */
            return virAsprintf(&controller->info.alias, "pcie.%d", controller->idx);
        }
        /* All other PCI controllers use the consistent "pci.%u"
         * (including the hardcoded pci-root controller on
         * multibus-capable qemus).
         */
        return virAsprintf(&controller->info.alias, "pci.%d", controller->idx);
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE) {
        /* for any machine based on e.g. I440FX or G3Beige, the
         * first (and currently only) IDE controller is an integrated
         * controller hardcoded with id "ide"
         */
        if (qemuDomainMachineHasBuiltinIDE(domainDef) &&
            controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "ide");
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA) {
        /* for any Q35 machine, the first SATA controller is the
         * integrated one, and it too is hardcoded with id "ide"
         */
        if (qemuDomainMachineIsQ35(domainDef) && controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "ide");
    } else if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
        /* first USB device is "usb", others are normal "usb%d" */
        if (controller->idx == 0)
            return VIR_STRDUP(controller->info.alias, "usb");
    }
    /* all other controllers use the default ${type}${index} naming
     * scheme for alias/id.
     */
    return virAsprintf(&controller->info.alias, "%s%d", prefix, controller->idx);
}

static ssize_t
qemuGetNextChrDevIndex(virDomainDefPtr def,
                       virDomainChrDefPtr chr,
                       const char *prefix)
{
    const virDomainChrDef **arrPtr;
    size_t cnt;
    size_t i;
    ssize_t idx = 0;
    const char *prefix2 = NULL;

    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE)
        prefix2 = "serial";

    virDomainChrGetDomainPtrs(def, chr->deviceType, &arrPtr, &cnt);

    for (i = 0; i < cnt; i++) {
        ssize_t thisidx;
        if (((thisidx = qemuDomainDeviceAliasIndex(&arrPtr[i]->info, prefix)) < 0) &&
            (prefix2 &&
             (thisidx = qemuDomainDeviceAliasIndex(&arrPtr[i]->info, prefix2)) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to determine device index for character device"));
            return -1;
        }
        if (thisidx >= idx)
            idx = thisidx + 1;
    }

    return idx;
}


int
qemuAssignDeviceRNGAlias(virDomainRNGDefPtr rng,
                         size_t idx)
{
    if (virAsprintf(&rng->info.alias, "rng%zu", idx) < 0)
        return -1;

    return 0;
}


int
qemuAssignDeviceChrAlias(virDomainDefPtr def,
                         virDomainChrDefPtr chr,
                         ssize_t idx)
{
    const char *prefix = NULL;

    switch ((virDomainChrDeviceType) chr->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        prefix = "parallel";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        prefix = "serial";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        prefix = "console";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        prefix = "channel";
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        return -1;
    }

    if (idx == -1 && (idx = qemuGetNextChrDevIndex(def, chr, prefix)) < 0)
        return -1;

    return virAsprintf(&chr->info.alias, "%s%zd", prefix, idx);
}

int
qemuAssignDeviceAliases(virDomainDefPtr def, virQEMUCapsPtr qemuCaps)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (qemuAssignDeviceDiskAlias(def, def->disks[i], qemuCaps) < 0)
            return -1;
    }
    for (i = 0; i < def->nnets; i++) {
        /* type='hostdev' interfaces are also on the hostdevs list,
         * and will have their alias assigned with other hostdevs.
         */
        if (virDomainNetGetActualType(def->nets[i])
            != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
            qemuAssignDeviceNetAlias(def, def->nets[i], i) < 0) {
            return -1;
        }
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        return 0;

    for (i = 0; i < def->nfss; i++) {
        if (virAsprintf(&def->fss[i]->info.alias, "fs%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nsounds; i++) {
        if (virAsprintf(&def->sounds[i]->info.alias, "sound%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nhostdevs; i++) {
        if (qemuAssignDeviceHostdevAlias(def, def->hostdevs[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nredirdevs; i++) {
        if (qemuAssignDeviceRedirdevAlias(def, def->redirdevs[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nvideos; i++) {
        if (virAsprintf(&def->videos[i]->info.alias, "video%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->ncontrollers; i++) {
        if (qemuAssignDeviceControllerAlias(def, qemuCaps, def->controllers[i]) < 0)
            return -1;
    }
    for (i = 0; i < def->ninputs; i++) {
        if (virAsprintf(&def->inputs[i]->info.alias, "input%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nparallels; i++) {
        if (qemuAssignDeviceChrAlias(def, def->parallels[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nserials; i++) {
        if (qemuAssignDeviceChrAlias(def, def->serials[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nchannels; i++) {
        if (qemuAssignDeviceChrAlias(def, def->channels[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nconsoles; i++) {
        if (qemuAssignDeviceChrAlias(def, def->consoles[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nhubs; i++) {
        if (virAsprintf(&def->hubs[i]->info.alias, "hub%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nshmems; i++) {
        if (virAsprintf(&def->shmems[i]->info.alias, "shmem%zu", i) < 0)
            return -1;
    }
    for (i = 0; i < def->nsmartcards; i++) {
        if (virAsprintf(&def->smartcards[i]->info.alias, "smartcard%zu", i) < 0)
            return -1;
    }
    if (def->watchdog) {
        if (virAsprintf(&def->watchdog->info.alias, "watchdog%d", 0) < 0)
            return -1;
    }
    if (def->memballoon) {
        if (virAsprintf(&def->memballoon->info.alias, "balloon%d", 0) < 0)
            return -1;
    }
    for (i = 0; i < def->nrngs; i++) {
        if (qemuAssignDeviceRNGAlias(def->rngs[i], i) < 0)
            return -1;
    }
    if (def->tpm) {
        if (virAsprintf(&def->tpm->info.alias, "tpm%d", 0) < 0)
            return -1;
    }
    for (i = 0; i < def->nmems; i++) {
        if (virAsprintf(&def->mems[i]->info.alias, "dimm%zu", i) < 0)
            return -1;
    }

    return 0;
}


static void
qemuDomainPrimeVirtioDeviceAddresses(virDomainDefPtr def,
                                     virDomainDeviceAddressType type)
{
    /*
       declare address-less virtio devices to be of address type 'type'
       disks, networks, consoles, controllers, memballoon and rng in this
       order
       if type is ccw filesystem devices are declared to be of address type ccw
    */
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->disks[i]->info.type = type;
    }

    for (i = 0; i < def->nnets; i++) {
        if (STREQ(def->nets[i]->model, "virtio") &&
            def->nets[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            def->nets[i]->info.type = type;
        }
    }

    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->inputs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->inputs[i]->info.type = type;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        if ((def->controllers[i]->type ==
             VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL ||
             def->controllers[i]->type ==
             VIR_DOMAIN_CONTROLLER_TYPE_SCSI) &&
            def->controllers[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->controllers[i]->info.type = type;
    }

    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        def->memballoon->info.type = type;

    for (i = 0; i < def->nrngs; i++) {
        if (def->rngs[i]->model == VIR_DOMAIN_RNG_MODEL_VIRTIO &&
            def->rngs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->rngs[i]->info.type = type;
    }

    if (type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        for (i = 0; i < def->nfss; i++) {
            if (def->fss[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                def->fss[i]->info.type = type;
        }
    }
}


/*
 * Three steps populating CCW devnos
 * 1. Allocate empty address set
 * 2. Gather addresses with explicit devno
 * 3. Assign defaults to the rest
 */
static int
qemuDomainAssignS390Addresses(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virDomainObjPtr obj)
{
    int ret = -1;
    virDomainCCWAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (qemuDomainMachineIsS390CCW(def) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW);

        if (!(addrs = virDomainCCWAddressSetCreate()))
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, virDomainCCWAddressValidate,
                                       addrs) < 0)
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, virDomainCCWAddressAllocate,
                                       addrs) < 0)
            goto cleanup;
    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
        /* deal with legacy virtio-s390 */
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390);
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            /* if this is the live domain object, we persist the CCW addresses*/
            virDomainCCWAddressSetFree(priv->ccwaddrs);
            priv->persistentAddrs = 1;
            priv->ccwaddrs = addrs;
            addrs = NULL;
        } else {
            priv->persistentAddrs = 0;
        }
    }
    ret = 0;

 cleanup:
    virDomainCCWAddressSetFree(addrs);

    return ret;
}

static int
qemuDomainAssignARMVirtioMMIOAddresses(virDomainDefPtr def,
                                       virQEMUCapsPtr qemuCaps)
{
    if (((def->os.arch == VIR_ARCH_ARMV7L) ||
        (def->os.arch == VIR_ARCH_AARCH64)) &&
        (STRPREFIX(def->os.machine, "vexpress-") ||
            STREQ(def->os.machine, "virt") ||
            STRPREFIX(def->os.machine, "virt-")) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MMIO)) {
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO);
    }
    return 0;
}

static int
qemuSpaprVIOFindByReg(virDomainDefPtr def ATTRIBUTE_UNUSED,
                      virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                      virDomainDeviceInfoPtr info, void *opaque)
{
    virDomainDeviceInfoPtr target = opaque;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Match a dev that has a reg, is not us, and has a matching reg */
    if (info->addr.spaprvio.has_reg && info != target &&
        info->addr.spaprvio.reg == target->addr.spaprvio.reg)
        /* Has to be < 0 so virDomainDeviceInfoIterate() will exit */
        return -1;

    return 0;
}

static int
qemuAssignSpaprVIOAddress(virDomainDefPtr def, virDomainDeviceInfoPtr info,
                          unsigned long long default_reg)
{
    bool user_reg;
    int ret;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Check if the user has assigned the reg already, if so use it */
    user_reg = info->addr.spaprvio.has_reg;
    if (!user_reg) {
        info->addr.spaprvio.reg = default_reg;
        info->addr.spaprvio.has_reg = true;
    }

    ret = virDomainDeviceInfoIterate(def, qemuSpaprVIOFindByReg, info);
    while (ret != 0) {
        if (user_reg) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("spapr-vio address %#llx already in use"),
                           info->addr.spaprvio.reg);
            return -EEXIST;
        }

        /* We assigned the reg, so try a new value */
        info->addr.spaprvio.reg += 0x1000;
        ret = virDomainDeviceInfoIterate(def, qemuSpaprVIOFindByReg, info);
    }

    return 0;
}


static int
qemuDomainAssignVirtioSerialAddresses(virDomainDefPtr def,
                                      virDomainObjPtr obj)
{
    int ret = -1;
    size_t i;
    virDomainVirtioSerialAddrSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!(addrs = virDomainVirtioSerialAddrSetCreate()))
        goto cleanup;

    if (virDomainVirtioSerialAddrSetAddControllers(addrs, def) < 0)
        goto cleanup;

    if (virDomainDeviceInfoIterate(def, virDomainVirtioSerialAddrReserve,
                                   addrs) < 0)
        goto cleanup;

    VIR_DEBUG("Finished reserving existing ports");

    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDefPtr chr = def->consoles[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssign(def, addrs, &chr->info, true) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr chr = def->channels[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
            chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssign(def, addrs, &chr->info, false) < 0)
            goto cleanup;
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        /* if this is the live domain object, we persist the addresses */
        virDomainVirtioSerialAddrSetFree(priv->vioserialaddrs);
        priv->persistentAddrs = 1;
        priv->vioserialaddrs = addrs;
        addrs = NULL;
    }
    ret = 0;

 cleanup:
    virDomainVirtioSerialAddrSetFree(addrs);
    return ret;
}


int qemuDomainAssignSpaprVIOAddresses(virDomainDefPtr def,
                                      virQEMUCapsPtr qemuCaps)
{
    size_t i;
    int ret = -1;
    int model;

    /* Default values match QEMU. See spapr_(llan|vscsi|vty).c */

    for (i = 0; i < def->nnets; i++) {
        if (def->nets[i]->model &&
            STREQ(def->nets[i]->model, "spapr-vlan"))
            def->nets[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->nets[i]->info,
                                      VIO_ADDR_NET) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        model = def->controllers[i]->model;
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            if (qemuSetSCSIControllerModel(def, qemuCaps, &model) < 0)
                goto cleanup;
        }

        if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI &&
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->controllers[i]->info,
                                      VIO_ADDR_SCSI) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nserials; i++) {
        if (def->serials[i]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries"))
            def->serials[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->serials[i]->info,
                                      VIO_ADDR_SERIAL) < 0)
            goto cleanup;
    }

    if (def->nvram) {
        if (ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries"))
            def->nvram->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->nvram->info,
                                      VIO_ADDR_NVRAM) < 0)
            goto cleanup;
    }

    /* No other devices are currently supported on spapr-vio */

    ret = 0;

 cleanup:
    return ret;
}


static int
qemuCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                      virDomainDeviceDefPtr device,
                      virDomainDeviceInfoPtr info,
                      void *opaque)
{
    virDomainPCIAddressSetPtr addrs = opaque;
    int ret = -1;
    virDevicePCIAddressPtr addr = &info->addr.pci;
    bool entireSlot;
    /* flags may be changed from default below */
    virDomainPCIConnectFlags flags = (VIR_PCI_CONNECT_HOTPLUGGABLE |
                                      VIR_PCI_CONNECT_TYPE_PCI);

    if ((info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        || ((device->type == VIR_DOMAIN_DEVICE_HOSTDEV) &&
            (device->data.hostdev->parent.type != VIR_DOMAIN_DEVICE_NONE))) {
        /* If a hostdev has a parent, its info will be a part of the
         * parent, and will have its address collected during the scan
         * of the parent's device type.
        */
        return 0;
    }

    /* Change flags according to differing requirements of different
     * devices.
     */
    switch (device->type) {
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        switch (device->data.controller->type) {
        case  VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            switch (device->data.controller->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                /* pci-bridge needs a PCI slot, but it isn't
                 * hot-pluggable, so it doesn't need a hot-pluggable slot.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCI;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                /* pci-bridge needs a PCIe slot, but it isn't
                 * hot-pluggable, so it doesn't need a hot-pluggable slot.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                /* pcie-root-port can only connect to pcie-root, isn't
                 * hot-pluggable
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_ROOT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                /* pcie-switch can only connect to a true
                 * pcie bus, and can't be hot-plugged.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_PORT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                /* pcie-switch-downstream-port can only connect to a
                 * pcie-switch-upstream-port, and can't be hot-plugged.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_SWITCH;
                break;
            default:
                break;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            /* SATA controllers aren't hot-plugged, and can be put in
             * either a PCI or PCIe slot
             */
            flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
           /* allow UHCI and EHCI controllers to be manually placed on
            * the PCIe bus (but don't put them there automatically)
            */
           switch (device->data.controller->model) {
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
              flags = VIR_PCI_CONNECT_TYPE_PCI;
              break;
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
              /* should this be PCIE-only? Or do we need to allow PCI
               * for backward compatibility?
               */
              flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
              break;
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
              /* Allow these for PCI only */
              break;
           }
        }
        break;

    case VIR_DOMAIN_DEVICE_SOUND:
        switch (device->data.sound->model) {
        case VIR_DOMAIN_SOUND_MODEL_ICH6:
        case VIR_DOMAIN_SOUND_MODEL_ICH9:
            flags = VIR_PCI_CONNECT_TYPE_PCI;
            break;
        }
        break;

    case VIR_DOMAIN_DEVICE_VIDEO:
        /* video cards aren't hot-plugged, and can be put in either a
         * PCI or PCIe slot
         */
        flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
        break;
    }

    /* Ignore implicit controllers on slot 0:0:1.0:
     * implicit IDE controller on 0:0:1.1 (no qemu command line)
     * implicit USB controller on 0:0:1.2 (-usb)
     *
     * If the machine does have a PCI bus, they will get reserved
     * in qemuAssignDevicePCISlots().
     */

    /* These are the IDE and USB controllers in the PIIX3, hardcoded
     * to bus 0 slot 1.  They cannot be attached to a PCIe slot, only
     * PCI.
     */
    if (device->type == VIR_DOMAIN_DEVICE_CONTROLLER && addr->domain == 0 &&
        addr->bus == 0 && addr->slot == 1) {
        virDomainControllerDefPtr cont = device->data.controller;

        if ((cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE && cont->idx == 0 &&
             addr->function == 1) ||
            (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB && cont->idx == 0 &&
             (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
              cont->model == -1) && addr->function == 2)) {
            /* Note the check for nbuses > 0 - if there are no PCI
             * buses, we skip this check. This is a quirk required for
             * some machinetypes such as s390, which pretend to have a
             * PCI bus for long enough to generate the "-usb" on the
             * commandline, but that don't really care if a PCI bus
             * actually exists. */
            if (addrs->nbuses > 0 &&
                !(addrs->buses[0].flags & VIR_PCI_CONNECT_TYPE_PCI)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Bus 0 must be PCI for integrated PIIX3 "
                                 "USB or IDE controllers"));
                return -1;
            } else {
                return 0;
            }
        }
    }

    entireSlot = (addr->function == 0 &&
                  addr->multi != VIR_TRISTATE_SWITCH_ON);

    if (virDomainPCIAddressReserveAddr(addrs, addr, flags,
                                       entireSlot, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}

static bool
qemuDomainSupportsPCI(virDomainDefPtr def, virQEMUCapsPtr qemuCaps)
{
    if ((def->os.arch != VIR_ARCH_ARMV7L) && (def->os.arch != VIR_ARCH_AARCH64))
        return true;

    if (STREQ(def->os.machine, "versatilepb"))
        return true;

    if ((STREQ(def->os.machine, "virt") ||
         STRPREFIX(def->os.machine, "virt-")) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_GPEX))
        return true;

    return false;
}

static bool
qemuDomainPCIBusFullyReserved(virDomainPCIAddressBusPtr bus)
{
    size_t i;

    for (i = bus->minSlot; i <= bus->maxSlot; i++)
        if (!bus->slots[i])
            return false;

    return true;
}


int qemuDomainAssignAddresses(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virDomainObjPtr obj)
{
    int rc;

    rc = qemuDomainAssignVirtioSerialAddresses(def, obj);
    if (rc)
        return rc;

    rc = qemuDomainAssignSpaprVIOAddresses(def, qemuCaps);
    if (rc)
        return rc;

    rc = qemuDomainAssignS390Addresses(def, qemuCaps, obj);
    if (rc)
        return rc;

    rc = qemuDomainAssignARMVirtioMMIOAddresses(def, qemuCaps);
    if (rc)
        return rc;

    return qemuDomainAssignPCIAddresses(def, qemuCaps, obj);
}


virDomainPCIAddressSetPtr
qemuDomainPCIAddressSetCreate(virDomainDefPtr def,
                              unsigned int nbuses,
                              bool dryRun)
{
    virDomainPCIAddressSetPtr addrs;
    size_t i;

    if ((addrs = virDomainPCIAddressSetAlloc(nbuses)) == NULL)
        return NULL;

    addrs->nbuses = nbuses;
    addrs->dryRun = dryRun;

    /* As a safety measure, set default model='pci-root' for first pci
     * controller and 'pci-bridge' for all subsequent. After setting
     * those defaults, then scan the config and set the actual model
     * for all addrs[idx]->bus that already have a corresponding
     * controller in the config.
     *
     */
    if (nbuses > 0)
        virDomainPCIAddressBusSetModel(&addrs->buses[0],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT);
    for (i = 1; i < nbuses; i++) {
        virDomainPCIAddressBusSetModel(&addrs->buses[i],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE);
    }

    for (i = 0; i < def->ncontrollers; i++) {
        size_t idx = def->controllers[i]->idx;

        if (def->controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        if (idx >= addrs->nbuses) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Inappropriate new pci controller index %zu "
                             "not found in addrs"), idx);
            goto error;
        }

        if (virDomainPCIAddressBusSetModel(&addrs->buses[idx],
                                           def->controllers[i]->model) < 0)
            goto error;
        }

    if (virDomainDeviceInfoIterate(def, qemuCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

 error:
    virDomainPCIAddressSetFree(addrs);
    return NULL;
}


void
qemuDomainReleaseDeviceAddress(virDomainObjPtr vm,
                               virDomainDeviceInfoPtr info,
                               const char *devstr)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!devstr)
        devstr = info->alias;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
        qemuDomainMachineIsS390CCW(vm->def) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW) &&
        virDomainCCWAddressReleaseAddr(priv->ccwaddrs, info) < 0)
        VIR_WARN("Unable to release CCW address on %s",
                 NULLSTR(devstr));
    else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
             virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
             virDomainPCIAddressReleaseSlot(priv->pciaddrs,
                                            &info->addr.pci) < 0)
        VIR_WARN("Unable to release PCI address on %s",
                 NULLSTR(devstr));
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL &&
        virDomainVirtioSerialAddrRelease(priv->vioserialaddrs, info) < 0)
        VIR_WARN("Unable to release virtio-serial address on %s",
                 NULLSTR(devstr));
}


#define IS_USB2_CONTROLLER(ctrl) \
    (((ctrl)->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) && \
     ((ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3))


static int
qemuValidateDevicePCISlotsPIIX3(virDomainDefPtr def,
                                virQEMUCapsPtr qemuCaps,
                                virDomainPCIAddressSetPtr addrs)
{
    int ret = -1;
    size_t i;
    virDevicePCIAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;

    /* Verify that first IDE and USB controllers (if any) is on the PIIX3, fn 1 */
    for (i = 0; i < def->ncontrollers; i++) {
        /* First IDE controller lives on the PIIX3 at slot=1, function=1 */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Primary IDE controller must have PCI address 0:0:1.1"));
                    goto cleanup;
                }
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 1;
            }
        } else if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                   def->controllers[i]->idx == 0 &&
                   (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
                    def->controllers[i]->model == -1)) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 2) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PIIX3 USB controller must have PCI address 0:0:1.2"));
                    goto cleanup;
                }
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 2;
            }
        }
    }

    /* PIIX3 (ISA bridge, IDE controller, something else unknown, USB controller)
     * hardcoded slot=1, multifunction device
     */
    if (addrs->nbuses) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 1;
        if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
            goto cleanup;
    }

    if (def->nvideos > 0) {
        /* Because the PIIX3 integrated IDE/USB controllers are
         * already at slot 1, when qemu looks for the first free slot
         * to place the VGA controller (which is always the first
         * device added after integrated devices), it *always* ends up
         * at slot 2.
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (primaryVideo->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 2;

            if (!(addrStr = virDomainPCIAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, false))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (virDomainPCIAddressReserveNextSlot(addrs,
                                                           &primaryVideo->info,
                                                           flags) < 0)
                        goto cleanup;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:2.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
                    goto cleanup;
                primaryVideo->info.addr.pci = tmp_addr;
                primaryVideo->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            }
        } else if (!qemuDeviceVideoUsable) {
            if (primaryVideo->info.addr.pci.domain != 0 ||
                primaryVideo->info.addr.pci.bus != 0 ||
                primaryVideo->info.addr.pci.slot != 2 ||
                primaryVideo->info.addr.pci.function != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Primary video card must have PCI address 0:0:2.0"));
                goto cleanup;
            }
            /* If TYPE == PCI, then qemuCollectPCIAddress() function
             * has already reserved the address, so we must skip */
        }
    } else if (addrs->nbuses && !qemuDeviceVideoUsable) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 2;

        if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
            VIR_DEBUG("PCI address 0:0:2.0 in use, future addition of a video"
                      " device will not be possible without manual"
                      " intervention");
        } else if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0) {
            goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    VIR_FREE(addrStr);
    return ret;
}


static int
qemuDomainValidateDevicePCISlotsQ35(virDomainDefPtr def,
                                    virQEMUCapsPtr qemuCaps,
                                    virDomainPCIAddressSetPtr addrs)
{
    int ret = -1;
    size_t i;
    virDevicePCIAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_TYPE_PCIE;

    for (i = 0; i < def->ncontrollers; i++) {
        switch (def->controllers[i]->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            /* Verify that the first SATA controller is at 00:1F.2 the
             * q35 machine type *always* has a SATA controller at this
             * address.
             */
            if (def->controllers[i]->idx == 0) {
                if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                    if (def->controllers[i]->info.addr.pci.domain != 0 ||
                        def->controllers[i]->info.addr.pci.bus != 0 ||
                        def->controllers[i]->info.addr.pci.slot != 0x1F ||
                        def->controllers[i]->info.addr.pci.function != 2) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Primary SATA controller must have PCI address 0:0:1f.2"));
                        goto cleanup;
                    }
                } else {
                    def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = 0x1F;
                    def->controllers[i]->info.addr.pci.function = 2;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
            if ((def->controllers[i]->model
                 == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1) &&
                (def->controllers[i]->info.type
                 == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
                /* Try to assign the first found USB2 controller to
                 * 00:1D.0 and 2nd to 00:1A.0 (because that is their
                 * standard location on real Q35 hardware) unless they
                 * are already taken, but don't insist on it.
                 *
                 * (NB: all other controllers at the same index will
                 * get assigned to the same slot as the UHCI1 when
                 * addresses are later assigned to all devices.)
                 */
                bool assign = false;

                memset(&tmp_addr, 0, sizeof(tmp_addr));
                tmp_addr.slot = 0x1D;
                if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                    assign = true;
                } else {
                    tmp_addr.slot = 0x1A;
                    if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr))
                        assign = true;
                }
                if (assign) {
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr,
                                                       flags, false, true) < 0)
                        goto cleanup;
                    def->controllers[i]->info.type
                        = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = tmp_addr.slot;
                    def->controllers[i]->info.addr.pci.function = 0;
                    def->controllers[i]->info.addr.pci.multi
                       = VIR_TRISTATE_SWITCH_ON;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            if (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE &&
                def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                /* Try to assign this bridge to 00:1E.0 (because that
                * is its standard location on real hardware) unless
                * it's already taken, but don't insist on it.
                */
                memset(&tmp_addr, 0, sizeof(tmp_addr));
                tmp_addr.slot = 0x1E;
                if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr,
                                                       flags, true, false) < 0)
                        goto cleanup;
                    def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = 0x1E;
                    def->controllers[i]->info.addr.pci.function = 0;
                }
            }
            break;
        }
    }

    /* Reserve slot 0x1F function 0 (ISA bridge, not in config model)
     * and function 3 (SMBus, also not (yet) in config model). As with
     * the SATA controller, these devices are always present in a q35
     * machine; there is no way to not have them.
     */
    if (addrs->nbuses) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 0x1F;
        tmp_addr.function = 0;
        tmp_addr.multi = VIR_TRISTATE_SWITCH_ON;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags,
                                           false, false) < 0)
           goto cleanup;
        tmp_addr.function = 3;
        tmp_addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags,
                                           false, false) < 0)
           goto cleanup;
    }

    if (def->nvideos > 0) {
        /* NB: unlike the pc machinetypes, on q35 machinetypes the
         * integrated devices are at slot 0x1f, so when qemu looks for
         * the first free lot for the first VGA, it will always be at
         * slot 1 (which was used up by the integrated PIIX3 devices
         * on pc machinetypes).
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (primaryVideo->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 1;

            if (!(addrStr = virDomainPCIAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, false))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (virDomainPCIAddressReserveNextSlot(addrs,
                                                           &primaryVideo->info,
                                                           flags) < 0)
                        goto cleanup;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:1.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
                    goto cleanup;
                primaryVideo->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                primaryVideo->info.addr.pci = tmp_addr;
            }
        } else if (!qemuDeviceVideoUsable) {
            if (primaryVideo->info.addr.pci.domain != 0 ||
                primaryVideo->info.addr.pci.bus != 0 ||
                primaryVideo->info.addr.pci.slot != 1 ||
                primaryVideo->info.addr.pci.function != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Primary video card must have PCI address 0:0:1.0"));
                goto cleanup;
            }
            /* If TYPE == PCI, then qemuCollectPCIAddress() function
             * has already reserved the address, so we must skip */
        }
    } else if (addrs->nbuses && !qemuDeviceVideoUsable) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 1;

        if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
            VIR_DEBUG("PCI address 0:0:1.0 in use, future addition of a video"
                      " device will not be possible without manual"
                      " intervention");
            virResetLastError();
        } else if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0) {
            goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    VIR_FREE(addrStr);
    return ret;
}

static int
qemuValidateDevicePCISlotsChipsets(virDomainDefPtr def,
                                   virQEMUCapsPtr qemuCaps,
                                   virDomainPCIAddressSetPtr addrs)
{
    if (qemuDomainMachineIsI440FX(def) &&
        qemuValidateDevicePCISlotsPIIX3(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    if (qemuDomainMachineIsQ35(def) &&
        qemuDomainValidateDevicePCISlotsQ35(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    return 0;
}

int
qemuDomainAssignPCIAddresses(virDomainDefPtr def,
                             virQEMUCapsPtr qemuCaps,
                             virDomainObjPtr obj)
{
    int ret = -1;
    virDomainPCIAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        int max_idx = -1;
        int nbuses = 0;
        size_t i;
        int rv;
        bool buses_reserved = true;

        virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_TYPE_PCI;

        for (i = 0; i < def->ncontrollers; i++) {
            if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
                if ((int) def->controllers[i]->idx > max_idx)
                    max_idx = def->controllers[i]->idx;
            }
        }

        nbuses = max_idx + 1;

        if (nbuses > 0 &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCI_BRIDGE)) {
            virDomainDeviceInfo info;

            /* 1st pass to figure out how many PCI bridges we need */
            if (!(addrs = qemuDomainPCIAddressSetCreate(def, nbuses, true)))
                goto cleanup;

            if (qemuValidateDevicePCISlotsChipsets(def, qemuCaps, addrs) < 0)
                goto cleanup;

            for (i = 0; i < addrs->nbuses; i++) {
                if (!qemuDomainPCIBusFullyReserved(&addrs->buses[i]))
                    buses_reserved = false;
            }

            /* Reserve 1 extra slot for a (potential) bridge only if buses
             * are not fully reserved yet
             */
            if (!buses_reserved &&
                virDomainPCIAddressReserveNextSlot(addrs, &info, flags) < 0)
                goto cleanup;

            if (qemuAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
                goto cleanup;

            for (i = 1; i < addrs->nbuses; i++) {
                virDomainPCIAddressBusPtr bus = &addrs->buses[i];

                if ((rv = virDomainDefMaybeAddController(
                         def, VIR_DOMAIN_CONTROLLER_TYPE_PCI,
                         i, bus->model)) < 0)
                    goto cleanup;
                /* If we added a new bridge, we will need one more address */
                if (rv > 0 &&
                    virDomainPCIAddressReserveNextSlot(addrs, &info, flags) < 0)
                    goto cleanup;
            }
            nbuses = addrs->nbuses;
            virDomainPCIAddressSetFree(addrs);
            addrs = NULL;

        } else if (max_idx > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("PCI bridges are not supported "
                             "by this QEMU binary"));
            goto cleanup;
        }

        if (!(addrs = qemuDomainPCIAddressSetCreate(def, nbuses, false)))
            goto cleanup;

        if (qemuDomainSupportsPCI(def, qemuCaps)) {
            if (qemuValidateDevicePCISlotsChipsets(def, qemuCaps, addrs) < 0)
                goto cleanup;

            if (qemuAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
                goto cleanup;

            for (i = 0; i < def->ncontrollers; i++) {
                virDomainControllerDefPtr cont = def->controllers[i];
                int idx = cont->idx;
                virDevicePCIAddressPtr addr;
                virDomainPCIControllerOptsPtr options;

                if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
                    continue;

                addr = &cont->info.addr.pci;
                options = &cont->opts.pciopts;

                /* set defaults for any other auto-generated config
                 * options for this controller that haven't been
                 * specified in config.
                 */
                switch ((virDomainControllerModelPCI)cont->model) {
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE;
                    if (options->chassisNr == -1)
                        options->chassisNr = cont->idx;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420;
                    if (options->chassis == -1)
                       options->chassis = cont->idx;
                    if (options->port == -1)
                       options->port = (addr->slot << 3) + addr->function;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM;
                    if (options->chassis == -1)
                       options->chassis = cont->idx;
                    if (options->port == -1)
                       options->port = addr->slot;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
                    break;
                }

                /* check if every PCI bridge controller's ID is greater than
                 * the bus it is placed onto
                 */
                if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE &&
                    idx <= addr->bus) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("failed to create PCI bridge "
                                     "on bus %d: too many devices with fixed "
                                     "addresses"),
                                   addr->bus);
                    goto cleanup;
                }
            }
        }
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            /* if this is the live domain object, we persist the PCI addresses*/
            virDomainPCIAddressSetFree(priv->pciaddrs);
            priv->persistentAddrs = 1;
            priv->pciaddrs = addrs;
            addrs = NULL;
        } else {
            priv->persistentAddrs = 0;
        }
    }

    ret = 0;

 cleanup:
    virDomainPCIAddressSetFree(addrs);

    return ret;
}


/*
 * This assigns static PCI slots to all configured devices.
 * The ordering here is chosen to match the ordering used
 * with old QEMU < 0.12, so that if a user updates a QEMU
 * host from old QEMU to QEMU >= 0.12, their guests should
 * get PCI addresses in the same order as before.
 *
 * NB, if they previously hotplugged devices then all bets
 * are off. Hotplug for old QEMU was unfixably broken wrt
 * to stable PCI addressing.
 *
 * Order is:
 *
 *  - Host bridge (slot 0)
 *  - PIIX3 ISA bridge, IDE controller, something else unknown, USB controller (slot 1)
 *  - Video (slot 2)
 *
 *  - These integrated devices were already added by
 *    qemuValidateDevicePCISlotsChipsets invoked right before this function
 *
 * Incrementally assign slots from 3 onwards:
 *
 *  - Net
 *  - Sound
 *  - SCSI controllers
 *  - VirtIO block
 *  - VirtIO balloon
 *  - Host device passthrough
 *  - Watchdog
 *  - pci serial devices
 *
 * Prior to this function being invoked, qemuCollectPCIAddress() will have
 * added all existing PCI addresses from the 'def' to 'addrs'. Thus this
 * function must only try to reserve addresses if info.type == NONE and
 * skip over info.type == PCI
 */
int
qemuAssignDevicePCISlots(virDomainDefPtr def,
                         virQEMUCapsPtr qemuCaps,
                         virDomainPCIAddressSetPtr addrs)
{
    size_t i, j;
    virDomainPCIConnectFlags flags;
    virDevicePCIAddress tmp_addr;

    /* PCI controllers */
    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                continue;
            switch (def->controllers[i]->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                /* pci-root and pcie-root are implicit in the machine,
                 * and needs no address */
                continue;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                /* pci-bridge doesn't require hot-plug
                 * (although it does provide hot-plug in its slots)
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCI;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                /* dmi-to-pci-bridge requires a non-hotplug PCIe
                 * slot
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                /* pcie-root-port can only plug into pcie-root */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_ROOT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                /* pcie-switch really does need a real PCIe
                 * port, but it doesn't need to be pcie-root
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_PORT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                /* pcie-switch-port can only plug into pcie-switch */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_SWITCH;
                break;
            default:
                flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;
                break;
            }
            if (virDomainPCIAddressReserveNextSlot(addrs,
                                                   &def->controllers[i]->info,
                                                   flags) < 0)
                goto error;
        }
    }

    flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;

    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* Only support VirtIO-9p-pci so far. If that changes,
         * we might need to skip devices here */
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->fss[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Network interfaces */
    for (i = 0; i < def->nnets; i++) {
        /* type='hostdev' network devices might be USB, and are also
         * in hostdevs list anyway, so handle them with other hostdevs
         * instead of here.
         */
        if ((def->nets[i]->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) ||
            (def->nets[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
            continue;
        }
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->nets[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Sound cards */
    for (i = 0; i < def->nsounds; i++) {
        if (def->sounds[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        /* Skip ISA sound card, PCSPK and usb-audio */
        if (def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_SB16 ||
            def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_PCSPK ||
            def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_USB)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs, &def->sounds[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Device controllers (SCSI, USB, but not IDE, FDC or CCID) */
    for (i = 0; i < def->ncontrollers; i++) {
        /* PCI controllers have been dealt with earlier */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        /* USB controller model 'none' doesn't need a PCI address */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            continue;

        /* FDC lives behind the ISA bridge; CCID is a usb device */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC ||
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID)
            continue;

        /* First IDE controller lives on the PIIX3 at slot=1, function=1,
           dealt with earlier on*/
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0)
            continue;

        if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* USB2 needs special handling to put all companions in the same slot */
        if (IS_USB2_CONTROLLER(def->controllers[i])) {
            virDevicePCIAddress addr = { 0, 0, 0, 0, false };
            bool foundAddr = false;

            memset(&tmp_addr, 0, sizeof(tmp_addr));
            for (j = 0; j < def->ncontrollers; j++) {
                if (IS_USB2_CONTROLLER(def->controllers[j]) &&
                    def->controllers[j]->idx == def->controllers[i]->idx &&
                    def->controllers[j]->info.type
                    == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                    addr = def->controllers[j]->info.addr.pci;
                    foundAddr = true;
                    break;
                }
            }

            switch (def->controllers[i]->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
                addr.function = 7;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
                addr.function = 0;
                addr.multi = VIR_TRISTATE_SWITCH_ON;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
                addr.function = 1;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
                addr.function = 2;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            }

            if (!foundAddr) {
                /* This is the first part of the controller, so need
                 * to find a free slot & then reserve a function */
                if (virDomainPCIAddressGetNextSlot(addrs, &tmp_addr, flags) < 0)
                    goto error;

                addr.bus = tmp_addr.bus;
                addr.slot = tmp_addr.slot;

                addrs->lastaddr = addr;
                addrs->lastaddr.function = 0;
                addrs->lastaddr.multi = VIR_TRISTATE_SWITCH_ABSENT;
            }
            /* Finally we can reserve the slot+function */
            if (virDomainPCIAddressReserveAddr(addrs, &addr, flags,
                                               false, foundAddr) < 0)
                goto error;

            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            def->controllers[i]->info.addr.pci = addr;
        } else {
            if (virDomainPCIAddressReserveNextSlot(addrs,
                                                   &def->controllers[i]->info,
                                                   flags) < 0)
                goto error;
        }
    }

    /* Disks (VirtIO only for now) */
    for (i = 0; i < def->ndisks; i++) {
        /* Only VirtIO disks use PCI addrs */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        /* don't touch s390 devices */
        if (def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
            def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390 ||
            def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
            continue;

        /* Also ignore virtio-mmio disks if our machine allows them */
        if (def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MMIO))
            continue;

        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio disk cannot have an address of type '%s'"),
                           virDomainDeviceAddressTypeToString(def->disks[i]->info.type));
            goto error;
        }

        if (virDomainPCIAddressReserveNextSlot(addrs, &def->disks[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Host PCI devices */
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               def->hostdevs[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* VirtIO balloon */
    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->memballoon->info,
                                               flags) < 0)
            goto error;
    }

    /* VirtIO RNG */
    for (i = 0; i < def->nrngs; i++) {
        if (def->rngs[i]->model != VIR_DOMAIN_RNG_MODEL_VIRTIO ||
            def->rngs[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->rngs[i]->info, flags) < 0)
            goto error;
    }

    /* A watchdog - check if it is a PCI device */
    if (def->watchdog &&
        def->watchdog->model == VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB &&
        def->watchdog->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->watchdog->info,
                                               flags) < 0)
            goto error;
    }

    /* Assign a PCI slot to the primary video card if there is not an
     * assigned address. */
    if (def->nvideos > 0 &&
        def->videos[0]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->videos[0]->info,
                                               flags) < 0)
            goto error;
    }

    /* Further non-primary video cards which have to be qxl type */
    for (i = 1; i < def->nvideos; i++) {
        if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("non-primary video device must be type of 'qxl'"));
            goto error;
        }
        if (def->videos[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->videos[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Shared Memory */
    for (i = 0; i < def->nshmems; i++) {
        if (def->shmems[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->shmems[i]->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus != VIR_DOMAIN_INPUT_BUS_VIRTIO)
            continue;
        if (def->inputs[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->inputs[i]->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->nparallels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr chr = def->serials[i];

        if (chr->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI)
            continue;

        if (chr->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs, &chr->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->nchannels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nhubs; i++) {
        /* Nada - none are PCI based (yet) */
    }

    return 0;

 error:
    return -1;
}

static int
qemuBuildDeviceAddressStr(virBufferPtr buf,
                          virDomainDefPtr domainDef,
                          virDomainDeviceInfoPtr info,
                          virQEMUCapsPtr qemuCaps)
{
    int ret = -1;
    char *devStr = NULL;
    const char *contAlias = NULL;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        size_t i;

        if (!(devStr = virDomainPCIAddressAsString(&info->addr.pci)))
            goto cleanup;
        for (i = 0; i < domainDef->ncontrollers; i++) {
            virDomainControllerDefPtr cont = domainDef->controllers[i];

            if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
                cont->idx == info->addr.pci.bus) {
                contAlias = cont->info.alias;
                if (!contAlias) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Device alias was not set for PCI "
                                     "controller with index %u required "
                                     "for device at address %s"),
                                   info->addr.pci.bus, devStr);
                    goto cleanup;
                }
                break;
            }
        }
        if (!contAlias) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find PCI "
                             "controller with index %u required "
                             "for device at address %s"),
                           info->addr.pci.bus, devStr);
            goto cleanup;
        }

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_MULTIFUNCTION)) {
            if (info->addr.pci.function != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only PCI device addresses with function=0 "
                                 "are supported with this QEMU binary"));
                goto cleanup;
            }
            if (info->addr.pci.multi == VIR_TRISTATE_SWITCH_ON) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("'multifunction=on' is not supported with "
                                 "this QEMU binary"));
                goto cleanup;
            }
        }

        if (info->addr.pci.bus != 0 &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCI_BRIDGE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Multiple PCI buses are not supported "
                             "with this QEMU binary"));
            goto cleanup;
        }
        virBufferAsprintf(buf, ",bus=%s", contAlias);

        if (info->addr.pci.multi == VIR_TRISTATE_SWITCH_ON)
            virBufferAddLit(buf, ",multifunction=on");
        else if (info->addr.pci.multi == VIR_TRISTATE_SWITCH_OFF)
            virBufferAddLit(buf, ",multifunction=off");
        virBufferAsprintf(buf, ",addr=0x%x", info->addr.pci.slot);
        if (info->addr.pci.function != 0)
           virBufferAsprintf(buf, ".0x%x", info->addr.pci.function);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        if (!(contAlias = virDomainControllerAliasFind(domainDef,
                                                       VIR_DOMAIN_CONTROLLER_TYPE_USB,
                                                       info->addr.usb.bus)))
            goto cleanup;
        virBufferAsprintf(buf, ",bus=%s.0,port=%s", contAlias, info->addr.usb.port);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO) {
        if (info->addr.spaprvio.has_reg)
            virBufferAsprintf(buf, ",reg=0x%llx", info->addr.spaprvio.reg);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        if (info->addr.ccw.assigned)
            virBufferAsprintf(buf, ",devno=%x.%x.%04x",
                              info->addr.ccw.cssid,
                              info->addr.ccw.ssid,
                              info->addr.ccw.devno);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA) {
        virBufferAsprintf(buf, ",iobase=0x%x,irq=0x%x",
                          info->addr.isa.iobase,
                          info->addr.isa.irq);
    }

    ret = 0;
 cleanup:
    VIR_FREE(devStr);
    return ret;
}

static int
qemuBuildRomStr(virBufferPtr buf,
                virDomainDeviceInfoPtr info,
                virQEMUCapsPtr qemuCaps)
{
    if (info->rombar || info->romfile) {
        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("rombar and romfile are supported only for PCI devices"));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_ROMBAR)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("rombar and romfile not supported in this QEMU binary"));
            return -1;
        }

        switch (info->rombar) {
        case VIR_TRISTATE_SWITCH_OFF:
            virBufferAddLit(buf, ",rombar=0");
            break;
        case VIR_TRISTATE_SWITCH_ON:
            virBufferAddLit(buf, ",rombar=1");
            break;
        default:
            break;
        }
        if (info->romfile)
           virBufferAsprintf(buf, ",romfile=%s", info->romfile);
    }
    return 0;
}

static int
qemuBuildIoEventFdStr(virBufferPtr buf,
                      virTristateSwitch use,
                      virQEMUCapsPtr qemuCaps)
{
    if (use && virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_IOEVENTFD))
        virBufferAsprintf(buf, ",ioeventfd=%s",
                          virTristateSwitchTypeToString(use));
    return 0;
}

#define QEMU_SERIAL_PARAM_ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ "

static int
qemuSafeSerialParamValue(const char *value)
{
    if (strspn(value, QEMU_SERIAL_PARAM_ACCEPTED_CHARS) != strlen(value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("driver serial '%s' contains unsafe characters"),
                       value);
        return -1;
    }

    return 0;
}

static char *
qemuGetSecretString(virConnectPtr conn,
                    const char *scheme,
                    bool encoded,
                    virStorageAuthDefPtr authdef,
                    virSecretUsageType secretUsageType)
{
    size_t secret_size;
    virSecretPtr sec = NULL;
    char *secret = NULL;
    char uuidStr[VIR_UUID_STRING_BUFLEN];

    /* look up secret */
    switch (authdef->secretType) {
    case VIR_STORAGE_SECRET_TYPE_UUID:
        sec = virSecretLookupByUUID(conn, authdef->secret.uuid);
        virUUIDFormat(authdef->secret.uuid, uuidStr);
        break;
    case VIR_STORAGE_SECRET_TYPE_USAGE:
        sec = virSecretLookupByUsage(conn, secretUsageType,
                                     authdef->secret.usage);
        break;
    }

    if (!sec) {
        if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
            virReportError(VIR_ERR_NO_SECRET,
                           _("%s no secret matches uuid '%s'"),
                           scheme, uuidStr);
        } else {
            virReportError(VIR_ERR_NO_SECRET,
                           _("%s no secret matches usage value '%s'"),
                           scheme, authdef->secret.usage);
        }
        goto cleanup;
    }

    secret = (char *)conn->secretDriver->secretGetValue(sec, &secret_size, 0,
                                                        VIR_SECRET_GET_VALUE_INTERNAL_CALL);
    if (!secret) {
        if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get value of the secret for "
                             "username '%s' using uuid '%s'"),
                           authdef->username, uuidStr);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get value of the secret for "
                             "username '%s' using usage value '%s'"),
                           authdef->username, authdef->secret.usage);
        }
        goto cleanup;
    }

    if (encoded) {
        char *base64 = NULL;

        base64_encode_alloc(secret, secret_size, &base64);
        VIR_FREE(secret);
        if (!base64) {
            virReportOOMError();
            goto cleanup;
        }
        secret = base64;
    }

 cleanup:
    virObjectUnref(sec);
    return secret;
}


static int
qemuParseRBDString(virDomainDiskDefPtr disk)
{
    char *source = disk->src->path;
    int ret;

    disk->src->path = NULL;

    ret = virStorageSourceParseRBDColonString(source, disk->src);

    VIR_FREE(source);
    return ret;
}


static int
qemuParseDriveURIString(virDomainDiskDefPtr def, virURIPtr uri,
                        const char *scheme)
{
    int ret = -1;
    char *transp = NULL;
    char *sock = NULL;
    char *volimg = NULL;
    char *secret = NULL;
    virStorageAuthDefPtr authdef = NULL;

    if (VIR_ALLOC(def->src->hosts) < 0)
        goto error;

    transp = strchr(uri->scheme, '+');
    if (transp)
        *transp++ = 0;

    if (STRNEQ(uri->scheme, scheme)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid transport/scheme '%s'"), uri->scheme);
        goto error;
    }

    if (!transp) {
        def->src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
    } else {
        def->src->hosts->transport = virStorageNetHostTransportTypeFromString(transp);
        if (def->src->hosts->transport < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid %s transport type '%s'"), scheme, transp);
            goto error;
        }
    }
    def->src->nhosts = 0; /* set to 1 once everything succeeds */

    if (def->src->hosts->transport != VIR_STORAGE_NET_HOST_TRANS_UNIX) {
        if (VIR_STRDUP(def->src->hosts->name, uri->server) < 0)
            goto error;

        if (virAsprintf(&def->src->hosts->port, "%d", uri->port) < 0)
            goto error;
    } else {
        def->src->hosts->name = NULL;
        def->src->hosts->port = 0;
        if (uri->query) {
            if (STRPREFIX(uri->query, "socket=")) {
                sock = strchr(uri->query, '=') + 1;
                if (VIR_STRDUP(def->src->hosts->socket, sock) < 0)
                    goto error;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid query parameter '%s'"), uri->query);
                goto error;
            }
        }
    }
    if (uri->path) {
        volimg = uri->path + 1; /* skip the prefix slash */
        VIR_FREE(def->src->path);
        if (VIR_STRDUP(def->src->path, volimg) < 0)
            goto error;
    } else {
        VIR_FREE(def->src->path);
    }

    if (uri->user) {
        const char *secrettype;
        /* formulate authdef for disk->src->auth */
        if (VIR_ALLOC(authdef) < 0)
            goto error;

        secret = strchr(uri->user, ':');
        if (secret)
            *secret = '\0';

        if (VIR_STRDUP(authdef->username, uri->user) < 0)
            goto error;
        if (STREQ(scheme, "iscsi")) {
            secrettype =
                virSecretUsageTypeToString(VIR_SECRET_USAGE_TYPE_ISCSI);
            if (VIR_STRDUP(authdef->secrettype, secrettype) < 0)
                goto error;
        }
        def->src->auth = authdef;
        authdef = NULL;

        /* Cannot formulate a secretType (eg, usage or uuid) given
         * what is provided.
         */
    }

    def->src->nhosts = 1;
    ret = 0;

 cleanup:
    virURIFree(uri);

    return ret;

 error:
    virStorageNetHostDefClear(def->src->hosts);
    VIR_FREE(def->src->hosts);
    virStorageAuthDefFree(authdef);
    goto cleanup;
}

static int
qemuParseGlusterString(virDomainDiskDefPtr def)
{
    virURIPtr uri = NULL;

    if (!(uri = virURIParse(def->src->path)))
        return -1;

    return qemuParseDriveURIString(def, uri, "gluster");
}

static int
qemuParseISCSIString(virDomainDiskDefPtr def)
{
    virURIPtr uri = NULL;
    char *slash;
    unsigned lun;

    if (!(uri = virURIParse(def->src->path)))
        return -1;

    if (uri->path &&
        (slash = strchr(uri->path + 1, '/')) != NULL) {

        if (slash[1] == '\0') {
            *slash = '\0';
        } else if (virStrToLong_ui(slash + 1, NULL, 10, &lun) == -1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid name '%s' for iSCSI disk"),
                           def->src->path);
            virURIFree(uri);
            return -1;
        }
    }

    return qemuParseDriveURIString(def, uri, "iscsi");
}

static int
qemuParseNBDString(virDomainDiskDefPtr disk)
{
    virStorageNetHostDefPtr h = NULL;
    char *host, *port;
    char *src;

    virURIPtr uri = NULL;

    if (strstr(disk->src->path, "://")) {
        if (!(uri = virURIParse(disk->src->path)))
            return -1;
        return qemuParseDriveURIString(disk, uri, "nbd");
    }

    if (VIR_ALLOC(h) < 0)
        goto error;

    host = disk->src->path + strlen("nbd:");
    if (STRPREFIX(host, "unix:/")) {
        src = strchr(host + strlen("unix:"), ':');
        if (src)
            *src++ = '\0';

        h->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
        if (VIR_STRDUP(h->socket, host + strlen("unix:")) < 0)
            goto error;
    } else {
        port = strchr(host, ':');
        if (!port) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse nbd filename '%s'"), disk->src->path);
            goto error;
        }

        *port++ = '\0';
        if (VIR_STRDUP(h->name, host) < 0)
            goto error;

        src = strchr(port, ':');
        if (src)
            *src++ = '\0';

        if (VIR_STRDUP(h->port, port) < 0)
            goto error;
    }

    if (src && STRPREFIX(src, "exportname=")) {
        if (VIR_STRDUP(src, strchr(src, '=') + 1) < 0)
            goto error;
    } else {
        src = NULL;
    }

    VIR_FREE(disk->src->path);
    disk->src->path = src;
    disk->src->nhosts = 1;
    disk->src->hosts = h;
    return 0;

 error:
    virStorageNetHostDefClear(h);
    VIR_FREE(h);
    return -1;
}


static int
qemuNetworkDriveGetPort(int protocol,
                        const char *port)
{
    int ret = 0;

    if (port) {
        if (virStrToLong_i(port, NULL, 10, &ret) < 0 || ret < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse port number '%s'"),
                           port);
            return -1;
        }

        return ret;
    }

    switch ((virStorageNetProtocol) protocol) {
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
            return 80;

        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
            return 443;

        case VIR_STORAGE_NET_PROTOCOL_FTP:
            return 21;

        case VIR_STORAGE_NET_PROTOCOL_FTPS:
            return 990;

        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            return 69;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            return 7000;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
            return 10809;

        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            /* no default port specified */
            return 0;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
            /* not applicable */
            return -1;
    }

    return -1;
}

#define QEMU_DEFAULT_NBD_PORT "10809"

static char *
qemuBuildNetworkDriveURI(virStorageSourcePtr src,
                         const char *username,
                         const char *secret)
{
    char *ret = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virURIPtr uri = NULL;
    size_t i;

    switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NBD:
            if (src->nhosts != 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("protocol '%s' accepts only one host"),
                               virStorageNetProtocolTypeToString(src->protocol));
                goto cleanup;
            }

            if (!((src->hosts->name && strchr(src->hosts->name, ':')) ||
                  (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP &&
                   !src->hosts->name) ||
                  (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_UNIX &&
                   src->hosts->socket &&
                   src->hosts->socket[0] != '/'))) {

                virBufferAddLit(&buf, "nbd:");

                switch (src->hosts->transport) {
                case VIR_STORAGE_NET_HOST_TRANS_TCP:
                    virBufferStrcat(&buf, src->hosts->name, NULL);
                    virBufferAsprintf(&buf, ":%s",
                                      src->hosts->port ? src->hosts->port :
                                      QEMU_DEFAULT_NBD_PORT);
                    break;

                case VIR_STORAGE_NET_HOST_TRANS_UNIX:
                    if (!src->hosts->socket) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("socket attribute required for "
                                         "unix transport"));
                        goto cleanup;
                    }

                    virBufferAsprintf(&buf, "unix:%s", src->hosts->socket);
                    break;

                default:
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("nbd does not support transport '%s'"),
                                   virStorageNetHostTransportTypeToString(src->hosts->transport));
                    goto cleanup;
                }

                if (src->path)
                    virBufferAsprintf(&buf, ":exportname=%s", src->path);

                if (virBufferCheckError(&buf) < 0)
                    goto cleanup;

                ret = virBufferContentAndReset(&buf);
                goto cleanup;
            }
            /* fallthrough */
            /* NBD code uses same formatting scheme as others in some cases */

        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            if (src->nhosts != 1) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("protocol '%s' accepts only one host"),
                               virStorageNetProtocolTypeToString(src->protocol));
                goto cleanup;
            }

            if (VIR_ALLOC(uri) < 0)
                goto cleanup;

            if (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {
                if (VIR_STRDUP(uri->scheme,
                               virStorageNetProtocolTypeToString(src->protocol)) < 0)
                    goto cleanup;
            } else {
                if (virAsprintf(&uri->scheme, "%s+%s",
                                virStorageNetProtocolTypeToString(src->protocol),
                                virStorageNetHostTransportTypeToString(src->hosts->transport)) < 0)
                    goto cleanup;
            }

            if ((uri->port = qemuNetworkDriveGetPort(src->protocol, src->hosts->port)) < 0)
                goto cleanup;

            if (src->path) {
                if (src->volume) {
                    if (virAsprintf(&uri->path, "/%s%s",
                                    src->volume, src->path) < 0)
                        goto cleanup;
                } else {
                    if (virAsprintf(&uri->path, "%s%s",
                                    src->path[0] == '/' ? "" : "/",
                                    src->path) < 0)
                        goto cleanup;
                }
            }

            if (src->hosts->socket &&
                virAsprintf(&uri->query, "socket=%s", src->hosts->socket) < 0)
                goto cleanup;

            if (username) {
                if (secret) {
                    if (virAsprintf(&uri->user, "%s:%s", username, secret) < 0)
                        goto cleanup;
                } else {
                    if (VIR_STRDUP(uri->user, username) < 0)
                        goto cleanup;
                }
            }

            if (VIR_STRDUP(uri->server, src->hosts->name) < 0)
                goto cleanup;

            ret = virURIFormat(uri);

            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            if (!src->path) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing disk source for 'sheepdog' protocol"));
                goto cleanup;
            }

            if (src->nhosts == 0) {
                if (virAsprintf(&ret, "sheepdog:%s", src->path) < 0)
                    goto cleanup;
            } else if (src->nhosts == 1) {
                if (virAsprintf(&ret, "sheepdog:%s:%s:%s",
                                src->hosts->name,
                                src->hosts->port ? src->hosts->port : "7000",
                                src->path) < 0)
                    goto cleanup;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("protocol 'sheepdog' accepts up to one host"));
                goto cleanup;
            }

            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            if (strchr(src->path, ':')) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("':' not allowed in RBD source volume name '%s'"),
                               src->path);
                goto cleanup;
            }

            virBufferStrcat(&buf, "rbd:", src->path, NULL);

            if (src->snapshot)
                virBufferEscape(&buf, '\\', ":", "@%s", src->snapshot);

            if (username) {
                virBufferEscape(&buf, '\\', ":", ":id=%s", username);
                virBufferEscape(&buf, '\\', ":",
                                ":key=%s:auth_supported=cephx\\;none",
                                secret);
            } else {
                virBufferAddLit(&buf, ":auth_supported=none");
            }

            if (src->nhosts > 0) {
                virBufferAddLit(&buf, ":mon_host=");
                for (i = 0; i < src->nhosts; i++) {
                    if (i)
                        virBufferAddLit(&buf, "\\;");

                    /* assume host containing : is ipv6 */
                    if (strchr(src->hosts[i].name, ':'))
                        virBufferEscape(&buf, '\\', ":", "[%s]",
                                        src->hosts[i].name);
                    else
                        virBufferAsprintf(&buf, "%s", src->hosts[i].name);

                    if (src->hosts[i].port)
                        virBufferAsprintf(&buf, "\\:%s", src->hosts[i].port);
                }
            }

            if (src->configFile)
                virBufferEscape(&buf, '\\', ":", ":conf=%s", src->configFile);

            if (virBufferCheckError(&buf) < 0)
                goto cleanup;

            ret = virBufferContentAndReset(&buf);
            break;


        case VIR_STORAGE_NET_PROTOCOL_LAST:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected network protocol '%s'"),
                           virStorageNetProtocolTypeToString(src->protocol));
            goto cleanup;
    }

 cleanup:
    virBufferFreeAndReset(&buf);
    virURIFree(uri);

    return ret;
}


int
qemuGetDriveSourceString(virStorageSourcePtr src,
                         virConnectPtr conn,
                         char **source)
{
    int actualType = virStorageSourceGetActualType(src);
    char *secret = NULL;
    char *username = NULL;
    int ret = -1;

    *source = NULL;

    /* return 1 for empty sources */
    if (virStorageSourceIsEmpty(src))
        return 1;

    if (conn) {
        if (actualType == VIR_STORAGE_TYPE_NETWORK &&
            src->auth &&
            (src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI ||
             src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD)) {
            bool encode = false;
            int secretType = VIR_SECRET_USAGE_TYPE_ISCSI;
            const char *protocol = virStorageNetProtocolTypeToString(src->protocol);
            username = src->auth->username;

            if (src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
                /* qemu requires the secret to be encoded for RBD */
                encode = true;
                secretType = VIR_SECRET_USAGE_TYPE_CEPH;
            }

            if (!(secret = qemuGetSecretString(conn,
                                               protocol,
                                               encode,
                                               src->auth,
                                               secretType)))
                goto cleanup;
        }
    }

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_DIR:
        if (VIR_STRDUP(*source, src->path) < 0)
            goto cleanup;

        break;

    case VIR_STORAGE_TYPE_NETWORK:
        if (!(*source = qemuBuildNetworkDriveURI(src, username, secret)))
            goto cleanup;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        break;
    }

    ret = 0;

 cleanup:
    VIR_FREE(secret);
    return ret;
}


/* Perform disk definition config validity checks */
int
qemuCheckDiskConfig(virDomainDiskDefPtr disk)
{
    if (virDiskNameToIndex(disk->dst) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    if (disk->wwn) {
        if ((disk->bus != VIR_DOMAIN_DISK_BUS_IDE) &&
            (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only ide and scsi disk support wwn"));
            goto error;
        }
    }

    if ((disk->vendor || disk->product) &&
        disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only scsi disk supports vendor and product"));
            goto error;
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* make sure that both the bus supports type='lun' (SG_IO). */
        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO &&
            disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device='lun' is not supported for bus='%s'"),
                           virDomainDiskQEMUBusTypeToString(disk->bus));
            goto error;
        }
        if (disk->src->type == VIR_STORAGE_TYPE_NETWORK) {
            if (disk->src->protocol != VIR_STORAGE_NET_PROTOCOL_ISCSI) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk device='lun' is not supported "
                                 "for protocol='%s'"),
                               virStorageNetProtocolTypeToString(disk->src->protocol));
                goto error;
            }
        } else if (!virDomainDiskSourceIsBlockType(disk->src, true)) {
            goto error;
        }
        if (disk->wwn) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn is not supported for lun device"));
            goto error;
        }
        if (disk->vendor || disk->product) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting vendor or product is not supported "
                             "for lun device"));
            goto error;
        }
    }
    return 0;
 error:
    return -1;
}


/* Check whether the device address is using either 'ccw' or default s390
 * address format and whether that's "legal" for the current qemu and/or
 * guest os.machine type. This is the corollary to the code which doesn't
 * find the address type set using an emulator that supports either 'ccw'
 * or s390 and sets the address type based on the capabilities.
 *
 * If the address is using 'ccw' or s390 and it's not supported, generate
 * an error and return false; otherwise, return true.
 */
bool
qemuCheckCCWS390AddressSupport(virDomainDefPtr def,
                               virDomainDeviceInfo info,
                               virQEMUCapsPtr qemuCaps,
                               const char *devicename)
{
    if (info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        if (!qemuDomainMachineIsS390CCW(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("cannot use CCW address type for device "
                             "'%s' using machine type '%s'"),
                       devicename, def->os.machine);
            return false;
        } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CCW address type is not supported by "
                             "this QEMU"));
            return false;
        }
    } else if (info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio S390 address type is not supported by "
                             "this QEMU"));
            return false;
        }
    }
    return true;
}


/* Qemu 1.2 and later have a binary flag -enable-fips that must be
 * used for VNC auth to obey FIPS settings; but the flag only
 * exists on Linux, and with no way to probe for it via QMP.  Our
 * solution: if FIPS mode is required, then unconditionally use
 * the flag, regardless of qemu version, for the following matrix:
 *
 *                          old QEMU            new QEMU
 * FIPS enabled             doesn't start       VNC auth disabled
 * FIPS disabled/missing    VNC auth enabled    VNC auth enabled
 */
bool
qemuCheckFips(void)
{
    bool ret = false;

    if (virFileExists("/proc/sys/crypto/fips_enabled")) {
        char *buf = NULL;

        if (virFileReadAll("/proc/sys/crypto/fips_enabled", 10, &buf) < 0)
            return ret;
        if (STREQ(buf, "1\n"))
            ret = true;
        VIR_FREE(buf);
    }

    return ret;
}


char *
qemuBuildDriveStr(virConnectPtr conn,
                  virDomainDiskDefPtr disk,
                  bool bootable,
                  virQEMUCapsPtr qemuCaps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    const char *trans =
        virDomainDiskGeometryTransTypeToString(disk->geometry.trans);
    int idx = virDiskNameToIndex(disk->dst);
    int busid = -1, unitid = -1;
    char *source = NULL;
    int actualType = virStorageSourceGetActualType(disk->src);

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for scsi disk"));
            goto error;
        }

        /* Setting bus= attr for SCSI drives, causes a controller
         * to be created. Yes this is slightly odd. It is not possible
         * to have > 1 bus on a SCSI controller (yet). */
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("SCSI controller only supports 1 bus"));
            goto error;
        }
        busid = disk->info.addr.drive.controller;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for ide disk"));
            goto error;
        }
        /* We can only have 1 IDE controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        busid = disk->info.addr.drive.bus;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for fdc disk"));
            goto error;
        }
        /* We can only have 1 FDC controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        /* We can only have 1 FDC bus (currently) */
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s bus is supported"), bus);
            goto error;
        }
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for controller fdc"));
            goto error;
        }
        unitid = disk->info.addr.drive.unit;

        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        idx = -1;
        break;

    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_SD:
        /* Xen and SD have no address type currently, so assign
         * based on index */
        break;
    }

    if (qemuGetDriveSourceString(disk->src, conn, &source) < 0)
        goto error;

    if (source &&
        !((disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY ||
           disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
          disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN)) {

        virBufferAddLit(&opt, "file=");

        switch (actualType) {
        case VIR_STORAGE_TYPE_DIR:
            /* QEMU only supports magic FAT format for now */
            if (disk->src->format > 0 &&
                disk->src->format != VIR_STORAGE_FILE_FAT) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported disk driver type for '%s'"),
                               virStorageFileFormatTypeToString(disk->src->format));
                goto error;
            }

            if (!disk->src->readonly) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create virtual FAT disks in read-write mode"));
                goto error;
            }

            virBufferAddLit(&opt, "fat:");

            if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                virBufferAddLit(&opt, "floppy:");

            break;

        case VIR_STORAGE_TYPE_BLOCK:
            if (disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               disk->src->type == VIR_STORAGE_TYPE_VOLUME ?
                               _("tray status 'open' is invalid for block type volume") :
                               _("tray status 'open' is invalid for block type disk"));
                goto error;
            }

            break;

        default:
            break;
        }

        virBufferEscape(&opt, ',', ",", "%s,", source);

        if (disk->src->format > 0 &&
            disk->src->type != VIR_STORAGE_TYPE_DIR)
            virBufferAsprintf(&opt, "format=%s,",
                              virStorageFileFormatTypeToString(disk->src->format));
    }
    VIR_FREE(source);

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
        virBufferAddLit(&opt, "if=none");
    else
        virBufferAsprintf(&opt, "if=%s", bus);

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_CD))
                virBufferAddLit(&opt, ",media=cdrom");
        } else if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_IDE_CD))
                virBufferAddLit(&opt, ",media=cdrom");
        } else {
            virBufferAddLit(&opt, ",media=cdrom");
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        virBufferAsprintf(&opt, ",id=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    } else {
        if (busid == -1 && unitid == -1) {
            if (idx != -1)
                virBufferAsprintf(&opt, ",index=%d", idx);
        } else {
            if (busid != -1)
                virBufferAsprintf(&opt, ",bus=%d", busid);
            if (unitid != -1)
                virBufferAsprintf(&opt, ",unit=%d", unitid);
        }
    }
    if (bootable &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_BOOT) &&
        (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
         disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) &&
        disk->bus != VIR_DOMAIN_DISK_BUS_IDE)
        virBufferAddLit(&opt, ",boot=on");
    if (disk->src->readonly &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_READONLY)) {
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
            if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("readonly ide disks are not supported"));
                goto error;
            }
            if (disk->bus == VIR_DOMAIN_DISK_BUS_SATA) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("readonly sata disks are not supported"));
                goto error;
            }
        }
        virBufferAddLit(&opt, ",readonly=on");
    }
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        goto error;
    }

    /* generate geometry command string */
    if (disk->geometry.cylinders > 0 &&
        disk->geometry.heads > 0 &&
        disk->geometry.sectors > 0) {

        virBufferAsprintf(&opt, ",cyls=%u,heads=%u,secs=%u",
                          disk->geometry.cylinders,
                          disk->geometry.heads,
                          disk->geometry.sectors);

        if (disk->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT)
            virBufferAsprintf(&opt, ",trans=%s", trans);
    }

    if (disk->serial &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_SERIAL)) {
        if (qemuSafeSerialParamValue(disk->serial) < 0)
            goto error;
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI &&
            disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("scsi-block 'lun' devices do not support the "
                             "serial property"));
            goto error;
        }
        virBufferAddLit(&opt, ",serial=");
        virBufferEscape(&opt, '\\', " ", "%s", disk->serial);
    }

    if (disk->cachemode) {
        const char *mode = NULL;

        mode = qemuDiskCacheV2TypeToString(disk->cachemode);

        if (disk->cachemode == VIR_DOMAIN_DISK_CACHE_DIRECTSYNC &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk cache mode 'directsync' is not "
                             "supported by this QEMU"));
            goto error;
        } else if (disk->cachemode == VIR_DOMAIN_DISK_CACHE_UNSAFE &&
                   !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_CACHE_UNSAFE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk cache mode 'unsafe' is not "
                             "supported by this QEMU"));
            goto error;
        }

        if (disk->iomode == VIR_DOMAIN_DISK_IO_NATIVE &&
            disk->cachemode != VIR_DOMAIN_DISK_CACHE_DIRECTSYNC &&
            disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("native I/O needs either no disk cache "
                             "or directsync cache mode, QEMU will fallback "
                             "to aio=threads"));
            goto error;
        }

        virBufferAsprintf(&opt, ",cache=%s", mode);
    } else if (disk->src->shared && !disk->src->readonly) {
        virBufferAddLit(&opt, ",cache=none");
    }

    if (disk->copy_on_read) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_COPY_ON_READ)) {
            virBufferAsprintf(&opt, ",copy-on-read=%s",
                              virTristateSwitchTypeToString(disk->copy_on_read));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("copy_on_read is not supported by this QEMU binary"));
            goto error;
        }
    }

    if (disk->discard) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_DISCARD)) {
            virBufferAsprintf(&opt, ",discard=%s",
                              virDomainDiskDiscardTypeToString(disk->discard));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("discard is not supported by this QEMU binary"));
            goto error;
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MONITOR_JSON)) {
        const char *wpolicy = NULL, *rpolicy = NULL;

        if (disk->error_policy)
            wpolicy = virDomainDiskErrorPolicyTypeToString(disk->error_policy);
        if (disk->rerror_policy)
            rpolicy = virDomainDiskErrorPolicyTypeToString(disk->rerror_policy);

        if (disk->error_policy == VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE) {
            /* in the case of enospace, the option is spelled
             * differently in qemu, and it's only valid for werror,
             * not for rerror, so leave leave rerror NULL.
             */
            wpolicy = "enospc";
        } else if (!rpolicy) {
            /* for other policies, rpolicy can match wpolicy */
            rpolicy = wpolicy;
        }

        if (wpolicy)
            virBufferAsprintf(&opt, ",werror=%s", wpolicy);
        if (rpolicy)
            virBufferAsprintf(&opt, ",rerror=%s", rpolicy);
    }

    if (disk->iomode) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_AIO)) {
            virBufferAsprintf(&opt, ",aio=%s",
                              virDomainDiskIoTypeToString(disk->iomode));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk aio mode not supported with this "
                             "QEMU binary"));
            goto error;
        }
    }

    /* block I/O throttling */
    if ((disk->blkdeviotune.total_bytes_sec ||
         disk->blkdeviotune.read_bytes_sec ||
         disk->blkdeviotune.write_bytes_sec ||
         disk->blkdeviotune.total_iops_sec ||
         disk->blkdeviotune.read_iops_sec ||
         disk->blkdeviotune.write_iops_sec) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_IOTUNE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block I/O throttling not supported with this "
                         "QEMU binary"));
        goto error;
    }

    /* block I/O throttling 1.7 */
    if ((disk->blkdeviotune.total_bytes_sec_max ||
         disk->blkdeviotune.read_bytes_sec_max ||
         disk->blkdeviotune.write_bytes_sec_max ||
         disk->blkdeviotune.total_iops_sec_max ||
         disk->blkdeviotune.read_iops_sec_max ||
         disk->blkdeviotune.write_iops_sec_max ||
         disk->blkdeviotune.size_iops_sec) &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_IOTUNE_MAX)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("there are some block I/O throttling parameters "
                         "that are not supported with this QEMU binary"));
        goto error;
    }

    if (disk->blkdeviotune.total_bytes_sec > LLONG_MAX ||
        disk->blkdeviotune.read_bytes_sec > LLONG_MAX ||
        disk->blkdeviotune.write_bytes_sec > LLONG_MAX ||
        disk->blkdeviotune.total_iops_sec > LLONG_MAX ||
        disk->blkdeviotune.read_iops_sec > LLONG_MAX ||
        disk->blkdeviotune.write_iops_sec > LLONG_MAX ||
        disk->blkdeviotune.total_bytes_sec_max > LLONG_MAX ||
        disk->blkdeviotune.read_bytes_sec_max > LLONG_MAX ||
        disk->blkdeviotune.write_bytes_sec_max > LLONG_MAX ||
        disk->blkdeviotune.total_iops_sec_max > LLONG_MAX ||
        disk->blkdeviotune.read_iops_sec_max > LLONG_MAX ||
        disk->blkdeviotune.write_iops_sec_max > LLONG_MAX ||
        disk->blkdeviotune.size_iops_sec > LLONG_MAX) {
        virReportError(VIR_ERR_OVERFLOW,
                      _("block I/O throttle limit must "
                        "be less than %llu using QEMU"), LLONG_MAX);
        goto error;
    }

    if (disk->blkdeviotune.total_bytes_sec) {
        virBufferAsprintf(&opt, ",bps=%llu",
                          disk->blkdeviotune.total_bytes_sec);
    }

    if (disk->blkdeviotune.read_bytes_sec) {
        virBufferAsprintf(&opt, ",bps_rd=%llu",
                          disk->blkdeviotune.read_bytes_sec);
    }

    if (disk->blkdeviotune.write_bytes_sec) {
        virBufferAsprintf(&opt, ",bps_wr=%llu",
                          disk->blkdeviotune.write_bytes_sec);
    }

    if (disk->blkdeviotune.total_iops_sec) {
        virBufferAsprintf(&opt, ",iops=%llu",
                          disk->blkdeviotune.total_iops_sec);
    }

    if (disk->blkdeviotune.read_iops_sec) {
        virBufferAsprintf(&opt, ",iops_rd=%llu",
                          disk->blkdeviotune.read_iops_sec);
    }

    if (disk->blkdeviotune.write_iops_sec) {
        virBufferAsprintf(&opt, ",iops_wr=%llu",
                          disk->blkdeviotune.write_iops_sec);
    }

    if (disk->blkdeviotune.total_bytes_sec_max) {
        virBufferAsprintf(&opt, ",bps_max=%llu",
                          disk->blkdeviotune.total_bytes_sec_max);
    }

    if (disk->blkdeviotune.read_bytes_sec_max) {
        virBufferAsprintf(&opt, ",bps_rd_max=%llu",
                          disk->blkdeviotune.read_bytes_sec_max);
    }

    if (disk->blkdeviotune.write_bytes_sec_max) {
        virBufferAsprintf(&opt, ",bps_wr_max=%llu",
                          disk->blkdeviotune.write_bytes_sec_max);
    }

    if (disk->blkdeviotune.total_iops_sec_max) {
        virBufferAsprintf(&opt, ",iops_max=%llu",
                          disk->blkdeviotune.total_iops_sec_max);
    }

    if (disk->blkdeviotune.read_iops_sec_max) {
        virBufferAsprintf(&opt, ",iops_rd_max=%llu",
                          disk->blkdeviotune.read_iops_sec_max);
    }

    if (disk->blkdeviotune.write_iops_sec_max) {
        virBufferAsprintf(&opt, ",iops_wr_max=%llu",
                          disk->blkdeviotune.write_iops_sec_max);
    }

    if (disk->blkdeviotune.size_iops_sec) {
        virBufferAsprintf(&opt, ",iops_size=%llu",
                          disk->blkdeviotune.size_iops_sec);
    }

    if (virBufferCheckError(&opt) < 0)
        goto error;

    return virBufferContentAndReset(&opt);

 error:
    VIR_FREE(source);
    virBufferFreeAndReset(&opt);
    return NULL;
}


static bool
qemuCheckIOThreads(virDomainDefPtr def,
                   virDomainDiskDefPtr disk)
{
    /* Right "type" of disk" */
    if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO ||
        (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
         disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOThreads only available for virtio pci and "
                         "virtio ccw disk"));
        return false;
    }

    /* Can we find the disk iothread in the iothreadid list? */
    if (!virDomainIOThreadIDFind(def, disk->iothread)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk iothread '%u' not defined in iothreadid"),
                       disk->iothread);
        return false;
    }

    return true;
}


char *
qemuBuildDriveDevStr(virDomainDefPtr def,
                     virDomainDiskDefPtr disk,
                     int bootindex,
                     virQEMUCapsPtr qemuCaps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    const char *contAlias;
    int controllerModel;

    if (virDomainDiskDefDstDuplicates(def))
        goto error;

    if (qemuCheckDiskConfig(disk) < 0)
        goto error;

    /* Live only checks */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* make sure that the qemu binary supports type='lun' (SG_IO). */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_SG_IO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk device='lun' is not supported by "
                             "this QEMU"));
            goto error;
        }
    }

    if (!qemuCheckCCWS390AddressSupport(def, disk->info, qemuCaps, disk->dst))
        goto error;

    if (disk->iothread && !qemuCheckIOThreads(def, disk))
        goto error;

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for ide controller"));
            goto error;
        }

        if (disk->wwn &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_IDE_DRIVE_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn for ide disk is not supported "
                             "by this QEMU"));
            goto error;
        }

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_IDE_CD)) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                virBufferAddLit(&opt, "ide-cd");
            else
                virBufferAddLit(&opt, "ide-hd");
        } else {
            virBufferAddLit(&opt, "ide-drive");
        }

        if (!(contAlias = virDomainControllerAliasFind(def, VIR_DOMAIN_CONTROLLER_TYPE_IDE,
                                                       disk->info.addr.drive.controller)))
           goto error;
        virBufferAsprintf(&opt, ",bus=%s.%d,unit=%d",
                          contAlias,
                          disk->info.addr.drive.bus,
                          disk->info.addr.drive.unit);
        break;

    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_BLOCK)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support scsi-block for "
                                 "lun passthrough"));
                goto error;
            }
        }

        if (disk->wwn &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn for scsi disk is not supported "
                             "by this QEMU"));
            goto error;
        }

        /* Properties wwn, vendor and product were introduced in the
         * same QEMU release (1.2.0).
         */
        if ((disk->vendor || disk->product) &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting vendor or product for scsi disk is not "
                             "supported by this QEMU"));
            goto error;
        }

        controllerModel =
            virDomainDeviceFindControllerModel(def, &disk->info,
                                               VIR_DOMAIN_CONTROLLER_TYPE_SCSI);
        if ((qemuSetSCSIControllerModel(def, qemuCaps, &controllerModel)) < 0)
            goto error;

        if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            virBufferAddLit(&opt, "scsi-block");
        } else {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_CD)) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                    virBufferAddLit(&opt, "scsi-cd");
                else
                    virBufferAddLit(&opt, "scsi-hd");
            } else {
                virBufferAddLit(&opt, "scsi-disk");
            }
        }

        if (!(contAlias = virDomainControllerAliasFind(def, VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                                       disk->info.addr.drive.controller)))
           goto error;

        if (controllerModel == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
            if (disk->info.addr.drive.target != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("target must be 0 for controller "
                                 "model 'lsilogic'"));
                goto error;
            }

            virBufferAsprintf(&opt, ",bus=%s.%d,scsi-id=%d",
                              contAlias,
                              disk->info.addr.drive.bus,
                              disk->info.addr.drive.unit);
        } else {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_DISK_CHANNEL)) {
                if (disk->info.addr.drive.target > 7) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU doesn't support target "
                                     "greater than 7"));
                    goto error;
                }

                if (disk->info.addr.drive.bus != 0 &&
                    disk->info.addr.drive.unit != 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU only supports both bus and "
                                     "unit equal to 0"));
                    goto error;
                }
            }

            virBufferAsprintf(&opt, ",bus=%s.0,channel=%d,scsi-id=%d,lun=%d",
                              contAlias,
                              disk->info.addr.drive.bus,
                              disk->info.addr.drive.target,
                              disk->info.addr.drive.unit);
        }
        break;

    case VIR_DOMAIN_DISK_BUS_SATA:
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("bus must be 0 for ide controller"));
            goto error;
        }
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for ide controller"));
            goto error;
        }

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_IDE_CD)) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                virBufferAddLit(&opt, "ide-cd");
            else
                virBufferAddLit(&opt, "ide-hd");
        } else {
            virBufferAddLit(&opt, "ide-drive");
        }

        if (!(contAlias = virDomainControllerAliasFind(def, VIR_DOMAIN_CONTROLLER_TYPE_SATA,
                                                      disk->info.addr.drive.controller)))
           goto error;
        virBufferAsprintf(&opt, ",bus=%s.%d",
                          contAlias,
                          disk->info.addr.drive.unit);
        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            virBufferAddLit(&opt, "virtio-blk-ccw");
            if (disk->iothread)
                virBufferAsprintf(&opt, ",iothread=iothread%u", disk->iothread);
        } else if (disk->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
            virBufferAddLit(&opt, "virtio-blk-s390");
        } else if (disk->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO) {
            virBufferAddLit(&opt, "virtio-blk-device");
        } else {
            virBufferAddLit(&opt, "virtio-blk-pci");
            if (disk->iothread)
                virBufferAsprintf(&opt, ",iothread=iothread%u", disk->iothread);
        }
        qemuBuildIoEventFdStr(&opt, disk->ioeventfd, qemuCaps);
        if (disk->event_idx &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_EVENT_IDX)) {
            virBufferAsprintf(&opt, ",event_idx=%s",
                              virTristateSwitchTypeToString(disk->event_idx));
        }
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BLK_SCSI)) {
            /* if sg_io is true but the scsi option isn't supported,
             * that means it's just always on in this version of qemu.
             */
            virBufferAsprintf(&opt, ",scsi=%s",
                              (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN)
                              ? "on" : "off");
        }
        if (qemuBuildDeviceAddressStr(&opt, def, &disk->info, qemuCaps) < 0)
            goto error;
        break;

    case VIR_DOMAIN_DISK_BUS_USB:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for usb disk"));
            goto error;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("This QEMU doesn't support '-device "
                             "usb-storage'"));
            goto error;

        }
        virBufferAddLit(&opt, "usb-storage");

        if (qemuBuildDeviceAddressStr(&opt, def, &disk->info, qemuCaps) < 0)
            goto error;
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk bus '%s' with device setup"), bus);
        goto error;
    }

    virBufferAsprintf(&opt, ",drive=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    virBufferAsprintf(&opt, ",id=%s", disk->info.alias);
    if (bootindex && virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOTINDEX))
        virBufferAsprintf(&opt, ",bootindex=%d", bootindex);
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BLOCKIO)) {
        if (disk->blockio.logical_block_size > 0)
            virBufferAsprintf(&opt, ",logical_block_size=%u",
                              disk->blockio.logical_block_size);
        if (disk->blockio.physical_block_size > 0)
            virBufferAsprintf(&opt, ",physical_block_size=%u",
                              disk->blockio.physical_block_size);
    }

    if (disk->wwn) {
        if (STRPREFIX(disk->wwn, "0x"))
            virBufferAsprintf(&opt, ",wwn=%s", disk->wwn);
        else
            virBufferAsprintf(&opt, ",wwn=0x%s", disk->wwn);
    }

    if (disk->vendor)
        virBufferAsprintf(&opt, ",vendor=%s", disk->vendor);

    if (disk->product)
        virBufferAsprintf(&opt, ",product=%s", disk->product);

    if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_STORAGE_REMOVABLE)) {
            if (disk->removable == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&opt, ",removable=on");
            else
                virBufferAddLit(&opt, ",removable=off");
        } else {
            if (disk->removable != VIR_TRISTATE_SWITCH_ABSENT) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support setting the "
                                 "removable flag of USB storage devices"));
                goto error;
            }
        }
    }

    if (virBufferCheckError(&opt) < 0)
        goto error;

    return virBufferContentAndReset(&opt);

 error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *qemuBuildFSStr(virDomainFSDefPtr fs,
                     virQEMUCapsPtr qemuCaps ATTRIBUTE_UNUSED)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *driver = qemuDomainFSDriverTypeToString(fs->fsdriver);
    const char *wrpolicy = virDomainFSWrpolicyTypeToString(fs->wrpolicy);

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only supports mount filesystem type"));
        goto error;
    }

    if (!driver) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Filesystem driver type not supported"));
        goto error;
    }
    virBufferAdd(&opt, driver, -1);

    if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_PATH ||
        fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) {
        if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_MAPPED) {
            virBufferAddLit(&opt, ",security_model=mapped");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virBufferAddLit(&opt, ",security_model=passthrough");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_SQUASH) {
            virBufferAddLit(&opt, ",security_model=none");
        }
    } else {
        /* For other fs drivers, default(passthru) should always
         * be supported */
        if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only supports passthrough accessmode"));
            goto error;
        }
    }

    if (fs->wrpolicy) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_FSDEV_WRITEOUT)) {
            virBufferAsprintf(&opt, ",writeout=%s", wrpolicy);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("filesystem writeout not supported"));
            goto error;
        }
    }

    virBufferAsprintf(&opt, ",id=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferAsprintf(&opt, ",path=%s", fs->src);

    if (fs->readonly) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_FSDEV_READONLY)) {
            virBufferAddLit(&opt, ",readonly");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("readonly filesystem is not supported by this "
                             "QEMU binary"));
            goto error;
        }
    }

    if (virBufferCheckError(&opt) < 0)
        goto error;

    return virBufferContentAndReset(&opt);

 error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *
qemuBuildFSDevStr(virDomainDefPtr def,
                  virDomainFSDefPtr fs,
                  virQEMUCapsPtr qemuCaps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("can only passthrough directories"));
        goto error;
    }

    if (fs->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
        virBufferAddLit(&opt, "virtio-9p-ccw");
    else
        virBufferAddLit(&opt, "virtio-9p-pci");

    virBufferAsprintf(&opt, ",id=%s", fs->info.alias);
    virBufferAsprintf(&opt, ",fsdev=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferAsprintf(&opt, ",mount_tag=%s", fs->dst);

    if (qemuBuildDeviceAddressStr(&opt, def, &fs->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&opt) < 0)
        goto error;

    return virBufferContentAndReset(&opt);

 error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


static int
qemuControllerModelUSBToCaps(int model)
{
    switch (model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
        return QEMU_CAPS_PIIX3_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
        return QEMU_CAPS_PIIX4_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
        return QEMU_CAPS_USB_EHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
        return QEMU_CAPS_ICH9_USB_EHCI1;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
        return QEMU_CAPS_VT82C686B_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
        return QEMU_CAPS_PCI_OHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
        return QEMU_CAPS_NEC_USB_XHCI;
    default:
        return -1;
    }
}


static int
qemuBuildUSBControllerDevStr(virDomainDefPtr domainDef,
                             virDomainControllerDefPtr def,
                             virQEMUCapsPtr qemuCaps,
                             virBuffer *buf)
{
    const char *smodel;
    int model, flags;

    model = def->model;

    if (model == -1) {
        if ARCH_IS_PPC64(domainDef->os.arch)
            model = VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI;
        else
            model = VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI;
    }

    smodel = qemuControllerModelUSBTypeToString(model);
    flags = qemuControllerModelUSBToCaps(model);

    if (flags == -1 || !virQEMUCapsGet(qemuCaps, flags)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s not supported in this QEMU binary"), smodel);
        return -1;
    }

    virBufferAsprintf(buf, "%s", smodel);

    if (def->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB)
        virBufferAsprintf(buf, ",masterbus=%s.0,firstport=%d",
                          def->info.alias, def->info.master.usb.startport);
    else
        virBufferAsprintf(buf, ",id=%s", def->info.alias);

    return 0;
}

char *
qemuBuildControllerDevStr(virDomainDefPtr domainDef,
                          virDomainControllerDefPtr def,
                          virQEMUCapsPtr qemuCaps,
                          int *nusbcontroller)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int model = def->model;
    const char *modelName = NULL;

    if (!qemuCheckCCWS390AddressSupport(domainDef, def->info, qemuCaps,
                                        "controller"))
        return NULL;

    if (def->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
        if ((qemuSetSCSIControllerModel(domainDef, qemuCaps, &model)) < 0)
            return NULL;
    }

    if (!(def->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI &&
          model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI)) {
        if (def->queues) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'queues' is only supported by virtio-scsi controller"));
            return NULL;
        }
        if (def->cmd_per_lun) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'cmd_per_lun' is only supported by virtio-scsi controller"));
            return NULL;
        }
        if (def->max_sectors) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'max_sectors' is only supported by virtio-scsi controller"));
            return NULL;
        }
        if (def->ioeventfd) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'ioeventfd' is only supported by virtio-scsi controller"));
            return NULL;
        }
    }

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        switch (model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
                virBufferAddLit(&buf, "virtio-scsi-ccw");
            else if (def->info.type ==
                     VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
                virBufferAddLit(&buf, "virtio-scsi-s390");
            else if (def->info.type ==
                     VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO)
                virBufferAddLit(&buf, "virtio-scsi-device");
            else
                virBufferAddLit(&buf, "virtio-scsi-pci");
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            virBufferAddLit(&buf, "lsi");
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            virBufferAddLit(&buf, "spapr-vscsi");
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
            virBufferAddLit(&buf, "megasas");
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller model: %s"),
                           virDomainControllerModelSCSITypeToString(def->model));
        }
        virBufferAsprintf(&buf, ",id=%s", def->info.alias);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virBufferAddLit(&buf, "virtio-serial-pci");
        } else if (def->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            virBufferAddLit(&buf, "virtio-serial-ccw");
        } else if (def->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
            virBufferAddLit(&buf, "virtio-serial-s390");
        } else if (def->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO) {
            virBufferAddLit(&buf, "virtio-serial-device");
        } else {
            virBufferAddLit(&buf, "virtio-serial");
        }
        virBufferAsprintf(&buf, ",id=%s", def->info.alias);
        if (def->opts.vioserial.ports != -1) {
            virBufferAsprintf(&buf, ",max_ports=%d",
                              def->opts.vioserial.ports);
        }
        if (def->opts.vioserial.vectors != -1) {
            virBufferAsprintf(&buf, ",vectors=%d",
                              def->opts.vioserial.vectors);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
        virBufferAsprintf(&buf, "usb-ccid,id=%s", def->info.alias);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_AHCI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("SATA is not supported with this "
                             "QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "ahci,id=%s", def->info.alias);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (qemuBuildUSBControllerDevStr(domainDef, def, qemuCaps, &buf) == -1)
            goto error;

        if (nusbcontroller)
            *nusbcontroller += 1;

        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
        if (def->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
            def->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("wrong function called for pci-root/pcie-root"));
            return NULL;
        }
        if (def->idx == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("index for pci controllers of model '%s' must be > 0"),
                           virDomainControllerModelPCITypeToString(def->model));
            goto error;
        }
        switch (def->model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
            if (def->opts.pciopts.modelName
                == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE ||
                def->opts.pciopts.chassisNr == -1) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("autogenerated pci-bridge options not set"));
                goto error;
            }

            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown pci-bridge model name value %d"),
                               def->opts.pciopts.modelName);
                goto error;
            }
            if (def->opts.pciopts.modelName
                != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller model name '%s' "
                                 "is not valid for a pci-bridge"),
                               modelName);
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCI_BRIDGE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the pci-bridge controller "
                                 "is not supported in this QEMU binary"));
                goto error;
            }
            virBufferAsprintf(&buf, "%s,chassis_nr=%d,id=%s",
                              modelName, def->opts.pciopts.chassisNr,
                              def->info.alias);
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
            if (def->opts.pciopts.modelName
                == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("autogenerated dmi-to-pci-bridge options not set"));
                goto error;
            }

            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown dmi-to-pci-bridge model name value %d"),
                               def->opts.pciopts.modelName);
                goto error;
            }
            if (def->opts.pciopts.modelName
                != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller model name '%s' "
                                 "is not valid for a dmi-to-pci-bridge"),
                               modelName);
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_DMI_TO_PCI_BRIDGE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the dmi-to-pci-bridge (i82801b11-bridge) "
                                 "controller is not supported in this QEMU binary"));
                goto error;
            }
            virBufferAsprintf(&buf, "%s,id=%s", modelName, def->info.alias);
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
            if (def->opts.pciopts.modelName
                == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("autogenerated pcie-root-port options not set"));
                goto error;
            }
            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown pcie-root-port model name value %d"),
                               def->opts.pciopts.modelName);
                goto error;
            }
            if (def->opts.pciopts.modelName
                != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller model name '%s' "
                                 "is not valid for a pcie-root-port"),
                               modelName);
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_IOH3420)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the pcie-root-port (ioh3420) "
                                 "controller is not supported in this QEMU binary"));
                goto error;
            }

            virBufferAsprintf(&buf, "%s,port=0x%x,chassis=%d,id=%s",
                              modelName, def->opts.pciopts.port,
                              def->opts.pciopts.chassis, def->info.alias);
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
            if (def->opts.pciopts.modelName
                == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("autogenerated pcie-switch-upstream-port options not set"));
                goto error;
            }
            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown pcie-switch-upstream-port model name value %d"),
                               def->opts.pciopts.modelName);
                goto error;
            }
            if (def->opts.pciopts.modelName
                != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller model name '%s' "
                                 "is not valid for a pcie-switch-upstream-port"),
                               modelName);
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_X3130_UPSTREAM)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the pcie-switch-upstream-port (x3130-upstream) "
                                 "controller is not supported in this QEMU binary"));
                goto error;
            }

            virBufferAsprintf(&buf, "%s,id=%s", modelName, def->info.alias);
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
            if (def->opts.pciopts.modelName
                == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE ||
                def->opts.pciopts.chassis == -1 ||
                def->opts.pciopts.port == -1) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("autogenerated pcie-switch-downstream-port "
                                 "options not set"));
                goto error;
            }

            modelName = virDomainControllerPCIModelNameTypeToString(def->opts.pciopts.modelName);
            if (!modelName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown pcie-switch-downstream-port model name value %d"),
                               def->opts.pciopts.modelName);
                goto error;
            }
            if (def->opts.pciopts.modelName
                != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller model name '%s' "
                                 "is not valid for a pcie-switch-downstream-port"),
                               modelName);
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_XIO3130_DOWNSTREAM)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("The pcie-switch-downstream-port "
                                 "(xio3130-downstream) controller "
                                 "is not supported in this QEMU binary"));
                goto error;
            }
            virBufferAsprintf(&buf, "%s,port=0x%x,chassis=%d,id=%s",
                              modelName, def->opts.pciopts.port,
                              def->opts.pciopts.chassis, def->info.alias);
            break;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
        /* Since we currently only support the integrated IDE
         * controller on various boards, if we ever get to here, it's
         * because some other machinetype had an IDE controller
         * specified, or one with a single IDE contraller had multiple
         * ide controllers specified.
         */
        if (qemuDomainMachineHasBuiltinIDE(domainDef))
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only a single IDE controller is supported "
                             "for this machine type"));
        else
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("IDE controllers are unsupported for "
                             "this QEMU binary or machine type"));
        goto error;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported controller type: %s"),
                       virDomainControllerTypeToString(def->type));
        goto error;
    }

    if (def->queues)
        virBufferAsprintf(&buf, ",num_queues=%u", def->queues);

    if (def->cmd_per_lun)
        virBufferAsprintf(&buf, ",cmd_per_lun=%u", def->cmd_per_lun);

    if (def->max_sectors)
        virBufferAsprintf(&buf, ",max_sectors=%u", def->max_sectors);

    qemuBuildIoEventFdStr(&buf, def->ioeventfd, qemuCaps);

    if (qemuBuildDeviceAddressStr(&buf, domainDef, &def->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


/**
 * qemuBuildMemoryBackendStr:
 * @size: size of the memory device in kibibytes
 * @pagesize: size of the requested memory page in KiB, 0 for default
 * @guestNode: NUMA node in the guest that the memory object will be attached
 *             to, or -1 if NUMA is not used in the guest
 * @hostNodes: map of host nodes to alloc the memory in, NULL for default
 * @autoNodeset: fallback nodeset in case of automatic numa placement
 * @def: domain definition object
 * @qemuCaps: qemu capabilities object
 * @cfg: qemu driver config object
 * @aliasPrefix: prefix string of the alias (to allow for multiple frontents)
 * @id: index of the device (to construct the alias)
 * @backendStr: returns the object string
 *
 * Formats the configuration string for the memory device backend according
 * to the configuration. @pagesize and @hostNodes can be used to override the
 * default source configuration, both are optional.
 *
 * Returns 0 on success, 1 if only the implicit memory-device-ram with no
 * other configuration was used (to detect legacy configurations). Returns
 * -1 in case of an error.
 */
int
qemuBuildMemoryBackendStr(unsigned long long size,
                          unsigned long long pagesize,
                          int guestNode,
                          virBitmapPtr userNodeset,
                          virBitmapPtr autoNodeset,
                          virDomainDefPtr def,
                          virQEMUCapsPtr qemuCaps,
                          virQEMUDriverConfigPtr cfg,
                          const char **backendType,
                          virJSONValuePtr *backendProps,
                          bool force)
{
    virDomainHugePagePtr master_hugepage = NULL;
    virDomainHugePagePtr hugepage = NULL;
    virDomainNumatuneMemMode mode;
    const long system_page_size = virGetSystemPageSizeKB();
    virNumaMemAccess memAccess = VIR_NUMA_MEM_ACCESS_DEFAULT;
    size_t i;
    char *mem_path = NULL;
    virBitmapPtr nodemask = NULL;
    int ret = -1;
    virJSONValuePtr props = NULL;
    bool nodeSpecified = virDomainNumatuneNodeSpecified(def->numa, guestNode);

    *backendProps = NULL;
    *backendType = NULL;

    if (guestNode >= 0) {
        /* memory devices could provide a invalid guest node */
        if (guestNode >= virDomainNumaGetNodeCount(def->numa)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("can't add memory backend for guest node '%d' as "
                             "the guest has only '%zu' NUMA nodes configured"),
                           guestNode, virDomainNumaGetNodeCount(def->numa));
            return -1;
        }

        memAccess = virDomainNumaGetNodeMemoryAccessMode(def->numa, guestNode);
    }

    if (virDomainNumatuneGetMode(def->numa, guestNode, &mode) < 0 &&
        virDomainNumatuneGetMode(def->numa, -1, &mode) < 0)
        mode = VIR_DOMAIN_NUMATUNE_MEM_STRICT;

    if (pagesize == 0) {
        /* Find the huge page size we want to use */
        for (i = 0; i < def->mem.nhugepages; i++) {
            bool thisHugepage = false;

            hugepage = &def->mem.hugepages[i];

            if (!hugepage->nodemask) {
                master_hugepage = hugepage;
                continue;
            }

            /* just find the master hugepage in case we don't use NUMA */
            if (guestNode < 0)
                continue;

            if (virBitmapGetBit(hugepage->nodemask, guestNode,
                                &thisHugepage) < 0) {
                /* Ignore this error. It's not an error after all. Well,
                 * the nodemask for this <page/> can contain lower NUMA
                 * nodes than we are querying in here. */
                continue;
            }

            if (thisHugepage) {
                /* Hooray, we've found the page size */
                break;
            }
        }

        if (i == def->mem.nhugepages) {
            /* We have not found specific huge page to be used with this
             * NUMA node. Use the generic setting then (<page/> without any
             * @nodemask) if possible. */
            hugepage = master_hugepage;
        }

        if (hugepage)
            pagesize = hugepage->size;
    }

    if (pagesize == system_page_size) {
        /* However, if user specified to use "huge" page
         * of regular system page size, it's as if they
         * hasn't specified any huge pages at all. */
        pagesize = 0;
        hugepage = NULL;
    }

    if (!(props = virJSONValueNewObject()))
        return -1;

    if (pagesize || hugepage) {
        if (pagesize) {
            /* Now lets see, if the huge page we want to use is even mounted
             * and ready to use */
            for (i = 0; i < cfg->nhugetlbfs; i++) {
                if (cfg->hugetlbfs[i].size == pagesize)
                    break;
            }

            if (i == cfg->nhugetlbfs) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to find any usable hugetlbfs mount for %llu KiB"),
                               pagesize);
                goto cleanup;
            }

            if (!(mem_path = qemuGetHugepagePath(&cfg->hugetlbfs[i])))
                goto cleanup;
        } else {
            if (!(mem_path = qemuGetDefaultHugepath(cfg->hugetlbfs,
                                                    cfg->nhugetlbfs)))
                goto cleanup;
        }

        *backendType = "memory-backend-file";

        if (virJSONValueObjectAdd(props,
                                  "b:prealloc", true,
                                  "s:mem-path", mem_path,
                                  NULL) < 0)
            goto cleanup;

        switch (memAccess) {
        case VIR_NUMA_MEM_ACCESS_SHARED:
            if (virJSONValueObjectAdd(props, "b:share", true, NULL) < 0)
                goto cleanup;
            break;

        case VIR_NUMA_MEM_ACCESS_PRIVATE:
            if (virJSONValueObjectAdd(props, "b:share", false, NULL) < 0)
                goto cleanup;
            break;

        case VIR_NUMA_MEM_ACCESS_DEFAULT:
        case VIR_NUMA_MEM_ACCESS_LAST:
            break;
        }
    } else {
        if (memAccess) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Shared memory mapping is supported "
                             "only with hugepages"));
            goto cleanup;
        }

        *backendType = "memory-backend-ram";
    }

    if (virJSONValueObjectAdd(props, "U:size", size * 1024, NULL) < 0)
        goto cleanup;

    if (userNodeset) {
        nodemask = userNodeset;
    } else {
        if (virDomainNumatuneMaybeGetNodeset(def->numa, autoNodeset,
                                             &nodemask, guestNode) < 0)
            goto cleanup;
    }

    if (nodemask) {
        if (!virNumaNodesetIsAvailable(nodemask))
            goto cleanup;
        if (virJSONValueObjectAdd(props,
                                  "m:host-nodes", nodemask,
                                  "S:policy", qemuNumaPolicyTypeToString(mode),
                                  NULL) < 0)
            goto cleanup;
    }

    /* If none of the following is requested... */
    if (!pagesize && !userNodeset && !memAccess && !nodeSpecified && !force) {
        /* report back that using the new backend is not necessary
         * to achieve the desired configuration */
        ret = 1;
    } else {
        /* otherwise check the required capability */
        if (STREQ(*backendType, "memory-backend-file") &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the "
                             "memory-backend-file object"));
            goto cleanup;
        } else if (STREQ(*backendType, "memory-backend-ram") &&
                   !virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_RAM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the "
                             "memory-backend-ram object"));
            goto cleanup;
        }

        ret = 0;
    }

    *backendProps = props;
    props = NULL;

 cleanup:
    virJSONValueFree(props);
    VIR_FREE(mem_path);

    return ret;
}


static int
qemuBuildMemoryCellBackendStr(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virQEMUDriverConfigPtr cfg,
                              size_t cell,
                              virBitmapPtr auto_nodeset,
                              char **backendStr)
{
    virJSONValuePtr props = NULL;
    char *alias = NULL;
    const char *backendType;
    int ret = -1;
    int rc;
    unsigned long long memsize = virDomainNumaGetNodeMemorySize(def->numa,
                                                                cell);

    *backendStr = NULL;

    if (virAsprintf(&alias, "ram-node%zu", cell) < 0)
        goto cleanup;

    if ((rc = qemuBuildMemoryBackendStr(memsize, 0, cell, NULL, auto_nodeset,
                                        def, qemuCaps, cfg, &backendType,
                                        &props, false)) < 0)
        goto cleanup;

    if (!(*backendStr = qemuBuildObjectCommandlineFromJSON(backendType,
                                                           alias,
                                                           props)))
        goto cleanup;

    ret = rc;

 cleanup:
    VIR_FREE(alias);
    virJSONValueFree(props);

    return ret;
}


static char *
qemuBuildMemoryDimmBackendStr(virDomainMemoryDefPtr mem,
                              virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              virQEMUDriverConfigPtr cfg)
{
    virJSONValuePtr props = NULL;
    char *alias = NULL;
    const char *backendType;
    char *ret = NULL;

    if (!mem->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("memory device alias is not assigned"));
        return NULL;
    }

    if (virAsprintf(&alias, "mem%s", mem->info.alias) < 0)
        goto cleanup;

    if (qemuBuildMemoryBackendStr(mem->size, mem->pagesize,
                                  mem->targetNode, mem->sourceNodes, NULL,
                                  def, qemuCaps, cfg,
                                  &backendType, &props, true) < 0)
        goto cleanup;

    ret = qemuBuildObjectCommandlineFromJSON(backendType, alias, props);

 cleanup:
    VIR_FREE(alias);
    virJSONValueFree(props);

    return ret;
}


char *
qemuBuildMemoryDeviceStr(virDomainMemoryDefPtr mem)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!mem->info.alias) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing alias for memory device"));
        return NULL;
    }

    switch ((virDomainMemoryModel) mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        virBufferAddLit(&buf, "pc-dimm,");

        if (mem->targetNode >= 0)
            virBufferAsprintf(&buf, "node=%d,", mem->targetNode);

        virBufferAsprintf(&buf, "memdev=mem%s,id=%s",
                          mem->info.alias, mem->info.alias);

        if (mem->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM) {
            virBufferAsprintf(&buf, ",slot=%d", mem->info.addr.dimm.slot);
            virBufferAsprintf(&buf, ",addr=%llu", mem->info.addr.dimm.base);
        }

        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid memory device type"));
        break;

    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *
qemuBuildNicStr(virDomainNetDefPtr net,
                const char *prefix,
                int vlan)
{
    char *str;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    ignore_value(virAsprintf(&str,
                             "%smacaddr=%s,vlan=%d%s%s%s%s",
                             prefix ? prefix : "",
                             virMacAddrFormat(&net->mac, macaddr),
                             vlan,
                             (net->model ? ",model=" : ""),
                             (net->model ? net->model : ""),
                             (net->info.alias ? ",name=" : ""),
                             (net->info.alias ? net->info.alias : "")));
    return str;
}


char *
qemuBuildNicDevStr(virDomainDefPtr def,
                   virDomainNetDefPtr net,
                   int vlan,
                   int bootindex,
                   size_t vhostfdSize,
                   virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *nic = net->model;
    bool usingVirtio = false;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    if (STREQ(net->model, "virtio")) {
        if (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
            nic = "virtio-net-ccw";
        else if (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
            nic = "virtio-net-s390";
        else if (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO)
            nic = "virtio-net-device";
        else
            nic = "virtio-net-pci";

        usingVirtio = true;
    }

    virBufferAdd(&buf, nic, -1);
    if (usingVirtio && net->driver.virtio.txmode) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_TX_ALG)) {
            virBufferAddLit(&buf, ",tx=");
            switch (net->driver.virtio.txmode) {
                case VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD:
                    virBufferAddLit(&buf, "bh");
                    break;

                case VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER:
                    virBufferAddLit(&buf, "timer");
                    break;
                default:
                    /* this should never happen, if it does, we need
                     * to add another case to this switch.
                     */
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("unrecognized virtio-net-pci 'tx' option"));
                    goto error;
            }
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-net-pci 'tx' option not supported in this QEMU binary"));
            goto error;
        }
    }
    if (usingVirtio) {
        qemuBuildIoEventFdStr(&buf, net->driver.virtio.ioeventfd, qemuCaps);
        if (net->driver.virtio.event_idx &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_NET_EVENT_IDX)) {
            virBufferAsprintf(&buf, ",event_idx=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.event_idx));
        }
        if (net->driver.virtio.host.csum) {
            virBufferAsprintf(&buf, ",csum=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.csum));
        }
        if (net->driver.virtio.host.gso) {
            virBufferAsprintf(&buf, ",gso=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.gso));
        }
        if (net->driver.virtio.host.tso4) {
            virBufferAsprintf(&buf, ",host_tso4=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.tso4));
        }
        if (net->driver.virtio.host.tso6) {
            virBufferAsprintf(&buf, ",host_tso6=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.tso6));
        }
        if (net->driver.virtio.host.ecn) {
            virBufferAsprintf(&buf, ",host_ecn=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.ecn));
        }
        if (net->driver.virtio.host.ufo) {
            virBufferAsprintf(&buf, ",host_ufo=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.ufo));
        }
        if (net->driver.virtio.host.mrg_rxbuf) {
            virBufferAsprintf(&buf, ",mrg_rxbuf=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.host.mrg_rxbuf));
        }
        if (net->driver.virtio.guest.csum) {
            virBufferAsprintf(&buf, ",guest_csum=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.guest.csum));
        }
        if (net->driver.virtio.guest.tso4) {
            virBufferAsprintf(&buf, ",guest_tso4=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.guest.tso4));
        }
        if (net->driver.virtio.guest.tso6) {
            virBufferAsprintf(&buf, ",guest_tso6=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.guest.tso6));
        }
        if (net->driver.virtio.guest.ecn) {
            virBufferAsprintf(&buf, ",guest_ecn=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.guest.ecn));
        }
        if (net->driver.virtio.guest.ufo) {
            virBufferAsprintf(&buf, ",guest_ufo=%s",
                              virTristateSwitchTypeToString(net->driver.virtio.guest.ufo));
        }
    }
    if (usingVirtio && vhostfdSize > 1) {
        if (net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
            /* ccw provides a one to one relation of fds to queues and
             * does not support the vectors option
             */
            virBufferAddLit(&buf, ",mq=on");
        } else {
            /* As advised at http://www.linux-kvm.org/page/Multiqueue
             * we should add vectors=2*N+2 where N is the vhostfdSize
             */
            virBufferAsprintf(&buf, ",mq=on,vectors=%zu", 2 * vhostfdSize + 2);
        }
    }
    if (vlan == -1)
        virBufferAsprintf(&buf, ",netdev=host%s", net->info.alias);
    else
        virBufferAsprintf(&buf, ",vlan=%d", vlan);
    virBufferAsprintf(&buf, ",id=%s", net->info.alias);
    virBufferAsprintf(&buf, ",mac=%s",
                      virMacAddrFormat(&net->mac, macaddr));
    if (qemuBuildDeviceAddressStr(&buf, def, &net->info, qemuCaps) < 0)
        goto error;
    if (qemuBuildRomStr(&buf, &net->info, qemuCaps) < 0)
        goto error;
    if (bootindex && virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOTINDEX))
        virBufferAsprintf(&buf, ",bootindex=%d", bootindex);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildHostNetStr(virDomainNetDefPtr net,
                    virQEMUDriverPtr driver,
                    char type_sep,
                    int vlan,
                    char **tapfd,
                    size_t tapfdSize,
                    char **vhostfd,
                    size_t vhostfdSize)
{
    bool is_tap = false;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainNetType netType = virDomainNetGetActualType(net);
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    size_t i;

    if (net->script && netType != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("scripts are not supported on interfaces of type %s"),
                       virDomainNetTypeToString(netType));
        virObjectUnref(cfg);
        return NULL;
    }

    switch (netType) {
    /*
     * If type='bridge', and we're running as privileged user
     * or -netdev bridge is not supported then it will fall
     * through, -net tap,fd
     */
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        virBufferAsprintf(&buf, "tap%c", type_sep);
        /* for one tapfd 'fd=' shall be used,
         * for more than one 'fds=' is the right choice */
        if (tapfdSize == 1) {
            virBufferAsprintf(&buf, "fd=%s", tapfd[0]);
        } else {
            virBufferAddLit(&buf, "fds=");
            for (i = 0; i < tapfdSize; i++) {
                if (i)
                    virBufferAddChar(&buf, ':');
                virBufferAdd(&buf, tapfd[i], -1);
            }
        }
        type_sep = ',';
        is_tap = true;
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        virBufferAddLit(&buf, "tap");
        if (net->ifname) {
            virBufferAsprintf(&buf, "%cifname=%s", type_sep, net->ifname);
            type_sep = ',';
        }
        if (net->script) {
            virBufferAsprintf(&buf, "%cscript=%s", type_sep,
                              net->script);
            type_sep = ',';
        }
        is_tap = true;
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
       virBufferAsprintf(&buf, "socket%cconnect=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
       virBufferAsprintf(&buf, "socket%clisten=%s:%d",
                         type_sep,
                         net->data.socket.address ? net->data.socket.address
                                                  : "",
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_MCAST:
       virBufferAsprintf(&buf, "socket%cmcast=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_UDP:
       virBufferAsprintf(&buf, "socket%cudp=%s:%d,localaddr=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port,
                         net->data.socket.localaddr,
                         net->data.socket.localport);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_USER:
    default:
        virBufferAddLit(&buf, "user");
        break;
    }

    if (vlan >= 0) {
        virBufferAsprintf(&buf, "%cvlan=%d", type_sep, vlan);
        if (net->info.alias)
            virBufferAsprintf(&buf, ",name=host%s",
                              net->info.alias);
    } else {
        virBufferAsprintf(&buf, "%cid=host%s",
                          type_sep, net->info.alias);
    }

    if (is_tap) {
        if (vhostfdSize) {
            virBufferAddLit(&buf, ",vhost=on,");
            if (vhostfdSize == 1) {
                virBufferAsprintf(&buf, "vhostfd=%s", vhostfd[0]);
            } else {
                virBufferAddLit(&buf, "vhostfds=");
                for (i = 0; i < vhostfdSize; i++) {
                    if (i)
                        virBufferAddChar(&buf, ':');
                    virBufferAdd(&buf, vhostfd[i], -1);
                }
            }
        }
        if (net->tune.sndbuf_specified)
            virBufferAsprintf(&buf, ",sndbuf=%lu", net->tune.sndbuf);
    }

    virObjectUnref(cfg);

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *
qemuBuildWatchdogDevStr(virDomainDefPtr def,
                        virDomainWatchdogDefPtr dev,
                        virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    const char *model = virDomainWatchdogModelTypeToString(dev->model);
    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing watchdog model"));
        goto error;
    }

    virBufferAsprintf(&buf, "%s,id=%s", model, dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildMemballoonDevStr(virDomainDefPtr def,
                          virDomainMemballoonDefPtr dev,
                          virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (dev->info.type) {
        case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
            virBufferAddLit(&buf, "virtio-balloon-pci");
            break;
        case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
            virBufferAddLit(&buf, "virtio-balloon-ccw");
            break;
        case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
            virBufferAddLit(&buf, "virtio-balloon-device");
            break;
        default:
            virReportError(VIR_ERR_XML_ERROR,
                           _("memballoon unsupported with address type '%s'"),
                           virDomainDeviceAddressTypeToString(dev->info.type));
            goto error;
    }

    virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (dev->autodeflate != VIR_TRISTATE_SWITCH_ABSENT) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_BALLOON_AUTODEFLATE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("deflate-on-oom is not supported by this QEMU binary"));
            goto error;
        }

        virBufferAsprintf(&buf, ",deflate-on-oom=%s",
                          virTristateSwitchTypeToString(dev->autodeflate));
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildNVRAMDevStr(virDomainNVRAMDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO &&
        dev->info.addr.spaprvio.has_reg) {
        virBufferAsprintf(&buf, "spapr-nvram.reg=0x%llx",
                          dev->info.addr.spaprvio.reg);
    } else {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("nvram address type must be spaprvio"));
        goto error;
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildVirtioInputDevStr(virDomainDefPtr def,
                           virDomainInputDefPtr dev,
                           virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *suffix;

    if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        suffix = "-pci";
    } else if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO) {
        suffix = "-device";
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported address type %s for virtio input device"),
                       virDomainDeviceAddressTypeToString(dev->info.type));
        goto error;
    }

    switch ((virDomainInputType) dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_MOUSE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-mouse is not supported by this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "virtio-mouse%s,id=%s", suffix, dev->info.alias);
        break;
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_TABLET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-tablet is not supported by this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "virtio-tablet%s,id=%s", suffix, dev->info.alias);
        break;
    case VIR_DOMAIN_INPUT_TYPE_KBD:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_KEYBOARD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-keyboard is not supported by this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "virtio-keyboard%s,id=%s", suffix, dev->info.alias);
        break;
    case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_INPUT_HOST)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-input-host is not supported by this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "virtio-input-host%s,id=%s,evdev=", suffix, dev->info.alias);
        virBufferEscape(&buf, ',', ",", "%s", dev->source.evdev);
        break;
    case VIR_DOMAIN_INPUT_TYPE_LAST:
        break;
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

char *
qemuBuildUSBInputDevStr(virDomainDefPtr def,
                        virDomainInputDefPtr dev,
                        virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (dev->type) {
    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
        virBufferAsprintf(&buf, "usb-mouse,id=%s", dev->info.alias);
        break;
    case VIR_DOMAIN_INPUT_TYPE_TABLET:
        virBufferAsprintf(&buf, "usb-tablet,id=%s", dev->info.alias);
        break;
    case VIR_DOMAIN_INPUT_TYPE_KBD:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_KBD))
            goto error;
        virBufferAsprintf(&buf, "usb-kbd,id=%s", dev->info.alias);
        break;
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildSoundDevStr(virDomainDefPtr def,
                     virDomainSoundDefPtr sound,
                     virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model = NULL;

    /* Hack for devices with different names in QEMU and libvirt */
    switch ((virDomainSoundModel) sound->model) {
    case VIR_DOMAIN_SOUND_MODEL_ES1370:
        model = "ES1370";
        break;
    case VIR_DOMAIN_SOUND_MODEL_AC97:
        model = "AC97";
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH6:
        model = "intel-hda";
        break;
    case VIR_DOMAIN_SOUND_MODEL_USB:
        model = "usb-audio";
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_USB_AUDIO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("usb-audio controller is not supported "
                             "by this QEMU binary"));
            goto error;
        }
        break;
    case VIR_DOMAIN_SOUND_MODEL_ICH9:
        model = "ich9-intel-hda";
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ICH9_INTEL_HDA)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The ich9-intel-hda audio controller "
                             "is not supported in this QEMU binary"));
            goto error;
        }
        break;
    case VIR_DOMAIN_SOUND_MODEL_SB16:
        model = "sb16";
        break;
    case VIR_DOMAIN_SOUND_MODEL_PCSPK: /* pc-speaker is handled separately */
    case VIR_DOMAIN_SOUND_MODEL_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("sound card model '%s' is not supported by qemu"),
                       virDomainSoundModelTypeToString(sound->model));
        goto error;
    }

    virBufferAsprintf(&buf, "%s,id=%s", model, sound->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, def, &sound->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
qemuSoundCodecTypeToCaps(int type)
{
    switch (type) {
    case VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX:
        return QEMU_CAPS_HDA_DUPLEX;
    case VIR_DOMAIN_SOUND_CODEC_TYPE_MICRO:
        return QEMU_CAPS_HDA_MICRO;
    default:
        return -1;
    }
}


static char *
qemuBuildSoundCodecStr(virDomainSoundDefPtr sound,
                       virDomainSoundCodecDefPtr codec,
                       virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *stype;
    int type, flags;

    type = codec->type;
    stype = qemuSoundCodecTypeToString(type);
    flags = qemuSoundCodecTypeToCaps(type);

    if (flags == -1 || !virQEMUCapsGet(qemuCaps, flags)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s not supported in this QEMU binary"), stype);
        goto error;
    }

    virBufferAsprintf(&buf, "%s,id=%s-codec%d,bus=%s.0,cad=%d",
                      stype, sound->info.alias, codec->cad, sound->info.alias, codec->cad);

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildDeviceVideoStr(virDomainDefPtr def,
                        virDomainVideoDefPtr video,
                        virQEMUCapsPtr qemuCaps,
                        bool primary)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model;

    if (primary) {
        model = qemuDeviceVideoTypeToString(video->type);
        if (!model || STREQ(model, "")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type %s is not supported with QEMU"),
                           virDomainVideoTypeToString(video->type));
            goto error;
        }
    } else {
        if (video->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("non-primary video device must be type of 'qxl'"));
            goto error;
        }

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_QXL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("only one video card is currently supported"));
            goto error;
        }

        model = "qxl";
    }

    virBufferAsprintf(&buf, "%s,id=%s", model, video->info.alias);

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
        if (video->accel && video->accel->accel3d) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_GPU_VIRGL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("virtio-gpu 3d acceleration is not supported"));
                goto error;
            }

            virBufferAsprintf(&buf, ",virgl=%s",
                              virTristateSwitchTypeToString(video->accel->accel3d));
        }
    } else if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (video->vram > (UINT_MAX / 1024)) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("value for 'vram' must be less than '%u'"),
                           UINT_MAX / 1024);
            goto error;
        }
        if (video->ram > (UINT_MAX / 1024)) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("value for 'ram' must be less than '%u'"),
                           UINT_MAX / 1024);
            goto error;
        }

        if (video->ram) {
            /* QEMU accepts bytes for ram_size. */
            virBufferAsprintf(&buf, ",ram_size=%u", video->ram * 1024);
        }

        if (video->vram) {
            /* QEMU accepts bytes for vram_size. */
            virBufferAsprintf(&buf, ",vram_size=%u", video->vram * 1024);
        }

        if ((primary && virQEMUCapsGet(qemuCaps, QEMU_CAPS_QXL_VGA_VGAMEM)) ||
            (!primary && virQEMUCapsGet(qemuCaps, QEMU_CAPS_QXL_VGAMEM))) {
            /* QEMU accepts mebibytes for vgamem_mb. */
            virBufferAsprintf(&buf, ",vgamem_mb=%u", video->vgamem / 1024);
        }
    } else if (video->vram &&
        ((video->type == VIR_DOMAIN_VIDEO_TYPE_VGA &&
          virQEMUCapsGet(qemuCaps, QEMU_CAPS_VGA_VGAMEM)) ||
         (video->type == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
          virQEMUCapsGet(qemuCaps, QEMU_CAPS_VMWARE_SVGA_VGAMEM)))) {

        if (video->vram < 1024) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("value for 'vram' must be at least 1 MiB "
                                   "(1024 KiB)"));
            goto error;
        }

        virBufferAsprintf(&buf, ",vgamem_mb=%u", video->vram / 1024);
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &video->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
qemuOpenPCIConfig(virDomainHostdevDefPtr dev)
{
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    char *path = NULL;
    int configfd = -1;

    if (virAsprintf(&path, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/config",
                    pcisrc->addr.domain, pcisrc->addr.bus,
                    pcisrc->addr.slot, pcisrc->addr.function) < 0)
        return -1;

    configfd = open(path, O_RDWR, 0);

    if (configfd < 0)
        virReportSystemError(errno, _("Failed opening %s"), path);

    VIR_FREE(path);

    return configfd;
}

char *
qemuBuildPCIHostdevDevStr(virDomainDefPtr def,
                          virDomainHostdevDefPtr dev,
                          int bootIndex, /* used iff dev->info->bootIndex == 0 */
                          const char *configfd,
                          virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;
    int backend = pcisrc->backend;

    /* caller has to assign proper passthrough backend type */
    switch ((virDomainHostdevSubsysPCIBackendType) backend) {
    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
        virBufferAddLit(&buf, "pci-assign");
        if (configfd && *configfd)
            virBufferAsprintf(&buf, ",configfd=%s", configfd);
        break;

    case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
        virBufferAddLit(&buf, "vfio-pci");
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid PCI passthrough type '%s'"),
                       virDomainHostdevSubsysPCIBackendTypeToString(backend));
        goto error;
    }

    virBufferAddLit(&buf, ",host=");
    if (pcisrc->addr.domain) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_HOST_PCI_MULTIDOMAIN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("non-zero domain='%.4x' in host device PCI address "
                             "not supported in this QEMU binary"),
                           pcisrc->addr.domain);
            goto error;
        }
        virBufferAsprintf(&buf, "%.4x:", pcisrc->addr.domain);
    }
    virBufferAsprintf(&buf, "%.2x:%.2x.%.1x",
                      pcisrc->addr.bus, pcisrc->addr.slot,
                      pcisrc->addr.function);
    virBufferAsprintf(&buf, ",id=%s", dev->info->alias);
    if (dev->info->bootIndex)
        bootIndex = dev->info->bootIndex;
    if (bootIndex)
        virBufferAsprintf(&buf, ",bootindex=%d", bootIndex);
    if (qemuBuildDeviceAddressStr(&buf, def, dev->info, qemuCaps) < 0)
        goto error;
    if (qemuBuildRomStr(&buf, dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildPCIHostdevPCIDevStr(virDomainHostdevDefPtr dev,
                             virQEMUCapsPtr qemuCaps)
{
    char *ret = NULL;
    virDomainHostdevSubsysPCIPtr pcisrc = &dev->source.subsys.u.pci;

    if (pcisrc->addr.domain) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_HOST_PCI_MULTIDOMAIN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("non-zero domain='%.4x' in host device PCI address "
                             "not supported in this QEMU binary"),
                           pcisrc->addr.domain);
            goto cleanup;
        }
        ignore_value(virAsprintf(&ret, "host=%.4x:%.2x:%.2x.%.1x",
                                 pcisrc->addr.domain, pcisrc->addr.bus,
                                 pcisrc->addr.slot, pcisrc->addr.function));
    } else {
        ignore_value(virAsprintf(&ret, "host=%.2x:%.2x.%.1x",
                                 pcisrc->addr.bus, pcisrc->addr.slot,
                                 pcisrc->addr.function));
    }
 cleanup:
    return ret;
}


char *
qemuBuildRedirdevDevStr(virDomainDefPtr def,
                        virDomainRedirdevDefPtr dev,
                        virQEMUCapsPtr qemuCaps)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainRedirFilterDefPtr redirfilter = def->redirfilter;

    if (dev->bus != VIR_DOMAIN_REDIRDEV_BUS_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Redirection bus %s is not supported by QEMU"),
                       virDomainRedirdevBusTypeToString(dev->bus));
        goto error;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_REDIR)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("USB redirection is not supported "
                         "by this version of QEMU"));
        goto error;
    }

    virBufferAsprintf(&buf, "usb-redir,chardev=char%s,id=%s",
                      dev->info.alias, dev->info.alias);

    if (redirfilter && redirfilter->nusbdevs) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_REDIR_FILTER)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("USB redirection filter is not "
                             "supported by this version of QEMU"));
            goto error;
        }

        virBufferAddLit(&buf, ",filter=");

        for (i = 0; i < redirfilter->nusbdevs; i++) {
            virDomainRedirFilterUSBDevDefPtr usbdev = redirfilter->usbdevs[i];
            if (usbdev->usbClass >= 0)
                virBufferAsprintf(&buf, "0x%02X:", usbdev->usbClass);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->vendor >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->vendor);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->product >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->product);
            else
                virBufferAddLit(&buf, "-1:");

            if (usbdev->version >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->version);
            else
                virBufferAddLit(&buf, "-1:");

            virBufferAsprintf(&buf, "%u", usbdev->allow);
            if (i < redirfilter->nusbdevs -1)
                virBufferAddLit(&buf, "|");
        }
    }

    if (dev->info.bootIndex) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_REDIR_BOOTINDEX)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("USB redirection booting is not "
                             "supported by this version of QEMU"));
            goto error;
        }
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info.bootIndex);
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

char *
qemuBuildUSBHostdevDevStr(virDomainDefPtr def,
                          virDomainHostdevDefPtr dev,
                          virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;

    if (!dev->missing && !usbsrc->bus && !usbsrc->device) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("USB host device is missing bus/device information"));
        return NULL;
    }

    virBufferAddLit(&buf, "usb-host");
    if (!dev->missing) {
        virBufferAsprintf(&buf, ",hostbus=%d,hostaddr=%d",
                          usbsrc->bus, usbsrc->device);
    }
    virBufferAsprintf(&buf, ",id=%s", dev->info->alias);
    if (dev->info->bootIndex)
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info->bootIndex);

    if (qemuBuildDeviceAddressStr(&buf, def, dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildHubDevStr(virDomainDefPtr def,
                   virDomainHubDefPtr dev,
                   virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (dev->type != VIR_DOMAIN_HUB_TYPE_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hub type %s not supported"),
                       virDomainHubTypeToString(dev->type));
        goto error;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_HUB)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb-hub not supported by QEMU binary"));
        goto error;
    }

    virBufferAddLit(&buf, "usb-hub");
    virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildUSBHostdevUSBDevStr(virDomainHostdevDefPtr dev)
{
    char *ret = NULL;
    virDomainHostdevSubsysUSBPtr usbsrc = &dev->source.subsys.u.usb;

    if (dev->missing) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("This QEMU doesn't not support missing USB devices"));
        return NULL;
    }

    if (!usbsrc->bus && !usbsrc->device) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("USB host device is missing bus/device information"));
        return NULL;
    }

    ignore_value(virAsprintf(&ret, "host:%d.%d", usbsrc->bus, usbsrc->device));
    return ret;
}

static char *
qemuBuildSCSIHostHostdevDrvStr(virDomainHostdevDefPtr dev,
                               virQEMUCapsPtr qemuCaps ATTRIBUTE_UNUSED,
                               qemuBuildCommandLineCallbacksPtr callbacks)
{
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    char *sg = NULL;

    sg = (callbacks->qemuGetSCSIDeviceSgName)(NULL,
                                              scsihostsrc->adapter,
                                              scsihostsrc->bus,
                                              scsihostsrc->target,
                                              scsihostsrc->unit);
    return sg;
}

static char *
qemuBuildSCSIiSCSIHostdevDrvStr(virConnectPtr conn,
                                virDomainHostdevDefPtr dev)
{
    char *source = NULL;
    char *secret = NULL;
    char *username = NULL;
    virStorageSource src;

    memset(&src, 0, sizeof(src));

    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIiSCSIPtr iscsisrc = &scsisrc->u.iscsi;

    if (conn && iscsisrc->auth) {
        const char *protocol =
            virStorageNetProtocolTypeToString(VIR_STORAGE_NET_PROTOCOL_ISCSI);
        bool encode = false;
        int secretType = VIR_SECRET_USAGE_TYPE_ISCSI;

        username = iscsisrc->auth->username;
        if (!(secret = qemuGetSecretString(conn, protocol, encode,
                                           iscsisrc->auth, secretType)))
            goto cleanup;
    }

    src.protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;
    src.path = iscsisrc->path;
    src.hosts = iscsisrc->hosts;
    src.nhosts = iscsisrc->nhosts;

    /* Rather than pull what we think we want - use the network disk code */
    source = qemuBuildNetworkDriveURI(&src, username, secret);

 cleanup:
    VIR_FREE(secret);
    return source;
}

char *
qemuBuildSCSIHostdevDrvStr(virConnectPtr conn,
                           virDomainHostdevDefPtr dev,
                           virQEMUCapsPtr qemuCaps,
                           qemuBuildCommandLineCallbacksPtr callbacks)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *source = NULL;
    virDomainHostdevSubsysSCSIPtr scsisrc = &dev->source.subsys.u.scsi;

    if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
        if (!(source = qemuBuildSCSIiSCSIHostdevDrvStr(conn, dev)))
            goto error;
        virBufferAsprintf(&buf, "file=%s,if=none,format=raw", source);
    } else {
        if (!(source = qemuBuildSCSIHostHostdevDrvStr(dev, qemuCaps,
                                                      callbacks)))
            goto error;
        virBufferAsprintf(&buf, "file=/dev/%s,if=none", source);
    }
    virBufferAsprintf(&buf, ",id=%s-%s",
                      virDomainDeviceAddressTypeToString(dev->info->type),
                      dev->info->alias);

    if (dev->readonly) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_READONLY)) {
            virBufferAddLit(&buf, ",readonly=on");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support 'readonly' "
                             "for -drive"));
            goto error;
        }
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    VIR_FREE(source);
    return virBufferContentAndReset(&buf);
 error:
    VIR_FREE(source);
    virBufferFreeAndReset(&buf);
    return NULL;
}

char *
qemuBuildSCSIHostdevDevStr(virDomainDefPtr def,
                           virDomainHostdevDefPtr dev,
                           virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int model = -1;
    const char *contAlias;

    model = virDomainDeviceFindControllerModel(def, dev->info,
                                               VIR_DOMAIN_CONTROLLER_TYPE_SCSI);

    if (qemuSetSCSIControllerModel(def, qemuCaps, &model) < 0)
        goto error;

    if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
        if (dev->info->addr.drive.target != 0) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for scsi host device "
                             "if its controller model is 'lsilogic'"));
            goto error;
        }

        if (dev->info->addr.drive.unit > 7) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unit must be not more than 7 for scsi host "
                             "device if its controller model is 'lsilogic'"));
            goto error;
        }
    }

    virBufferAddLit(&buf, "scsi-generic");

    if (!(contAlias = virDomainControllerAliasFind(def, VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
                                                   dev->info->addr.drive.controller)))
        goto error;

    if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
        virBufferAsprintf(&buf, ",bus=%s.%d,scsi-id=%d",
                          contAlias,
                          dev->info->addr.drive.bus,
                          dev->info->addr.drive.unit);
    } else {
        virBufferAsprintf(&buf, ",bus=%s.0,channel=%d,scsi-id=%d,lun=%d",
                          contAlias,
                          dev->info->addr.drive.bus,
                          dev->info->addr.drive.target,
                          dev->info->addr.drive.unit);
    }

    virBufferAsprintf(&buf, ",drive=%s-%s,id=%s",
                      virDomainDeviceAddressTypeToString(dev->info->type),
                      dev->info->alias, dev->info->alias);

    if (dev->info->bootIndex)
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info->bootIndex);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);
 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

/* This function outputs a -chardev command line option which describes only the
 * host side of the character device */
static char *
qemuBuildChrChardevStr(virDomainChrSourceDefPtr dev, const char *alias,
                       virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool telnet;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferAsprintf(&buf, "null,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferAsprintf(&buf, "vc,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAsprintf(&buf, "pty,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferAsprintf(&buf, "%s,id=char%s,path=%s",
                          STRPREFIX(alias, "parallel") ? "parport" : "tty",
                          alias, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(&buf, "file,id=char%s,path=%s", alias,
                          dev->data.file.path);
        if (dev->data.file.append != VIR_TRISTATE_SWITCH_ABSENT) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_FILE_APPEND)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("append not supported in this QEMU binary"));
                goto error;
            }

            virBufferAsprintf(&buf, ",append=%s",
                              virTristateSwitchTypeToString(dev->data.file.append));
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(&buf, "pipe,id=char%s,path=%s", alias,
                          dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAsprintf(&buf, "stdio,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = dev->data.udp.connectHost;
        const char *bindHost = dev->data.udp.bindHost;
        const char *bindService = dev->data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        virBufferAsprintf(&buf,
                          "udp,id=char%s,host=%s,port=%s,localaddr=%s,"
                          "localport=%s",
                          alias,
                          connectHost,
                          dev->data.udp.connectService,
                          bindHost, bindService);
        break;
    }
    case VIR_DOMAIN_CHR_TYPE_TCP:
        telnet = dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        virBufferAsprintf(&buf,
                          "socket,id=char%s,host=%s,port=%s%s%s",
                          alias,
                          dev->data.tcp.host,
                          dev->data.tcp.service,
                          telnet ? ",telnet" : "",
                          dev->data.tcp.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&buf,
                          "socket,id=char%s,path=%s%s",
                          alias,
                          dev->data.nix.path,
                          dev->data.nix.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEVMC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spicevmc not supported in this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "spicevmc,id=char%s,name=%s", alias,
                          virDomainChrSpicevmcTypeToString(dev->data.spicevmc));
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV_SPICEPORT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spiceport not supported in this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "spiceport,id=char%s,name=%s", alias,
                          dev->data.spiceport.channel);
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%s'"),
                       virDomainChrTypeToString(dev->type));
        goto error;
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *
qemuBuildChrArgStr(virDomainChrSourceDefPtr dev, const char *prefix)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (prefix)
        virBufferAdd(&buf, prefix, strlen(prefix));

    switch ((virDomainChrType)dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferAddLit(&buf, "null");
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferAddLit(&buf, "vc");
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAddLit(&buf, "pty");
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferStrcat(&buf, dev->data.file.path, NULL);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(&buf, "file:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(&buf, "pipe:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAddLit(&buf, "stdio");
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = dev->data.udp.connectHost;
        const char *bindHost = dev->data.udp.bindHost;
        const char *bindService  = dev->data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        virBufferAsprintf(&buf, "udp:%s:%s@%s:%s",
                          connectHost,
                          dev->data.udp.connectService,
                          bindHost,
                          bindService);
        break;
    }
    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET) {
            virBufferAsprintf(&buf, "telnet:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        } else {
            virBufferAsprintf(&buf, "tcp:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&buf, "unix:%s%s",
                          dev->data.nix.path,
                          dev->data.nix.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *
qemuBuildVirtioSerialPortDevStr(virDomainDefPtr def,
                                virDomainChrDefPtr dev,
                                virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *contAlias;

    switch (dev->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        virBufferAddLit(&buf, "virtconsole");
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        /* Legacy syntax  '-device spicevmc' */
        if (dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SPICEVMC)) {
            virBufferAddLit(&buf, "spicevmc");
        } else {
            virBufferAddLit(&buf, "virtserialport");
        }
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use virtio serial for parallel/serial devices"));
        return NULL;
    }

    if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
        dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
        /* Check it's a virtio-serial address */
        if (dev->info.type !=
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL)
        {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("virtio serial device has invalid address type"));
            goto error;
        }

        contAlias = virDomainControllerAliasFind(def, VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
                                                 dev->info.addr.vioserial.controller);
        if (!contAlias)
            goto error;

        virBufferAsprintf(&buf, ",bus=%s.%d,nr=%d", contAlias,
                          dev->info.addr.vioserial.bus,
                          dev->info.addr.vioserial.port);
    }

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
        dev->target.name &&
        STRNEQ(dev->target.name, "com.redhat.spice.0")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported spicevmc target name '%s'"),
                       dev->target.name);
        goto error;
    }

    if (!(dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
          dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
          virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SPICEVMC))) {
        virBufferAsprintf(&buf, ",chardev=char%s,id=%s",
                          dev->info.alias, dev->info.alias);
        if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
            (dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC ||
             dev->target.name)) {
            virBufferAsprintf(&buf, ",name=%s", dev->target.name
                              ? dev->target.name : "com.redhat.spice.0");
        }
    } else {
        virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
    }
    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildSclpDevStr(virDomainChrDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE) {
        switch (dev->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
            virBufferAddLit(&buf, "sclpconsole");
            break;
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            virBufferAddLit(&buf, "sclplmconsole");
            break;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use slcp with devices other than console"));
        goto error;
    }
    virBufferAsprintf(&buf, ",chardev=char%s,id=%s",
                      dev->info.alias, dev->info.alias);
    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
qemuBuildRNGBackendChrdevStr(virDomainRNGDefPtr rng,
                             virQEMUCapsPtr qemuCaps,
                             char **chr)
{
    *chr = NULL;

    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
    case VIR_DOMAIN_RNG_BACKEND_LAST:
        /* no chardev backend is needed */
        return 0;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (!(*chr = qemuBuildChrChardevStr(rng->source.chardev,
                                            rng->info.alias, qemuCaps)))
            return -1;
    }

    return 0;
}


int
qemuBuildRNGBackendProps(virDomainRNGDefPtr rng,
                         virQEMUCapsPtr qemuCaps,
                         const char **type,
                         virJSONValuePtr *props)
{
    char *charBackendAlias = NULL;
    int ret = -1;

    switch ((virDomainRNGBackend) rng->backend) {
    case VIR_DOMAIN_RNG_BACKEND_RANDOM:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_RANDOM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the rng-random "
                             "backend"));
            goto cleanup;
        }

        *type = "rng-random";

        if (virJSONValueObjectCreate(props, "s:filename", rng->source.file,
                                     NULL) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_RNG_BACKEND_EGD:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_RNG_EGD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this qemu doesn't support the rng-egd "
                             "backend"));
            goto cleanup;
        }

        *type = "rng-egd";

        if (virAsprintf(&charBackendAlias, "char%s", rng->info.alias) < 0)
            goto cleanup;

        if (virJSONValueObjectCreate(props, "s:chardev", charBackendAlias,
                                     NULL) < 0)
            goto cleanup;

        break;

    case VIR_DOMAIN_RNG_BACKEND_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown rng-random backend"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(charBackendAlias);
    return ret;
}


static char *
qemuBuildRNGBackendStr(virDomainRNGDefPtr rng,
                       virQEMUCapsPtr qemuCaps)
{
    const char *type = NULL;
    char *alias = NULL;
    virJSONValuePtr props = NULL;
    char *ret = NULL;

    if (virAsprintf(&alias, "obj%s", rng->info.alias) < 0)
        goto cleanup;

    if (qemuBuildRNGBackendProps(rng, qemuCaps, &type, &props) < 0)
        goto cleanup;

    ret = qemuBuildObjectCommandlineFromJSON(type, alias, props);

 cleanup:
    VIR_FREE(alias);
    virJSONValueFree(props);
    return ret;
}


char *
qemuBuildRNGDevStr(virDomainDefPtr def,
                   virDomainRNGDefPtr dev,
                   virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (dev->model != VIR_DOMAIN_RNG_MODEL_VIRTIO ||
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_RNG)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("this qemu doesn't support RNG device type '%s'"),
                       virDomainRNGModelTypeToString(dev->model));
        goto error;
    }

    if (!qemuCheckCCWS390AddressSupport(def, dev->info, qemuCaps,
                                        dev->source.file))
        goto error;

    if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
        virBufferAsprintf(&buf, "virtio-rng-ccw,rng=obj%s,id=%s",
                          dev->info.alias, dev->info.alias);
    else if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
        virBufferAsprintf(&buf, "virtio-rng-s390,rng=obj%s,id=%s",
                          dev->info.alias, dev->info.alias);
    else if (dev->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO)
        virBufferAsprintf(&buf, "virtio-rng-device,rng=obj%s,id=%s",
                          dev->info.alias, dev->info.alias);
    else
        virBufferAsprintf(&buf, "virtio-rng-pci,rng=obj%s,id=%s",
                          dev->info.alias, dev->info.alias);

    if (dev->rate > 0) {
        virBufferAsprintf(&buf, ",max-bytes=%u", dev->rate);
        if (dev->period)
            virBufferAsprintf(&buf, ",period=%u", dev->period);
        else
            virBufferAddLit(&buf, ",period=1000");
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &dev->info, qemuCaps) < 0)
        goto error;
    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *qemuBuildTPMBackendStr(const virDomainDef *def,
                                    virCommandPtr cmd,
                                    virQEMUCapsPtr qemuCaps,
                                    const char *emulator,
                                    int *tpmfd, int *cancelfd)
{
    const virDomainTPMDef *tpm = def->tpm;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type = virDomainTPMBackendTypeToString(tpm->type);
    char *cancel_path = NULL, *devset = NULL;
    const char *tpmdev;

    *tpmfd = -1;
    *cancelfd = -1;

    virBufferAsprintf(&buf, "%s,id=tpm-%s", type, tpm->info.alias);

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_TPM_PASSTHROUGH))
            goto no_support;

        tpmdev = tpm->data.passthrough.source.data.file.path;
        if (!(cancel_path = virTPMCreateCancelPath(tpmdev)))
            goto error;

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_ADD_FD)) {
            *tpmfd = open(tpmdev, O_RDWR);
            if (*tpmfd < 0) {
                virReportSystemError(errno, _("Could not open TPM device %s"),
                                     tpmdev);
                goto error;
            }

            virCommandPassFD(cmd, *tpmfd,
                             VIR_COMMAND_PASS_FD_CLOSE_PARENT);
            devset = qemuVirCommandGetDevSet(cmd, *tpmfd);
            if (devset == NULL)
                goto error;

            *cancelfd = open(cancel_path, O_WRONLY);
            if (*cancelfd < 0) {
                virReportSystemError(errno,
                                     _("Could not open TPM device's cancel "
                                       "path %s"), cancel_path);
                goto error;
            }
            VIR_FREE(cancel_path);

            virCommandPassFD(cmd, *cancelfd,
                             VIR_COMMAND_PASS_FD_CLOSE_PARENT);
            cancel_path = qemuVirCommandGetDevSet(cmd, *cancelfd);
            if (cancel_path == NULL)
                goto error;
        }
        virBufferAddLit(&buf, ",path=");
        virBufferEscape(&buf, ',', ",", "%s", devset ? devset : tpmdev);

        virBufferAddLit(&buf, ",cancel-path=");
        virBufferEscape(&buf, ',', ",", "%s", cancel_path);

        VIR_FREE(devset);
        VIR_FREE(cancel_path);

        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        goto error;
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 no_support:
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("The QEMU executable %s does not support TPM "
                     "backend type %s"),
                   emulator, type);

 error:
    VIR_FREE(devset);
    VIR_FREE(cancel_path);

    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *qemuBuildTPMDevStr(const virDomainDef *def,
                                virQEMUCapsPtr qemuCaps,
                                const char *emulator)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const virDomainTPMDef *tpm = def->tpm;
    const char *model = virDomainTPMModelTypeToString(tpm->model);

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_TPM_TIS)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("The QEMU executable %s does not support TPM "
                       "model %s"),
                       emulator, model);
        goto error;
    }

    virBufferAsprintf(&buf, "%s,tpmdev=tpm-%s,id=%s",
                      model, tpm->info.alias, tpm->info.alias);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *qemuBuildSmbiosBiosStr(virSysinfoBIOSDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=0");

    /* 0:Vendor */
    if (def->vendor)
        virBufferAsprintf(&buf, ",vendor=%s", def->vendor);
    /* 0:BIOS Version */
    if (def->version)
        virBufferAsprintf(&buf, ",version=%s", def->version);
    /* 0:BIOS Release Date */
    if (def->date)
        virBufferAsprintf(&buf, ",date=%s", def->date);
    /* 0:System BIOS Major Release and 0:System BIOS Minor Release */
    if (def->release)
        virBufferAsprintf(&buf, ",release=%s", def->release);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *qemuBuildSmbiosSystemStr(virSysinfoSystemDefPtr def,
                                      bool skip_uuid)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!def ||
        (!def->manufacturer && !def->product && !def->version &&
         !def->serial && (!def->uuid || skip_uuid) &&
         def->sku && !def->family))
        return NULL;

    virBufferAddLit(&buf, "type=1");

    /* 1:Manufacturer */
    if (def->manufacturer)
        virBufferAsprintf(&buf, ",manufacturer=%s",
                          def->manufacturer);
     /* 1:Product Name */
    if (def->product)
        virBufferAsprintf(&buf, ",product=%s", def->product);
    /* 1:Version */
    if (def->version)
        virBufferAsprintf(&buf, ",version=%s", def->version);
    /* 1:Serial Number */
    if (def->serial)
        virBufferAsprintf(&buf, ",serial=%s", def->serial);
    /* 1:UUID */
    if (def->uuid && !skip_uuid)
        virBufferAsprintf(&buf, ",uuid=%s", def->uuid);
    /* 1:SKU Number */
    if (def->sku)
        virBufferAsprintf(&buf, ",sku=%s", def->sku);
    /* 1:Family */
    if (def->family)
        virBufferAsprintf(&buf, ",family=%s", def->family);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *qemuBuildSmbiosBaseBoardStr(virSysinfoBaseBoardDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!def)
        return NULL;

    virBufferAddLit(&buf, "type=2");

    /* 2:Manufacturer */
    if (def->manufacturer)
        virBufferAsprintf(&buf, ",manufacturer=%s",
                          def->manufacturer);
    /* 2:Product Name */
    if (def->product)
        virBufferAsprintf(&buf, ",product=%s", def->product);
    /* 2:Version */
    if (def->version)
        virBufferAsprintf(&buf, ",version=%s", def->version);
    /* 2:Serial Number */
    if (def->serial)
        virBufferAsprintf(&buf, ",serial=%s", def->serial);
    /* 2:Asset Tag */
    if (def->asset)
        virBufferAsprintf(&buf, ",asset=%s", def->asset);
    /* 2:Location */
    if (def->location)
        virBufferAsprintf(&buf, ",location=%s", def->location);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildClockArgStr(virDomainClockDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (def->offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        virBufferAddLit(&buf, "base=utc");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virBufferAddLit(&buf, "base=localtime");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE: {
        time_t now = time(NULL);
        struct tm nowbits;

        if (def->data.variable.basis == VIR_DOMAIN_CLOCK_BASIS_LOCALTIME) {
            long localOffset;

            /* in the case of basis='localtime', rather than trying to
             * keep that basis (and associated offset from UTC) in the
             * status and deal with adding in the difference each time
             * there is an RTC_CHANGE event, it is simpler and less
             * error prone to just convert the adjustment an offset
             * from UTC right now (and change the status to
             * "basis='utc' to reflect this). This eliminates
             * potential errors in both RTC_CHANGE events and in
             * migration (in the case that the status of DST, or the
             * timezone of the destination host, changed relative to
             * startup).
             */
            if (virTimeLocalOffsetFromUTC(&localOffset) < 0)
               goto error;
            def->data.variable.adjustment += localOffset;
            def->data.variable.basis = VIR_DOMAIN_CLOCK_BASIS_UTC;
        }

        now += def->data.variable.adjustment;
        gmtime_r(&now, &nowbits);

        /* when an RTC_CHANGE event is received from qemu, we need to
         * have the adjustment used at domain start time available to
         * compute the new offset from UTC. As this new value is
         * itself stored in def->data.variable.adjustment, we need to
         * save a copy of it now.
        */
        def->data.variable.adjustment0 = def->data.variable.adjustment;

        virBufferAsprintf(&buf, "base=%d-%02d-%02dT%02d:%02d:%02d",
                          nowbits.tm_year + 1900,
                          nowbits.tm_mon + 1,
                          nowbits.tm_mday,
                          nowbits.tm_hour,
                          nowbits.tm_min,
                          nowbits.tm_sec);
    }   break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported clock offset '%s'"),
                       virDomainClockOffsetTypeToString(def->offset));
        goto error;
    }

    /* Look for an 'rtc' timer element, and add in appropriate clock= and driftfix= */
    size_t i;
    for (i = 0; i < def->ntimers; i++) {
        if (def->timers[i]->name == VIR_DOMAIN_TIMER_NAME_RTC) {
            switch (def->timers[i]->track) {
            case -1: /* unspecified - use hypervisor default */
                break;
            case VIR_DOMAIN_TIMER_TRACK_BOOT:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported rtc timer track '%s'"),
                               virDomainTimerTrackTypeToString(def->timers[i]->track));
                goto error;
            case VIR_DOMAIN_TIMER_TRACK_GUEST:
                virBufferAddLit(&buf, ",clock=vm");
                break;
            case VIR_DOMAIN_TIMER_TRACK_WALL:
                virBufferAddLit(&buf, ",clock=host");
                break;
            }

            switch (def->timers[i]->tickpolicy) {
            case -1:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* This is the default - missed ticks delivered when
                   next scheduled, at normal rate */
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                /* deliver ticks at a faster rate until caught up */
                virBufferAddLit(&buf, ",driftfix=slew");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported rtc timer tickpolicy '%s'"),
                               virDomainTimerTickpolicyTypeToString(def->timers[i]->tickpolicy));
                goto error;
            }
            break; /* no need to check other timers - there is only one rtc */
        }
    }

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static int
qemuBuildCpuModelArgStr(virQEMUDriverPtr driver,
                        const virDomainDef *def,
                        virBufferPtr buf,
                        virQEMUCapsPtr qemuCaps,
                        bool *hasHwVirt,
                        bool migrating)
{
    int ret = -1;
    size_t i;
    virCPUDefPtr host = NULL;
    virCPUDefPtr guest = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUDefPtr featCpu = NULL;
    size_t ncpus = 0;
    char **cpus = NULL;
    virCPUDataPtr data = NULL;
    virCPUDataPtr hostData = NULL;
    char *compare_msg = NULL;
    virCPUCompareResult cmp;
    const char *preferred;
    virCapsPtr caps = NULL;
    bool compareAgainstHost = ((def->virtType == VIR_DOMAIN_VIRT_KVM ||
                                def->cpu->mode != VIR_CPU_MODE_CUSTOM) &&
                               def->cpu->mode != VIR_CPU_MODE_HOST_PASSTHROUGH);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    host = caps->host.cpu;

    if (!host ||
        !host->model ||
        (ncpus = virQEMUCapsGetCPUDefinitions(qemuCaps, &cpus)) == 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("CPU specification not supported by hypervisor"));
        goto cleanup;
    }

    if (!(cpu = virCPUDefCopy(def->cpu)))
        goto cleanup;

    if (cpu->mode == VIR_CPU_MODE_HOST_MODEL &&
        !migrating &&
        cpuUpdate(cpu, host) < 0)
        goto cleanup;

    /* For non-KVM, CPU features are emulated, so host compat doesn't matter */
    if (compareAgainstHost) {
        bool noTSX = false;

        cmp = cpuGuestData(host, cpu, &data, &compare_msg);
        switch (cmp) {
        case VIR_CPU_COMPARE_INCOMPATIBLE:
            if (cpuEncode(host->arch, host, NULL, &hostData,
                          NULL, NULL, NULL, NULL) == 0 &&
                (!cpuHasFeature(hostData, "hle") ||
                 !cpuHasFeature(hostData, "rtm")) &&
                (STREQ_NULLABLE(cpu->model, "Haswell") ||
                 STREQ_NULLABLE(cpu->model, "Broadwell")))
                noTSX = true;

            if (compare_msg) {
                if (noTSX) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("guest and host CPU are not compatible: "
                                     "%s; try using '%s-noTSX' CPU model"),
                                   compare_msg, cpu->model);
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("guest and host CPU are not compatible: "
                                     "%s"),
                                   compare_msg);
                }
            } else {
                if (noTSX) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("guest CPU is not compatible with host "
                                     "CPU; try using '%s-noTSX' CPU model"),
                                   cpu->model);
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("guest CPU is not compatible with host "
                                     "CPU"));
                }
            }
            /* fall through */
        case VIR_CPU_COMPARE_ERROR:
            goto cleanup;

        default:
            break;
        }
    }

    /* Only 'svm' requires --enable-nesting. The nested
     * 'vmx' patches now simply hook off the CPU features
     */
    if ((def->os.arch == VIR_ARCH_X86_64 || def->os.arch == VIR_ARCH_I686) &&
         compareAgainstHost) {
        int hasSVM = cpuHasFeature(data, "svm");
        if (hasSVM < 0)
            goto cleanup;
        *hasHwVirt = hasSVM > 0 ? true : false;
    }

    if ((cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH) ||
        ((cpu->mode == VIR_CPU_MODE_HOST_MODEL) &&
          ARCH_IS_PPC64(def->os.arch))) {
        const char *mode = virCPUModeTypeToString(cpu->mode);
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_HOST)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CPU mode '%s' is not supported by QEMU"
                             " binary"), mode);
            goto cleanup;
        }
        if (def->virtType != VIR_DOMAIN_VIRT_KVM) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("CPU mode '%s' is only supported with kvm"),
                           mode);
            goto cleanup;
        }
        virBufferAddLit(buf, "host");

        if (def->os.arch == VIR_ARCH_ARMV7L &&
            host->arch == VIR_ARCH_AARCH64) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_AARCH64_OFF)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("QEMU binary does not support CPU "
                                 "host-passthrough for armv7l on "
                                 "aarch64 host"));
                goto cleanup;
            }

            virBufferAddLit(buf, ",aarch64=off");
        }

        if (ARCH_IS_PPC64(def->os.arch) &&
            cpu->mode == VIR_CPU_MODE_HOST_MODEL &&
            def->cpu->model != NULL) {
            virBufferAsprintf(buf, ",compat=%s", def->cpu->model);
        } else {
            featCpu = cpu;
        }

    } else {
        if (VIR_ALLOC(guest) < 0)
            goto cleanup;
        if (VIR_STRDUP(guest->vendor_id, cpu->vendor_id) < 0)
            goto cleanup;

        if (compareAgainstHost) {
            guest->arch = host->arch;
            if (cpu->match == VIR_CPU_MATCH_MINIMUM)
                preferred = host->model;
            else
                preferred = cpu->model;

            guest->type = VIR_CPU_TYPE_GUEST;
            guest->fallback = cpu->fallback;
            if (cpuDecode(guest, data,
                          (const char **)cpus, ncpus, preferred) < 0)
                goto cleanup;
        } else {
            guest->arch = def->os.arch;
            if (VIR_STRDUP(guest->model, cpu->model) < 0)
                goto cleanup;
        }
        virBufferAdd(buf, guest->model, -1);
        if (guest->vendor_id)
            virBufferAsprintf(buf, ",vendor=%s", guest->vendor_id);
        featCpu = guest;
    }

    if (featCpu) {
        for (i = 0; i < featCpu->nfeatures; i++) {
            char sign;
            if (featCpu->features[i].policy == VIR_CPU_FEATURE_DISABLE)
                sign = '-';
            else
                sign = '+';

            virBufferAsprintf(buf, ",%c%s", sign, featCpu->features[i].name);
        }
    }

    ret = 0;
 cleanup:
    virObjectUnref(caps);
    VIR_FREE(compare_msg);
    cpuDataFree(data);
    cpuDataFree(hostData);
    virCPUDefFree(guest);
    virCPUDefFree(cpu);
    return ret;
}

static int
qemuBuildCpuArgStr(virQEMUDriverPtr driver,
                   const virDomainDef *def,
                   const char *emulator,
                   virQEMUCapsPtr qemuCaps,
                   virArch hostarch,
                   char **opt,
                   bool *hasHwVirt,
                   bool migrating)
{
    const char *default_model;
    bool have_cpu = false;
    int ret = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    *hasHwVirt = false;

    if (def->os.arch == VIR_ARCH_I686)
        default_model = "qemu32";
    else
        default_model = "qemu64";

    if (def->cpu &&
        (def->cpu->mode != VIR_CPU_MODE_CUSTOM || def->cpu->model)) {
        if (qemuBuildCpuModelArgStr(driver, def, &buf, qemuCaps,
                                    hasHwVirt, migrating) < 0)
            goto cleanup;
        have_cpu = true;
    } else {
        /*
         * Need to force a 32-bit guest CPU type if
         *
         *  1. guest OS is i686
         *  2. host OS is x86_64
         *  3. emulator is qemu-kvm or kvm
         *
         * Or
         *
         *  1. guest OS is i686
         *  2. emulator is qemu-system-x86_64
         */
        if (def->os.arch == VIR_ARCH_I686 &&
            ((hostarch == VIR_ARCH_X86_64 &&
              strstr(emulator, "kvm")) ||
             strstr(emulator, "x86_64"))) {
            virBufferAdd(&buf, default_model, -1);
            have_cpu = true;
        }
    }

    /* Handle paravirtual timers  */
    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDefPtr timer = def->clock.timers[i];

        if (timer->present == -1)
            continue;

        if (timer->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK) {
            virBufferAsprintf(&buf, "%s,%ckvmclock",
                              have_cpu ? "" : default_model,
                              timer->present ? '+' : '-');
            have_cpu = true;
        } else if (timer->name == VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK &&
                   timer->present) {
            virBufferAsprintf(&buf, "%s,hv_time",
                              have_cpu ? "" : default_model);
            have_cpu = true;
        }
    }

    if (def->apic_eoi) {
        char sign;
        if (def->apic_eoi == VIR_TRISTATE_SWITCH_ON)
            sign = '+';
        else
            sign = '-';

        virBufferAsprintf(&buf, "%s,%ckvm_pv_eoi",
                          have_cpu ? "" : default_model,
                          sign);
        have_cpu = true;
    }

    if (def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK]) {
        char sign;
        if (def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK] == VIR_TRISTATE_SWITCH_ON)
            sign = '+';
        else
            sign = '-';

        virBufferAsprintf(&buf, "%s,%ckvm_pv_unhalt",
                          have_cpu ? "" : default_model,
                          sign);
        have_cpu = true;
    }

    if (def->features[VIR_DOMAIN_FEATURE_HYPERV] == VIR_TRISTATE_SWITCH_ON) {
        if (!have_cpu) {
            virBufferAdd(&buf, default_model, -1);
            have_cpu = true;
        }

        for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
            switch ((virDomainHyperv) i) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
                if (def->hyperv_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAsprintf(&buf, ",hv_%s",
                                      virDomainHypervTypeToString(i));
                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                if (def->hyperv_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAsprintf(&buf, ",hv_spinlocks=0x%x",
                                      def->hyperv_spinlocks);
                break;

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
    }

    for (i = 0; i < def->npanics; i++) {
        if (def->panics[i]->model == VIR_DOMAIN_PANIC_MODEL_HYPERV) {
            if (!have_cpu) {
                virBufferAdd(&buf, default_model, -1);
                have_cpu = true;
            }

            virBufferAddLit(&buf, ",hv_crash");
            break;
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_KVM] == VIR_TRISTATE_SWITCH_ON) {
        if (!have_cpu) {
            virBufferAdd(&buf, default_model, -1);
            have_cpu = true;
        }

        for (i = 0; i < VIR_DOMAIN_KVM_LAST; i++) {
            switch ((virDomainKVM) i) {
            case VIR_DOMAIN_KVM_HIDDEN:
                if (def->kvm_features[i] == VIR_TRISTATE_SWITCH_ON)
                    virBufferAddLit(&buf, ",kvm=off");
                break;

            /* coverity[dead_error_begin] */
            case VIR_DOMAIN_KVM_LAST:
                break;
            }
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_PMU]) {
        virTristateSwitch pmu = def->features[VIR_DOMAIN_FEATURE_PMU];
        if (!have_cpu)
            virBufferAdd(&buf, default_model, -1);

        virBufferAsprintf(&buf, ",pmu=%s",
                          virTristateSwitchTypeToString(pmu));
        have_cpu = true;
    }

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    *opt = virBufferContentAndReset(&buf);

    ret = 0;

 cleanup:
    return ret;
}

static int
qemuBuildObsoleteAccelArg(virCommandPtr cmd,
                          const virDomainDef *def,
                          virQEMUCapsPtr qemuCaps)
{
    bool disableKVM = false;
    bool enableKVM = false;

    switch (def->virtType) {
    case VIR_DOMAIN_VIRT_QEMU:
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
            disableKVM = true;
        break;

    case VIR_DOMAIN_VIRT_KQEMU:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("the QEMU binary does not support kqemu"));
        break;

    case VIR_DOMAIN_VIRT_KVM:
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_ENABLE_KVM)) {
            enableKVM = true;
        } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("the QEMU binary does not support kvm"));
            return -1;
        }
        break;

    case VIR_DOMAIN_VIRT_XEN:
        /* XXX better check for xenner */
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("the QEMU binary does not support %s"),
                       virDomainVirtTypeToString(def->virtType));
        return -1;
    }

    if (disableKVM)
        virCommandAddArg(cmd, "-no-kvm");
    if (enableKVM)
        virCommandAddArg(cmd, "-enable-kvm");

    return 0;
}

static bool
qemuAppendKeyWrapMachineParm(virBuffer *buf, virQEMUCapsPtr qemuCaps,
                             int flag, const char *pname, int pstate)
{
    if (pstate != VIR_TRISTATE_SWITCH_ABSENT) {
        if (!virQEMUCapsGet(qemuCaps, flag)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%s is not available with this QEMU binary"), pname);
            return false;
        }

        virBufferAsprintf(buf, ",%s=%s", pname,
                          virTristateSwitchTypeToString(pstate));
    }

    return true;
}

static bool
qemuAppendKeyWrapMachineParms(virBuffer *buf, virQEMUCapsPtr qemuCaps,
                              const virDomainKeyWrapDef *keywrap)
{
    if (!qemuAppendKeyWrapMachineParm(buf, qemuCaps, QEMU_CAPS_AES_KEY_WRAP,
                                      "aes-key-wrap", keywrap->aes))
        return false;

    if (!qemuAppendKeyWrapMachineParm(buf, qemuCaps, QEMU_CAPS_DEA_KEY_WRAP,
                                      "dea-key-wrap", keywrap->dea))
        return false;

    return true;
}

static int
qemuBuildMachineArgStr(virCommandPtr cmd,
                       const virDomainDef *def,
                       virQEMUCapsPtr qemuCaps)
{
    bool obsoleteAccel = false;

    /* This should *never* be NULL, since we always provide
     * a machine in the capabilities data for QEMU. So this
     * check is just here as a safety in case the unexpected
     * happens */
    if (!def->os.machine)
        return 0;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_OPT)) {
        /* if no parameter to the machine type is needed, we still use
         * '-M' to keep the most of the compatibility with older versions.
         */
        virCommandAddArgList(cmd, "-M", def->os.machine, NULL);
        if (def->mem.dump_core) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("dump-guest-core is not available "
                             "with this QEMU binary"));
            return -1;
        }

        if (def->mem.nosharepages) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disable shared memory is not available "
                             "with this QEMU binary"));
             return -1;
        }

        obsoleteAccel = true;

        if (def->keywrap) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("key wrap support is not available "
                             "with this QEMU binary"));
            return -1;
        }
    } else {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        virTristateSwitch vmport = def->features[VIR_DOMAIN_FEATURE_VMPORT];

        virCommandAddArg(cmd, "-machine");
        virBufferAdd(&buf, def->os.machine, -1);

        if (def->virtType == VIR_DOMAIN_VIRT_QEMU)
            virBufferAddLit(&buf, ",accel=tcg");
        else if (def->virtType == VIR_DOMAIN_VIRT_KVM)
            virBufferAddLit(&buf, ",accel=kvm");
        else
            obsoleteAccel = true;

        /* To avoid the collision of creating USB controllers when calling
         * machine->init in QEMU, it needs to set usb=off
         */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_USB_OPT))
            virBufferAddLit(&buf, ",usb=off");

        if (vmport) {
            if (!virQEMUCapsSupportsVmport(qemuCaps, def)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vmport is not available "
                                 "with this QEMU binary"));
                virBufferFreeAndReset(&buf);
                return -1;
            }

            virBufferAsprintf(&buf, ",vmport=%s",
                              virTristateSwitchTypeToString(vmport));
        }

        if (def->mem.dump_core) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DUMP_GUEST_CORE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("dump-guest-core is not available "
                                 "with this QEMU binary"));
                virBufferFreeAndReset(&buf);
                return -1;
            }

            virBufferAsprintf(&buf, ",dump-guest-core=%s",
                              virTristateSwitchTypeToString(def->mem.dump_core));
        }

        if (def->mem.nosharepages) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MEM_MERGE)) {
                virBufferAddLit(&buf, ",mem-merge=off");
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("disable shared memory is not available "
                                 "with this QEMU binary"));
                virBufferFreeAndReset(&buf);
                return -1;
            }
        }

        if (def->keywrap &&
            !qemuAppendKeyWrapMachineParms(&buf, qemuCaps, def->keywrap)) {
            virBufferFreeAndReset(&buf);
            return -1;
        }

        if (def->features[VIR_DOMAIN_FEATURE_GIC] == VIR_TRISTATE_SWITCH_ON) {
            if (def->gic_version) {
                if ((def->os.arch != VIR_ARCH_ARMV7L &&
                     def->os.arch != VIR_ARCH_AARCH64) ||
                    (STRNEQ(def->os.machine, "virt") &&
                     !STRPREFIX(def->os.machine, "virt-"))) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("gic-version option is available "
                                     "only for ARM virt machine"));
                    virBufferFreeAndReset(&buf);
                    return -1;
                }

                /* 2 is the default, so we don't put it as option for
                 * backwards compatibility
                 */
                if (def->gic_version != 2) {
                    if (!virQEMUCapsGet(qemuCaps,
                                        QEMU_CAPS_MACH_VIRT_GIC_VERSION)) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("gic-version option is not available "
                                         "with this QEMU binary"));
                        virBufferFreeAndReset(&buf);
                        return -1;
                    }

                    virBufferAsprintf(&buf, ",gic-version=%d", def->gic_version);
                }
            }
        }

        virCommandAddArgBuffer(cmd, &buf);
    }

    if (obsoleteAccel &&
        qemuBuildObsoleteAccelArg(cmd, def, qemuCaps) < 0)
        return -1;

    return 0;
}

static char *
qemuBuildSmpArgStr(const virDomainDef *def,
                   virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%u", virDomainDefGetVcpus(def));

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMP_TOPOLOGY)) {
        if (virDomainDefHasVcpusOffline(def))
            virBufferAsprintf(&buf, ",maxcpus=%u", virDomainDefGetVcpusMax(def));
        /* sockets, cores, and threads are either all zero
         * or all non-zero, thus checking one of them is enough */
        if (def->cpu && def->cpu->sockets) {
            virBufferAsprintf(&buf, ",sockets=%u", def->cpu->sockets);
            virBufferAsprintf(&buf, ",cores=%u", def->cpu->cores);
            virBufferAsprintf(&buf, ",threads=%u", def->cpu->threads);
        } else {
            virBufferAsprintf(&buf, ",sockets=%u", virDomainDefGetVcpusMax(def));
            virBufferAsprintf(&buf, ",cores=%u", 1);
            virBufferAsprintf(&buf, ",threads=%u", 1);
        }
    } else if (virDomainDefHasVcpusOffline(def)) {
        virBufferFreeAndReset(&buf);
        /* FIXME - consider hot-unplugging cpus after boot for older qemu */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("setting current vcpu count less than maximum is "
                         "not supported with this QEMU binary"));
        return NULL;
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

static int
qemuBuildMemPathStr(virQEMUDriverConfigPtr cfg,
                    virDomainDefPtr def,
                    virQEMUCapsPtr qemuCaps,
                    virCommandPtr cmd)
{
    const long system_page_size = virGetSystemPageSizeKB();
    char *mem_path = NULL;
    size_t i = 0;

    /*
     *  No-op if hugepages were not requested.
     */
    if (!def->mem.nhugepages)
        return 0;

    /* There is one special case: if user specified "huge"
     * pages of regular system pages size.
     * And there is nothing to do in this case.
     */
    if (def->mem.hugepages[0].size == system_page_size)
        return 0;

    if (!cfg->nhugetlbfs) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("hugetlbfs filesystem is not mounted "
                               "or disabled by administrator config"));
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MEM_PATH)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("hugepage backing not supported by '%s'"),
                       def->emulator);
        return -1;
    }

    if (!def->mem.hugepages[0].size) {
        if (!(mem_path = qemuGetDefaultHugepath(cfg->hugetlbfs,
                                                cfg->nhugetlbfs)))
            return -1;
    } else {
        for (i = 0; i < cfg->nhugetlbfs; i++) {
            if (cfg->hugetlbfs[i].size == def->mem.hugepages[0].size)
                break;
        }

        if (i == cfg->nhugetlbfs) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find any usable hugetlbfs "
                             "mount for %llu KiB"),
                           def->mem.hugepages[0].size);
            return -1;
        }

        if (!(mem_path = qemuGetHugepagePath(&cfg->hugetlbfs[i])))
            return -1;
    }

    virCommandAddArgList(cmd, "-mem-prealloc", "-mem-path", mem_path, NULL);
    VIR_FREE(mem_path);

    return 0;
}

static int
qemuBuildNumaArgStr(virQEMUDriverConfigPtr cfg,
                    virDomainDefPtr def,
                    virCommandPtr cmd,
                    virQEMUCapsPtr qemuCaps,
                    virBitmapPtr auto_nodeset)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *cpumask = NULL, *tmpmask = NULL, *next = NULL;
    char **nodeBackends = NULL;
    bool needBackend = false;
    int rc;
    int ret = -1;
    size_t ncells = virDomainNumaGetNodeCount(def->numa);
    const long system_page_size = virGetSystemPageSizeKB();

    if (virDomainNumatuneHasPerNodeBinding(def->numa) &&
        !(virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_RAM) ||
          virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Per-node memory binding is not supported "
                         "with this QEMU"));
        goto cleanup;
    }

    if (def->mem.nhugepages &&
        def->mem.hugepages[0].size != system_page_size &&
        !virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("huge pages per NUMA node are not "
                         "supported with this QEMU"));
        goto cleanup;
    }

    if (!virDomainNumatuneNodesetIsAvailable(def->numa, auto_nodeset))
        goto cleanup;

    for (i = 0; i < def->mem.nhugepages; i++) {
        ssize_t next_bit, pos = 0;

        if (!def->mem.hugepages[i].nodemask) {
            /* This is the master hugepage to use. Skip it as it has no
             * nodemask anyway. */
            continue;
        }

        if (ncells) {
            /* Fortunately, we allow only guest NUMA nodes to be continuous
             * starting from zero. */
            pos = ncells - 1;
        }

        next_bit = virBitmapNextSetBit(def->mem.hugepages[i].nodemask, pos);
        if (next_bit >= 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("hugepages: node %zd not found"),
                           next_bit);
            goto cleanup;
        }
    }

    if (VIR_ALLOC_N(nodeBackends, ncells) < 0)
        goto cleanup;

    /* using of -numa memdev= cannot be combined with -numa mem=, thus we
     * need to check which approach to use */
    for (i = 0; i < ncells; i++) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_RAM) ||
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_MEMORY_FILE)) {
            if ((rc = qemuBuildMemoryCellBackendStr(def, qemuCaps, cfg, i,
                                                    auto_nodeset,
                                                    &nodeBackends[i])) < 0)
                goto cleanup;

            if (rc == 0)
                needBackend = true;
        } else {
            if (virDomainNumaGetNodeMemoryAccessMode(def->numa, i)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Shared memory mapping is not supported "
                                 "with this QEMU"));
                goto cleanup;
            }
        }
    }

    if (!needBackend &&
        qemuBuildMemPathStr(cfg, def, qemuCaps, cmd) < 0)
        goto cleanup;

    for (i = 0; i < ncells; i++) {
        VIR_FREE(cpumask);
        if (!(cpumask = virBitmapFormat(virDomainNumaGetNodeCpumask(def->numa, i))))
            goto cleanup;

        if (strchr(cpumask, ',') &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_NUMA)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disjoint NUMA cpu ranges are not supported "
                             "with this QEMU"));
            goto cleanup;
        }

        if (needBackend)
            virCommandAddArgList(cmd, "-object", nodeBackends[i], NULL);

        virCommandAddArg(cmd, "-numa");
        virBufferAsprintf(&buf, "node,nodeid=%zu", i);

        for (tmpmask = cpumask; tmpmask; tmpmask = next) {
            if ((next = strchr(tmpmask, ',')))
                *(next++) = '\0';
            virBufferAddLit(&buf, ",cpus=");
            virBufferAdd(&buf, tmpmask, -1);
        }

        if (needBackend)
            virBufferAsprintf(&buf, ",memdev=ram-node%zu", i);
        else
            virBufferAsprintf(&buf, ",mem=%llu",
                              virDomainNumaGetNodeMemorySize(def->numa, i) / 1024);

        virCommandAddArgBuffer(cmd, &buf);
    }
    ret = 0;

 cleanup:
    VIR_FREE(cpumask);

    if (nodeBackends) {
        for (i = 0; i < ncells; i++)
            VIR_FREE(nodeBackends[i]);

        VIR_FREE(nodeBackends);
    }

    virBufferFreeAndReset(&buf);
    return ret;
}


static int
qemuBuildGraphicsVNCCommandLine(virQEMUDriverConfigPtr cfg,
                                virCommandPtr cmd,
                                virDomainDefPtr def,
                                virQEMUCapsPtr qemuCaps,
                                virDomainGraphicsDefPtr graphics)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *listenNetwork;
    const char *listenAddr = NULL;
    char *netAddr = NULL;
    bool escapeAddr;
    int ret;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vnc graphics are not supported with this QEMU"));
        goto error;
    }

    if (graphics->data.vnc.socket || cfg->vncAutoUnixSocket) {
        if (!graphics->data.vnc.socket &&
            virAsprintf(&graphics->data.vnc.socket,
                        "%s/domain-%s/vnc.sock", cfg->libDir, def->name) == -1)
            goto error;

        virBufferAsprintf(&opt, "unix:%s", graphics->data.vnc.socket);

    } else {
        if (!graphics->data.vnc.autoport &&
            (graphics->data.vnc.port < 5900 ||
             graphics->data.vnc.port > 65535)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc port must be in range [5900,65535]"));
            goto error;
        }

        switch (virDomainGraphicsListenGetType(graphics, 0)) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            listenAddr = virDomainGraphicsListenGetAddress(graphics, 0);
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            listenNetwork = virDomainGraphicsListenGetNetwork(graphics, 0);
            if (!listenNetwork)
                break;
            ret = networkGetNetworkAddress(listenNetwork, &netAddr);
            if (ret <= -2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("network-based listen not possible, "
                                       "network driver not present"));
                goto error;
            }
            if (ret < 0)
                goto error;

            listenAddr = netAddr;
            /* store the address we found in the <graphics> element so it
             * will show up in status. */
            if (virDomainGraphicsListenSetAddress(graphics, 0,
                                                  listenAddr, -1, false) < 0)
                goto error;
            break;
        }

        if (!listenAddr)
            listenAddr = cfg->vncListen;

        escapeAddr = strchr(listenAddr, ':') != NULL;
        if (escapeAddr)
            virBufferAsprintf(&opt, "[%s]", listenAddr);
        else
            virBufferAdd(&opt, listenAddr, -1);
        virBufferAsprintf(&opt, ":%d",
                          graphics->data.vnc.port - 5900);

        VIR_FREE(netAddr);
    }

    if (!graphics->data.vnc.socket &&
        graphics->data.vnc.websocket) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC_WEBSOCKET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("VNC WebSockets are not supported "
                             "with this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&opt, ",websocket=%d", graphics->data.vnc.websocket);
    }

    if (graphics->data.vnc.sharePolicy) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VNC_SHARE_POLICY)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc display sharing policy is not "
                             "supported with this QEMU"));
            goto error;
        }

        virBufferAsprintf(&opt, ",share=%s",
                          virDomainGraphicsVNCSharePolicyTypeToString(
                              graphics->data.vnc.sharePolicy));
    }

    if (graphics->data.vnc.auth.passwd || cfg->vncPassword)
        virBufferAddLit(&opt, ",password");

    if (cfg->vncTLS) {
        virBufferAddLit(&opt, ",tls");
        if (cfg->vncTLSx509verify)
            virBufferAsprintf(&opt, ",x509verify=%s", cfg->vncTLSx509certdir);
        else
            virBufferAsprintf(&opt, ",x509=%s", cfg->vncTLSx509certdir);
    }

    if (cfg->vncSASL) {
        virBufferAddLit(&opt, ",sasl");

        if (cfg->vncSASLdir)
            virCommandAddEnvPair(cmd, "SASL_CONF_PATH", cfg->vncSASLdir);

        /* TODO: Support ACLs later */
    }

    virCommandAddArg(cmd, "-vnc");
    virCommandAddArgBuffer(cmd, &opt);
    if (graphics->data.vnc.keymap)
        virCommandAddArgList(cmd, "-k", graphics->data.vnc.keymap, NULL);

    /* Unless user requested it, set the audio backend to none, to
     * prevent it opening the host OS audio devices, since that causes
     * security issues and might not work when using VNC.
     */
    if (cfg->vncAllowHostAudio)
        virCommandAddEnvPassBlockSUID(cmd, "QEMU_AUDIO_DRV", NULL);
    else
        virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=none");

    return 0;

 error:
    VIR_FREE(netAddr);
    virBufferFreeAndReset(&opt);
    return -1;
}


static int
qemuBuildGraphicsSPICECommandLine(virQEMUDriverConfigPtr cfg,
                                  virCommandPtr cmd,
                                  virQEMUCapsPtr qemuCaps,
                                  virDomainGraphicsDefPtr graphics)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *listenNetwork;
    const char *listenAddr = NULL;
    char *netAddr = NULL;
    int ret;
    int defaultMode = graphics->data.spice.defaultMode;
    int port = graphics->data.spice.port;
    int tlsPort = graphics->data.spice.tlsPort;
    size_t i;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("spice graphics are not supported with this QEMU"));
        goto error;
    }

    if (port > 0 || tlsPort <= 0)
        virBufferAsprintf(&opt, "port=%u", port);

    if (tlsPort > 0) {
        if (!cfg->spiceTLS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spice TLS port set in XML configuration,"
                             " but TLS is disabled in qemu.conf"));
            goto error;
        }
        if (port > 0)
            virBufferAddChar(&opt, ',');
        virBufferAsprintf(&opt, "tls-port=%u", tlsPort);
    }

    if (cfg->spiceSASL) {
        virBufferAddLit(&opt, ",sasl");

        if (cfg->spiceSASLdir)
            virCommandAddEnvPair(cmd, "SASL_CONF_PATH",
                                 cfg->spiceSASLdir);

        /* TODO: Support ACLs later */
    }

    switch (virDomainGraphicsListenGetType(graphics, 0)) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
        listenAddr = virDomainGraphicsListenGetAddress(graphics, 0);
        break;

    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        listenNetwork = virDomainGraphicsListenGetNetwork(graphics, 0);
        if (!listenNetwork)
            break;
        ret = networkGetNetworkAddress(listenNetwork, &netAddr);
        if (ret <= -2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("network-based listen not possible, "
                                   "network driver not present"));
            goto error;
        }
        if (ret < 0)
            goto error;

        listenAddr = netAddr;
        /* store the address we found in the <graphics> element so it will
         * show up in status. */
        if (virDomainGraphicsListenSetAddress(graphics, 0,
                                              listenAddr, -1, false) < 0)
           goto error;
        break;
    }

    if (!listenAddr)
        listenAddr = cfg->spiceListen;
    if (listenAddr)
        virBufferAsprintf(&opt, ",addr=%s", listenAddr);

    VIR_FREE(netAddr);

    if (graphics->data.spice.mousemode) {
        switch (graphics->data.spice.mousemode) {
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER:
            virBufferAddLit(&opt, ",agent-mouse=off");
            break;
        case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT:
            virBufferAddLit(&opt, ",agent-mouse=on");
            break;
        default:
            break;
        }
    }

    /* In the password case we set it via monitor command, to avoid
     * making it visible on CLI, so there's no use of password=XXX
     * in this bit of the code */
    if (!graphics->data.spice.auth.passwd &&
        !cfg->spicePassword)
        virBufferAddLit(&opt, ",disable-ticketing");

    if (tlsPort > 0)
        virBufferAsprintf(&opt, ",x509-dir=%s", cfg->spiceTLSx509certdir);

    switch (defaultMode) {
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
        virBufferAddLit(&opt, ",tls-channel=default");
        break;
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
        virBufferAddLit(&opt, ",plaintext-channel=default");
        break;
    case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
        /* nothing */
        break;
    }

    for (i = 0; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST; i++) {
        switch (graphics->data.spice.channels[i]) {
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
            if (tlsPort <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("spice secure channels set in XML configuration, "
                                 "but TLS port is not provided"));
                goto error;
            }
            virBufferAsprintf(&opt, ",tls-channel=%s",
                              virDomainGraphicsSpiceChannelNameTypeToString(i));
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
            if (port <= 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("spice insecure channels set in XML "
                                 "configuration, but plain port is not provided"));
                goto error;
            }
            virBufferAsprintf(&opt, ",plaintext-channel=%s",
                              virDomainGraphicsSpiceChannelNameTypeToString(i));
            break;

        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
            switch (defaultMode) {
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                if (tlsPort <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("spice defaultMode secure requested in XML "
                                     "configuration but TLS port not provided"));
                    goto error;
                }
                break;

            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                if (port <= 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("spice defaultMode insecure requested in XML "
                                     "configuration but plain port not provided"));
                    goto error;
                }
                break;

            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
                /* don't care */
            break;
            }
        }
    }

    if (graphics->data.spice.image)
        virBufferAsprintf(&opt, ",image-compression=%s",
                          virDomainGraphicsSpiceImageCompressionTypeToString(graphics->data.spice.image));
    if (graphics->data.spice.jpeg)
        virBufferAsprintf(&opt, ",jpeg-wan-compression=%s",
                          virDomainGraphicsSpiceJpegCompressionTypeToString(graphics->data.spice.jpeg));
    if (graphics->data.spice.zlib)
        virBufferAsprintf(&opt, ",zlib-glz-wan-compression=%s",
                          virDomainGraphicsSpiceZlibCompressionTypeToString(graphics->data.spice.zlib));
    if (graphics->data.spice.playback)
        virBufferAsprintf(&opt, ",playback-compression=%s",
                          virTristateSwitchTypeToString(graphics->data.spice.playback));
    if (graphics->data.spice.streaming)
        virBufferAsprintf(&opt, ",streaming-video=%s",
                          virDomainGraphicsSpiceStreamingModeTypeToString(graphics->data.spice.streaming));
    if (graphics->data.spice.copypaste == VIR_TRISTATE_BOOL_NO)
        virBufferAddLit(&opt, ",disable-copy-paste");
    if (graphics->data.spice.filetransfer == VIR_TRISTATE_BOOL_NO) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPICE_FILE_XFER_DISABLE)) {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("This QEMU can't disable file transfers through spice"));
            goto error;
        } else {
            virBufferAddLit(&opt, ",disable-agent-file-xfer");
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SEAMLESS_MIGRATION)) {
        /* If qemu supports seamless migration turn it
         * unconditionally on. If migration destination
         * doesn't support it, it fallbacks to previous
         * migration algorithm silently. */
        virBufferAddLit(&opt, ",seamless-migration=on");
    }

    virCommandAddArg(cmd, "-spice");
    virCommandAddArgBuffer(cmd, &opt);
    if (graphics->data.spice.keymap)
        virCommandAddArgList(cmd, "-k",
                             graphics->data.spice.keymap, NULL);
    /* SPICE includes native support for tunnelling audio, so we
     * set the audio backend to point at SPICE's own driver
     */
    virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=spice");

    return 0;

 error:
    VIR_FREE(netAddr);
    virBufferFreeAndReset(&opt);
    return -1;
}

static int
qemuBuildGraphicsCommandLine(virQEMUDriverConfigPtr cfg,
                             virCommandPtr cmd,
                             virDomainDefPtr def,
                             virQEMUCapsPtr qemuCaps,
                             virDomainGraphicsDefPtr graphics)
{
    switch ((virDomainGraphicsType) graphics->type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SDL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("sdl not supported by '%s'"), def->emulator);
            return -1;
        }

        if (graphics->data.sdl.xauth)
            virCommandAddEnvPair(cmd, "XAUTHORITY", graphics->data.sdl.xauth);
        if (graphics->data.sdl.display)
            virCommandAddEnvPair(cmd, "DISPLAY", graphics->data.sdl.display);
        if (graphics->data.sdl.fullscreen)
            virCommandAddArg(cmd, "-full-screen");

        /* If using SDL for video, then we should just let it
         * use QEMU's host audio drivers, possibly SDL too
         * User can set these two before starting libvirtd
         */
        virCommandAddEnvPassBlockSUID(cmd, "QEMU_AUDIO_DRV", NULL);
        virCommandAddEnvPassBlockSUID(cmd, "SDL_AUDIODRIVER", NULL);

        /* New QEMU has this flag to let us explicitly ask for
         * SDL graphics. This is better than relying on the
         * default, since the default changes :-( */
        virCommandAddArg(cmd, "-sdl");

        break;

    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        return qemuBuildGraphicsVNCCommandLine(cfg, cmd, def, qemuCaps, graphics);

    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        return qemuBuildGraphicsSPICECommandLine(cfg, cmd, qemuCaps, graphics);

    case VIR_DOMAIN_GRAPHICS_TYPE_RDP:
    case VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP:
    case VIR_DOMAIN_GRAPHICS_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported graphics type '%s'"),
                       virDomainGraphicsTypeToString(graphics->type));
        return -1;
    }

    return 0;
}

static int
qemuBuildVhostuserCommandLine(virCommandPtr cmd,
                              virDomainDefPtr def,
                              virDomainNetDefPtr net,
                              virQEMUCapsPtr qemuCaps,
                              int bootindex)
{
    virBuffer chardev_buf = VIR_BUFFER_INITIALIZER;
    virBuffer netdev_buf = VIR_BUFFER_INITIALIZER;
    unsigned int queues = net->driver.virtio.queues;
    char *nic = NULL;

    if (!qemuDomainSupportsNetdev(def, qemuCaps, net)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Netdev support unavailable"));
        goto error;
    }

    switch ((virDomainChrType) net->data.vhostuser->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&chardev_buf, "socket,id=char%s,path=%s%s",
                          net->info.alias, net->data.vhostuser->data.nix.path,
                          net->data.vhostuser->data.nix.listen ? ",server" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_UDP:
    case VIR_DOMAIN_CHR_TYPE_TCP:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("vhost-user type '%s' not supported"),
                        virDomainChrTypeToString(net->data.vhostuser->type));
        goto error;
    }

    virBufferAsprintf(&netdev_buf, "type=vhost-user,id=host%s,chardev=char%s",
                      net->info.alias, net->info.alias);

    if (queues > 1) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VHOSTUSER_MULTIQUEUE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("multi-queue is not supported for vhost-user "
                             "with this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&netdev_buf, ",queues=%u", queues);
    }

    virCommandAddArg(cmd, "-chardev");
    virCommandAddArgBuffer(cmd, &chardev_buf);

    virCommandAddArg(cmd, "-netdev");
    virCommandAddArgBuffer(cmd, &netdev_buf);

    if (!(nic = qemuBuildNicDevStr(def, net, -1, bootindex,
                                   queues, qemuCaps))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Error generating NIC -device string"));
        goto error;
    }

    virCommandAddArgList(cmd, "-device", nic, NULL);
    VIR_FREE(nic);

    return 0;

 error:
    virBufferFreeAndReset(&chardev_buf);
    virBufferFreeAndReset(&netdev_buf);
    VIR_FREE(nic);

    return -1;
}

static int
qemuBuildInterfaceCommandLine(virCommandPtr cmd,
                              virQEMUDriverPtr driver,
                              virDomainDefPtr def,
                              virDomainNetDefPtr net,
                              virQEMUCapsPtr qemuCaps,
                              int vlan,
                              int bootindex,
                              virNetDevVPortProfileOp vmop,
                              bool standalone,
                              size_t *nnicindexes,
                              int **nicindexes)
{
    int ret = -1;
    char *nic = NULL, *host = NULL;
    int *tapfd = NULL;
    size_t tapfdSize = 0;
    int *vhostfd = NULL;
    size_t vhostfdSize = 0;
    char **tapfdName = NULL;
    char **vhostfdName = NULL;
    int actualType = virDomainNetGetActualType(net);
    virQEMUDriverConfigPtr cfg = NULL;
    virNetDevBandwidthPtr actualBandwidth;
    size_t i;


    if (!bootindex)
        bootindex = net->info.bootIndex;

    if (actualType == VIR_DOMAIN_NET_TYPE_VHOSTUSER)
        return qemuBuildVhostuserCommandLine(cmd, def, net, qemuCaps, bootindex);

    if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        /* NET_TYPE_HOSTDEV devices are really hostdev devices, so
         * their commandlines are constructed with other hostdevs.
         */
        return 0;
    }

    /* Currently nothing besides TAP devices supports multiqueue. */
    if (net->driver.virtio.queues > 0 &&
        !(actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
          actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
          actualType == VIR_DOMAIN_NET_TYPE_DIRECT)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Multiqueue network is not supported for: %s"),
                       virDomainNetTypeToString(actualType));
        return -1;
    }

    /* and only TAP devices support nwfilter rules */
    if (net->filter &&
        !(actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
          actualType == VIR_DOMAIN_NET_TYPE_BRIDGE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("filterref is not supported for "
                         "network interfaces of type %s"),
                       virDomainNetTypeToString(actualType));
        return -1;
    }

    if (net->backend.tap &&
        !(actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
          actualType == VIR_DOMAIN_NET_TYPE_BRIDGE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Custom tap device path is not supported for: %s"),
                       virDomainNetTypeToString(actualType));
        return -1;
    }

    cfg = virQEMUDriverGetConfig(driver);

    if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
        actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        tapfdSize = net->driver.virtio.queues;
        if (!tapfdSize)
            tapfdSize = 1;

        if (VIR_ALLOC_N(tapfd, tapfdSize) < 0 ||
            VIR_ALLOC_N(tapfdName, tapfdSize) < 0)
            goto cleanup;

        memset(tapfd, -1, tapfdSize * sizeof(tapfd[0]));

        if (qemuNetworkIfaceConnect(def, driver, net,
                                    tapfd, &tapfdSize) < 0)
            goto cleanup;
    } else if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
        tapfdSize = net->driver.virtio.queues;
        if (!tapfdSize)
            tapfdSize = 1;

        if (VIR_ALLOC_N(tapfd, tapfdSize) < 0 ||
            VIR_ALLOC_N(tapfdName, tapfdSize) < 0)
            goto cleanup;

        memset(tapfd, -1, tapfdSize * sizeof(tapfd[0]));

        if (qemuPhysIfaceConnect(def, driver, net, tapfd, tapfdSize, vmop) < 0)
            goto cleanup;
    }

    /* For types whose implementations use a netdev on the host, add
     * an entry to nicindexes for passing on to systemd.
    */
    switch ((virDomainNetType)actualType) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    {
        int nicindex;

        /* network and bridge use a tap device, and direct uses a
         * macvtap device
         */
        if (virQEMUDriverIsPrivileged(driver) && nicindexes && nnicindexes &&
            net->ifname) {
            if (virNetDevGetIndex(net->ifname, &nicindex) < 0 ||
                VIR_APPEND_ELEMENT(*nicindexes, *nnicindexes, nicindex) < 0)
                goto cleanup;
        }
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_LAST:
       /* These types don't use a network device on the host, but
        * instead use some other type of connection to the emulated
        * device in the qemu process.
        *
        * (Note that hostdev can't be considered as "using a network
        * device", because by the time it is being used, it has been
        * detached from the hostside network driver so it doesn't show
        * up in the list of interfaces on the host - it's just some
        * PCI device.)
        */
       break;
    }

    /* Set bandwidth or warn if requested and not supported. */
    actualBandwidth = virDomainNetGetActualBandwidth(net);
    if (actualBandwidth) {
        if (virNetDevSupportBandwidth(actualType)) {
            if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false) < 0)
                goto cleanup;
        } else {
            VIR_WARN("setting bandwidth on interfaces of "
                     "type '%s' is not implemented yet",
                     virDomainNetTypeToString(actualType));
        }
    }

    if ((actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
         actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
         actualType == VIR_DOMAIN_NET_TYPE_ETHERNET ||
         actualType == VIR_DOMAIN_NET_TYPE_DIRECT) &&
        !standalone) {
        /* Attempt to use vhost-net mode for these types of
           network device */
        vhostfdSize = net->driver.virtio.queues;
        if (!vhostfdSize)
            vhostfdSize = 1;

        if (VIR_ALLOC_N(vhostfd, vhostfdSize) < 0 ||
            VIR_ALLOC_N(vhostfdName, vhostfdSize))
            goto cleanup;

        memset(vhostfd, -1, vhostfdSize * sizeof(vhostfd[0]));

        if (qemuOpenVhostNet(def, net, qemuCaps, vhostfd, &vhostfdSize) < 0)
            goto cleanup;
    }

    for (i = 0; i < tapfdSize; i++) {
        if (virSecurityManagerSetTapFDLabel(driver->securityManager,
                                            def, tapfd[i]) < 0)
            goto cleanup;
        virCommandPassFD(cmd, tapfd[i],
                         VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        if (virAsprintf(&tapfdName[i], "%d", tapfd[i]) < 0)
            goto cleanup;
    }

    for (i = 0; i < vhostfdSize; i++) {
        virCommandPassFD(cmd, vhostfd[i],
                         VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        if (virAsprintf(&vhostfdName[i], "%d", vhostfd[i]) < 0)
            goto cleanup;
    }

    /* Possible combinations:
     *
     *  1. Old way:   -net nic,model=e1000,vlan=1 -net tap,vlan=1
     *  2. Semi-new:  -device e1000,vlan=1        -net tap,vlan=1
     *  3. Best way:  -netdev type=tap,id=netdev1 -device e1000,id=netdev1
     *
     * NB, no support for -netdev without use of -device
     */
    if (qemuDomainSupportsNetdev(def, qemuCaps, net)) {
        if (!(host = qemuBuildHostNetStr(net, driver,
                                         ',', vlan,
                                         tapfdName, tapfdSize,
                                         vhostfdName, vhostfdSize)))
            goto cleanup;
        virCommandAddArgList(cmd, "-netdev", host, NULL);
    }
    if (qemuDomainSupportsNicdev(def, qemuCaps, net)) {
        if (!(nic = qemuBuildNicDevStr(def, net, vlan, bootindex,
                                       vhostfdSize, qemuCaps)))
            goto cleanup;
        virCommandAddArgList(cmd, "-device", nic, NULL);
    } else {
        if (!(nic = qemuBuildNicStr(net, "nic,", vlan)))
            goto cleanup;
        virCommandAddArgList(cmd, "-net", nic, NULL);
    }
    if (!qemuDomainSupportsNetdev(def, qemuCaps, net)) {
        if (!(host = qemuBuildHostNetStr(net, driver,
                                         ',', vlan,
                                         tapfdName, tapfdSize,
                                         vhostfdName, vhostfdSize)))
            goto cleanup;
        virCommandAddArgList(cmd, "-net", host, NULL);
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        virErrorPtr saved_err = virSaveLastError();
        virDomainConfNWFilterTeardown(net);
        virSetError(saved_err);
        virFreeError(saved_err);
    }
    for (i = 0; tapfd && i < tapfdSize && tapfd[i] >= 0; i++) {
        if (ret < 0)
            VIR_FORCE_CLOSE(tapfd[i]);
        if (tapfdName)
            VIR_FREE(tapfdName[i]);
    }
    for (i = 0; vhostfd && i < vhostfdSize && vhostfd[i] >= 0; i++) {
        if (ret < 0)
            VIR_FORCE_CLOSE(vhostfd[i]);
        if (vhostfdName)
            VIR_FREE(vhostfdName[i]);
    }
    VIR_FREE(tapfd);
    VIR_FREE(vhostfd);
    VIR_FREE(nic);
    VIR_FREE(host);
    VIR_FREE(tapfdName);
    VIR_FREE(vhostfdName);
    virObjectUnref(cfg);
    return ret;
}

char *
qemuBuildShmemDevStr(virDomainDefPtr def,
                     virDomainShmemDefPtr shmem,
                     virQEMUCapsPtr qemuCaps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ivshmem device is not supported "
                         "with this QEMU binary"));
        goto error;
    }

    virBufferAddLit(&buf, "ivshmem");
    if (shmem->size) {
        /*
         * Thanks to our parsing code, we have a guarantee that the
         * size is power of two and is at least a mebibyte in size.
         * But because it may change in the future, the checks are
         * doubled in here.
         */
        if (shmem->size & (shmem->size - 1)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("shmem size must be a power of two"));
            goto error;
        }
        if (shmem->size < 1024 * 1024) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("shmem size must be at least 1 MiB (1024 KiB)"));
            goto error;
        }
        virBufferAsprintf(&buf, ",size=%llum", shmem->size >> 20);
    }

    if (!shmem->server.enabled) {
        virBufferAsprintf(&buf, ",shm=%s,id=%s", shmem->name, shmem->info.alias);
    } else {
        virBufferAsprintf(&buf, ",chardev=char%s,id=%s", shmem->info.alias, shmem->info.alias);
        if (shmem->msi.enabled) {
            virBufferAddLit(&buf, ",msi=on");
            if (shmem->msi.vectors)
                virBufferAsprintf(&buf, ",vectors=%u", shmem->msi.vectors);
            if (shmem->msi.ioeventfd)
                virBufferAsprintf(&buf, ",ioeventfd=%s",
                                  virTristateSwitchTypeToString(shmem->msi.ioeventfd));
        }
    }

    if (shmem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 'pci' addresses are supported for the "
                         "shared memory device"));
        goto error;
    }

    if (qemuBuildDeviceAddressStr(&buf, def, &shmem->info, qemuCaps) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

char *
qemuBuildShmemBackendStr(virDomainShmemDefPtr shmem,
                         virQEMUCapsPtr qemuCaps)
{
    char *devstr = NULL;

    if (!shmem->server.chr.data.nix.path &&
        virAsprintf(&shmem->server.chr.data.nix.path,
                    "/var/lib/libvirt/shmem-%s-sock",
                    shmem->name) < 0)
        return NULL;

    devstr = qemuBuildChrChardevStr(&shmem->server.chr, shmem->info.alias, qemuCaps);

    return devstr;
}

static int
qemuBuildShmemCommandLine(virCommandPtr cmd,
                          virDomainDefPtr def,
                          virDomainShmemDefPtr shmem,
                          virQEMUCapsPtr qemuCaps)
{
    char *devstr = NULL;

    if (!(devstr = qemuBuildShmemDevStr(def, shmem, qemuCaps)))
        return -1;
    virCommandAddArgList(cmd, "-device", devstr, NULL);
    VIR_FREE(devstr);

    if (shmem->server.enabled) {
        if (!(devstr = qemuBuildShmemBackendStr(shmem, qemuCaps)))
            return -1;

        virCommandAddArgList(cmd, "-chardev", devstr, NULL);
        VIR_FREE(devstr);
    }

    return 0;
}

static int
qemuBuildChrDeviceCommandLine(virCommandPtr cmd,
                              virDomainDefPtr def,
                              virDomainChrDefPtr chr,
                              virQEMUCapsPtr qemuCaps)
{
    char *devstr = NULL;

    if (qemuBuildChrDeviceStr(&devstr, def, chr, qemuCaps) < 0)
        return -1;

    virCommandAddArgList(cmd, "-device", devstr, NULL);
    VIR_FREE(devstr);
    return 0;
}

static int
qemuBuildDomainLoaderCommandLine(virCommandPtr cmd,
                                 virDomainDefPtr def,
                                 virQEMUCapsPtr qemuCaps)
{
    int ret = -1;
    virDomainLoaderDefPtr loader = def->os.loader;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int unit = 0;

    if (!loader)
        return 0;

    switch ((virDomainLoader) loader->type) {
    case VIR_DOMAIN_LOADER_TYPE_ROM:
        virCommandAddArg(cmd, "-bios");
        virCommandAddArg(cmd, loader->path);
        break;

    case VIR_DOMAIN_LOADER_TYPE_PFLASH:
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_ACPI) &&
            def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ACPI must be enabled in order to use UEFI"));
            goto cleanup;
        }

        virBufferAsprintf(&buf,
                          "file=%s,if=pflash,format=raw,unit=%d",
                          loader->path, unit);
        unit++;

        if (loader->readonly) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_READONLY)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this qemu doesn't support passing "
                                 "readonly attribute"));
                goto cleanup;
            }

            virBufferAsprintf(&buf, ",readonly=%s",
                              virTristateSwitchTypeToString(loader->readonly));
        }

        virCommandAddArg(cmd, "-drive");
        virCommandAddArgBuffer(cmd, &buf);

        if (loader->nvram) {
            virBufferFreeAndReset(&buf);
            virBufferAsprintf(&buf,
                              "file=%s,if=pflash,format=raw,unit=%d",
                              loader->nvram, unit);

            virCommandAddArg(cmd, "-drive");
            virCommandAddArgBuffer(cmd, &buf);
        }
        break;

    case VIR_DOMAIN_LOADER_TYPE_LAST:
        /* nada */
        break;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
}

static int
qemuBuildTPMCommandLine(virDomainDefPtr def,
                        virCommandPtr cmd,
                        virQEMUCapsPtr qemuCaps,
                        const char *emulator)
{
    char *optstr;
    int tpmfd = -1;
    int cancelfd = -1;
    char *fdset;

    if (!(optstr = qemuBuildTPMBackendStr(def, cmd, qemuCaps, emulator,
                                          &tpmfd, &cancelfd)))
        return -1;

    virCommandAddArgList(cmd, "-tpmdev", optstr, NULL);
    VIR_FREE(optstr);

    if (tpmfd >= 0) {
        fdset = qemuVirCommandGetFDSet(cmd, tpmfd);
        if (!fdset)
            return -1;

        virCommandAddArgList(cmd, "-add-fd", fdset, NULL);
        VIR_FREE(fdset);
    }

    if (cancelfd >= 0) {
        fdset = qemuVirCommandGetFDSet(cmd, cancelfd);
        if (!fdset)
            return -1;

        virCommandAddArgList(cmd, "-add-fd", fdset, NULL);
        VIR_FREE(fdset);
    }

    if (!(optstr = qemuBuildTPMDevStr(def, qemuCaps, emulator)))
        return -1;

    virCommandAddArgList(cmd, "-device", optstr, NULL);
    VIR_FREE(optstr);

    return 0;
}


qemuBuildCommandLineCallbacks buildCommandLineCallbacks = {
    .qemuGetSCSIDeviceSgName = virSCSIDeviceGetSgName,
};

/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 *
 * XXX 'conn' is only required to resolve network -> bridge name
 * figure out how to remove this requirement some day
 */
virCommandPtr
qemuBuildCommandLine(virConnectPtr conn,
                     virQEMUDriverPtr driver,
                     virDomainDefPtr def,
                     virDomainChrSourceDefPtr monitor_chr,
                     bool monitor_json,
                     virQEMUCapsPtr qemuCaps,
                     const char *migrateURI,
                     virDomainSnapshotObjPtr snapshot,
                     virNetDevVPortProfileOp vmop,
                     qemuBuildCommandLineCallbacksPtr callbacks,
                     bool standalone,
                     bool enableFips,
                     virBitmapPtr nodeset,
                     size_t *nnicindexes,
                     int **nicindexes)
{
    virErrorPtr originalError = NULL;
    size_t i, j;
    const char *emulator;
    char uuid[VIR_UUID_STRING_BUFLEN];
    char *cpu;
    char *smp;
    int last_good_net = -1;
    bool hasHwVirt = false;
    virCommandPtr cmd = NULL;
    bool allowReboot = true;
    bool emitBootindex = false;
    int sdl = 0;
    int vnc = 0;
    int spice = 0;
    int usbcontroller = 0;
    int actualSerials = 0;
    bool usblegacy = false;
    int contOrder[] = {
        /*
         * List of controller types that we add commandline args for,
         * *in the order we want to add them*.
         *
         * The floppy controller is implicit on PIIX4 and older Q35
         * machines. For newer Q35 machines it is added out of the
         * controllers loop, after the floppy drives.
         *
         * We don't add PCI/PCIe root controller either, because it's
         * implicit, but we do add PCI bridges and other PCI
         * controllers, so we leave that in to check each
         * one. Likewise, we don't do anything for the primary IDE
         * controller on an i440fx machine or primary SATA on q35, but
         * we do add those beyond these two exceptions.
         */
        VIR_DOMAIN_CONTROLLER_TYPE_PCI,
        VIR_DOMAIN_CONTROLLER_TYPE_USB,
        VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
        VIR_DOMAIN_CONTROLLER_TYPE_IDE,
        VIR_DOMAIN_CONTROLLER_TYPE_SATA,
        VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
        VIR_DOMAIN_CONTROLLER_TYPE_CCID,
    };
    virArch hostarch = virArchFromHost();
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virBuffer boot_buf = VIR_BUFFER_INITIALIZER;
    char *boot_order_str = NULL, *boot_opts_str = NULL;
    virBuffer fdc_opts = VIR_BUFFER_INITIALIZER;
    char *fdc_opts_str = NULL;
    int bootCD = 0, bootFloppy = 0, bootDisk = 0, bootHostdevNet = 0;


    VIR_DEBUG("conn=%p driver=%p def=%p mon=%p json=%d "
              "qemuCaps=%p migrateURI=%s snapshot=%p vmop=%d",
              conn, driver, def, monitor_chr, monitor_json,
              qemuCaps, migrateURI, snapshot, vmop);

    virUUIDFormat(def->uuid, uuid);

    emulator = def->emulator;

    if (!virQEMUDriverIsPrivileged(driver)) {
        /* If we have no cgroups then we can have no tunings that
         * require them */

        if (virMemoryLimitIsSet(def->mem.hard_limit) ||
            virMemoryLimitIsSet(def->mem.soft_limit) ||
            def->mem.min_guarantee ||
            virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory tuning is not available in session mode"));
            goto error;
        }

        if (def->blkio.weight) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available in session mode"));
            goto error;
        }

        if (def->cputune.sharesSpecified || def->cputune.period ||
            def->cputune.quota || def->cputune.emulator_period ||
            def->cputune.emulator_quota) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU tuning is not available in session mode"));
            goto error;
        }
    }

    for (i = 0; i < def->ngraphics; ++i) {
        switch (def->graphics[i]->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            ++sdl;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            ++vnc;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            ++spice;
            break;
        }
    }

    /*
     * do not use boot=on for drives when not using KVM since this
     * is not supported at all in upstream QEmu.
     */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
        (def->virtType == VIR_DOMAIN_VIRT_QEMU))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DRIVE_BOOT);

    cmd = virCommandNew(emulator);

    virCommandAddEnvPassCommon(cmd);

    virCommandAddArg(cmd, "-name");
    if (cfg->setProcessName &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_NAME_PROCESS)) {
        virCommandAddArgFormat(cmd, "%s,process=qemu:%s",
                               def->name, def->name);
    } else {
        virCommandAddArg(cmd, def->name);
    }

    if (!standalone)
        virCommandAddArg(cmd, "-S"); /* freeze CPU */

    if (enableFips)
        virCommandAddArg(cmd, "-enable-fips");

    if (qemuBuildMachineArgStr(cmd, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildCpuArgStr(driver, def, emulator, qemuCaps,
                           hostarch, &cpu, &hasHwVirt, !!migrateURI) < 0)
        goto error;

    if (cpu) {
        virCommandAddArgList(cmd, "-cpu", cpu, NULL);
        VIR_FREE(cpu);

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NESTING) &&
            hasHwVirt)
            virCommandAddArg(cmd, "-enable-nesting");
    }

    if (qemuBuildDomainLoaderCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (!migrateURI && !snapshot &&
        qemuDomainAlignMemorySizes(def) < 0)
        goto error;

    if (qemuDomainDefValidateMemoryHotplug(def, qemuCaps, NULL) < 0)
        goto error;

    virCommandAddArg(cmd, "-m");

    if (virDomainDefHasMemoryHotplug(def)) {
        /* Use the 'k' suffix to let qemu handle the units */
        virCommandAddArgFormat(cmd, "size=%lluk,slots=%u,maxmem=%lluk",
                               virDomainDefGetMemoryInitial(def),
                               def->mem.memory_slots,
                               def->mem.max_memory);

    } else {
       virCommandAddArgFormat(cmd, "%llu", virDomainDefGetMemoryInitial(def) / 1024);
    }

    /*
     * Add '-mem-path' (and '-mem-prealloc') parameter here only if
     * there is no numa node specified.
     */
    if (!virDomainNumaGetNodeCount(def->numa) &&
        qemuBuildMemPathStr(cfg, def, qemuCaps, cmd) < 0)
        goto error;

    if (def->mem.locked && !virQEMUCapsGet(qemuCaps, QEMU_CAPS_MLOCK)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory locking not supported by QEMU binary"));
        goto error;
    }
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MLOCK)) {
        virCommandAddArg(cmd, "-realtime");
        virCommandAddArgFormat(cmd, "mlock=%s",
                               def->mem.locked ? "on" : "off");
    }

    virCommandAddArg(cmd, "-smp");
    if (!(smp = qemuBuildSmpArgStr(def, qemuCaps)))
        goto error;
    virCommandAddArg(cmd, smp);
    VIR_FREE(smp);

    if (def->niothreadids) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("IOThreads not supported for this QEMU"));
            goto error;
        }

        /* Create iothread objects using the defined iothreadids list
         * and the defined id and name from the list. These may be used
         * by a disk definition which will associate to an iothread by
         * supplying a value of an id from the list
         */
        for (i = 0; i < def->niothreadids; i++) {
            virCommandAddArg(cmd, "-object");
            virCommandAddArgFormat(cmd, "iothread,id=iothread%u",
                                   def->iothreadids[i]->iothread_id);
        }
    }

    if (virDomainNumaGetNodeCount(def->numa) &&
        qemuBuildNumaArgStr(cfg, def, cmd, qemuCaps, nodeset) < 0)
            goto error;

    /* memory hotplug requires NUMA to be enabled - we already checked
     * that memory devices are present only when NUMA is */


    for (i = 0; i < def->nmems; i++) {
        char *backStr;
        char *dimmStr;

        if (!(backStr = qemuBuildMemoryDimmBackendStr(def->mems[i], def,
                                                      qemuCaps, cfg)))
            goto error;

        if (!(dimmStr = qemuBuildMemoryDeviceStr(def->mems[i]))) {
            VIR_FREE(backStr);
            goto error;
        }

        virCommandAddArgList(cmd, "-object", backStr, "-device", dimmStr, NULL);

        VIR_FREE(backStr);
        VIR_FREE(dimmStr);
    }

    virCommandAddArgList(cmd, "-uuid", uuid, NULL);
    if (def->virtType == VIR_DOMAIN_VIRT_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_LINUX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu emulator '%s' does not support xen"),
                       def->emulator);
        goto error;
    }

    if ((def->os.smbios_mode != VIR_DOMAIN_SMBIOS_NONE) &&
        (def->os.smbios_mode != VIR_DOMAIN_SMBIOS_EMULATE)) {
        virSysinfoDefPtr source = NULL;
        bool skip_uuid = false;

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMBIOS_TYPE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("the QEMU binary %s does not support smbios settings"),
                           emulator);
            goto error;
        }

        /* should we really error out or just warn in those cases ? */
        if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
            if (driver->hostsysinfo == NULL) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Host SMBIOS information is not available"));
                goto error;
            }
            source = driver->hostsysinfo;
            /* Host and guest uuid must differ, by definition of UUID. */
            skip_uuid = true;
        } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_SYSINFO) {
            if (def->sysinfo == NULL) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Domain '%s' sysinfo are not available"),
                               def->name);
                goto error;
            }
            source = def->sysinfo;
            /* domain_conf guaranteed that system_uuid matches guest uuid. */
        }
        if (source != NULL) {
            char *smbioscmd;

            smbioscmd = qemuBuildSmbiosBiosStr(source->bios);
            if (smbioscmd != NULL) {
                virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
                VIR_FREE(smbioscmd);
            }
            smbioscmd = qemuBuildSmbiosSystemStr(source->system, skip_uuid);
            if (smbioscmd != NULL) {
                virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
                VIR_FREE(smbioscmd);
            }

            if (source->nbaseBoard > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("qemu does not support more than "
                                 "one entry to Type 2 in SMBIOS table"));
                goto error;
            }

            for (i = 0; i < source->nbaseBoard; i++) {
                if (!(smbioscmd = qemuBuildSmbiosBaseBoardStr(source->baseBoard + i)))
                    goto error;

                virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
                VIR_FREE(smbioscmd);
            }
        }
    }

    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (!def->graphics) {
        virCommandAddArg(cmd, "-nographic");

        if (cfg->nogfxAllowHostAudio)
            virCommandAddEnvPassBlockSUID(cmd, "QEMU_AUDIO_DRV", NULL);
        else
            virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=none");
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        /* Disable global config files and default devices */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_USER_CONFIG))
            virCommandAddArg(cmd, "-no-user-config");
        else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NODEFCONFIG))
            virCommandAddArg(cmd, "-nodefconfig");
        virCommandAddArg(cmd, "-nodefaults");
    }

    /* Serial graphics adapter */
    if (def->os.bios.useserial == VIR_TRISTATE_BOOL_YES) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support -device"));
            goto error;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SGA)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support SGA"));
            goto error;
        }
        if (!def->nserials) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("need at least one serial port to use SGA"));
            goto error;
        }
        virCommandAddArgList(cmd, "-device", "sga", NULL);
    }

    if (monitor_chr) {
        char *chrdev;
        /* Use -chardev if it's available */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV)) {

            virCommandAddArg(cmd, "-chardev");
            if (!(chrdev = qemuBuildChrChardevStr(monitor_chr, "monitor",
                                                  qemuCaps)))
                goto error;
            virCommandAddArg(cmd, chrdev);
            VIR_FREE(chrdev);

            virCommandAddArg(cmd, "-mon");
            virCommandAddArgFormat(cmd,
                                   "chardev=charmonitor,id=monitor,mode=%s",
                                   monitor_json ? "control" : "readline");
        } else {
            const char *prefix = NULL;
            if (monitor_json)
                prefix = "control,";

            virCommandAddArg(cmd, "-monitor");
            if (!(chrdev = qemuBuildChrArgStr(monitor_chr, prefix)))
                goto error;
            virCommandAddArg(cmd, chrdev);
            VIR_FREE(chrdev);
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_RTC)) {
        char *rtcopt;
        virCommandAddArg(cmd, "-rtc");
        if (!(rtcopt = qemuBuildClockArgStr(&def->clock)))
            goto error;
        virCommandAddArg(cmd, rtcopt);
        VIR_FREE(rtcopt);
    } else {
        switch (def->clock.offset) {
        case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
        case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
            virCommandAddArg(cmd, "-localtime");
            break;

        case VIR_DOMAIN_CLOCK_OFFSET_UTC:
            /* Nothing, its the default */
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported clock offset '%s'"),
                           virDomainClockOffsetTypeToString(def->clock.offset));
            goto error;
        }
    }
    if (def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE &&
        def->clock.data.timezone) {
        virCommandAddEnvPair(cmd, "TZ", def->clock.data.timezone);
    }

    for (i = 0; i < def->clock.ntimers; i++) {
        switch ((virDomainTimerNameType) def->clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_TSC:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%s'"),
                           virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            goto error;

        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
            /* Timers above are handled when building -cpu.  */
        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;

        case VIR_DOMAIN_TIMER_NAME_RTC:
            /* This has already been taken care of (in qemuBuildClockArgStr)
               if QEMU_CAPS_RTC is set (mutually exclusive with
               QEMUD_FLAG_RTC_TD_HACK) */
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_RTC_TD_HACK)) {
                switch (def->clock.timers[i]->tickpolicy) {
                case -1:
                case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                    /* the default - do nothing */
                    break;
                case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                    virCommandAddArg(cmd, "-rtc-td-hack");
                    break;
                case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
                case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported rtc tickpolicy '%s'"),
                                   virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                    goto error;
                }
            } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_RTC) &&
                       (def->clock.timers[i]->tickpolicy
                        != VIR_DOMAIN_TIMER_TICKPOLICY_DELAY) &&
                       (def->clock.timers[i]->tickpolicy != -1)) {
                /* a non-default rtc policy was given, but there is no
                   way to implement it in this version of qemu */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported rtc tickpolicy '%s'"),
                               virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PIT:
            switch (def->clock.timers[i]->tickpolicy) {
            case -1:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* delay is the default if we don't have kernel
                   (-no-kvm-pit), otherwise, the default is catchup. */
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM_PIT_TICK_POLICY))
                    virCommandAddArgList(cmd, "-global",
                                         "kvm-pit.lost_tick_policy=discard", NULL);
                else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_KVM_PIT))
                    virCommandAddArg(cmd, "-no-kvm-pit-reinjection");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_KVM_PIT) ||
                    virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM_PIT_TICK_POLICY)) {
                    /* do nothing - this is default for kvm-pit */
                } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_TDF)) {
                    /* -tdf switches to 'catchup' with userspace pit. */
                    virCommandAddArg(cmd, "-tdf");
                } else {
                    /* can't catchup if we have neither pit mode */
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported pit tickpolicy '%s'"),
                                   virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                    goto error;
                }
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                /* no way to support these modes for pit in qemu */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported pit tickpolicy '%s'"),
                               virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            /* the only meaningful attribute for hpet is "present". If
             * present is -1, that means it wasn't specified, and
             * should be left at the default for the
             * hypervisor. "default" when -no-hpet exists is "yes",
             * and when -no-hpet doesn't exist is "no". "confusing"?
             * "yes"! */

            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_HPET)) {
                if (def->clock.timers[i]->present == 0)
                    virCommandAddArg(cmd, "-no-hpet");
            } else {
                /* no hpet timer available. The only possible action
                   is to raise an error if present="yes" */
                if (def->clock.timers[i]->present == 1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   "%s", _("hpet timer is not supported"));
                    goto error;
                }
            }
            break;
        }
    }

    /* Only add -no-reboot option if each event destroys domain */
    if (def->onReboot == VIR_DOMAIN_LIFECYCLE_DESTROY &&
        def->onPoweroff == VIR_DOMAIN_LIFECYCLE_DESTROY &&
        (def->onCrash == VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY ||
         def->onCrash == VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY)) {
        allowReboot = false;
        virCommandAddArg(cmd, "-no-reboot");
    }

    /* If JSON monitor is enabled, we can receive an event
     * when QEMU stops. If we use no-shutdown, then we can
     * watch for this event and do a soft/warm reboot.
     */
    if (monitor_json && allowReboot &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_SHUTDOWN)) {
        virCommandAddArg(cmd, "-no-shutdown");
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NO_ACPI)) {
        if (def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON)
            virCommandAddArg(cmd, "-no-acpi");
    }

    /* We fall back to PIIX4_PM even for q35, since it's what we did
       pre-q35-pm support. QEMU starts up fine (with a warning) if
       mixing PIIX PM and -M q35. Starting to reject things here
       could mean we refuse to start existing configs in the wild.*/
    if (def->pm.s3) {
        const char *pm_object = "PIIX4_PM";

        if (qemuDomainMachineIsQ35(def) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_DISABLE_S3)) {
            pm_object = "ICH9-LPC";
        } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX_DISABLE_S3)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("setting ACPI S3 not supported"));
            goto error;
        }

        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "%s.disable_s3=%d",
                               pm_object, def->pm.s3 == VIR_TRISTATE_BOOL_NO);
    }

    if (def->pm.s4) {
        const char *pm_object = "PIIX4_PM";

        if (qemuDomainMachineIsQ35(def) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_ICH9_DISABLE_S4)) {
            pm_object = "ICH9-LPC";
        } else if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX_DISABLE_S4)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("setting ACPI S4 not supported"));
            goto error;
        }

        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "%s.disable_s4=%d",
                               pm_object, def->pm.s4 == VIR_TRISTATE_BOOL_NO);
    }

    /*
     * We prefer using explicit bootindex=N parameters for predictable
     * results even though domain XML doesn't use per device boot elements.
     * However, we can't use bootindex if boot menu was requested.
     */
    if (!def->os.nBootDevs) {
        /* def->os.nBootDevs is guaranteed to be > 0 unless per-device boot
         * configuration is used
         */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOTINDEX)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("hypervisor lacks deviceboot feature"));
            goto error;
        }
        emitBootindex = true;
    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOTINDEX) &&
               (def->os.bootmenu != VIR_TRISTATE_BOOL_YES ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOT_MENU))) {
        emitBootindex = true;
    }

    if (!emitBootindex) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];

        for (i = 0; i < def->os.nBootDevs; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_DISK:
                boot[i] = 'c';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            default:
                boot[i] = 'c';
                break;
            }
        }
        boot[def->os.nBootDevs] = '\0';

        virBufferAsprintf(&boot_buf, "%s", boot);
        if (virBufferCheckError(&boot_buf) < 0)
            goto error;
        boot_order_str = virBufferContentAndReset(&boot_buf);
    }

    if (def->os.bootmenu) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOT_MENU)) {
            if (def->os.bootmenu == VIR_TRISTATE_BOOL_YES)
                virBufferAddLit(&boot_buf, "menu=on,");
            else
                virBufferAddLit(&boot_buf, "menu=off,");
        } else {
            /* We cannot emit an error when bootmenu is enabled but
             * unsupported because of backward compatibility */
            VIR_WARN("bootmenu is enabled but not "
                     "supported by this QEMU binary");
        }
    }

    if (def->os.bios.rt_set) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_REBOOT_TIMEOUT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("reboot timeout is not supported "
                             "by this QEMU binary"));
            goto error;
        }

        virBufferAsprintf(&boot_buf,
                          "reboot-timeout=%d,",
                          def->os.bios.rt_delay);
    }

    if (def->os.bm_timeout_set) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SPLASH_TIMEOUT)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("splash timeout is not supported "
                             "by this QEMU binary"));
            goto error;
        }

        virBufferAsprintf(&boot_buf, "splash-time=%u,", def->os.bm_timeout);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BOOT_STRICT))
        virBufferAddLit(&boot_buf, "strict=on,");

    virBufferTrim(&boot_buf, ",", -1);

    if (virBufferCheckError(&boot_buf) < 0)
        goto error;

    boot_opts_str = virBufferContentAndReset(&boot_buf);
    if (boot_order_str || boot_opts_str) {
        virCommandAddArg(cmd, "-boot");

        if (boot_order_str && boot_opts_str) {
            virCommandAddArgFormat(cmd, "order=%s,%s",
                                   boot_order_str, boot_opts_str);
        } else if (boot_order_str) {
            virCommandAddArg(cmd, boot_order_str);
        } else if (boot_opts_str) {
            virCommandAddArg(cmd, boot_opts_str);
        }
    }
    VIR_FREE(boot_opts_str);
    VIR_FREE(boot_order_str);

    if (def->os.kernel)
        virCommandAddArgList(cmd, "-kernel", def->os.kernel, NULL);
    if (def->os.initrd)
        virCommandAddArgList(cmd, "-initrd", def->os.initrd, NULL);
    if (def->os.cmdline)
        virCommandAddArgList(cmd, "-append", def->os.cmdline, NULL);
    if (def->os.dtb) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DTB)) {
            virCommandAddArgList(cmd, "-dtb", def->os.dtb, NULL);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("dtb is not supported with this QEMU binary"));
            goto error;
        }
    }

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            cont->opts.pciopts.pcihole64) {
            const char *hoststr = NULL;
            bool cap = false;
            bool machine = false;

            switch (cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
                hoststr = "i440FX-pcihost";
                cap = virQEMUCapsGet(qemuCaps, QEMU_CAPS_I440FX_PCI_HOLE64_SIZE);
                machine = qemuDomainMachineIsI440FX(def);
                break;

            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                hoststr = "q35-pcihost";
                cap = virQEMUCapsGet(qemuCaps, QEMU_CAPS_Q35_PCI_HOLE64_SIZE);
                machine = qemuDomainMachineIsQ35(def);
                break;

            default:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("64-bit PCI hole setting is only for root"
                                 " PCI controllers"));
                goto error;
            }

            if (!machine) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                             _("Setting the 64-bit PCI hole size is not "
                             "supported for machine '%s'"), def->os.machine);
                goto error;
            }
            if (!cap) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("64-bit PCI hole size setting is not supported "
                                 "with this QEMU binary"));
                goto error;
            }

            virCommandAddArg(cmd, "-global");
            virCommandAddArgFormat(cmd, "%s.pci-hole64-size=%luK", hoststr,
                                   cont->opts.pciopts.pcihole64size);
        }
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (disk->src->driverName != NULL &&
            STRNEQ(disk->src->driverName, "qemu")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported driver name '%s' for disk '%s'"),
                           disk->src->driverName, disk->src->path);
            goto error;
        }
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        for (j = 0; j < ARRAY_CARDINALITY(contOrder); j++) {
            for (i = 0; i < def->ncontrollers; i++) {
                virDomainControllerDefPtr cont = def->controllers[i];
                char *devstr;

                if (cont->type != contOrder[j])
                    continue;

                /* skip USB controllers with type none.*/
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                    cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
                    usbcontroller = -1; /* mark we don't want a controller */
                    continue;
                }

                /* skip pci-root/pcie-root */
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
                    (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
                     cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT))
                    continue;

                /* first SATA controller on Q35 machines is implicit */
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA &&
                    cont->idx == 0 && qemuDomainMachineIsQ35(def))
                        continue;

                /* first IDE controller is implicit on various machines */
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
                    cont->idx == 0 && qemuDomainMachineHasBuiltinIDE(def))
                        continue;

                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                    cont->model == -1 &&
                    !qemuDomainMachineIsQ35(def)) {
                    bool need_legacy = false;

                    /* We're not using legacy usb controller for q35 */
                    if (ARCH_IS_PPC64(def->os.arch)) {
                        /* For ppc64 the legacy was OHCI */
                        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_OHCI))
                            need_legacy = true;
                    } else {
                        /* For anything else, we used PIIX3_USB_UHCI */
                        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PIIX3_USB_UHCI))
                            need_legacy = true;
                    }

                    if (need_legacy) {
                        if (usblegacy) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                           _("Multiple legacy USB controllers are "
                                             "not supported"));
                            goto error;
                        }
                        usblegacy = true;
                        continue;
                    }
                }

                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildControllerDevStr(def, cont, qemuCaps,
                                                         &usbcontroller)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    if (usbcontroller == 0 &&
        !qemuDomainMachineIsQ35(def) &&
        !ARCH_IS_S390(def->os.arch))
        virCommandAddArg(cmd, "-usb");

    for (i = 0; i < def->nhubs; i++) {
        virDomainHubDefPtr hub = def->hubs[i];
        char *optstr;

        virCommandAddArg(cmd, "-device");
        if (!(optstr = qemuBuildHubDevStr(def, hub, qemuCaps)))
            goto error;
        virCommandAddArg(cmd, optstr);
        VIR_FREE(optstr);
    }

    if ((virQEMUCapsGet(qemuCaps, QEMU_CAPS_DRIVE_BOOT) || emitBootindex)) {
        /* bootDevs will get translated into either bootindex=N or boot=on
         * depending on what qemu supports */
        for (i = 0; i < def->os.nBootDevs; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_CDROM:
                bootCD = i + 1;
                break;
            case VIR_DOMAIN_BOOT_FLOPPY:
                bootFloppy = i + 1;
                break;
            case VIR_DOMAIN_BOOT_DISK:
                bootDisk = i + 1;
                break;
            }
        }
    }

    for (i = 0; i < def->ndisks; i++) {
        char *optstr;
        int bootindex = 0;
        virDomainDiskDefPtr disk = def->disks[i];
        bool withDeviceArg = false;
        bool deviceFlagMasked = false;

        /* Unless we have -device, then USB disks need special
           handling */
        if ((disk->bus == VIR_DOMAIN_DISK_BUS_USB) &&
            !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                virCommandAddArg(cmd, "-usbdevice");
                virCommandAddArgFormat(cmd, "disk:%s", disk->src->path);
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported usb disk type for '%s'"),
                               disk->src->path);
                goto error;
            }
            continue;
        }

        /* PowerPC pseries based VMs do not support floppy device */
        if ((disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) &&
            ARCH_IS_PPC64(def->os.arch) && STRPREFIX(def->os.machine, "pseries")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("PowerPC pseries machines do not support floppy device"));
            goto error;
        }

        switch (disk->device) {
        case VIR_DOMAIN_DISK_DEVICE_CDROM:
            bootindex = bootCD;
            bootCD = 0;
            break;
        case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
            bootindex = bootFloppy;
            bootFloppy = 0;
            break;
        case VIR_DOMAIN_DISK_DEVICE_DISK:
        case VIR_DOMAIN_DISK_DEVICE_LUN:
            bootindex = bootDisk;
            bootDisk = 0;
            break;
        }

        virCommandAddArg(cmd, "-drive");

        /* Unfortunately it is not possible to use
           -device for floppies, xen PV, or SD
           devices. Fortunately, those don't need
           static PCI addresses, so we don't really
           care that we can't use -device */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            if (disk->bus != VIR_DOMAIN_DISK_BUS_XEN &&
                disk->bus != VIR_DOMAIN_DISK_BUS_SD) {
                withDeviceArg = true;
            } else {
                virQEMUCapsClear(qemuCaps, QEMU_CAPS_DEVICE);
                deviceFlagMasked = true;
            }
        }
        optstr = qemuBuildDriveStr(conn, disk,
                                   emitBootindex ? false : !!bootindex,
                                   qemuCaps);
        if (deviceFlagMasked)
            virQEMUCapsSet(qemuCaps, QEMU_CAPS_DEVICE);
        if (!optstr)
            goto error;
        virCommandAddArg(cmd, optstr);
        VIR_FREE(optstr);

        if (!emitBootindex)
            bootindex = 0;
        else if (disk->info.bootIndex)
            bootindex = disk->info.bootIndex;

        if (withDeviceArg) {
            if (disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
                if (virAsprintf(&optstr, "drive%c=drive-%s",
                                disk->info.addr.drive.unit ? 'B' : 'A',
                                disk->info.alias) < 0)
                    goto error;

                if (!qemuDomainMachineNeedsFDC(def)) {
                    virCommandAddArg(cmd, "-global");
                    virCommandAddArgFormat(cmd, "isa-fdc.%s", optstr);
                } else {
                    virBufferAsprintf(&fdc_opts, "%s,", optstr);
                }
                VIR_FREE(optstr);

                if (bootindex) {
                    if (virAsprintf(&optstr, "bootindex%c=%d",
                                    disk->info.addr.drive.unit
                                    ? 'B' : 'A',
                                    bootindex) < 0)
                        goto error;

                    if (!qemuDomainMachineNeedsFDC(def)) {
                        virCommandAddArg(cmd, "-global");
                        virCommandAddArgFormat(cmd, "isa-fdc.%s", optstr);
                    } else {
                        virBufferAsprintf(&fdc_opts, "%s,", optstr);
                    }
                    VIR_FREE(optstr);
                }
            } else {
                virCommandAddArg(cmd, "-device");

                if (!(optstr = qemuBuildDriveDevStr(def, disk, bootindex,
                                                    qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, optstr);
                VIR_FREE(optstr);
            }
        }
    }
    /* Newer Q35 machine types require an explicit FDC controller */
    virBufferTrim(&fdc_opts, ",", -1);
    if ((fdc_opts_str = virBufferContentAndReset(&fdc_opts))) {
        virCommandAddArg(cmd, "-device");
        virCommandAddArgFormat(cmd, "isa-fdc,%s", fdc_opts_str);
        VIR_FREE(fdc_opts_str);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_FSDEV)) {
        for (i = 0; i < def->nfss; i++) {
            char *optstr;
            virDomainFSDefPtr fs = def->fss[i];

            virCommandAddArg(cmd, "-fsdev");
            if (!(optstr = qemuBuildFSStr(fs, qemuCaps)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);

            virCommandAddArg(cmd, "-device");
            if (!(optstr = qemuBuildFSDevStr(def, fs, qemuCaps)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        }
    } else {
        if (def->nfss) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("filesystem passthrough not supported by this QEMU"));
            goto error;
        }
    }

    if (!def->nnets) {
        /* If we have -device, then we set -nodefault already */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-net", "none", NULL);
    } else {
        int bootNet = 0;

        if (emitBootindex) {
            /* convert <boot dev='network'/> to bootindex since we didn't emit
             * -boot n
             */
            for (i = 0; i < def->os.nBootDevs; i++) {
                if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_NET) {
                    bootNet = i + 1;
                    break;
                }
            }
        }

        for (i = 0; i < def->nnets; i++) {
            virDomainNetDefPtr net = def->nets[i];
            int vlan;

            /* VLANs are not used with -netdev, so don't record them */
            if (qemuDomainSupportsNetdev(def, qemuCaps, net))
                vlan = -1;
            else
                vlan = i;

            if (qemuBuildInterfaceCommandLine(cmd, driver, def, net,
                                              qemuCaps, vlan, bootNet, vmop,
                                              standalone, nnicindexes, nicindexes) < 0)
                goto error;

            last_good_net = i;
            /* if this interface is a type='hostdev' interface and we
             * haven't yet added a "bootindex" parameter to an
             * emulated network device, save the bootindex - hostdev
             * interface commandlines will be built later on when we
             * cycle through all the hostdevs, and we'll use it then.
             */
            if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_HOSTDEV &&
                bootHostdevNet == 0) {
                bootHostdevNet = bootNet;
            }
            bootNet = 0;
        }
    }

    if (def->nsmartcards) {
        /* -device usb-ccid was already emitted along with other
         * controllers.  For now, qemu handles only one smartcard.  */
        virDomainSmartcardDefPtr smartcard = def->smartcards[0];
        char *devstr;
        virBuffer opt = VIR_BUFFER_INITIALIZER;
        const char *database;

        if (def->nsmartcards > 1 ||
            smartcard->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID ||
            smartcard->info.addr.ccid.controller != 0 ||
            smartcard->info.addr.ccid.slot != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU binary lacks multiple smartcard "
                             "support"));
            virBufferFreeAndReset(&opt);
            goto error;
        }

        switch (smartcard->type) {
        case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV) ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_EMULATED)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard host "
                                 "mode support"));
                goto error;
            }

            virBufferAddLit(&opt, "ccid-card-emulated,backend=nss-emulated");
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV) ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_EMULATED)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard host "
                                 "mode support"));
                goto error;
            }

            virBufferAddLit(&opt, "ccid-card-emulated,backend=certificates");
            for (j = 0; j < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; j++) {
                if (strchr(smartcard->data.cert.file[j], ',')) {
                    virBufferFreeAndReset(&opt);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("invalid certificate name: %s"),
                                   smartcard->data.cert.file[j]);
                    goto error;
                }
                virBufferAsprintf(&opt, ",cert%zu=%s", j + 1,
                                  smartcard->data.cert.file[j]);
            }
            if (smartcard->data.cert.database) {
                if (strchr(smartcard->data.cert.database, ',')) {
                    virBufferFreeAndReset(&opt);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("invalid database name: %s"),
                                   smartcard->data.cert.database);
                    goto error;
                }
                database = smartcard->data.cert.database;
            } else {
                database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
            }
            virBufferAsprintf(&opt, ",db=%s", database);
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV) ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCID_PASSTHRU)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard "
                                 "passthrough mode support"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&smartcard->data.passthru,
                                                  smartcard->info.alias,
                                                  qemuCaps))) {
                virBufferFreeAndReset(&opt);
                goto error;
            }
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virBufferAsprintf(&opt, "ccid-card-passthru,chardev=char%s",
                              smartcard->info.alias);
            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected smartcard type %d"),
                           smartcard->type);
            virBufferFreeAndReset(&opt);
            goto error;
        }
        virCommandAddArg(cmd, "-device");
        virBufferAsprintf(&opt, ",id=%s,bus=ccid0.0", smartcard->info.alias);
        virCommandAddArgBuffer(cmd, &opt);
    }

    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr serial = def->serials[i];
        char *devstr;

        if (serial->source.type == VIR_DOMAIN_CHR_TYPE_SPICEPORT && !spice)
            continue;

        /* Use -chardev with -device if they are available */
        if (virQEMUCapsSupportsChardev(def, qemuCaps, serial)) {
            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&serial->source,
                                                  serial->info.alias,
                                                  qemuCaps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            if (qemuBuildChrDeviceCommandLine(cmd, def, serial, qemuCaps) < 0)
                goto error;
        } else {
            virCommandAddArg(cmd, "-serial");
            if (!(devstr = qemuBuildChrArgStr(&serial->source, NULL)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
        }
        actualSerials++;
    }

    /* If we have -device, then we set -nodefault already */
    if (!actualSerials && !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-serial", "none", NULL);

    if (!def->nparallels) {
        /* If we have -device, then we set -nodefault already */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-parallel", "none", NULL);
    } else {
        for (i = 0; i < def->nparallels; i++) {
            virDomainChrDefPtr parallel = def->parallels[i];
            char *devstr;

            /* Use -chardev with -device if they are available */
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV) &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(&parallel->source,
                                                      parallel->info.alias,
                                                      qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);

                if (qemuBuildChrDeviceCommandLine(cmd, def, parallel, qemuCaps) < 0)
                    goto error;
            } else {
                virCommandAddArg(cmd, "-parallel");
                if (!(devstr = qemuBuildChrArgStr(&parallel->source, NULL)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr channel = def->channels[i];
        char *devstr;

        switch (channel->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV) ||
                !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("guestfwd requires QEMU to support -chardev & -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&channel->source,
                                                  channel->info.alias,
                                                  qemuCaps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            if (qemuBuildChrDeviceStr(&devstr, def, channel, qemuCaps) < 0)
                goto error;
            virCommandAddArgList(cmd, "-netdev", devstr, NULL);
            VIR_FREE(devstr);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            /*
             * TODO: Refactor so that we generate this (and onther
             * things) somewhere else then where we are building the
             * command line.
             */
            if (channel->source.type == VIR_DOMAIN_CHR_TYPE_UNIX &&
                !channel->source.data.nix.path) {
                if (virAsprintf(&channel->source.data.nix.path,
                                "%s/domain-%s/%s",
                                cfg->channelTargetDir, def->name,
                                channel->target.name ? channel->target.name
                                : "unknown.sock") < 0)
                    goto error;

                channel->source.data.nix.listen = true;
            }

            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SPICEVMC) &&
                channel->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
                /* spicevmc was originally introduced via a -device
                 * with a backend internal to qemu; although we prefer
                 * the newer -chardev interface.  */
                ;
            } else {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(&channel->source,
                                                      channel->info.alias,
                                                      qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }

            if (qemuBuildChrDeviceCommandLine(cmd, def, channel, qemuCaps) < 0)
                goto error;
            break;
        }
    }

    /* Explicit console devices */
    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDefPtr console = def->consoles[i];
        char *devstr;

        switch (console->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclp console requires QEMU to support -device"));
                goto error;
            }
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCLP_S390)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclp console requires QEMU to support s390-sclp"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&console->source,
                                                  console->info.alias,
                                                  qemuCaps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            if (qemuBuildChrDeviceCommandLine(cmd, def, console, qemuCaps) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&console->source,
                                                  console->info.alias,
                                                  qemuCaps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            if (qemuBuildChrDeviceCommandLine(cmd, def, console, qemuCaps) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported console target type %s"),
                           NULLSTR(virDomainChrConsoleTargetTypeToString(console->targetType)));
            goto error;
        }
    }

    if (def->tpm) {
        if (qemuBuildTPMCommandLine(def, cmd, qemuCaps, emulator) < 0)
            goto error;
    }

    for (i = 0; i < def->ninputs; i++) {
        virDomainInputDefPtr input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                char *optstr;
                virCommandAddArg(cmd, "-device");
                if (!(optstr = qemuBuildUSBInputDevStr(def, input, qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, optstr);
                VIR_FREE(optstr);
            } else {
                switch (input->type) {
                    case VIR_DOMAIN_INPUT_TYPE_MOUSE:
                        virCommandAddArgList(cmd, "-usbdevice", "mouse", NULL);
                        break;
                    case VIR_DOMAIN_INPUT_TYPE_TABLET:
                        virCommandAddArgList(cmd, "-usbdevice", "tablet", NULL);
                        break;
                    case VIR_DOMAIN_INPUT_TYPE_KBD:
                        virCommandAddArgList(cmd, "-usbdevice", "keyboard", NULL);
                        break;
                }
            }
        } else if (input->bus == VIR_DOMAIN_INPUT_BUS_VIRTIO) {
            char *optstr;
            virCommandAddArg(cmd, "-device");
            if (!(optstr = qemuBuildVirtioInputDevStr(def, input, qemuCaps)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        }
    }

    if (sdl > 1 || vnc > 1 || spice > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 1 graphics device of each type "
                         "(sdl, vnc, spice) is supported"));
        goto error;
    }

    for (i = 0; i < def->ngraphics; ++i) {
        if (qemuBuildGraphicsCommandLine(cfg, cmd, def, qemuCaps,
                                         def->graphics[i]) < 0)
            goto error;
    }

    if (def->nvideos > 0) {
        int primaryVideoType = def->videos[0]->type;
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY) &&
             ((primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VGA &&
                 virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_CIRRUS &&
                 virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_CIRRUS_VGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
                 virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VMWARE_SVGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_QXL &&
                 virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_QXL_VGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
                 virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_GPU)))
            ) {
            for (i = 0; i < def->nvideos; i++) {
                char *str;
                virCommandAddArg(cmd, "-device");
                if (!(str = qemuBuildDeviceVideoStr(def, def->videos[i], qemuCaps, !i)))
                    goto error;

                virCommandAddArg(cmd, str);
                VIR_FREE(str);
            }
        } else {
            if (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_XEN) {
                /* nothing - vga has no effect on Xen pvfb */
            } else {
                if ((primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_QXL) &&
                    !virQEMUCapsGet(qemuCaps, QEMU_CAPS_VGA_QXL)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU does not support QXL graphics adapters"));
                    goto error;
                }

                const char *vgastr = qemuVideoTypeToString(primaryVideoType);
                if (!vgastr || STREQ(vgastr, "")) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("video type %s is not supported with QEMU"),
                                   virDomainVideoTypeToString(primaryVideoType));
                    goto error;
                }

                virCommandAddArgList(cmd, "-vga", vgastr, NULL);

                /* If we cannot use --device option to specify the video device
                 * in QEMU we will fallback to the old --vga option. To get the
                 * correct device name for the --vga option the 'qemuVideo' is
                 * used, but to set some device attributes we need to use the
                 * --global option and for that we need to specify the device
                 * name the same as for --device option and for that we need to
                 * use 'qemuDeviceVideo'.
                 *
                 * See 'Graphics Devices' section in docs/qdev-device-use.txt in
                 * QEMU repository.
                 */
                const char *dev = qemuDeviceVideoTypeToString(primaryVideoType);

                if (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_QXL &&
                    (def->videos[0]->vram || def->videos[0]->ram) &&
                    virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                    unsigned int ram = def->videos[0]->ram;
                    unsigned int vram = def->videos[0]->vram;
                    unsigned int vgamem = def->videos[0]->vgamem;

                    if (vram > (UINT_MAX / 1024)) {
                        virReportError(VIR_ERR_OVERFLOW,
                               _("value for 'vram' must be less than '%u'"),
                                       UINT_MAX / 1024);
                        goto error;
                    }
                    if (ram > (UINT_MAX / 1024)) {
                        virReportError(VIR_ERR_OVERFLOW,
                           _("value for 'ram' must be less than '%u'"),
                                       UINT_MAX / 1024);
                        goto error;
                    }

                    if (ram) {
                        virCommandAddArg(cmd, "-global");
                        virCommandAddArgFormat(cmd, "%s.ram_size=%u",
                                               dev, ram * 1024);
                    }
                    if (vram) {
                        virCommandAddArg(cmd, "-global");
                        virCommandAddArgFormat(cmd, "%s.vram_size=%u",
                                               dev, vram * 1024);
                    }
                    if (vgamem &&
                        virQEMUCapsGet(qemuCaps, QEMU_CAPS_QXL_VGA_VGAMEM)) {
                        virCommandAddArg(cmd, "-global");
                        virCommandAddArgFormat(cmd, "%s.vgamem_mb=%u",
                                               dev, vgamem / 1024);
                    }
                }

                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE) &&
                    def->videos[0]->vram &&
                    ((primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VGA &&
                      virQEMUCapsGet(qemuCaps, QEMU_CAPS_VGA_VGAMEM)) ||
                     (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
                      virQEMUCapsGet(qemuCaps, QEMU_CAPS_VMWARE_SVGA_VGAMEM)))) {
                    unsigned int vram = def->videos[0]->vram;

                    if (vram < 1024) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                       "%s", _("value for 'vgamem' must be at "
                                               "least 1 MiB (1024 KiB)"));
                        goto error;
                    }

                    virCommandAddArg(cmd, "-global");
                    virCommandAddArgFormat(cmd, "%s.vgamem_mb=%u",
                                           dev, vram / 1024);
                }
            }

            if (def->nvideos > 1) {
                if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                    for (i = 1; i < def->nvideos; i++) {
                        char *str;
                        if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                           _("video type %s is only valid as primary video card"),
                                           virDomainVideoTypeToString(def->videos[0]->type));
                            goto error;
                        }

                        virCommandAddArg(cmd, "-device");

                        if (!(str = qemuBuildDeviceVideoStr(def, def->videos[i], qemuCaps, false)))
                            goto error;

                        virCommandAddArg(cmd, str);
                        VIR_FREE(str);
                    }
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   "%s", _("only one video card is currently supported"));
                    goto error;
                }
            }
        }

    } else {
        /* If we have -device, then we set -nodefault already */
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE) &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_VGA_NONE))
            virCommandAddArgList(cmd, "-vga", "none", NULL);
    }

    /* Add sound hardware */
    if (def->nsounds) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            for (i = 0; i < def->nsounds; i++) {
                virDomainSoundDefPtr sound = def->sounds[i];
                char *str = NULL;

                /* Sadly pcspk device doesn't use -device syntax. Fortunately
                 * we don't need to set any PCI address on it, so we don't
                 * mind too much */
                if (sound->model == VIR_DOMAIN_SOUND_MODEL_PCSPK) {
                    virCommandAddArgList(cmd, "-soundhw", "pcspk", NULL);
                } else {
                    virCommandAddArg(cmd, "-device");
                    if (!(str = qemuBuildSoundDevStr(def, sound, qemuCaps)))
                        goto error;

                    virCommandAddArg(cmd, str);
                    VIR_FREE(str);
                    if (sound->model == VIR_DOMAIN_SOUND_MODEL_ICH6 ||
                        sound->model == VIR_DOMAIN_SOUND_MODEL_ICH9) {
                        char *codecstr = NULL;

                        for (j = 0; j < sound->ncodecs; j++) {
                            virCommandAddArg(cmd, "-device");
                            if (!(codecstr = qemuBuildSoundCodecStr(sound, sound->codecs[j], qemuCaps))) {
                                goto error;

                            }
                            virCommandAddArg(cmd, codecstr);
                            VIR_FREE(codecstr);
                        }
                        if (j == 0) {
                            virDomainSoundCodecDef codec = {
                                VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX,
                                0
                            };
                            virCommandAddArg(cmd, "-device");
                            if (!(codecstr = qemuBuildSoundCodecStr(sound, &codec, qemuCaps))) {
                                goto error;

                            }
                            virCommandAddArg(cmd, codecstr);
                            VIR_FREE(codecstr);
                        }
                    }
                }
            }
        } else {
            int size = 100;
            char *modstr;
            if (VIR_ALLOC_N(modstr, size+1) < 0)
                goto error;

            for (i = 0; i < def->nsounds && size > 0; i++) {
                virDomainSoundDefPtr sound = def->sounds[i];
                const char *model = virDomainSoundModelTypeToString(sound->model);
                if (!model) {
                    VIR_FREE(modstr);
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("invalid sound model"));
                    goto error;
                }

                if (sound->model == VIR_DOMAIN_SOUND_MODEL_ICH6 ||
                    sound->model == VIR_DOMAIN_SOUND_MODEL_ICH9) {
                    VIR_FREE(modstr);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("this QEMU binary lacks hda support"));
                    goto error;
                }

                strncat(modstr, model, size);
                size -= strlen(model);
                if (i < (def->nsounds - 1))
                    strncat(modstr, ",", size--);
            }
            virCommandAddArgList(cmd, "-soundhw", modstr, NULL);
            VIR_FREE(modstr);
        }
    }

    /* Add watchdog hardware */
    if (def->watchdog) {
        virDomainWatchdogDefPtr watchdog = def->watchdog;
        char *optstr;

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildWatchdogDevStr(def, watchdog, qemuCaps);
            if (!optstr)
                goto error;
        } else {
            virCommandAddArg(cmd, "-watchdog");

            const char *model = virDomainWatchdogModelTypeToString(watchdog->model);
            if (!model) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("missing watchdog model"));
                goto error;
            }

            if (VIR_STRDUP(optstr, model) < 0)
                goto error;
        }
        virCommandAddArg(cmd, optstr);
        VIR_FREE(optstr);

        int act = watchdog->action;
        if (act == VIR_DOMAIN_WATCHDOG_ACTION_DUMP)
            act = VIR_DOMAIN_WATCHDOG_ACTION_PAUSE;
        const char *action = virDomainWatchdogActionTypeToString(act);
        if (!action) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("invalid watchdog action"));
            goto error;
        }
        virCommandAddArgList(cmd, "-watchdog-action", action, NULL);
    }

    /* Add redirected devices */
    for (i = 0; i < def->nredirdevs; i++) {
        virDomainRedirdevDefPtr redirdev = def->redirdevs[i];
        char *devstr;

        virCommandAddArg(cmd, "-chardev");
        if (!(devstr = qemuBuildChrChardevStr(&redirdev->source.chr,
                                              redirdev->info.alias,
                                              qemuCaps))) {
            goto error;
        }

        virCommandAddArg(cmd, devstr);
        VIR_FREE(devstr);

        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("redirected devices are not supported by this QEMU"));
            goto error;
        }


        virCommandAddArg(cmd, "-device");
        if (!(devstr = qemuBuildRedirdevDevStr(def, redirdev, qemuCaps)))
            goto error;
        virCommandAddArg(cmd, devstr);
        VIR_FREE(devstr);
    }

    /* Add host passthrough hardware */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        char *devstr;

        if (hostdev->info->bootIndex) {
            if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
                (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
                 hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
                 hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("booting from assigned devices is only "
                                 "supported for PCI, USB and SCSI devices"));
                goto error;
            } else {
                if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
                    if (hostdev->source.subsys.u.pci.backend
                        == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VFIO_PCI_BOOTINDEX)) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                           _("booting from PCI devices assigned with VFIO "
                                             "is not supported with this version of qemu"));
                            goto error;
                        }
                    } else {
                        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_BOOTINDEX)) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                           _("booting from assigned PCI devices is not "
                                             "supported with this version of qemu"));
                            goto error;
                        }
                    }
                }
                if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
                    !virQEMUCapsGet(qemuCaps, QEMU_CAPS_USB_HOST_BOOTINDEX)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("booting from assigned USB devices is not "
                                     "supported with this version of qemu"));
                    goto error;
                }
                if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
                    !virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SCSI_GENERIC_BOOTINDEX)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("booting from assigned SCSI devices is not"
                                     " supported with this version of qemu"));
                    goto error;
                }
            }
        }

        /* USB */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {

            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildUSBHostdevDevStr(def, hostdev, qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virCommandAddArg(cmd, "-usbdevice");
                if (!(devstr = qemuBuildUSBHostdevUSBDevStr(hostdev)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }

        /* PCI */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            int backend = hostdev->source.subsys.u.pci.backend;

            if (backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
                if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("VFIO PCI device assignment is not "
                                     "supported by this version of qemu"));
                    goto error;
                }
            }

            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
                char *configfd_name = NULL;
                int bootIndex = hostdev->info->bootIndex;

                /* bootNet will be non-0 if boot order was set and no other
                 * net devices were encountered
                 */
                if (hostdev->parent.type == VIR_DOMAIN_DEVICE_NET &&
                    bootIndex == 0) {
                    bootIndex = bootHostdevNet;
                    bootHostdevNet = 0;
                }
                if ((backend != VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) &&
                    virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCI_CONFIGFD)) {
                    int configfd = qemuOpenPCIConfig(hostdev);

                    if (configfd >= 0) {
                        if (virAsprintf(&configfd_name, "%d", configfd) < 0) {
                            VIR_FORCE_CLOSE(configfd);
                            goto error;
                        }

                        virCommandPassFD(cmd, configfd,
                                         VIR_COMMAND_PASS_FD_CLOSE_PARENT);
                    }
                }
                virCommandAddArg(cmd, "-device");
                devstr = qemuBuildPCIHostdevDevStr(def, hostdev, bootIndex,
                                                   configfd_name, qemuCaps);
                VIR_FREE(configfd_name);
                if (!devstr)
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCIDEVICE)) {
                virCommandAddArg(cmd, "-pcidevice");
                if (!(devstr = qemuBuildPCIHostdevPCIDevStr(hostdev, qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("PCI device assignment is not supported by this version of qemu"));
                goto error;
            }
        }

        /* SCSI */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI) {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE) &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_SCSI_GENERIC)) {
                char *drvstr;

                virCommandAddArg(cmd, "-drive");
                if (!(drvstr = qemuBuildSCSIHostdevDrvStr(conn, hostdev, qemuCaps, callbacks)))
                    goto error;
                virCommandAddArg(cmd, drvstr);
                VIR_FREE(drvstr);

                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildSCSIHostdevDevStr(def, hostdev, qemuCaps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SCSI passthrough is not supported by this version of qemu"));
                goto error;
            }
        }
    }

    if (migrateURI)
        virCommandAddArgList(cmd, "-incoming", migrateURI, NULL);

    /* QEMU changed its default behavior to not include the virtio balloon
     * device.  Explicitly request it to ensure it will be present.
     *
     * NB: Earlier we declared that VirtIO balloon will always be in
     * slot 0x3 on bus 0x0
     */
    if (STREQLEN(def->os.machine, "s390-virtio", 10) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_S390) && def->memballoon)
        def->memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_NONE;

    if (def->memballoon &&
        def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE) {
        if (def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory balloon device type '%s' is not supported by this version of qemu"),
                           virDomainMemballoonModelTypeToString(def->memballoon->model));
            goto error;
        }
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            char *optstr;
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildMemballoonDevStr(def, def->memballoon, qemuCaps);
            if (!optstr)
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_BALLOON)) {
            virCommandAddArgList(cmd, "-balloon", "virtio", NULL);
        }
    }

    for (i = 0; i < def->nrngs; i++) {
        virDomainRNGDefPtr rng = def->rngs[i];
        char *tmp;

        if (!rng->info.alias) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("RNG device is missing alias"));
            goto error;
        }

        /* possibly add character device for backend */
        if (qemuBuildRNGBackendChrdevStr(rng, qemuCaps, &tmp) < 0)
            goto error;

        if (tmp) {
            virCommandAddArgList(cmd, "-chardev", tmp, NULL);
            VIR_FREE(tmp);
        }

        /* add the RNG source backend */
        if (!(tmp = qemuBuildRNGBackendStr(rng, qemuCaps)))
            goto error;

        virCommandAddArgList(cmd, "-object", tmp, NULL);
        VIR_FREE(tmp);

        /* add the device */
        if (!(tmp = qemuBuildRNGDevStr(def, rng, qemuCaps)))
            goto error;
        virCommandAddArgList(cmd, "-device", tmp, NULL);
        VIR_FREE(tmp);
    }

    if (def->nvram) {
        if (ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries")) {
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_NVRAM)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("nvram device is not supported by "
                                 "this QEMU binary"));
                goto error;
            }

            char *optstr;
            virCommandAddArg(cmd, "-global");
            optstr = qemuBuildNVRAMDevStr(def->nvram);
            if (!optstr)
                goto error;
            if (optstr)
                virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("nvram device is only supported for PPC64"));
            goto error;
        }
    }
    if (snapshot)
        virCommandAddArgList(cmd, "-loadvm", snapshot->def->name, NULL);

    if (def->namespaceData) {
        qemuDomainCmdlineDefPtr qemucmd;

        qemucmd = def->namespaceData;
        for (i = 0; i < qemucmd->num_args; i++)
            virCommandAddArg(cmd, qemucmd->args[i]);
        for (i = 0; i < qemucmd->num_env; i++)
            virCommandAddEnvPair(cmd, qemucmd->env_name[i],
                                 qemucmd->env_value[i]
                                 ? qemucmd->env_value[i] : "");
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SECCOMP_SANDBOX)) {
        if (cfg->seccompSandbox == 0)
            virCommandAddArgList(cmd, "-sandbox", "off", NULL);
        else if (cfg->seccompSandbox > 0)
            virCommandAddArgList(cmd, "-sandbox", "on", NULL);
    } else if (cfg->seccompSandbox > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("QEMU does not support seccomp sandboxes"));
        goto error;
    }

    for (i = 0; i < def->npanics; i++) {
        switch ((virDomainPanicModel) def->panics[i]->model) {
        case VIR_DOMAIN_PANIC_MODEL_HYPERV:
            /* Panic with model 'hyperv' is not a device, it should
             * be configured in cpu commandline. The address
             * cannot be configured by the user */
            if (!ARCH_IS_X86(def->os.arch)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only i686 and x86_64 guests support "
                                 "panic device of model 'hyperv'"));
                goto error;
            }
            if (def->panics[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("setting the panic device address is not "
                                 "supported for model 'hyperv'"));
                goto error;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_PSERIES:
            /* For pSeries guests, the firmware provides the same
             * functionality as the pvpanic device. The address
             * cannot be configured by the user */
            if (!ARCH_IS_PPC64(def->os.arch) ||
                !STRPREFIX(def->os.machine, "pseries")) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only pSeries guests support panic device "
                                 "of model 'pseries'"));
                goto error;
            }
            if (def->panics[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("setting the panic device address is not "
                                 "supported for model 'pseries'"));
                goto error;
            }
            break;

        case VIR_DOMAIN_PANIC_MODEL_ISA:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PANIC)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("the QEMU binary does not support the "
                                 "panic device"));
                goto error;
            }

            switch (def->panics[i]->info.type) {
            case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
                virCommandAddArg(cmd, "-device");
                virCommandAddArgFormat(cmd, "pvpanic,ioport=%d",
                                       def->panics[i]->info.addr.isa.iobase);
                break;

            case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
                virCommandAddArgList(cmd, "-device", "pvpanic", NULL);
                break;

            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("panic is supported only "
                                 "with ISA address type"));
                goto error;
            }

        /* default model value was changed before in post parse */
        case VIR_DOMAIN_PANIC_MODEL_DEFAULT:
        case VIR_DOMAIN_PANIC_MODEL_LAST:
            break;
        }
    }

    for (i = 0; i < def->nshmems; i++) {
        if (qemuBuildShmemCommandLine(cmd, def, def->shmems[i], qemuCaps))
            goto error;
    }

    /* In some situations, eg. VFIO passthrough, QEMU might need to lock a
     * significant amount of memory, so we need to set the limit accordingly */
    if (qemuDomainRequiresMemLock(def))
        virCommandSetMaxMemLock(cmd, qemuDomainGetMemLockLimitBytes(def));

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MSG_TIMESTAMP) &&
        cfg->logTimestamp)
        virCommandAddArgList(cmd, "-msg", "timestamp=on", NULL);

    virObjectUnref(cfg);
    return cmd;

 error:
    VIR_FREE(boot_order_str);
    VIR_FREE(boot_opts_str);
    virBufferFreeAndReset(&boot_buf);
    virObjectUnref(cfg);
    /* free up any resources in the network driver
     * but don't overwrite the original error */
    originalError = virSaveLastError();
    for (i = 0; last_good_net != -1 && i <= last_good_net; i++)
        virDomainConfNWFilterTeardown(def->nets[i]);
    virSetError(originalError);
    virFreeError(originalError);
    virCommandFree(cmd);
    return NULL;
}

/* This function generates the correct '-device' string for character
 * devices of each architecture.
 */
static int
qemuBuildSerialChrDeviceStr(char **deviceStr,
                            virDomainDefPtr def,
                            virDomainChrDefPtr serial,
                            virQEMUCapsPtr qemuCaps,
                            virArch arch,
                            char *machine)
{
    virBuffer cmd = VIR_BUFFER_INITIALIZER;

    if (ARCH_IS_PPC64(arch) && STRPREFIX(machine, "pseries")) {
        if (serial->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            serial->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO) {
            virBufferAsprintf(&cmd, "spapr-vty,chardev=char%s",
                              serial->info.alias);
            if (qemuBuildDeviceAddressStr(&cmd, def, &serial->info, qemuCaps) < 0)
                goto error;
        }
    } else {
        virBufferAsprintf(&cmd, "%s,chardev=char%s,id=%s",
                          virDomainChrSerialTargetTypeToString(serial->targetType),
                          serial->info.alias, serial->info.alias);

        switch (serial->targetType) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_SERIAL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("usb-serial is not supported in this QEMU binary"));
                goto error;
            }

            if (serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("usb-serial requires address of usb type"));
                goto error;
            }

            if (qemuBuildDeviceAddressStr(&cmd, def, &serial->info, qemuCaps) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
            if (serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("isa-serial requires address of isa type"));
                goto error;
            }

            if (qemuBuildDeviceAddressStr(&cmd, def, &serial->info, qemuCaps) < 0)
                goto error;
            break;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCI_SERIAL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("pci-serial is not supported with this QEMU binary"));
                goto error;
            }

            if (serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("pci-serial requires address of pci type"));
                goto error;
            }

            if (qemuBuildDeviceAddressStr(&cmd, def, &serial->info, qemuCaps) < 0)
                goto error;
            break;
        }
    }

    if (virBufferCheckError(&cmd) < 0)
        goto error;

    *deviceStr = virBufferContentAndReset(&cmd);
    return 0;

 error:
    virBufferFreeAndReset(&cmd);
    return -1;
}

static int
qemuBuildParallelChrDeviceStr(char **deviceStr,
                              virDomainChrDefPtr chr)
{
    if (virAsprintf(deviceStr, "isa-parallel,chardev=char%s,id=%s",
                    chr->info.alias, chr->info.alias) < 0)
        return -1;
    return 0;
}

static int
qemuBuildChannelChrDeviceStr(char **deviceStr,
                             virDomainDefPtr def,
                             virDomainChrDefPtr chr,
                             virQEMUCapsPtr qemuCaps)
{
    int ret = -1;
    char *addr = NULL;
    int port;

    switch ((virDomainChrChannelTargetType) chr->targetType) {
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:

        addr = virSocketAddrFormat(chr->target.addr);
        if (!addr)
            return ret;
        port = virSocketAddrGetPort(chr->target.addr);

        if (virAsprintf(deviceStr,
                        "user,guestfwd=tcp:%s:%i-chardev:char%s,id=user-%s",
                        addr, port, chr->info.alias, chr->info.alias) < 0)
            goto cleanup;
        break;

    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
        if (!(*deviceStr = qemuBuildVirtioSerialPortDevStr(def, chr, qemuCaps)))
            goto cleanup;
        break;

    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE:
    case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST:
        return ret;
    }

    ret = 0;
 cleanup:
    VIR_FREE(addr);
    return ret;
}

static int
qemuBuildConsoleChrDeviceStr(char **deviceStr,
                             virDomainDefPtr def,
                             virDomainChrDefPtr chr,
                             virQEMUCapsPtr qemuCaps)
{
    int ret = -1;

    switch ((virDomainChrConsoleTargetType) chr->targetType) {
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
        if (!(*deviceStr = qemuBuildSclpDevStr(chr)))
            goto cleanup;
        break;

    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
        if (!(*deviceStr = qemuBuildVirtioSerialPortDevStr(def, chr, qemuCaps)))
            goto cleanup;
        break;

    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
        break;

    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_UML:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ:
    case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported console target type %s"),
                       NULLSTR(virDomainChrConsoleTargetTypeToString(chr->targetType)));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

int
qemuBuildChrDeviceStr(char **deviceStr,
                      virDomainDefPtr vmdef,
                      virDomainChrDefPtr chr,
                      virQEMUCapsPtr qemuCaps)
{
    int ret = -1;

    switch ((virDomainChrDeviceType) chr->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL:
        ret = qemuBuildSerialChrDeviceStr(deviceStr, vmdef, chr, qemuCaps,
                                          vmdef->os.arch,
                                          vmdef->os.machine);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL:
        ret = qemuBuildParallelChrDeviceStr(deviceStr, chr);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        ret = qemuBuildChannelChrDeviceStr(deviceStr, vmdef, chr, qemuCaps);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        ret = qemuBuildConsoleChrDeviceStr(deviceStr, vmdef, chr, qemuCaps);
        break;

    case VIR_DOMAIN_CHR_DEVICE_TYPE_LAST:
        return ret;
    }

    return ret;
}


/*
 * This method takes a string representing a QEMU command line ARGV set
 * optionally prefixed by a list of environment variables. It then tries
 * to split it up into a NULL terminated list of env & argv, splitting
 * on space
 */
static int qemuStringToArgvEnv(const char *args,
                               char ***retenv,
                               char ***retargv)
{
    char **arglist = NULL;
    size_t argcount = 0;
    size_t argalloc = 0;
    size_t envend;
    size_t i;
    const char *curr = args;
    const char *start;
    char **progenv = NULL;
    char **progargv = NULL;

    /* Iterate over string, splitting on sequences of ' ' */
    while (curr && *curr != '\0') {
        char *arg;
        const char *next;

        start = curr;
        /* accept a space in CEPH_ARGS */
        if (STRPREFIX(curr, "CEPH_ARGS=-m "))
            start += strlen("CEPH_ARGS=-m ");
        if (*start == '\'') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '\'');
        } else if (*start == '"') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '"');
        } else {
            next = strchr(start, ' ');
        }
        if (!next)
            next = strchr(curr, '\n');

        if (VIR_STRNDUP(arg, curr, next ? next - curr : -1) < 0)
            goto error;

        if (next && (*next == '\'' || *next == '"'))
            next++;

        if (VIR_RESIZE_N(arglist, argalloc, argcount, 2) < 0) {
            VIR_FREE(arg);
            goto error;
        }

        arglist[argcount++] = arg;
        arglist[argcount] = NULL;

        while (next && c_isspace(*next))
            next++;

        curr = next;
    }

    /* Iterate over list of args, finding first arg not containing
     * the '=' character (eg, skip over env vars FOO=bar) */
    for (envend = 0; ((envend < argcount) &&
                       (strchr(arglist[envend], '=') != NULL));
         envend++)
        ; /* nada */

    /* Copy the list of env vars */
    if (envend > 0) {
        if (VIR_REALLOC_N(progenv, envend+1) < 0)
            goto error;
        for (i = 0; i < envend; i++)
            progenv[i] = arglist[i];
        progenv[i] = NULL;
    }

    /* Copy the list of argv */
    if (VIR_REALLOC_N(progargv, argcount-envend + 1) < 0)
        goto error;
    for (i = envend; i < argcount; i++)
        progargv[i-envend] = arglist[i];
    progargv[i-envend] = NULL;

    VIR_FREE(arglist);

    *retenv = progenv;
    *retargv = progargv;

    return 0;

 error:
    VIR_FREE(progenv);
    VIR_FREE(progargv);
    virStringFreeList(arglist);
    return -1;
}


/*
 * Search for a named env variable, and return the value part
 */
static const char *qemuFindEnv(char **progenv,
                               const char *name)
{
    size_t i;
    int len = strlen(name);

    for (i = 0; progenv && progenv[i]; i++) {
        if (STREQLEN(progenv[i], name, len) &&
            progenv[i][len] == '=')
            return progenv[i] + len + 1;
    }
    return NULL;
}

/*
 * Takes a string containing a set of key=value,key=value,key...
 * parameters and splits them up, returning two arrays with
 * the individual keys and values. If allowEmptyValue is nonzero,
 * the "=value" part is optional and if a key with no value is found,
 * NULL is be placed into corresponding place in retvalues.
 */
int
qemuParseKeywords(const char *str,
                  char ***retkeywords,
                  char ***retvalues,
                  int *retnkeywords,
                  int allowEmptyValue)
{
    int keywordCount = 0;
    int keywordAlloc = 0;
    char **keywords = NULL;
    char **values = NULL;
    const char *start = str;
    const char *end;
    size_t i;

    *retkeywords = NULL;
    *retvalues = NULL;
    *retnkeywords = 0;
    end = start + strlen(str);

    while (start) {
        const char *separator;
        const char *endmark;
        char *keyword;
        char *value = NULL;

        endmark = start;
        do {
            /* Qemu accepts ',,' as an escape for a literal comma;
             * skip past those here while searching for the end of the
             * value, then strip them down below */
            endmark = strchr(endmark, ',');
        } while (endmark && endmark[1] == ',' && (endmark += 2));
        if (!endmark)
            endmark = end;
        if (!(separator = strchr(start, '=')))
            separator = end;

        if (separator >= endmark) {
            if (!allowEmptyValue) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("malformed keyword arguments in '%s'"), str);
                goto error;
            }
            separator = endmark;
        }

        if (VIR_STRNDUP(keyword, start, separator - start) < 0)
            goto error;

        if (separator < endmark) {
            separator++;
            if (VIR_STRNDUP(value, separator, endmark - separator) < 0) {
                VIR_FREE(keyword);
                goto error;
            }
            if (strchr(value, ',')) {
                char *p = strchr(value, ',') + 1;
                char *q = p + 1;
                while (*q) {
                    if (*q == ',')
                        q++;
                    *p++ = *q++;
                }
                *p = '\0';
            }
        }

        if (keywordAlloc == keywordCount) {
            if (VIR_REALLOC_N(keywords, keywordAlloc + 10) < 0 ||
                VIR_REALLOC_N(values, keywordAlloc + 10) < 0) {
                VIR_FREE(keyword);
                VIR_FREE(value);
                goto error;
            }
            keywordAlloc += 10;
        }

        keywords[keywordCount] = keyword;
        values[keywordCount] = value;
        keywordCount++;

        start = endmark < end ? endmark + 1 : NULL;
    }

    *retkeywords = keywords;
    *retvalues = values;
    *retnkeywords = keywordCount;
    return 0;

 error:
    for (i = 0; i < keywordCount; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return -1;
}

/*
 * Tries to parse new style QEMU -drive  args.
 *
 * eg -drive file=/dev/HostVG/VirtData1,if=ide,index=1
 *
 * Will fail if not using the 'index' keyword
 */
static virDomainDiskDefPtr
qemuParseCommandLineDisk(virDomainXMLOptionPtr xmlopt,
                         const char *val,
                         virDomainDefPtr dom,
                         int nvirtiodisk,
                         bool old_style_ceph_args)
{
    virDomainDiskDefPtr def = NULL;
    char **keywords;
    char **values;
    int nkeywords;
    size_t i;
    int idx = -1;
    int busid = -1;
    int unitid = -1;

    if (qemuParseKeywords(val,
                          &keywords,
                          &values,
                          &nkeywords,
                          0) < 0)
        return NULL;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;
    if (VIR_ALLOC(def->src) < 0)
        goto error;

    if ((ARCH_IS_PPC64(dom->os.arch) &&
        dom->os.machine && STRPREFIX(dom->os.machine, "pseries")))
        def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
    else
       def->bus = VIR_DOMAIN_DISK_BUS_IDE;
    def->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    def->src->type = VIR_STORAGE_TYPE_FILE;

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "file")) {
            if (values[i] && STRNEQ(values[i], "")) {
                def->src->path = values[i];
                values[i] = NULL;
                if (STRPREFIX(def->src->path, "/dev/"))
                    def->src->type = VIR_STORAGE_TYPE_BLOCK;
                else if (STRPREFIX(def->src->path, "nbd:") ||
                         STRPREFIX(def->src->path, "nbd+")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;

                    if (qemuParseNBDString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "rbd:")) {
                    char *p = def->src->path;

                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
                    if (VIR_STRDUP(def->src->path, p + strlen("rbd:")) < 0)
                        goto error;
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!old_style_ceph_args && qemuParseRBDString(def) < 0) {
                        VIR_FREE(p);
                        goto error;
                    }

                    VIR_FREE(p);
                } else if (STRPREFIX(def->src->path, "gluster:") ||
                           STRPREFIX(def->src->path, "gluster+")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;

                    if (qemuParseGlusterString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "iscsi:")) {
                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_ISCSI;

                    if (qemuParseISCSIString(def) < 0)
                        goto error;
                } else if (STRPREFIX(def->src->path, "sheepdog:")) {
                    char *p = def->src->path;
                    char *port, *vdi;

                    def->src->type = VIR_STORAGE_TYPE_NETWORK;
                    def->src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;
                    if (VIR_STRDUP(def->src->path, p + strlen("sheepdog:")) < 0)
                        goto error;
                    VIR_FREE(p);

                    /* def->src->path must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(def->src->path, ':');
                    if (port) {
                        *port = '\0';
                        vdi = strchr(port + 1, ':');
                        if (!vdi) {
                            *port = ':';
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse sheepdog filename '%s'"),
                                           def->src->path);
                            goto error;
                        }
                        port++;
                        *vdi++ = '\0';
                        if (VIR_ALLOC(def->src->hosts) < 0)
                            goto error;
                        def->src->nhosts = 1;
                        def->src->hosts->name = def->src->path;
                        if (VIR_STRDUP(def->src->hosts->port, port) < 0)
                            goto error;
                        def->src->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
                        def->src->hosts->socket = NULL;
                        if (VIR_STRDUP(def->src->path, vdi) < 0)
                            goto error;
                    }
                } else {
                    def->src->type = VIR_STORAGE_TYPE_FILE;
                }
            } else {
                def->src->type = VIR_STORAGE_TYPE_FILE;
            }
        } else if (STREQ(keywords[i], "if")) {
            if (STREQ(values[i], "ide")) {
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
                if ((ARCH_IS_PPC64(dom->os.arch) &&
                     dom->os.machine && STRPREFIX(dom->os.machine, "pseries"))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("pseries systems do not support ide devices '%s'"), val);
                    goto error;
                }
            } else if (STREQ(values[i], "scsi")) {
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            } else if (STREQ(values[i], "floppy")) {
                def->bus = VIR_DOMAIN_DISK_BUS_FDC;
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
            } else if (STREQ(values[i], "virtio")) {
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            } else if (STREQ(values[i], "xen")) {
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
            } else if (STREQ(values[i], "sd")) {
                def->bus = VIR_DOMAIN_DISK_BUS_SD;
            }
        } else if (STREQ(keywords[i], "media")) {
            if (STREQ(values[i], "cdrom")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                def->src->readonly = true;
            } else if (STREQ(values[i], "floppy")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
            }
        } else if (STREQ(keywords[i], "format")) {
            if (VIR_STRDUP(def->src->driverName, "qemu") < 0)
                goto error;
            def->src->format = virStorageFileFormatTypeFromString(values[i]);
        } else if (STREQ(keywords[i], "cache")) {
            if (STREQ(values[i], "off") ||
                STREQ(values[i], "none"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DISABLE;
            else if (STREQ(values[i], "writeback") ||
                     STREQ(values[i], "on"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITEBACK;
            else if (STREQ(values[i], "writethrough"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITETHRU;
            else if (STREQ(values[i], "directsync"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DIRECTSYNC;
            else if (STREQ(values[i], "unsafe"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_UNSAFE;
        } else if (STREQ(keywords[i], "werror")) {
            if (STREQ(values[i], "stop"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
            else if (STREQ(values[i], "enospc"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE;
        } else if (STREQ(keywords[i], "rerror")) {
            if (STREQ(values[i], "stop"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
        } else if (STREQ(keywords[i], "index")) {
            if (virStrToLong_i(values[i], NULL, 10, &idx) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive index '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "bus")) {
            if (virStrToLong_i(values[i], NULL, 10, &busid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive bus '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "unit")) {
            if (virStrToLong_i(values[i], NULL, 10, &unitid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive unit '%s'"), val);
                goto error;
            }
        } else if (STREQ(keywords[i], "readonly")) {
            if ((values[i] == NULL) || STREQ(values[i], "on"))
                def->src->readonly = true;
        } else if (STREQ(keywords[i], "aio")) {
            if ((def->iomode = virDomainDiskIoTypeFromString(values[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse io mode '%s'"), values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "cyls")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.cylinders)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse cylinders value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "heads")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.heads)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse heads value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "secs")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.sectors)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sectors value'%s'"),
                               values[i]);
                goto error;
            }
        } else if (STREQ(keywords[i], "trans")) {
            def->geometry.trans =
                virDomainDiskGeometryTransTypeFromString(values[i]);
            if ((def->geometry.trans < VIR_DOMAIN_DISK_TRANS_DEFAULT) ||
                (def->geometry.trans >= VIR_DOMAIN_DISK_TRANS_LAST)) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse translation value '%s'"),
                               values[i]);
                goto error;
            }
        }
    }

    if (def->rerror_policy == def->error_policy)
        def->rerror_policy = 0;

    if (!def->src->path &&
        def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        def->src->type != VIR_STORAGE_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing file parameter in drive '%s'"), val);
        goto error;
    }
    if (idx == -1 &&
        def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
        idx = nvirtiodisk;

    if (idx == -1 &&
        unitid == -1 &&
        busid == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing index/unit/bus parameter in drive '%s'"),
                       val);
        goto error;
    }

    if (idx == -1) {
        if (unitid == -1)
            unitid = 0;
        if (busid == -1)
            busid = 0;
        switch (def->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            idx = (busid * 2) + unitid;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            idx = (busid * 7) + unitid;
            break;
        default:
            idx = unitid;
            break;
        }
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        ignore_value(VIR_STRDUP(def->dst, "hda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI ||
               def->bus == VIR_DOMAIN_DISK_BUS_SD) {
        ignore_value(VIR_STRDUP(def->dst, "sda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        ignore_value(VIR_STRDUP(def->dst, "vda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_XEN) {
        ignore_value(VIR_STRDUP(def->dst, "xvda"));
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        ignore_value(VIR_STRDUP(def->dst, "fda"));
    } else {
        ignore_value(VIR_STRDUP(def->dst, "hda"));
    }

    if (!def->dst)
        goto error;
    if (STREQ(def->dst, "xvda"))
        def->dst[3] = 'a' + idx;
    else
        def->dst[2] = 'a' + idx;

    if (virDomainDiskDefAssignAddress(xmlopt, def, dom) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid device name '%s'"), def->dst);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }

 cleanup:
    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;

 error:
    virDomainDiskDefFree(def);
    def = NULL;
    goto cleanup;
}

/*
 * Tries to find a NIC definition matching a vlan we want
 */
static const char *
qemuFindNICForVLAN(int nnics,
                   const char **nics,
                   int wantvlan)
{
    size_t i;
    for (i = 0; i < nnics; i++) {
        int gotvlan;
        const char *tmp = strstr(nics[i], "vlan=");
        char *end;
        if (!tmp)
            continue;

        tmp += strlen("vlan=");

        if (virStrToLong_i(tmp, &end, 10, &gotvlan) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse NIC vlan in '%s'"), nics[i]);
            return NULL;
        }

        if (gotvlan == wantvlan)
            return nics[i];
    }

    if (wantvlan == 0 && nnics > 0)
        return nics[0];

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot find NIC definition for vlan %d"), wantvlan);
    return NULL;
}


/*
 * Tries to parse a QEMU -net backend argument. Gets given
 * a list of all known -net frontend arguments to try and
 * match up against. Horribly complicated stuff
 */
static virDomainNetDefPtr
qemuParseCommandLineNet(virDomainXMLOptionPtr xmlopt,
                        const char *val,
                        int nnics,
                        const char **nics)
{
    virDomainNetDefPtr def = NULL;
    char **keywords = NULL;
    char **values = NULL;
    int nkeywords;
    const char *nic;
    int wantvlan = 0;
    const char *tmp;
    bool genmac = true;
    size_t i;

    tmp = strchr(val, ',');

    if (tmp) {
        if (qemuParseKeywords(tmp+1,
                              &keywords,
                              &values,
                              &nkeywords,
                              0) < 0)
            return NULL;
    } else {
        nkeywords = 0;
    }

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    /* 'tap' could turn into libvirt type=ethernet, type=bridge or
     * type=network, but we can't tell, so use the generic config */
    if (STRPREFIX(val, "tap,"))
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
    else if (STRPREFIX(val, "socket"))
        def->type = VIR_DOMAIN_NET_TYPE_CLIENT;
    else if (STRPREFIX(val, "user"))
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    else
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "vlan")) {
            if (virStrToLong_i(values[i], NULL, 10, &wantvlan) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse vlan in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "script") && STRNEQ(values[i], "")) {
            def->script = values[i];
            values[i] = NULL;
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "ifname")) {
            def->ifname = values[i];
            values[i] = NULL;
        }
    }


    /* Done parsing the nic backend. Now to try and find corresponding
     * frontend, based off vlan number. NB this assumes a 1-1 mapping
     */

    nic = qemuFindNICForVLAN(nnics, nics, wantvlan);
    if (!nic) {
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (!STRPREFIX(nic, "nic")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse NIC definition '%s'"), nic);
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);

    if (STRPREFIX(nic, "nic,")) {
        if (qemuParseKeywords(nic + strlen("nic,"),
                              &keywords,
                              &values,
                              &nkeywords,
                              0) < 0) {
            virDomainNetDefFree(def);
            def = NULL;
            goto cleanup;
        }
    } else {
        nkeywords = 0;
    }

    for (i = 0; i < nkeywords; i++) {
        if (STREQ(keywords[i], "macaddr")) {
            genmac = false;
            if (virMacAddrParse(values[i], &def->mac) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unable to parse mac address '%s'"),
                               values[i]);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "model")) {
            def->model = values[i];
            values[i] = NULL;
        } else if (STREQ(keywords[i], "vhost")) {
            if ((values[i] == NULL) || STREQ(values[i], "on")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_VHOST;
            } else if (STREQ(keywords[i], "off")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_QEMU;
            }
        } else if (STREQ(keywords[i], "sndbuf") && values[i]) {
            if (virStrToLong_ul(values[i], NULL, 10, &def->tune.sndbuf) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sndbuf size in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
            def->tune.sndbuf_specified = true;
        }
    }

    if (genmac)
        virDomainNetGenerateMAC(xmlopt, &def->mac);

 cleanup:
    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}


/*
 * Tries to parse a QEMU PCI device
 */
static virDomainHostdevDefPtr
qemuParseCommandLinePCI(const char *val)
{
    int bus = 0, slot = 0, func = 0;
    const char *start;
    char *end;
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc();

    if (!def)
        goto error;

    if (!STRPREFIX(val, "host=")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown PCI device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host=");
    if (virStrToLong_i(start, &end, 16, &bus) < 0 || *end != ':') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device bus '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, &end, 16, &slot) < 0 || *end != '.') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device slot '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, NULL, 16, &func) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device function '%s'"), val);
        goto error;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = true;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    def->source.subsys.u.pci.addr.bus = bus;
    def->source.subsys.u.pci.addr.slot = slot;
    def->source.subsys.u.pci.addr.function = func;
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU USB device
 */
static virDomainHostdevDefPtr
qemuParseCommandLineUSB(const char *val)
{
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc();
    virDomainHostdevSubsysUSBPtr usbsrc;
    int first = 0, second = 0;
    const char *start;
    char *end;

    if (!def)
        goto error;
    usbsrc = &def->source.subsys.u.usb;

    if (!STRPREFIX(val, "host:")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown USB device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host:");
    if (strchr(start, ':')) {
        if (virStrToLong_i(start, &end, 16, &first) < 0 || *end != ':') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device vendor '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 16, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device product '%s'"), val);
            goto error;
        }
    } else {
        if (virStrToLong_i(start, &end, 10, &first) < 0 || *end != '.') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device bus '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 10, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device address '%s'"), val);
            goto error;
        }
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = false;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
    if (*end == '.') {
        usbsrc->bus = first;
        usbsrc->device = second;
    } else {
        usbsrc->vendor = first;
        usbsrc->product = second;
    }
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU serial/parallel device
 */
static int
qemuParseCommandLineChr(virDomainChrSourceDefPtr source,
                        const char *val)
{
    if (STREQ(val, "null")) {
        source->type = VIR_DOMAIN_CHR_TYPE_NULL;
    } else if (STREQ(val, "vc")) {
        source->type = VIR_DOMAIN_CHR_TYPE_VC;
    } else if (STREQ(val, "pty")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if (STRPREFIX(val, "file:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_FILE;
        if (VIR_STRDUP(source->data.file.path, val + strlen("file:")) < 0)
            goto error;
    } else if (STRPREFIX(val, "pipe:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        if (VIR_STRDUP(source->data.file.path, val + strlen("pipe:")) < 0)
            goto error;
    } else if (STREQ(val, "stdio")) {
        source->type = VIR_DOMAIN_CHR_TYPE_STDIO;
    } else if (STRPREFIX(val, "udp:")) {
        const char *svc1, *host2, *svc2;
        source->type = VIR_DOMAIN_CHR_TYPE_UDP;
        val += strlen("udp:");
        svc1 = strchr(val, ':');
        host2 = svc1 ? strchr(svc1, '@') : NULL;
        svc2 = host2 ? strchr(host2, ':') : NULL;

        if (svc1 && svc1 != val &&
            VIR_STRNDUP(source->data.udp.connectHost, val, svc1 - val) < 0)
            goto error;

        if (svc1) {
            svc1++;
            if (VIR_STRNDUP(source->data.udp.connectService, svc1,
                            host2 ? host2 - svc1 : strlen(svc1)) < 0)
                goto error;
        }

        if (host2) {
            host2++;
            if (svc2 && svc2 != host2 &&
                VIR_STRNDUP(source->data.udp.bindHost, host2, svc2 - host2) < 0)
                goto error;
        }

        if (svc2) {
            svc2++;
            if (STRNEQ(svc2, "0")) {
                if (VIR_STRDUP(source->data.udp.bindService, svc2) < 0)
                    goto error;
            }
        }
    } else if (STRPREFIX(val, "tcp:") ||
               STRPREFIX(val, "telnet:")) {
        const char *opt, *svc;
        source->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (STRPREFIX(val, "tcp:")) {
            val += strlen("tcp:");
        } else {
            val += strlen("telnet:");
            source->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        }
        svc = strchr(val, ':');
        if (!svc) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot find port number in character device %s"), val);
            goto error;
        }
        opt = strchr(svc, ',');
        if (opt && strstr(opt, "server"))
            source->data.tcp.listen = true;

        if (VIR_STRNDUP(source->data.tcp.host, val, svc - val) < 0)
            goto error;
        svc++;
        if (VIR_STRNDUP(source->data.tcp.service, svc, opt ? opt - svc : -1) < 0)
            goto error;
    } else if (STRPREFIX(val, "unix:")) {
        const char *opt;
        val += strlen("unix:");
        opt = strchr(val, ',');
        source->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        if (VIR_STRNDUP(source->data.nix.path, val, opt ? opt - val : -1) < 0)
            goto error;

    } else if (STRPREFIX(val, "/dev")) {
        source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        if (VIR_STRDUP(source->data.file.path, val) < 0)
            goto error;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown character device syntax %s"), val);
        goto error;
    }

    return 0;

 error:
    return -1;
}


static virCPUDefPtr
qemuInitGuestCPU(virDomainDefPtr dom)
{
    if (!dom->cpu) {
        virCPUDefPtr cpu;

        if (VIR_ALLOC(cpu) < 0)
            return NULL;

        cpu->type = VIR_CPU_TYPE_GUEST;
        cpu->match = VIR_CPU_MATCH_EXACT;
        dom->cpu = cpu;
    }

    return dom->cpu;
}


static int
qemuParseCommandLineCPU(virDomainDefPtr dom,
                        const char *val)
{
    virCPUDefPtr cpu = NULL;
    char **tokens;
    char **hv_tokens = NULL;
    char *model = NULL;
    int ret = -1;
    size_t i;

    if (!(tokens = virStringSplit(val, ",", 0)))
        goto cleanup;

    if (tokens[0] == NULL)
        goto syntax;

    for (i = 0; tokens[i] != NULL; i++) {
        if (*tokens[i] == '\0')
            goto syntax;

        if (i == 0) {
            if (VIR_STRDUP(model, tokens[i]) < 0)
                goto cleanup;

            if (STRNEQ(model, "qemu32") && STRNEQ(model, "qemu64")) {
                if (!(cpu = qemuInitGuestCPU(dom)))
                    goto cleanup;

                cpu->model = model;
                model = NULL;
            }
        } else if (*tokens[i] == '+' || *tokens[i] == '-') {
            const char *feature = tokens[i] + 1; /* '+' or '-' */
            int policy;

            if (*tokens[i] == '+')
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = VIR_CPU_FEATURE_DISABLE;

            if (*feature == '\0')
                goto syntax;

            if (dom->os.arch != VIR_ARCH_X86_64 &&
                dom->os.arch != VIR_ARCH_I686) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("%s platform doesn't support CPU features'"),
                               virArchToString(dom->os.arch));
                goto cleanup;
             }

            if (STREQ(feature, "kvmclock")) {
                bool present = (policy == VIR_CPU_FEATURE_REQUIRE);
                size_t j;

                for (j = 0; j < dom->clock.ntimers; j++) {
                    if (dom->clock.timers[j]->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK)
                        break;
                }

                if (j == dom->clock.ntimers) {
                    virDomainTimerDefPtr timer;
                    if (VIR_ALLOC(timer) < 0 ||
                        VIR_APPEND_ELEMENT_COPY(dom->clock.timers,
                                                dom->clock.ntimers, timer) < 0) {
                        VIR_FREE(timer);
                        goto cleanup;
                    }
                    timer->name = VIR_DOMAIN_TIMER_NAME_KVMCLOCK;
                    timer->present = present;
                    timer->tickpolicy = -1;
                    timer->track = -1;
                    timer->mode = -1;
                } else if (dom->clock.timers[j]->present != -1 &&
                    dom->clock.timers[j]->present != present) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("conflicting occurrences of kvmclock feature"));
                    goto cleanup;
                }
            } else if (STREQ(feature, "kvm_pv_eoi")) {
                if (policy == VIR_CPU_FEATURE_REQUIRE)
                    dom->apic_eoi = VIR_TRISTATE_SWITCH_ON;
                else
                    dom->apic_eoi = VIR_TRISTATE_SWITCH_OFF;
            } else {
                if (!cpu) {
                    if (!(cpu = qemuInitGuestCPU(dom)))
                        goto cleanup;

                    cpu->model = model;
                    model = NULL;
                }

                if (virCPUDefAddFeature(cpu, feature, policy) < 0)
                    goto cleanup;
            }
        } else if (STREQ(tokens[i], "hv_crash")) {
            size_t j;
            for (j = 0; j < dom->npanics; j++) {
                 if (dom->panics[j]->model == VIR_DOMAIN_PANIC_MODEL_HYPERV)
                     break;
            }

            if (j == dom->npanics) {
                virDomainPanicDefPtr panic;
                if (VIR_ALLOC(panic) < 0 ||
                    VIR_APPEND_ELEMENT_COPY(dom->panics,
                                            dom->npanics, panic) < 0) {
                    VIR_FREE(panic);
                    goto cleanup;
                }
                panic->model = VIR_DOMAIN_PANIC_MODEL_HYPERV;
            }
        } else if (STRPREFIX(tokens[i], "hv_")) {
            const char *token = tokens[i] + 3; /* "hv_" */
            const char *feature, *value;
            int f;

            if (*token == '\0')
                goto syntax;

            if (!(hv_tokens = virStringSplit(token, "=", 2)))
                goto cleanup;

            feature = hv_tokens[0];
            value = hv_tokens[1];

            if (*feature == '\0')
                goto syntax;

            dom->features[VIR_DOMAIN_FEATURE_HYPERV] = VIR_TRISTATE_SWITCH_ON;

            if ((f = virDomainHypervTypeFromString(feature)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported HyperV Enlightenment feature "
                                 "'%s'"), feature);
                goto cleanup;
            }

            switch ((virDomainHyperv) f) {
            case VIR_DOMAIN_HYPERV_RELAXED:
            case VIR_DOMAIN_HYPERV_VAPIC:
                if (value) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("HyperV feature '%s' should not "
                                     "have a value"), feature);
                    goto cleanup;
                }
                dom->hyperv_features[f] = VIR_TRISTATE_SWITCH_ON;
                break;

            case VIR_DOMAIN_HYPERV_SPINLOCKS:
                dom->hyperv_features[f] = VIR_TRISTATE_SWITCH_ON;
                if (!value) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("missing HyperV spinlock retry count"));
                    goto cleanup;
                }

                if (virStrToLong_ui(value, NULL, 0, &dom->hyperv_spinlocks) < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("cannot parse HyperV spinlock retry count"));
                    goto cleanup;
                }

                if (dom->hyperv_spinlocks < 0xFFF)
                    dom->hyperv_spinlocks = 0xFFF;
                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
            virStringFreeList(hv_tokens);
            hv_tokens = NULL;
        } else if (STREQ(tokens[i], "kvm=off")) {
             dom->features[VIR_DOMAIN_FEATURE_KVM] = VIR_TRISTATE_SWITCH_ON;
             dom->kvm_features[VIR_DOMAIN_KVM_HIDDEN] = VIR_TRISTATE_SWITCH_ON;
        }
    }

    if (dom->os.arch == VIR_ARCH_X86_64) {
        bool is_32bit = false;
        if (cpu) {
            virCPUDataPtr cpuData = NULL;

            if (cpuEncode(VIR_ARCH_X86_64, cpu, NULL, &cpuData,
                          NULL, NULL, NULL, NULL) < 0)
                goto cleanup;

            is_32bit = (cpuHasFeature(cpuData, "lm") != 1);
            cpuDataFree(cpuData);
        } else if (model) {
            is_32bit = STREQ(model, "qemu32");
        }

        if (is_32bit)
            dom->os.arch = VIR_ARCH_I686;
    }

    ret = 0;

 cleanup:
    VIR_FREE(model);
    virStringFreeList(tokens);
    virStringFreeList(hv_tokens);
    return ret;

 syntax:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("unknown CPU syntax '%s'"), val);
    goto cleanup;
}


static int
qemuParseCommandLineSmp(virDomainDefPtr dom,
                        const char *val)
{
    unsigned int sockets = 0;
    unsigned int cores = 0;
    unsigned int threads = 0;
    unsigned int maxcpus = 0;
    unsigned int vcpus = 0;
    size_t i;
    int nkws;
    char **kws;
    char **vals;
    int n;
    char *end;
    int ret;

    if (qemuParseKeywords(val, &kws, &vals, &nkws, 1) < 0)
        return -1;

    for (i = 0; i < nkws; i++) {
        if (vals[i] == NULL) {
            if (i > 0 ||
                virStrToLong_ui(kws[i], &end, 10, &vcpus) < 0 || *end != '\0')
                goto syntax;
        } else {
            if (virStrToLong_i(vals[i], &end, 10, &n) < 0 || *end != '\0')
                goto syntax;
            if (STREQ(kws[i], "sockets"))
                sockets = n;
            else if (STREQ(kws[i], "cores"))
                cores = n;
            else if (STREQ(kws[i], "threads"))
                threads = n;
            else if (STREQ(kws[i], "maxcpus"))
                maxcpus = n;
            else
                goto syntax;
        }
    }

    if (maxcpus == 0)
        maxcpus = vcpus;

    if (virDomainDefSetVcpusMax(dom, maxcpus) < 0)
        goto error;

    if (virDomainDefSetVcpus(dom, vcpus) < 0)
        goto error;

    if (sockets && cores && threads) {
        virCPUDefPtr cpu;

        if (!(cpu = qemuInitGuestCPU(dom)))
            goto error;
        cpu->sockets = sockets;
        cpu->cores = cores;
        cpu->threads = threads;
    } else if (sockets || cores || threads) {
        goto syntax;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < nkws; i++) {
        VIR_FREE(kws[i]);
        VIR_FREE(vals[i]);
    }
    VIR_FREE(kws);
    VIR_FREE(vals);

    return ret;

 syntax:
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse CPU topology '%s'"), val);
 error:
    ret = -1;
    goto cleanup;
}


static void
qemuParseCommandLineBootDevs(virDomainDefPtr def, const char *str)
{
    int n, b = 0;

    for (n = 0; str[n] && b < VIR_DOMAIN_BOOT_LAST; n++) {
        if (str[n] == 'a')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_FLOPPY;
        else if (str[n] == 'c')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_DISK;
        else if (str[n] == 'd')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_CDROM;
        else if (str[n] == 'n')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_NET;
        else if (str[n] == ',')
            break;
    }
    def->os.nBootDevs = b;
}


/*
 * Analyse the env and argv settings and reconstruct a
 * virDomainDefPtr representing these settings as closely
 * as is practical. This is not an exact science....
 */
static virDomainDefPtr
qemuParseCommandLine(virCapsPtr qemuCaps,
                     virDomainXMLOptionPtr xmlopt,
                     char **progenv,
                     char **progargv,
                     char **pidfile,
                     virDomainChrSourceDefPtr *monConfig,
                     bool *monJSON)
{
    virDomainDefPtr def;
    size_t i;
    bool nographics = false;
    bool fullscreen = false;
    char **list = NULL;
    char *path;
    size_t nnics = 0;
    const char **nics = NULL;
    int video = VIR_DOMAIN_VIDEO_TYPE_CIRRUS;
    int nvirtiodisk = 0;
    qemuDomainCmdlineDefPtr cmd = NULL;
    virDomainDiskDefPtr disk = NULL;
    const char *ceph_args = qemuFindEnv(progenv, "CEPH_ARGS");
    bool have_sdl = false;

    if (pidfile)
        *pidfile = NULL;
    if (monConfig)
        *monConfig = NULL;
    if (monJSON)
        *monJSON = false;

    if (!progargv[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no emulator path found"));
        return NULL;
    }

    if (!(def = virDomainDefNew()))
        goto error;

    /* allocate the cmdlinedef up-front; if it's unused, we'll free it later */
    if (VIR_ALLOC(cmd) < 0)
        goto error;

    if (virUUIDGenerate(def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        goto error;
    }

    def->id = -1;
    def->mem.cur_balloon = 64 * 1024;
    virDomainDefSetMemoryTotal(def, def->mem.cur_balloon);
    if (virDomainDefSetVcpusMax(def, 1) < 0)
        goto error;
    if (virDomainDefSetVcpus(def, 1) < 0)
        goto error;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;

    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->virtType = VIR_DOMAIN_VIRT_QEMU;
    if (VIR_STRDUP(def->emulator, progargv[0]) < 0)
        goto error;

    if (!(path = last_component(def->emulator)))
        goto error;

    def->os.type = VIR_DOMAIN_OSTYPE_HVM;
    if (strstr(path, "kvm")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
    }

    if (def->virtType == VIR_DOMAIN_VIRT_KVM)
        def->os.arch = qemuCaps->host.arch;
    else if (STRPREFIX(path, "qemu-system-"))
        def->os.arch = virArchFromString(path + strlen("qemu-system-"));
    else
        def->os.arch = VIR_ARCH_I686;

    if ((def->os.arch == VIR_ARCH_I686) ||
        (def->os.arch == VIR_ARCH_X86_64))
        def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;

#define WANT_VALUE()                                                   \
    const char *val = progargv[++i];                                   \
    if (!val) {                                                        \
        virReportError(VIR_ERR_INTERNAL_ERROR,                         \
                       _("missing value for %s argument"), arg);       \
        goto error;                                                    \
    }

    /* One initial loop to get list of NICs, so we
     * can correlate them later */
    for (i = 1; progargv[i]; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (STRPREFIX(val, "nic") &&
                VIR_APPEND_ELEMENT(nics, nnics, val) < 0)
                goto error;
        }
    }

    /* Now the real processing loop */
    for (i = 1; progargv[i]; i++) {
        const char *arg = progargv[i];
        bool argRecognized = true;

        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-vnc")) {
            virDomainGraphicsDefPtr vnc;
            char *tmp;
            WANT_VALUE();
            if (VIR_ALLOC(vnc) < 0)
                goto error;
            vnc->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

            if (STRPREFIX(val, "unix:")) {
                /* -vnc unix:/some/big/path */
                if (VIR_STRDUP(vnc->data.vnc.socket, val + 5) < 0) {
                    virDomainGraphicsDefFree(vnc);
                    goto error;
                }
            } else {
                /*
                 * -vnc 127.0.0.1:4
                 * -vnc [2001:1:2:3:4:5:1234:1234]:4
                 * -vnc some.host.name:4
                 */
                char *opts;
                char *port;
                const char *sep = ":";
                if (val[0] == '[')
                    sep = "]:";
                tmp = strstr(val, sep);
                if (!tmp) {
                    virDomainGraphicsDefFree(vnc);
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("missing VNC port number in '%s'"), val);
                    goto error;
                }
                port = tmp + strlen(sep);
                if (virStrToLong_i(port, &opts, 10,
                                   &vnc->data.vnc.port) < 0) {
                    virDomainGraphicsDefFree(vnc);
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot parse VNC port '%s'"), port);
                    goto error;
                }
                if (val[0] == '[')
                    virDomainGraphicsListenSetAddress(vnc, 0,
                                                      val+1, tmp-(val+1), true);
                else
                    virDomainGraphicsListenSetAddress(vnc, 0,
                                                      val, tmp-val, true);
                if (!virDomainGraphicsListenGetAddress(vnc, 0)) {
                    virDomainGraphicsDefFree(vnc);
                    goto error;
                }

                if (*opts == ',') {
                    char *orig_opts;

                    if (VIR_STRDUP(orig_opts, opts + 1) < 0) {
                        virDomainGraphicsDefFree(vnc);
                        goto error;
                    }
                    opts = orig_opts;

                    while (opts && *opts) {
                        char *nextopt = strchr(opts, ',');
                        if (nextopt)
                            *(nextopt++) = '\0';

                        if (STRPREFIX(opts, "websocket")) {
                            char *websocket = opts + strlen("websocket");
                            if (*(websocket++) == '=' &&
                                *websocket) {
                                /* If the websocket continues with
                                 * '=<something>', we'll parse it */
                                if (virStrToLong_i(websocket,
                                                   NULL, 0,
                                                   &vnc->data.vnc.websocket) < 0) {
                                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                                   _("cannot parse VNC "
                                                     "WebSocket port '%s'"),
                                                   websocket);
                                    virDomainGraphicsDefFree(vnc);
                                    VIR_FREE(orig_opts);
                                    goto error;
                                }
                            } else {
                                /* Otherwise, we'll compute the port the same
                                 * way QEMU does, by adding a 5700 to the
                                 * display value. */
                                vnc->data.vnc.websocket =
                                    vnc->data.vnc.port + 5700;
                            }
                        } else if (STRPREFIX(opts, "share=")) {
                            char *sharePolicy = opts + strlen("share=");
                            if (sharePolicy && *sharePolicy) {
                                int policy =
                                    virDomainGraphicsVNCSharePolicyTypeFromString(sharePolicy);

                                if (policy < 0) {
                                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                                   _("unknown vnc display sharing policy '%s'"),
                                                     sharePolicy);
                                    virDomainGraphicsDefFree(vnc);
                                    VIR_FREE(orig_opts);
                                    goto error;
                                } else {
                                    vnc->data.vnc.sharePolicy = policy;
                                }
                            } else {
                                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                               _("missing vnc sharing policy"));
                                virDomainGraphicsDefFree(vnc);
                                VIR_FREE(orig_opts);
                                goto error;
                            }
                        }

                        opts = nextopt;
                    }
                    VIR_FREE(orig_opts);
                }
                vnc->data.vnc.port += 5900;
                vnc->data.vnc.autoport = false;
            }

            if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, vnc) < 0) {
                virDomainGraphicsDefFree(vnc);
                goto error;
            }
        } else if (STREQ(arg, "-sdl")) {
            have_sdl = true;
        } else if (STREQ(arg, "-m")) {
            int mem;
            WANT_VALUE();
            if (virStrToLong_i(val, NULL, 10, &mem) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, \
                               _("cannot parse memory level '%s'"), val);
                goto error;
            }
            virDomainDefSetMemoryTotal(def, mem * 1024);
            def->mem.cur_balloon = mem * 1024;
        } else if (STREQ(arg, "-smp")) {
            WANT_VALUE();
            if (qemuParseCommandLineSmp(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-uuid")) {
            WANT_VALUE();
            if (virUUIDParse(val, def->uuid) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, \
                               _("cannot parse UUID '%s'"), val);
                goto error;
            }
        } else if (STRPREFIX(arg, "-hd") ||
                   STRPREFIX(arg, "-sd") ||
                   STRPREFIX(arg, "-fd") ||
                   STREQ(arg, "-cdrom")) {
            WANT_VALUE();
            if (!(disk = virDomainDiskDefNew(xmlopt)))
                goto error;

            if (STRPREFIX(val, "/dev/")) {
                disk->src->type = VIR_STORAGE_TYPE_BLOCK;
            } else if (STRPREFIX(val, "nbd:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;
            } else if (STRPREFIX(val, "rbd:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_RBD;
                val += strlen("rbd:");
            } else if (STRPREFIX(val, "gluster")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER;
            } else if (STRPREFIX(val, "sheepdog:")) {
                disk->src->type = VIR_STORAGE_TYPE_NETWORK;
                disk->src->protocol = VIR_STORAGE_NET_PROTOCOL_SHEEPDOG;
                val += strlen("sheepdog:");
            } else {
                disk->src->type = VIR_STORAGE_TYPE_FILE;
            }
            if (STREQ(arg, "-cdrom")) {
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                if ((ARCH_IS_PPC64(def->os.arch) &&
                    def->os.machine && STRPREFIX(def->os.machine, "pseries")))
                    disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                if (VIR_STRDUP(disk->dst, "hdc") < 0)
                    goto error;
                disk->src->readonly = true;
            } else {
                if (STRPREFIX(arg, "-fd")) {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                    disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
                } else {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                    if (STRPREFIX(arg, "-hd"))
                        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
                    else
                        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                   if ((ARCH_IS_PPC64(def->os.arch) &&
                       def->os.machine && STRPREFIX(def->os.machine, "pseries")))
                       disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                }
                if (VIR_STRDUP(disk->dst, arg + 1) < 0)
                    goto error;
            }
            if (VIR_STRDUP(disk->src->path, val) < 0)
                goto error;

            if (disk->src->type == VIR_STORAGE_TYPE_NETWORK) {
                char *port;

                switch ((virStorageNetProtocol) disk->src->protocol) {
                case VIR_STORAGE_NET_PROTOCOL_NBD:
                    if (qemuParseNBDString(disk) < 0)
                        goto error;
                    break;
                case VIR_STORAGE_NET_PROTOCOL_RBD:
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!ceph_args && qemuParseRBDString(disk) < 0)
                        goto error;
                    break;
                case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
                    /* disk->src must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(disk->src->path, ':');
                    if (port) {
                        char *vdi;

                        *port++ = '\0';
                        vdi = strchr(port, ':');
                        if (!vdi) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse sheepdog filename '%s'"), val);
                            goto error;
                        }
                        *vdi++ = '\0';
                        if (VIR_ALLOC(disk->src->hosts) < 0)
                            goto error;
                        disk->src->nhosts = 1;
                        disk->src->hosts->name = disk->src->path;
                        if (VIR_STRDUP(disk->src->hosts->port, port) < 0)
                            goto error;
                        if (VIR_STRDUP(disk->src->path, vdi) < 0)
                            goto error;
                    }
                    break;
                case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
                    if (qemuParseGlusterString(disk) < 0)
                        goto error;

                    break;
                case VIR_STORAGE_NET_PROTOCOL_ISCSI:
                    if (qemuParseISCSIString(disk) < 0)
                        goto error;

                    break;
                case VIR_STORAGE_NET_PROTOCOL_HTTP:
                case VIR_STORAGE_NET_PROTOCOL_HTTPS:
                case VIR_STORAGE_NET_PROTOCOL_FTP:
                case VIR_STORAGE_NET_PROTOCOL_FTPS:
                case VIR_STORAGE_NET_PROTOCOL_TFTP:
                case VIR_STORAGE_NET_PROTOCOL_LAST:
                case VIR_STORAGE_NET_PROTOCOL_NONE:
                    /* ignored for now */
                    break;
                }
            }

            if (virDomainDiskDefAssignAddress(xmlopt, disk, def) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot assign address for device name '%s'"),
                               disk->dst);
                goto error;
            }

            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto error;
        } else if (STREQ(arg, "-no-acpi")) {
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ABSENT;
        } else if (STREQ(arg, "-no-reboot")) {
            def->onReboot = VIR_DOMAIN_LIFECYCLE_DESTROY;
        } else if (STREQ(arg, "-no-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_QEMU;
        } else if (STREQ(arg, "-enable-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_KVM;
        } else if (STREQ(arg, "-nographic")) {
            nographics = true;
        } else if (STREQ(arg, "-full-screen")) {
            fullscreen = true;
        } else if (STREQ(arg, "-localtime")) {
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
        } else if (STREQ(arg, "-kernel")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.kernel, val) < 0)
                goto error;
        } else if (STREQ(arg, "-bios")) {
            WANT_VALUE();
            if (VIR_ALLOC(def->os.loader) < 0 ||
                VIR_STRDUP(def->os.loader->path, val) < 0)
                goto error;
        } else if (STREQ(arg, "-initrd")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.initrd, val) < 0)
                goto error;
        } else if (STREQ(arg, "-append")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.cmdline, val) < 0)
                goto error;
        } else if (STREQ(arg, "-dtb")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.dtb, val) < 0)
                goto error;
        } else if (STREQ(arg, "-boot")) {
            const char *token = NULL;
            WANT_VALUE();

            if (!strchr(val, ',')) {
                qemuParseCommandLineBootDevs(def, val);
            } else {
                token = val;
                while (token && *token) {
                    if (STRPREFIX(token, "order=")) {
                        token += strlen("order=");
                        qemuParseCommandLineBootDevs(def, token);
                    } else if (STRPREFIX(token, "menu=on")) {
                        def->os.bootmenu = 1;
                    } else if (STRPREFIX(token, "reboot-timeout=")) {
                        int num;
                        char *endptr;
                        if (virStrToLong_i(token + strlen("reboot-timeout="),
                                           &endptr, 10, &num) < 0 ||
                            (*endptr != '\0' && endptr != strchr(token, ','))) {
                            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                           _("cannot parse reboot-timeout value"));
                            goto error;
                        }
                        if (num > 65535)
                            num = 65535;
                        else if (num < -1)
                            num = -1;
                        def->os.bios.rt_delay = num;
                        def->os.bios.rt_set = true;
                    }
                    token = strchr(token, ',');
                    /* This incrementation has to be done here in order to make it
                     * possible to pass the token pointer properly into the loop */
                    if (token)
                        token++;
                }
            }
        } else if (STREQ(arg, "-name")) {
            char *process;
            WANT_VALUE();
            process = strstr(val, ",process=");
            if (process == NULL) {
                if (VIR_STRDUP(def->name, val) < 0)
                    goto error;
            } else {
                if (VIR_STRNDUP(def->name, val, process - val) < 0)
                    goto error;
            }
            if (STREQ(def->name, ""))
                VIR_FREE(def->name);
        } else if (STREQ(arg, "-M") ||
                   STREQ(arg, "-machine")) {
            char *param;
            size_t j = 0;

            /* -machine [type=]name[,prop[=value][,...]]
             * Set os.machine only if first parameter lacks '=' or
             * contains explicit type='...' */
            WANT_VALUE();
            if (!(list = virStringSplit(val, ",", 0)))
                goto error;
            param = list[0];

            if (STRPREFIX(param, "type="))
                param += strlen("type=");
            if (!strchr(param, '=')) {
                if (VIR_STRDUP(def->os.machine, param) < 0)
                    goto error;
                j++;
            }

            /* handle all remaining "-machine" parameters */
            while ((param = list[j++])) {
                if (STRPREFIX(param, "dump-guest-core=")) {
                    param += strlen("dump-guest-core=");
                    def->mem.dump_core = virTristateSwitchTypeFromString(param);
                    if (def->mem.dump_core <= 0)
                        def->mem.dump_core = VIR_TRISTATE_SWITCH_ABSENT;
                } else if (STRPREFIX(param, "mem-merge=off")) {
                    def->mem.nosharepages = true;
                } else if (STRPREFIX(param, "accel=kvm")) {
                    def->virtType = VIR_DOMAIN_VIRT_KVM;
                    def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
                } else if (STRPREFIX(param, "aes-key-wrap=")) {
                    if (STREQ(arg, "-M")) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("aes-key-wrap is not supported with "
                                         "this QEMU binary"));
                        goto error;
                    }
                    param += strlen("aes-key-wrap=");
                    if (!def->keywrap && VIR_ALLOC(def->keywrap) < 0)
                        goto error;
                    def->keywrap->aes = virTristateSwitchTypeFromString(param);
                    if (def->keywrap->aes < 0)
                        def->keywrap->aes = VIR_TRISTATE_SWITCH_ABSENT;
                } else if (STRPREFIX(param, "dea-key-wrap=")) {
                    if (STREQ(arg, "-M")) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("dea-key-wrap is not supported with "
                                         "this QEMU binary"));
                        goto error;
                    }
                    param += strlen("dea-key-wrap=");
                    if (!def->keywrap && VIR_ALLOC(def->keywrap) < 0)
                        goto error;
                    def->keywrap->dea = virTristateSwitchTypeFromString(param);
                    if (def->keywrap->dea < 0)
                        def->keywrap->dea = VIR_TRISTATE_SWITCH_ABSENT;
                }
            }
            virStringFreeList(list);
            list = NULL;
        } else if (STREQ(arg, "-serial")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;

                if (!(chr = virDomainChrDefNew()))
                    goto error;

                if (qemuParseCommandLineChr(&chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = def->nserials;
                if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-parallel")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;

                if (!(chr = virDomainChrDefNew()))
                    goto error;

                if (qemuParseCommandLineChr(&chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
                chr->target.port = def->nparallels;
                if (VIR_APPEND_ELEMENT(def->parallels, def->nparallels, chr) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-usbdevice")) {
            WANT_VALUE();
            if (STREQ(val, "tablet") ||
                STREQ(val, "mouse") ||
                STREQ(val, "keyboard")) {
                virDomainInputDefPtr input;
                if (VIR_ALLOC(input) < 0)
                    goto error;
                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(val, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else if (STREQ(val, "mouse"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                else
                    input->type = VIR_DOMAIN_INPUT_TYPE_KBD;

                if (VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input) < 0) {
                    virDomainInputDefFree(input);
                    goto error;
                }
            } else if (STRPREFIX(val, "disk:")) {
                if (!(disk = virDomainDiskDefNew(xmlopt)))
                    goto error;
                if (VIR_STRDUP(disk->src->path, val + strlen("disk:")) < 0)
                    goto error;
                if (STRPREFIX(disk->src->path, "/dev/"))
                    disk->src->type = VIR_STORAGE_TYPE_BLOCK;
                else
                    disk->src->type = VIR_STORAGE_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                disk->bus = VIR_DOMAIN_DISK_BUS_USB;
                disk->removable = VIR_TRISTATE_SWITCH_ABSENT;
                if (VIR_STRDUP(disk->dst, "sda") < 0)
                    goto error;
                if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                    goto error;
            } else {
                virDomainHostdevDefPtr hostdev;
                if (!(hostdev = qemuParseCommandLineUSB(val)))
                    goto error;
                if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
                    virDomainHostdevDefFree(hostdev);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (!STRPREFIX(val, "nic") && STRNEQ(val, "none")) {
                virDomainNetDefPtr net;
                if (!(net = qemuParseCommandLineNet(xmlopt, val, nnics, nics)))
                    goto error;
                if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0) {
                    virDomainNetDefFree(net);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-drive")) {
            WANT_VALUE();
            if (!(disk = qemuParseCommandLineDisk(xmlopt, val, def,
                                                  nvirtiodisk,
                                                  ceph_args != NULL)))
                goto error;
            if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
                nvirtiodisk++;
            if (VIR_APPEND_ELEMENT(def->disks, def->ndisks, disk) < 0)
                goto error;
        } else if (STREQ(arg, "-pcidevice")) {
            virDomainHostdevDefPtr hostdev;
            WANT_VALUE();
            if (!(hostdev = qemuParseCommandLinePCI(val)))
                goto error;
            if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
                virDomainHostdevDefFree(hostdev);
                goto error;
            }
        } else if (STREQ(arg, "-soundhw")) {
            const char *start;
            WANT_VALUE();
            start = val;
            while (start) {
                const char *tmp = strchr(start, ',');
                int type = -1;
                if (STRPREFIX(start, "pcspk")) {
                    type = VIR_DOMAIN_SOUND_MODEL_PCSPK;
                } else if (STRPREFIX(start, "sb16")) {
                    type = VIR_DOMAIN_SOUND_MODEL_SB16;
                } else if (STRPREFIX(start, "es1370")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ES1370;
                } else if (STRPREFIX(start, "ac97")) {
                    type = VIR_DOMAIN_SOUND_MODEL_AC97;
                } else if (STRPREFIX(start, "hda")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ICH6;
                }

                if (type != -1) {
                    virDomainSoundDefPtr snd;
                    if (VIR_ALLOC(snd) < 0)
                        goto error;
                    snd->model = type;
                    if (VIR_APPEND_ELEMENT(def->sounds, def->nsounds, snd) < 0) {
                        VIR_FREE(snd);
                        goto error;
                    }
                }

                start = tmp ? tmp + 1 : NULL;
            }
        } else if (STREQ(arg, "-watchdog")) {
            WANT_VALUE();
            int model = virDomainWatchdogModelTypeFromString(val);

            if (model != -1) {
                virDomainWatchdogDefPtr wd;
                if (VIR_ALLOC(wd) < 0)
                    goto error;
                wd->model = model;
                wd->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;
                def->watchdog = wd;
            }
        } else if (STREQ(arg, "-watchdog-action") && def->watchdog) {
            WANT_VALUE();
            int action = virDomainWatchdogActionTypeFromString(val);

            if (action != -1)
                def->watchdog->action = action;
        } else if (STREQ(arg, "-bootloader")) {
            WANT_VALUE();
            if (VIR_STRDUP(def->os.bootloader, val) < 0)
                goto error;
        } else if (STREQ(arg, "-vmwarevga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VMVGA;
        } else if (STREQ(arg, "-std-vga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VGA;
        } else if (STREQ(arg, "-vga")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                video = qemuVideoTypeFromString(val);
                if (video < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unknown video adapter type '%s'"), val);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-cpu")) {
            WANT_VALUE();
            if (qemuParseCommandLineCPU(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-domid")) {
            WANT_VALUE();
            /* ignore, generted on the fly */
        } else if (STREQ(arg, "-usb")) {
            virDomainControllerDefPtr ctldef;
            if (VIR_ALLOC(ctldef) < 0)
                goto error;
            ctldef->type = VIR_DOMAIN_CONTROLLER_TYPE_USB;
            ctldef->idx = 0;
            ctldef->model = -1;
            if (virDomainControllerInsert(def, ctldef) < 0) {
                VIR_FREE(ctldef);
                goto error;
            }
        } else if (STREQ(arg, "-pidfile")) {
            WANT_VALUE();
            if (pidfile)
                if (VIR_STRDUP(*pidfile, val) < 0)
                    goto error;
        } else if (STREQ(arg, "-incoming")) {
            WANT_VALUE();
            /* ignore, used via restore/migrate APIs */
        } else if (STREQ(arg, "-monitor")) {
            WANT_VALUE();
            if (monConfig) {
                virDomainChrSourceDefPtr chr;

                if (VIR_ALLOC(chr) < 0)
                    goto error;

                if (qemuParseCommandLineChr(chr, val) < 0) {
                    virDomainChrSourceDefFree(chr);
                    goto error;
                }

                *monConfig = chr;
            }
        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s3=")) {
            /* We want to parse only the known "-global" parameters,
             * so the ones that we don't know are still added to the
             * namespace */
            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s3=");
            if (STREQ(val, "0")) {
                def->pm.s3 = VIR_TRISTATE_BOOL_YES;
            } else if (STREQ(val, "1")) {
                def->pm.s3 = VIR_TRISTATE_BOOL_NO;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s3 parameter: "
                                 "'%s'"), val);
                goto error;
            }

        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s4=")) {

            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s4=");
            if (STREQ(val, "0")) {
                def->pm.s4 = VIR_TRISTATE_BOOL_YES;
            } else if (STREQ(val, "1")) {
                def->pm.s4 = VIR_TRISTATE_BOOL_NO;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s4 parameter: "
                                 "'%s'"), val);
                goto error;
            }

        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "spapr-nvram.reg=")) {
            WANT_VALUE();

            if (VIR_ALLOC(def->nvram) < 0)
                goto error;

            def->nvram->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
            def->nvram->info.addr.spaprvio.has_reg = true;

            val += strlen("spapr-nvram.reg=");
            if (virStrToLong_ull(val, NULL, 16,
                                 &def->nvram->info.addr.spaprvio.reg) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse nvram's address '%s'"), val);
                goto error;
            }
        } else if (STREQ(arg, "-S") ||
                   STREQ(arg, "-nodefaults") ||
                   STREQ(arg, "-nodefconfig")) {
            /* ignore, always added by libvirt */
        } else if (STREQ(arg, "-device") && progargv[1 + 1]) {
            const char *opts = progargv[i + 1];

            /* NB: we can't do WANT_VALUE until we're sure that we
             * recognize the device, otherwise the !argRecognized
             * logic below will be messed up
             */

            if (STRPREFIX(opts, "virtio-balloon")) {
                WANT_VALUE();
                if (VIR_ALLOC(def->memballoon) < 0)
                    goto error;
                def->memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO;
            } else {
                /* add in new -device's here */

                argRecognized = false;
            }
        } else {
            argRecognized = false;
        }

        if (!argRecognized) {
            char *tmp = NULL;
            /* something we can't yet parse.  Add it to the qemu namespace
             * cmdline/environment advanced options and hope for the best
             */
            VIR_WARN("unknown QEMU argument '%s', adding to the qemu namespace",
                     arg);
            if (VIR_STRDUP(tmp, arg) < 0 ||
                VIR_APPEND_ELEMENT(cmd->args, cmd->num_args, tmp) < 0) {
                VIR_FREE(tmp);
                goto error;
            }
        }
    }

#undef WANT_VALUE
    if (def->ndisks > 0 && ceph_args) {
        char *hosts, *port, *saveptr = NULL, *token;
        virDomainDiskDefPtr first_rbd_disk = NULL;
        for (i = 0; i < def->ndisks; i++) {
            if (def->disks[i]->src->type == VIR_STORAGE_TYPE_NETWORK &&
                def->disks[i]->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
                first_rbd_disk = def->disks[i];
                break;
            }
        }

        if (!first_rbd_disk) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CEPH_ARGS was set without an rbd disk"));
            goto error;
        }

        /* CEPH_ARGS should be: -m host1[:port1][,host2[:port2]]... */
        if (!STRPREFIX(ceph_args, "-m ")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not parse CEPH_ARGS '%s'"), ceph_args);
            goto error;
        }
        if (VIR_STRDUP(hosts, strchr(ceph_args, ' ') + 1) < 0)
            goto error;
        first_rbd_disk->src->nhosts = 0;
        token = strtok_r(hosts, ",", &saveptr);
        while (token != NULL) {
            if (VIR_REALLOC_N(first_rbd_disk->src->hosts,
                              first_rbd_disk->src->nhosts + 1) < 0) {
                VIR_FREE(hosts);
                goto error;
            }
            port = strchr(token, ':');
            if (port) {
                *port++ = '\0';
                if (VIR_STRDUP(port, port) < 0) {
                    VIR_FREE(hosts);
                    goto error;
                }
            }
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].port = port;
            if (VIR_STRDUP(first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].name,
                           token) < 0) {
                VIR_FREE(hosts);
                goto error;
            }
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            first_rbd_disk->src->hosts[first_rbd_disk->src->nhosts].socket = NULL;

            first_rbd_disk->src->nhosts++;
            token = strtok_r(NULL, ",", &saveptr);
        }
        VIR_FREE(hosts);

        if (first_rbd_disk->src->nhosts == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("found no rbd hosts in CEPH_ARGS '%s'"), ceph_args);
            goto error;
        }
    }

    if (!def->os.machine) {
        virCapsDomainDataPtr capsdata;

        if (!(capsdata = virCapabilitiesDomainDataLookup(qemuCaps, def->os.type,
                def->os.arch, def->virtType, NULL, NULL)))
            goto error;

        if (VIR_STRDUP(def->os.machine, capsdata->machinetype) < 0) {
            VIR_FREE(capsdata);
            goto error;
        }
        VIR_FREE(capsdata);
    }

    if (!nographics && (def->ngraphics == 0 || have_sdl)) {
        virDomainGraphicsDefPtr sdl;
        const char *display = qemuFindEnv(progenv, "DISPLAY");
        const char *xauth = qemuFindEnv(progenv, "XAUTHORITY");
        if (VIR_ALLOC(sdl) < 0)
            goto error;
        sdl->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        sdl->data.sdl.fullscreen = fullscreen;
        if (VIR_STRDUP(sdl->data.sdl.display, display) < 0) {
            VIR_FREE(sdl);
            goto error;
        }
        if (VIR_STRDUP(sdl->data.sdl.xauth, xauth) < 0) {
            VIR_FREE(sdl);
            goto error;
        }

        if (VIR_APPEND_ELEMENT(def->graphics, def->ngraphics, sdl) < 0) {
            virDomainGraphicsDefFree(sdl);
            goto error;
        }
    }

    if (def->ngraphics) {
        virDomainVideoDefPtr vid;
        if (VIR_ALLOC(vid) < 0)
            goto error;
        if (def->virtType == VIR_DOMAIN_VIRT_XEN)
            vid->type = VIR_DOMAIN_VIDEO_TYPE_XEN;
        else
            vid->type = video;
        vid->vram = virDomainVideoDefaultRAM(def, vid->type);
        if (vid->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
            vid->ram = virDomainVideoDefaultRAM(def, vid->type);
            vid->vgamem = QEMU_QXL_VGAMEM_DEFAULT;
        } else {
            vid->ram = 0;
            vid->vgamem = 0;
        }
        vid->heads = 1;

        if (VIR_APPEND_ELEMENT(def->videos, def->nvideos, vid) < 0) {
            virDomainVideoDefFree(vid);
            goto error;
        }
    }

    /*
     * having a balloon is the default, define one with type="none" to avoid it
     */
    if (!def->memballoon) {
        virDomainMemballoonDefPtr memballoon;
        if (VIR_ALLOC(memballoon) < 0)
            goto error;
        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_NONE;

        def->memballoon = memballoon;
    }

    VIR_FREE(nics);

    if (virDomainDefAddImplicitControllers(def) < 0)
        goto error;

    if (virDomainDefPostParse(def, qemuCaps, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt) < 0)
        goto error;

    if (cmd->num_args || cmd->num_env) {
        def->ns = *virDomainXMLOptionGetNamespace(xmlopt);
        def->namespaceData = cmd;
    }
    else
        qemuDomainCmdlineDefFree(cmd);

    return def;

 error:
    virDomainDiskDefFree(disk);
    qemuDomainCmdlineDefFree(cmd);
    virDomainDefFree(def);
    virStringFreeList(list);
    VIR_FREE(nics);
    if (monConfig) {
        virDomainChrSourceDefFree(*monConfig);
        *monConfig = NULL;
    }
    if (pidfile)
        VIR_FREE(*pidfile);
    return NULL;
}


virDomainDefPtr qemuParseCommandLineString(virCapsPtr qemuCaps,
                                           virDomainXMLOptionPtr xmlopt,
                                           const char *args,
                                           char **pidfile,
                                           virDomainChrSourceDefPtr *monConfig,
                                           bool *monJSON)
{
    char **progenv = NULL;
    char **progargv = NULL;
    virDomainDefPtr def = NULL;

    if (qemuStringToArgvEnv(args, &progenv, &progargv) < 0)
        goto cleanup;

    def = qemuParseCommandLine(qemuCaps, xmlopt, progenv, progargv,
                               pidfile, monConfig, monJSON);

 cleanup:
    virStringFreeList(progargv);
    virStringFreeList(progenv);

    return def;
}


static int qemuParseProcFileStrings(int pid_value,
                                    const char *name,
                                    char ***list)
{
    char *path = NULL;
    int ret = -1;
    char *data = NULL;
    ssize_t len;
    char *tmp;
    size_t nstr = 0;
    char **str = NULL;

    if (virAsprintf(&path, "/proc/%d/%s", pid_value, name) < 0)
        goto cleanup;

    if ((len = virFileReadAll(path, 1024*128, &data)) < 0)
        goto cleanup;

    tmp = data;
    while (tmp < (data + len)) {
        if (VIR_EXPAND_N(str, nstr, 1) < 0)
            goto cleanup;

        if (VIR_STRDUP(str[nstr-1], tmp) < 0)
            goto cleanup;
        /* Skip arg */
        tmp += strlen(tmp);
        /* Skip \0 separator */
        tmp++;
    }

    if (VIR_EXPAND_N(str, nstr, 1) < 0)
        goto cleanup;

    str[nstr-1] = NULL;

    ret = nstr-1;
    *list = str;

 cleanup:
    if (ret < 0)
        virStringFreeList(str);
    VIR_FREE(data);
    VIR_FREE(path);
    return ret;
}

virDomainDefPtr qemuParseCommandLinePid(virCapsPtr qemuCaps,
                                        virDomainXMLOptionPtr xmlopt,
                                        pid_t pid,
                                        char **pidfile,
                                        virDomainChrSourceDefPtr *monConfig,
                                        bool *monJSON)
{
    virDomainDefPtr def = NULL;
    char **progargv = NULL;
    char **progenv = NULL;
    char *exepath = NULL;
    char *emulator;

    /* The parser requires /proc/pid, which only exists on platforms
     * like Linux where pid_t fits in int.  */
    if ((int) pid != pid ||
        qemuParseProcFileStrings(pid, "cmdline", &progargv) < 0 ||
        qemuParseProcFileStrings(pid, "environ", &progenv) < 0)
        goto cleanup;

    if (!(def = qemuParseCommandLine(qemuCaps, xmlopt, progenv, progargv,
                                     pidfile, monConfig, monJSON)))
        goto cleanup;

    if (virAsprintf(&exepath, "/proc/%d/exe", (int) pid) < 0)
        goto cleanup;

    if (virFileResolveLink(exepath, &emulator) < 0) {
        virReportSystemError(errno,
                             _("Unable to resolve %s for pid %u"),
                             exepath, (int) pid);
        goto cleanup;
    }
    VIR_FREE(def->emulator);
    def->emulator = emulator;

 cleanup:
    VIR_FREE(exepath);
    virStringFreeList(progargv);
    virStringFreeList(progenv);
    return def;
}
