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
#include "qemu_interface.h"
#include "qemu_alias.h"
#include "cpu/cpu.h"
#include "dirname.h"
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
#include "virgic.h"
#if defined(__linux__)
# include <linux/capability.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_command");

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
        if ((qemuDomainSetSCSIControllerModel(def, qemuCaps,
                                              &controllerModel)) < 0)
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
        if ((qemuDomainSetSCSIControllerModel(domainDef, qemuCaps, &model)) < 0)
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
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
            virBufferAddLit(&buf, "mptsas1068");
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

    if (qemuDomainSetSCSIControllerModel(def, qemuCaps, &model) < 0)
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
qemuBuildChrChardevStr(const virDomainChrSourceDef *dev,
                       const char *alias,
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
qemuBuildChrArgStr(const virDomainChrSourceDef *dev,
                   const char *prefix)
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


static int
qemuBuildMonitorCommandLine(virCommandPtr cmd,
                            virQEMUCapsPtr qemuCaps,
                            const virDomainChrSourceDef *monitor_chr,
                            bool monitor_json)
{
    char *chrdev;

    if (!monitor_chr)
        return 0;

    /* Use -chardev if it's available */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CHARDEV)) {

        virCommandAddArg(cmd, "-chardev");
        if (!(chrdev = qemuBuildChrChardevStr(monitor_chr, "monitor",
                                              qemuCaps)))
            return -1;
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
            return -1;
        virCommandAddArg(cmd, chrdev);
        VIR_FREE(chrdev);
    }

    return 0;
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


static int
qemuBuildSmbiosCommandLine(virCommandPtr cmd,
                           virQEMUDriverPtr driver,
                           const virDomainDef *def,
                           virQEMUCapsPtr qemuCaps)
{
    size_t i;
    virSysinfoDefPtr source = NULL;
    bool skip_uuid = false;

    if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_NONE ||
        def->os.smbios_mode == VIR_DOMAIN_SMBIOS_EMULATE)
        return 0;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMBIOS_TYPE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("the QEMU binary %s does not support smbios settings"),
                       def->emulator);
        return -1;
    }

    /* should we really error out or just warn in those cases ? */
    if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
        if (driver->hostsysinfo == NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Host SMBIOS information is not available"));
            return -1;
        }
        source = driver->hostsysinfo;
        /* Host and guest uuid must differ, by definition of UUID. */
        skip_uuid = true;
    } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_SYSINFO) {
        if (def->sysinfo == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Domain '%s' sysinfo are not available"),
                           def->name);
            return -1;
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
            return -1;
        }

        for (i = 0; i < source->nbaseBoard; i++) {
            if (!(smbioscmd =
                  qemuBuildSmbiosBaseBoardStr(source->baseBoard + i)))
                return -1;

            virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
            VIR_FREE(smbioscmd);
        }
    }

    return 0;
}


static int
qemuBuildSgaCommandLine(virCommandPtr cmd,
                        const virDomainDef *def,
                        virQEMUCapsPtr qemuCaps)
{
    /* Serial graphics adapter */
    if (def->os.bios.useserial == VIR_TRISTATE_BOOL_YES) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support -device"));
            return -1;
        }
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SGA)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support SGA"));
            return -1;
        }
        if (!def->nserials) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("need at least one serial port to use SGA"));
            return -1;
        }
        virCommandAddArgList(cmd, "-device", "sga", NULL);
    }

    return 0;
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
qemuBuildCpuCommandLine(virCommandPtr cmd,
                        virQEMUDriverPtr driver,
                        const virDomainDef *def,
                        virQEMUCapsPtr qemuCaps,
                        bool migrating)
{
    virArch hostarch = virArchFromHost();
    char *cpu = NULL;
    bool hasHwVirt = false;
    const char *default_model;
    bool have_cpu = false;
    int ret = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    if (def->os.arch == VIR_ARCH_I686)
        default_model = "qemu32";
    else
        default_model = "qemu64";

    if (def->cpu &&
        (def->cpu->mode != VIR_CPU_MODE_CUSTOM || def->cpu->model)) {
        if (qemuBuildCpuModelArgStr(driver, def, &buf, qemuCaps,
                                    &hasHwVirt, migrating) < 0)
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
              strstr(def->emulator, "kvm")) ||
             strstr(def->emulator, "x86_64"))) {
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
        if (def->features[VIR_DOMAIN_FEATURE_PVSPINLOCK] ==
            VIR_TRISTATE_SWITCH_ON)
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

    cpu = virBufferContentAndReset(&buf);

    if (cpu) {
        virCommandAddArgList(cmd, "-cpu", cpu, NULL);

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NESTING) && hasHwVirt)
            virCommandAddArg(cmd, "-enable-nesting");
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpu);
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
qemuBuildMachineCommandLine(virCommandPtr cmd,
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
            if (def->gic_version != VIR_GIC_VERSION_NONE) {
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

                /* The default GIC version should not be specified on the
                 * QEMU commandline for backwards compatibility reasons */
                if (def->gic_version != VIR_GIC_VERSION_DEFAULT) {
                    if (!virQEMUCapsGet(qemuCaps,
                                        QEMU_CAPS_MACH_VIRT_GIC_VERSION)) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("gic-version option is not available "
                                         "with this QEMU binary"));
                        virBufferFreeAndReset(&buf);
                        return -1;
                    }

                    virBufferAsprintf(&buf, ",gic-version=%s",
                                      virGICVersionTypeToString(def->gic_version));
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

static int
qemuBuildSmpCommandLine(virCommandPtr cmd,
                        const virDomainDef *def,
                        virQEMUCapsPtr qemuCaps)
{
    char *smp;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virCommandAddArg(cmd, "-smp");

    virBufferAsprintf(&buf, "%u", virDomainDefGetVcpus(def));

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SMP_TOPOLOGY)) {
        if (virDomainDefHasVcpusOffline(def))
            virBufferAsprintf(&buf, ",maxcpus=%u",
                              virDomainDefGetVcpusMax(def));
        /* sockets, cores, and threads are either all zero
         * or all non-zero, thus checking one of them is enough */
        if (def->cpu && def->cpu->sockets) {
            virBufferAsprintf(&buf, ",sockets=%u", def->cpu->sockets);
            virBufferAsprintf(&buf, ",cores=%u", def->cpu->cores);
            virBufferAsprintf(&buf, ",threads=%u", def->cpu->threads);
        } else {
            virBufferAsprintf(&buf, ",sockets=%u",
                              virDomainDefGetVcpusMax(def));
            virBufferAsprintf(&buf, ",cores=%u", 1);
            virBufferAsprintf(&buf, ",threads=%u", 1);
        }
    } else if (virDomainDefHasVcpusOffline(def)) {
        virBufferFreeAndReset(&buf);
        /* FIXME - consider hot-unplugging cpus after boot for older qemu */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("setting current vcpu count less than maximum is "
                         "not supported with this QEMU binary"));
        return -1;
    }

    if (virBufferCheckError(&buf) < 0)
        return -1;

    smp = virBufferContentAndReset(&buf);
    virCommandAddArg(cmd, smp);
    VIR_FREE(smp);

    return 0;
}


static int
qemuBuildMemPathStr(virQEMUDriverConfigPtr cfg,
                    const virDomainDef *def,
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
qemuBuildMemCommandLine(virCommandPtr cmd,
                        virQEMUDriverConfigPtr cfg,
                        const virDomainDef *def,
                        virQEMUCapsPtr qemuCaps)
{
    if (qemuDomainDefValidateMemoryHotplug(def, qemuCaps, NULL) < 0)
        return -1;

    virCommandAddArg(cmd, "-m");

    if (virDomainDefHasMemoryHotplug(def)) {
        /* Use the 'k' suffix to let qemu handle the units */
        virCommandAddArgFormat(cmd, "size=%lluk,slots=%u,maxmem=%lluk",
                               virDomainDefGetMemoryInitial(def),
                               def->mem.memory_slots,
                               def->mem.max_memory);

    } else {
       virCommandAddArgFormat(cmd, "%llu",
                              virDomainDefGetMemoryInitial(def) / 1024);
    }

    /*
     * Add '-mem-path' (and '-mem-prealloc') parameter here only if
     * there is no numa node specified.
     */
    if (!virDomainNumaGetNodeCount(def->numa) &&
        qemuBuildMemPathStr(cfg, def, qemuCaps, cmd) < 0)
        return -1;

    if (def->mem.locked && !virQEMUCapsGet(qemuCaps, QEMU_CAPS_MLOCK)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("memory locking not supported by QEMU binary"));
        return -1;
    }
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MLOCK)) {
        virCommandAddArg(cmd, "-realtime");
        virCommandAddArgFormat(cmd, "mlock=%s",
                               def->mem.locked ? "on" : "off");
    }

    return 0;
}


static int
qemuBuildIOThreadCommandLine(virCommandPtr cmd,
                             const virDomainDef *def,
                             virQEMUCapsPtr qemuCaps)
{
    size_t i;

    if (def->niothreadids == 0)
        return 0;

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_IOTHREAD)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOThreads not supported for this QEMU"));
        return -1;
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
qemuBuildNumaCommandLine(virCommandPtr cmd,
                         virQEMUDriverConfigPtr cfg,
                         virDomainDefPtr def,
                         virQEMUCapsPtr qemuCaps,
                         virBitmapPtr nodeset)
{
    size_t i;

    if (virDomainNumaGetNodeCount(def->numa) &&
        qemuBuildNumaArgStr(cfg, def, cmd, qemuCaps, nodeset) < 0)
        return -1;

    /* memory hotplug requires NUMA to be enabled - we already checked
     * that memory devices are present only when NUMA is */
    for (i = 0; i < def->nmems; i++) {
        char *backStr;
        char *dimmStr;

        if (!(backStr = qemuBuildMemoryDimmBackendStr(def->mems[i], def,
                                                      qemuCaps, cfg)))
            return -1;

        if (!(dimmStr = qemuBuildMemoryDeviceStr(def->mems[i]))) {
            VIR_FREE(backStr);
            return -1;
        }

        virCommandAddArgList(cmd, "-object", backStr, "-device", dimmStr, NULL);

        VIR_FREE(backStr);
        VIR_FREE(dimmStr);
    }

    return 0;
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

        if (qemuInterfaceBridgeConnect(def, driver, net,
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

        if (qemuInterfaceDirectConnect(def, driver, net,
                                       tapfd, tapfdSize, vmop) < 0)
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

        if (qemuInterfaceOpenVhostNet(def, net, qemuCaps,
                                      vhostfd, &vhostfdSize) < 0)
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


static char *
qemuBuildTPMDevStr(const virDomainDef *def,
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


static char *
qemuBuildTPMBackendStr(const virDomainDef *def,
                       virCommandPtr cmd,
                       virQEMUCapsPtr qemuCaps,
                       const char *emulator,
                       int *tpmfd,
                       int *cancelfd)
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


/**
 * qemuBuildCommandLineValidate:
 *
 * Prior to taking the plunge and building a long command line only
 * to find some configuration option isn't valid, let's do a couple
 * of checks and fail early.
 *
 * Returns 0 on success, returns -1 and messages what the issue is.
 */
static int
qemuBuildCommandLineValidate(virQEMUDriverPtr driver,
                             const virDomainDef *def)
{
    size_t i;
    int sdl = 0;
    int vnc = 0;
    int spice = 0;

    if (!virQEMUDriverIsPrivileged(driver)) {
        /* If we have no cgroups then we can have no tunings that
         * require them */

        if (virMemoryLimitIsSet(def->mem.hard_limit) ||
            virMemoryLimitIsSet(def->mem.soft_limit) ||
            def->mem.min_guarantee ||
            virMemoryLimitIsSet(def->mem.swap_hard_limit)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Memory tuning is not available in session mode"));
            return -1;
        }

        if (def->blkio.weight) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Block I/O tuning is not available in session mode"));
            return -1;
        }

        if (def->cputune.sharesSpecified || def->cputune.period ||
            def->cputune.quota || def->cputune.emulator_period ||
            def->cputune.emulator_quota) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU tuning is not available in session mode"));
            return -1;
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

    if (sdl > 1 || vnc > 1 || spice > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 1 graphics device of each type "
                         "(sdl, vnc, spice) is supported"));
        return -1;
    }

    if (def->virtType == VIR_DOMAIN_VIRT_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_XEN ||
        def->os.type == VIR_DOMAIN_OSTYPE_LINUX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu emulator '%s' does not support xen"),
                       def->emulator);
        return -1;
    }

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (disk->src->driverName != NULL &&
            STRNEQ(disk->src->driverName, "qemu")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported driver name '%s' for disk '%s'"),
                           disk->src->driverName, disk->src->path);
            return -1;
        }
    }

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
    char uuid[VIR_UUID_STRING_BUFLEN];
    bool havespice = false;
    int last_good_net = -1;
    virCommandPtr cmd = NULL;
    bool allowReboot = true;
    bool emitBootindex = false;
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

    if (qemuBuildCommandLineValidate(driver, def) < 0)
        goto error;

    /*
     * do not use boot=on for drives when not using KVM since this
     * is not supported at all in upstream QEmu.
     */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM) &&
        (def->virtType == VIR_DOMAIN_VIRT_QEMU))
        virQEMUCapsClear(qemuCaps, QEMU_CAPS_DRIVE_BOOT);

    cmd = virCommandNew(def->emulator);

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

    if (qemuBuildMachineCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildCpuCommandLine(cmd, driver, def, qemuCaps, !!migrateURI) < 0)
        goto error;

    if (qemuBuildDomainLoaderCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (!migrateURI && !snapshot && qemuDomainAlignMemorySizes(def) < 0)
        goto error;

    if (qemuBuildMemCommandLine(cmd, cfg, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildSmpCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildIOThreadCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildNumaCommandLine(cmd, cfg, def, qemuCaps, nodeset) < 0)
        goto error;

    virUUIDFormat(def->uuid, uuid);
    virCommandAddArgList(cmd, "-uuid", uuid, NULL);

    if (qemuBuildSmbiosCommandLine(cmd, driver, def, qemuCaps) < 0)
        goto error;

    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (!def->ngraphics) {
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

    if (qemuBuildSgaCommandLine(cmd, def, qemuCaps) < 0)
        goto error;

    if (qemuBuildMonitorCommandLine(cmd, qemuCaps, monitor_chr,
                                    monitor_json) < 0)
        goto error;

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

    if (def->nserials) {
        for (i = 0; i < def->ngraphics; i++) {
            if (def->graphics[i]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
                havespice = true;
                break;
            }
        }
    }

    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr serial = def->serials[i];
        char *devstr;

        if (serial->source.type == VIR_DOMAIN_CHR_TYPE_SPICEPORT && !havespice)
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
        if (qemuBuildTPMCommandLine(def, cmd, qemuCaps, def->emulator) < 0)
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
