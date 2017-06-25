/*
 * xen_sxpr.c: Xen SEXPR parsing functions
 *
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2005 Anthony Liguori <aliguori@us.ibm.com>
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
 * Author: Anthony Liguori <aliguori@us.ibm.com>
 * Author: Daniel Veillard <veillard@redhat.com>
 * Author: Markus Groß <gross@univention.de>
 */

#include <config.h>

#include <regex.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "verify.h"
#include "viruuid.h"
#include "virlog.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_sxpr.h"
#include "virstoragefile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_SEXPR

VIR_LOG_INIT("xenconfig.xen_sxpr");

/* Get a domain id from a S-expression string */
int xenGetDomIdFromSxprString(const char *sexpr, int *id)
{
    struct sexpr *root = string2sexpr(sexpr);
    int ret;

    *id = -1;

    if (!root)
        return -1;

    ret = xenGetDomIdFromSxpr(root, id);
    sexpr_free(root);
    return ret;
}

/* Get a domain id from a S-expression */
int xenGetDomIdFromSxpr(const struct sexpr *root, int *id)
{
    const char * tmp = sexpr_node(root, "domain/domid");

    *id = tmp ? sexpr_int(root, "domain/domid") : -1;
    return 0;
}

/*****************************************************************
 ******
 ****** Parsing of S-Expression into virDomainDef objects
 ******
 *****************************************************************/

/**
 * xenParseSxprOS:
 * @node: the root of the parsed S-Expression
 * @def: the domain config
 * @hvm: true or 1 if node contains HVM S-Expression
 *
 * Parse the xend sexp for description of os and append it to buf.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
xenParseSxprOS(const struct sexpr *node,
               virDomainDefPtr def,
               int hvm)
{
    if (hvm) {
        if (VIR_ALLOC(def->os.loader) < 0)
            goto error;
        if (sexpr_node_copy(node, "domain/image/hvm/loader", &def->os.loader->path) < 0)
            goto error;
        if (def->os.loader->path == NULL) {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.loader->path) < 0)
                goto error;

            if (def->os.loader->path == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("domain information incomplete, missing HVM loader"));
                return -1;
            }
        } else {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.kernel) < 0)
                goto error;
            if (sexpr_node_copy(node, "domain/image/hvm/ramdisk", &def->os.initrd) < 0)
                goto error;
            if (sexpr_node_copy(node, "domain/image/hvm/args", &def->os.cmdline) < 0)
                goto error;
            if (sexpr_node_copy(node, "domain/image/hvm/root", &def->os.root) < 0)
                goto error;
        }
    } else {
        if (sexpr_node_copy(node, "domain/image/linux/kernel", &def->os.kernel) < 0)
            goto error;
        if (sexpr_node_copy(node, "domain/image/linux/ramdisk", &def->os.initrd) < 0)
            goto error;
        if (sexpr_node_copy(node, "domain/image/linux/args", &def->os.cmdline) < 0)
            goto error;
        if (sexpr_node_copy(node, "domain/image/linux/root", &def->os.root) < 0)
            goto error;
    }

    /* If HVM kenrel == loader, then old xend, so kill off kernel */
    if (hvm &&
        def->os.kernel &&
        STREQ(def->os.kernel, def->os.loader->path)) {
        VIR_FREE(def->os.kernel);
    }
    /* Drop kernel argument that has no value */
    if (hvm &&
        def->os.kernel && *def->os.kernel == '\0' &&
        def->os.loader) {
        VIR_FREE(def->os.kernel);
    }

    if (!def->os.kernel &&
        hvm) {
        const char *boot = sexpr_node(node, "domain/image/hvm/boot");
        if ((boot != NULL) && (boot[0] != 0)) {
            while (*boot &&
                   def->os.nBootDevs < VIR_DOMAIN_BOOT_LAST) {
                if (*boot == 'a')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_FLOPPY;
                else if (*boot == 'c')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_DISK;
                else if (*boot == 'd')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_CDROM;
                else if (*boot == 'n')
                    def->os.bootDevs[def->os.nBootDevs++] = VIR_DOMAIN_BOOT_NET;
                boot++;
            }
        }
    }

    if (!hvm &&
        !def->os.kernel &&
        !def->os.bootloader) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("domain information incomplete, missing kernel & bootloader"));
        return -1;
    }

    return 0;

 error:
    return -1;
}


/**
  * xenParseSxprChar:
  * @value: A string describing a character device.
  * @tty: the console pty path
  *
  * Parse the xend S-expression for description of a character device.
  *
  * Returns a character device object or NULL in case of failure.
  */
virDomainChrDefPtr
xenParseSxprChar(const char *value,
                 const char *tty)
{
    const char *prefix;
    char *tmp;
    virDomainChrDefPtr def;

    if (!(def = virDomainChrDefNew(NULL)))
        return NULL;

    prefix = value;

    if (value[0] == '/') {
        def->source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        if (VIR_STRDUP(def->source->data.file.path, value) < 0)
            goto error;
    } else {
        if ((tmp = strchr(value, ':')) != NULL) {
            *tmp = '\0';
            value = tmp + 1;
        }

        if (STRPREFIX(prefix, "telnet")) {
            def->source->type = VIR_DOMAIN_CHR_TYPE_TCP;
            def->source->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else {
            if ((def->source->type = virDomainChrTypeFromString(prefix)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown chr device type '%s'"), prefix);
                goto error;
            }
        }
    }

    switch (def->source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (VIR_STRDUP(def->source->data.file.path, tty) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (VIR_STRDUP(def->source->data.file.path, value) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2;

        if (offset == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            VIR_STRNDUP(def->source->data.tcp.host, value, offset - value) < 0)
            goto error;

        offset2 = strchr(offset, ',');
        offset++;
        if (VIR_STRNDUP(def->source->data.tcp.service, offset,
                        offset2 ? offset2 - offset : -1) < 0)
            goto error;

        if (offset2 && strstr(offset2, ",server"))
            def->source->data.tcp.listen = true;
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            VIR_STRNDUP(def->source->data.udp.connectHost, value, offset - value) < 0)
            goto error;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if (VIR_STRNDUP(def->source->data.udp.connectService,
                            offset + 1, offset2 - offset - 1) < 0)
                goto error;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                VIR_STRNDUP(def->source->data.udp.bindHost,
                            offset2 + 1, offset3 - offset2 - 1) < 0)
                goto error;

            if (VIR_STRDUP(def->source->data.udp.bindService, offset3 + 1) < 0)
                goto error;
        } else {
            if (VIR_STRDUP(def->source->data.udp.connectService, offset + 1) < 0)
                goto error;
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (VIR_STRNDUP(def->source->data.nix.path, value,
                        offset ? offset - value : -1) < 0)
            goto error;

        if (offset != NULL &&
            strstr(offset, ",server") != NULL)
            def->source->data.nix.listen = true;
    }
    break;
    }

    return def;

 error:
    virDomainChrDefFree(def);
    return NULL;
}


static const char *vif_bytes_per_sec_re = "^[0-9]+[GMK]?[Bb]/s$";

int
xenParseSxprVifRate(const char *rate, unsigned long long *kbytes_per_sec)
{
    char *trate = NULL;
    char *p;
    regex_t rec;
    int err;
    char *suffix;
    unsigned long long tmp;
    int ret = -1;

    if (VIR_STRDUP(trate, rate) < 0)
        return -1;

    p = strchr(trate, '@');
    if (p != NULL)
        *p = 0;

    err = regcomp(&rec, vif_bytes_per_sec_re, REG_EXTENDED|REG_NOSUB);
    if (err != 0) {
        char error[100];
        regerror(err, &rec, error, sizeof(error));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regular expression '%s': %s"),
                       vif_bytes_per_sec_re, error);
        goto cleanup;
    }

    if (regexec(&rec, trate, 0, NULL, 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid rate '%s' specified"), rate);
        goto cleanup;
    }

    if (virStrToLong_ull(rate, &suffix, 10, &tmp)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse rate '%s'"), rate);
        goto cleanup;
    }

    if (*suffix == 'G')
       tmp *= 1024 * 1024;
    else if (*suffix == 'M')
       tmp *= 1024;

    if (*suffix == 'b' || *(suffix + 1) == 'b')
       tmp /= 8;

    *kbytes_per_sec = tmp;
    ret = 0;

 cleanup:
    regfree(&rec);
    VIR_FREE(trate);
    return ret;
}


/**
 * xenParseSxprDisks:
 * @def: the domain config
 * @root: root S-expression
 * @hvm: true or 1 if node contains HVM S-Expression
 *
 * This parses out block devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprDisks(virDomainDefPtr def,
                  const struct sexpr *root,
                  int hvm)
{
    const struct sexpr *cur, *node;
    virDomainDiskDefPtr disk = NULL;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        /* Normally disks are in a (device (vbd ...)) block
           but blktap disks ended up in a differently named
           (device (tap ....)) block.... */
        if (sexpr_lookup(node, "device/vbd") ||
            sexpr_lookup(node, "device/tap") ||
            sexpr_lookup(node, "device/tap2")) {
            char *offset;
            const char *src = NULL;
            const char *dst = NULL;
            const char *mode = NULL;
            const char *bootable = NULL;

            /* Again dealing with (vbd...) vs (tap ...) differences */
            if (sexpr_lookup(node, "device/vbd")) {
                src = sexpr_node(node, "device/vbd/uname");
                dst = sexpr_node(node, "device/vbd/dev");
                mode = sexpr_node(node, "device/vbd/mode");
                bootable = sexpr_node(node, "device/vbd/bootable");
            } else if (sexpr_lookup(node, "device/tap2")) {
                src = sexpr_node(node, "device/tap2/uname");
                dst = sexpr_node(node, "device/tap2/dev");
                mode = sexpr_node(node, "device/tap2/mode");
                bootable = sexpr_node(node, "device/tap2/bootable");
            } else {
                src = sexpr_node(node, "device/tap/uname");
                dst = sexpr_node(node, "device/tap/dev");
                mode = sexpr_node(node, "device/tap/mode");
                bootable = sexpr_node(node, "device/tap/bootable");
            }

            if (!(disk = virDomainDiskDefNew(NULL)))
                goto error;

            if (dst == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("domain information incomplete, vbd has no dev"));
                goto error;
            }

            if (src == NULL) {
                /* There is a case without the uname to the CD-ROM device */
                offset = strchr(dst, ':');
                if (!offset ||
                    !hvm ||
                    STRNEQ(offset, ":cdrom")) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("domain information incomplete, vbd has no src"));
                    goto error;
                }
            }

            if (src != NULL) {
                offset = strchr(src, ':');
                if (!offset) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("cannot parse vbd filename, missing driver name"));
                    goto error;
                }

                if (sexpr_lookup(node, "device/tap2") &&
                    STRPREFIX(src, "tap:")) {
                    if (virDomainDiskSetDriver(disk, "tap2") < 0)
                        goto error;
                } else {
                    char *tmp;
                    if (VIR_STRNDUP(tmp, src, offset - src) < 0)
                        goto error;
                    if (virDomainDiskSetDriver(disk, tmp) < 0) {
                        VIR_FREE(tmp);
                        goto error;
                    }
                    VIR_FREE(tmp);
                }

                src = offset + 1;

                if (STREQ(virDomainDiskGetDriver(disk), "tap") ||
                    STREQ(virDomainDiskGetDriver(disk), "tap2")) {
                    char *driverType = NULL;

                    offset = strchr(src, ':');
                    if (!offset) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       "%s", _("cannot parse vbd filename, missing driver type"));
                        goto error;
                    }

                    if (VIR_STRNDUP(driverType, src, offset - src) < 0)
                        goto error;
                    if (STREQ(driverType, "aio"))
                        virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);
                    else
                        virDomainDiskSetFormat(disk,
                                               virStorageFileFormatTypeFromString(driverType));
                    VIR_FREE(driverType);
                    if (virDomainDiskGetFormat(disk) <= 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Unknown driver type %s"), src);
                        goto error;
                    }

                    src = offset + 1;
                    /* Its possible to use blktap driver for block devs
                       too, but kinda pointless because blkback is better,
                       so we assume common case here. If blktap becomes
                       omnipotent, we can revisit this, perhaps stat()'ing
                       the src file in question */
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                } else if (STREQ(virDomainDiskGetDriver(disk), "phy")) {
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
                } else if (STREQ(virDomainDiskGetDriver(disk), "file")) {
                    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
                }
            } else {
                /* No CDROM media so can't really tell. We'll just
                   call if a FILE for now and update when media
                   is inserted later */
                virDomainDiskSetType(disk, VIR_STORAGE_TYPE_FILE);
            }

            if (STREQLEN(dst, "ioemu:", 6))
                dst += 6;

            disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
            offset = strrchr(dst, ':');
            if (offset) {
                if (STREQ(offset, ":cdrom")) {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                } else if (STREQ(offset, ":disk")) {
                    /* The default anyway */
                } else {
                    /* Unknown, lets pretend its a disk too */
                }
                offset[0] = '\0';
            }

            if (VIR_STRDUP(disk->dst, dst) < 0)
                goto error;
            if (virDomainDiskSetSource(disk, src) < 0)
                goto error;

            if (STRPREFIX(disk->dst, "xvd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            else if (STRPREFIX(disk->dst, "hd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STRPREFIX(disk->dst, "sd"))
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;

            if (mode &&
                strchr(mode, 'r'))
                disk->src->readonly = true;
            if (mode &&
                strchr(mode, '!'))
                disk->src->shared = true;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto error;

            /* re-order disks if there is a bootable device */
            if (STREQ_NULLABLE(bootable, "1")) {
                def->disks[def->ndisks++] = def->disks[0];
                def->disks[0] = disk;
            } else {
                def->disks[def->ndisks++] = disk;
            }
            disk = NULL;
        }
    }

    return 0;

 error:
    virDomainDiskDefFree(disk);
    return -1;
}


/**
 * xenParseSxprNets:
 * @def: the domain config
 * @root: root S-expression
 *
 * This parses out network devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprNets(virDomainDefPtr def,
                 const struct sexpr *root)
{
    virDomainNetDefPtr net = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;
    int vif_index = 0;

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vif")) {
            const char *tmp2, *model, *type;
            tmp2 = sexpr_node(node, "device/vif/script");
            tmp = sexpr_node(node, "device/vif/bridge");
            model = sexpr_node(node, "device/vif/model");
            type = sexpr_node(node, "device/vif/type");

            if (VIR_ALLOC(net) < 0)
                goto cleanup;

            if (tmp != NULL ||
                (tmp2 != NULL && STREQ(tmp2, DEFAULT_VIF_SCRIPT))) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
                /* XXX virtual network reverse resolve */

                if (VIR_STRDUP(net->data.bridge.brname, tmp) < 0)
                    goto cleanup;
                if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
                    VIR_STRDUP(net->script, tmp2) < 0)
                    goto cleanup;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp && virDomainNetAppendIPAddress(net, tmp, AF_UNSPEC, 0) < 0)
                    goto cleanup;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                if (VIR_STRDUP(net->script, tmp2) < 0)
                    goto cleanup;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp && virDomainNetAppendIPAddress(net, tmp, AF_UNSPEC, 0) < 0)
                    goto cleanup;
            }

            tmp = sexpr_node(node, "device/vif/vifname");
            /* If vifname is specified in xend config, include it in net
             * definition regardless of domain state.  If vifname is not
             * specified, only generate one if domain is active (id != -1). */
            if (tmp) {
                if (VIR_STRDUP(net->ifname, tmp) < 0)
                    goto cleanup;
            } else if (def->id != -1) {
                if (virAsprintf(&net->ifname, "vif%d.%d", def->id, vif_index) < 0)
                    goto cleanup;
            }

            tmp = sexpr_node(node, "device/vif/mac");
            if (tmp) {
                if (virMacAddrParse(tmp, &net->mac) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("malformed mac address '%s'"), tmp);
                    goto cleanup;
                }
            }

            if (VIR_STRDUP(net->model, model) < 0)
                goto cleanup;

            if (!model && type && STREQ(type, "netfront") &&
                VIR_STRDUP(net->model, "netfront") < 0)
                goto cleanup;

            tmp = sexpr_node(node, "device/vif/rate");
            if (tmp) {
                virNetDevBandwidthPtr bandwidth;
                unsigned long long kbytes_per_sec;

                if (xenParseSxprVifRate(tmp, &kbytes_per_sec) < 0)
                    goto cleanup;

                if (VIR_ALLOC(bandwidth) < 0)
                    goto cleanup;
                if (VIR_ALLOC(bandwidth->out) < 0) {
                    VIR_FREE(bandwidth);
                    goto cleanup;
                }

                bandwidth->out->average = kbytes_per_sec;
                net->bandwidth = bandwidth;
            }

            if (VIR_APPEND_ELEMENT(def->nets, def->nnets, net) < 0)
                goto cleanup;

            vif_index++;
        }
    }

    return 0;

 cleanup:
    virDomainNetDefFree(net);
    return -1;
}


/**
 * xenParseSxprSound:
 * @def: the domain config
 * @str: comma separated list of sound models
 *
 * This parses out sound devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
int
xenParseSxprSound(virDomainDefPtr def,
                  const char *str)
{
    if (STREQ(str, "all")) {
        size_t i;

        /*
         * Special compatibility code for Xen with a bogus
         * sound=all in config.
         *
         * NB deliberately, don't include all possible
         * sound models anymore, just the 2 that were
         * historically present in Xen's QEMU.
         *
         * ie just es1370 + sb16.
         *
         * Hence use of MODEL_ES1370 + 1, instead of MODEL_LAST
         */

        if (VIR_ALLOC_N(def->sounds,
                        VIR_DOMAIN_SOUND_MODEL_ES1370 + 1) < 0)
            goto error;


        for (i = 0; i < (VIR_DOMAIN_SOUND_MODEL_ES1370 + 1); i++) {
            virDomainSoundDefPtr sound;
            if (VIR_ALLOC(sound) < 0)
                goto error;
            sound->model = i;
            def->sounds[def->nsounds++] = sound;
        }
    } else {
        char model[10];
        const char *offset = str, *offset2;

        do {
            int len;
            virDomainSoundDefPtr sound;
            offset2 = strchr(offset, ',');
            if (offset2)
                len = (offset2 - offset);
            else
                len = strlen(offset);
            if (virStrncpy(model, offset, len, sizeof(model)) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Sound model %s too big for destination"),
                               offset);
                goto error;
            }

            if (VIR_ALLOC(sound) < 0)
                goto error;

            if ((sound->model = virDomainSoundModelTypeFromString(model)) < 0) {
                VIR_FREE(sound);
                goto error;
            }

            if (VIR_APPEND_ELEMENT(def->sounds, def->nsounds, sound) < 0) {
                virDomainSoundDefFree(sound);
                goto error;
            }

            offset = offset2 ? offset2 + 1 : NULL;
        } while (offset);
    }

    return 0;

 error:
    return -1;
}


/**
 * xenParseSxprUSB:
 * @def: the domain config
 * @root: root S-expression
 *
 * This parses out USB devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprUSB(virDomainDefPtr def,
                const struct sexpr *root)
{
    struct sexpr *cur, *node;
    const char *tmp;

    for (cur = sexpr_lookup(root, "domain/image/hvm"); cur && cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "usbdevice")) {
            tmp = sexpr_node(node, "usbdevice");
            if (tmp && *tmp) {
                if (STREQ(tmp, "tablet") ||
                    STREQ(tmp, "mouse") ||
                    STREQ(tmp, "keyboard")) {
                    virDomainInputDefPtr input;
                    if (VIR_ALLOC(input) < 0)
                        goto error;
                    input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                    if (STREQ(tmp, "tablet"))
                        input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                    else if (STREQ(tmp, "mouse"))
                        input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                    else
                        input->type = VIR_DOMAIN_INPUT_TYPE_KBD;

                    if (VIR_APPEND_ELEMENT(def->inputs, def->ninputs, input) < 0) {
                        VIR_FREE(input);
                        goto error;
                    }
                } else {
                    /* XXX Handle other non-input USB devices later */
                }
            }
        }
    }
    return 0;

 error:
    return -1;
}


/*
 * xenParseSxprGraphicsOld:
 * @def: the domain config
 * @root: root S-expression
 * @hvm: true or 1 if root contains HVM S-Expression
 * @vncport: VNC port number
 *
 * This parses out VNC devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprGraphicsOld(virDomainDefPtr def,
                        const struct sexpr *root,
                        int hvm,
                        int vncport)
{
    const char *tmp;
    virDomainGraphicsDefPtr graphics = NULL;

    if ((tmp = sexpr_fmt_node(root, "domain/image/%s/vnc", hvm ? "hvm" : "linux")) &&
        tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV VNC config) */
        int port;
        const char *listenAddr = sexpr_fmt_node(root, "domain/image/%s/vnclisten", hvm ? "hvm" : "linux");
        const char *vncPasswd = sexpr_fmt_node(root, "domain/image/%s/vncpasswd", hvm ? "hvm" : "linux");
        const char *keymap = sexpr_fmt_node(root, "domain/image/%s/keymap", hvm ? "hvm" : "linux");
        const char *unused = sexpr_fmt_node(root, "domain/image/%s/vncunused", hvm ? "hvm" : "linux");

        port = vncport;

        if (VIR_ALLOC(graphics) < 0)
            goto error;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
        if ((unused && STREQ(unused, "1")) || port == -1)
            graphics->data.vnc.autoport = true;
        graphics->data.vnc.port = port;

        if (virDomainGraphicsListenAppendAddress(graphics, listenAddr) < 0)
            goto error;

        if (VIR_STRDUP(graphics->data.vnc.auth.passwd, vncPasswd) < 0)
            goto error;

        if (VIR_STRDUP(graphics->data.vnc.keymap, keymap) < 0)
            goto error;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto error;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    } else if ((tmp = sexpr_fmt_node(root, "domain/image/%s/sdl", hvm ? "hvm" : "linux")) &&
               tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV sdl config) */
        const char *display = sexpr_fmt_node(root, "domain/image/%s/display", hvm ? "hvm" : "linux");
        const char *xauth = sexpr_fmt_node(root, "domain/image/%s/xauthority", hvm ? "hvm" : "linux");

        if (VIR_ALLOC(graphics) < 0)
            goto error;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        if (VIR_STRDUP(graphics->data.sdl.display, display) < 0)
            goto error;
        if (VIR_STRDUP(graphics->data.sdl.xauth, xauth) < 0)
            goto error;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto error;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    }

    return 0;

 error:
    virDomainGraphicsDefFree(graphics);
    return -1;
}


/*
 * xenParseSxprGraphicsNew:
 * @def: the domain config
 * @root: root S-expression
 * @vncport: VNC port number
 *
 * This parses out VNC devices from the domain S-expression
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprGraphicsNew(virDomainDefPtr def,
                        const struct sexpr *root, int vncport)
{
    virDomainGraphicsDefPtr graphics = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;
    int typeVal;

    /* append network devices and framebuffer */
    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if (sexpr_lookup(node, "device/vfb")) {
            /* New style graphics config for PV guests in >= 3.0.4,
             * or for HVM guests in >= 3.0.5 */
            if (sexpr_node(node, "device/vfb/type")) {
                tmp = sexpr_node(node, "device/vfb/type");
            } else if (sexpr_node(node, "device/vfb/vnc")) {
                tmp = "vnc";
            } else if (sexpr_node(node, "device/vfb/sdl")) {
                tmp = "sdl";
            } else {
                tmp = "unknown";
            }

            if (VIR_ALLOC(graphics) < 0)
                goto error;

            if ((typeVal = virDomainGraphicsTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown graphics type '%s'"), tmp);
                goto error;
            }
            graphics->type = typeVal;

            if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                const char *display = sexpr_node(node, "device/vfb/display");
                const char *xauth = sexpr_node(node, "device/vfb/xauthority");
                if (VIR_STRDUP(graphics->data.sdl.display, display) < 0)
                    goto error;
                if (VIR_STRDUP(graphics->data.sdl.xauth, xauth) < 0)
                    goto error;
            } else {
                int port;
                const char *listenAddr = sexpr_node(node, "device/vfb/vnclisten");
                const char *vncPasswd = sexpr_node(node, "device/vfb/vncpasswd");
                const char *keymap = sexpr_node(node, "device/vfb/keymap");
                const char *unused = sexpr_node(node, "device/vfb/vncunused");

                port = vncport;

                /* Didn't find port entry in xenstore */
                if (port == -1) {
                    const char *str = sexpr_node(node, "device/vfb/vncdisplay");
                    int val;
                    if (str != NULL && virStrToLong_i(str, NULL, 0, &val) == 0)
                        port = val;
                }

                if ((unused && STREQ(unused, "1")) || port == -1)
                    graphics->data.vnc.autoport = true;

                if (port >= 0 && port < 5900)
                    port += 5900;
                graphics->data.vnc.port = port;

                if (virDomainGraphicsListenAppendAddress(graphics, listenAddr) < 0)
                    goto error;

                if (VIR_STRDUP(graphics->data.vnc.auth.passwd, vncPasswd) < 0)
                    goto error;

                if (VIR_STRDUP(graphics->data.vnc.keymap, keymap) < 0)
                    goto error;
            }

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto error;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
            break;
        }
    }

    return 0;

 error:
    virDomainGraphicsDefFree(graphics);
    return -1;
}


/**
 * xenParseSxprPCI:
 * @def: the domain config
 * @root: root sexpr
 *
 * This parses out PCI devices from the domain sexpr
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenParseSxprPCI(virDomainDefPtr def,
                const struct sexpr *root)
{
    const struct sexpr *cur, *tmp = NULL, *node;
    virDomainHostdevDefPtr dev = NULL;

    /*
     * With the (domain ...) block we have the following odd setup
     *
     * (device
     *    (pci
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x1b) (func 0x0))
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x13) (func 0x0))
     *    )
     * )
     *
     * Normally there is one (device ...) block per device, but in
     * weird world of Xen PCI, once (device ...) covers multiple
     * devices.
     */

    for (cur = root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        node = cur->u.s.car;
        if ((tmp = sexpr_lookup(node, "device/pci")) != NULL)
            break;
    }

    if (!tmp)
        return 0;

    for (cur = tmp; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
        const char *domain = NULL;
        const char *bus = NULL;
        const char *slot = NULL;
        const char *func = NULL;
        int domainID;
        int busID;
        int slotID;
        int funcID;

        node = cur->u.s.car;
        if (!sexpr_lookup(node, "dev"))
            continue;

        if (!(domain = sexpr_node(node, "dev/domain"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing PCI domain"));
            goto error;
        }
        if (!(bus = sexpr_node(node, "dev/bus"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing PCI bus"));
            goto error;
        }
        if (!(slot = sexpr_node(node, "dev/slot"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing PCI slot"));
            goto error;
        }
        if (!(func = sexpr_node(node, "dev/func"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing PCI func"));
            goto error;
        }

        if (virStrToLong_i(domain, NULL, 0, &domainID) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse PCI domain '%s'"), domain);
            goto error;
        }
        if (virStrToLong_i(bus, NULL, 0, &busID) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse PCI bus '%s'"), bus);
            goto error;
        }
        if (virStrToLong_i(slot, NULL, 0, &slotID) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse PCI slot '%s'"), slot);
            goto error;
        }
        if (virStrToLong_i(func, NULL, 0, &funcID) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse PCI func '%s'"), func);
            goto error;
        }

        if (!(dev = virDomainHostdevDefNew(NULL)))
           goto error;

        dev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        dev->managed = false;
        dev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
        dev->source.subsys.u.pci.addr.domain = domainID;
        dev->source.subsys.u.pci.addr.bus = busID;
        dev->source.subsys.u.pci.addr.slot = slotID;
        dev->source.subsys.u.pci.addr.function = funcID;

        if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, dev) < 0)
            goto error;
    }

    return 0;

 error:
    virDomainHostdevDefFree(dev);
    return -1;
}


/**
 * xenParseSxpr:
 * @root: the root of the parsed S-Expression
 * @cpus: set of cpus the domain may be pinned to
 * @tty: the console pty path
 * @vncport: VNC port number
 *
 * Parse the xend S-expression description and turn it into a virDomainDefPtr
 * representing these settings as closely as is practical.
 *
 * Returns the domain config or NULL in case of error.
 *         The caller must free() the returned value.
 */
virDomainDefPtr
xenParseSxpr(const struct sexpr *root,
             const char *cpus,
             char *tty,
             int vncport,
             virCapsPtr caps,
             virDomainXMLOptionPtr xmlopt)
{
    const char *tmp;
    virDomainDefPtr def;
    int hvm = 0, vmlocaltime;
    unsigned int vcpus;

    if (!(def = virDomainDefNew()))
        goto error;

    tmp = sexpr_node(root, "domain/domid");
    def->virtType = VIR_DOMAIN_VIRT_XEN;
    if (tmp)
        def->id = sexpr_int(root, "domain/domid");
    else
        def->id = -1;

    if (sexpr_node_copy(root, "domain/name", &def->name) < 0)
        goto error;
    if (def->name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("domain information incomplete, missing name"));
        goto error;
    }

    tmp = sexpr_node(root, "domain/uuid");
    if (tmp == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("domain information incomplete, missing name"));
        goto error;
    }
    if (virUUIDParse(tmp, def->uuid) < 0)
        goto error;

    if (sexpr_node_copy(root, "domain/description", &def->description) < 0)
        goto error;

    hvm = sexpr_lookup(root, "domain/image/hvm") ? 1 : 0;
    if (!hvm) {
        if (sexpr_node_copy(root, "domain/bootloader",
                            &def->os.bootloader) < 0)
            goto error;

        if (!def->os.bootloader &&
            sexpr_has(root, "domain/bootloader") &&
            VIR_STRDUP(def->os.bootloader, "") < 0)
            goto error;

        if (def->os.bootloader &&
            sexpr_node_copy(root, "domain/bootloader_args",
                            &def->os.bootloaderArgs) < 0)
            goto error;
    }

    def->os.type = (hvm ? VIR_DOMAIN_OSTYPE_HVM : VIR_DOMAIN_OSTYPE_LINUX);

    if (def->id != 0) {
        if (sexpr_lookup(root, "domain/image")) {
            if (xenParseSxprOS(root, def, hvm) < 0)
                goto error;
        }
    }

    virDomainDefSetMemoryTotal(def, (sexpr_u64(root, "domain/maxmem") << 10));
    def->mem.cur_balloon = (sexpr_u64(root, "domain/memory") << 10);

    if (def->mem.cur_balloon > virDomainDefGetMemoryTotal(def))
        def->mem.cur_balloon = virDomainDefGetMemoryTotal(def);

    if (cpus != NULL) {
        if (virBitmapParse(cpus, &def->cpumask, VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto error;

        if (virBitmapIsAllClear(def->cpumask)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid value of 'cpumask': %s"),
                           cpus);
            goto error;
        }
    }

    if (virDomainDefSetVcpusMax(def, sexpr_int(root, "domain/vcpus"), xmlopt) < 0)
        goto error;

    vcpus = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
    if (!vcpus || virDomainDefGetVcpusMax(def) < vcpus)
        vcpus = virDomainDefGetVcpusMax(def);

    if (virDomainDefSetVcpus(def, vcpus) < 0)
        goto error;

    tmp = sexpr_node(root, "domain/on_poweroff");
    if (tmp != NULL) {
        if ((def->onPoweroff = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else {
        def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    }

    tmp = sexpr_node(root, "domain/on_reboot");
    if (tmp != NULL) {
        if ((def->onReboot = virDomainLifecycleTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else {
        def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    }

    tmp = sexpr_node(root, "domain/on_crash");
    if (tmp != NULL) {
        if ((def->onCrash = virDomainLifecycleCrashTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else {
        def->onCrash = VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY;
    }

    if (hvm) {
        if (sexpr_int(root, "domain/image/hvm/acpi"))
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;
        if (sexpr_int(root, "domain/image/hvm/apic"))
            def->features[VIR_DOMAIN_FEATURE_APIC] = VIR_TRISTATE_SWITCH_ON;
        if (sexpr_int(root, "domain/image/hvm/pae"))
            def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
        if (sexpr_int(root, "domain/image/hvm/hap"))
            def->features[VIR_DOMAIN_FEATURE_HAP] = VIR_TRISTATE_SWITCH_ON;
        if (sexpr_int(root, "domain/image/hvm/viridian"))
            def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] = VIR_TRISTATE_SWITCH_ON;
    }

    /* 12aaf4a2486b (3.0.3) added a second low-priority 'localtime' setting */
    vmlocaltime = sexpr_int(root, "domain/localtime");
    if (hvm) {
        const char *value = sexpr_node(root, "domain/image/hvm/localtime");
        int rtc_offset;

        if (value) {
            if (virStrToLong_i(value, NULL, 0, &vmlocaltime) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown localtime offset %s"), value);
                goto error;
            }
        }
        def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_VARIABLE;
        rtc_offset =  sexpr_int(root, "domain/image/hvm/rtc_timeoffset");
        def->clock.data.variable.adjustment = rtc_offset;
        def->clock.data.variable.basis = vmlocaltime ?
            VIR_DOMAIN_CLOCK_BASIS_LOCALTIME :
            VIR_DOMAIN_CLOCK_BASIS_UTC;

        if (sexpr_lookup(root, "domain/image/hvm/hpet")) {
            virDomainTimerDefPtr timer;

            if (VIR_ALLOC_N(def->clock.timers, 1) < 0 ||
                VIR_ALLOC(timer) < 0)
                goto error;

            timer->name = VIR_DOMAIN_TIMER_NAME_HPET;
            timer->present = sexpr_int(root, "domain/image/hvm/hpet");
            timer->tickpolicy = -1;
            timer->mode = -1;
            timer->track = -1;

            def->clock.ntimers = 1;
            def->clock.timers[0] = timer;
        }
    } else {
        const char *value = sexpr_node(root, "domain/image/linux/localtime");
        if (value) {
            if (virStrToLong_i(value, NULL, 0, &vmlocaltime) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unknown localtime offset %s"), value);
                goto error;
            }
        }
        /* PV domains do not have an emulated RTC and the offset is fixed. */
        if (vmlocaltime)
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
        else
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
        def->clock.data.utc_reset = true;
    } /* !hvm */

    if (sexpr_node_copy(root, hvm ?
                        "domain/image/hvm/device_model" :
                        "domain/image/linux/device_model",
                        &def->emulator) < 0)
        goto error;

    /* append block devices */
    if (xenParseSxprDisks(def, root, hvm) < 0)
        goto error;

    if (xenParseSxprNets(def, root) < 0)
        goto error;

    if (xenParseSxprPCI(def, root) < 0)
        goto error;

    /* New style graphics device config */
    if (xenParseSxprGraphicsNew(def, root, vncport) < 0)
        goto error;

    /* Graphics device (HVM <= 3.0.4, or PV <= 3.0.3) vnc config */
    if ((def->ngraphics == 0) &&
        xenParseSxprGraphicsOld(def, root, hvm, vncport) < 0)
        goto error;

    /* in case of HVM we have USB device emulation */
    if (hvm &&
        xenParseSxprUSB(def, root) < 0)
        goto error;

    /* Character device config */
    if (hvm) {
        const struct sexpr *serial_root;
        bool have_multiple_serials = false;

        serial_root = sexpr_lookup(root, "domain/image/hvm/serial");
        if (serial_root) {
            const struct sexpr *cur, *node, *cur2;
            int ports_skipped = 0;

            for (cur = serial_root; cur->kind == SEXPR_CONS; cur = cur->u.s.cdr) {
                node = cur->u.s.car;

                for (cur2 = node; cur2->kind == SEXPR_CONS; cur2 = cur2->u.s.cdr) {
                    tmp = cur2->u.s.car->u.value;

                    if (tmp && STRNEQ(tmp, "none")) {
                        virDomainChrDefPtr chr;
                        if ((chr = xenParseSxprChar(tmp, tty)) == NULL)
                            goto error;
                        chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                        chr->target.port = def->nserials + ports_skipped;
                        if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0) {
                            virDomainChrDefFree(chr);
                            goto error;
                        }
                    }
                    else
                        ports_skipped++;

                    have_multiple_serials = true;
                }
            }
        }

        if (!have_multiple_serials) {
            tmp = sexpr_node(root, "domain/image/hvm/serial");
            if (tmp && STRNEQ(tmp, "none")) {
                virDomainChrDefPtr chr;
                if ((chr = xenParseSxprChar(tmp, tty)) == NULL)
                    goto error;
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = 0;
                if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
            }
        }

        tmp = sexpr_node(root, "domain/image/hvm/parallel");
        if (tmp && STRNEQ(tmp, "none")) {
            virDomainChrDefPtr chr;
            /* XXX does XenD stuff parallel port tty info into xenstore somewhere ? */
            if ((chr = xenParseSxprChar(tmp, NULL)) == NULL)
                goto error;
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            chr->target.port = 0;
            if (VIR_APPEND_ELEMENT(def->parallels, def->nparallels, chr) < 0) {
                virDomainChrDefFree(chr);
                goto error;
            }
        }
    } else if (def->id != 0) {
        if (VIR_ALLOC_N(def->consoles, 1) < 0)
            goto error;
        def->nconsoles = 1;
        /* Fake a paravirt console, since that's not in the sexpr */
        if (!(def->consoles[0] = xenParseSxprChar("pty", tty)))
            goto error;
        def->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->consoles[0]->target.port = 0;
        def->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
    }
    VIR_FREE(tty);


    /* Sound device config */
    if (hvm &&
        (tmp = sexpr_node(root, "domain/image/hvm/soundhw")) != NULL &&
        *tmp) {
        if (xenParseSxprSound(def, tmp) < 0)
            goto error;
    }

    if (virDomainDefPostParse(def, caps, VIR_DOMAIN_DEF_PARSE_ABI_UPDATE,
                              xmlopt, NULL) < 0)
        goto error;

    return def;

 error:
    VIR_FREE(tty);
    virDomainDefFree(def);
    return NULL;
}


/**
 * xenParseSxprString:
 * @sexpr: the root of the parsed S-Expression
 * @tty: the console pty path
 * @vncport: VNC port number
 *
 * Parse the xend S-expression description and turn it into a virDomainDefPtr
 * representing these settings as closely as is practical.
 *
 * Returns the domain config or NULL in case of error.
 *         The caller must free() the returned value.
 */
virDomainDefPtr
xenParseSxprString(const char *sexpr,
                   char *tty,
                   int vncport,
                   virCapsPtr caps,
                   virDomainXMLOptionPtr xmlopt)
{
    struct sexpr *root = string2sexpr(sexpr);
    virDomainDefPtr def;

    if (!root)
        return NULL;

    def = xenParseSxpr(root, NULL, tty, vncport, caps, xmlopt);
    sexpr_free(root);

    return def;
}

/************************************************************************
 *                                                                      *
 * Converter functions to go from the XML tree to an S-Expr for Xen     *
 *                                                                      *
 ************************************************************************/


/**
 * xenFormatSxprGraphicsNew:
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 *
 * Convert the graphics part of the domain description into a S-expression
 * in buf. (HVM > 3.0.4 or PV > 3.0.3)
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xenFormatSxprGraphicsNew(virDomainGraphicsDefPtr def,
                         virBufferPtr buf)
{
    virDomainGraphicsListenDefPtr glisten;

    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected graphics type %d"),
                       def->type);
        return -1;
    }

    virBufferAddLit(buf, "(device (vkbd))");
    virBufferAddLit(buf, "(device (vfb ");

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        virBufferAddLit(buf, "(type sdl)");
        if (def->data.sdl.display)
            virBufferAsprintf(buf, "(display '%s')", def->data.sdl.display);
        if (def->data.sdl.xauth)
            virBufferAsprintf(buf, "(xauthority '%s')", def->data.sdl.xauth);
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBufferAddLit(buf, "(type vnc)");
        if (def->data.vnc.autoport) {
            virBufferAddLit(buf, "(vncunused 1)");
        } else {
            virBufferAddLit(buf, "(vncunused 0)");
            virBufferAsprintf(buf, "(vncdisplay %d)", def->data.vnc.port-5900);
        }

        if ((glisten = virDomainGraphicsGetListen(def, 0)) &&
            glisten->address)
            virBufferAsprintf(buf, "(vnclisten '%s')", glisten->address);
        if (def->data.vnc.auth.passwd)
            virBufferAsprintf(buf, "(vncpasswd '%s')", def->data.vnc.auth.passwd);
        if (def->data.vnc.keymap)
            virBufferAsprintf(buf, "(keymap '%s')", def->data.vnc.keymap);
    }

    virBufferAddLit(buf, "))");

    return 0;
}


/**
 * xenFormatSxprGraphicsOld:
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 *
 * Convert the graphics part of the domain description into a S-expression
 * in buf. (HVM <= 3.0.4 or PV <= 3.0.3)
 *
 * Returns 0 in case of success, -1 in case of error
 */
static int
xenFormatSxprGraphicsOld(virDomainGraphicsDefPtr def, virBufferPtr buf)
{
    virDomainGraphicsListenDefPtr glisten;

    if (def->type != VIR_DOMAIN_GRAPHICS_TYPE_SDL &&
        def->type != VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected graphics type %d"),
                       def->type);
        return -1;
    }

    if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        virBufferAddLit(buf, "(sdl 1)");
        if (def->data.sdl.display)
            virBufferAsprintf(buf, "(display '%s')", def->data.sdl.display);
        if (def->data.sdl.xauth)
            virBufferAsprintf(buf, "(xauthority '%s')", def->data.sdl.xauth);
    } else if (def->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBufferAddLit(buf, "(vnc 1)");
        if (def->data.vnc.autoport) {
            virBufferAddLit(buf, "(vncunused 1)");
        } else {
            virBufferAddLit(buf, "(vncunused 0)");
            virBufferAsprintf(buf, "(vncdisplay %d)", def->data.vnc.port-5900);
        }

        if ((glisten = virDomainGraphicsGetListen(def, 0)) &&
            glisten->address)
            virBufferAsprintf(buf, "(vnclisten '%s')", glisten->address);
        if (def->data.vnc.auth.passwd)
            virBufferAsprintf(buf, "(vncpasswd '%s')", def->data.vnc.auth.passwd);
        if (def->data.vnc.keymap)
            virBufferAsprintf(buf, "(keymap '%s')", def->data.vnc.keymap);
    }

    return 0;
}


/**
 * xenFormatSxprChr:
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 *
 * Convert the character device part of the domain config into a S-expression
 * in buf.
 *
 * Returns 0 in case of success, -1 in case of error
 */
int
xenFormatSxprChr(virDomainChrDefPtr def,
                 virBufferPtr buf)
{
    const char *type = virDomainChrTypeToString(def->source->type);

    if (!type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unexpected chr device type"));
        return -1;
    }

    switch (def->source->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAdd(buf, type, -1);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(buf, "%s:", type);
        virBufferEscapeSexpr(buf, "%s", def->source->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferEscapeSexpr(buf, "%s", def->source->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        virBufferAsprintf(buf, "%s:%s:%s%s",
                          (def->source->data.tcp.protocol
                           == VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW ?
                           "tcp" : "telnet"),
                          (def->source->data.tcp.host ?
                           def->source->data.tcp.host : ""),
                          (def->source->data.tcp.service ?
                           def->source->data.tcp.service : ""),
                          (def->source->data.tcp.listen ?
                           ",server,nowait" : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferAsprintf(buf, "%s:%s:%s@%s:%s", type,
                          (def->source->data.udp.connectHost ?
                           def->source->data.udp.connectHost : ""),
                          (def->source->data.udp.connectService ?
                           def->source->data.udp.connectService : ""),
                          (def->source->data.udp.bindHost ?
                           def->source->data.udp.bindHost : ""),
                          (def->source->data.udp.bindService ?
                           def->source->data.udp.bindService : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(buf, "%s:", type);
        virBufferEscapeSexpr(buf, "%s", def->source->data.nix.path);
        if (def->source->data.nix.listen)
            virBufferAddLit(buf, ",server,nowait");
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chr device type '%s'"), type);
        return -1;
    }

    if (virBufferCheckError(buf) < 0)
        return -1;

    return 0;
}


/**
 * xenFormatSxprDisk:
 * @node: node containing the disk description
 * @buf: a buffer for the result S-expression
 * @hvm: true or 1 if domain is HVM
 * @isAttach: create expression for device attach (1).
 *
 * Convert the disk device part of the domain config into a S-expresssion in buf.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenFormatSxprDisk(virDomainDiskDefPtr def,
                  virBufferPtr buf,
                  int hvm,
                  int isAttach)
{
    const char *src = virDomainDiskGetSource(def);
    const char *driver = virDomainDiskGetDriver(def);

    /* Xend (all versions) put the floppy device config
     * under the hvm (image (os)) block
     */
    if (hvm &&
        def->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY) {
        if (isAttach) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Cannot directly attach floppy %s"), src);
            return -1;
        }
        return 0;
    }

    if (!isAttach)
        virBufferAddLit(buf, "(device ");

    /* Normally disks are in a (device (vbd ...)) block
     * but blktap disks ended up in a differently named
     * (device (tap ....)) block.... */
    if (STREQ_NULLABLE(driver, "tap")) {
        virBufferAddLit(buf, "(tap ");
    } else if (STREQ_NULLABLE(driver, "tap2")) {
        virBufferAddLit(buf, "(tap2 ");
    } else {
        virBufferAddLit(buf, "(vbd ");
    }

    if (hvm) {
        virBufferEscapeSexpr(buf, "(dev '%s:", def->dst);
        virBufferAsprintf(buf, "%s')",
                          def->device == VIR_DOMAIN_DISK_DEVICE_CDROM ?
                          "cdrom" : "disk");
    } else if (def->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virBufferEscapeSexpr(buf, "(dev '%s:cdrom')", def->dst);
    } else {
        virBufferEscapeSexpr(buf, "(dev '%s')", def->dst);
    }

    if (src) {
        if (driver) {
            if (STREQ(driver, "tap") ||
                STREQ(driver, "tap2")) {
                const char *type;
                int format = virDomainDiskGetFormat(def);

                if (!format || format == VIR_STORAGE_FILE_RAW)
                    type = "aio";
                else
                    type = virStorageFileFormatTypeToString(format);
                virBufferEscapeSexpr(buf, "(uname '%s:", driver);
                virBufferEscapeSexpr(buf, "%s:", type);
                virBufferEscapeSexpr(buf, "%s')", src);
            } else {
                virBufferEscapeSexpr(buf, "(uname '%s:", driver);
                virBufferEscapeSexpr(buf, "%s')", src);
            }
        } else {
            int type = virDomainDiskGetType(def);

            if (type == VIR_STORAGE_TYPE_FILE) {
                virBufferEscapeSexpr(buf, "(uname 'file:%s')", src);
            } else if (type == VIR_STORAGE_TYPE_BLOCK) {
                if (src[0] == '/')
                    virBufferEscapeSexpr(buf, "(uname 'phy:%s')", src);
                else
                    virBufferEscapeSexpr(buf, "(uname 'phy:/dev/%s')",
                                         src);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported disk type %s"),
                               virStorageTypeToString(type));
                return -1;
            }
        }
    }

    if (def->src->readonly)
        virBufferAddLit(buf, "(mode 'r')");
    else if (def->src->shared)
        virBufferAddLit(buf, "(mode 'w!')");
    else
        virBufferAddLit(buf, "(mode 'w')");
    if (def->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        return -1;
    }

    if (!isAttach)
        virBufferAddLit(buf, ")");

    virBufferAddLit(buf, ")");

    return 0;
}

/**
 * xenFormatSxprNet:
 * @conn: connection
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 * @hvm: true or 1 if domain is HVM
 * @isAttach: create expression for device attach (1).
 *
 * Convert the interface description of the domain config into a S-expression in buf.
 * This is a temporary interface as the S-Expr interface
 * will be replaced by XML-RPC in the future. However the XML format should
 * stay valid over time.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenFormatSxprNet(virConnectPtr conn,
                 virDomainNetDefPtr def,
                 virBufferPtr buf,
                 int hvm,
                 int isAttach)
{
    const char *script = DEFAULT_VIF_SCRIPT;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    if (def->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        def->type != VIR_DOMAIN_NET_TYPE_NETWORK &&
        def->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported network type %d"), def->type);
        return -1;
    }
    if (def->script &&
        def->type != VIR_DOMAIN_NET_TYPE_BRIDGE &&
        def->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("scripts are not supported on interfaces of type %s"),
                       virDomainNetTypeToString(def->type));
        return -1;
    }

    if (!isAttach)
        virBufferAddLit(buf, "(device ");

    virBufferAddLit(buf, "(vif ");

    virBufferAsprintf(buf, "(mac '%s')", virMacAddrFormat(&def->mac, macaddr));

    if (def->bandwidth && def->bandwidth->out && def->bandwidth->out->average)
        virBufferAsprintf(buf, "(rate '%lluKB/s')", def->bandwidth->out->average);

    switch (def->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferEscapeSexpr(buf, "(bridge '%s')", def->data.bridge.brname);
        if (def->script)
            script = def->script;

        virBufferEscapeSexpr(buf, "(script '%s')", script);
        if (def->guestIP.nips == 1) {
            char *ipStr = virSocketAddrFormat(&def->guestIP.ips[0]->address);
            virBufferEscapeSexpr(buf, "(ip '%s')", ipStr);
            VIR_FREE(ipStr);
        } else if (def->guestIP.nips > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Driver does not support setting multiple IP addresses"));
            return -1;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        virNetworkPtr network =
            virNetworkLookupByName(conn, def->data.network.name);
        char *bridge;

        if (!network) {
            virReportError(VIR_ERR_NO_NETWORK, "%s",
                           def->data.network.name);
            return -1;
        }

        bridge = virNetworkGetBridgeName(network);
        virObjectUnref(network);
        if (!bridge) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network %s is not active"),
                           def->data.network.name);
            return -1;
        }
        virBufferEscapeSexpr(buf, "(bridge '%s')", bridge);
        virBufferEscapeSexpr(buf, "(script '%s')", script);
        VIR_FREE(bridge);
    }
    break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (def->script)
            virBufferEscapeSexpr(buf, "(script '%s')",
                                 def->script);
        if (def->guestIP.nips == 1) {
            char *ipStr = virSocketAddrFormat(&def->guestIP.ips[0]->address);
            virBufferEscapeSexpr(buf, "(ip '%s')", ipStr);
            VIR_FREE(ipStr);
        } else if (def->guestIP.nips > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Driver does not support setting multiple IP addresses"));
            return -1;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }

    if (def->ifname != NULL &&
        !STRPREFIX(def->ifname, "vif"))
        virBufferEscapeSexpr(buf, "(vifname '%s')", def->ifname);

    if (!hvm) {
        if (def->model != NULL)
            virBufferEscapeSexpr(buf, "(model '%s')", def->model);
    } else {
        if (def->model != NULL && STREQ(def->model, "netfront")) {
            virBufferAddLit(buf, "(type netfront)");
        } else {
            if (def->model != NULL)
                virBufferEscapeSexpr(buf, "(model '%s')", def->model);
        }
    }

    if (!isAttach)
        virBufferAddLit(buf, ")");

    virBufferAddLit(buf, ")");

    return 0;
}


/**
 * xenFormatSxprPCI:
 * @def: the device config
 * @buf: a buffer for the result S-expression
 *
 * Convert a single PCI device part of the domain config into a S-expresssion in buf.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static void
xenFormatSxprPCI(virDomainHostdevDefPtr def,
                 virBufferPtr buf)
{
    virBufferAsprintf(buf, "(dev (domain 0x%04x)(bus 0x%02x)(slot 0x%02x)(func 0x%x))",
                      def->source.subsys.u.pci.addr.domain,
                      def->source.subsys.u.pci.addr.bus,
                      def->source.subsys.u.pci.addr.slot,
                      def->source.subsys.u.pci.addr.function);
}


/**
 * xenFormatSxprOnePCI:
 * @def: the device config
 * @buf: a buffer for the result S-expression
 * @detach: create expression for device detach (1).
 *
 * Convert a single PCI device part of the domain config into a S-expresssion in buf.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
int
xenFormatSxprOnePCI(virDomainHostdevDefPtr def,
                    virBufferPtr buf,
                    int detach)
{
    if (def->managed) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("managed PCI devices not supported with XenD"));
        return -1;
    }

    virBufferAddLit(buf, "(pci ");
    xenFormatSxprPCI(def, buf);
    if (detach)
        virBufferAddLit(buf, "(state 'Closing')");
    else
        virBufferAddLit(buf, "(state 'Initialising')");
    virBufferAddLit(buf, ")");

    return 0;
}


/**
 * xenFormatSxprAllPCI:
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 *
 * Convert all PCI device parts of the domain config into a S-expresssion in buf.
 *
 * Returns 0 in case of success, -1 in case of error.
 */
static int
xenFormatSxprAllPCI(virDomainDefPtr def,
                    virBufferPtr buf)
{
    int hasPCI = 0;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++)
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            hasPCI = 1;

    if (!hasPCI)
        return 0;

    /*
     * With the (domain ...) block we have the following odd setup
     *
     * (device
     *    (pci
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x1b) (func 0x0))
     *       (dev (domain 0x0000) (bus 0x00) (slot 0x13) (func 0x0))
     *    )
     * )
     *
     * Normally there is one (device ...) block per device, but in the
     * weird world of Xen PCI, one (device ...) covers multiple devices.
     */

    virBufferAddLit(buf, "(device (pci ");
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (def->hostdevs[i]->managed) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("managed PCI devices not supported with XenD"));
                return -1;
            }

            xenFormatSxprPCI(def->hostdevs[i], buf);
        }
    }
    virBufferAddLit(buf, "))");

    return 0;
}


/**
 * xenFormatSxprSound:
 * @def: the domain config
 * @buf: a buffer for the result S-expression
 *
 * Convert all sound device parts of the domain config into S-expression in buf.
 *
 * Returns 0 if successful or -1 if failed.
 */
int
xenFormatSxprSound(virDomainDefPtr def,
                   virBufferPtr buf)
{
    const char *str;
    size_t i;

    for (i = 0; i < def->nsounds; i++) {
        if (!(str = virDomainSoundModelTypeToString(def->sounds[i]->model))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected sound model %d"),
                           def->sounds[i]->model);
            return -1;
        }
        if (i)
            virBufferAddChar(buf, ',');
        virBufferEscapeSexpr(buf, "%s", str);
    }

    if (virBufferCheckError(buf) < 0)
        return -1;

    return 0;
}


/**
 * xenFormatSxprInput:
 * @input: the input config
 * @buf: a buffer for the result S-expression
 *
 * Convert all input device parts of the domain config into S-expression in buf.
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenFormatSxprInput(virDomainInputDefPtr input,
                   virBufferPtr buf)
{
    if (input->bus != VIR_DOMAIN_INPUT_BUS_USB)
        return 0;

    if (input->type != VIR_DOMAIN_INPUT_TYPE_MOUSE &&
        input->type != VIR_DOMAIN_INPUT_TYPE_TABLET &&
        input->type != VIR_DOMAIN_INPUT_TYPE_KBD) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected input type %d"), input->type);
        return -1;
    }

    switch (input->type) {
        case VIR_DOMAIN_INPUT_TYPE_MOUSE:
            virBufferAsprintf(buf, "(usbdevice %s)", "mouse");
            break;
        case VIR_DOMAIN_INPUT_TYPE_TABLET:
            virBufferAsprintf(buf, "(usbdevice %s)", "tablet");
            break;
        case VIR_DOMAIN_INPUT_TYPE_KBD:
            virBufferAsprintf(buf, "(usbdevice %s)", "keyboard");
            break;
    }

    return 0;
}


/* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
   either 32, or 64 on a platform where long is big enough.  */
verify(MAX_VIRT_CPUS <= sizeof(1UL) * CHAR_BIT);

/**
 * xenFormatSxpr:
 * @conn: pointer to the hypervisor connection
 * @def: domain config definition
 *
 * Generate an S-expression representing the domain configuration.
 *
 * Returns the 0 terminated S-Expr string or NULL in case of error.
 *         the caller must free() the returned value.
 */
char *
xenFormatSxpr(virConnectPtr conn, virDomainDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    const char *tmp;
    char *bufout;
    int hvm = 0, vmlocaltime = -1;
    size_t i;
    bool in_image = false;

    VIR_DEBUG("Formatting domain sexpr");

    virBufferAddLit(&buf, "(vm ");
    virBufferEscapeSexpr(&buf, "(name '%s')", def->name);
    virBufferAsprintf(&buf, "(memory %llu)(maxmem %llu)",
                      VIR_DIV_UP(def->mem.cur_balloon, 1024),
                      VIR_DIV_UP(virDomainDefGetMemoryTotal(def), 1024));
    virBufferAsprintf(&buf, "(vcpus %u)", virDomainDefGetVcpusMax(def));
    /* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
       either 32, or 64 on a platform where long is big enough.  */
    if (virDomainDefHasVcpusOffline(def))
        virBufferAsprintf(&buf, "(vcpu_avail %lu)",
                          (1UL << virDomainDefGetVcpus(def)) - 1);

    if (def->cpumask) {
        char *ranges = virBitmapFormat(def->cpumask);
        if (ranges == NULL)
            goto error;
        virBufferEscapeSexpr(&buf, "(cpus '%s')", ranges);
        VIR_FREE(ranges);
    }

    virUUIDFormat(def->uuid, uuidstr);
    virBufferAsprintf(&buf, "(uuid '%s')", uuidstr);

    if (def->description)
        virBufferEscapeSexpr(&buf, "(description '%s')", def->description);

    if (def->os.bootloader) {
        if (def->os.bootloader[0])
            virBufferEscapeSexpr(&buf, "(bootloader '%s')", def->os.bootloader);
        else
            virBufferAddLit(&buf, "(bootloader)");

        if (def->os.bootloaderArgs)
            virBufferEscapeSexpr(&buf, "(bootloader_args '%s')", def->os.bootloaderArgs);
    }

    if (!(tmp = virDomainLifecycleTypeToString(def->onPoweroff))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle value %d"), def->onPoweroff);
        goto error;
    }
    virBufferAsprintf(&buf, "(on_poweroff '%s')", tmp);

    if (!(tmp = virDomainLifecycleTypeToString(def->onReboot))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle value %d"), def->onReboot);
        goto error;
    }
    virBufferAsprintf(&buf, "(on_reboot '%s')", tmp);

    if (!(tmp = virDomainLifecycleCrashTypeToString(def->onCrash))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle value %d"), def->onCrash);
        goto error;
    }
    virBufferAsprintf(&buf, "(on_crash '%s')", tmp);

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM)
        hvm = 1;

    if (!def->os.bootloader) {
        if (hvm)
            virBufferAddLit(&buf, "(image (hvm ");
        else
            virBufferAddLit(&buf, "(image (linux ");
        in_image = true;

        if (hvm &&
            def->os.loader == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("no HVM domain loader"));
            goto error;
        }

        if (def->os.kernel)
            virBufferEscapeSexpr(&buf, "(kernel '%s')", def->os.kernel);
        if (def->os.initrd)
            virBufferEscapeSexpr(&buf, "(ramdisk '%s')", def->os.initrd);
        if (def->os.root)
            virBufferEscapeSexpr(&buf, "(root '%s')", def->os.root);
        if (def->os.cmdline)
            virBufferEscapeSexpr(&buf, "(args '%s')", def->os.cmdline);

        if (hvm) {
            char bootorder[VIR_DOMAIN_BOOT_LAST+1];
            if (def->os.kernel)
                virBufferEscapeSexpr(&buf, "(loader '%s')", def->os.loader->path);
            else
                virBufferEscapeSexpr(&buf, "(kernel '%s')", def->os.loader->path);

            virBufferAsprintf(&buf, "(vcpus %u)", virDomainDefGetVcpusMax(def));
            if (virDomainDefHasVcpusOffline(def))
                virBufferAsprintf(&buf, "(vcpu_avail %lu)",
                                  (1UL << virDomainDefGetVcpus(def)) - 1);

            for (i = 0; i < def->os.nBootDevs; i++) {
                switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootorder[i] = 'a';
                    break;
                default:
                case VIR_DOMAIN_BOOT_DISK:
                    bootorder[i] = 'c';
                    break;
                case VIR_DOMAIN_BOOT_CDROM:
                    bootorder[i] = 'd';
                    break;
                case VIR_DOMAIN_BOOT_NET:
                    bootorder[i] = 'n';
                    break;
                }
            }
            if (def->os.nBootDevs == 0) {
                bootorder[0] = 'c';
                bootorder[1] = '\0';
            } else {
                bootorder[def->os.nBootDevs] = '\0';
            }
            virBufferAsprintf(&buf, "(boot %s)", bootorder);

            if (def->features[VIR_DOMAIN_FEATURE_ACPI] == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&buf, "(acpi 1)");
            if (def->features[VIR_DOMAIN_FEATURE_APIC] == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&buf, "(apic 1)");
            if (def->features[VIR_DOMAIN_FEATURE_PAE] == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&buf, "(pae 1)");
            if (def->features[VIR_DOMAIN_FEATURE_HAP] == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&buf, "(hap 1)");
            if (def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] == VIR_TRISTATE_SWITCH_ON)
                virBufferAddLit(&buf, "(viridian 1)");

            virBufferAddLit(&buf, "(usb 1)");

            for (i = 0; i < def->ninputs; i++)
                if (xenFormatSxprInput(def->inputs[i], &buf) < 0)
                    goto error;

            if (def->parallels) {
                virBufferAddLit(&buf, "(parallel ");
                if (xenFormatSxprChr(def->parallels[0], &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, ")");
            } else {
                virBufferAddLit(&buf, "(parallel none)");
            }
            if (def->serials) {
                if ((def->nserials > 1) || (def->serials[0]->target.port != 0)) {
                    int maxport = -1, port;
                    size_t j = 0;

                    virBufferAddLit(&buf, "(serial (");
                    for (i = 0; i < def->nserials; i++)
                        if (def->serials[i]->target.port > maxport)
                            maxport = def->serials[i]->target.port;

                    for (port = 0; port <= maxport; port++) {
                        virDomainChrDefPtr chr = NULL;

                        if (port)
                            virBufferAddLit(&buf, " ");
                        for (j = 0; j < def->nserials; j++) {
                            if (def->serials[j]->target.port == port) {
                                chr = def->serials[j];
                                break;
                            }
                        }
                        if (chr) {
                            if (xenFormatSxprChr(chr, &buf) < 0)
                                goto error;
                        } else {
                            virBufferAddLit(&buf, "none");
                        }
                    }
                    virBufferAddLit(&buf, "))");
                } else {
                    virBufferAddLit(&buf, "(serial ");
                    if (xenFormatSxprChr(def->serials[0], &buf) < 0)
                        goto error;
                    virBufferAddLit(&buf, ")");
                }
            } else {
                virBufferAddLit(&buf, "(serial none)");
            }

            if (def->sounds) {
                virBufferAddLit(&buf, "(soundhw '");
                if (xenFormatSxprSound(def, &buf) < 0)
                    goto error;
                virBufferAddLit(&buf, "')");
            }
        } /* hvm */

        /* get the device emulation model */
        if (def->emulator && hvm)
            virBufferEscapeSexpr(&buf, "(device_model '%s')", def->emulator);

        /* look for HPET in order to override the hypervisor/xend default */
        for (i = 0; i < def->clock.ntimers; i++) {
            if (def->clock.timers[i]->name == VIR_DOMAIN_TIMER_NAME_HPET &&
                def->clock.timers[i]->present != -1) {
                virBufferAsprintf(&buf, "(hpet %d)",
                                  def->clock.timers[i]->present);
                break;
            }
        }

        /* PV graphics for xen <= 3.0.4, or HVM graphics */
        if (hvm) {
            if ((def->ngraphics == 1) &&
                xenFormatSxprGraphicsOld(def->graphics[0], &buf) < 0)
                goto error;
        }
    } else {
        /* PV domains accept kernel cmdline args */
        if (def->os.cmdline) {
            virBufferEscapeSexpr(&buf, "(image (linux (args '%s')", def->os.cmdline);
            in_image = true;
        }
    } /* os.bootloader */

    if (!in_image) {
        if (hvm)
            virBufferAddLit(&buf, "(image (hvm ");
        else
            virBufferAddLit(&buf, "(image (linux ");
        in_image = true;
    }
    if (hvm) {
        /* >=3.1 HV: VARIABLE */
        int rtc_timeoffset;
        switch (def->clock.offset) {
        case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE:
            vmlocaltime = (int)def->clock.data.variable.basis;
            rtc_timeoffset = def->clock.data.variable.adjustment;
            break;
        case VIR_DOMAIN_CLOCK_OFFSET_UTC:
            if (def->clock.data.utc_reset) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("unsupported clock adjustment='reset'"));
                goto error;
            }
            vmlocaltime = 0;
            rtc_timeoffset = 0;
            break;
        case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
            if (def->clock.data.utc_reset) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("unsupported clock adjustment='reset'"));
                goto error;
            }
            vmlocaltime = 1;
            rtc_timeoffset = 0;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported clock offset='%s'"),
                           virDomainClockOffsetTypeToString(def->clock.offset));
            goto error;
        }
        virBufferAsprintf(&buf, "(rtc_timeoffset %d)", rtc_timeoffset);
    } else {
        /* >=3.1 PV: UTC and LOCALTIME */
        switch (def->clock.offset) {
        case VIR_DOMAIN_CLOCK_OFFSET_UTC:
            vmlocaltime = 0;
            break;
        case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
            vmlocaltime = 1;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported clock offset='%s'"),
                           virDomainClockOffsetTypeToString(def->clock.offset));
            goto error;
        }
    } /* !hvm */
    /* default post-XenD-3.1 location: */
    virBufferAsprintf(&buf, "(localtime %d)", vmlocaltime);

    if (in_image) {
        /* closes (image(hvm|linux */
        virBufferAddLit(&buf, "))");
        in_image = false;
    }
    /* pre-XenD-3.1 and compatibility location */
    virBufferAsprintf(&buf, "(localtime %d)", vmlocaltime);


    for (i = 0; i < def->ndisks; i++)
        if (xenFormatSxprDisk(def->disks[i], &buf, hvm, 0) < 0)
            goto error;

    for (i = 0; i < def->nnets; i++)
        if (xenFormatSxprNet(conn, def->nets[i], &buf, hvm, 0) < 0)
            goto error;

    if (xenFormatSxprAllPCI(def, &buf) < 0)
        goto error;

    /* New style PV graphics config xen >= 3.0.4 */
    if (!hvm) {
        if ((def->ngraphics == 1) &&
            xenFormatSxprGraphicsNew(def->graphics[0], &buf) < 0)
            goto error;
    }

    virBufferAddLit(&buf, ")"); /* closes (vm */

    if (virBufferCheckError(&buf) < 0)
        goto error;

    bufout = virBufferContentAndReset(&buf);
    VIR_DEBUG("Formatted sexpr: \n%s", bufout);
    return bufout;

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}
