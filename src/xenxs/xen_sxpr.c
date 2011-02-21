/*
 * xen_sxpr.c: Xen SEXPR parsing functions
 *
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Anthony Liguori <aliguori@us.ibm.com>
 * Author: Daniel Veillard <veillard@redhat.com>
 * Author: Markus Groß <gross@univention.de>
 */

#include <config.h>

#include "internal.h"
#include "virterror_internal.h"
#include "conf.h"
#include "memory.h"
#include "verify.h"
#include "uuid.h"
#include "logging.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_sxpr.h"

/* Get a domain id from a sexpr string */
int xenGetDomIdFromSxprString(const char *sexpr, int xendConfigVersion)
{
    struct sexpr *root = string2sexpr(sexpr);

    if (!root)
        return -1;

    int id = xenGetDomIdFromSxpr(root, xendConfigVersion);
    sexpr_free(root);
    return id;
}

/* Get a domain id from a sexpr */
int xenGetDomIdFromSxpr(const struct sexpr *root, int xendConfigVersion)
{
    int id = -1;
    const char * tmp = sexpr_node(root, "domain/domid");
    if (tmp == NULL && xendConfigVersion < 3) { /* Old XenD, domid was mandatory */
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing id"));
    } else {
      id = tmp ? sexpr_int(root, "domain/domid") : -1;
    }
    return id;
}

/*****************************************************************
 ******
 ****** Parsing of SEXPR into virDomainDef objects
 ******
 *****************************************************************/

/**
 * xenDaemonParseSxprOS
 * @node: the root of the parsed S-Expression
 * @def: the domain config
 * @hvm: true or 1 if no contains HVM S-Expression
 * @bootloader: true or 1 if a bootloader is defined
 *
 * Parse the xend sexp for description of os and append it to buf.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
xenDaemonParseSxprOS(const struct sexpr *node,
                     virDomainDefPtr def,
                     int hvm)
{
    if (hvm) {
        if (sexpr_node_copy(node, "domain/image/hvm/loader", &def->os.loader) < 0)
            goto no_memory;
        if (def->os.loader == NULL) {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.loader) < 0)
                goto no_memory;

            if (def->os.loader == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("domain information incomplete, missing HVM loader"));
                return(-1);
            }
        } else {
            if (sexpr_node_copy(node, "domain/image/hvm/kernel", &def->os.kernel) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/ramdisk", &def->os.initrd) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/args", &def->os.cmdline) < 0)
                goto no_memory;
            if (sexpr_node_copy(node, "domain/image/hvm/root", &def->os.root) < 0)
                goto no_memory;
        }
    } else {
        if (sexpr_node_copy(node, "domain/image/linux/kernel", &def->os.kernel) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/ramdisk", &def->os.initrd) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/args", &def->os.cmdline) < 0)
            goto no_memory;
        if (sexpr_node_copy(node, "domain/image/linux/root", &def->os.root) < 0)
            goto no_memory;
    }

    /* If HVM kenrel == loader, then old xend, so kill off kernel */
    if (hvm &&
        def->os.kernel &&
        STREQ(def->os.kernel, def->os.loader)) {
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
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing kernel & bootloader"));
        return -1;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

virDomainChrDefPtr
xenDaemonParseSxprChar(const char *value,
                       const char *tty)
{
    const char *prefix;
    char *tmp;
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    prefix = value;

    if (value[0] == '/') {
        def->source.type = VIR_DOMAIN_CHR_TYPE_DEV;
    } else {
        if ((tmp = strchr(value, ':')) != NULL) {
            *tmp = '\0';
            value = tmp + 1;
        }

        if (STRPREFIX(prefix, "telnet")) {
            def->source.type = VIR_DOMAIN_CHR_TYPE_TCP;
            def->source.data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        } else {
            if ((def->source.type = virDomainChrTypeFromString(prefix)) < 0) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("unknown chr device type '%s'"), prefix);
                goto error;
            }
        }
    }

    /* Compat with legacy  <console tty='/dev/pts/5'/> syntax */
    switch (def->source.type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (tty != NULL &&
            !(def->source.data.file.path = strdup(tty)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (!(def->source.data.file.path = strdup(value)))
            goto no_memory;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2;

        if (offset == NULL) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->source.data.tcp.host = strndup(value,
                                                 offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, ',');
        if (offset2 == NULL)
            def->source.data.tcp.service = strdup(offset+1);
        else
            def->source.data.tcp.service = strndup(offset+1,
                                                   offset2-(offset+1));
        if (def->source.data.tcp.service == NULL)
            goto no_memory;

        if (offset2 && strstr(offset2, ",server"))
            def->source.data.tcp.listen = true;
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
    {
        const char *offset = strchr(value, ':');
        const char *offset2, *offset3;

        if (offset == NULL) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("malformed char device string"));
            goto error;
        }

        if (offset != value &&
            (def->source.data.udp.connectHost
             = strndup(value, offset - value)) == NULL)
            goto no_memory;

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            if ((def->source.data.udp.connectService
                 = strndup(offset + 1, offset2-(offset+1))) == NULL)
                goto no_memory;

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1) &&
                (def->source.data.udp.bindHost
                 = strndup(offset2 + 1, offset3 - (offset2+1))) == NULL)
                goto no_memory;

            if ((def->source.data.udp.bindService
                 = strdup(offset3 + 1)) == NULL)
                goto no_memory;
        } else {
            if ((def->source.data.udp.connectService
                 = strdup(offset + 1)) == NULL)
                goto no_memory;
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (offset)
            def->source.data.nix.path = strndup(value, (offset - value));
        else
            def->source.data.nix.path = strdup(value);
        if (def->source.data.nix.path == NULL)
            goto no_memory;

        if (offset != NULL &&
            strstr(offset, ",server") != NULL)
            def->source.data.nix.listen = true;
    }
    break;
    }

    return def;

no_memory:
    virReportOOMError();
error:
    virDomainChrDefFree(def);
    return NULL;
}

/**
 * xend_parse_sexp_desc_disks
 * @conn: connection
 * @root: root sexpr
 * @xendConfigVersion: version of xend
 *
 * This parses out block devices from the domain sexpr
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenDaemonParseSxprDisks(virDomainDefPtr def,
                        const struct sexpr *root,
                        int hvm,
                        int xendConfigVersion)
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

            /* Again dealing with (vbd...) vs (tap ...) differences */
            if (sexpr_lookup(node, "device/vbd")) {
                src = sexpr_node(node, "device/vbd/uname");
                dst = sexpr_node(node, "device/vbd/dev");
                mode = sexpr_node(node, "device/vbd/mode");
            } else if (sexpr_lookup(node, "device/tap2")) {
                src = sexpr_node(node, "device/tap2/uname");
                dst = sexpr_node(node, "device/tap2/dev");
                mode = sexpr_node(node, "device/tap2/mode");
            } else {
                src = sexpr_node(node, "device/tap/uname");
                dst = sexpr_node(node, "device/tap/dev");
                mode = sexpr_node(node, "device/tap/mode");
            }

            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            if (dst == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("domain information incomplete, vbd has no dev"));
                goto error;
            }

            if (src == NULL) {
                /* There is a case without the uname to the CD-ROM device */
                offset = strchr(dst, ':');
                if (!offset ||
                    !hvm ||
                    STRNEQ(offset, ":cdrom")) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("domain information incomplete, vbd has no src"));
                    goto error;
                }
            }

            if (src != NULL) {
                offset = strchr(src, ':');
                if (!offset) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("cannot parse vbd filename, missing driver name"));
                    goto error;
                }

                if (VIR_ALLOC_N(disk->driverName, (offset-src)+1) < 0)
                    goto no_memory;
                if (virStrncpy(disk->driverName, src, offset-src,
                              (offset-src)+1) == NULL) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Driver name %s too big for destination"),
                                 src);
                    goto error;
                }

                src = offset + 1;

                if (STREQ (disk->driverName, "tap") ||
                    STREQ (disk->driverName, "tap2")) {
                    offset = strchr(src, ':');
                    if (!offset) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                     "%s", _("cannot parse vbd filename, missing driver type"));
                        goto error;
                    }

                    if (VIR_ALLOC_N(disk->driverType, (offset-src)+1)< 0)
                        goto no_memory;
                    if (virStrncpy(disk->driverType, src, offset-src,
                                   (offset-src)+1) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                     _("Driver type %s too big for destination"),
                                     src);
                        goto error;
                    }

                    src = offset + 1;
                    /* Its possible to use blktap driver for block devs
                       too, but kinda pointless because blkback is better,
                       so we assume common case here. If blktap becomes
                       omnipotent, we can revisit this, perhaps stat()'ing
                       the src file in question */
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                } else if (STREQ(disk->driverName, "phy")) {
                    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                } else if (STREQ(disk->driverName, "file")) {
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                }
            } else {
                /* No CDROM media so can't really tell. We'll just
                   call if a FILE for now and update when media
                   is inserted later */
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            }

            if (STREQLEN (dst, "ioemu:", 6))
                dst += 6;

            disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
            /* New style disk config from Xen >= 3.0.3 */
            if (xendConfigVersion > 1) {
                offset = strrchr(dst, ':');
                if (offset) {
                    if (STREQ (offset, ":cdrom")) {
                        disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                    } else if (STREQ (offset, ":disk")) {
                        /* The default anyway */
                    } else {
                        /* Unknown, lets pretend its a disk too */
                    }
                    offset[0] = '\0';
                }
            }

            if (!(disk->dst = strdup(dst)))
                goto no_memory;
            if (src &&
                !(disk->src = strdup(src)))
                goto no_memory;

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
                disk->readonly = 1;
            if (mode &&
                strchr(mode, '!'))
                disk->shared = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;

            def->disks[def->ndisks++] = disk;
            disk = NULL;
        }
    }

    return 0;

no_memory:
    virReportOOMError();

error:
    virDomainDiskDefFree(disk);
    return -1;
}


static int
xenDaemonParseSxprNets(virDomainDefPtr def,
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
            char buf[50];
            tmp2 = sexpr_node(node, "device/vif/script");
            tmp = sexpr_node(node, "device/vif/bridge");
            model = sexpr_node(node, "device/vif/model");
            type = sexpr_node(node, "device/vif/type");

            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            if (tmp != NULL ||
                (tmp2 != NULL && STREQ(tmp2, DEFAULT_VIF_SCRIPT))) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
                /* XXX virtual network reverse resolve */

                if (tmp &&
                    !(net->data.bridge.brname = strdup(tmp)))
                    goto no_memory;
                if (tmp2 &&
                    net->type == VIR_DOMAIN_NET_TYPE_BRIDGE &&
                    !(net->data.bridge.script = strdup(tmp2)))
                    goto no_memory;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp &&
                    !(net->data.bridge.ipaddr = strdup(tmp)))
                    goto no_memory;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
                if (tmp2 &&
                    !(net->data.ethernet.script = strdup(tmp2)))
                    goto no_memory;
                tmp = sexpr_node(node, "device/vif/ip");
                if (tmp &&
                    !(net->data.ethernet.ipaddr = strdup(tmp)))
                    goto no_memory;
            }

            tmp = sexpr_node(node, "device/vif/vifname");
            if (!tmp) {
                snprintf(buf, sizeof(buf), "vif%d.%d", def->id, vif_index);
                tmp = buf;
            }
            if (!(net->ifname = strdup(tmp)))
                goto no_memory;

            tmp = sexpr_node(node, "device/vif/mac");
            if (tmp) {
                if (virParseMacAddr(tmp, net->mac) < 0) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("malformed mac address '%s'"), tmp);
                    goto cleanup;
                }
            }

            if (model &&
                !(net->model = strdup(model)))
                goto no_memory;

            if (!model && type &&
                STREQ(type, "netfront") &&
                !(net->model = strdup("netfront")))
                goto no_memory;

            if (VIR_REALLOC_N(def->nets, def->nnets + 1) < 0)
                goto no_memory;

            def->nets[def->nnets++] = net;
            vif_index++;
        }
    }

    return 0;

no_memory:
    virReportOOMError();
cleanup:
    virDomainNetDefFree(net);
    return -1;
}


int
xenDaemonParseSxprSound(virDomainDefPtr def,
                        const char *str)
{
    if (STREQ(str, "all")) {
        int i;

        /*
         * Special compatability code for Xen with a bogus
         * sound=all in config.
         *
         * NB delibrately, don't include all possible
         * sound models anymore, just the 2 that were
         * historically present in Xen's QEMU.
         *
         * ie just es1370 + sb16.
         *
         * Hence use of MODEL_ES1370 + 1, instead of MODEL_LAST
         */

        if (VIR_ALLOC_N(def->sounds,
                        VIR_DOMAIN_SOUND_MODEL_ES1370 + 1) < 0)
            goto no_memory;


        for (i = 0 ; i < (VIR_DOMAIN_SOUND_MODEL_ES1370 + 1) ; i++) {
            virDomainSoundDefPtr sound;
            if (VIR_ALLOC(sound) < 0)
                goto no_memory;
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
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                 _("Sound model %s too big for destination"),
                             offset);
                goto error;
            }

            if (VIR_ALLOC(sound) < 0)
                goto no_memory;

            if ((sound->model = virDomainSoundModelTypeFromString(model)) < 0) {
                VIR_FREE(sound);
                goto error;
            }

            if (VIR_REALLOC_N(def->sounds, def->nsounds+1) < 0) {
                virDomainSoundDefFree(sound);
                goto no_memory;
            }

            def->sounds[def->nsounds++] = sound;
            offset = offset2 ? offset2 + 1 : NULL;
        } while (offset);
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}


static int
xenDaemonParseSxprUSB(virDomainDefPtr def,
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
                    STREQ(tmp, "mouse")) {
                    virDomainInputDefPtr input;
                    if (VIR_ALLOC(input) < 0)
                        goto no_memory;
                    input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                    if (STREQ(tmp, "tablet"))
                        input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                    else
                        input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;

                    if (VIR_REALLOC_N(def->inputs, def->ninputs+1) < 0) {
                        VIR_FREE(input);
                        goto no_memory;
                    }
                    def->inputs[def->ninputs++] = input;
                } else {
                    /* XXX Handle other non-input USB devices later */
                }
            }
        }
    }
    return 0;

no_memory:
    virReportOOMError();
    return -1;
}

static int
xenDaemonParseSxprGraphicsOld(virDomainDefPtr def,
                              const struct sexpr *root,
                              int hvm,
                              int xendConfigVersion, int vncport)
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
            goto no_memory;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
        /* For Xen >= 3.0.3, don't generate a fixed port mapping
         * because it will almost certainly be wrong ! Just leave
         * it as -1 which lets caller see that the VNC server isn't
         * present yet. Subsquent dumps of the XML will eventually
         * find the port in XenStore once VNC server has started
         */
        if (port == -1 && xendConfigVersion < 2)
            port = 5900 + def->id;

        if ((unused && STREQ(unused, "1")) || port == -1)
            graphics->data.vnc.autoport = 1;
        graphics->data.vnc.port = port;

        if (listenAddr &&
            !(graphics->data.vnc.listenAddr = strdup(listenAddr)))
            goto no_memory;

        if (vncPasswd &&
            !(graphics->data.vnc.auth.passwd = strdup(vncPasswd)))
            goto no_memory;

        if (keymap &&
            !(graphics->data.vnc.keymap = strdup(keymap)))
            goto no_memory;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto no_memory;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    } else if ((tmp = sexpr_fmt_node(root, "domain/image/%s/sdl", hvm ? "hvm" : "linux")) &&
               tmp[0] == '1') {
        /* Graphics device (HVM, or old (pre-3.0.4) style PV sdl config) */
        const char *display = sexpr_fmt_node(root, "domain/image/%s/display", hvm ? "hvm" : "linux");
        const char *xauth = sexpr_fmt_node(root, "domain/image/%s/xauthority", hvm ? "hvm" : "linux");

        if (VIR_ALLOC(graphics) < 0)
            goto no_memory;

        graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        if (display &&
            !(graphics->data.sdl.display = strdup(display)))
            goto no_memory;
        if (xauth &&
            !(graphics->data.sdl.xauth = strdup(xauth)))
            goto no_memory;

        if (VIR_ALLOC_N(def->graphics, 1) < 0)
            goto no_memory;
        def->graphics[0] = graphics;
        def->ngraphics = 1;
        graphics = NULL;
    }

    return 0;

no_memory:
    virReportOOMError();
    virDomainGraphicsDefFree(graphics);
    return -1;
}


static int
xenDaemonParseSxprGraphicsNew(virDomainDefPtr def,
                              const struct sexpr *root, int vncport)
{
    virDomainGraphicsDefPtr graphics = NULL;
    const struct sexpr *cur, *node;
    const char *tmp;

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
                goto no_memory;

            if ((graphics->type = virDomainGraphicsTypeFromString(tmp)) < 0) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                             _("unknown graphics type '%s'"), tmp);
                goto error;
            }

            if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                const char *display = sexpr_node(node, "device/vfb/display");
                const char *xauth = sexpr_node(node, "device/vfb/xauthority");
                if (display &&
                    !(graphics->data.sdl.display = strdup(display)))
                    goto no_memory;
                if (xauth &&
                    !(graphics->data.sdl.xauth = strdup(xauth)))
                    goto no_memory;
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
                    graphics->data.vnc.autoport = 1;

                if (port >= 0 && port < 5900)
                    port += 5900;
                graphics->data.vnc.port = port;

                if (listenAddr &&
                    !(graphics->data.vnc.listenAddr = strdup(listenAddr)))
                    goto no_memory;

                if (vncPasswd &&
                    !(graphics->data.vnc.auth.passwd = strdup(vncPasswd)))
                    goto no_memory;

                if (keymap &&
                    !(graphics->data.vnc.keymap = strdup(keymap)))
                    goto no_memory;
            }

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
            break;
        }
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    virDomainGraphicsDefFree(graphics);
    return -1;
}

/**
 * xenDaemonParseSxprPCI
 * @root: root sexpr
 *
 * This parses out block devices from the domain sexpr
 *
 * Returns 0 if successful or -1 if failed.
 */
static int
xenDaemonParseSxprPCI(virDomainDefPtr def,
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
     * wierd world of Xen PCI, once (device ...) covers multiple
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
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI domain"));
            goto error;
        }
        if (!(bus = sexpr_node(node, "dev/bus"))) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI bus"));
            goto error;
        }
        if (!(slot = sexpr_node(node, "dev/slot"))) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI slot"));
            goto error;
        }
        if (!(func = sexpr_node(node, "dev/func"))) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         "%s", _("missing PCI func"));
            goto error;
        }

        if (virStrToLong_i(domain, NULL, 0, &domainID) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI domain '%s'"), domain);
            goto error;
        }
        if (virStrToLong_i(bus, NULL, 0, &busID) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI bus '%s'"), bus);
            goto error;
        }
        if (virStrToLong_i(slot, NULL, 0, &slotID) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI slot '%s'"), slot);
            goto error;
        }
        if (virStrToLong_i(func, NULL, 0, &funcID) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("cannot parse PCI func '%s'"), func);
            goto error;
        }

        if (VIR_ALLOC(dev) < 0)
            goto no_memory;

        dev->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        dev->managed = 0;
        dev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
        dev->source.subsys.u.pci.domain = domainID;
        dev->source.subsys.u.pci.bus = busID;
        dev->source.subsys.u.pci.slot = slotID;
        dev->source.subsys.u.pci.function = funcID;

        if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
            goto no_memory;
        }

        def->hostdevs[def->nhostdevs++] = dev;
    }

    return 0;

no_memory:
    virReportOOMError();

error:
    virDomainHostdevDefFree(dev);
    return -1;
}


/**
 * xenDaemonParseSxpr:
 * @conn: the connection associated with the XML
 * @root: the root of the parsed S-Expression
 * @xendConfigVersion: version of xend
 * @cpus: set of cpus the domain may be pinned to
 *
 * Parse the xend sexp description and turn it into the XML format similar
 * to the one unsed for creation.
 *
 * Returns the 0 terminated XML string or NULL in case of error.
 *         the caller must free() the returned value.
 */
virDomainDefPtr
xenDaemonParseSxpr(const struct sexpr *root,
                   int xendConfigVersion,
                   const char *cpus, char *tty, int vncport)
{
    const char *tmp;
    virDomainDefPtr def;
    int hvm = 0;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    tmp = sexpr_node(root, "domain/domid");
    if (tmp == NULL && xendConfigVersion < 3) { /* Old XenD, domid was mandatory */
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing id"));
        goto error;
    }
    def->virtType = VIR_DOMAIN_VIRT_XEN;
    if (tmp)
        def->id = sexpr_int(root, "domain/domid");
    else
        def->id = -1;

    if (sexpr_node_copy(root, "domain/name", &def->name) < 0)
        goto no_memory;
    if (def->name == NULL) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing name"));
        goto error;
    }

    tmp = sexpr_node(root, "domain/uuid");
    if (tmp == NULL) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                     "%s", _("domain information incomplete, missing name"));
        goto error;
    }
    virUUIDParse(tmp, def->uuid);

    if (sexpr_node_copy(root, "domain/description", &def->description) < 0)
        goto no_memory;

    hvm = sexpr_lookup(root, "domain/image/hvm") ? 1 : 0;
    if (!hvm) {
        if (sexpr_node_copy(root, "domain/bootloader",
                            &def->os.bootloader) < 0)
            goto no_memory;

        if (!def->os.bootloader &&
            sexpr_has(root, "domain/bootloader") &&
            (def->os.bootloader = strdup("")) == NULL)
            goto no_memory;

        if (def->os.bootloader &&
            sexpr_node_copy(root, "domain/bootloader_args",
                            &def->os.bootloaderArgs) < 0)
            goto no_memory;
    }

    if (!(def->os.type = strdup(hvm ? "hvm" : "linux")))
        goto no_memory;

    if (def->id != 0) {
        if (sexpr_lookup(root, "domain/image")) {
            if (xenDaemonParseSxprOS(root, def, hvm) < 0)
                goto error;
        }
    }

    def->mem.max_balloon = (unsigned long)
                           (sexpr_u64(root, "domain/maxmem") << 10);
    def->mem.cur_balloon = (unsigned long)
                           (sexpr_u64(root, "domain/memory") << 10);
    if (def->mem.cur_balloon > def->mem.max_balloon)
        def->mem.cur_balloon = def->mem.max_balloon;

    if (cpus != NULL) {
        def->cpumasklen = VIR_DOMAIN_CPUMASK_LEN;
        if (VIR_ALLOC_N(def->cpumask, def->cpumasklen) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virDomainCpuSetParse(&cpus,
                                 0, def->cpumask,
                                 def->cpumasklen) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("invalid CPU mask %s"), cpus);
            goto error;
        }
    }

    def->maxvcpus = sexpr_int(root, "domain/vcpus");
    def->vcpus = count_one_bits_l(sexpr_u64(root, "domain/vcpu_avail"));
    if (!def->vcpus || def->maxvcpus < def->vcpus)
        def->vcpus = def->maxvcpus;

    tmp = sexpr_node(root, "domain/on_poweroff");
    if (tmp != NULL) {
        if ((def->onPoweroff = virDomainLifecycleTypeFromString(tmp)) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;

    tmp = sexpr_node(root, "domain/on_reboot");
    if (tmp != NULL) {
        if ((def->onReboot = virDomainLifecycleTypeFromString(tmp)) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;

    tmp = sexpr_node(root, "domain/on_crash");
    if (tmp != NULL) {
        if ((def->onCrash = virDomainLifecycleCrashTypeFromString(tmp)) < 0) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("unknown lifecycle type %s"), tmp);
            goto error;
        }
    } else
        def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;

    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
    if (hvm) {
        if (sexpr_int(root, "domain/image/hvm/acpi"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI);
        if (sexpr_int(root, "domain/image/hvm/apic"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_APIC);
        if (sexpr_int(root, "domain/image/hvm/pae"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
        if (sexpr_int(root, "domain/image/hvm/hap"))
            def->features |= (1 << VIR_DOMAIN_FEATURE_HAP);

        /* Old XenD only allows localtime here for HVM */
        if (sexpr_int(root, "domain/image/hvm/localtime"))
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
    }

    /* Current XenD allows localtime here, for PV and HVM */
    if (sexpr_int(root, "domain/localtime"))
        def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;

    if (sexpr_node_copy(root, hvm ?
                        "domain/image/hvm/device_model" :
                        "domain/image/linux/device_model",
                        &def->emulator) < 0)
        goto no_memory;

    /* append block devices */
    if (xenDaemonParseSxprDisks(def, root, hvm, xendConfigVersion) < 0)
        goto error;

    if (xenDaemonParseSxprNets(def, root) < 0)
        goto error;

    if (xenDaemonParseSxprPCI(def, root) < 0)
        goto error;

    /* New style graphics device config */
    if (xenDaemonParseSxprGraphicsNew(def, root, vncport) < 0)
        goto error;

    /* Graphics device (HVM <= 3.0.4, or PV <= 3.0.3) vnc config */
    if ((def->ngraphics == 0) &&
        xenDaemonParseSxprGraphicsOld(def, root, hvm, xendConfigVersion,
                                      vncport) < 0)
        goto error;


    /* Old style cdrom config from Xen <= 3.0.2 */
    if (hvm &&
        xendConfigVersion == 1) {
        tmp = sexpr_node(root, "domain/image/hvm/cdrom");
        if ((tmp != NULL) && (tmp[0] != 0)) {
            virDomainDiskDefPtr disk;
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;
            if (!(disk->src = strdup(tmp))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (!(disk->dst = strdup("hdc"))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            if (!(disk->driverName = strdup("file"))) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;
        }
    }


    /* Floppy disk config */
    if (hvm) {
        const char *const fds[] = { "fda", "fdb" };
        int i;
        for (i = 0 ; i < ARRAY_CARDINALITY(fds) ; i++) {
            tmp = sexpr_fmt_node(root, "domain/image/hvm/%s", fds[i]);
            if ((tmp != NULL) && (tmp[0] != 0)) {
                virDomainDiskDefPtr disk;
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                if (!(disk->src = strdup(tmp))) {
                    VIR_FREE(disk);
                    goto no_memory;
                }
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                if (!(disk->dst = strdup(fds[i]))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (!(disk->driverName = strdup("file"))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                disk->bus = VIR_DOMAIN_DISK_BUS_FDC;

                if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                def->disks[def->ndisks++] = disk;
            }
        }
    }

    /* in case of HVM we have USB device emulation */
    if (hvm &&
        xenDaemonParseSxprUSB(def, root) < 0)
        goto error;

    /* Character device config */
    if (hvm) {
        tmp = sexpr_node(root, "domain/image/hvm/serial");
        if (tmp && STRNEQ(tmp, "none")) {
            virDomainChrDefPtr chr;
            if ((chr = xenDaemonParseSxprChar(tmp, tty)) == NULL)
                goto error;
            if (VIR_REALLOC_N(def->serials, def->nserials+1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
            def->serials[def->nserials++] = chr;
        }
        tmp = sexpr_node(root, "domain/image/hvm/parallel");
        if (tmp && STRNEQ(tmp, "none")) {
            virDomainChrDefPtr chr;
            /* XXX does XenD stuff parallel port tty info into xenstore somewhere ? */
            if ((chr = xenDaemonParseSxprChar(tmp, NULL)) == NULL)
                goto error;
            if (VIR_REALLOC_N(def->parallels, def->nparallels+1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            def->parallels[def->nparallels++] = chr;
        }
    } else {
        /* Fake a paravirt console, since that's not in the sexpr */
        if (!(def->console = xenDaemonParseSxprChar("pty", tty)))
            goto error;
        def->console->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->console->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
    }
    VIR_FREE(tty);


    /* Sound device config */
    if (hvm &&
        (tmp = sexpr_node(root, "domain/image/hvm/soundhw")) != NULL &&
        *tmp) {
        if (xenDaemonParseSxprSound(def, tmp) < 0)
            goto error;
    }

    return def;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(tty);
    virDomainDefFree(def);
    return NULL;
}

virDomainDefPtr
xenDaemonParseSxprString(const char *sexpr,
                         int xendConfigVersion, char *tty, int vncport)
{
    struct sexpr *root = string2sexpr(sexpr);
    virDomainDefPtr def;

    if (!root)
        return NULL;

    def = xenDaemonParseSxpr(root, xendConfigVersion, NULL, tty, vncport);

    sexpr_free(root);

    return def;
}