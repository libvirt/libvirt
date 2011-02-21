/*
 * xen_xm.c: Xen XM parsing functions
 *
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * Author: Markus Groß <gross@univention.de>
 */

#include <config.h>

#include "internal.h"
#include "virterror_internal.h"
#include "conf.h"
#include "memory.h"
#include "verify.h"
#include "uuid.h"
#include "sexpr.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_xm.h"
#include "xen_sxpr.h"

/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetBool(virConfPtr conf,
                              const char *name,
                              int *value,
                              int def) {
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_LONG) {
        *value = val->l ? 1 : 0;
    } else if (val->type == VIR_CONF_STRING) {
        *value = STREQ(val->str, "1") ? 1 : 0;
    } else {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetULong(virConfPtr conf,
                               const char *name,
                               unsigned long *value,
                               int def) {
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_LONG) {
        *value = val->l;
    } else if (val->type == VIR_CONF_STRING) {
        char *ret;
        *value = strtol(val->str, &ret, 10);
        if (ret == val->str) {
            XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was malformed"), name);
            return -1;
        }
    } else {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a string from the config file object */
static int xenXMConfigGetString(virConfPtr conf,
                                const char *name,
                                const char **value,
                                const char *def) {
    virConfValuePtr val;

    *value = NULL;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type != VIR_CONF_STRING) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was malformed"), name);
        return -1;
    }
    if (!val->str)
        *value = def;
    else
        *value = val->str;
    return 0;
}

static int xenXMConfigCopyStringInternal(virConfPtr conf,
                                         const char *name,
                                         char **value,
                                         int allowMissing) {
    virConfValuePtr val;

    *value = NULL;
    if (!(val = virConfGetValue(conf, name))) {
        if (allowMissing)
            return 0;
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was missing"), name);
        return -1;
    }

    if (val->type != VIR_CONF_STRING) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was not a string"), name);
        return -1;
    }
    if (!val->str) {
        if (allowMissing)
            return 0;
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("config value %s was missing"), name);
        return -1;
    }

    if (!(*value = strdup(val->str))) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


static int xenXMConfigCopyString(virConfPtr conf,
                                 const char *name,
                                 char **value) {
    return xenXMConfigCopyStringInternal(conf, name, value, 0);
}

static int xenXMConfigCopyStringOpt(virConfPtr conf,
                                    const char *name,
                                    char **value) {
    return xenXMConfigCopyStringInternal(conf, name, value, 1);
}


/* Convenience method to grab a string UUID from the config file object */
static int xenXMConfigGetUUID(virConfPtr conf, const char *name, unsigned char *uuid) {
    virConfValuePtr val;
    if (!uuid || !name || !conf)
        return (-1);
    if (!(val = virConfGetValue(conf, name))) {
        return (-1);
    }

    if (val->type != VIR_CONF_STRING)
        return (-1);
    if (!val->str)
        return (-1);

    if (virUUIDParse(val->str, uuid) < 0)
        return (-1);

    return (0);
}

#define MAX_VFB 1024
/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateXML
 */
virDomainDefPtr
xenXMDomainConfigParse(virConfPtr conf, int xendConfigVersion,
                       virCapsPtr caps) {
    const char *str;
    int hvm = 0;
    int val;
    virConfValuePtr list;
    virDomainDefPtr def = NULL;
    virDomainDiskDefPtr disk = NULL;
    virDomainNetDefPtr net = NULL;
    virDomainGraphicsDefPtr graphics = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    int i;
    const char *defaultArch, *defaultMachine;
    int vmlocaltime = 0;
    unsigned long count;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenXMConfigCopyString(conf, "name", &def->name) < 0)
        goto cleanup;
    if (xenXMConfigGetUUID(conf, "uuid", def->uuid) < 0)
        goto cleanup;


    if ((xenXMConfigGetString(conf, "builder", &str, "linux") == 0) &&
        STREQ(str, "hvm"))
        hvm = 1;

    if (!(def->os.type = strdup(hvm ? "hvm" : "xen")))
        goto no_memory;

    defaultArch = virCapabilitiesDefaultGuestArch(caps, def->os.type, virDomainVirtTypeToString(def->virtType));
    if (defaultArch == NULL) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("no supported architecture for os type '%s'"),
                   def->os.type);
        goto cleanup;
    }
    if (!(def->os.arch = strdup(defaultArch)))
        goto no_memory;

    defaultMachine = virCapabilitiesDefaultGuestMachine(caps,
                                                        def->os.type,
                                                        def->os.arch,
                                                        virDomainVirtTypeToString(def->virtType));
    if (defaultMachine != NULL) {
        if (!(def->os.machine = strdup(defaultMachine)))
            goto no_memory;
    }

    if (hvm) {
        const char *boot;
        if (xenXMConfigCopyString(conf, "kernel", &def->os.loader) < 0)
            goto cleanup;

        if (xenXMConfigGetString(conf, "boot", &boot, "c") < 0)
            goto cleanup;

        for (i = 0 ; i < VIR_DOMAIN_BOOT_LAST && boot[i] ; i++) {
            switch (*boot) {
            case 'a':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_FLOPPY;
                break;
            case 'd':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_CDROM;
                break;
            case 'n':
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_NET;
                break;
            case 'c':
            default:
                def->os.bootDevs[i] = VIR_DOMAIN_BOOT_DISK;
                break;
            }
            def->os.nBootDevs++;
        }
    } else {
        if (xenXMConfigCopyStringOpt(conf, "bootloader", &def->os.bootloader) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conf, "bootargs", &def->os.bootloaderArgs) < 0)
            goto cleanup;

        if (xenXMConfigCopyStringOpt(conf, "kernel", &def->os.kernel) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conf, "ramdisk", &def->os.initrd) < 0)
            goto cleanup;
        if (xenXMConfigCopyStringOpt(conf, "extra", &def->os.cmdline) < 0)
            goto cleanup;
    }

    if (xenXMConfigGetULong(conf, "memory", &def->mem.cur_balloon,
                            MIN_XEN_GUEST_SIZE * 2) < 0)
        goto cleanup;

    if (xenXMConfigGetULong(conf, "maxmem", &def->mem.max_balloon,
                            def->mem.cur_balloon) < 0)
        goto cleanup;

    def->mem.cur_balloon *= 1024;
    def->mem.max_balloon *= 1024;

    if (xenXMConfigGetULong(conf, "vcpus", &count, 1) < 0 ||
        MAX_VIRT_CPUS < count)
        goto cleanup;
    def->maxvcpus = count;
    if (xenXMConfigGetULong(conf, "vcpu_avail", &count, -1) < 0)
        goto cleanup;
    def->vcpus = MIN(count_one_bits_l(count), def->maxvcpus);

    if (xenXMConfigGetString(conf, "cpus", &str, NULL) < 0)
        goto cleanup;
    if (str) {
        def->cpumasklen = 4096;
        if (VIR_ALLOC_N(def->cpumask, def->cpumasklen) < 0)
            goto no_memory;

        if (virDomainCpuSetParse(&str, 0,
                                 def->cpumask, def->cpumasklen) < 0)
            goto cleanup;
    }


    if (xenXMConfigGetString(conf, "on_poweroff", &str, "destroy") < 0)
        goto cleanup;
    if ((def->onPoweroff = virDomainLifecycleTypeFromString(str)) < 0) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_poweroff"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conf, "on_reboot", &str, "restart") < 0)
        goto cleanup;
    if ((def->onReboot = virDomainLifecycleTypeFromString(str)) < 0) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_reboot"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conf, "on_crash", &str, "restart") < 0)
        goto cleanup;
    if ((def->onCrash = virDomainLifecycleCrashTypeFromString(str)) < 0) {
        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                   _("unexpected value %s for on_crash"), str);
        goto cleanup;
    }



    if (hvm) {
        if (xenXMConfigGetBool(conf, "pae", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
        if (xenXMConfigGetBool(conf, "acpi", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI);
        if (xenXMConfigGetBool(conf, "apic", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_APIC);
        if (xenXMConfigGetBool(conf, "hap", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features |= (1 << VIR_DOMAIN_FEATURE_HAP);
    }
    if (xenXMConfigGetBool(conf, "localtime", &vmlocaltime, 0) < 0)
        goto cleanup;

    def->clock.offset = vmlocaltime ?
        VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME :
        VIR_DOMAIN_CLOCK_OFFSET_UTC;

    if (xenXMConfigCopyStringOpt(conf, "device_model", &def->emulator) < 0)
        goto cleanup;

    list = virConfGetValue(conf, "disk");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char *head;
            char *offset;
            char *tmp;

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipdisk;
            head = list->str;

            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            /*
             * Disks have 3 components, SOURCE,DEST-DEVICE,MODE
             * eg, phy:/dev/HostVG/XenGuest1,xvda,w
             * The SOURCE is usually prefixed with a driver type,
             * and optionally driver sub-type
             * The DEST-DEVICE is optionally post-fixed with disk type
             */

            /* Extract the source file path*/
            if (!(offset = strchr(head, ',')))
                goto skipdisk;
            if ((offset - head) >= (PATH_MAX-1))
                goto skipdisk;

            if (offset == head) {
                disk->src = NULL; /* No source file given, eg CDROM with no media */
            } else {
                if (VIR_ALLOC_N(disk->src, (offset - head) + 1) < 0)
                    goto no_memory;
                if (virStrncpy(disk->src, head, offset - head,
                               (offset - head) + 1) == NULL) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                               _("Source file %s too big for destination"),
                               head);
                    goto cleanup;
                }
            }
            head = offset + 1;

            /* Remove legacy ioemu: junk */
            if (STRPREFIX(head, "ioemu:"))
                head = head + 6;

            /* Extract the dest device name */
            if (!(offset = strchr(head, ',')))
                goto skipdisk;
            if (VIR_ALLOC_N(disk->dst, (offset - head) + 1) < 0)
                goto no_memory;
            if (virStrncpy(disk->dst, head, offset - head,
                           (offset - head) + 1) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("Dest file %s too big for destination"), head);
                goto cleanup;
            }
            head = offset + 1;


            /* Extract source driver type */
            if (disk->src) {
                /* The main type  phy:, file:, tap: ... */
                if ((tmp = strchr(disk->src, ':')) != NULL) {
                    if (VIR_ALLOC_N(disk->driverName, (tmp - disk->src) + 1) < 0)
                        goto no_memory;
                    if (virStrncpy(disk->driverName, disk->src,
                                   (tmp - disk->src),
                                   (tmp - disk->src) + 1) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Driver name %s too big for destination"),
                                   disk->src);
                        goto cleanup;
                    }

                    /* Strip the prefix we found off the source file name */
                    memmove(disk->src, disk->src+(tmp-disk->src)+1,
                            strlen(disk->src)-(tmp-disk->src));
                }

                /* And the sub-type for tap:XXX: type */
                if (disk->driverName &&
                    STREQ(disk->driverName, "tap")) {
                    if (!(tmp = strchr(disk->src, ':')))
                        goto skipdisk;
                    if (VIR_ALLOC_N(disk->driverType, (tmp - disk->src) + 1) < 0)
                        goto no_memory;
                    if (virStrncpy(disk->driverType, disk->src,
                                   (tmp - disk->src),
                                   (tmp - disk->src) + 1) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Driver type %s too big for destination"),
                                   disk->src);
                        goto cleanup;
                    }

                    /* Strip the prefix we found off the source file name */
                    memmove(disk->src, disk->src+(tmp-disk->src)+1,
                            strlen(disk->src)-(tmp-disk->src));
                }
            }

            /* No source, or driver name, so fix to phy: */
            if (!disk->driverName &&
                !(disk->driverName = strdup("phy")))
                goto no_memory;


            /* phy: type indicates a block device */
            disk->type = STREQ(disk->driverName, "phy") ?
                VIR_DOMAIN_DISK_TYPE_BLOCK : VIR_DOMAIN_DISK_TYPE_FILE;

            /* Check for a :cdrom/:disk postfix */
            disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
            if ((tmp = strchr(disk->dst, ':')) != NULL) {
                if (STREQ(tmp, ":cdrom"))
                    disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                tmp[0] = '\0';
            }

            if (STRPREFIX(disk->dst, "xvd") || !hvm) {
                disk->bus = VIR_DOMAIN_DISK_BUS_XEN;
            } else if (STRPREFIX(disk->dst, "sd")) {
                disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            } else {
                disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            }

            if (STREQ(head, "r") ||
                STREQ(head, "ro"))
                disk->readonly = 1;
            else if ((STREQ(head, "w!")) ||
                     (STREQ(head, "!")))
                disk->shared = 1;

            /* Maintain list in sorted order according to target device name */
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            def->disks[def->ndisks++] = disk;
            disk = NULL;

            skipdisk:
            list = list->next;
            virDomainDiskDefFree(disk);
        }
    }

    if (hvm && xendConfigVersion == 1) {
        if (xenXMConfigGetString(conf, "cdrom", &str, NULL) < 0)
            goto cleanup;
        if (str) {
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (!(disk->driverName = strdup("file")))
                goto no_memory;
            if (!(disk->src = strdup(str)))
                goto no_memory;
            if (!(disk->dst = strdup("hdc")))
                goto no_memory;
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = 1;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            def->disks[def->ndisks++] = disk;
            disk = NULL;
        }
    }

    list = virConfGetValue(conf, "vif");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char script[PATH_MAX];
            char model[10];
            char type[10];
            char ip[16];
            char mac[18];
            char bridge[50];
            char vifname[50];
            char *key;

            bridge[0] = '\0';
            mac[0] = '\0';
            script[0] = '\0';
            ip[0] = '\0';
            model[0] = '\0';
            type[0] = '\0';
            vifname[0] = '\0';

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skipnic;

            key = list->str;
            while (key) {
                char *data;
                char *nextkey = strchr(key, ',');

                if (!(data = strchr(key, '=')))
                    goto skipnic;
                data++;

                if (STRPREFIX(key, "mac=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(mac) - 1;
                    if (virStrncpy(mac, data, len, sizeof(mac)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("MAC address %s too big for destination"),
                                   data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "bridge=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(bridge) - 1;
                    if (virStrncpy(bridge, data, len, sizeof(bridge)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Bridge %s too big for destination"),
                                   data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "script=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(script) - 1;
                    if (virStrncpy(script, data, len, sizeof(script)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Script %s too big for destination"),
                                   data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "model=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(model) - 1;
                    if (virStrncpy(model, data, len, sizeof(model)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Model %s too big for destination"), data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "type=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(type) - 1;
                    if (virStrncpy(type, data, len, sizeof(type)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Type %s too big for destination"), data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "vifname=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(vifname) - 1;
                    if (virStrncpy(vifname, data, len, sizeof(vifname)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("Vifname %s too big for destination"),
                                   data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "ip=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(ip) - 1;
                    if (virStrncpy(ip, data, len, sizeof(ip)) == NULL) {
                        XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                                   _("IP %s too big for destination"), data);
                        goto skipnic;
                    }
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }

            if (VIR_ALLOC(net) < 0)
                goto no_memory;

            if (mac[0]) {
                if (virParseMacAddr(mac, net->mac) < 0) {
                    XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                               _("malformed mac address '%s'"), mac);
                    goto cleanup;
                }
            }

            if (bridge[0] || STREQ(script, "vif-bridge") ||
                STREQ(script, "vif-vnic")) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            }

            if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                if (bridge[0] &&
                    !(net->data.bridge.brname = strdup(bridge)))
                    goto no_memory;
                if (script[0] &&
                    !(net->data.bridge.script = strdup(script)))
                    goto no_memory;
                if (ip[0] &&
                    !(net->data.bridge.ipaddr = strdup(ip)))
                    goto no_memory;
            } else {
                if (script[0] &&
                    !(net->data.ethernet.script = strdup(script)))
                    goto no_memory;
                if (ip[0] &&
                    !(net->data.ethernet.ipaddr = strdup(ip)))
                    goto no_memory;
            }

            if (model[0] &&
                !(net->model = strdup(model)))
                goto no_memory;

            if (!model[0] && type[0] &&
                STREQ(type, "netfront") &&
                !(net->model = strdup("netfront")))
                goto no_memory;

            if (vifname[0] &&
                !(net->ifname = strdup(vifname)))
                goto no_memory;

            if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0)
                goto no_memory;
            def->nets[def->nnets++] = net;
            net = NULL;

        skipnic:
            list = list->next;
            virDomainNetDefFree(net);
        }
    }

    list = virConfGetValue(conf, "pci");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char domain[5];
            char bus[3];
            char slot[3];
            char func[2];
            char *key, *nextkey;
            int domainID;
            int busID;
            int slotID;
            int funcID;

            domain[0] = bus[0] = slot[0] = func[0] = '\0';

            if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                goto skippci;

            /* pci=['0000:00:1b.0','0000:00:13.0'] */
            if (!(key = list->str))
                goto skippci;
            if (!(nextkey = strchr(key, ':')))
                goto skippci;

            if (virStrncpy(domain, key, (nextkey - key), sizeof(domain)) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("Domain %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (!(nextkey = strchr(key, ':')))
                goto skippci;

            if (virStrncpy(bus, key, (nextkey - key), sizeof(bus)) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("Bus %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (!(nextkey = strchr(key, '.')))
                goto skippci;

            if (virStrncpy(slot, key, (nextkey - key), sizeof(slot)) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("Slot %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (strlen(key) != 1)
                goto skippci;

            if (virStrncpy(func, key, 1, sizeof(func)) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("Function %s too big for destination"), key);
                goto skippci;
            }

            if (virStrToLong_i(domain, NULL, 16, &domainID) < 0)
                goto skippci;
            if (virStrToLong_i(bus, NULL, 16, &busID) < 0)
                goto skippci;
            if (virStrToLong_i(slot, NULL, 16, &slotID) < 0)
                goto skippci;
            if (virStrToLong_i(func, NULL, 16, &funcID) < 0)
                goto skippci;

            if (VIR_ALLOC(hostdev) < 0)
                goto no_memory;

            hostdev->managed = 0;
            hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
            hostdev->source.subsys.u.pci.domain = domainID;
            hostdev->source.subsys.u.pci.bus = busID;
            hostdev->source.subsys.u.pci.slot = slotID;
            hostdev->source.subsys.u.pci.function = funcID;

            if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0)
                goto no_memory;
            def->hostdevs[def->nhostdevs++] = hostdev;
            hostdev = NULL;

        skippci:
            list = list->next;
        }
    }

    if (hvm) {
        if (xenXMConfigGetString(conf, "usbdevice", &str, NULL) < 0)
            goto cleanup;
        if (str &&
            (STREQ(str, "tablet") ||
             STREQ(str, "mouse"))) {
            virDomainInputDefPtr input;
            if (VIR_ALLOC(input) < 0)
                goto no_memory;
            input->bus = VIR_DOMAIN_INPUT_BUS_USB;
            input->type = STREQ(str, "tablet") ?
                VIR_DOMAIN_INPUT_TYPE_TABLET :
                VIR_DOMAIN_INPUT_TYPE_MOUSE;
            if (VIR_ALLOC_N(def->inputs, 1) < 0) {
                virDomainInputDefFree(input);
                goto no_memory;
            }
            def->inputs[0] = input;
            def->ninputs = 1;
        }
    }

    /* HVM guests, or old PV guests use this config format */
    if (hvm || xendConfigVersion < 3) {
        if (xenXMConfigGetBool(conf, "vnc", &val, 0) < 0)
            goto cleanup;

        if (val) {
            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
            if (xenXMConfigGetBool(conf, "vncunused", &val, 1) < 0)
                goto cleanup;
            graphics->data.vnc.autoport = val ? 1 : 0;

            if (!graphics->data.vnc.autoport) {
                unsigned long vncdisplay;
                if (xenXMConfigGetULong(conf, "vncdisplay", &vncdisplay, 0) < 0)
                    goto cleanup;
                graphics->data.vnc.port = (int)vncdisplay + 5900;
            }
            if (xenXMConfigCopyStringOpt(conf, "vnclisten", &graphics->data.vnc.listenAddr) < 0)
                goto cleanup;
            if (xenXMConfigCopyStringOpt(conf, "vncpasswd", &graphics->data.vnc.auth.passwd) < 0)
                goto cleanup;
            if (xenXMConfigCopyStringOpt(conf, "keymap", &graphics->data.vnc.keymap) < 0)
                goto cleanup;

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        } else {
            if (xenXMConfigGetBool(conf, "sdl", &val, 0) < 0)
                goto cleanup;
            if (val) {
                if (VIR_ALLOC(graphics) < 0)
                    goto no_memory;
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                if (xenXMConfigCopyStringOpt(conf, "display", &graphics->data.sdl.display) < 0)
                    goto cleanup;
                if (xenXMConfigCopyStringOpt(conf, "xauthority", &graphics->data.sdl.xauth) < 0)
                    goto cleanup;
                if (VIR_ALLOC_N(def->graphics, 1) < 0)
                    goto no_memory;
                def->graphics[0] = graphics;
                def->ngraphics = 1;
                graphics = NULL;
            }
        }
    }

    if (!hvm && def->graphics == NULL) { /* New PV guests use this format */
        list = virConfGetValue(conf, "vfb");
        if (list && list->type == VIR_CONF_LIST &&
            list->list && list->list->type == VIR_CONF_STRING &&
            list->list->str) {
            char vfb[MAX_VFB];
            char *key = vfb;

            if (virStrcpyStatic(vfb, list->list->str) == NULL) {
                XENXS_ERROR(VIR_ERR_INTERNAL_ERROR,
                           _("VFB %s too big for destination"),
                           list->list->str);
                goto cleanup;
            }

            if (VIR_ALLOC(graphics) < 0)
                goto no_memory;

            if (strstr(key, "type=sdl"))
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
            else
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

            while (key) {
                char *nextkey = strchr(key, ',');
                char *end = nextkey;
                if (nextkey) {
                    *end = '\0';
                    nextkey++;
                }

                if (!strchr(key, '='))
                    break;

                if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
                    if (STRPREFIX(key, "vncunused=")) {
                        if (STREQ(key + 10, "1"))
                            graphics->data.vnc.autoport = 1;
                    } else if (STRPREFIX(key, "vnclisten=")) {
                        if (!(graphics->data.vnc.listenAddr = strdup(key + 10)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "vncpasswd=")) {
                        if (!(graphics->data.vnc.auth.passwd = strdup(key + 10)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "keymap=")) {
                        if (!(graphics->data.vnc.keymap = strdup(key + 7)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "vncdisplay=")) {
                        graphics->data.vnc.port = strtol(key+11, NULL, 10) + 5900;
                    }
                } else {
                    if (STRPREFIX(key, "display=")) {
                        if (!(graphics->data.sdl.display = strdup(key + 8)))
                            goto no_memory;
                    } else if (STRPREFIX(key, "xauthority=")) {
                        if (!(graphics->data.sdl.xauth = strdup(key + 11)))
                            goto no_memory;
                    }
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }
            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto no_memory;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        }
    }

    if (hvm) {
        virDomainChrDefPtr chr = NULL;

        if (xenXMConfigGetString(conf, "parallel", &str, NULL) < 0)
            goto cleanup;
        if (str && STRNEQ(str, "none") &&
            !(chr = xenDaemonParseSxprChar(str, NULL)))
            goto cleanup;

        if (chr) {
            if (VIR_ALLOC_N(def->parallels, 1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            def->parallels[0] = chr;
            def->nparallels++;
            chr = NULL;
        }

        if (xenXMConfigGetString(conf, "serial", &str, NULL) < 0)
            goto cleanup;
        if (str && STRNEQ(str, "none") &&
            !(chr = xenDaemonParseSxprChar(str, NULL)))
            goto cleanup;

        if (chr) {
            if (VIR_ALLOC_N(def->serials, 1) < 0) {
                virDomainChrDefFree(chr);
                goto no_memory;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
            def->serials[0] = chr;
            def->nserials++;
        }
    } else {
        if (!(def->console = xenDaemonParseSxprChar("pty", NULL)))
            goto cleanup;
        def->console->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->console->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
    }

    if (hvm) {
        if (xenXMConfigGetString(conf, "soundhw", &str, NULL) < 0)
            goto cleanup;

        if (str &&
            xenDaemonParseSxprSound(def, str) < 0)
            goto cleanup;
    }

    return def;

no_memory:
    virReportOOMError();
    /* fallthrough */
cleanup:
    virDomainGraphicsDefFree(graphics);
    virDomainNetDefFree(net);
    virDomainDiskDefFree(disk);
    virDomainDefFree(def);
    return NULL;
}
