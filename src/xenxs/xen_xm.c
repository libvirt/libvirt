/*
 * xen_xm.c: Xen XM parsing functions
 *
 * Copyright (C) 2006-2007, 2009-2010, 2012-2013 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
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
 * Author: Markus Groß <gross@univention.de>
 */

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "verify.h"
#include "viruuid.h"
#include "virsexpr.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "xen_xm.h"
#include "xen_sxpr.h"
#include "domain_conf.h"
#include "virstoragefile.h"
#include "virstring.h"

/* Convenience method to grab a long int from the config file object */
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetULong(virConfPtr conf,
                               const char *name,
                               unsigned long *value,
                               unsigned long def) {
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
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("config value %s was malformed"), name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was malformed"), name);
        return -1;
    }
    return 0;
}


/* Convenience method to grab a int from the config file object */
static int xenXMConfigGetULongLong(virConfPtr conf,
                                   const char *name,
                                   unsigned long long *value,
                                   unsigned long long def) {
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
        *value = strtoll(val->str, &ret, 10);
        if (ret == val->str) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("config value %s was malformed"), name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was missing"), name);
        return -1;
    }

    if (val->type != VIR_CONF_STRING) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was not a string"), name);
        return -1;
    }
    if (!val->str) {
        if (allowMissing)
            return 0;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was missing"), name);
        return -1;
    }

    return VIR_STRDUP(*value, val->str);
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

    if (!uuid || !name || !conf) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Arguments must be non null"));
        return -1;
    }

    if (!(val = virConfGetValue(conf, name))) {
        if (virUUIDGenerate(uuid)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            return -1;
        } else {
            return 0;
        }
    }

    if (val->type != VIR_CONF_STRING) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("config value %s not a string"), name);
        return -1;
    }

    if (!val->str) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s can't be empty"), name);
        return -1;
    }

    if (virUUIDParse(val->str, uuid) < 0) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s not parseable"), val->str);
        return -1;
    }

    return 0;
}

#define MAX_VFB 1024
/*
 * Turn a config record into a lump of XML describing the
 * domain, suitable for later feeding for virDomainCreateXML
 */
virDomainDefPtr
xenParseXM(virConfPtr conf, int xendConfigVersion,
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
    size_t i;
    const char *defaultMachine;
    int vmlocaltime = 0;
    unsigned long count;
    char *script = NULL;
    char *listenAddr = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    def->virtType = VIR_DOMAIN_VIRT_XEN;
    def->id = -1;

    if (xenXMConfigCopyString(conf, "name", &def->name) < 0)
        goto cleanup;
    if (xenXMConfigGetUUID(conf, "uuid", def->uuid) < 0)
        goto cleanup;


    if ((xenXMConfigGetString(conf, "builder", &str, "linux") == 0) &&
        STREQ(str, "hvm"))
        hvm = 1;

    if (VIR_STRDUP(def->os.type, hvm ? "hvm" : "xen") < 0)
        goto cleanup;

    def->os.arch =
        virCapabilitiesDefaultGuestArch(caps,
                                        def->os.type,
                                        virDomainVirtTypeToString(def->virtType));
    if (!def->os.arch) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no supported architecture for os type '%s'"),
                       def->os.type);
        goto cleanup;
    }

    defaultMachine = virCapabilitiesDefaultGuestMachine(caps,
                                                        def->os.type,
                                                        def->os.arch,
                                                        virDomainVirtTypeToString(def->virtType));
    if (defaultMachine != NULL) {
        if (VIR_STRDUP(def->os.machine, defaultMachine) < 0)
            goto cleanup;
    }

    if (hvm) {
        const char *boot;
        if (xenXMConfigCopyString(conf, "kernel", &def->os.loader) < 0)
            goto cleanup;

        if (xenXMConfigGetString(conf, "boot", &boot, "c") < 0)
            goto cleanup;

        for (i = 0; i < VIR_DOMAIN_BOOT_LAST && boot[i]; i++) {
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

    if (xenXMConfigGetULongLong(conf, "memory", &def->mem.cur_balloon,
                                MIN_XEN_GUEST_SIZE * 2) < 0)
        goto cleanup;

    if (xenXMConfigGetULongLong(conf, "maxmem", &def->mem.max_balloon,
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
    if (str && (virBitmapParse(str, 0, &def->cpumask, 4096) < 0))
            goto cleanup;

    if (xenXMConfigGetString(conf, "on_poweroff", &str, "destroy") < 0)
        goto cleanup;
    if ((def->onPoweroff = virDomainLifecycleTypeFromString(str)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_poweroff"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conf, "on_reboot", &str, "restart") < 0)
        goto cleanup;
    if ((def->onReboot = virDomainLifecycleTypeFromString(str)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_reboot"), str);
        goto cleanup;
    }

    if (xenXMConfigGetString(conf, "on_crash", &str, "restart") < 0)
        goto cleanup;
    if ((def->onCrash = virDomainLifecycleCrashTypeFromString(str)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_crash"), str);
        goto cleanup;
    }



    if (hvm) {
        if (xenXMConfigGetBool(conf, "pae", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_DOMAIN_FEATURE_STATE_ON;
        if (xenXMConfigGetBool(conf, "acpi", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_DOMAIN_FEATURE_STATE_ON;
        if (xenXMConfigGetBool(conf, "apic", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features[VIR_DOMAIN_FEATURE_APIC] = VIR_DOMAIN_FEATURE_STATE_ON;
        if (xenXMConfigGetBool(conf, "hap", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features[VIR_DOMAIN_FEATURE_HAP] = VIR_DOMAIN_FEATURE_STATE_ON;
        if (xenXMConfigGetBool(conf, "viridian", &val, 0) < 0)
            goto cleanup;
        else if (val)
            def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] = VIR_DOMAIN_FEATURE_STATE_ON;

        if (xenXMConfigGetBool(conf, "hpet", &val, -1) < 0)
            goto cleanup;
        else if (val != -1) {
            virDomainTimerDefPtr timer;

            if (VIR_ALLOC_N(def->clock.timers, 1) < 0 ||
                VIR_ALLOC(timer) < 0)
                goto cleanup;

            timer->name = VIR_DOMAIN_TIMER_NAME_HPET;
            timer->present = val;
            timer->tickpolicy = -1;

            def->clock.ntimers = 1;
            def->clock.timers[0] = timer;
        }
    }
    if (xenXMConfigGetBool(conf, "localtime", &vmlocaltime, 0) < 0)
        goto cleanup;

    if (hvm) {
        /* only managed HVM domains since 3.1.0 have persistent rtc_timeoffset */
        if (xendConfigVersion < XEND_CONFIG_VERSION_3_1_0) {
            if (vmlocaltime)
                def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
            else
                def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
            def->clock.data.utc_reset = true;
        } else {
            unsigned long rtc_timeoffset;
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_VARIABLE;
            if (xenXMConfigGetULong(conf, "rtc_timeoffset", &rtc_timeoffset, 0) < 0)
                goto cleanup;
            def->clock.data.variable.adjustment = (int)rtc_timeoffset;
            def->clock.data.variable.basis = vmlocaltime ?
                VIR_DOMAIN_CLOCK_BASIS_LOCALTIME :
                VIR_DOMAIN_CLOCK_BASIS_UTC;
        }
    } else {
        /* PV domains do not have an emulated RTC and the offset is fixed. */
        def->clock.offset = vmlocaltime ?
            VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME :
            VIR_DOMAIN_CLOCK_OFFSET_UTC;
        def->clock.data.utc_reset = true;
    } /* !hvm */

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
                goto cleanup;

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

            if (offset == head) {
                disk->src = NULL; /* No source file given, eg CDROM with no media */
            } else {
                if (VIR_ALLOC_N(disk->src, (offset - head) + 1) < 0)
                    goto cleanup;
                if (virStrncpy(disk->src, head, offset - head,
                               (offset - head) + 1) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
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
                goto cleanup;
            if (virStrncpy(disk->dst, head, offset - head,
                           (offset - head) + 1) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Dest file %s too big for destination"), head);
                goto cleanup;
            }
            head = offset + 1;


            /* Extract source driver type */
            if (disk->src) {
                /* The main type  phy:, file:, tap: ... */
                if ((tmp = strchr(disk->src, ':')) != NULL) {
                    if (VIR_ALLOC_N(disk->driverName, (tmp - disk->src) + 1) < 0)
                        goto cleanup;
                    if (virStrncpy(disk->driverName, disk->src,
                                   (tmp - disk->src),
                                   (tmp - disk->src) + 1) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
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
                    char *driverType;

                    if (!(tmp = strchr(disk->src, ':')))
                        goto skipdisk;

                    if (VIR_STRNDUP(driverType, disk->src, tmp - disk->src) < 0)
                        goto cleanup;
                    if (STREQ(driverType, "aio"))
                        disk->format = VIR_STORAGE_FILE_RAW;
                    else
                        disk->format =
                            virStorageFileFormatTypeFromString(driverType);
                    VIR_FREE(driverType);
                    if (disk->format <= 0) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Unknown driver type %s"),
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
                VIR_STRDUP(disk->driverName, "phy") < 0)
                goto cleanup;


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
                disk->readonly = true;
            else if ((STREQ(head, "w!")) ||
                     (STREQ(head, "!")))
                disk->shared = true;

            /* Maintain list in sorted order according to target device name */
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto cleanup;
            def->disks[def->ndisks++] = disk;
            disk = NULL;

            skipdisk:
            list = list->next;
            virDomainDiskDefFree(disk);
        }
    }

    if (hvm && xendConfigVersion == XEND_CONFIG_VERSION_3_0_2) {
        if (xenXMConfigGetString(conf, "cdrom", &str, NULL) < 0)
            goto cleanup;
        if (str) {
            if (VIR_ALLOC(disk) < 0)
                goto cleanup;

            disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
            if (VIR_STRDUP(disk->driverName, "file") < 0)
                goto cleanup;
            if (VIR_STRDUP(disk->src, str) < 0)
                goto cleanup;
            if (VIR_STRDUP(disk->dst, "hdc") < 0)
                goto cleanup;
            disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
            disk->readonly = true;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto cleanup;
            def->disks[def->ndisks++] = disk;
            disk = NULL;
        }
    }

    list = virConfGetValue(conf, "vif");
    if (list && list->type == VIR_CONF_LIST) {
        list = list->list;
        while (list) {
            char model[10];
            char type[10];
            char ip[16];
            char mac[18];
            char bridge[50];
            char vifname[50];
            char *key;

            bridge[0] = '\0';
            mac[0] = '\0';
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
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("MAC address %s too big for destination"),
                                       data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "bridge=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(bridge) - 1;
                    if (virStrncpy(bridge, data, len, sizeof(bridge)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Bridge %s too big for destination"),
                                       data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "script=")) {
                    int len = nextkey ? (nextkey - data) : strlen(data);
                    VIR_FREE(script);
                    if (VIR_STRNDUP(script, data, len) < 0)
                        goto cleanup;
                } else if (STRPREFIX(key, "model=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(model) - 1;
                    if (virStrncpy(model, data, len, sizeof(model)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Model %s too big for destination"), data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "type=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(type) - 1;
                    if (virStrncpy(type, data, len, sizeof(type)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Type %s too big for destination"), data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "vifname=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(vifname) - 1;
                    if (virStrncpy(vifname, data, len, sizeof(vifname)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("Vifname %s too big for destination"),
                                       data);
                        goto skipnic;
                    }
                } else if (STRPREFIX(key, "ip=")) {
                    int len = nextkey ? (nextkey - data) : sizeof(ip) - 1;
                    if (virStrncpy(ip, data, len, sizeof(ip)) == NULL) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
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
                goto cleanup;

            if (mac[0]) {
                if (virMacAddrParse(mac, &net->mac) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("malformed mac address '%s'"), mac);
                    goto cleanup;
                }
            }

            if (bridge[0] || STREQ_NULLABLE(script, "vif-bridge") ||
                STREQ_NULLABLE(script, "vif-vnic")) {
                net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
            } else {
                net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
            }

            if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                if (bridge[0] && VIR_STRDUP(net->data.bridge.brname, bridge) < 0)
                    goto cleanup;
                if (ip[0] && VIR_STRDUP(net->data.bridge.ipaddr, ip) < 0)
                    goto cleanup;
            } else {
                if (ip[0] && VIR_STRDUP(net->data.ethernet.ipaddr, ip) < 0)
                    goto cleanup;
            }

            if (script && script[0] &&
                VIR_STRDUP(net->script, script) < 0)
                goto cleanup;

            if (model[0] &&
                VIR_STRDUP(net->model, model) < 0)
                goto cleanup;

            if (!model[0] && type[0] && STREQ(type, "netfront") &&
                VIR_STRDUP(net->model, "netfront") < 0)
                goto cleanup;

            if (vifname[0] &&
                VIR_STRDUP(net->ifname, vifname) < 0)
                goto cleanup;

            if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0)
                goto cleanup;
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Domain %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (!(nextkey = strchr(key, ':')))
                goto skippci;

            if (virStrncpy(bus, key, (nextkey - key), sizeof(bus)) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Bus %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (!(nextkey = strchr(key, '.')))
                goto skippci;

            if (virStrncpy(slot, key, (nextkey - key), sizeof(slot)) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Slot %s too big for destination"), key);
                goto skippci;
            }

            key = nextkey + 1;
            if (strlen(key) != 1)
                goto skippci;

            if (virStrncpy(func, key, 1, sizeof(func)) == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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

            if (!(hostdev = virDomainHostdevDefAlloc()))
               goto cleanup;

            hostdev->managed = false;
            hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
            hostdev->source.subsys.u.pci.addr.domain = domainID;
            hostdev->source.subsys.u.pci.addr.bus = busID;
            hostdev->source.subsys.u.pci.addr.slot = slotID;
            hostdev->source.subsys.u.pci.addr.function = funcID;

            if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
                virDomainHostdevDefFree(hostdev);
                goto cleanup;
            }
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
                goto cleanup;
            input->bus = VIR_DOMAIN_INPUT_BUS_USB;
            input->type = STREQ(str, "tablet") ?
                VIR_DOMAIN_INPUT_TYPE_TABLET :
                VIR_DOMAIN_INPUT_TYPE_MOUSE;
            if (VIR_ALLOC_N(def->inputs, 1) < 0) {
                virDomainInputDefFree(input);
                goto cleanup;
            }
            def->inputs[0] = input;
            def->ninputs = 1;
        }
    }

    /* HVM guests, or old PV guests use this config format */
    if (hvm || xendConfigVersion < XEND_CONFIG_VERSION_3_0_4) {
        if (xenXMConfigGetBool(conf, "vnc", &val, 0) < 0)
            goto cleanup;

        if (val) {
            if (VIR_ALLOC(graphics) < 0)
                goto cleanup;
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

            if (xenXMConfigCopyStringOpt(conf, "vnclisten", &listenAddr) < 0)
                goto cleanup;
            if (listenAddr &&
                virDomainGraphicsListenSetAddress(graphics, 0, listenAddr,
                                                  -1, true) < 0) {
               goto cleanup;
            }
            VIR_FREE(listenAddr);

            if (xenXMConfigCopyStringOpt(conf, "vncpasswd", &graphics->data.vnc.auth.passwd) < 0)
                goto cleanup;
            if (xenXMConfigCopyStringOpt(conf, "keymap", &graphics->data.vnc.keymap) < 0)
                goto cleanup;

            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto cleanup;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        } else {
            if (xenXMConfigGetBool(conf, "sdl", &val, 0) < 0)
                goto cleanup;
            if (val) {
                if (VIR_ALLOC(graphics) < 0)
                    goto cleanup;
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                if (xenXMConfigCopyStringOpt(conf, "display", &graphics->data.sdl.display) < 0)
                    goto cleanup;
                if (xenXMConfigCopyStringOpt(conf, "xauthority", &graphics->data.sdl.xauth) < 0)
                    goto cleanup;
                if (VIR_ALLOC_N(def->graphics, 1) < 0)
                    goto cleanup;
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("VFB %s too big for destination"),
                               list->list->str);
                goto cleanup;
            }

            if (VIR_ALLOC(graphics) < 0)
                goto cleanup;

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
                            graphics->data.vnc.autoport = true;
                    } else if (STRPREFIX(key, "vnclisten=")) {
                        if (virDomainGraphicsListenSetAddress(graphics, 0, key+10,
                                                              -1, true) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "vncpasswd=")) {
                        if (VIR_STRDUP(graphics->data.vnc.auth.passwd, key + 10) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "keymap=")) {
                        if (VIR_STRDUP(graphics->data.vnc.keymap, key + 7) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "vncdisplay=")) {
                        graphics->data.vnc.port = strtol(key+11, NULL, 10) + 5900;
                    }
                } else {
                    if (STRPREFIX(key, "display=")) {
                        if (VIR_STRDUP(graphics->data.sdl.display, key + 8) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "xauthority=")) {
                        if (VIR_STRDUP(graphics->data.sdl.xauth, key + 11) < 0)
                            goto cleanup;
                    }
                }

                while (nextkey && (nextkey[0] == ',' ||
                                   nextkey[0] == ' ' ||
                                   nextkey[0] == '\t'))
                    nextkey++;
                key = nextkey;
            }
            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto cleanup;
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
            !(chr = xenParseSxprChar(str, NULL)))
            goto cleanup;

        if (chr) {
            if (VIR_ALLOC_N(def->parallels, 1) < 0) {
                virDomainChrDefFree(chr);
                goto cleanup;
            }
            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            chr->target.port = 0;
            def->parallels[0] = chr;
            def->nparallels++;
            chr = NULL;
        }

        /* Try to get the list of values to support multiple serial ports */
        list = virConfGetValue(conf, "serial");
        if (list && list->type == VIR_CONF_LIST) {
            int portnum = -1;

            list = list->list;
            while (list) {
                char *port = NULL;

                if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
                    goto cleanup;

                port = list->str;
                portnum++;
                if (STREQ(port, "none")) {
                    list = list->next;
                    continue;
                }

                if (!(chr = xenParseSxprChar(port, NULL)))
                    goto cleanup;

                if (VIR_REALLOC_N(def->serials, def->nserials+1) < 0) {
                    virDomainChrDefFree(chr);
                    goto cleanup;
                }

                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = portnum;

                def->serials[def->nserials++] = chr;
                chr = NULL;

                list = list->next;
            }
        } else {
            /* If domain is not using multiple serial ports we parse data old way */
            if (xenXMConfigGetString(conf, "serial", &str, NULL) < 0)
                goto cleanup;
            if (str && STRNEQ(str, "none") &&
                !(chr = xenParseSxprChar(str, NULL)))
                goto cleanup;
            if (chr) {
                if (VIR_ALLOC_N(def->serials, 1) < 0) {
                    virDomainChrDefFree(chr);
                    goto cleanup;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = 0;
                def->serials[0] = chr;
                def->nserials++;
            }
        }
    } else {
        if (VIR_ALLOC_N(def->consoles, 1) < 0)
            goto cleanup;
        def->nconsoles = 1;
        if (!(def->consoles[0] = xenParseSxprChar("pty", NULL)))
            goto cleanup;
        def->consoles[0]->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE;
        def->consoles[0]->target.port = 0;
        def->consoles[0]->targetType = VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN;
    }

    if (hvm) {
        if (xenXMConfigGetString(conf, "soundhw", &str, NULL) < 0)
            goto cleanup;

        if (str &&
            xenParseSxprSound(def, str) < 0)
            goto cleanup;
    }

    VIR_FREE(script);
    return def;

cleanup:
    virDomainGraphicsDefFree(graphics);
    virDomainNetDefFree(net);
    virDomainDiskDefFree(disk);
    virDomainDefFree(def);
    VIR_FREE(script);
    VIR_FREE(listenAddr);
    return NULL;
}


static
int xenXMConfigSetInt(virConfPtr conf, const char *setting, long long l) {
    virConfValuePtr value = NULL;

    if ((long) l != l) {
        virReportError(VIR_ERR_OVERFLOW, _("failed to store %lld to %s"),
                       l, setting);
        return -1;
    }
    if (VIR_ALLOC(value) < 0)
        return -1;

    value->type = VIR_CONF_LONG;
    value->next = NULL;
    value->l = l;

    return virConfSetValue(conf, setting, value);
}


static
int xenXMConfigSetString(virConfPtr conf, const char *setting, const char *str) {
    virConfValuePtr value = NULL;

    if (VIR_ALLOC(value) < 0)
        return -1;

    value->type = VIR_CONF_STRING;
    value->next = NULL;
    if (VIR_STRDUP(value->str, str) < 0) {
        VIR_FREE(value);
        return -1;
    }

    return virConfSetValue(conf, setting, value);
}


static int xenFormatXMDisk(virConfValuePtr list,
                                       virDomainDiskDefPtr disk,
                                       int hvm,
                                       int xendConfigVersion)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;

    if (disk->src) {
        if (disk->format) {
            const char *type;

            if (disk->format == VIR_STORAGE_FILE_RAW)
                type = "aio";
            else
                type = virStorageFileFormatTypeToString(disk->format);
            virBufferAsprintf(&buf, "%s:", disk->driverName);
            if (STREQ(disk->driverName, "tap"))
                virBufferAsprintf(&buf, "%s:", type);
        } else {
            switch (disk->type) {
            case VIR_DOMAIN_DISK_TYPE_FILE:
                virBufferAddLit(&buf, "file:");
                break;
            case VIR_DOMAIN_DISK_TYPE_BLOCK:
                virBufferAddLit(&buf, "phy:");
                break;
            default:
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported disk type %s"),
                               virDomainDiskTypeToString(disk->type));
                goto cleanup;
            }
        }
        virBufferAdd(&buf, disk->src, -1);
    }
    virBufferAddLit(&buf, ",");
    if (hvm && xendConfigVersion == XEND_CONFIG_VERSION_3_0_2)
        virBufferAddLit(&buf, "ioemu:");

    virBufferAdd(&buf, disk->dst, -1);
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&buf, ":cdrom");

    if (disk->readonly)
        virBufferAddLit(&buf, ",r");
    else if (disk->shared)
        virBufferAddLit(&buf, ",!");
    else
        virBufferAddLit(&buf, ",w");
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        return -1;
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_ALLOC(val) < 0)
        goto cleanup;

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;

cleanup:
    virBufferFreeAndReset(&buf);
    return -1;
}

static int xenFormatXMSerial(virConfValuePtr list,
                             virDomainChrDefPtr serial)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    int ret;

    if (serial) {
        ret = xenFormatSxprChr(serial, &buf);
        if (ret < 0)
            goto cleanup;
    } else {
        virBufferAddLit(&buf, "none");
    }
    if (virBufferError(&buf)) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_ALLOC(val) < 0)
        goto cleanup;

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;

cleanup:
    virBufferFreeAndReset(&buf);
    return -1;
}

static int xenFormatXMNet(virConnectPtr conn,
                                      virConfValuePtr list,
                                      virDomainNetDefPtr net,
                                      int hvm, int xendConfigVersion)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virBufferAsprintf(&buf, "mac=%s", virMacAddrFormat(&net->mac, macaddr));

    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        virBufferAsprintf(&buf, ",bridge=%s", net->data.bridge.brname);
        if (net->data.bridge.ipaddr)
            virBufferAsprintf(&buf, ",ip=%s", net->data.bridge.ipaddr);
        virBufferAsprintf(&buf, ",script=%s", DEFAULT_VIF_SCRIPT);
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (net->script)
            virBufferAsprintf(&buf, ",script=%s", net->script);
        if (net->data.ethernet.ipaddr)
            virBufferAsprintf(&buf, ",ip=%s", net->data.ethernet.ipaddr);
        break;

    case VIR_DOMAIN_NET_TYPE_NETWORK:
    {
        virNetworkPtr network = virNetworkLookupByName(conn, net->data.network.name);
        char *bridge;
        if (!network) {
            virReportError(VIR_ERR_NO_NETWORK, "%s",
                           net->data.network.name);
            return -1;
        }
        bridge = virNetworkGetBridgeName(network);
        virNetworkFree(network);
        if (!bridge) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network %s is not active"),
                           net->data.network.name);
            return -1;
        }

        virBufferAsprintf(&buf, ",bridge=%s", bridge);
        virBufferAsprintf(&buf, ",script=%s", DEFAULT_VIF_SCRIPT);
    }
    break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported network type %d"),
                       net->type);
        goto cleanup;
    }

    if (!hvm) {
        if (net->model != NULL)
            virBufferAsprintf(&buf, ",model=%s", net->model);
    }
    else {
        if (net->model != NULL && STREQ(net->model, "netfront")) {
            virBufferAddLit(&buf, ",type=netfront");
        }
        else {
            if (net->model != NULL)
                virBufferAsprintf(&buf, ",model=%s", net->model);

            /*
             * apparently type ioemu breaks paravirt drivers on HVM so skip this
             * from XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU
             */
            if (xendConfigVersion <= XEND_CONFIG_MAX_VERS_NET_TYPE_IOEMU)
                virBufferAddLit(&buf, ",type=ioemu");
        }
    }

    if (net->ifname)
        virBufferAsprintf(&buf, ",vifname=%s",
                          net->ifname);

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_ALLOC(val) < 0)
        goto cleanup;

    val->type = VIR_CONF_STRING;
    val->str = virBufferContentAndReset(&buf);
    tmp = list->list;
    while (tmp && tmp->next)
        tmp = tmp->next;
    if (tmp)
        tmp->next = val;
    else
        list->list = val;

    return 0;

cleanup:
    virBufferFreeAndReset(&buf);
    return -1;
}



static int
xenFormatXMPCI(virConfPtr conf,
                           virDomainDefPtr def)
{

    virConfValuePtr pciVal = NULL;
    int hasPCI = 0;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++)
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            hasPCI = 1;

    if (!hasPCI)
        return 0;

    if (VIR_ALLOC(pciVal) < 0)
        return -1;

    pciVal->type = VIR_CONF_LIST;
    pciVal->list = NULL;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virConfValuePtr val, tmp;
            char *buf;

            if (virAsprintf(&buf, "%04x:%02x:%02x.%x",
                            def->hostdevs[i]->source.subsys.u.pci.addr.domain,
                            def->hostdevs[i]->source.subsys.u.pci.addr.bus,
                            def->hostdevs[i]->source.subsys.u.pci.addr.slot,
                            def->hostdevs[i]->source.subsys.u.pci.addr.function) < 0)
                goto error;

            if (VIR_ALLOC(val) < 0) {
                VIR_FREE(buf);
                goto error;
            }
            val->type = VIR_CONF_STRING;
            val->str = buf;
            tmp = pciVal->list;
            while (tmp && tmp->next)
                tmp = tmp->next;
            if (tmp)
                tmp->next = val;
            else
                pciVal->list = val;
        }
    }

    if (pciVal->list != NULL) {
        int ret = virConfSetValue(conf, "pci", pciVal);
        pciVal = NULL;
        if (ret < 0)
            return -1;
    }
    VIR_FREE(pciVal);

    return 0;

error:
    virConfFreeValue(pciVal);
    return -1;
}


/* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
   either 32, or 64 on a platform where long is big enough.  */
verify(MAX_VIRT_CPUS <= sizeof(1UL) * CHAR_BIT);

virConfPtr xenFormatXM(virConnectPtr conn,
                                   virDomainDefPtr def,
                                   int xendConfigVersion) {
    virConfPtr conf = NULL;
    int hvm = 0, vmlocaltime = 0;
    size_t i;
    char *cpus = NULL;
    const char *lifecycle;
    char uuid[VIR_UUID_STRING_BUFLEN];
    virConfValuePtr diskVal = NULL;
    virConfValuePtr netVal = NULL;

    if (!(conf = virConfNew()))
        goto cleanup;


    if (xenXMConfigSetString(conf, "name", def->name) < 0)
        goto cleanup;

    virUUIDFormat(def->uuid, uuid);
    if (xenXMConfigSetString(conf, "uuid", uuid) < 0)
        goto cleanup;

    if (xenXMConfigSetInt(conf, "maxmem",
                          VIR_DIV_UP(def->mem.max_balloon, 1024)) < 0)
        goto cleanup;

    if (xenXMConfigSetInt(conf, "memory",
                          VIR_DIV_UP(def->mem.cur_balloon, 1024)) < 0)
        goto cleanup;

    if (xenXMConfigSetInt(conf, "vcpus", def->maxvcpus) < 0)
        goto cleanup;
    /* Computing the vcpu_avail bitmask works because MAX_VIRT_CPUS is
       either 32, or 64 on a platform where long is big enough.  */
    if (def->vcpus < def->maxvcpus &&
        xenXMConfigSetInt(conf, "vcpu_avail", (1UL << def->vcpus) - 1) < 0)
        goto cleanup;

    if ((def->cpumask != NULL) &&
        ((cpus = virBitmapFormat(def->cpumask)) == NULL)) {
        goto cleanup;
    }

    if (cpus &&
        xenXMConfigSetString(conf, "cpus", cpus) < 0)
        goto cleanup;
    VIR_FREE(cpus);

    hvm = STREQ(def->os.type, "hvm") ? 1 : 0;

    if (hvm) {
        char boot[VIR_DOMAIN_BOOT_LAST+1];
        if (xenXMConfigSetString(conf, "builder", "hvm") < 0)
            goto cleanup;

        if (def->os.loader &&
            xenXMConfigSetString(conf, "kernel", def->os.loader) < 0)
            goto cleanup;

        for (i = 0; i < def->os.nBootDevs; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            case VIR_DOMAIN_BOOT_DISK:
            default:
                boot[i] = 'c';
                break;
            }
        }
        if (!def->os.nBootDevs) {
            boot[0] = 'c';
            boot[1] = '\0';
        } else {
            boot[def->os.nBootDevs] = '\0';
        }

        if (xenXMConfigSetString(conf, "boot", boot) < 0)
            goto cleanup;

        if (xenXMConfigSetInt(conf, "pae",
                              (def->features[VIR_DOMAIN_FEATURE_PAE] ==
                               VIR_DOMAIN_FEATURE_STATE_ON) ? 1 : 0) < 0)
            goto cleanup;

        if (xenXMConfigSetInt(conf, "acpi",
                              (def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                               VIR_DOMAIN_FEATURE_STATE_ON) ? 1 : 0) < 0)
            goto cleanup;

        if (xenXMConfigSetInt(conf, "apic",
                              (def->features[VIR_DOMAIN_FEATURE_APIC] ==
                               VIR_DOMAIN_FEATURE_STATE_ON) ? 1 : 0) < 0)
            goto cleanup;

        if (xendConfigVersion >= XEND_CONFIG_VERSION_3_0_4) {
            if (xenXMConfigSetInt(conf, "hap",
                                  (def->features[VIR_DOMAIN_FEATURE_HAP] ==
                                   VIR_DOMAIN_FEATURE_STATE_ON) ? 1 : 0) < 0)
                goto cleanup;

            if (xenXMConfigSetInt(conf, "viridian",
                                  (def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] ==
                                   VIR_DOMAIN_FEATURE_STATE_ON) ? 1 : 0) < 0)
                goto cleanup;
        }

        for (i = 0; i < def->clock.ntimers; i++) {
            if (def->clock.timers[i]->name == VIR_DOMAIN_TIMER_NAME_HPET &&
                def->clock.timers[i]->present != -1 &&
                xenXMConfigSetInt(conf, "hpet", def->clock.timers[i]->present) < 0)
                goto cleanup;
        }

        if (xendConfigVersion == XEND_CONFIG_VERSION_3_0_2) {
            for (i = 0; i < def->ndisks; i++) {
                if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
                    def->disks[i]->dst &&
                    STREQ(def->disks[i]->dst, "hdc") &&
                    def->disks[i]->src) {
                    if (xenXMConfigSetString(conf, "cdrom",
                                             def->disks[i]->src) < 0)
                        goto cleanup;
                    break;
                }
            }
        }

        /* XXX floppy disks */
    } else {
        if (def->os.bootloader &&
            xenXMConfigSetString(conf, "bootloader", def->os.bootloader) < 0)
            goto cleanup;
        if (def->os.bootloaderArgs &&
            xenXMConfigSetString(conf, "bootargs", def->os.bootloaderArgs) < 0)
            goto cleanup;
        if (def->os.kernel &&
            xenXMConfigSetString(conf, "kernel", def->os.kernel) < 0)
            goto cleanup;
        if (def->os.initrd &&
            xenXMConfigSetString(conf, "ramdisk", def->os.initrd) < 0)
            goto cleanup;
        if (def->os.cmdline &&
            xenXMConfigSetString(conf, "extra", def->os.cmdline) < 0)
            goto cleanup;
    } /* !hvm */


    if (xendConfigVersion < XEND_CONFIG_VERSION_3_1_0) {
        /* <3.1: UTC and LOCALTIME */
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
            goto cleanup;
        }
    } else {
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
                    goto cleanup;
                }
                vmlocaltime = 0;
                rtc_timeoffset = 0;
                break;
            case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
                if (def->clock.data.utc_reset) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("unsupported clock adjustment='reset'"));
                    goto cleanup;
                }
                vmlocaltime = 1;
                rtc_timeoffset = 0;
                break;
            default:
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported clock offset='%s'"),
                               virDomainClockOffsetTypeToString(def->clock.offset));
                goto cleanup;
            }
            if (xenXMConfigSetInt(conf, "rtc_timeoffset", rtc_timeoffset) < 0)
                goto cleanup;
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
                goto cleanup;
            }
        } /* !hvm */
    }
    if (xenXMConfigSetInt(conf, "localtime", vmlocaltime) < 0)
        goto cleanup;


    if (!(lifecycle = virDomainLifecycleTypeToString(def->onPoweroff))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onPoweroff);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_poweroff", lifecycle) < 0)
        goto cleanup;


    if (!(lifecycle = virDomainLifecycleTypeToString(def->onReboot))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onReboot);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_reboot", lifecycle) < 0)
        goto cleanup;


    if (!(lifecycle = virDomainLifecycleCrashTypeToString(def->onCrash))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onCrash);
        goto cleanup;
    }
    if (xenXMConfigSetString(conf, "on_crash", lifecycle) < 0)
        goto cleanup;



    if (hvm) {
        if (def->emulator &&
            xenXMConfigSetString(conf, "device_model", def->emulator) < 0)
            goto cleanup;

        for (i = 0; i < def->ninputs; i++) {
            if (def->inputs[i]->bus == VIR_DOMAIN_INPUT_BUS_USB) {
                if (xenXMConfigSetInt(conf, "usb", 1) < 0)
                    goto cleanup;
                if (xenXMConfigSetString(conf, "usbdevice",
                                         def->inputs[i]->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                                         "mouse" : "tablet") < 0)
                    goto cleanup;
                break;
            }
        }
    }

    if (def->ngraphics == 1) {
        if (hvm || (xendConfigVersion < XEND_CONFIG_MIN_VERS_PVFB_NEWCONF)) {
            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                if (xenXMConfigSetInt(conf, "sdl", 1) < 0)
                    goto cleanup;
                if (xenXMConfigSetInt(conf, "vnc", 0) < 0)
                    goto cleanup;
                if (def->graphics[0]->data.sdl.display &&
                    xenXMConfigSetString(conf, "display",
                                     def->graphics[0]->data.sdl.display) < 0)
                    goto cleanup;
                if (def->graphics[0]->data.sdl.xauth &&
                    xenXMConfigSetString(conf, "xauthority",
                                         def->graphics[0]->data.sdl.xauth) < 0)
                    goto cleanup;
            } else {
                const char *listenAddr;

                if (xenXMConfigSetInt(conf, "sdl", 0) < 0)
                    goto cleanup;
                if (xenXMConfigSetInt(conf, "vnc", 1) < 0)
                    goto cleanup;
                if (xenXMConfigSetInt(conf, "vncunused",
                              def->graphics[0]->data.vnc.autoport ? 1 : 0) < 0)
                    goto cleanup;
                if (!def->graphics[0]->data.vnc.autoport &&
                    xenXMConfigSetInt(conf, "vncdisplay",
                                  def->graphics[0]->data.vnc.port - 5900) < 0)
                    goto cleanup;
                listenAddr = virDomainGraphicsListenGetAddress(def->graphics[0], 0);
                if (listenAddr &&
                    xenXMConfigSetString(conf, "vnclisten", listenAddr) < 0)
                    goto cleanup;
                if (def->graphics[0]->data.vnc.auth.passwd &&
                    xenXMConfigSetString(conf, "vncpasswd",
                                        def->graphics[0]->data.vnc.auth.passwd) < 0)
                    goto cleanup;
                if (def->graphics[0]->data.vnc.keymap &&
                    xenXMConfigSetString(conf, "keymap",
                                        def->graphics[0]->data.vnc.keymap) < 0)
                    goto cleanup;
            }
        } else {
            virConfValuePtr vfb, disp;
            char *vfbstr = NULL;
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                virBufferAddLit(&buf, "type=sdl");
                if (def->graphics[0]->data.sdl.display)
                    virBufferAsprintf(&buf, ",display=%s",
                                      def->graphics[0]->data.sdl.display);
                if (def->graphics[0]->data.sdl.xauth)
                    virBufferAsprintf(&buf, ",xauthority=%s",
                                      def->graphics[0]->data.sdl.xauth);
            } else {
                const char *listenAddr
                    = virDomainGraphicsListenGetAddress(def->graphics[0], 0);

                virBufferAddLit(&buf, "type=vnc");
                virBufferAsprintf(&buf, ",vncunused=%d",
                                  def->graphics[0]->data.vnc.autoport ? 1 : 0);
                if (!def->graphics[0]->data.vnc.autoport)
                    virBufferAsprintf(&buf, ",vncdisplay=%d",
                                      def->graphics[0]->data.vnc.port - 5900);
                if (listenAddr)
                    virBufferAsprintf(&buf, ",vnclisten=%s", listenAddr);
                if (def->graphics[0]->data.vnc.auth.passwd)
                    virBufferAsprintf(&buf, ",vncpasswd=%s",
                                      def->graphics[0]->data.vnc.auth.passwd);
                if (def->graphics[0]->data.vnc.keymap)
                    virBufferAsprintf(&buf, ",keymap=%s",
                                      def->graphics[0]->data.vnc.keymap);
            }
            if (virBufferError(&buf)) {
                virBufferFreeAndReset(&buf);
                virReportOOMError();
                goto cleanup;
            }

            vfbstr = virBufferContentAndReset(&buf);

            if (VIR_ALLOC(vfb) < 0) {
                VIR_FREE(vfbstr);
                goto cleanup;
            }

            if (VIR_ALLOC(disp) < 0) {
                VIR_FREE(vfb);
                VIR_FREE(vfbstr);
                goto cleanup;
            }

            vfb->type = VIR_CONF_LIST;
            vfb->list = disp;
            disp->type = VIR_CONF_STRING;
            disp->str = vfbstr;

            if (virConfSetValue(conf, "vfb", vfb) < 0)
                goto cleanup;
        }
    }

    /* analyze of the devices */
    if (VIR_ALLOC(diskVal) < 0)
        goto cleanup;
    diskVal->type = VIR_CONF_LIST;
    diskVal->list = NULL;

    for (i = 0; i < def->ndisks; i++) {
        if (xendConfigVersion == XEND_CONFIG_VERSION_3_0_2 &&
            def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
            def->disks[i]->dst &&
            STREQ(def->disks[i]->dst, "hdc")) {
            continue;
        }
        if (def->disks[i]->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
            continue;

        if (xenFormatXMDisk(diskVal, def->disks[i],
                            hvm, xendConfigVersion) < 0)
            goto cleanup;
    }
    if (diskVal->list != NULL) {
        int ret = virConfSetValue(conf, "disk", diskVal);
        diskVal = NULL;
        if (ret < 0)
            goto cleanup;
    }
    VIR_FREE(diskVal);

    if (VIR_ALLOC(netVal) < 0)
        goto cleanup;
    netVal->type = VIR_CONF_LIST;
    netVal->list = NULL;

    for (i = 0; i < def->nnets; i++) {
        if (xenFormatXMNet(conn, netVal, def->nets[i],
                           hvm, xendConfigVersion) < 0)
            goto cleanup;
    }
    if (netVal->list != NULL) {
        int ret = virConfSetValue(conf, "vif", netVal);
        netVal = NULL;
        if (ret < 0)
            goto cleanup;
    }
    VIR_FREE(netVal);

    if (xenFormatXMPCI(conf, def) < 0)
        goto cleanup;

    if (hvm) {
        if (def->nparallels) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str;
            int ret;

            ret = xenFormatSxprChr(def->parallels[0], &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenXMConfigSetString(conf, "parallel", str);
            VIR_FREE(str);
            if (ret < 0)
                goto cleanup;
        } else {
            if (xenXMConfigSetString(conf, "parallel", "none") < 0)
                goto cleanup;
        }

        if (def->nserials) {
            if ((def->nserials == 1) && (def->serials[0]->target.port == 0)) {
                virBuffer buf = VIR_BUFFER_INITIALIZER;
                char *str;
                int ret;

                ret = xenFormatSxprChr(def->serials[0], &buf);
                str = virBufferContentAndReset(&buf);
                if (ret == 0)
                    ret = xenXMConfigSetString(conf, "serial", str);
                VIR_FREE(str);
                if (ret < 0)
                    goto cleanup;
            } else {
                size_t j = 0;
                int maxport = -1, port;
                virConfValuePtr serialVal = NULL;

                if (VIR_ALLOC(serialVal) < 0)
                    goto cleanup;
                serialVal->type = VIR_CONF_LIST;
                serialVal->list = NULL;

                for (i = 0; i < def->nserials; i++)
                    if (def->serials[i]->target.port > maxport)
                        maxport = def->serials[i]->target.port;

                for (port = 0; port <= maxport; port++) {
                    virDomainChrDefPtr chr = NULL;
                    for (j = 0; j < def->nserials; j++) {
                        if (def->serials[j]->target.port == port) {
                            chr = def->serials[j];
                            break;
                        }
                    }
                    if (xenFormatXMSerial(serialVal, chr) < 0) {
                        virConfFreeValue(serialVal);
                        goto cleanup;
                    }
                }

                if (serialVal->list != NULL) {
                    int ret = virConfSetValue(conf, "serial", serialVal);
                    serialVal = NULL;
                    if (ret < 0)
                        goto cleanup;
                }
                VIR_FREE(serialVal);
            }
        } else {
            if (xenXMConfigSetString(conf, "serial", "none") < 0)
                goto cleanup;
        }


        if (def->sounds) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str = NULL;
            int ret = xenFormatSxprSound(def, &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenXMConfigSetString(conf, "soundhw", str);

            VIR_FREE(str);
            if (ret < 0)
                goto cleanup;
        }
    }

    return conf;

cleanup:
    virConfFreeValue(diskVal);
    virConfFreeValue(netVal);
    VIR_FREE(cpus);
    if (conf)
        virConfFree(conf);
    return NULL;
}
