/*
 * xen_common.c: Parsing and formatting functions for config common
 * between XM and XL
 *
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2006-2007, 2009-2016 Red Hat, Inc.
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
 */

#include <config.h>

#include "internal.h"
#include "virerror.h"
#include "virconf.h"
#include "viralloc.h"
#include "viruuid.h"
#include "count-one-bits.h"
#include "xenxs_private.h"
#include "domain_conf.h"
#include "virstring.h"
#include "xen_common.h"

#define VIR_FROM_THIS VIR_FROM_XEN

/*
 * Convenience method to grab a long int from the config file object
 */
int
xenConfigGetBool(virConfPtr conf,
                 const char *name,
                 int *value,
                 int def)
{
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_ULLONG) {
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


/*
 * Convenience method to grab a int from the config file object
 */
int
xenConfigGetULong(virConfPtr conf,
                  const char *name,
                  unsigned long *value,
                  unsigned long def)
{
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_ULLONG) {
        *value = val->l;
    } else if (val->type == VIR_CONF_STRING) {
        if (virStrToLong_ul(val->str, NULL, 10, value) < 0) {
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


/*
 * Convenience method to grab a int from the config file object
 */
static int
xenConfigGetULongLong(virConfPtr conf,
                      const char *name,
                      unsigned long long *value,
                      unsigned long long def)
{
    virConfValuePtr val;

    *value = 0;
    if (!(val = virConfGetValue(conf, name))) {
        *value = def;
        return 0;
    }

    if (val->type == VIR_CONF_ULLONG) {
        *value = val->l;
    } else if (val->type == VIR_CONF_STRING) {
        if (virStrToLong_ull(val->str, NULL, 10, value) < 0) {
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


static int
xenConfigCopyStringInternal(virConfPtr conf,
                            const char *name,
                            char **value,
                            int allowMissing)
{
    int rc;

    *value = NULL;
    if ((rc = virConfGetValueString(conf, name, value)) < 0)
        return -1;

    if (rc == 0) {
        if (allowMissing)
            return 0;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %s was missing"), name);
        return -1;
    }

    return 1;
}


int
xenConfigCopyString(virConfPtr conf, const char *name, char **value)
{
    return xenConfigCopyStringInternal(conf, name, value, 0);
}


int
xenConfigCopyStringOpt(virConfPtr conf, const char *name, char **value)
{
    return xenConfigCopyStringInternal(conf, name, value, 1);
}


/*
 * Convenience method to grab a string UUID from the config file object
 */
static int
xenConfigGetUUID(virConfPtr conf, const char *name, unsigned char *uuid)
{
    VIR_AUTOFREE(char *) string = NULL;
    int rc;

    if (!uuid || !name || !conf) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Arguments must be non null"));
        return -1;
    }


    if ((rc = virConfGetValueString(conf, name, &string)) < 0)
        return -1;

    if (rc == 0) {
        if (virUUIDGenerate(uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            return -1;
        } else {
            return 0;
        }
    }

    if (!string) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s can't be empty"), name);
        return -1;
    }

    if (virUUIDParse(string, uuid) < 0) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%s not parseable"), string);
        return -1;
    }

    return 0;
}


/*
 * Convenience method to grab a string from the config file object
 */
int
xenConfigGetString(virConfPtr conf,
                   const char *name,
                   char **value,
                   const char *def)
{
    char *string = NULL;
    int rc;

    *value = NULL;
    if ((rc = virConfGetValueString(conf, name, &string)) < 0)
        return -1;

    if (rc == 0 || !string) {
        if (VIR_STRDUP(*value, def) < 0)
            return -1;
    } else {
        *value = string;
    }

    return 0;
}


int
xenConfigSetInt(virConfPtr conf, const char *setting, long long l)
{
    virConfValuePtr value = NULL;

    if ((long)l != l) {
        virReportError(VIR_ERR_OVERFLOW, _("failed to store %lld to %s"),
                       l, setting);
        return -1;
    }
    if (VIR_ALLOC(value) < 0)
        return -1;

    value->type = VIR_CONF_LLONG;
    value->next = NULL;
    value->l = l;

    return virConfSetValue(conf, setting, value);
}


int
xenConfigSetString(virConfPtr conf, const char *setting, const char *str)
{
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


static int
xenParseMem(virConfPtr conf, virDomainDefPtr def)
{
    unsigned long long memory;

    if (xenConfigGetULongLong(conf, "memory", &def->mem.cur_balloon,
                                MIN_XEN_GUEST_SIZE * 2) < 0)
        return -1;

    if (xenConfigGetULongLong(conf, "maxmem", &memory,
                                def->mem.cur_balloon) < 0)
        return -1;

    def->mem.cur_balloon *= 1024;
    virDomainDefSetMemoryTotal(def, memory * 1024);

    return 0;
}


static int
xenParseTimeOffset(virConfPtr conf, virDomainDefPtr def)
{
    int vmlocaltime;

    if (xenConfigGetBool(conf, "localtime", &vmlocaltime, 0) < 0)
        return -1;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        unsigned long rtc_timeoffset;
        def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_VARIABLE;
        if (xenConfigGetULong(conf, "rtc_timeoffset", &rtc_timeoffset, 0) < 0)
            return -1;

        def->clock.data.variable.adjustment = (int)rtc_timeoffset;
        def->clock.data.variable.basis = vmlocaltime ?
            VIR_DOMAIN_CLOCK_BASIS_LOCALTIME :
            VIR_DOMAIN_CLOCK_BASIS_UTC;
    } else {
        /* PV domains do not have an emulated RTC and the offset is fixed. */
        def->clock.offset = vmlocaltime ?
            VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME :
            VIR_DOMAIN_CLOCK_OFFSET_UTC;
        def->clock.data.utc_reset = true;
    } /* !hvm */

    return 0;
}


static int
xenParseEventsActions(virConfPtr conf, virDomainDefPtr def)
{
    VIR_AUTOFREE(char *) on_poweroff = NULL;
    VIR_AUTOFREE(char *) on_reboot = NULL;
    VIR_AUTOFREE(char *) on_crash = NULL;

    if (xenConfigGetString(conf, "on_poweroff", &on_poweroff, "destroy") < 0)
        return -1;

    if ((def->onPoweroff = virDomainLifecycleActionTypeFromString(on_poweroff)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_poweroff"), on_poweroff);
        return -1;
    }

    if (xenConfigGetString(conf, "on_reboot", &on_reboot, "restart") < 0)
        return -1;

    if ((def->onReboot = virDomainLifecycleActionTypeFromString(on_reboot)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_reboot"), on_reboot);
        return -1;
    }

    if (xenConfigGetString(conf, "on_crash", &on_crash, "restart") < 0)
        return -1;

    if ((def->onCrash = virDomainLifecycleActionTypeFromString(on_crash)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %s for on_crash"), on_crash);
        return -1;
    }

    return 0;
}


static virDomainHostdevDefPtr
xenParsePCI(char *entry)
{
    virDomainHostdevDefPtr hostdev = NULL;
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

    /* pci=['0000:00:1b.0','0000:00:13.0'] */
    if (!(key = entry))
        return NULL;
    if (!(nextkey = strchr(key, ':')))
        return NULL;
    if (virStrncpy(domain, key, (nextkey - key), sizeof(domain)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain %s too big for destination"), key);
        return NULL;
    }

    key = nextkey + 1;
    if (!(nextkey = strchr(key, ':')))
        return NULL;
    if (virStrncpy(bus, key, (nextkey - key), sizeof(bus)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Bus %s too big for destination"), key);
        return NULL;
    }

    key = nextkey + 1;
    if (!(nextkey = strchr(key, '.')))
        return NULL;
    if (virStrncpy(slot, key, (nextkey - key), sizeof(slot)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Slot %s too big for destination"), key);
        return NULL;
    }

    key = nextkey + 1;
    if (strlen(key) != 1)
        return NULL;
    if (virStrncpy(func, key, 1, sizeof(func)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Function %s too big for destination"), key);
        return NULL;
    }

    if (virStrToLong_i(domain, NULL, 16, &domainID) < 0)
        return NULL;
    if (virStrToLong_i(bus, NULL, 16, &busID) < 0)
        return NULL;
    if (virStrToLong_i(slot, NULL, 16, &slotID) < 0)
        return NULL;
    if (virStrToLong_i(func, NULL, 16, &funcID) < 0)
        return NULL;

    if (!(hostdev = virDomainHostdevDefNew()))
       return NULL;

    hostdev->managed = false;
    hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    hostdev->source.subsys.u.pci.addr.domain = domainID;
    hostdev->source.subsys.u.pci.addr.bus = busID;
    hostdev->source.subsys.u.pci.addr.slot = slotID;
    hostdev->source.subsys.u.pci.addr.function = funcID;

    return hostdev;
}


static int
xenHandleConfGetValueStringListErrors(int ret)
{
    if (ret < 0) {
        /* It means virConfGetValueStringList() didn't fail because the
         * cval->type switch fell through - since we're passing
         * @compatString == false - assumes failures for memory allocation
         * and VIR_CONF_LIST traversal failure should cause -1 to be
         * returned to the caller with the error message set. */
        if (virGetLastErrorCode() != VIR_ERR_INTERNAL_ERROR)
            return -1;

        /* If we did fall through the switch, then ignore and clear the
         * last error. */
        virResetLastError();
    }
    return 0;
}


static int
xenParsePCIList(virConfPtr conf, virDomainDefPtr def)
{
    VIR_AUTOSTRINGLIST pcis = NULL;
    char **entries = NULL;
    int rc;

    if ((rc = virConfGetValueStringList(conf, "pci", false, &pcis)) <= 0)
        return xenHandleConfGetValueStringListErrors(rc);

    for (entries = pcis; *entries; entries++) {
        char *entry = *entries;
        virDomainHostdevDefPtr hostdev;

        if (!(hostdev = xenParsePCI(entry)))
            return -1;

        if (VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev) < 0) {
            virDomainHostdevDefFree(hostdev);
            return -1;
        }
    }

    return 0;
}


static int
xenParseCPUFeatures(virConfPtr conf,
                    virDomainDefPtr def,
                    virDomainXMLOptionPtr xmlopt)
{
    unsigned long count = 0;
    VIR_AUTOFREE(char *) cpus = NULL;
    VIR_AUTOFREE(char *) tsc_mode = NULL;
    int val = 0;
    virDomainTimerDefPtr timer;

    if (xenConfigGetULong(conf, "vcpus", &count, 1) < 0)
        return -1;

    if (virDomainDefSetVcpusMax(def, count, xmlopt) < 0)
        return -1;

    if (virDomainDefSetVcpus(def, count) < 0)
        return -1;

    if (virConfGetValue(conf, "maxvcpus")) {
        if (xenConfigGetULong(conf, "maxvcpus", &count, 0) < 0)
            return -1;

        if (virDomainDefSetVcpusMax(def, count, xmlopt) < 0)
            return -1;
    }

    if (xenConfigGetString(conf, "cpus", &cpus, NULL) < 0)
        return -1;

    if (cpus && (virBitmapParse(cpus, &def->cpumask, 4096) < 0))
        return -1;

    if (xenConfigGetString(conf, "tsc_mode", &tsc_mode, NULL) < 0)
        return -1;

    if (tsc_mode) {
        if (VIR_EXPAND_N(def->clock.timers, def->clock.ntimers, 1) < 0 ||
            VIR_ALLOC(timer) < 0)
            return -1;

        timer->name = VIR_DOMAIN_TIMER_NAME_TSC;
        timer->present = 1;
        timer->tickpolicy = -1;
        timer->mode = VIR_DOMAIN_TIMER_MODE_AUTO;
        timer->track = -1;
        if (STREQ_NULLABLE(tsc_mode, "always_emulate"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_EMULATE;
        else if (STREQ_NULLABLE(tsc_mode, "native"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_NATIVE;
        else if (STREQ_NULLABLE(tsc_mode, "native_paravirt"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_PARAVIRT;

        def->clock.timers[def->clock.ntimers - 1] = timer;
    }

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (xenConfigGetBool(conf, "pae", &val, 1) < 0)
            return -1;

        else if (val)
            def->features[VIR_DOMAIN_FEATURE_PAE] = VIR_TRISTATE_SWITCH_ON;
        if (xenConfigGetBool(conf, "acpi", &val, 1) < 0)
            return -1;

        else if (val)
            def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ON;
        if (xenConfigGetBool(conf, "apic", &val, 1) < 0)
            return -1;

        else if (val)
            def->features[VIR_DOMAIN_FEATURE_APIC] = VIR_TRISTATE_SWITCH_ON;
        if (xenConfigGetBool(conf, "hap", &val, 1) < 0)
            return -1;

        else if (!val)
            def->features[VIR_DOMAIN_FEATURE_HAP] = VIR_TRISTATE_SWITCH_OFF;
        if (xenConfigGetBool(conf, "viridian", &val, 0) < 0)
            return -1;

        else if (val)
            def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] = VIR_TRISTATE_SWITCH_ON;

        if (xenConfigGetBool(conf, "hpet", &val, -1) < 0)
            return -1;

        if (val != -1) {
            if (VIR_EXPAND_N(def->clock.timers, def->clock.ntimers, 1) < 0 ||
                VIR_ALLOC(timer) < 0)
                return -1;

            timer->name = VIR_DOMAIN_TIMER_NAME_HPET;
            timer->present = val;
            timer->tickpolicy = -1;
            timer->mode = -1;
            timer->track = -1;

            def->clock.timers[def->clock.ntimers - 1] = timer;
        }
    }

    return 0;
}


#define MAX_VFB 1024

static int
xenParseVfb(virConfPtr conf, virDomainDefPtr def)
{
    int val;
    char *listenAddr = NULL;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;
    virDomainGraphicsDefPtr graphics = NULL;

    if (hvm) {
        if (xenConfigGetBool(conf, "vnc", &val, 0) < 0)
            goto cleanup;
        if (val) {
            if (VIR_ALLOC(graphics) < 0)
                goto cleanup;
            graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;
            if (xenConfigGetBool(conf, "vncunused", &val, 1) < 0)
                goto cleanup;
            graphics->data.vnc.autoport = val ? 1 : 0;
            if (!graphics->data.vnc.autoport) {
                unsigned long vncdisplay;
                if (xenConfigGetULong(conf, "vncdisplay", &vncdisplay, 0) < 0)
                    goto cleanup;
                graphics->data.vnc.port = (int)vncdisplay + 5900;
            }

            if (xenConfigCopyStringOpt(conf, "vnclisten", &listenAddr) < 0)
                goto cleanup;
            if (virDomainGraphicsListenAppendAddress(graphics, listenAddr) < 0)
                goto cleanup;
            VIR_FREE(listenAddr);

            if (xenConfigCopyStringOpt(conf, "vncpasswd", &graphics->data.vnc.auth.passwd) < 0)
                goto cleanup;
            if (xenConfigCopyStringOpt(conf, "keymap", &graphics->data.vnc.keymap) < 0)
                goto cleanup;
            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto cleanup;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        } else {
            if (xenConfigGetBool(conf, "sdl", &val, 0) < 0)
                goto cleanup;
            if (val) {
                if (VIR_ALLOC(graphics) < 0)
                    goto cleanup;
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                if (xenConfigCopyStringOpt(conf, "display", &graphics->data.sdl.display) < 0)
                    goto cleanup;
                if (xenConfigCopyStringOpt(conf, "xauthority", &graphics->data.sdl.xauth) < 0)
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
        VIR_AUTOSTRINGLIST vfbs = NULL;
        int rc;

        if ((rc = virConfGetValueStringList(conf, "vfb", false, &vfbs)) == 1) {
            char vfb[MAX_VFB];
            char *key = vfb;

            if (virStrcpyStatic(vfb, *vfbs) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("VFB %s too big for destination"),
                               *vfbs);
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
                        if (VIR_STRDUP(listenAddr, key+10) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "vncpasswd=")) {
                        if (VIR_STRDUP(graphics->data.vnc.auth.passwd, key + 10) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "keymap=")) {
                        if (VIR_STRDUP(graphics->data.vnc.keymap, key + 7) < 0)
                            goto cleanup;
                    } else if (STRPREFIX(key, "vncdisplay=")) {
                        if (virStrToLong_i(key + 11, NULL, 10,
                                           &graphics->data.vnc.port) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("invalid vncdisplay value '%s'"),
                                           key + 11);
                            goto cleanup;
                        }
                        graphics->data.vnc.port += 5900;
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
            if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
                if (virDomainGraphicsListenAppendAddress(graphics,
                                                         listenAddr) < 0)
                    goto cleanup;
                VIR_FREE(listenAddr);
            }
            if (VIR_ALLOC_N(def->graphics, 1) < 0)
                goto cleanup;
            def->graphics[0] = graphics;
            def->ngraphics = 1;
            graphics = NULL;
        } else {
            if (xenHandleConfGetValueStringListErrors(rc) < 0)
                goto cleanup;
        }
    }

    return 0;

 cleanup:
    virDomainGraphicsDefFree(graphics);
    VIR_FREE(listenAddr);
    return -1;
}


static int
xenParseCharDev(virConfPtr conf, virDomainDefPtr def, const char *nativeFormat)
{
    VIR_AUTOSTRINGLIST serials = NULL;
    virDomainChrDefPtr chr = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        VIR_AUTOFREE(char *) parallel = NULL;
        int rc;

        if (xenConfigGetString(conf, "parallel", &parallel, NULL) < 0)
            goto cleanup;
        if (parallel && STRNEQ(parallel, "none") &&
            !(chr = xenParseSxprChar(parallel, NULL)))
            goto cleanup;
        if (chr) {
            if (VIR_ALLOC_N(def->parallels, 1) < 0)
                goto cleanup;

            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            chr->target.port = 0;
            def->parallels[0] = chr;
            def->nparallels++;
            chr = NULL;
        }

        /* Try to get the list of values to support multiple serial ports */
        if ((rc = virConfGetValueStringList(conf, "serial", false, &serials)) == 1) {
            char **entries;
            int portnum = -1;

            if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Multiple serial devices are not supported by xen-xm"));
                goto cleanup;
            }

            for (entries = serials; *entries; entries++) {
                char *port = *entries;

                portnum++;
                if (STREQ(port, "none"))
                    continue;

                if (!(chr = xenParseSxprChar(port, NULL)))
                    goto cleanup;
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = portnum;
                if (VIR_APPEND_ELEMENT(def->serials, def->nserials, chr) < 0)
                    goto cleanup;
            }
        } else {
            VIR_AUTOFREE(char *) serial = NULL;

            if (xenHandleConfGetValueStringListErrors(rc) < 0)
                goto cleanup;

            /* If domain is not using multiple serial ports we parse data old way */
            if (xenConfigGetString(conf, "serial", &serial, NULL) < 0)
                goto cleanup;
            if (serial && STRNEQ(serial, "none") &&
                !(chr = xenParseSxprChar(serial, NULL)))
                goto cleanup;
            if (chr) {
                if (VIR_ALLOC_N(def->serials, 1) < 0)
                    goto cleanup;
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

    return 0;

 cleanup:
    virDomainChrDefFree(chr);
    return -1;
}


static int
xenParseVifBridge(virDomainNetDefPtr net, char *bridge)
{
    char *vlanstr;
    unsigned int tag;

    if ((vlanstr = strchr(bridge, '.'))) {
        /* 'bridge' string contains a bridge name and single vlan tag */
        if (VIR_STRNDUP(net->data.bridge.brname, bridge, vlanstr - bridge) < 0)
            return -1;

        vlanstr++;
        if (virStrToLong_ui(vlanstr, NULL, 10, &tag) < 0)
            return -1;

        if (VIR_ALLOC_N(net->vlan.tag, 1) < 0)
            return -1;

        net->vlan.tag[0] = tag;
        net->vlan.nTags = 1;

        if (VIR_ALLOC(net->virtPortProfile) < 0)
            return -1;

        net->virtPortProfile->virtPortType = VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH;
        return 0;
    } else if ((vlanstr = strchr(bridge, ':'))) {
        /* 'bridge' string contains a bridge name and one or more vlan trunks */
        size_t i;
        size_t nvlans = 0;
        char **vlanstr_list = virStringSplit(bridge, ":", 0);

        if (!vlanstr_list)
            return -1;

        if (VIR_STRDUP(net->data.bridge.brname, vlanstr_list[0]) < 0) {
            virStringListFree(vlanstr_list);
            return -1;
        }

        for (i = 1; vlanstr_list[i]; i++)
            nvlans++;

        if (VIR_ALLOC_N(net->vlan.tag, nvlans) < 0) {
            virStringListFree(vlanstr_list);
            return -1;
        }

        for (i = 1; i <= nvlans; i++) {
            if (virStrToLong_ui(vlanstr_list[i], NULL, 10, &tag) < 0) {
                virStringListFree(vlanstr_list);
                return -1;
            }
            net->vlan.tag[i - 1] = tag;
        }
        net->vlan.nTags = nvlans;
        net->vlan.trunk = true;
        virStringListFree(vlanstr_list);

        if (VIR_ALLOC(net->virtPortProfile) < 0)
            return -1;

        net->virtPortProfile->virtPortType = VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH;
        return 0;
    } else {
        /* 'bridge' string only contains the bridge name */
        if (VIR_STRDUP(net->data.bridge.brname, bridge) < 0)
            return -1;
    }

    return 0;
}


static virDomainNetDefPtr
xenParseVif(char *entry, const char *vif_typename)
{
    virDomainNetDefPtr net = NULL;
    virDomainNetDefPtr ret = NULL;
    char *script = NULL;
    char model[10];
    char type[10];
    char ip[128];
    char mac[18];
    char bridge[50];
    char vifname[50];
    char rate[50];
    char *key;

    bridge[0] = '\0';
    mac[0] = '\0';
    ip[0] = '\0';
    model[0] = '\0';
    type[0] = '\0';
    vifname[0] = '\0';
    rate[0] = '\0';

    key = entry;
    while (key) {
        char *data;
        char *nextkey = strchr(key, ',');

        if (!(data = strchr(key, '=')))
            return NULL;
        data++;

        if (STRPREFIX(key, "mac=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(mac, data, len, sizeof(mac)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("MAC address %s too big for destination"),
                               data);
                return NULL;
            }
        } else if (STRPREFIX(key, "bridge=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(bridge, data, len, sizeof(bridge)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Bridge %s too big for destination"),
                               data);
                return NULL;
            }
        } else if (STRPREFIX(key, "script=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            VIR_FREE(script);
            if (VIR_STRNDUP(script, data, len) < 0)
                return NULL;
        } else if (STRPREFIX(key, "model=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(model, data, len, sizeof(model)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Model %s too big for destination"),
                               data);
                return NULL;
            }
        } else if (STRPREFIX(key, "type=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(type, data, len, sizeof(type)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Type %s too big for destination"),
                               data);
                return NULL;
            }
        } else if (STRPREFIX(key, "vifname=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(vifname, data, len, sizeof(vifname)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Vifname %s too big for destination"),
                               data);
                return NULL;
            }
        } else if (STRPREFIX(key, "ip=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(ip, data, len, sizeof(ip)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("IP %s too big for destination"), data);
                return NULL;
            }
        } else if (STRPREFIX(key, "rate=")) {
            int len = nextkey ? (nextkey - data) : strlen(data);
            if (virStrncpy(rate, data, len, sizeof(rate)) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("rate %s too big for destination"), data);
                return NULL;
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

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE && bridge[0]) {
        if (xenParseVifBridge(net, bridge) < 0)
            goto cleanup;
    }
    if (ip[0]) {
        char **ip_list = virStringSplit(ip, " ", 0);
        size_t i;

        if (!ip_list)
            goto cleanup;

        for (i = 0; ip_list[i]; i++) {
            if (virDomainNetAppendIPAddress(net, ip_list[i], 0, 0) < 0) {
                virStringListFree(ip_list);
                goto cleanup;
            }
        }
        virStringListFree(ip_list);
    }

    if (script && script[0] &&
        VIR_STRDUP(net->script, script) < 0)
        goto cleanup;

    if (model[0] &&
        VIR_STRDUP(net->model, model) < 0)
        goto cleanup;

    if (!model[0] && type[0] && STREQ(type, vif_typename) &&
        VIR_STRDUP(net->model, "netfront") < 0)
        goto cleanup;

    if (vifname[0] &&
        VIR_STRDUP(net->ifname, vifname) < 0)
        goto cleanup;

    if (rate[0]) {
        virNetDevBandwidthPtr bandwidth;
        unsigned long long kbytes_per_sec;

        if (xenParseSxprVifRate(rate, &kbytes_per_sec) < 0)
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

    VIR_STEAL_PTR(ret, net);

 cleanup:
    virDomainNetDefFree(net);
    VIR_FREE(script);
    return ret;
}


static int
xenParseVifList(virConfPtr conf, virDomainDefPtr def, const char *vif_typename)
{
    virConfValuePtr list = virConfGetValue(conf, "vif");

    if (!list || list->type != VIR_CONF_LIST)
        return 0;

    for (list = list->list; list; list = list->next) {
        virDomainNetDefPtr net = NULL;
        int rc;

        if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
            continue;

        if (!(net = xenParseVif(list->str, vif_typename)))
            return -1;

        rc = VIR_APPEND_ELEMENT(def->nets, def->nnets, net);
        if (rc < 0) {
            virDomainNetDefFree(net);
            return -1;
        }
    }

    return 0;
}


static int
xenParseEmulatedDevices(virConfPtr conf, virDomainDefPtr def)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (xenConfigGetString(conf, "soundhw", &str, NULL) < 0)
            return -1;

        if (str &&
            xenParseSxprSound(def, str) < 0)
            return -1;
    }

    return 0;
}


static int
xenParseGeneralMeta(virConfPtr conf, virDomainDefPtr def, virCapsPtr caps)
{
    virCapsDomainDataPtr capsdata = NULL;
    VIR_AUTOFREE(char *) str = NULL;
    int ret = -1;

    if (xenConfigCopyString(conf, "name", &def->name) < 0)
        goto out;

    if (xenConfigGetUUID(conf, "uuid", def->uuid) < 0)
        goto out;

    def->os.type = VIR_DOMAIN_OSTYPE_XEN;

    if (xenConfigGetString(conf, "type", &str, NULL) == 0 && str) {
        if (STREQ(str, "pv")) {
            def->os.type = VIR_DOMAIN_OSTYPE_XEN;
        } else if (STREQ(str, "pvh")) {
            def->os.type = VIR_DOMAIN_OSTYPE_XENPVH;
        } else if (STREQ(str, "hvm")) {
            def->os.type = VIR_DOMAIN_OSTYPE_HVM;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("type %s is not supported"), str);
            return -1;
        }
    } else {
        if ((xenConfigGetString(conf, "builder", &str, "linux") == 0) &&
            STREQ(str, "hvm")) {
            def->os.type = VIR_DOMAIN_OSTYPE_HVM;
        }
    }

    if (!(capsdata = virCapabilitiesDomainDataLookup(caps, def->os.type,
            VIR_ARCH_NONE, def->virtType, NULL, NULL)))
        goto out;

    def->os.arch = capsdata->arch;
    if (VIR_STRDUP(def->os.machine, capsdata->machinetype) < 0)
        goto out;

    ret = 0;
 out:
    VIR_FREE(capsdata);
    return ret;
}


/*
 * A convenience function for parsing all config common to both XM and XL
 */
int
xenParseConfigCommon(virConfPtr conf,
                     virDomainDefPtr def,
                     virCapsPtr caps,
                     const char *nativeFormat,
                     virDomainXMLOptionPtr xmlopt)
{
    if (xenParseGeneralMeta(conf, def, caps) < 0)
        return -1;

    if (xenParseMem(conf, def) < 0)
        return -1;

    if (xenParseEventsActions(conf, def) < 0)
        return -1;

    if (xenParseCPUFeatures(conf, def, xmlopt) < 0)
        return -1;

    if (xenParseTimeOffset(conf, def) < 0)
        return -1;

    if (xenConfigCopyStringOpt(conf, "device_model", &def->emulator) < 0)
        return -1;

    if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XL)) {
        if (xenParseVifList(conf, def, "vif") < 0)
            return -1;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
        if (xenParseVifList(conf, def, "netfront") < 0)
            return -1;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        return -1;
    }

    if (xenParsePCIList(conf, def) < 0)
        return -1;

    if (xenParseEmulatedDevices(conf, def) < 0)
        return -1;

    if (xenParseVfb(conf, def) < 0)
        return -1;

    if (xenParseCharDev(conf, def, nativeFormat) < 0)
        return -1;

    return 0;
}


static int
xenFormatSerial(virConfValuePtr list, virDomainChrDefPtr serial)
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
    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

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

char *
xenMakeIPList(virNetDevIPInfoPtr guestIP)
{
    size_t i;
    char **address_array;
    char *ret = NULL;

    if (VIR_ALLOC_N(address_array, guestIP->nips + 1) < 0)
        return NULL;

    for (i = 0; i < guestIP->nips; i++) {
        address_array[i] = virSocketAddrFormat(&guestIP->ips[i]->address);
        if (!address_array[i])
            goto cleanup;
    }
    ret = virStringListJoin((const char**)address_array, " ");

 cleanup:
    virStringListFree(address_array);
    return ret;
}

static int
xenFormatNet(virConnectPtr conn,
             virConfValuePtr list,
             virDomainNetDefPtr net,
             int hvm,
             const char *vif_typename)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virConfValuePtr val, tmp;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virBufferAsprintf(&buf, "mac=%s", virMacAddrFormat(&net->mac, macaddr));

    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    {
        virNetDevVPortProfilePtr port_profile = virDomainNetGetActualVirtPortProfile(net);
        virNetDevVlanPtr virt_vlan = virDomainNetGetActualVlan(net);
        const char *script = net->script;
        size_t i;

        virBufferAsprintf(&buf, ",bridge=%s", net->data.bridge.brname);
        if (port_profile &&
            port_profile->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            if (!script)
                script = "vif-openvswitch";
            /*
             * libxl_device_nic->bridge supports an extended format for
             * specifying VLAN tags and trunks
             *
             * BRIDGE_NAME[.VLAN][:TRUNK:TRUNK]
             */
            if (virt_vlan && virt_vlan->nTags > 0) {
                if (virt_vlan->trunk) {
                    for (i = 0; i < virt_vlan->nTags; i++)
                        virBufferAsprintf(&buf, ":%d", virt_vlan->tag[i]);
                } else {
                    virBufferAsprintf(&buf, ".%d", virt_vlan->tag[0]);
                }
            }
        }

        if (net->guestIP.nips > 0) {
            char *ipStr = xenMakeIPList(&net->guestIP);
            virBufferAsprintf(&buf, ",ip=%s", ipStr);
            VIR_FREE(ipStr);
        }
        virBufferAsprintf(&buf, ",script=%s", script ? script : DEFAULT_VIF_SCRIPT);
    }
    break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (net->script)
            virBufferAsprintf(&buf, ",script=%s", net->script);
        if (net->guestIP.nips > 0) {
            char *ipStr = xenMakeIPList(&net->guestIP);
            virBufferAsprintf(&buf, ",ip=%s", ipStr);
            VIR_FREE(ipStr);
        }
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
        virObjectUnref(network);
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

    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_USER:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("Unsupported net type '%s'"),
                       virDomainNetTypeToString(net->type));
        goto cleanup;

    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainNetType, net->type);
        goto cleanup;
    }

    if (!hvm) {
        if (net->model != NULL)
            virBufferAsprintf(&buf, ",model=%s", net->model);
    } else {
        if (net->model != NULL && STREQ(net->model, "netfront")) {
            virBufferAsprintf(&buf, ",type=%s", vif_typename);
        } else {
            if (net->model != NULL)
                virBufferAsprintf(&buf, ",model=%s", net->model);
        }
    }

    if (net->ifname)
        virBufferAsprintf(&buf, ",vifname=%s",
                          net->ifname);

    if (net->bandwidth && net->bandwidth->out && net->bandwidth->out->average)
        virBufferAsprintf(&buf, ",rate=%lluKB/s", net->bandwidth->out->average);

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

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
xenFormatPCI(virConfPtr conf, virDomainDefPtr def)
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


static int
xenFormatGeneralMeta(virConfPtr conf, virDomainDefPtr def)
{
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (xenConfigSetString(conf, "name", def->name) < 0)
        return -1;

    virUUIDFormat(def->uuid, uuid);
    if (xenConfigSetString(conf, "uuid", uuid) < 0)
        return -1;

    return 0;
}


static int
xenFormatMem(virConfPtr conf, virDomainDefPtr def)
{
    if (xenConfigSetInt(conf, "maxmem",
                        VIR_DIV_UP(virDomainDefGetMemoryTotal(def), 1024)) < 0)
        return -1;

    if (xenConfigSetInt(conf, "memory",
                        VIR_DIV_UP(def->mem.cur_balloon, 1024)) < 0)
        return -1;

    return 0;
}


static int
xenFormatTimeOffset(virConfPtr conf, virDomainDefPtr def)
{
    int vmlocaltime;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
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
                return -1;
            }
            vmlocaltime = 0;
            rtc_timeoffset = 0;
            break;
        case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
            if (def->clock.data.utc_reset) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("unsupported clock adjustment='reset'"));
                return -1;
            }
            vmlocaltime = 1;
            rtc_timeoffset = 0;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported clock offset='%s'"),
                           virDomainClockOffsetTypeToString(def->clock.offset));
            return -1;
        }
        if (xenConfigSetInt(conf, "rtc_timeoffset", rtc_timeoffset) < 0)
            return -1;
    } else {
        /* PV: UTC and LOCALTIME */
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
            return -1;
        }
    } /* !hvm */

    if (xenConfigSetInt(conf, "localtime", vmlocaltime) < 0)
        return -1;

    return 0;
}


static int
xenFormatEventActions(virConfPtr conf, virDomainDefPtr def)
{
    const char *lifecycle = NULL;

    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onPoweroff))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onPoweroff);
        return -1;
    }
    if (xenConfigSetString(conf, "on_poweroff", lifecycle) < 0)
        return -1;


    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onReboot))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onReboot);
        return -1;
    }
    if (xenConfigSetString(conf, "on_reboot", lifecycle) < 0)
        return -1;


    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onCrash))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %d"), def->onCrash);
        return -1;
    }
    if (xenConfigSetString(conf, "on_crash", lifecycle) < 0)
        return -1;

    return 0;
}


static int
xenFormatCharDev(virConfPtr conf, virDomainDefPtr def,
                 const char *nativeFormat)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (def->nparallels) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str;
            int ret;

            ret = xenFormatSxprChr(def->parallels[0], &buf);
            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenConfigSetString(conf, "parallel", str);
            VIR_FREE(str);
            if (ret < 0)
                return -1;
        } else {
            if (xenConfigSetString(conf, "parallel", "none") < 0)
                return -1;
        }

        if (def->nserials) {
            if ((def->nserials == 1) && (def->serials[0]->target.port == 0)) {
                virBuffer buf = VIR_BUFFER_INITIALIZER;
                char *str;
                int ret;

                ret = xenFormatSxprChr(def->serials[0], &buf);
                str = virBufferContentAndReset(&buf);
                if (ret == 0)
                    ret = xenConfigSetString(conf, "serial", str);
                VIR_FREE(str);
                if (ret < 0)
                    return -1;
            } else {
                size_t j = 0;
                int maxport = -1, port;
                virConfValuePtr serialVal = NULL;

                if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Multiple serial devices are not supported by xen-xm"));
                    return -1;
                }

                if (VIR_ALLOC(serialVal) < 0)
                    return -1;

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

                    if (xenFormatSerial(serialVal, chr) < 0) {
                        VIR_FREE(serialVal);
                        return -1;
                    }
                }

                if (serialVal->list != NULL) {
                    int ret = virConfSetValue(conf, "serial", serialVal);

                    serialVal = NULL;
                    if (ret < 0)
                        return -1;
                }
                VIR_FREE(serialVal);
            }
        } else {
            if (xenConfigSetString(conf, "serial", "none") < 0)
                return -1;
        }
    }

    return 0;
}


static int
xenFormatCPUAllocation(virConfPtr conf, virDomainDefPtr def)
{
    int ret = -1;
    char *cpus = NULL;

    if (virDomainDefGetVcpus(def) < virDomainDefGetVcpusMax(def) &&
        xenConfigSetInt(conf, "maxvcpus", virDomainDefGetVcpusMax(def)) < 0)
        goto cleanup;
    if (xenConfigSetInt(conf, "vcpus", virDomainDefGetVcpus(def)) < 0)
        goto cleanup;

    if ((def->cpumask != NULL) &&
        ((cpus = virBitmapFormat(def->cpumask)) == NULL)) {
        goto cleanup;
    }

    if (cpus &&
        xenConfigSetString(conf, "cpus", cpus) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(cpus);
    return ret;
}


static int
xenFormatCPUFeatures(virConfPtr conf, virDomainDefPtr def)
{
    size_t i;
    bool hvm = !!(def->os.type == VIR_DOMAIN_OSTYPE_HVM);

    if (hvm) {
        if (xenConfigSetInt(conf, "pae",
                            (def->features[VIR_DOMAIN_FEATURE_PAE] ==
                            VIR_TRISTATE_SWITCH_ON) ? 1 : 0) < 0)
            return -1;

        if (xenConfigSetInt(conf, "acpi",
                            (def->features[VIR_DOMAIN_FEATURE_ACPI] ==
                            VIR_TRISTATE_SWITCH_ON) ? 1 : 0) < 0)
            return -1;

        if (xenConfigSetInt(conf, "apic",
                            (def->features[VIR_DOMAIN_FEATURE_APIC] ==
                            VIR_TRISTATE_SWITCH_ON) ? 1 : 0) < 0)
            return -1;

        if (def->features[VIR_DOMAIN_FEATURE_HAP] == VIR_TRISTATE_SWITCH_OFF) {
            if (xenConfigSetInt(conf, "hap", 0) < 0)
                return -1;
        }

        if (xenConfigSetInt(conf, "viridian",
                            (def->features[VIR_DOMAIN_FEATURE_VIRIDIAN] ==
                             VIR_TRISTATE_SWITCH_ON) ? 1 : 0) < 0)
            return -1;
    }

    for (i = 0; i < def->clock.ntimers; i++) {
        switch ((virDomainTimerNameType)def->clock.timers[i]->name) {
        case VIR_DOMAIN_TIMER_NAME_TSC:
            switch (def->clock.timers[i]->mode) {
            case VIR_DOMAIN_TIMER_MODE_NATIVE:
                if (xenConfigSetString(conf, "tsc_mode", "native") < 0)
                    return -1;
                break;
            case VIR_DOMAIN_TIMER_MODE_PARAVIRT:
                if (xenConfigSetString(conf, "tsc_mode", "native_paravirt") < 0)
                    return -1;
                break;
            case VIR_DOMAIN_TIMER_MODE_EMULATE:
                if (xenConfigSetString(conf, "tsc_mode", "always_emulate") < 0)
                    return -1;
                break;
            default:
                if (xenConfigSetString(conf, "tsc_mode", "default") < 0)
                    return -1;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            if (hvm) {
                int enable_hpet = def->clock.timers[i]->present != 0;

                /* disable hpet if 'present' is 0, enable otherwise */
                if (xenConfigSetInt(conf, "hpet", enable_hpet) < 0)
                    return -1;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported timer type (name) '%s'"),
                               virDomainTimerNameTypeToString(def->clock.timers[i]->name));
                return -1;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_PIT:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%s'"),
                           virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            return -1;

        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        }
    }

    return 0;
}


static int
xenFormatEmulator(virConfPtr conf, virDomainDefPtr def)
{
    if (def->emulator &&
        xenConfigSetString(conf, "device_model", def->emulator) < 0)
        return -1;

    return 0;
}


static int
xenFormatVfb(virConfPtr conf, virDomainDefPtr def)
{
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM ? 1 : 0;

    if (def->ngraphics == 1 &&
        def->graphics[0]->type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        if (hvm) {
            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                if (xenConfigSetInt(conf, "sdl", 1) < 0)
                    return -1;

                if (xenConfigSetInt(conf, "vnc", 0) < 0)
                    return -1;

                if (def->graphics[0]->data.sdl.display &&
                    xenConfigSetString(conf, "display",
                                       def->graphics[0]->data.sdl.display) < 0)
                    return -1;

                if (def->graphics[0]->data.sdl.xauth &&
                    xenConfigSetString(conf, "xauthority",
                                       def->graphics[0]->data.sdl.xauth) < 0)
                    return -1;
            } else {
                virDomainGraphicsListenDefPtr glisten;

                if (xenConfigSetInt(conf, "sdl", 0) < 0)
                    return -1;

                if (xenConfigSetInt(conf, "vnc", 1) < 0)
                    return -1;

                if (xenConfigSetInt(conf, "vncunused",
                              def->graphics[0]->data.vnc.autoport ? 1 : 0) < 0)
                    return -1;

                if (!def->graphics[0]->data.vnc.autoport &&
                    xenConfigSetInt(conf, "vncdisplay",
                                    def->graphics[0]->data.vnc.port - 5900) < 0)
                    return -1;

                if ((glisten = virDomainGraphicsGetListen(def->graphics[0], 0)) &&
                    glisten->address &&
                    xenConfigSetString(conf, "vnclisten", glisten->address) < 0)
                    return -1;

                if (def->graphics[0]->data.vnc.auth.passwd &&
                    xenConfigSetString(conf, "vncpasswd",
                                       def->graphics[0]->data.vnc.auth.passwd) < 0)
                    return -1;

                if (def->graphics[0]->data.vnc.keymap &&
                    xenConfigSetString(conf, "keymap",
                                       def->graphics[0]->data.vnc.keymap) < 0)
                    return -1;
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
                virDomainGraphicsListenDefPtr glisten
                    = virDomainGraphicsGetListen(def->graphics[0], 0);

                virBufferAddLit(&buf, "type=vnc");
                virBufferAsprintf(&buf, ",vncunused=%d",
                                  def->graphics[0]->data.vnc.autoport ? 1 : 0);
                if (!def->graphics[0]->data.vnc.autoport)
                    virBufferAsprintf(&buf, ",vncdisplay=%d",
                                      def->graphics[0]->data.vnc.port - 5900);
                if (glisten && glisten->address)
                    virBufferAsprintf(&buf, ",vnclisten=%s", glisten->address);
                if (def->graphics[0]->data.vnc.auth.passwd)
                    virBufferAsprintf(&buf, ",vncpasswd=%s",
                                      def->graphics[0]->data.vnc.auth.passwd);
                if (def->graphics[0]->data.vnc.keymap)
                    virBufferAsprintf(&buf, ",keymap=%s",
                                      def->graphics[0]->data.vnc.keymap);
            }
            if (virBufferCheckError(&buf) < 0)
                return -1;

            vfbstr = virBufferContentAndReset(&buf);

            if (VIR_ALLOC(vfb) < 0) {
                VIR_FREE(vfbstr);
                return -1;
            }

            if (VIR_ALLOC(disp) < 0) {
                VIR_FREE(vfb);
                VIR_FREE(vfbstr);
                return -1;
            }

            vfb->type = VIR_CONF_LIST;
            vfb->list = disp;
            disp->type = VIR_CONF_STRING;
            disp->str = vfbstr;

            if (virConfSetValue(conf, "vfb", vfb) < 0)
                return -1;
        }
    }

    return 0;
}


static int
xenFormatSound(virConfPtr conf, virDomainDefPtr def)
{
    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (def->sounds) {
            virBuffer buf = VIR_BUFFER_INITIALIZER;
            char *str = NULL;
            int ret = xenFormatSxprSound(def, &buf);

            str = virBufferContentAndReset(&buf);
            if (ret == 0)
                ret = xenConfigSetString(conf, "soundhw", str);

            VIR_FREE(str);
            if (ret < 0)
                return -1;
        }
    }

    return 0;
}



static int
xenFormatVif(virConfPtr conf,
             virConnectPtr conn,
             virDomainDefPtr def,
             const char *vif_typename)
{
    virConfValuePtr netVal = NULL;
    size_t i;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;

    if (VIR_ALLOC(netVal) < 0)
        goto cleanup;
    netVal->type = VIR_CONF_LIST;
    netVal->list = NULL;

    for (i = 0; i < def->nnets; i++) {
        if (xenFormatNet(conn, netVal, def->nets[i],
                         hvm, vif_typename) < 0)
            goto cleanup;
    }

    if (netVal->list != NULL) {
        int ret = virConfSetValue(conf, "vif", netVal);
        netVal = NULL;
        if (ret < 0)
            goto cleanup;
    }

    VIR_FREE(netVal);
    return 0;

 cleanup:
    virConfFreeValue(netVal);
    return -1;
}


/*
 * A convenience function for formatting all config common to both XM and XL
 */
int
xenFormatConfigCommon(virConfPtr conf,
                      virDomainDefPtr def,
                      virConnectPtr conn,
                      const char *nativeFormat)
{
    if (xenFormatGeneralMeta(conf, def) < 0)
        return -1;

    if (xenFormatMem(conf, def) < 0)
        return -1;

    if (xenFormatCPUAllocation(conf, def) < 0)
        return -1;

    if (xenFormatCPUFeatures(conf, def) < 0)
        return -1;

    if (xenFormatTimeOffset(conf, def) < 0)
        return -1;

    if (xenFormatEventActions(conf, def) < 0)
        return -1;

    if (xenFormatEmulator(conf, def) < 0)
        return -1;

    if (xenFormatVfb(conf, def) < 0)
        return -1;

    if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XL)) {
        if (xenFormatVif(conf, conn, def, "vif") < 0)
            return -1;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
        if (xenFormatVif(conf, conn, def, "netfront") < 0)
            return -1;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %s"), nativeFormat);
        return -1;
    }

    if (xenFormatPCI(conf, def) < 0)
        return -1;

    if (xenFormatCharDev(conf, def, nativeFormat) < 0)
        return -1;

    if (xenFormatSound(conf, def) < 0)
        return -1;

    return 0;
}


int
xenDomainDefAddImplicitInputDevice(virDomainDefPtr def)
{
    virDomainInputBus implicitInputBus = VIR_DOMAIN_INPUT_BUS_XEN;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM)
        implicitInputBus = VIR_DOMAIN_INPUT_BUS_PS2;

    if (virDomainDefMaybeAddInput(def,
                                  VIR_DOMAIN_INPUT_TYPE_MOUSE,
                                  implicitInputBus) < 0)
        return -1;

    if (virDomainDefMaybeAddInput(def,
                                  VIR_DOMAIN_INPUT_TYPE_KBD,
                                  implicitInputBus) < 0)
        return -1;

    return 0;
}
