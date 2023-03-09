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
#include "xenxs_private.h"
#include "domain_conf.h"
#include "virstring.h"
#include "xen_common.h"

#define VIR_FROM_THIS VIR_FROM_XEN

/*
 * Convenience method to grab a long int from the config file object
 */
int
xenConfigGetBool(virConf *conf,
                 const char *name,
                 int *value,
                 int def)
{
    virConfValue *val;

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
                       _("config value %1$s was malformed"), name);
        return -1;
    }
    return 0;
}


/*
 * Convenience method to grab a int from the config file object
 */
int
xenConfigGetULong(virConf *conf,
                  const char *name,
                  unsigned long *value,
                  unsigned long def)
{
    virConfValue *val;

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
                           _("config value %1$s was malformed"), name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %1$s was malformed"), name);
        return -1;
    }
    return 0;
}


/*
 * Convenience method to grab a int from the config file object
 */
static int
xenConfigGetULongLong(virConf *conf,
                      const char *name,
                      unsigned long long *value,
                      unsigned long long def)
{
    virConfValue *val;

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
                           _("config value %1$s was malformed"), name);
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("config value %1$s was malformed"), name);
        return -1;
    }
    return 0;
}


static int
xenConfigCopyStringInternal(virConf *conf,
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
                       _("config value %1$s was missing"), name);
        return -1;
    }

    return 1;
}


int
xenConfigCopyString(virConf *conf, const char *name, char **value)
{
    return xenConfigCopyStringInternal(conf, name, value, 0);
}


int
xenConfigCopyStringOpt(virConf *conf, const char *name, char **value)
{
    return xenConfigCopyStringInternal(conf, name, value, 1);
}


/*
 * Convenience method to grab a string UUID from the config file object
 */
static int
xenConfigGetUUID(virConf *conf, const char *name, unsigned char *uuid)
{
    g_autofree char *string = NULL;
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
                       _("%1$s can't be empty"), name);
        return -1;
    }

    if (virUUIDParse(string, uuid) < 0) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("%1$s not parseable"), string);
        return -1;
    }

    return 0;
}


/*
 * Convenience method to grab a string from the config file object
 */
int
xenConfigGetString(virConf *conf,
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
        *value = g_strdup(def);
    } else {
        *value = string;
    }

    return 0;
}


int
xenConfigSetInt(virConf *conf, const char *setting, long long l)
{
    virConfValue *value = NULL;

    if ((long)l != l) {
        virReportError(VIR_ERR_OVERFLOW, _("failed to store %1$lld to %2$s"),
                       l, setting);
        return -1;
    }
    value = g_new0(virConfValue, 1);

    value->type = VIR_CONF_LLONG;
    value->next = NULL;
    value->l = l;

    return virConfSetValue(conf, setting, &value);
}


int
xenConfigSetString(virConf *conf, const char *setting, const char *str)
{
    virConfValue *value = NULL;

    value = g_new0(virConfValue, 1);

    value->type = VIR_CONF_STRING;
    value->next = NULL;
    value->str = g_strdup(str);

    return virConfSetValue(conf, setting, &value);
}


static int
xenParseMem(virConf *conf, virDomainDef *def)
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
xenParseTimeOffset(virConf *conf, virDomainDef *def)
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
xenParseEventsActions(virConf *conf, virDomainDef *def)
{
    g_autofree char *on_poweroff = NULL;
    g_autofree char *on_reboot = NULL;
    g_autofree char *on_crash = NULL;

    if (xenConfigGetString(conf, "on_poweroff", &on_poweroff, "destroy") < 0)
        return -1;

    if ((def->onPoweroff = virDomainLifecycleActionTypeFromString(on_poweroff)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %1$s for on_poweroff"), on_poweroff);
        return -1;
    }

    if (xenConfigGetString(conf, "on_reboot", &on_reboot, "restart") < 0)
        return -1;

    if ((def->onReboot = virDomainLifecycleActionTypeFromString(on_reboot)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %1$s for on_reboot"), on_reboot);
        return -1;
    }

    if (xenConfigGetString(conf, "on_crash", &on_crash, "restart") < 0)
        return -1;

    if ((def->onCrash = virDomainLifecycleActionTypeFromString(on_crash)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected value %1$s for on_crash"), on_crash);
        return -1;
    }

    return 0;
}


static virDomainHostdevDef *
xenParsePCI(char *entry)
{
    virDomainHostdevDef *hostdev = NULL;
    g_auto(GStrv) tokens = NULL;
    g_auto(GStrv) options = NULL;
    size_t nexttoken = 0;
    char *str;
    char *nextstr;
    int domain = 0x0;
    int bus;
    int slot;
    int func;
    virTristateBool filtered = VIR_TRISTATE_BOOL_ABSENT;

    /* pci=['00:1b.0','0000:00:13.0,permissive=1'] */
    if (!(tokens = g_strsplit(entry, ":", 3)))
        return NULL;

    /* domain */
    if (g_strv_length(tokens) == 3) {
        if (virStrToLong_i(tokens[nexttoken], NULL, 16, &domain) < 0)
            return NULL;
        nexttoken++;
    }

    /* bus */
    if (virStrToLong_i(tokens[nexttoken], NULL, 16, &bus) < 0)
        return NULL;
    nexttoken++;

    /* slot, function, and options */
    str = tokens[nexttoken];
    if (!(nextstr = strchr(str, '.'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed PCI address %1$s"), str);
        return NULL;
    }
    *nextstr = '\0';
    nextstr++;
    if (virStrToLong_i(str, NULL, 16, &slot) < 0)
        return NULL;
    str = nextstr++;

    nextstr = strchr(str, ',');
    if (nextstr) {
        *nextstr = '\0';
        nextstr++;
    }
    if (virStrToLong_i(str, NULL, 16, &func) < 0)
        return NULL;

    str = nextstr;
    if (str && (options = g_strsplit(str, ",", 0))) {
        size_t i;

        for (i = 0; options[i] != NULL; i++) {
            char *val;

            if (!(val = strchr(options[i], '='))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Malformed PCI options %1$s"), str);
                return NULL;
            }
            *val = '\0';
            val++;
            if (STREQ(options[i], "permissive")) {
                int intval;

                /* xl.cfg(5) specifies false as 0 and true as any other numeric value */
                if (virStrToLong_i(val, NULL, 10, &intval) < 0)
                    return NULL;
                filtered = intval ? VIR_TRISTATE_BOOL_NO : VIR_TRISTATE_BOOL_YES;
            }
        }
    }

    if (!(hostdev = virDomainHostdevDefNew()))
       return NULL;

    hostdev->managed = false;
    hostdev->writeFiltering = filtered;
    hostdev->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    hostdev->source.subsys.u.pci.addr.domain = domain;
    hostdev->source.subsys.u.pci.addr.bus = bus;
    hostdev->source.subsys.u.pci.addr.slot = slot;
    hostdev->source.subsys.u.pci.addr.function = func;

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
xenParsePCIList(virConf *conf, virDomainDef *def)
{
    g_auto(GStrv) pcis = NULL;
    char **entries = NULL;
    int rc;

    if ((rc = virConfGetValueStringList(conf, "pci", false, &pcis)) <= 0)
        return xenHandleConfGetValueStringListErrors(rc);

    for (entries = pcis; *entries; entries++) {
        char *entry = *entries;
        virDomainHostdevDef *hostdev;

        if (!(hostdev = xenParsePCI(entry)))
            return -1;

        VIR_APPEND_ELEMENT(def->hostdevs, def->nhostdevs, hostdev);
    }

    return 0;
}


static int
xenParseCPU(virConf *conf,
            virDomainDef *def,
            virDomainXMLOption *xmlopt)
{
    unsigned long count = 0;
    g_autofree char *cpus = NULL;

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

    return 0;
}


static int
xenParseHypervisorFeatures(virConf *conf, virDomainDef *def)
{
    g_autofree char *tscmode = NULL;
    g_autofree char *passthrough = NULL;
    virDomainTimerDef *timer;
    int val = 0;

    if (xenConfigGetString(conf, "tsc_mode", &tscmode, NULL) < 0)
        return -1;

    if (tscmode) {
        VIR_EXPAND_N(def->clock.timers, def->clock.ntimers, 1);

        timer = g_new0(virDomainTimerDef, 1);
        timer->name = VIR_DOMAIN_TIMER_NAME_TSC;
        timer->present = VIR_TRISTATE_BOOL_YES;
        timer->tickpolicy = VIR_DOMAIN_TIMER_TICKPOLICY_NONE;
        timer->mode = VIR_DOMAIN_TIMER_MODE_AUTO;
        timer->track = VIR_DOMAIN_TIMER_TRACK_NONE;
        if (STREQ_NULLABLE(tscmode, "always_emulate"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_EMULATE;
        else if (STREQ_NULLABLE(tscmode, "native"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_NATIVE;
        else if (STREQ_NULLABLE(tscmode, "native_paravirt"))
            timer->mode = VIR_DOMAIN_TIMER_MODE_PARAVIRT;

        def->clock.timers[def->clock.ntimers - 1] = timer;
    }

    if (xenConfigGetString(conf, "passthrough", &passthrough, NULL) < 0)
        return -1;

    if (passthrough) {
        if (STREQ(passthrough, "disabled")) {
            def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_OFF;
            def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH] = VIR_TRISTATE_SWITCH_OFF;
        } else if (STREQ(passthrough, "enabled")) {
            def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_ON;
            def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH] = VIR_TRISTATE_SWITCH_ON;
        } else if (STREQ(passthrough, "sync_pt")) {
            def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_ON;
            def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH] = VIR_TRISTATE_SWITCH_ON;
            def->xen_passthrough_mode = VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SYNC_PT;
        } else if (STREQ(passthrough, "share_pt")) {
            def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_ON;
            def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH] = VIR_TRISTATE_SWITCH_ON;
            def->xen_passthrough_mode = VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SHARE_PT;
        } else {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("Invalid passthrough mode %1$s"), passthrough);
        }
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
            VIR_EXPAND_N(def->clock.timers, def->clock.ntimers, 1);

            timer = g_new0(virDomainTimerDef, 1);
            timer->name = VIR_DOMAIN_TIMER_NAME_HPET;
            timer->present = virTristateBoolFromBool(val);
            timer->tickpolicy = VIR_DOMAIN_TIMER_TICKPOLICY_NONE;
            timer->mode = VIR_DOMAIN_TIMER_MODE_NONE;
            timer->track = VIR_DOMAIN_TIMER_TRACK_NONE;

            def->clock.timers[def->clock.ntimers - 1] = timer;
        }
    } else {
        if (xenConfigGetBool(conf, "e820_host", &val, 0) < 0) {
            return -1;
        } else if (val) {
            def->features[VIR_DOMAIN_FEATURE_XEN] = VIR_TRISTATE_SWITCH_ON;
            def->xen_features[VIR_DOMAIN_XEN_E820_HOST] = VIR_TRISTATE_SWITCH_ON;
        }
    }

    return 0;
}


#define MAX_VFB 1024

static int
xenParseVfb(virConf *conf, virDomainDef *def)
{
    int val;
    char *listenAddr = NULL;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;
    virDomainGraphicsDef *graphics = NULL;

    if (hvm) {
        if (xenConfigGetBool(conf, "vnc", &val, 0) < 0)
            goto cleanup;
        if (val) {
            graphics = g_new0(virDomainGraphicsDef, 1);
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
            def->graphics = g_new0(virDomainGraphicsDef *, 1);
            def->graphics[0] = g_steal_pointer(&graphics);
            def->ngraphics = 1;
        } else {
            if (xenConfigGetBool(conf, "sdl", &val, 0) < 0)
                goto cleanup;
            if (val) {
                graphics = g_new0(virDomainGraphicsDef, 1);
                graphics->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
                if (xenConfigCopyStringOpt(conf, "display", &graphics->data.sdl.display) < 0)
                    goto cleanup;
                if (xenConfigCopyStringOpt(conf, "xauthority", &graphics->data.sdl.xauth) < 0)
                    goto cleanup;
                def->graphics = g_new0(virDomainGraphicsDef *, 1);
                def->graphics[0] = g_steal_pointer(&graphics);
                def->ngraphics = 1;
            }
        }
    }

    if (!hvm && def->graphics == NULL) { /* New PV guests use this format */
        g_auto(GStrv) vfbs = NULL;
        int rc;

        if ((rc = virConfGetValueStringList(conf, "vfb", false, &vfbs)) == 1) {
            char vfb[MAX_VFB];
            char *key = vfb;

            if (virStrcpyStatic(vfb, *vfbs) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("VFB %1$s too big for destination"),
                               *vfbs);
                goto cleanup;
            }

            graphics = g_new0(virDomainGraphicsDef, 1);
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
                        listenAddr = g_strdup(key + 10);
                    } else if (STRPREFIX(key, "vncpasswd=")) {
                        graphics->data.vnc.auth.passwd = g_strdup(key + 10);
                    } else if (STRPREFIX(key, "keymap=")) {
                        graphics->data.vnc.keymap = g_strdup(key + 7);
                    } else if (STRPREFIX(key, "vncdisplay=")) {
                        if (virStrToLong_i(key + 11, NULL, 10,
                                           &graphics->data.vnc.port) < 0) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("invalid vncdisplay value '%1$s'"),
                                           key + 11);
                            goto cleanup;
                        }
                        graphics->data.vnc.port += 5900;
                    }
                } else {
                    if (STRPREFIX(key, "display=")) {
                        graphics->data.sdl.display = g_strdup(key + 8);
                    } else if (STRPREFIX(key, "xauthority=")) {
                        graphics->data.sdl.xauth = g_strdup(key + 11);
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
            def->graphics = g_new0(virDomainGraphicsDef *, 1);
            def->graphics[0] = g_steal_pointer(&graphics);
            def->ngraphics = 1;
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


/**
  * xenParseSxprChar:
  * @value: A string describing a character device.
  * @tty: the console pty path
  *
  * Parse the xend S-expression for description of a character device.
  *
  * Returns a character device object or NULL in case of failure.
  */
static virDomainChrDef *
xenParseSxprChar(const char *value,
                 const char *tty)
{
    const char *prefix;
    char *tmp;
    virDomainChrDef *def;

    if (!(def = virDomainChrDefNew(NULL)))
        return NULL;

    prefix = value;

    if (g_path_is_absolute(value)) {
        def->source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        def->source->data.file.path = g_strdup(value);
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
                               _("unknown chr device type '%1$s'"), prefix);
                goto error;
            }
        }
    }

    switch (def->source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        def->source->data.file.path = g_strdup(tty);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        def->source->data.file.path = g_strdup(value);
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

        if (offset != value)
            def->source->data.tcp.host = g_strndup(value, offset - value);

        offset2 = strchr(offset, ',');
        offset++;
        if (offset2)
            def->source->data.tcp.service = g_strndup(offset,
                                                      offset2 - offset);
        else
            def->source->data.tcp.service = g_strdup(offset);

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

        if (offset != value)
            def->source->data.udp.connectHost = g_strndup(value,
                                                          offset - value);

        offset2 = strchr(offset, '@');
        if (offset2 != NULL) {
            def->source->data.udp.connectService = g_strndup(offset + 1,
                                                             offset2 - offset - 1);

            offset3 = strchr(offset2, ':');
            if (offset3 == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("malformed char device string"));
                goto error;
            }

            if (offset3 > (offset2 + 1))
                def->source->data.udp.bindHost = g_strndup(offset2 + 1,
                                                           offset3 - offset2 - 1);

            def->source->data.udp.bindService = g_strdup(offset3 + 1);
        } else {
            def->source->data.udp.connectService = g_strdup(offset + 1);
        }
    }
    break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    {
        const char *offset = strchr(value, ',');
        if (offset)
            def->source->data.nix.path = g_strndup(value, offset - value);
        else
            def->source->data.nix.path = g_strdup(value);

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


static int
xenParseCharDev(virConf *conf, virDomainDef *def, const char *nativeFormat)
{
    g_auto(GStrv) serials = NULL;
    virDomainChrDef *chr = NULL;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        g_autofree char *parallel = NULL;
        int rc;

        if (xenConfigGetString(conf, "parallel", &parallel, NULL) < 0)
            goto cleanup;
        if (parallel && STRNEQ(parallel, "none") &&
            !(chr = xenParseSxprChar(parallel, NULL)))
            goto cleanup;
        if (chr) {
            def->parallels = g_new0(virDomainChrDef *, 1);

            chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
            chr->target.port = 0;
            def->parallels[0] = g_steal_pointer(&chr);
            def->nparallels++;
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
                VIR_APPEND_ELEMENT(def->serials, def->nserials, chr);
            }
        } else {
            g_autofree char *serial = NULL;

            if (xenHandleConfGetValueStringListErrors(rc) < 0)
                goto cleanup;

            /* If domain is not using multiple serial ports we parse data old way */
            if (xenConfigGetString(conf, "serial", &serial, NULL) < 0)
                goto cleanup;
            if (serial && STRNEQ(serial, "none") &&
                !(chr = xenParseSxprChar(serial, NULL)))
                goto cleanup;
            if (chr) {
                def->serials = g_new0(virDomainChrDef *, 1);
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = 0;
                def->serials[0] = chr;
                def->nserials++;
            }
        }
    } else {
        def->consoles = g_new0(virDomainChrDef *, 1);
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
xenParseVifBridge(virDomainNetDef *net, const char *bridge)
{
    char *vlanstr;
    unsigned int tag;

    if ((vlanstr = strchr(bridge, '.'))) {
        /* 'bridge' string contains a bridge name and single vlan tag */
        net->data.bridge.brname = g_strndup(bridge, vlanstr - bridge);

        vlanstr++;
        if (virStrToLong_ui(vlanstr, NULL, 10, &tag) < 0)
            return -1;

        net->vlan.tag = g_new0(unsigned int, 1);
        net->vlan.tag[0] = tag;
        net->vlan.nTags = 1;

        net->virtPortProfile = g_new0(virNetDevVPortProfile, 1);
        net->virtPortProfile->virtPortType = VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH;
        return 0;
    } else if ((vlanstr = strchr(bridge, ':'))) {
        /* 'bridge' string contains a bridge name and one or more vlan trunks */
        size_t i;
        size_t nvlans = 0;
        g_auto(GStrv) vlanstr_list = g_strsplit(bridge, ":", 0);

        if (!vlanstr_list)
            return -1;

        net->data.bridge.brname = g_strdup(vlanstr_list[0]);

        for (i = 1; vlanstr_list[i]; i++)
            nvlans++;

        net->vlan.tag = g_new0(unsigned int, nvlans);

        for (i = 1; i <= nvlans; i++) {
            if (virStrToLong_ui(vlanstr_list[i], NULL, 10, &tag) < 0)
                return -1;

            net->vlan.tag[i - 1] = tag;
        }
        net->vlan.nTags = nvlans;
        net->vlan.trunk = true;

        net->virtPortProfile = g_new0(virNetDevVPortProfile, 1);
        net->virtPortProfile->virtPortType = VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH;
        return 0;
    } else {
        /* 'bridge' string only contains the bridge name */
        net->data.bridge.brname = g_strdup(bridge);
    }

    return 0;
}


static const char *vif_bytes_per_sec_re = "^[0-9]+[GMK]?[Bb]/s$";

static int
xenParseSxprVifRate(const char *rate, unsigned long long *kbytes_per_sec)
{
    g_autoptr(GRegex) regex = NULL;
    g_autoptr(GError) err = NULL;
    g_autofree char *trate = NULL;
    char *p;
    char *suffix;
    unsigned long long tmp;

    trate = g_strdup(rate);

    p = strchr(trate, '@');
    if (p != NULL)
        *p = 0;

    regex = g_regex_new(vif_bytes_per_sec_re, 0, 0, &err);
    if (!regex) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to compile regex %1$s"), err->message);
        return -1;
    }

    if (!g_regex_match(regex, trate, 0, NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid rate '%1$s' specified"), rate);
        return -1;
    }

    if (virStrToLong_ull(rate, &suffix, 10, &tmp)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse rate '%1$s'"), rate);
        return -1;
    }

    if (*suffix == 'G')
       tmp *= 1024 * 1024;
    else if (*suffix == 'M')
       tmp *= 1024;

    if (*suffix == 'b' || *(suffix + 1) == 'b')
       tmp /= 8;

    *kbytes_per_sec = tmp;
    return 0;
}


static virDomainNetDef *
xenParseVif(char *entry, const char *vif_typename)
{
    virDomainNetDef *net = NULL;
    virDomainNetDef *ret = NULL;
    g_auto(GStrv) keyvals = NULL;
    GStrv keyval;
    const char *script = NULL;
    const char *model = NULL;
    const char *type = NULL;
    const char *ip = NULL;
    const char *mac = NULL;
    const char *bridge = NULL;
    const char *vifname = NULL;
    const char *rate = NULL;

    keyvals = g_strsplit(entry, ",", 0);

    for (keyval = keyvals; keyval && *keyval; keyval++) {
        const char *key = *keyval;
        char *val = strchr(key, '=');

        virSkipSpaces(&key);

        if (!val)
            return NULL;

        val++;

        if (STRPREFIX(key, "mac=")) {
            mac = val;
        } else if (STRPREFIX(key, "bridge=")) {
            bridge = val;
        } else if (STRPREFIX(key, "script=")) {
            script = val;
        } else if (STRPREFIX(key, "model=")) {
            model = val;
        } else if (STRPREFIX(key, "type=")) {
            type = val;
        } else if (STRPREFIX(key, "vifname=")) {
            vifname = val;
        } else if (STRPREFIX(key, "ip=")) {
            ip = val;
        } else if (STRPREFIX(key, "rate=")) {
            rate = val;
        }
    }

    if (!(net = virDomainNetDefNew(NULL)))
        goto cleanup;

    if (mac) {
        if (virMacAddrParse(mac, &net->mac) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("malformed mac address '%1$s'"), mac);
            goto cleanup;
        }
    }

    if (bridge || STREQ_NULLABLE(script, "vif-bridge") ||
        STREQ_NULLABLE(script, "vif-vnic")) {
        net->type = VIR_DOMAIN_NET_TYPE_BRIDGE;
    } else {
        net->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE && bridge) {
        if (xenParseVifBridge(net, bridge) < 0)
            goto cleanup;
    }
    if (ip) {
        g_auto(GStrv) ip_list = g_strsplit(ip, " ", 0);
        size_t i;

        if (!ip_list)
            goto cleanup;

        for (i = 0; ip_list[i]; i++) {
            if (virDomainNetAppendIPAddress(net, ip_list[i], 0, 0) < 0)
                goto cleanup;
        }
    }

    if (script && script[0])
        net->script = g_strdup(script);

    if (model) {
        if (virDomainNetSetModelString(net, model) < 0)
            goto cleanup;
    } else {
        if (type && STREQ(type, vif_typename))
            net->model = VIR_DOMAIN_NET_MODEL_NETFRONT;
    }

    if (vifname && vifname[0])
        net->ifname = g_strdup(vifname);

    if (rate) {
        virNetDevBandwidth *bandwidth;
        unsigned long long kbytes_per_sec;

        if (xenParseSxprVifRate(rate, &kbytes_per_sec) < 0)
            goto cleanup;

        bandwidth = g_new0(virNetDevBandwidth, 1);
        bandwidth->out = g_new0(virNetDevBandwidthRate, 1);
        bandwidth->out->average = kbytes_per_sec;
        net->bandwidth = bandwidth;
    }

    ret = g_steal_pointer(&net);

 cleanup:
    virDomainNetDefFree(net);
    return ret;
}


static int
xenParseVifList(virConf *conf, virDomainDef *def, const char *vif_typename)
{
    virConfValue *list = virConfGetValue(conf, "vif");

    if (!list || list->type != VIR_CONF_LIST)
        return 0;

    for (list = list->list; list; list = list->next) {
        virDomainNetDef *net = NULL;

        if ((list->type != VIR_CONF_STRING) || (list->str == NULL))
            continue;

        if (!(net = xenParseVif(list->str, vif_typename)))
            return -1;

        VIR_APPEND_ELEMENT(def->nets, def->nnets, net);
    }

    return 0;
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
static int
xenParseSxprSound(virDomainDef *def,
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

        def->sounds = g_new0(virDomainSoundDef *,
                             VIR_DOMAIN_SOUND_MODEL_ES1370 + 1);

        for (i = 0; i < (VIR_DOMAIN_SOUND_MODEL_ES1370 + 1); i++) {
            virDomainSoundDef *sound = g_new0(virDomainSoundDef, 1);
            sound->model = i;
            def->sounds[def->nsounds++] = sound;
        }
    } else {
        g_autofree char *sounds = g_strdup(str);
        char *sound = sounds;
        int model;

        while (*sound != '\0') {
            char *next = strchr(sound, ',');
            virDomainSoundDef *snddef;

            if (next)
                *next = '\0';

            if ((model = virDomainSoundModelTypeFromString(sound)) < 0)
                return -1;

            snddef = g_new0(virDomainSoundDef, 1);
            snddef->model = model;

            VIR_APPEND_ELEMENT(def->sounds, def->nsounds, snddef);

            if (!next)
                break;

            sound = next + 1;
        }
    }

    return 0;
}


static int
xenParseEmulatedDevices(virConf *conf, virDomainDef *def)
{
    g_autofree char *str = NULL;

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
xenParseGeneralMeta(virConf *conf, virDomainDef *def, virCaps *caps)
{
    virCapsDomainData *capsdata = NULL;
    g_autofree char *str = NULL;
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
                           _("type %1$s is not supported"), str);
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
    def->os.machine = g_strdup(capsdata->machinetype);

    ret = 0;
 out:
    VIR_FREE(capsdata);
    return ret;
}


/*
 * A convenience function for parsing all config common to both XM and XL
 */
int
xenParseConfigCommon(virConf *conf,
                     virDomainDef *def,
                     virCaps *caps,
                     const char *nativeFormat,
                     virDomainXMLOption *xmlopt)
{
    if (xenParseGeneralMeta(conf, def, caps) < 0)
        return -1;

    if (xenParseMem(conf, def) < 0)
        return -1;

    if (xenParseEventsActions(conf, def) < 0)
        return -1;

    if (xenParseCPU(conf, def, xmlopt) < 0)
        return -1;

    if (xenParseHypervisorFeatures(conf, def) < 0)
        return -1;

    if (xenParseTimeOffset(conf, def) < 0)
        return -1;

    if (xenConfigCopyStringOpt(conf, "device_model_override", &def->emulator) < 0)
        return -1;

    if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XL)) {
        if (xenParseVifList(conf, def, "vif") < 0)
            return -1;
    } else if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
        if (xenParseVifList(conf, def, "netfront") < 0)
            return -1;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported config type %1$s"), nativeFormat);
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
static int
xenFormatSxprChr(virDomainChrDef *def,
                 virBuffer *buf)
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
                          NULLSTR_EMPTY(def->source->data.tcp.host),
                          NULLSTR_EMPTY(def->source->data.tcp.service),
                          (def->source->data.tcp.listen ?
                           ",server,nowait" : ""));
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferAsprintf(buf, "%s:%s:%s@%s:%s", type,
                          NULLSTR_EMPTY(def->source->data.udp.connectHost),
                          NULLSTR_EMPTY(def->source->data.udp.connectService),
                          NULLSTR_EMPTY(def->source->data.udp.bindHost),
                          NULLSTR_EMPTY(def->source->data.udp.bindService));
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(buf, "%s:", type);
        virBufferEscapeSexpr(buf, "%s", def->source->data.nix.path);
        if (def->source->data.nix.listen)
            virBufferAddLit(buf, ",server,nowait");
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chr device type '%1$s'"), type);
        return -1;
    }

    return 0;
}


static int
xenFormatSerial(virConfValue *list, virDomainChrDef *serial)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virConfValue *val;
    virConfValue *tmp;
    int ret;

    if (serial) {
        ret = xenFormatSxprChr(serial, &buf);
        if (ret < 0)
            return -1;
    } else {
        virBufferAddLit(&buf, "none");
    }

    val = g_new0(virConfValue, 1);

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
}

char *
xenMakeIPList(virNetDevIPInfo *guestIP)
{
    size_t i;
    g_auto(GStrv) address_array = NULL;

    address_array = g_new0(char *, guestIP->nips + 1);

    for (i = 0; i < guestIP->nips; i++) {
        address_array[i] = virSocketAddrFormat(&guestIP->ips[i]->address);
        if (!address_array[i])
            return NULL;
    }
    return g_strjoinv(" ", address_array);
}

static int
xenFormatNet(virConnectPtr conn,
             virConfValue *list,
             virDomainNetDef *net,
             int hvm,
             const char *vif_typename)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virConfValue *val;
    virConfValue *tmp;
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virBufferAsprintf(&buf, "mac=%s", virMacAddrFormat(&net->mac, macaddr));

    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    {
        const virNetDevVPortProfile *port_profile = virDomainNetGetActualVirtPortProfile(net);
        const virNetDevVlan *virt_vlan = virDomainNetGetActualVlan(net);
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
                           _("network %1$s is not active"),
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
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, _("Unsupported net type '%1$s'"),
                       virDomainNetTypeToString(net->type));
        return -1;

    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainNetType, net->type);
        return -1;
    }

    if (virDomainNetGetModelString(net)) {
        if (!hvm) {
            virBufferAsprintf(&buf, ",model=%s",
                              virDomainNetGetModelString(net));
        } else {
            if (net->model == VIR_DOMAIN_NET_MODEL_NETFRONT)
                virBufferAsprintf(&buf, ",type=%s", vif_typename);
            else
                virBufferAsprintf(&buf, ",model=%s",
                                  virDomainNetGetModelString(net));
        }
    }

    if (net->ifname)
        virBufferAsprintf(&buf, ",vifname=%s",
                          net->ifname);

    if (net->bandwidth && net->bandwidth->out && net->bandwidth->out->average)
        virBufferAsprintf(&buf, ",rate=%lluKB/s", net->bandwidth->out->average);

    val = g_new0(virConfValue, 1);
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
}


static int
xenFormatPCI(virConf *conf, virDomainDef *def)
{
    g_autoptr(virConfValue) pciVal = NULL;
    int hasPCI = 0;
    size_t i;

    for (i = 0; i < def->nhostdevs; i++)
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            hasPCI = 1;

    if (!hasPCI)
        return 0;

    pciVal = g_new0(virConfValue, 1);

    pciVal->type = VIR_CONF_LIST;
    pciVal->list = NULL;

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virConfValue *val;
            virConfValue *tmp;
            char *buf;
            const char *permissive_str = NULL;

            switch (def->hostdevs[i]->writeFiltering) {
                case VIR_TRISTATE_BOOL_YES:
                    permissive_str = ",permissive=0";
                    break;
                case VIR_TRISTATE_BOOL_NO:
                    permissive_str = ",permissive=1";
                    break;
                case VIR_TRISTATE_BOOL_ABSENT:
                case VIR_TRISTATE_BOOL_LAST:
                    permissive_str = "";
                    break;
            }

            buf = g_strdup_printf("%04x:%02x:%02x.%x%s",
                                  def->hostdevs[i]->source.subsys.u.pci.addr.domain,
                                  def->hostdevs[i]->source.subsys.u.pci.addr.bus,
                                  def->hostdevs[i]->source.subsys.u.pci.addr.slot,
                                  def->hostdevs[i]->source.subsys.u.pci.addr.function,
                                  permissive_str);


            val = g_new0(virConfValue, 1);
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

    if (pciVal->list != NULL &&
        virConfSetValue(conf, "pci", &pciVal) < 0)
        return -1;

    return 0;
}


static int
xenFormatGeneralMeta(virConf *conf, virDomainDef *def)
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
xenFormatMem(virConf *conf, virDomainDef *def)
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
xenFormatTimeOffset(virConf *conf, virDomainDef *def)
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
                           _("unsupported clock offset='%1$s'"),
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
                           _("unsupported clock offset='%1$s'"),
                           virDomainClockOffsetTypeToString(def->clock.offset));
            return -1;
        }
    } /* !hvm */

    if (xenConfigSetInt(conf, "localtime", vmlocaltime) < 0)
        return -1;

    return 0;
}


static int
xenFormatEventActions(virConf *conf, virDomainDef *def)
{
    const char *lifecycle = NULL;

    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onPoweroff))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %1$d"), def->onPoweroff);
        return -1;
    }
    if (xenConfigSetString(conf, "on_poweroff", lifecycle) < 0)
        return -1;


    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onReboot))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %1$d"), def->onReboot);
        return -1;
    }
    if (xenConfigSetString(conf, "on_reboot", lifecycle) < 0)
        return -1;


    if (!(lifecycle = virDomainLifecycleActionTypeToString(def->onCrash))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected lifecycle action %1$d"), def->onCrash);
        return -1;
    }
    if (xenConfigSetString(conf, "on_crash", lifecycle) < 0)
        return -1;

    return 0;
}


static int
xenFormatCharDev(virConf *conf, virDomainDef *def,
                 const char *nativeFormat)
{
    size_t i;

    if (def->os.type == VIR_DOMAIN_OSTYPE_HVM) {
        if (def->nparallels) {
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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
                g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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
                g_autoptr(virConfValue) serialVal = NULL;

                if (STREQ(nativeFormat, XEN_CONFIG_FORMAT_XM)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Multiple serial devices are not supported by xen-xm"));
                    return -1;
                }

                serialVal = g_new0(virConfValue, 1);
                serialVal->type = VIR_CONF_LIST;
                serialVal->list = NULL;

                for (i = 0; i < def->nserials; i++)
                    if (def->serials[i]->target.port > maxport)
                        maxport = def->serials[i]->target.port;

                for (port = 0; port <= maxport; port++) {
                    virDomainChrDef *chr = NULL;

                    for (j = 0; j < def->nserials; j++) {
                        if (def->serials[j]->target.port == port) {
                            chr = def->serials[j];
                            break;
                        }
                    }

                    if (xenFormatSerial(serialVal, chr) < 0) {
                        return -1;
                    }
                }

                if (serialVal->list != NULL &&
                    virConfSetValue(conf, "serial", &serialVal) < 0)
                    return -1;
            }
        } else {
            if (xenConfigSetString(conf, "serial", "none") < 0)
                return -1;
        }
    }

    return 0;
}


static int
xenFormatCPUAllocation(virConf *conf, virDomainDef *def)
{
    g_autofree char *cpus = NULL;

    if (virDomainDefGetVcpus(def) < virDomainDefGetVcpusMax(def) &&
        xenConfigSetInt(conf, "maxvcpus", virDomainDefGetVcpusMax(def)) < 0)
        return -1;
    if (xenConfigSetInt(conf, "vcpus", virDomainDefGetVcpus(def)) < 0)
        return -1;

    if ((def->cpumask != NULL) &&
        ((cpus = virBitmapFormat(def->cpumask)) == NULL)) {
        return -1;
    }

    if (cpus &&
        xenConfigSetString(conf, "cpus", cpus) < 0)
        return -1;

    return 0;
}


static int
xenFormatHypervisorFeatures(virConf *conf, virDomainDef *def)
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
    } else {
        if (def->features[VIR_DOMAIN_FEATURE_XEN] == VIR_TRISTATE_SWITCH_ON) {
            if (def->xen_features[VIR_DOMAIN_XEN_E820_HOST] == VIR_TRISTATE_SWITCH_ON)
                if (xenConfigSetInt(conf, "e820_host", 1) < 0)
                    return -1;
        }
    }

    if (def->features[VIR_DOMAIN_FEATURE_XEN] == VIR_TRISTATE_SWITCH_ON) {
        if (def->xen_features[VIR_DOMAIN_XEN_PASSTHROUGH] == VIR_TRISTATE_SWITCH_ON) {
            if (def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SYNC_PT ||
                def->xen_passthrough_mode == VIR_DOMAIN_XEN_PASSTHROUGH_MODE_SHARE_PT) {
                if (xenConfigSetString(conf, "passthrough",
                                       virDomainXenPassthroughModeTypeToString(def->xen_passthrough_mode)) < 0)
                    return -1;
            } else {
                if (xenConfigSetString(conf, "passthrough", "enabled") < 0)
                    return -1;
            }
        }
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
            case VIR_DOMAIN_TIMER_MODE_NONE:
            case VIR_DOMAIN_TIMER_MODE_AUTO:
            case VIR_DOMAIN_TIMER_MODE_SMPSAFE:
                if (xenConfigSetString(conf, "tsc_mode", "default") < 0)
                    return -1;
            case VIR_DOMAIN_TIMER_MODE_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            if (hvm) {
                int enable_hpet = def->clock.timers[i]->present != VIR_TRISTATE_BOOL_NO;

                /* disable hpet if 'present' is VIR_TRISTATE_BOOL_NO, enable
                 * otherwise */
                if (xenConfigSetInt(conf, "hpet", enable_hpet) < 0)
                    return -1;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported timer type (name) '%1$s'"),
                               virDomainTimerNameTypeToString(def->clock.timers[i]->name));
                return -1;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_RTC:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%1$s'"),
                           virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            return -1;

        case VIR_DOMAIN_TIMER_NAME_LAST:
            break;
        }
    }

    return 0;
}


static int
xenFormatEmulator(virConf *conf, virDomainDef *def)
{
    if (def->emulator &&
        xenConfigSetString(conf, "device_model_override", def->emulator) < 0)
        return -1;

    return 0;
}


static int
xenFormatVfb(virConf *conf, virDomainDef *def)
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
                virDomainGraphicsListenDef *glisten;

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
            g_autoptr(virConfValue) vfb = NULL;
            g_autoptr(virConfValue) disp = NULL;
            char *vfbstr = NULL;
            g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

            if (def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
                virBufferAddLit(&buf, "type=sdl");
                if (def->graphics[0]->data.sdl.display)
                    virBufferAsprintf(&buf, ",display=%s",
                                      def->graphics[0]->data.sdl.display);
                if (def->graphics[0]->data.sdl.xauth)
                    virBufferAsprintf(&buf, ",xauthority=%s",
                                      def->graphics[0]->data.sdl.xauth);
            } else {
                virDomainGraphicsListenDef *glisten
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

            vfbstr = virBufferContentAndReset(&buf);

            disp = g_new0(virConfValue, 1);
            disp->type = VIR_CONF_STRING;
            disp->str = vfbstr;

            vfb = g_new0(virConfValue, 1);
            vfb->type = VIR_CONF_LIST;
            vfb->list = g_steal_pointer(&disp);

            if (virConfSetValue(conf, "vfb", &vfb) < 0)
                return -1;
        }
    }

    return 0;
}


static int
xenFormatSound(virConf *conf, virDomainDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char * model;
    g_autofree char *str = NULL;
    size_t i;

    if (def->os.type != VIR_DOMAIN_OSTYPE_HVM ||
        !def->sounds)
        return 0;

    for (i = 0; i < def->nsounds; i++) {
        if (!(model = virDomainSoundModelTypeToString(def->sounds[i]->model))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected sound model %1$d"),
                           def->sounds[i]->model);
            return -1;
        }
        if (i)
            virBufferAddChar(&buf, ',');
        virBufferEscapeSexpr(&buf, "%s", model);
    }

    str = virBufferContentAndReset(&buf);

    return xenConfigSetString(conf, "soundhw", str);
}


static int
xenFormatVif(virConf *conf,
             virConnectPtr conn,
             virDomainDef *def,
             const char *vif_typename)
{
    g_autoptr(virConfValue) netVal = NULL;
    size_t i;
    int hvm = def->os.type == VIR_DOMAIN_OSTYPE_HVM;

    netVal = g_new0(virConfValue, 1);
    netVal->type = VIR_CONF_LIST;
    netVal->list = NULL;

    for (i = 0; i < def->nnets; i++) {
        if (xenFormatNet(conn, netVal, def->nets[i],
                         hvm, vif_typename) < 0)
            return -1;
    }

    if (netVal->list != NULL &&
        virConfSetValue(conf, "vif", &netVal) < 0)
        return -1;

    return 0;
}


/*
 * A convenience function for formatting all config common to both XM and XL
 */
int
xenFormatConfigCommon(virConf *conf,
                      virDomainDef *def,
                      virConnectPtr conn,
                      const char *nativeFormat)
{
    if (xenFormatGeneralMeta(conf, def) < 0)
        return -1;

    if (xenFormatMem(conf, def) < 0)
        return -1;

    if (xenFormatCPUAllocation(conf, def) < 0)
        return -1;

    if (xenFormatHypervisorFeatures(conf, def) < 0)
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
                       _("unsupported config type %1$s"), nativeFormat);
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
xenDomainDefAddImplicitInputDevice(virDomainDef *def)
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
