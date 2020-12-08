/*
 * domain_validate.c: domain general validation functions
 *
 * Copyright IBM Corp, 2020
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

#include "domain_validate.h"
#include "domain_conf.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_validate");

int
virDomainDefBootValidate(const virDomainDef *def)
{
    if (def->os.bm_timeout_set && def->os.bm_timeout > 65535) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("invalid value for boot menu timeout, "
                         "must be in range [0,65535]"));
        return -1;
    }

    if (def->os.bios.rt_set &&
        (def->os.bios.rt_delay < -1 || def->os.bios.rt_delay > 65535)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("invalid value for rebootTimeout, "
                         "must be in range [-1,65535]"));
        return -1;
    }

    return 0;
}


int
virDomainDefVideoValidate(const virDomainDef *def)
{
    size_t i;

    if (def->nvideos == 0)
        return 0;

    /* Any video marked as primary will be put in index 0 by the
     * parser. Ensure that we have only one primary set by the user. */
    if (def->videos[0]->primary) {
        for (i = 1; i < def->nvideos; i++) {
            if (def->videos[i]->primary) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only one primary video device is supported"));
                return -1;
            }
        }
    }

    return 0;
}


int
virDomainVideoDefValidate(const virDomainVideoDef *video,
                          const virDomainDef *def)
{
    size_t i;

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing video model and cannot determine default"));
        return -1;
    }

    /* it doesn't make sense to pair video device type 'none' with any other
     * types, there can be only a single video device in such case
     */
    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->type == VIR_DOMAIN_VIDEO_TYPE_NONE &&
            def->nvideos > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("a 'none' video type must be the only video device "
                             "defined for the domain"));
            return -1;
        }
    }

    switch (video->backend) {
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER:
        if (video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'vhostuser' driver is only supported with 'virtio' device"));
            return -1;
        }
        break;
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_DEFAULT:
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_QEMU:
        if (video->accel && video->accel->rendernode) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported rendernode accel attribute without 'vhostuser'"));
            return -1;
        }
        break;
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainInputType, video->backend);
        return -1;
    }

    if (video->res && (video->res->x == 0 || video->res->y == 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("video resolution values must be greater than 0"));
        return -1;
    }

    return 0;
}
