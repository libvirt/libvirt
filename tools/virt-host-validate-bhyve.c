/*
 * virt-host-validate-bhyve.c: Sanity check a bhyve hypervisor host
 *
 * Copyright (C) 2017 Roman Bogorodskiy
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
 */

#include <config.h>

#include <sys/param.h>
#include <sys/linker.h>
#include <stdio.h>

#include "virt-host-validate-bhyve.h"
#include "virt-host-validate-common.h"

#define MODULE_STATUS(mod, err_msg, err_code)                  \
    virHostMsgCheck("BHYVE", _("for %s module"), #mod);        \
    if (mod ## _loaded) {                                      \
        virHostMsgPass();                                      \
    } else {                                                   \
        virHostMsgFail(err_code,                               \
                       _("%s module is not loaded, " err_msg), \
                        #mod);                                 \
        ret = -1;                                              \
    }                                                          \

#define MODULE_STATUS_FAIL(mod, err_msg) \
    MODULE_STATUS(mod, err_msg, VIR_HOST_VALIDATE_FAIL)

#define MODULE_STATUS_WARN(mod, err_msg) \
    MODULE_STATUS(mod, err_msg, VIR_HOST_VALIDATE_WARN)


int virHostValidateBhyve(void)
{
    int ret = 0;
    int fileid = 0;
    struct kld_file_stat stat;
    bool vmm_loaded = false, if_tap_loaded = false;
    bool if_bridge_loaded = false, nmdm_loaded = false;

    for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
        stat.version = sizeof(struct kld_file_stat);
        if (kldstat(fileid, &stat) < 0)
            continue;

        if (STREQ(stat.name, "vmm.ko"))
            vmm_loaded = true;
        else if (STREQ(stat.name, "if_tap.ko"))
            if_tap_loaded = true;
        else if (STREQ(stat.name, "if_bridge.ko"))
            if_bridge_loaded = true;
        else if (STREQ(stat.name, "nmdm.ko"))
            nmdm_loaded = true;
    }

    MODULE_STATUS_FAIL(vmm, "will not be able to start VMs");
    MODULE_STATUS_WARN(if_tap, "networking will not work");
    MODULE_STATUS_WARN(if_bridge, "bridged networking will not work");
    MODULE_STATUS_WARN(nmdm, "nmdm console will not work");

    return ret;
}
