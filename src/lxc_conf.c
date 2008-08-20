/*
 * Copyright IBM Corp. 2008
 *
 * lxc_conf.c: config functions for managing linux containers
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 */

/* includes */
#include <config.h>

#include <sys/utsname.h>

#include "lxc_conf.h"

/* debug macros */
#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

/* Functions */
void lxcError(virConnectPtr conn, virDomainPtr dom, int code,
              const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];
    const char *codeErrorMessage;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    codeErrorMessage = __virErrorMsg(code, fmt);
    __virRaiseError(conn, dom, NULL, VIR_FROM_LXC, code, VIR_ERR_ERROR,
                    codeErrorMessage, errorMessage, NULL, 0, 0,
                    codeErrorMessage, errorMessage);
}

virCapsPtr lxcCapsInit(void)
{
    struct utsname utsname;
    virCapsPtr caps;
    virCapsGuestPtr guest;

    uname(&utsname);

    if ((caps = virCapabilitiesNew(utsname.machine,
                                   0, 0)) == NULL)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "exe",
                                         utsname.machine,
                                         sizeof(int) == 4 ? 32 : 8,
                                         BINDIR "/libvirt_lxc",
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "lxc",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;
    return caps;

no_memory:
    virCapabilitiesFree(caps);
    return NULL;
}

int lxcLoadDriverConfig(lxc_driver_t *driver)
{
    /* Set the container configuration directory */
    if ((driver->configDir = strdup(LXC_CONFIG_DIR)) == NULL)
        goto no_memory;
    if ((driver->stateDir = strdup(LXC_STATE_DIR)) == NULL)
        goto no_memory;
    if ((driver->logDir = strdup(LXC_LOG_DIR)) == NULL)
        goto no_memory;

    return 0;

no_memory:
    lxcError(NULL, NULL, VIR_ERR_NO_MEMORY, "configDir");
    return -1;
}


