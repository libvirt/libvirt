/*
 * virsh-util.c: helpers for virsh
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

#include "virsh-util.h"

#include "virfile.h"
#include "virstring.h"

static virDomainPtr
virshLookupDomainInternal(vshControl *ctl,
                          const char *cmdname,
                          const char *name,
                          unsigned int flags)
{
    virDomainPtr dom = NULL;
    int id;
    virCheckFlags(VIRSH_BYID | VIRSH_BYUUID | VIRSH_BYNAME, NULL);
    virshControlPtr priv = ctl->privData;

    /* try it by ID */
    if (flags & VIRSH_BYID) {
        if (virStrToLong_i(name, NULL, 10, &id) == 0 && id >= 0) {
            vshDebug(ctl, VSH_ERR_DEBUG, "%s: <domain> looks like ID\n",
                     cmdname);
            dom = virDomainLookupByID(priv->conn, id);
        }
    }

    /* try it by UUID */
    if (!dom && (flags & VIRSH_BYUUID) &&
        strlen(name) == VIR_UUID_STRING_BUFLEN-1) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <domain> trying as domain UUID\n",
                 cmdname);
        dom = virDomainLookupByUUIDString(priv->conn, name);
    }

    /* try it by NAME */
    if (!dom && (flags & VIRSH_BYNAME)) {
        vshDebug(ctl, VSH_ERR_DEBUG, "%s: <domain> trying as domain NAME\n",
                 cmdname);
        dom = virDomainLookupByName(priv->conn, name);
    }

    vshResetLibvirtError();

    if (!dom)
        vshError(ctl, _("failed to get domain '%s'"), name);

    return dom;
}


virDomainPtr
virshLookupDomainBy(vshControl *ctl,
                    const char *name,
                    unsigned int flags)
{
    return virshLookupDomainInternal(ctl, "unknown", name, flags);
}


virDomainPtr
virshCommandOptDomainBy(vshControl *ctl,
                        const vshCmd *cmd,
                        const char **name,
                        unsigned int flags)
{
    const char *n = NULL;
    const char *optname = "domain";

    if (vshCommandOptStringReq(ctl, cmd, optname, &n) < 0)
        return NULL;

    vshDebug(ctl, VSH_ERR_INFO, "%s: found option <%s>: %s\n",
             cmd->def->name, optname, n);

    if (name)
        *name = n;

    return virshLookupDomainInternal(ctl, cmd->def->name, n, flags);
}


virDomainPtr
virshCommandOptDomain(vshControl *ctl,
                      const vshCmd *cmd,
                      const char **name)
{
    return virshCommandOptDomainBy(ctl, cmd, name,
                                   VIRSH_BYID | VIRSH_BYUUID | VIRSH_BYNAME);
}


int
virshDomainState(vshControl *ctl,
                 virDomainPtr dom,
                 int *reason)
{
    virDomainInfo info;
    virshControlPtr priv = ctl->privData;

    if (reason)
        *reason = -1;

    if (!priv->useGetInfo) {
        int state;
        if (virDomainGetState(dom, &state, reason, 0) < 0) {
            virErrorPtr err = virGetLastError();
            if (err && err->code == VIR_ERR_NO_SUPPORT)
                priv->useGetInfo = true;
            else
                return -1;
        } else {
            return state;
        }
    }

    /* fall back to virDomainGetInfo if virDomainGetState is not supported */
    if (virDomainGetInfo(dom, &info) < 0)
        return -1;
    else
        return info.state;
}


int
virshStreamSink(virStreamPtr st ATTRIBUTE_UNUSED,
                const char *bytes,
                size_t nbytes,
                void *opaque)
{
    int *fd = opaque;

    return safewrite(*fd, bytes, nbytes);
}


void
virshDomainFree(virDomainPtr dom)
{
    if (!dom)
        return;

    virDomainFree(dom); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshDomainSnapshotFree(virDomainSnapshotPtr snap)
{
    if (!snap)
        return;

    virDomainSnapshotFree(snap); /* sc_prohibit_obj_free_apis_in_virsh */
}
