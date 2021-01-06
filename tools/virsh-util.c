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
#include "viralloc.h"
#include "virxml.h"

static virDomainPtr
virshLookupDomainInternal(vshControl *ctl,
                          const char *cmdname,
                          const char *name,
                          unsigned int flags)
{
    virDomainPtr dom = NULL;
    int id;
    virshControlPtr priv = ctl->privData;

    virCheckFlags(VIRSH_BYID | VIRSH_BYUUID | VIRSH_BYNAME, NULL);

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
            if (virGetLastErrorCode() == VIR_ERR_NO_SUPPORT)
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
virshStreamSink(virStreamPtr st G_GNUC_UNUSED,
                const char *bytes,
                size_t nbytes,
                void *opaque)
{
    virshStreamCallbackDataPtr cbData = opaque;

    return safewrite(cbData->fd, bytes, nbytes);
}


int
virshStreamSource(virStreamPtr st G_GNUC_UNUSED,
                  char *bytes,
                  size_t nbytes,
                  void *opaque)
{
    virshStreamCallbackDataPtr cbData = opaque;
    int fd = cbData->fd;

    return saferead(fd, bytes, nbytes);
}


int
virshStreamSourceSkip(virStreamPtr st G_GNUC_UNUSED,
                      long long offset,
                      void *opaque)
{
    virshStreamCallbackDataPtr cbData = opaque;
    int fd = cbData->fd;

    if (lseek(fd, offset, SEEK_CUR) == (off_t) -1)
        return -1;

    return 0;
}


int
virshStreamSkip(virStreamPtr st G_GNUC_UNUSED,
                long long offset,
                void *opaque)
{
    virshStreamCallbackDataPtr cbData = opaque;
    off_t cur;

    if (cbData->isBlock) {
        g_autofree char * buf = NULL;
        const size_t buflen = 1 * 1024 * 1024; /* 1MiB */

        /* While for files it's enough to lseek() and ftruncate() to create
         * a hole which would emulate zeroes on read(), for block devices
         * we have to write zeroes to read() zeroes. And we have to write
         * @got bytes of zeroes. Do that in smaller chunks though.*/

        buf = g_new0(char, buflen);

        while (offset) {
            size_t count = MIN(offset, buflen);
            ssize_t r;

            if ((r = safewrite(cbData->fd, buf, count)) < 0)
                return -1;

            offset -= r;
        }
    } else {
        if ((cur = lseek(cbData->fd, offset, SEEK_CUR)) == (off_t) -1)
            return -1;

        if (ftruncate(cbData->fd, cur) < 0)
            return -1;
    }

    return 0;
}


int
virshStreamInData(virStreamPtr st G_GNUC_UNUSED,
                  int *inData,
                  long long *offset,
                  void *opaque)
{
    virshStreamCallbackDataPtr cbData = opaque;
    vshControl *ctl = cbData->ctl;
    int fd = cbData->fd;

    if (cbData->isBlock) {
        /* Block devices are always in data section by definition. The
         * @sectionLen is slightly more tricky. While we could try and get
         * how much bytes is there left until EOF, we can pretend there is
         * always X bytes left and let the saferead() below hit EOF (which
         * is then handled gracefully anyway). Worst case scenario, this
         * branch is called more than once.
         * X was chosen to be 1MiB but it has ho special meaning. */
        *inData = 1;
        *offset = 1 * 1024 * 1024;
    } else {
        if (virFileInData(fd, inData, offset) < 0) {
            vshError(ctl, "%s", _("Unable to get current position in stream"));
            return -1;
        }
    }

    return 0;
}


void
virshDomainFree(virDomainPtr dom)
{
    if (!dom)
        return;

    vshSaveLibvirtHelperError();
    virDomainFree(dom); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshDomainCheckpointFree(virDomainCheckpointPtr chk)
{
    if (!chk)
        return;

    vshSaveLibvirtHelperError();
    virDomainCheckpointFree(chk); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshDomainSnapshotFree(virDomainSnapshotPtr snap)
{
    if (!snap)
        return;

    vshSaveLibvirtHelperError();
    virDomainSnapshotFree(snap); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshSecretFree(virSecretPtr secret)
{
    if (!secret)
        return;

    vshSaveLibvirtHelperError();
    virSecretFree(secret); /* sc_prohibit_obj_free_apis_in_virsh */
}


int
virshDomainGetXMLFromDom(vshControl *ctl,
                         virDomainPtr dom,
                         unsigned int flags,
                         xmlDocPtr *xml,
                         xmlXPathContextPtr *ctxt)
{
    char *desc = NULL;

    if (!(desc = virDomainGetXMLDesc(dom, flags))) {
        vshError(ctl, _("Failed to get domain description xml"));
        return -1;
    }

    *xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), ctxt);
    VIR_FREE(desc);

    if (!(*xml)) {
        vshError(ctl, _("Failed to parse domain description xml"));
        return -1;
    }

    return 0;
}


int
virshDomainGetXML(vshControl *ctl,
                  const vshCmd *cmd,
                  unsigned int flags,
                  xmlDocPtr *xml,
                  xmlXPathContextPtr *ctxt)
{
    virDomainPtr dom;
    int ret;

    if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
        return -1;

    ret = virshDomainGetXMLFromDom(ctl, dom, flags, xml, ctxt);

    virshDomainFree(dom);

    return ret;
}
