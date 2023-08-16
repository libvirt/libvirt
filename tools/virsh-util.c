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
#include "virxml.h"

static virDomainPtr
virshLookupDomainInternal(vshControl *ctl,
                          const char *cmdname,
                          const char *name,
                          unsigned int flags)
{
    virDomainPtr dom = NULL;
    int id;
    virshControl *priv = ctl->privData;

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
        vshError(ctl, _("failed to get domain '%1$s'"), name);

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
    virshControl *priv = ctl->privData;

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
    return info.state;
}


int
virshStreamSink(virStreamPtr st G_GNUC_UNUSED,
                const char *bytes,
                size_t nbytes,
                void *opaque)
{
    virshStreamCallbackData *cbData = opaque;

    return safewrite(cbData->fd, bytes, nbytes);
}


int
virshStreamSource(virStreamPtr st G_GNUC_UNUSED,
                  char *bytes,
                  size_t nbytes,
                  void *opaque)
{
    virshStreamCallbackData *cbData = opaque;
    int fd = cbData->fd;

    return saferead(fd, bytes, nbytes);
}


int
virshStreamSourceSkip(virStreamPtr st G_GNUC_UNUSED,
                      long long offset,
                      void *opaque)
{
    virshStreamCallbackData *cbData = opaque;
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
    virshStreamCallbackData *cbData = opaque;
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
    virshStreamCallbackData *cbData = opaque;
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
virshInterfaceFree(virInterfacePtr iface)
{
    if (!iface)
        return;

    vshSaveLibvirtHelperError();
    virInterfaceFree(iface); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshNetworkFree(virNetworkPtr network)
{
    if (!network)
        return;

    vshSaveLibvirtHelperError();
    virNetworkFree(network); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshNodeDeviceFree(virNodeDevicePtr device)
{
    if (!device)
        return;

    vshSaveLibvirtHelperError();
    virNodeDeviceFree(device); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshNWFilterFree(virNWFilterPtr nwfilter)
{
    if (!nwfilter)
        return;

    vshSaveLibvirtHelperError();
    virNWFilterFree(nwfilter); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshSecretFree(virSecretPtr secret)
{
    if (!secret)
        return;

    vshSaveLibvirtHelperError();
    virSecretFree(secret); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshStoragePoolFree(virStoragePoolPtr pool)
{
    if (!pool)
        return;

    vshSaveLibvirtHelperError();
    virStoragePoolFree(pool); /* sc_prohibit_obj_free_apis_in_virsh */
}


void
virshStorageVolFree(virStorageVolPtr vol)
{
    if (!vol)
        return;

    vshSaveLibvirtHelperError();
    virStorageVolFree(vol); /* sc_prohibit_obj_free_apis_in_virsh */
}



void
virshStreamFree(virStreamPtr stream)
{
    if (!stream)
        return;

    vshSaveLibvirtHelperError();
    virStreamFree(stream); /* sc_prohibit_obj_free_apis_in_virsh */
}


int
virshDomainGetXMLFromDom(vshControl *ctl,
                         virDomainPtr dom,
                         unsigned int flags,
                         xmlDocPtr *xml,
                         xmlXPathContextPtr *ctxt)
{
    g_autofree char *desc = NULL;

    if (!(desc = virDomainGetXMLDesc(dom, flags))) {
        vshError(ctl, _("Failed to get domain description xml"));
        return -1;
    }

    *xml = virXMLParseStringCtxt(desc, _("(domain_definition)"), ctxt);

    if (!(*xml)) {
        vshError(ctl, _("Failed to parse domain description xml"));
        return -1;
    }

    return 0;
}


int
virshNetworkGetXMLFromNet(vshControl *ctl,
                          virNetworkPtr net,
                          unsigned int flags,
                          xmlDocPtr *xml,
                          xmlXPathContextPtr *ctxt)
{
    g_autofree char *desc = NULL;

    if (!(desc = virNetworkGetXMLDesc(net, flags))) {
        vshError(ctl, _("Failed to get network description xml"));
        return -1;
    }

    *xml = virXMLParseStringCtxt(desc, _("(network_definition)"), ctxt);

    if (!(*xml)) {
        vshError(ctl, _("Failed to parse network description xml"));
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


VIR_ENUM_IMPL(virshDomainBlockJob,
              VIR_DOMAIN_BLOCK_JOB_TYPE_LAST,
              N_("Unknown job"),
              N_("Block Pull"),
              N_("Block Copy"),
              N_("Block Commit"),
              N_("Active Block Commit"),
              N_("Backup"),
);


const char *
virshDomainBlockJobToString(int type)
{
    const char *str = virshDomainBlockJobTypeToString(type);
    return str ? _(str) : _("Unknown job");
}

bool
virshDumpXML(vshControl *ctl,
             const char *xml,
             const char *url,
             const char *xpath,
             bool wrap)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    int nnodes = 0;
    size_t i;
    int oldblanks;

    if (xpath == NULL) {
        vshPrint(ctl, "%s", xml);
        return true;
    }

    oldblanks = xmlKeepBlanksDefault(0);
    doc = virXMLParseStringCtxt(xml, url, &ctxt);
    xmlKeepBlanksDefault(oldblanks);
    if (!doc)
        return false;

    if ((nnodes = virXPathNodeSet(xpath, ctxt, &nodes)) < 0) {
        return false;
    }

    if (wrap) {
        g_autoptr(xmlDoc) newdoc = xmlNewDoc((xmlChar *)"1.0");
        xmlNodePtr newroot = xmlNewNode(NULL, (xmlChar *)"nodes");
        g_autofree char *xmlbit = NULL;

        xmlDocSetRootElement(newdoc, newroot);

        for (i = 0; i < nnodes; i++) {
            g_autoptr(xmlNode) copy = xmlDocCopyNode(nodes[i], newdoc, 1);
            if (!xmlAddChild(newroot, copy))
                return false;

            copy = NULL;
        }

        xmlbit = virXMLNodeToString(doc, newroot);
        vshPrint(ctl, "%s\n", xmlbit);
    } else {
        for (i = 0; i < nnodes; i++) {
            g_autofree char *xmlbit = virXMLNodeToString(doc, nodes[i]);
            vshPrint(ctl, "%s\n", xmlbit);
        }
    }

    return true;
}
