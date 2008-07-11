/*
 * network_conf.c: network XML handling
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
 */



#include <config.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#include "internal.h"

#include "network_conf.h"
#include "memory.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"

VIR_ENUM_DECL(virNetworkForward)

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route" )

static void virNetworkReportError(virConnectPtr conn,
                                  int code, const char *fmt, ...)
{
    va_list args;
    char errorMessage[1024];
    const char *virerr;

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    virerr = __virErrorMsg(code, (errorMessage[0] ? errorMessage : NULL));
    __virRaiseError(conn, NULL, NULL, VIR_FROM_NETWORK, code, VIR_ERR_ERROR,
                    virerr, errorMessage, NULL, -1, -1, virerr, errorMessage);
}


virNetworkObjPtr virNetworkFindByUUID(const virNetworkObjPtr nets,
                                      const unsigned char *uuid)
{
    virNetworkObjPtr net = nets;
    while (net) {
        if (!memcmp(net->def->uuid, uuid, VIR_UUID_BUFLEN))
            return net;
        net = net->next;
    }

    return NULL;
}

virNetworkObjPtr virNetworkFindByName(const virNetworkObjPtr nets,
                                      const char *name)
{
    virNetworkObjPtr net = nets;
    while (net) {
        if (STREQ(net->def->name, name))
            return net;
        net = net->next;
    }

    return NULL;
}


void virNetworkDefFree(virNetworkDefPtr def)
{
    int i;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->bridge);
    VIR_FREE(def->forwardDev);
    VIR_FREE(def->ipAddress);
    VIR_FREE(def->network);
    VIR_FREE(def->netmask);

    for (i = 0 ; i < def->nranges && def->ranges ; i++) {
        VIR_FREE(def->ranges[i].start);
        VIR_FREE(def->ranges[i].end);
    }
    VIR_FREE(def->ranges);

    VIR_FREE(def);
}

void virNetworkObjFree(virNetworkObjPtr net)
{
    if (!net)
        return;

    virNetworkDefFree(net->def);
    virNetworkDefFree(net->newDef);

    VIR_FREE(net->configFile);
    VIR_FREE(net->autostartLink);

    VIR_FREE(net);
}

virNetworkObjPtr virNetworkAssignDef(virConnectPtr conn,
                                     virNetworkObjPtr *nets,
                                     const virNetworkDefPtr def)
{
    virNetworkObjPtr network;

    if ((network = virNetworkFindByName(*nets, def->name))) {
        if (!virNetworkIsActive(network)) {
            virNetworkDefFree(network->def);
            network->def = def;
        } else {
            if (network->newDef)
                virNetworkDefFree(network->newDef);
            network->newDef = def;
        }

        return network;
    }

    if (VIR_ALLOC(network) < 0) {
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    network->def = def;
    network->next = *nets;

    *nets = network;

    return network;

}

void virNetworkRemoveInactive(virNetworkObjPtr *nets,
                              const virNetworkObjPtr net)
{
    virNetworkObjPtr prev = NULL;
    virNetworkObjPtr curr = *nets;

    while (curr &&
           curr != net) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            *nets = curr->next;
    }

    virNetworkObjFree(net);
}


static int
virNetworkDHCPRangeDefParseXML(virConnectPtr conn,
                               virNetworkDefPtr def,
                               xmlNodePtr node) {

    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        xmlChar *start, *end;

        if (cur->type != XML_ELEMENT_NODE ||
            !xmlStrEqual(cur->name, BAD_CAST "range")) {
            cur = cur->next;
            continue;
        }

        if (!(start = xmlGetProp(cur, BAD_CAST "start"))) {
            cur = cur->next;
            continue;
        }
        if (!(end = xmlGetProp(cur, BAD_CAST "end"))) {
            cur = cur->next;
            xmlFree(start);
            continue;
        }

        if (VIR_REALLOC_N(def->ranges, def->nranges + 1) < 0) {
            xmlFree(start);
            xmlFree(end);
            virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
            return -1;
        }
        def->ranges[def->nranges].start = (char *)start;
        def->ranges[def->nranges].end = (char *)end;
        def->nranges++;

        cur = cur->next;
    }

    return 0;
}

static virNetworkDefPtr
virNetworkDefParseXML(virConnectPtr conn,
                      xmlXPathContextPtr ctxt)
{
    virNetworkDefPtr def;
    char *tmp;

    if (VIR_ALLOC(def) < 0) {
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    /* Extract network name */
    def->name = virXPathString("string(./name[1])", ctxt);
    if (!def->name) {
        virNetworkReportError(conn, VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract network uuid */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        int err;
        if ((err = virUUIDGenerate(def->uuid))) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                             _("Failed to generate UUID: %s"), strerror(err));
            goto error;
        }
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            VIR_FREE(tmp);
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
    }

    /* Parse bridge information */
    def->bridge = virXPathString("string(./bridge[1]/@name)", ctxt);
    tmp = virXPathString("string(./bridge[1]/@stp)", ctxt);
    def->stp = (tmp && STREQ(tmp, "off")) ? 0 : 1;
    VIR_FREE(tmp);

    if (virXPathULong("string(./bridge[1]/@delay)", ctxt, &def->delay) < 0)
        def->delay = 0;

    def->ipAddress = virXPathString("string(./ip[1]/@address)", ctxt);
    def->netmask = virXPathString("string(./ip[1]/@netmask)", ctxt);
    if (def->ipAddress &&
        def->netmask) {
        /* XXX someday we want IPv6 too, so inet_aton won't work there */
        struct in_addr inaddress, innetmask;
        char *netaddr;
        xmlNodePtr dhcp;

        if (!inet_aton(def->ipAddress, &inaddress)) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse IP address '%s'"),
                                  def->ipAddress);
            goto error;
        }
        if (!inet_aton(def->netmask, &innetmask)) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse netmask '%s'"),
                                  def->netmask);
            goto error;
        }

        inaddress.s_addr &= innetmask.s_addr;
        netaddr = inet_ntoa(inaddress);

        if (asprintf(&def->network, "%s/%s", netaddr, def->netmask) < 0) {
            virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
            goto error;
        }

        if ((dhcp = virXPathNode("./ip[1]/dhcp[1]", ctxt)) &&
            virNetworkDHCPRangeDefParseXML(conn, def, dhcp) < 0)
            goto error;
    }


    /* IPv4 forwarding setup */
    if (virXPathBoolean("count(./forward) > 0", ctxt)) {
        if (!def->ipAddress ||
            !def->netmask) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("Forwarding requested, but no IPv4 address/netmask provided"));
            goto error;
        }

        tmp = virXPathString("string(./forward[1]/@mode)", ctxt);
        if (tmp) {
            if ((def->forwardType = virNetworkForwardTypeFromString(tmp)) < 0) {
                virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("unknown forwarding type '%s'"), tmp);
                VIR_FREE(tmp);
                goto error;
            }
            VIR_FREE(tmp);
        } else {
            def->forwardType = VIR_NETWORK_FORWARD_NAT;
        }


        def->forwardDev = virXPathString("string(./forward[1]/@dev)", ctxt);
    } else {
        def->forwardType = VIR_NETWORK_FORWARD_NONE;
    }

    return def;

 error:
    virNetworkDefFree(def);
    return NULL;
}

virNetworkDefPtr virNetworkDefParseString(virConnectPtr conn,
                                          const char *xmlStr)
{
    xmlDocPtr xml;
    xmlNodePtr root;
    virNetworkDefPtr def;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, "network.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        virNetworkReportError(conn, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        xmlFreeDoc(xml);
        return NULL;
    }

    def = virNetworkDefParseNode(conn, xml, root);

    xmlFreeDoc(xml);
    return def;
}

virNetworkDefPtr virNetworkDefParseFile(virConnectPtr conn,
                                        const char *filename)
{
    xmlDocPtr xml;
    xmlNodePtr root;
    virNetworkDefPtr def;

    if (!(xml = xmlReadFile(filename, NULL,
                            XML_PARSE_NOENT | XML_PARSE_NONET |
                            XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        virNetworkReportError(conn, VIR_ERR_XML_ERROR, NULL);
        return NULL;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        xmlFreeDoc(xml);
        return NULL;
    }

    def = virNetworkDefParseNode(conn, xml, root);

    xmlFreeDoc(xml);
    return def;
}


virNetworkDefPtr virNetworkDefParseNode(virConnectPtr conn,
                                        xmlDocPtr xml,
                                        xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNetworkDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "network")) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("incorrect root element"));
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    ctxt->node = root;
    def = virNetworkDefParseXML(conn, ctxt);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

char *virNetworkDefFormat(virConnectPtr conn,
                          const virNetworkDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char *tmp;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virBufferAddLit(&buf, "<network>\n");
    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    if (def->forwardType != VIR_NETWORK_FORWARD_NONE) {
        const char *mode = virNetworkForwardTypeToString(def->forwardType);
        if (mode) {
            if (def->forwardDev) {
                virBufferEscapeString(&buf, "  <forward dev='%s'",
                                      def->forwardDev);
            } else {
                virBufferAddLit(&buf, "  <forward");
            }
            virBufferVSprintf(&buf, " mode='%s'/>\n", mode);
        }
    }

    virBufferAddLit(&buf, "  <bridge");
    if (def->bridge)
        virBufferEscapeString(&buf, " name='%s'", def->bridge);
    virBufferVSprintf(&buf, " stp='%s' forwardDelay='%ld' />\n",
                      def->stp ? "on" : "off",
                      def->delay);

    if (def->ipAddress || def->netmask) {
        virBufferAddLit(&buf, "  <ip");

        if (def->ipAddress)
            virBufferVSprintf(&buf, " address='%s'", def->ipAddress);

        if (def->netmask)
            virBufferVSprintf(&buf, " netmask='%s'", def->netmask);

        virBufferAddLit(&buf, ">\n");

        if (def->nranges) {
            int i;
            virBufferAddLit(&buf, "    <dhcp>\n");
            for (i = 0 ; i < def->nranges ; i++)
                virBufferVSprintf(&buf, "      <range start='%s' end='%s' />\n",
                                  def->ranges[i].start, def->ranges[i].end);
            virBufferAddLit(&buf, "    </dhcp>\n");
        }

        virBufferAddLit(&buf, "  </ip>\n");
    }

    virBufferAddLit(&buf, "</network>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
}

int virNetworkSaveConfig(virConnectPtr conn,
                         const char *configDir,
                         const char *autostartDir,
                         virNetworkObjPtr net)
{
    char *xml;
    int fd = -1, ret = -1;
    size_t towrite;
    int err;

    if (!net->configFile &&
        asprintf(&net->configFile, "%s/%s.xml",
                 configDir, net->def->name) < 0) {
        net->configFile = NULL;
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }
    if (!net->autostartLink &&
        asprintf(&net->autostartLink, "%s/%s.xml",
                 autostartDir, net->def->name) < 0) {
        net->autostartLink = NULL;
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto cleanup;
    }

    if (!(xml = virNetworkDefFormat(conn,
                                    net->newDef ? net->newDef : net->def)))
        goto cleanup;

    if ((err = virFileMakePath(configDir))) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot create config directory %s: %s"),
                              configDir, strerror(err));
        goto cleanup;
    }

    if ((err = virFileMakePath(autostartDir))) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot create autostart directory %s: %s"),
                              autostartDir, strerror(err));
        goto cleanup;
    }

    if ((fd = open(net->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot create config file %s: %s"),
                              net->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) < 0) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot write config file %s: %s"),
                              net->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot save config file %s: %s"),
                              net->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    if (fd != -1)
        close(fd);

    return ret;
}

virNetworkObjPtr virNetworkLoadConfig(virConnectPtr conn,
                                      virNetworkObjPtr *nets,
                                      const char *configDir,
                                      const char *autostartDir,
                                      const char *file)
{
    char *configFile = NULL, *autostartLink = NULL;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr net;
    int autostart;

    if (asprintf(&configFile, "%s/%s",
                 configDir, file) < 0) {
        configFile = NULL;
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto error;
    }
    if (asprintf(&autostartLink, "%s/%s",
                 autostartDir, file) < 0) {
        autostartLink = NULL;
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        goto error;
    }

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        goto error;

    if (!(def = virNetworkDefParseFile(conn, file)))
        goto error;

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Network config filename '%s'"
                                " does not match network name '%s'"),
                              configFile, def->name);
        goto error;
    }

    if (!(net = virNetworkAssignDef(conn, nets, def)))
        goto error;

    net->configFile = configFile;
    net->autostartLink = autostartLink;
    net->autostart = autostart;

    return net;

error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virNetworkDefFree(def);
    return NULL;
}

int virNetworkLoadAllConfigs(virConnectPtr conn,
                             virNetworkObjPtr *nets,
                             const char *configDir,
                             const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("Failed to open dir '%s': %s"),
                              configDir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        virNetworkLoadConfig(conn,
                             nets,
                             configDir,
                             autostartDir,
                             entry->d_name);
    }

    closedir(dir);

    return 0;
}

int virNetworkDeleteConfig(virConnectPtr conn,
                           virNetworkObjPtr net)
{
    if (!net->configFile || !net->autostartLink) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("no config file for %s"), net->def->name);
        return -1;
    }

    /* Not fatal if this doesn't work */
    unlink(net->autostartLink);

    if (unlink(net->configFile) < 0) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot remove config for %s: %s"),
                              net->def->name, strerror(errno));
        return -1;
    }

    return 0;
}
