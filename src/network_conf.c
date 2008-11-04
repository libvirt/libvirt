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
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "network_conf.h"
#include "memory.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "c-ctype.h"

VIR_ENUM_DECL(virNetworkForward)

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route" )

#define virNetworkReportError(conn, code, fmt...)                            \
        virReportErrorHelper(conn, VIR_FROM_NETWORK, code, __FILE__,       \
                               __FUNCTION__, __LINE__, fmt)

virNetworkObjPtr virNetworkFindByUUID(const virNetworkObjListPtr nets,
                                      const unsigned char *uuid)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++)
        if (!memcmp(nets->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return nets->objs[i];

    return NULL;
}

virNetworkObjPtr virNetworkFindByName(const virNetworkObjListPtr nets,
                                      const char *name)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++)
        if (STREQ(nets->objs[i]->def->name, name))
            return nets->objs[i];

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
    VIR_FREE(def->domain);

    for (i = 0 ; i < def->nranges && def->ranges ; i++) {
        VIR_FREE(def->ranges[i].start);
        VIR_FREE(def->ranges[i].end);
    }
    VIR_FREE(def->ranges);

    for (i = 0 ; i < def->nhosts && def->hosts ; i++) {
        VIR_FREE(def->hosts[i].mac);
        VIR_FREE(def->hosts[i].ip);
        VIR_FREE(def->hosts[i].name);
    }
    VIR_FREE(def->hosts);

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

void virNetworkObjListFree(virNetworkObjListPtr nets)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++)
        virNetworkObjFree(nets->objs[i]);

    VIR_FREE(nets->objs);
    nets->count = 0;
}

virNetworkObjPtr virNetworkAssignDef(virConnectPtr conn,
                                     virNetworkObjListPtr nets,
                                     const virNetworkDefPtr def)
{
    virNetworkObjPtr network;

    if ((network = virNetworkFindByName(nets, def->name))) {
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

    if (VIR_REALLOC_N(nets->objs, nets->count + 1) < 0) {
        virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
        VIR_FREE(network);
        return NULL;
    }

    nets->objs[nets->count] = network;
    nets->count++;

    return network;

}

void virNetworkRemoveInactive(virNetworkObjListPtr nets,
                              const virNetworkObjPtr net)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++) {
        if (nets->objs[i] == net) {
            virNetworkObjFree(nets->objs[i]);

            if (i < (nets->count - 1))
                memmove(nets->objs + i, nets->objs + i + 1,
                        sizeof(*(nets->objs)) * (nets->count - (i + 1)));

            if (VIR_REALLOC_N(nets->objs, nets->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            nets->count--;

            break;
        }
    }
}


static int
virNetworkDHCPRangeDefParseXML(virConnectPtr conn,
                               virNetworkDefPtr def,
                               xmlNodePtr node) {

    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "range")) {
            xmlChar *start, *end;

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
        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "host")) {
            xmlChar *mac, *name, *ip;
            unsigned char addr[6];
            struct in_addr inaddress;

            mac = xmlGetProp(cur, BAD_CAST "mac");
            if ((mac != NULL) &&
                (virParseMacAddr((const char *) mac, &addr[0]) != 0)) {
                virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("cannot parse MAC address '%s'"),
                                      mac);
                VIR_FREE(mac);
            }
            name = xmlGetProp(cur, BAD_CAST "name");
            if ((name != NULL) && (!c_isalpha(name[0]))) {
                virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("cannot use name address '%s'"),
                                      name);
                VIR_FREE(name);
            }
            /*
             * You need at least one MAC address or one host name
             */
            if ((mac == NULL) && (name == NULL)) {
                VIR_FREE(mac);
                VIR_FREE(name);
                cur = cur->next;
                continue;
            }
            ip = xmlGetProp(cur, BAD_CAST "ip");
            if (inet_pton(AF_INET, (const char *) ip, &inaddress) <= 0) {
                virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("cannot parse IP address '%s'"),
                                      ip);
                VIR_FREE(ip);
                VIR_FREE(mac);
                VIR_FREE(name);
                cur = cur->next;
                continue;
            }
            if (VIR_REALLOC_N(def->hosts, def->nhosts + 1) < 0) {
                VIR_FREE(ip);
                VIR_FREE(mac);
                VIR_FREE(name);
                virNetworkReportError(conn, VIR_ERR_NO_MEMORY, NULL);
                return -1;
            }
            def->hosts[def->nhosts].mac = (char *)mac;
            def->hosts[def->nhosts].name = (char *)name;
            def->hosts[def->nhosts].ip = (char *)ip;
            def->nhosts++;
        }

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
    def->name = virXPathString(conn, "string(./name[1])", ctxt);
    if (!def->name) {
        virNetworkReportError(conn, VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract network uuid */
    tmp = virXPathString(conn, "string(./uuid[1])", ctxt);
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

    /* Parse network domain information */
    def->domain = virXPathString(conn, "string(./domain[1]/@name)", ctxt);

    /* Parse bridge information */
    def->bridge = virXPathString(conn, "string(./bridge[1]/@name)", ctxt);
    tmp = virXPathString(conn, "string(./bridge[1]/@stp)", ctxt);
    def->stp = (tmp && STREQ(tmp, "off")) ? 0 : 1;
    VIR_FREE(tmp);

    if (virXPathULong(conn, "string(./bridge[1]/@delay)", ctxt, &def->delay) < 0)
        def->delay = 0;

    def->ipAddress = virXPathString(conn, "string(./ip[1]/@address)", ctxt);
    def->netmask = virXPathString(conn, "string(./ip[1]/@netmask)", ctxt);
    if (def->ipAddress &&
        def->netmask) {
        /* XXX someday we want IPv6 too, so inet_aton won't work there */
        struct in_addr inaddress, innetmask;
        char *netaddr;
        xmlNodePtr dhcp;

        if (inet_pton(AF_INET, def->ipAddress, &inaddress) <= 0) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot parse IP address '%s'"),
                                  def->ipAddress);
            goto error;
        }
        if (inet_pton(AF_INET, def->netmask, &innetmask) <= 0) {
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

        if ((dhcp = virXPathNode(conn, "./ip[1]/dhcp[1]", ctxt)) &&
            virNetworkDHCPRangeDefParseXML(conn, def, dhcp) < 0)
            goto error;
    }


    /* IPv4 forwarding setup */
    if (virXPathBoolean(conn, "count(./forward) > 0", ctxt)) {
        if (!def->ipAddress ||
            !def->netmask) {
            virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("Forwarding requested, but no IPv4 address/netmask provided"));
            goto error;
        }

        tmp = virXPathString(conn, "string(./forward[1]/@mode)", ctxt);
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


        def->forwardDev = virXPathString(conn, "string(./forward[1]/@dev)", ctxt);
    } else {
        def->forwardType = VIR_NETWORK_FORWARD_NONE;
    }

    return def;

 error:
    virNetworkDefFree(def);
    return NULL;
}

/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError (void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (conn &&
            conn->err.code == VIR_ERR_NONE &&
            ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            virNetworkReportError (conn, VIR_ERR_XML_DETAIL,
                                   _("at line %d: %s"),
                                   ctxt->lastError.line,
                                   ctxt->lastError.message);
        }
    }
}

virNetworkDefPtr virNetworkDefParseString(virConnectPtr conn,
                                          const char *xmlStr)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virNetworkDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr, "network.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virNetworkReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virNetworkDefParseNode(conn, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}

virNetworkDefPtr virNetworkDefParseFile(virConnectPtr conn,
                                        const char *filename)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virNetworkDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadFile (pctxt, filename, NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virNetworkReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virNetworkReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virNetworkDefParseNode(conn, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
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

        if ((def->nranges || def->nhosts)) {
            int i;
            virBufferAddLit(&buf, "    <dhcp>\n");
            for (i = 0 ; i < def->nranges ; i++)
                virBufferVSprintf(&buf, "      <range start='%s' end='%s' />\n",
                                  def->ranges[i].start, def->ranges[i].end);
            for (i = 0 ; i < def->nhosts ; i++) {
                virBufferAddLit(&buf, "      <host ");
                if (def->hosts[i].mac)
                    virBufferVSprintf(&buf, "mac='%s' ", def->hosts[i].mac);
                if (def->hosts[i].name)
                    virBufferVSprintf(&buf, "name='%s' ", def->hosts[i].name);
                if (def->hosts[i].ip)
                    virBufferVSprintf(&buf, "ip='%s' ", def->hosts[i].ip);
                virBufferAddLit(&buf, "/>\n");
            }
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
                                      virNetworkObjListPtr nets,
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

    if (!(def = virNetworkDefParseFile(conn, configFile)))
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
                             virNetworkObjListPtr nets,
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
