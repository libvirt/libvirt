/*
 * storage_conf.c: config handling for storage driver
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

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "storage_conf.h"
#include "storage_backend.h"
#include "xml.h"
#include "uuid.h"
#include "buf.h"
#include "util.h"

#define virStorageLog(msg...) fprintf(stderr, msg)

void
virStorageReportError(virConnectPtr conn, int code, const char *fmt, ...) {
    va_list args;
    char errorMessage[1024];

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof(errorMessage)-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }
    virStorageLog("%s", errorMessage);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_STORAGE, code, VIR_ERR_ERROR,
                    NULL, NULL, NULL, -1, -1, "%s", errorMessage);
}



void
virStorageVolDefFree(virStorageVolDefPtr def) {
    int i;
    free(def->name);
    free(def->key);

    for (i = 0 ; i < def->source.nextent ; i++) {
        free(def->source.extents[i].path);
    }
    free(def->source.extents);

    free(def->target.path);
    free(def->target.perms.label);
    free(def);
}

void
virStoragePoolDefFree(virStoragePoolDefPtr def) {
    int i;

    free(def->name);
    free(def->source.host.name);
    for (i = 0 ; i < def->source.ndevice ; i++) {
        free(def->source.devices[i].freeExtents);
        free(def->source.devices[i].path);
    }
    free(def->source.devices);
    free(def->source.dir);

    if (def->source.authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        free(def->source.auth.chap.login);
        free(def->source.auth.chap.passwd);
    }

    free(def->target.path);
    free(def->target.perms.label);
    free(def);
}


void
virStoragePoolObjFree(virStoragePoolObjPtr obj) {
    if (obj->def)
        virStoragePoolDefFree(obj->def);
    if (obj->newDef)
        virStoragePoolDefFree(obj->newDef);

    free(obj->configFile);
    free(obj->autostartLink);
    free(obj);
}

void
virStoragePoolObjRemove(virStorageDriverStatePtr driver,
                        virStoragePoolObjPtr pool)
{
    virStoragePoolObjPtr prev = NULL, curr;

    curr = driver->pools;
    while (curr != pool) {
        prev = curr;
        curr = curr->next;
    }

    if (curr) {
        if (prev)
            prev->next = curr->next;
        else
            driver->pools = curr->next;

        driver->ninactivePools--;
    }

    virStoragePoolObjFree(pool);
}


static int
virStoragePoolDefParseAuthChap(virConnectPtr conn,
                               xmlXPathContextPtr ctxt,
                               virStoragePoolAuthChapPtr auth) {
    auth->login = virXPathString("string(/pool/source/auth/@login)", ctxt);
    if (auth->login == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth host attribute"));
        return -1;
    }

    auth->passwd = virXPathString("string(/pool/source/auth/@passwd)", ctxt);
    if (auth->passwd == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing auth passwd attribute"));
        return -1;
    }

    return 0;
}


static int
virStoragePoolDefParsePerms(virConnectPtr conn,
                            xmlXPathContextPtr ctxt,
                            virStoragePermsPtr perms) {
    char *mode;
    long v;

    mode = virXPathString("string(/pool/permissions/mode)", ctxt);
    if (!mode) {
        perms->mode = 0700;
    } else {
        char *end;
        perms->mode = strtol(mode, &end, 8);
        if (*end || perms->mode < 0 || perms->mode > 0777) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed octal mode"));
            return -1;
        }
    }

    if (virXPathNode("/pool/permissions/owner", ctxt) == NULL) {
        perms->uid = getuid();
    } else {
        if (virXPathLong("number(/pool/permissions/owner)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed owner element"));
            return -1;
        }
        perms->uid = (int)v;
    }

    if (virXPathNode("/pool/permissions/group", ctxt) == NULL) {
        perms->uid = getgid();
    } else {
        if (virXPathLong("number(/pool/permissions/group)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed group element"));
            return -1;
        }
        perms->gid = (int)v;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString("string(/pool/permissions/label)", ctxt);

    return 0;
}


static virStoragePoolDefPtr
virStoragePoolDefParseDoc(virConnectPtr conn,
                          xmlXPathContextPtr ctxt,
                          xmlNodePtr root) {
    virStorageBackendPoolOptionsPtr options;
    virStoragePoolDefPtr ret;
    xmlChar *type = NULL;
    char *uuid = NULL;
    char *authType = NULL;

    if ((ret = calloc(1, sizeof(virStoragePoolDef))) == NULL)
        return NULL;

    if (STRNEQ((const char *)root->name, "pool")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("unknown root element"));
        goto cleanup;
    }

    type = xmlGetProp(root, BAD_CAST "type");
    if ((ret->type = virStorageBackendFromString((const char *)type)) < 0)
        goto cleanup;
    xmlFree(type);
    type = NULL;

    if ((options = virStorageBackendPoolOptionsForType(ret->type)) == NULL) {
        goto cleanup;
    }

    if ((ret->name = virXPathString("string(/pool/name)", ctxt)) == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing name element"));
        goto cleanup;
    }

    uuid = virXPathString("string(/pool/uuid)", ctxt);
    if (uuid == NULL) {
        if (virUUIDGenerate(ret->uuid) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("unable to generate uuid"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuid, ret->uuid) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed uuid element"));
            goto cleanup;
        }
        free(uuid);
        uuid = NULL;
    }

    if (options->formatFromString) {
        char *format = virXPathString("string(/pool/source/format/@type)", ctxt);
        if ((ret->source.format = (options->formatFromString)(conn, format)) < 0) {
            free(format);
            goto cleanup;
        }
        free(format);
    }

    if (options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_HOST) {
        if ((ret->source.host.name = virXPathString("string(/pool/source/host/@name)", ctxt)) == NULL) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing source host name"));
            goto cleanup;
        }
    }
    if (options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_DEVICE) {
        xmlNodePtr *nodeset = NULL;
        int nsource, i;

        if ((nsource = virXPathNodeSet("/pool/source/device", ctxt, &nodeset)) <= 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("cannot extract source devices"));
            goto cleanup;
        }
        if ((ret->source.devices = calloc(nsource, sizeof(*ret->source.devices))) == NULL) {
            free(nodeset);
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("device"));
            goto cleanup;
        }
        for (i = 0 ; i < nsource ; i++) {
            xmlChar *path = xmlGetProp(nodeset[i], BAD_CAST "path");
            if (path == NULL) {
                free(nodeset);
                virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                      "%s", _("missing source device path"));
                goto cleanup;
            }
            ret->source.devices[i].path = (char *)path;
        }
        free(nodeset);
        ret->source.ndevice = nsource;
    }
    if (options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_DIR) {
        if ((ret->source.dir = virXPathString("string(/pool/source/dir/@path)", ctxt)) == NULL) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing source path"));
            goto cleanup;
        }
    }


    authType = virXPathString("string(/pool/source/auth/@type)", ctxt);
    if (authType == NULL) {
        ret->source.authType = VIR_STORAGE_POOL_AUTH_NONE;
    } else {
        if (STREQ(authType, "chap")) {
            ret->source.authType = VIR_STORAGE_POOL_AUTH_CHAP;
        } else {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown auth type '%s'"),
                                  (const char *)authType);
            free(authType);
            authType = NULL;
            goto cleanup;
        }
        free(authType);
        authType = NULL;
    }

    if (ret->source.authType == VIR_STORAGE_POOL_AUTH_CHAP) {
        if (virStoragePoolDefParseAuthChap(conn, ctxt, &ret->source.auth.chap) < 0)
            goto cleanup;
    }

    if ((ret->target.path = virXPathString("string(/pool/target/path)", ctxt)) == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing target path"));
        goto cleanup;
    }

    if (virStoragePoolDefParsePerms(conn, ctxt, &ret->target.perms) < 0)
        goto cleanup;

    return ret;

 cleanup:
    free(uuid);
    if (type)
        xmlFree(type);
    virStoragePoolDefFree(ret);
    return NULL;
}

virStoragePoolDefPtr
virStoragePoolDefParse(virConnectPtr conn,
                       const char *xmlStr,
                       const char *filename) {
    virStoragePoolDefPtr ret = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr ctxt = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr,
                           filename ? filename : "storage.xml",
                           NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("malformed xml document"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("xmlXPathContext"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStoragePoolDefParseDoc(conn, ctxt, node);

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return NULL;
}


char *
virStoragePoolDefFormat(virConnectPtr conn,
                        virStoragePoolDefPtr def) {
    virStorageBackendPoolOptionsPtr options;
    virBufferPtr buf;
    const char *type;
    char uuid[VIR_UUID_STRING_BUFLEN];
    int i;

    options = virStorageBackendPoolOptionsForType(def->type);
    if (options == NULL)
        return NULL;

    if ((buf = virBufferNew(8192)) == NULL)
        goto no_memory;

    type = virStorageBackendToString(def->type);
    if (!type) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected pool type"));
        goto cleanup;
    }
    if (virBufferVSprintf(buf, "<pool type='%s'>\n", type) < 0)
        goto no_memory;

    if (virBufferVSprintf(buf,"  <name>%s</name>\n", def->name) < 0)
        goto no_memory;

    virUUIDFormat(def->uuid, uuid);
    if (virBufferVSprintf(buf,"  <uuid>%s</uuid>\n", uuid) < 0)
        goto no_memory;

    if (virBufferVSprintf(buf,"  <capacity>%llu</capacity>\n",
                          def->capacity) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"  <allocation>%llu</allocation>\n",
                          def->allocation) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"  <available>%llu</available>\n",
                          def->available) < 0)
        goto no_memory;


    if (virBufferAddLit(buf,"  <source>\n") < 0)
        goto no_memory;
    if ((options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_HOST) &&
        def->source.host.name &&
        virBufferVSprintf(buf,"    <host name='%s'/>\n", def->source.host.name) < 0)
        goto no_memory;
    if ((options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_DEVICE) &&
        def->source.ndevice) {
        for (i = 0 ; i < def->source.ndevice ; i++) {
            if (virBufferVSprintf(buf,"    <device path='%s'>\n", def->source.devices[i].path) < 0)
                goto no_memory;
            if (def->source.devices[i].nfreeExtent) {
                int j;
                for (j = 0 ; j < def->source.devices[i].nfreeExtent ; j++) {
                    if (virBufferVSprintf(buf, "    <freeExtent start='%llu' end='%llu'/>\n",
                                          def->source.devices[i].freeExtents[j].start,
                                          def->source.devices[i].freeExtents[j].end) < 0)
                        goto no_memory;
                }
            }
            if (virBufferAddLit(buf,"    </device>\n") < 0)
                goto no_memory;
        }
    }
    if ((options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_DIR) &&
        def->source.dir &&
        virBufferVSprintf(buf,"    <dir path='%s'/>\n", def->source.dir) < 0)
        goto no_memory;
    if ((options->flags & VIR_STORAGE_BACKEND_POOL_SOURCE_ADAPTER) &&
        def->source.adapter &&
        virBufferVSprintf(buf,"    <adapter name='%s'/>\n", def->source.adapter) < 0)
        goto no_memory;

    if (options->formatToString) {
        const char *format = (options->formatToString)(conn, def->source.format);
        if (!format)
            goto cleanup;
        if (virBufferVSprintf(buf,"    <format type='%s'/>\n", format) < 0)
            goto no_memory;
    }


    if (def->source.authType == VIR_STORAGE_POOL_AUTH_CHAP &&
        virBufferVSprintf(buf,"    <auth type='chap' login='%s' passwd='%s'>\n",
                          def->source.auth.chap.login,
                          def->source.auth.chap.passwd) < 0)
        goto no_memory;
    if (virBufferAddLit(buf,"  </source>\n") < 0)
        goto no_memory;



    if (virBufferAddLit(buf,"  <target>\n") < 0)
        goto no_memory;

    if (def->target.path &&
        virBufferVSprintf(buf,"    <path>%s</path>\n", def->target.path) < 0)
        goto no_memory;

    if (virBufferAddLit(buf,"    <permissions>\n") < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <mode>0%o</mode>\n",
                          def->target.perms.mode) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <owner>%d</owner>\n",
                          def->target.perms.uid) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <group>%d</group>\n",
                          def->target.perms.gid) < 0)
        goto no_memory;

    if (def->target.perms.label) {
        if (virBufferVSprintf(buf,"      <label>%s</label>\n",
                              def->target.perms.label) < 0)
            goto no_memory;
    }
    if (virBufferAddLit(buf,"    </permissions>\n") < 0)
        goto no_memory;
    if (virBufferAddLit(buf,"  </target>\n") < 0)
        goto no_memory;

    if (virBufferAddLit(buf,"</pool>\n") < 0)
        goto no_memory;

    return virBufferContentAndFree(buf);

 no_memory:
    virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("xml"));
 cleanup:
    virBufferFree(buf);
    return NULL;
}


static int
virStorageVolDefParsePerms(virConnectPtr conn,
                           xmlXPathContextPtr ctxt,
                           virStoragePermsPtr perms) {
    char *mode;
    long v;

    mode = virXPathString("string(/volume/permissions/mode)", ctxt);
    if (!mode) {
        perms->mode = 0600;
    } else {
        char *end = NULL;
        perms->mode = strtol(mode, &end, 8);
        if (*end || perms->mode < 0 || perms->mode > 0777) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("malformed octal mode"));
            return -1;
        }
    }

    if (virXPathNode("/volume/permissions/owner", ctxt) == NULL) {
        perms->uid = getuid();
    } else {
        if (virXPathLong("number(/volume/permissions/owner)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing owner element"));
            return -1;
        }
        perms->uid = (int)v;
    }
    if (virXPathNode("/volume/permissions/group", ctxt) == NULL) {
        perms->gid = getgid();
    } else {
        if (virXPathLong("number(/volume/permissions/group)", ctxt, &v) < 0) {
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  "%s", _("missing owner element"));
            return -1;
        }
        perms->gid = (int)v;
    }

    /* NB, we're ignoring missing labels here - they'll simply inherit */
    perms->label = virXPathString("string(/volume/permissions/label)", ctxt);

    return 0;
}


static int
virStorageSize(virConnectPtr conn,
               const char *unit,
               const char *val,
               unsigned long long *ret) {
    unsigned long long mult;
    char *end;

    if (!unit) {
        mult = 1;
    } else {
        switch (unit[0]) {
        case 'k':
        case 'K':
            mult = 1024ull;
            break;

        case 'm':
        case 'M':
            mult = 1024ull * 1024ull;
            break;

        case 'g':
        case 'G':
            mult = 1024ull * 1024ull * 1024ull;
            break;

        case 't':
        case 'T':
            mult = 1024ull * 1024ull * 1024ull * 1024ull;
            break;

        case 'p':
        case 'P':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull;
            break;

        case 'y':
        case 'Y':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull *
                1024ull;
            break;

        case 'z':
        case 'Z':
            mult = 1024ull * 1024ull * 1024ull * 1024ull * 1024ull *
                1024ull * 1024ull;
            break;

        default:
            virStorageReportError(conn, VIR_ERR_XML_ERROR,
                                  _("unknown size units '%s'"), unit);
            return -1;
        }
    }

    if (virStrToLong_ull (val, &end, 10, ret) < 0) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("malformed capacity element"));
        return -1;
    }
    if (*ret > (ULLONG_MAX / mult)) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("capacity element value too large"));
            return -1;
    }

    *ret *= mult;

    return 0;
}

static virStorageVolDefPtr
virStorageVolDefParseDoc(virConnectPtr conn,
                         virStoragePoolDefPtr pool,
                         xmlXPathContextPtr ctxt,
                         xmlNodePtr root) {
    virStorageVolDefPtr ret;
    virStorageBackendVolOptionsPtr options;
    char *allocation = NULL;
    char *capacity = NULL;
    char *unit = NULL;

    options = virStorageBackendVolOptionsForType(pool->type);
    if (options == NULL)
        return NULL;

    if ((ret = calloc(1, sizeof(virStorageVolDef))) == NULL)
        return NULL;

    if (STRNEQ((const char *)root->name, "volume")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("unknown root element"));
        goto cleanup;
    }

    ret->name = virXPathString("string(/volume/name)", ctxt);
    if (ret->name == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing name element"));
        goto cleanup;
    }

    /* Auto-generated so deliberately ignore */
    /*ret->key = virXPathString("string(/volume/key)", ctxt);*/

    capacity = virXPathString("string(/volume/capacity)", ctxt);
    unit = virXPathString("string(/volume/capacity/@unit)", ctxt);
    if (capacity == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing capacity element"));
        goto cleanup;
    }
    if (virStorageSize(conn, unit, capacity, &ret->capacity) < 0)
        goto cleanup;
    free(capacity);
    capacity = NULL;
    free(unit);
    unit = NULL;

    allocation = virXPathString("string(/volume/allocation)", ctxt);
    if (allocation) {
        unit = virXPathString("string(/volume/allocation/@unit)", ctxt);
        if (virStorageSize(conn, unit, allocation, &ret->allocation) < 0)
            goto cleanup;
        free(allocation);
        allocation = NULL;
        free(unit);
        unit = NULL;
    } else {
        ret->allocation = ret->capacity;
    }

    ret->target.path = virXPathString("string(/volume/target/path)", ctxt);
    if (options->formatFromString) {
        char *format = virXPathString("string(/volume/target/format/@type)", ctxt);
        if ((ret->target.format = (options->formatFromString)(conn, format)) < 0) {
            free(format);
            goto cleanup;
        }
        free(format);
    }

    if (virStorageVolDefParsePerms(conn, ctxt, &ret->target.perms) < 0)
        goto cleanup;

    return ret;

 cleanup:
    free(allocation);
    free(capacity);
    free(unit);
    virStorageVolDefFree(ret);
    return NULL;
}


virStorageVolDefPtr
virStorageVolDefParse(virConnectPtr conn,
                      virStoragePoolDefPtr pool,
                      const char *xmlStr,
                      const char *filename) {
    virStorageVolDefPtr ret = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL;
    xmlXPathContextPtr ctxt = NULL;

    if (!(xml = xmlReadDoc(BAD_CAST xmlStr, filename ? filename : "storage.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("malformed xml document"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("xmlXPathContext"));
        goto cleanup;
    }

    node = xmlDocGetRootElement(xml);
    if (node == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    ret = virStorageVolDefParseDoc(conn, pool, ctxt, node);

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return ret;

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    return NULL;
}



char *
virStorageVolDefFormat(virConnectPtr conn,
                       virStoragePoolDefPtr pool,
                       virStorageVolDefPtr def) {
    virStorageBackendVolOptionsPtr options;
    virBufferPtr buf = virBufferNew(8192);

    options = virStorageBackendVolOptionsForType(pool->type);
    if (options == NULL)
        return NULL;

    if (!buf)
        goto no_memory;

    if (virBufferAddLit(buf, "<volume>\n") < 0)
        goto no_memory;

    if (virBufferVSprintf(buf,"  <name>%s</name>\n", def->name) < 0)
        goto no_memory;

    if (virBufferVSprintf(buf,"  <key>%s</key>\n", def->key) < 0)
        goto no_memory;

    if (virBufferAddLit(buf, "  <source>\n") < 0)
        goto no_memory;
    if (def->source.nextent) {
        int i;
        const char *thispath = NULL;
        for (i = 0 ; i < def->source.nextent ; i++) {
            if (thispath == NULL ||
                STRNEQ(thispath, def->source.extents[i].path)) {
                if (thispath != NULL)
                    if (virBufferAddLit(buf, "    </device>\n") < 0)
                        goto no_memory;
                if (virBufferVSprintf(buf, "    <device path='%s'>\n",
                                      def->source.extents[i].path) < 0)
                    goto no_memory;
            }

            if (virBufferVSprintf(buf,
                                  "      <extent start='%llu' end='%llu'/>\n",
                                  def->source.extents[i].start,
                                  def->source.extents[i].end) < 0)
                goto no_memory;
            thispath = def->source.extents[i].path;
        }
        if (thispath != NULL)
            if (virBufferAddLit(buf, "    </device>\n") < 0)
                goto no_memory;
    }
    if (virBufferAddLit(buf, "  </source>\n") < 0)
        goto no_memory;

    if (virBufferVSprintf(buf,"  <capacity>%llu</capacity>\n",
                          def->capacity) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"  <allocation>%llu</allocation>\n",
                          def->allocation) < 0)
        goto no_memory;

    if (virBufferAddLit(buf, "  <target>\n") < 0)
        goto no_memory;

    if (def->target.path &&
        virBufferVSprintf(buf,"    <path>%s</path>\n", def->target.path) < 0)
        goto no_memory;

    if (options->formatToString) {
        const char *format = (options->formatToString)(conn,
                                                       def->target.format);
        if (!format)
            goto cleanup;
        if (virBufferVSprintf(buf,"    <format type='%s'/>\n", format) < 0)
            goto no_memory;
    }

    if (virBufferAddLit(buf,"    <permissions>\n") < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <mode>0%o</mode>\n",
                          def->target.perms.mode) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <owner>%d</owner>\n",
                          def->target.perms.uid) < 0)
        goto no_memory;
    if (virBufferVSprintf(buf,"      <group>%d</group>\n",
                          def->target.perms.gid) < 0)
        goto no_memory;

    if (def->target.perms.label &&
        virBufferVSprintf(buf,"      <label>%s</label>\n",
                          def->target.perms.label) < 0)
        goto no_memory;
    if (virBufferAddLit(buf,"    </permissions>\n") < 0)
        goto no_memory;

    if (virBufferAddLit(buf, "  </target>\n") < 0)
        goto no_memory;

    if (virBufferAddLit(buf,"</volume>\n") < 0)
        goto no_memory;

    return virBufferContentAndFree(buf);

 no_memory:
    virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("xml"));
 cleanup:
    virBufferFree(buf);
    return NULL;
}


virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStorageDriverStatePtr driver,
                            const unsigned char *uuid) {
    virStoragePoolObjPtr pool = driver->pools;

    while (pool) {
        if (!memcmp(pool->def->uuid, uuid, VIR_UUID_BUFLEN))
            return pool;
        pool = pool->next;
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjFindByName(virStorageDriverStatePtr driver,
                            const char *name) {
    virStoragePoolObjPtr pool = driver->pools;

    while (pool) {
        if (STREQ(pool->def->name, name))
            return pool;
        pool = pool->next;
    }

    return NULL;
}

void
virStoragePoolObjClearVols(virStoragePoolObjPtr pool)
{
    virStorageVolDefPtr vol = pool->volumes;
    while (vol) {
        virStorageVolDefPtr next = vol->next;
        virStorageVolDefFree(vol);
        vol = next;
    }
    pool->volumes = NULL;
    pool->nvolumes = 0;
}

virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr pool,
                          const char *key) {
    virStorageVolDefPtr vol = pool->volumes;

    while (vol) {
        if (STREQ(vol->key, key))
            return vol;
        vol = vol->next;
    }

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr pool,
                           const char *path) {
    virStorageVolDefPtr vol = pool->volumes;

    while (vol) {
        if (STREQ(vol->target.path, path))
            return vol;
        vol = vol->next;
    }

    return NULL;
}

virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr pool,
                           const char *name) {
    virStorageVolDefPtr vol = pool->volumes;

    while (vol) {
        if (STREQ(vol->name, name))
            return vol;
        vol = vol->next;
    }

    return NULL;
}

virStoragePoolObjPtr
virStoragePoolObjAssignDef(virConnectPtr conn,
                           virStorageDriverStatePtr driver,
                           virStoragePoolDefPtr def) {
    virStoragePoolObjPtr pool;

    if ((pool = virStoragePoolObjFindByName(driver, def->name))) {
        if (!virStoragePoolObjIsActive(pool)) {
            virStoragePoolDefFree(pool->def);
            pool->def = def;
        } else {
            if (pool->newDef)
                virStoragePoolDefFree(pool->newDef);
            pool->newDef = def;
        }
        return pool;
    }

    if (!(pool = calloc(1, sizeof(virStoragePoolObj)))) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("pool"));
        return NULL;
    }

    pool->active = 0;
    pool->def = def;
    pool->next = driver->pools;

    driver->pools = pool;
    driver->ninactivePools++;

    return pool;
}

static virStoragePoolObjPtr
virStoragePoolObjLoad(virStorageDriverStatePtr driver,
                      const char *file,
                      const char *path,
                      const char *xml,
                      const char *autostartLink) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;

    if (!(def = virStoragePoolDefParse(NULL, xml, file))) {
        virErrorPtr err = virGetLastError();
        virStorageLog("Error parsing storage pool config '%s' : %s",
                      path, err->message);
        return NULL;
    }

    if (!virFileMatchesNameSuffix(file, def->name, ".xml")) {
        virStorageLog("Storage pool config filename '%s' does not match pool name '%s'",
                      path, def->name);
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(NULL, driver, def))) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->configFile = strdup(path);
    if (pool->configFile == NULL) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
        virStoragePoolDefFree(def);
        return NULL;
    }
    pool->autostartLink = strdup(autostartLink);
    if (pool->autostartLink == NULL) {
        virStorageLog("Failed to load storage pool config '%s': out of memory", path);
        virStoragePoolDefFree(def);
        return NULL;
    }

    pool->autostart = virFileLinkPointsTo(pool->autostartLink,
                                          pool->configFile);

    return pool;
}


int
virStoragePoolObjScanConfigs(virStorageDriverStatePtr driver) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(driver->configDir))) {
        if (errno == ENOENT)
            return 0;
        virStorageLog("Failed to open dir '%s': %s",
                      driver->configDir, strerror(errno));
        return -1;
    }

    while ((entry = readdir(dir))) {
        char *xml = NULL;
        char path[PATH_MAX];
        char autostartLink[PATH_MAX];

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileHasSuffix(entry->d_name, ".xml"))
            continue;

        if (virFileBuildPath(driver->configDir, entry->d_name,
                             NULL, path, PATH_MAX) < 0) {
            virStorageLog("Config filename '%s/%s' is too long",
                          driver->configDir, entry->d_name);
            continue;
        }

        if (virFileBuildPath(driver->autostartDir, entry->d_name,
                             NULL, autostartLink, PATH_MAX) < 0) {
            virStorageLog("Autostart link path '%s/%s' is too long",
                          driver->autostartDir, entry->d_name);
            continue;
        }

        if (virFileReadAll(path, 8192, &xml) < 0)
            continue;

        virStoragePoolObjLoad(driver, entry->d_name, path, xml, autostartLink);

        free(xml);
    }

    closedir(dir);

    return 0;
}

int
virStoragePoolObjSaveDef(virConnectPtr conn,
                         virStorageDriverStatePtr driver,
                         virStoragePoolObjPtr pool,
                         virStoragePoolDefPtr def) {
    char *xml;
    int fd = -1, ret = -1;
    ssize_t towrite;

    if (!pool->configFile) {
        int err;
        char path[PATH_MAX];

        if ((err = virFileMakePath(driver->configDir))) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot create config directory %s: %s"),
                                  driver->configDir, strerror(err));
            return -1;
        }

        if (virFileBuildPath(driver->configDir, def->name, ".xml",
                             path, sizeof(path)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot construct config file path"));
            return -1;
        }
        if (!(pool->configFile = strdup(path))) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                  "%s", _("configFile"));
            return -1;
        }

        if (virFileBuildPath(driver->autostartDir, def->name, ".xml",
                             path, sizeof(path)) < 0) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("cannot construct "
                                          "autostart link path"));
            free(pool->configFile);
            pool->configFile = NULL;
            return -1;
        }
        if (!(pool->autostartLink = strdup(path))) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                  "%s", _("config file"));
            free(pool->configFile);
            pool->configFile = NULL;
            return -1;
        }
    }

    if (!(xml = virStoragePoolDefFormat(conn, def))) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("failed to generate XML"));
        return -1;
    }

    if ((fd = open(pool->configFile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR )) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot create config file %s: %s"),
                              pool->configFile, strerror(errno));
        goto cleanup;
    }

    towrite = strlen(xml);
    if (safewrite(fd, xml, towrite) != towrite) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot write config file %s: %s"),
                              pool->configFile, strerror(errno));
        goto cleanup;
    }

    if (close(fd) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot save config file %s: %s"),
                              pool->configFile, strerror(errno));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (fd != -1)
        close(fd);

    free(xml);

    return ret;
}

int
virStoragePoolObjDeleteDef(virConnectPtr conn,
                           virStoragePoolObjPtr pool) {
    if (!pool->configFile) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("no config file for %s"), pool->def->name);
        return -1;
    }

    if (unlink(pool->configFile) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot remove config for %s"),
                              pool->def->name);
        return -1;
    }

    return 0;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
