/*
 * test.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Daniel Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libxml/xmlsave.h>


#include "virterror_internal.h"
#include "datatypes.h"
#include "test.h"
#include "buf.h"
#include "util.h"
#include "uuid.h"
#include "capabilities.h"
#include "memory.h"
#include "network_conf.h"
#include "domain_conf.h"
#include "storage_conf.h"
#include "xml.h"

#define MAX_CPUS 128

struct _testCell {
    unsigned long mem;
    int numCpus;
    int cpus[MAX_CPUS];
};
typedef struct _testCell testCell;
typedef struct _testCell *testCellPtr;

#define MAX_CELLS 128

struct _testConn {
    char path[PATH_MAX];
    int nextDomID;
    virCapsPtr caps;
    virNodeInfo nodeInfo;
    virDomainObjList domains;
    virNetworkObjList networks;
    virStoragePoolObjList pools;
    int numCells;
    testCell cells[MAX_CELLS];
};
typedef struct _testConn testConn;
typedef struct _testConn *testConnPtr;

#define TEST_MODEL "i686"
#define TEST_MODEL_WORDSIZE 32
#define TEST_EMULATOR "/usr/bin/test-hv"

static const virNodeInfo defaultNodeInfo = {
    TEST_MODEL,
    1024*1024*3, /* 3 GB */
    16,
    1400,
    2,
    2,
    2,
    2,
};

#define GET_DOMAIN(dom, ret)                                            \
    testConnPtr privconn;                                               \
    virDomainObjPtr privdom;                                            \
                                                                        \
    privconn = (testConnPtr)dom->conn->privateData;                     \
    do {                                                                \
        if ((privdom = virDomainFindByName(&privconn->domains,           \
                                            (dom)->name)) == NULL) {    \
            testError((dom)->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);  \
            return (ret);                                               \
        }                                                               \
    } while (0)

#define GET_NETWORK(net, ret)                                           \
    testConnPtr privconn;                                               \
    virNetworkObjPtr privnet;                                           \
                                                                        \
    privconn = (testConnPtr)net->conn->privateData;                     \
    do {                                                                \
        if ((privnet = virNetworkFindByName(&privconn->networks,        \
                                            (net)->name)) == NULL) {    \
            testError((net)->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);  \
            return (ret);                                               \
        }                                                               \
    } while (0)

#define GET_POOL(pool, ret)                                             \
    testConnPtr privconn;                                               \
    virStoragePoolObjPtr privpool;                                      \
                                                                        \
    privconn = (testConnPtr)pool->conn->privateData;                    \
    do {                                                                \
        if ((privpool = virStoragePoolObjFindByName(&privconn->pools,   \
                                                    (pool)->name)) == NULL) {\
            testError((pool)->conn, VIR_ERR_INVALID_ARG, __FUNCTION__); \
            return (ret);                                               \
        }                                                               \
    } while (0)

#define GET_POOL_FROM_VOL(vol, ret)                                     \
    GET_POOL(testStoragePoolLookupByName((virConnectPtr)                \
                                         vol->conn,                     \
                                         vol->pool), ret)

#define GET_VOL(vol, pool, ret)                                         \
    virStorageVolDefPtr privvol;                                        \
                                                                        \
    privvol = virStorageVolDefFindByName(pool, vol->name);              \
    do {                                                                \
        if (!privvol) {                                                 \
            testError(vol->conn, VIR_ERR_INVALID_STORAGE_VOL,           \
                      _("no storage vol with matching name '%s'"),      \
                      vol->name);                                       \
            return (ret);                                               \
        }                                                               \
    } while (0)                                                         \


#define GET_CONNECTION(conn)                                            \
    testConnPtr privconn;                                               \
                                                                        \
    privconn = (testConnPtr)conn->privateData;

#define POOL_IS_ACTIVE(pool, ret)                                       \
    if (!virStoragePoolObjIsActive(pool)) {                             \
        testError(obj->conn, VIR_ERR_INTERNAL_ERROR,                    \
                  _("storage pool '%s' is not active"), pool->def->name); \
       return (ret);                                                    \
    }                                                                   \

#define POOL_IS_NOT_ACTIVE(pool, ret)                                   \
    if (virStoragePoolObjIsActive(pool)) {                              \
        testError(obj->conn, VIR_ERR_INTERNAL_ERROR,                    \
                  _("storage pool '%s' is already active"), pool->def->name); \
        return (ret);                                                   \
    }                                                                   \

#define testError(conn, code, fmt...)                               \
        virReportErrorHelper(conn, VIR_FROM_TEST, code, __FILE__, \
                               __FUNCTION__, __LINE__, fmt)

static virCapsPtr
testBuildCapabilities(virConnectPtr conn) {
    virCapsPtr caps;
    virCapsGuestPtr guest;
    const char *const guest_types[] = { "hvm", "xen" };
    int i;
    GET_CONNECTION(conn);

    if ((caps = virCapabilitiesNew(TEST_MODEL, 0, 0)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddHostFeature(caps, "pae") < 0)
        goto no_memory;
    if (virCapabilitiesAddHostFeature(caps ,"nonpae") < 0)
        goto no_memory;

    for (i = 0; i < privconn->numCells; i++) {
        if (virCapabilitiesAddHostNUMACell(caps, i, privconn->cells[i].numCpus,
                                           privconn->cells[i].cpus) < 0)
            goto no_memory;
    }

    for (i = 0; i < ARRAY_CARDINALITY(guest_types) ; i++) {
        if ((guest = virCapabilitiesAddGuest(caps,
                                             guest_types[i],
                                             TEST_MODEL,
                                             TEST_MODEL_WORDSIZE,
                                             TEST_EMULATOR,
                                             NULL,
                                             0,
                                             NULL)) == NULL)
            goto no_memory;

        if (virCapabilitiesAddGuestDomain(guest,
                                          "test",
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto no_memory;

        if (virCapabilitiesAddGuestFeature(guest, "pae", 1, 1) == NULL)
            goto no_memory;
        if (virCapabilitiesAddGuestFeature(guest ,"nonpae", 1, 1) == NULL)
            goto no_memory;
    }

    return caps;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    virCapabilitiesFree(caps);
    return NULL;
}


static const char *defaultDomainXML =
"<domain type='test'>"
"  <name>test</name>"
"  <memory>8388608</memory>"
"  <currentMemory>2097152</currentMemory>"
"  <vcpu>2</vcpu>"
"  <os>"
"    <type>hvm</type>"
"  </os>"
"</domain>";


static const char *defaultNetworkXML =
"<network>"
"  <name>default</name>"
"  <bridge name='virbr0' />"
"  <forward/>"
"  <ip address='192.168.122.1' netmask='255.255.255.0'>"
"    <dhcp>"
"      <range start='192.168.122.2' end='192.168.122.254' />"
"    </dhcp>"
"  </ip>"
"</network>";

static const char *defaultPoolXML =
"<pool type='dir'>"
"  <name>default-pool</name>"
"  <target>"
"    <path>/default-pool</path>"
"  </target>"
"</pool>";

static const unsigned long long defaultPoolCap = (100 * 1024 * 1024 * 1024ul);
static const unsigned long long defaultPoolAlloc = 0;

static int testStoragePoolObjSetDefaults(virStoragePoolObjPtr pool);

static int testOpenDefault(virConnectPtr conn) {
    int u;
    struct timeval tv;
    testConnPtr privconn;
    virDomainDefPtr domdef = NULL;
    virDomainObjPtr domobj = NULL;
    virNetworkDefPtr netdef = NULL;
    virNetworkObjPtr netobj = NULL;
    virStoragePoolDefPtr pooldef = NULL;
    virStoragePoolObjPtr poolobj = NULL;

    if (VIR_ALLOC(privconn) < 0) {
        testError(conn, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = privconn;

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s", _("getting time of day"));
        goto error;
    }

    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    // Numa setup
    privconn->numCells = 2;
    for (u = 0; u < 2; ++u) {
        privconn->cells[u].numCpus = 8;
        privconn->cells[u].mem = (u + 1) * 2048 * 1024;
    }
    for (u = 0 ; u < 16 ; u++) {
        privconn->cells[u % 2].cpus[(u / 2)] = u;
    }

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    privconn->nextDomID = 1;

    if (!(domdef = virDomainDefParseString(conn, privconn->caps, defaultDomainXML)))
        goto error;
    if (!(domobj = virDomainAssignDef(conn, &privconn->domains, domdef))) {
        virDomainDefFree(domdef);
        goto error;
    }
    domobj->def->id = privconn->nextDomID++;
    domobj->state = VIR_DOMAIN_RUNNING;
    domobj->persistent = 1;

    if (!(netdef = virNetworkDefParseString(conn, defaultNetworkXML)))
        goto error;
    if (!(netobj = virNetworkAssignDef(conn, &privconn->networks, netdef))) {
        virNetworkDefFree(netdef);
        goto error;
    }
    netobj->active = 1;
    netobj->persistent = 1;

    if (!(pooldef = virStoragePoolDefParse(conn, defaultPoolXML, NULL)))
        goto error;

    if (!(poolobj = virStoragePoolObjAssignDef(conn, &privconn->pools,
                                               pooldef))) {
        virStoragePoolDefFree(pooldef);
        goto error;
    }
    if (testStoragePoolObjSetDefaults(poolobj) == -1)
        goto error;
    poolobj->active = 1;

    return VIR_DRV_OPEN_SUCCESS;

error:
    virDomainObjListFree(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virStoragePoolObjListFree(&privconn->pools);
    virCapabilitiesFree(privconn->caps);
    VIR_FREE(privconn);
    return VIR_DRV_OPEN_ERROR;
}


static char *testBuildFilename(const char *relativeTo,
                               const char *filename) {
    char *offset;
    int baseLen;
    if (!filename || filename[0] == '\0')
        return (NULL);
    if (filename[0] == '/')
        return strdup(filename);

    offset = strrchr(relativeTo, '/');
    if ((baseLen = (offset-relativeTo+1))) {
        char *absFile;
        if (VIR_ALLOC_N(absFile, baseLen + strlen(filename) + 1) < 0)
            return NULL;
        strncpy(absFile, relativeTo, baseLen);
        absFile[baseLen] = '\0';
        strcat(absFile, filename);
        return absFile;
    } else {
        return strdup(filename);
    }
}

static int testOpenFromFile(virConnectPtr conn,
                            const char *file) {
    int fd = -1, i, ret;
    long l;
    char *str;
    xmlDocPtr xml = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr *domains = NULL, *networks = NULL, *pools = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virNodeInfoPtr nodeInfo;
    virNetworkObjPtr net;
    virDomainObjPtr dom;
    testConnPtr privconn;
    if (VIR_ALLOC(privconn) < 0) {
        testError(NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = privconn;

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if ((fd = open(file, O_RDONLY)) < 0) {
        testError(NULL, VIR_ERR_INTERNAL_ERROR,
                  _("loading host definition file '%s': %s"),
                  file, strerror(errno));
        goto error;
    }

    if (!(xml = xmlReadFd(fd, file, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s", _("host"));
        goto error;
    }
    close(fd);
    fd = -1;

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "node"))) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                  _("creating xpath context"));
        goto error;
    }

    privconn->nextDomID = 1;
    privconn->numCells = 0;
    strncpy(privconn->path, file, PATH_MAX-1);
    privconn->path[PATH_MAX-1] = '\0';
    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    nodeInfo = &privconn->nodeInfo;
    ret = virXPathLong(conn, "string(/node/cpu/nodes[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->nodes = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node cpu numa nodes"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node cpu sockets"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node cpu cores"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node cpu threads"));
        goto error;
    }

    nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
    ret = virXPathLong(conn, "string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus) {
            nodeInfo->cpus = l;
        }
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node active cpu"));
        goto error;
    }
    ret = virXPathLong(conn, "string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node cpu mhz"));
        goto error;
    }

    str = virXPathString(conn, "string(/node/cpu/model[1])", ctxt);
    if (str != NULL) {
        strncpy(nodeInfo->model, str, sizeof(nodeInfo->model)-1);
        nodeInfo->model[sizeof(nodeInfo->model)-1] = '\0';
        VIR_FREE(str);
    }

    ret = virXPathLong(conn, "string(/node/memory[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->memory = l;
    } else if (ret == -2) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node memory"));
        goto error;
    }

    ret = virXPathNodeSet(conn, "/node/domain", ctxt, &domains);
    if (ret < 0) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node domain list"));
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        virDomainDefPtr def;
        char *relFile = virXMLPropString(domains[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s", _("resolving domain filename"));
                goto error;
            }
            def = virDomainDefParseFile(conn, privconn->caps, absFile,
                                        VIR_DOMAIN_XML_INACTIVE);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virDomainDefParseNode(conn, privconn->caps, xml, domains[i],
                                   VIR_DOMAIN_XML_INACTIVE)) == NULL)
                goto error;
        }

        if (!(dom = virDomainAssignDef(conn, &privconn->domains, def))) {
            virDomainDefFree(def);
            goto error;
        }

        dom->state = VIR_DOMAIN_RUNNING;
        dom->def->id = privconn->nextDomID++;
        dom->persistent = 1;
    }
    if (domains != NULL)
        VIR_FREE(domains);

    ret = virXPathNodeSet(conn, "/node/network", ctxt, &networks);
    if (ret < 0) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node network list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virNetworkDefPtr def;
        char *relFile = virXMLPropString(networks[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s", _("resolving network filename"));
                goto error;
            }

            def = virNetworkDefParseFile(conn, absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virNetworkDefParseNode(conn, xml, networks[i])) == NULL)
                goto error;
        }
        if (!(net = virNetworkAssignDef(conn, &privconn->networks,
                                        def))) {
            virNetworkDefFree(def);
            goto error;
        }

        net->persistent = 1;
    }
    if (networks != NULL)
        VIR_FREE(networks);

    /* Parse Storage Pool list */
    ret = virXPathNodeSet(conn, "/node/pool", ctxt, &pools);
    if (ret < 0) {
        testError(NULL, VIR_ERR_XML_ERROR, "%s", _("node pool list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virStoragePoolDefPtr def;
        virStoragePoolObjPtr pool;
        char *relFile = virXMLPropString(pools[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                          _("resolving pool filename"));
                goto error;
            }

            def = virStoragePoolDefParse(conn, NULL, absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            xmlBufferPtr buf;
            xmlSaveCtxtPtr sctxt;

            buf = xmlBufferCreate();
            sctxt = xmlSaveToBuffer(buf, NULL, 0);
            xmlSaveTree(sctxt, pools[i]);
            xmlSaveClose(sctxt);
            if ((def = virStoragePoolDefParse(conn,
                                              (const char *) buf->content,
                                              NULL)) == NULL) {
                xmlBufferFree(buf);
                goto error;
            }
        }

        if (!(pool = virStoragePoolObjAssignDef(conn, &privconn->pools,
                                                def))) {
            virStoragePoolDefFree(def);
            goto error;
        }

        if (testStoragePoolObjSetDefaults(pool) == -1)
            goto error;
        pool->active = 1;
    }
    if (pools != NULL)
        VIR_FREE(pools);

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return (0);

 error:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(domains);
    VIR_FREE(networks);
    VIR_FREE(pools);
    if (fd != -1)
        close(fd);
    virDomainObjListFree(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virStoragePoolObjListFree(&privconn->pools);
    VIR_FREE(privconn);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}


static int testOpen(virConnectPtr conn,
                    virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                    int flags ATTRIBUTE_UNUSED)
{
    int ret;

    if (!conn->uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!conn->uri->scheme || STRNEQ(conn->uri->scheme, "test"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* From this point on, the connection is for us. */
    if (!conn->uri->path
        || conn->uri->path[0] == '\0'
        || (conn->uri->path[0] == '/' && conn->uri->path[1] == '\0')) {
        testError (NULL, VIR_ERR_INVALID_ARG,
                   "%s", _("testOpen: supply a path or use test:///default"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STREQ(conn->uri->path, "/default"))
        ret = testOpenDefault(conn);
    else
        ret = testOpenFromFile(conn,
                               conn->uri->path);

    return (ret);
}

static int testClose(virConnectPtr conn)
{
    GET_CONNECTION(conn);

    virCapabilitiesFree(privconn->caps);
    virDomainObjListFree(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virStoragePoolObjListFree(&privconn->pools);

    VIR_FREE (privconn);
    conn->privateData = conn;
    return 0;
}

static int testGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED,
                          unsigned long *hvVer)
{
    *hvVer = 2;
    return (0);
}

static char *testGetHostname (virConnectPtr conn)
{
    int r;
    char hostname [HOST_NAME_MAX+1], *str;

    r = gethostname (hostname, HOST_NAME_MAX+1);
    if (r == -1) {
        testError (conn, VIR_ERR_SYSTEM_ERROR, "%s",
                   strerror (errno));
        return NULL;
    }
    str = strdup (hostname);
    if (str == NULL) {
        testError (conn, VIR_ERR_SYSTEM_ERROR, "%s",
                   strerror (errno));
        return NULL;
    }
    return str;
}

static int testGetMaxVCPUs(virConnectPtr conn ATTRIBUTE_UNUSED,
                           const char *type ATTRIBUTE_UNUSED)
{
    return 32;
}

static int testNodeGetInfo(virConnectPtr conn,
                           virNodeInfoPtr info)
{
    GET_CONNECTION(conn);
    memcpy(info, &privconn->nodeInfo, sizeof(virNodeInfo));
    return (0);
}

static char *testGetCapabilities (virConnectPtr conn)
{
    char *xml;
    GET_CONNECTION(conn);

    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL) {
        testError(conn, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return xml;
}

static int testNumOfDomains(virConnectPtr conn)
{
    unsigned int numActive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->domains.count ; i++)
        if (virDomainIsActive(privconn->domains.objs[i]))
            numActive++;

    return numActive;
}

static virDomainPtr
testDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    virDomainPtr ret;
    virDomainDefPtr def;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    if ((def = virDomainDefParseString(conn, privconn->caps, xml)) == NULL)
        return NULL;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL) {
        virDomainDefFree(def);
        return NULL;
    }
    dom->state = VIR_DOMAIN_RUNNING;
    dom->def->id = privconn->nextDomID++;

    ret = virGetDomain(conn, def->name, def->uuid);
    if (!ret)
        return NULL;
    ret->id = def->id;
    return ret;
}


static virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                         int id)
{
    virDomainObjPtr dom = NULL;
    virDomainPtr ret;
    GET_CONNECTION(conn);

    if ((dom = virDomainFindByID(&privconn->domains, id)) == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (!ret)
        return NULL;
    ret->id = dom->def->id;
    return ret;
}

static virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    virDomainPtr ret;
    virDomainObjPtr dom = NULL;
    GET_CONNECTION(conn);

    if ((dom = virDomainFindByUUID(&privconn->domains, uuid)) == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (!ret)
        return NULL;
    ret->id = dom->def->id;
    return ret;
}

static virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                           const char *name)
{
    virDomainPtr ret;
    virDomainObjPtr dom = NULL;
    GET_CONNECTION(conn);

    if ((dom = virDomainFindByName(&privconn->domains, name)) == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (!ret)
        return NULL;
    ret->id = dom->def->id;
    return ret;
}

static int testListDomains (virConnectPtr conn,
                            int *ids,
                            int maxids)
{
    unsigned int n = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->domains.count && n < maxids ; i++)
        if (virDomainIsActive(privconn->domains.objs[i]))
            ids[n++] = privconn->domains.objs[i]->def->id;

    return n;
}

static int testDestroyDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    privdom->state = VIR_DOMAIN_SHUTOFF;
    privdom->def->id = -1;
    domain->id = -1;
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
    }
    return (0);
}

static int testResumeDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->state != VIR_DOMAIN_PAUSED) {
        testError(domain->conn,
                  VIR_ERR_INTERNAL_ERROR, _("domain '%s' not paused"),
                  domain->name);
        return -1;
    }

    privdom->state = VIR_DOMAIN_RUNNING;
    return (0);
}

static int testPauseDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->state == VIR_DOMAIN_SHUTOFF ||
        privdom->state == VIR_DOMAIN_PAUSED) {
        testError(domain->conn,
                  VIR_ERR_INTERNAL_ERROR, _("domain '%s' not running"),
                  domain->name);
        return -1;
    }

    privdom->state = VIR_DOMAIN_PAUSED;
    return (0);
}

static int testShutdownDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' not running"), domain->name);
        return -1;
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    domain->id = -1;
    privdom->def->id = -1;

    return (0);
}

/* Similar behaviour as shutdown */
static int testRebootDomain (virDomainPtr domain,
                             unsigned int action ATTRIBUTE_UNUSED)
{
    GET_DOMAIN(domain, -1);

    privdom->state = VIR_DOMAIN_SHUTDOWN;
    switch (privdom->def->onReboot) {
    case VIR_DOMAIN_LIFECYCLE_DESTROY:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->def->id = -1;
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART:
        privdom->state = VIR_DOMAIN_RUNNING;
        break;

    case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->def->id = -1;
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
        privdom->state = VIR_DOMAIN_RUNNING;
        break;

    default:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->def->id = -1;
        break;
    }

    return (0);
}

static int testGetDomainInfo (virDomainPtr domain,
                              virDomainInfoPtr info)
{
    struct timeval tv;
    GET_DOMAIN(domain, -1);

    if (gettimeofday(&tv, NULL) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("getting time of day"));
        return (-1);
    }

    info->state = privdom->state;
    info->memory = privdom->def->memory;
    info->maxMem = privdom->def->maxmem;
    info->nrVirtCpu = privdom->def->vcpus;
    info->cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    return (0);
}

static char *testDomainDumpXML(virDomainPtr domain, int flags);

#define TEST_SAVE_MAGIC "TestGuestMagic"

static int testDomainSave(virDomainPtr domain,
                          const char *path)
{
    char *xml;
    int fd, len;
    GET_DOMAIN(domain, -1);

    xml = testDomainDumpXML(domain, 0);
    if (xml == NULL) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' failed to allocate space for metadata: %s"),
                  domain->name, strerror(errno));
        return (-1);
    }

    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' to '%s': open failed: %s"),
                  domain->name, path, strerror(errno));
        return (-1);
    }
    len = strlen(xml);
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' to '%s': write failed: %s"),
                  domain->name, path, strerror(errno));
        close(fd);
        return (-1);
    }
    if (safewrite(fd, (char*)&len, sizeof(len)) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' to '%s': write failed: %s"),
                  domain->name, path, strerror(errno));
        close(fd);
        return (-1);
    }
    if (safewrite(fd, xml, len) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' to '%s': write failed: %s"),
                  domain->name, path, strerror(errno));
        VIR_FREE(xml);
        close(fd);
        return (-1);
    }
    VIR_FREE(xml);
    if (close(fd) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("saving domain '%s' to '%s': write failed: %s"),
                  domain->name, path, strerror(errno));
        close(fd);
        return (-1);
    }
    privdom->state = VIR_DOMAIN_SHUTOFF;
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
    }
    return 0;
}

static int testDomainRestore(virConnectPtr conn,
                             const char *path)
{
    char *xml;
    char magic[15];
    int fd, len;
    virDomainDefPtr def;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    if ((fd = open(path, O_RDONLY)) < 0) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("cannot read domain image"));
        return (-1);
    }
    if (read(fd, magic, sizeof(magic)) != sizeof(magic)) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("incomplete save header"));
        close(fd);
        return (-1);
    }
    if (memcmp(magic, TEST_SAVE_MAGIC, sizeof(magic))) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("mismatched header magic"));
        close(fd);
        return (-1);
    }
    if (read(fd, (char*)&len, sizeof(len)) != sizeof(len)) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("failed to read metadata length"));
        close(fd);
        return (-1);
    }
    if (len < 1 || len > 8192) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("length of metadata out of range"));
        close(fd);
        return (-1);
    }
    if (VIR_ALLOC_N(xml, len+1) < 0) {
        testError(conn, VIR_ERR_NO_MEMORY, "xml");
        close(fd);
        return (-1);
    }
    if (read(fd, xml, len) != len) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("incomplete metdata"));
        close(fd);
        return (-1);
    }
    xml[len] = '\0';
    close(fd);

    def = virDomainDefParseString(conn, privconn->caps, xml);
    VIR_FREE(xml);
    if (!def)
        return -1;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL) {
        virDomainDefFree(def);
        return -1;
    }
    dom->state = VIR_DOMAIN_RUNNING;
    dom->def->id = privconn->nextDomID++;
    return dom->def->id;
}

static int testDomainCoreDump(virDomainPtr domain,
                              const char *to,
                              int flags ATTRIBUTE_UNUSED)
{
    int fd;
    GET_DOMAIN(domain, -1);

    if ((fd = open(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' coredump: failed to open %s: %s"),
                  domain->name, to, strerror (errno));
        return (-1);
    }
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' coredump: failed to write header to %s: %s"),
                  domain->name, to, strerror (errno));
        close(fd);
        return (-1);
    }
    if (close(fd) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' coredump: write failed: %s: %s"),
                  domain->name, to, strerror (errno));
        close(fd);
        return (-1);
    }
    privdom->state = VIR_DOMAIN_SHUTOFF;
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
    }
    return 0;
}

static char *testGetOSType(virDomainPtr dom) {
    char *ret = strdup("linux");
    if (!ret)
        testError(dom->conn, VIR_ERR_NO_MEMORY, NULL);
    return ret;
}

static unsigned long testGetMaxMemory(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    return privdom->def->maxmem;
}

static int testSetMaxMemory(virDomainPtr domain,
                            unsigned long memory)
{
    GET_DOMAIN(domain, -1);

    /* XXX validate not over host memory wrt to other domains */
    privdom->def->maxmem = memory;
    return (0);
}

static int testSetMemory(virDomainPtr domain,
                         unsigned long memory)
{
    GET_DOMAIN(domain, -1);

    if (memory > privdom->def->maxmem) {
        testError(domain->conn,
                  VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    privdom->def->memory = memory;
    return (0);
}

static int testSetVcpus(virDomainPtr domain,
                        unsigned int nrCpus) {
    GET_DOMAIN(domain, -1);

    /* We allow more cpus in guest than host */
    if (nrCpus > 32) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    privdom->def->vcpus = nrCpus;
    return (0);
}

static char *testDomainDumpXML(virDomainPtr domain, int flags)
{
    virDomainDefPtr def;
    GET_DOMAIN(domain, NULL);

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    return virDomainDefFormat(domain->conn,
                              def,
                              flags);
}

static int testNumOfDefinedDomains(virConnectPtr conn) {
    unsigned int numInactive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->domains.count ; i++)
        if (!virDomainIsActive(privconn->domains.objs[i]))
            numInactive++;

    return numInactive;
}

static int testListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames) {
    unsigned int n = 0, i;
    GET_CONNECTION(conn);

    memset(names, 0, sizeof(*names)*maxnames);
    for (i = 0 ; i < privconn->domains.count && n < maxnames ; i++)
        if (!virDomainIsActive(privconn->domains.objs[i]) &&
            !(names[n++] = strdup(privconn->domains.objs[i]->def->name)))
            goto no_memory;

    return n;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[n]);
    return -1;
}

static virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                        const char *xml) {
    virDomainPtr ret;
    virDomainDefPtr def;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    if ((def = virDomainDefParseString(conn, privconn->caps, xml)) == NULL)
        return NULL;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL) {
        virDomainDefFree(def);
        return NULL;
    }
    dom->persistent = 1;
    dom->def->id = -1;

    ret = virGetDomain(conn, def->name, def->uuid);
    if (!ret)
        return NULL;
    ret->id = -1;
    return ret;
}

static int testNodeGetCellsFreeMemory(virConnectPtr conn,
                                      unsigned long long *freemems,
                                      int startCell, int maxCells) {
    int i, j;

    GET_CONNECTION(conn);

    if (startCell > privconn->numCells) {
        testError(conn, VIR_ERR_INVALID_ARG,
                  "%s", _("Range exceeds available cells"));
        return -1;
    }

    for (i = startCell, j = 0;
         (i < privconn->numCells && j < maxCells) ;
         ++i, ++j) {
        freemems[j] = privconn->cells[i].mem;
    }

    return j;
}


static int testDomainCreate(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Domain '%s' is already running"), domain->name);
        return (-1);
    }

    domain->id = privdom->def->id = privconn->nextDomID++;
    privdom->state = VIR_DOMAIN_RUNNING;

    return (0);
}

static int testDomainUndefine(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Domain '%s' is still running"), domain->name);
        return (-1);
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    virDomainRemoveInactive(&privconn->domains,
                            privdom);

    return (0);
}

static int testDomainGetAutostart(virDomainPtr domain,
                                  int *autostart)
{
    GET_DOMAIN(domain, -1);
    *autostart = privdom->autostart;
    return (0);
}


static int testDomainSetAutostart(virDomainPtr domain,
                                  int autostart)
{
    GET_DOMAIN(domain, -1);
    privdom->autostart = autostart ? 1 : 0;
    return (0);
}

static char *testDomainGetSchedulerType(virDomainPtr domain,
                                        int *nparams)
{
    char *type;
    *nparams = 1;
    type = strdup("fair");
    if (!type) {
        testError(domain->conn, VIR_ERR_NO_MEMORY, "schedular");
        return (NULL);
    }
    return type;
}

static int testDomainGetSchedulerParams(virDomainPtr domain,
                                        virSchedParameterPtr params,
                                        int *nparams)
{
    GET_DOMAIN(domain, -1);
    if (*nparams != 1) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "nparams");
        return (-1);
    }
    strcpy(params[0].field, "weight");
    params[0].type = VIR_DOMAIN_SCHED_FIELD_UINT;
    /* XXX */
    /*params[0].value.ui = privdom->weight;*/
    params[0].value.ui = 50;
    return 0;
}


static int testDomainSetSchedulerParams(virDomainPtr domain,
                                        virSchedParameterPtr params,
                                        int nparams)
{
    GET_DOMAIN(domain, -1);
    if (nparams != 1) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "nparams");
        return (-1);
    }
    if (STRNEQ(params[0].field, "weight")) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "field");
        return (-1);
    }
    if (params[0].type != VIR_DOMAIN_SCHED_FIELD_UINT) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "type");
        return (-1);
    }
    /* XXX */
    /*privdom->weight = params[0].value.ui;*/
    return 0;
}

static virDrvOpenStatus testOpenNetwork(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        int flags ATTRIBUTE_UNUSED) {
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->networkPrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testCloseNetwork(virConnectPtr conn) {
    conn->networkPrivateData = NULL;
    return 0;
}


static virNetworkPtr testLookupNetworkByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    virNetworkObjPtr net = NULL;
    GET_CONNECTION(conn);

    if ((net = virNetworkFindByUUID(&privconn->networks, uuid)) == NULL) {
        testError (conn, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, net->def->name, net->def->uuid);
}

static virNetworkPtr testLookupNetworkByName(virConnectPtr conn,
                                             const char *name)
{
    virNetworkObjPtr net = NULL;
    GET_CONNECTION(conn);

    if ((net = virNetworkFindByName(&privconn->networks, name)) == NULL) {
        testError (conn, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, net->def->name, net->def->uuid);
}


static int testNumNetworks(virConnectPtr conn) {
    int numActive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->networks.count ; i++)
        if (virNetworkIsActive(privconn->networks.objs[i]))
            numActive++;

    return numActive;
}

static int testListNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn);

    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->networks.count && n < nnames ; i++)
        if (virNetworkIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name)))
            goto no_memory;

    return n;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    return (-1);
}

static int testNumDefinedNetworks(virConnectPtr conn) {
    int numInactive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->networks.count ; i++)
        if (!virNetworkIsActive(privconn->networks.objs[i]))
            numInactive++;

    return numInactive;
}

static int testListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn);

    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->networks.count && n < nnames ; i++)
        if (!virNetworkIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name)))
            goto no_memory;

    return n;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    return (-1);
}

static virNetworkPtr testNetworkCreate(virConnectPtr conn, const char *xml) {
    virNetworkDefPtr def;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    if ((def = virNetworkDefParseString(conn, xml)) == NULL)
        return NULL;

    if ((net = virNetworkAssignDef(conn, &privconn->networks,
                                   def)) == NULL) {
        virNetworkDefFree(def);
        return NULL;
    }
    net->active = 1;

    return virGetNetwork(conn, def->name, def->uuid);
}

static virNetworkPtr testNetworkDefine(virConnectPtr conn, const char *xml) {
    virNetworkDefPtr def;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    if ((def = virNetworkDefParseString(conn, xml)) == NULL)
        return NULL;

    if ((net = virNetworkAssignDef(conn, &privconn->networks,
                                   def)) == NULL) {
        virNetworkDefFree(def);
        return NULL;
    }
    net->persistent = 1;

    return virGetNetwork(conn, def->name, def->uuid);
}

static int testNetworkUndefine(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (virNetworkIsActive(privnet)) {
        testError(network->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Network '%s' is still running"), network->name);
        return (-1);
    }

    virNetworkRemoveInactive(&privconn->networks,
                             privnet);

    return (0);
}

static int testNetworkStart(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (virNetworkIsActive(privnet)) {
        testError(network->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Network '%s' is already running"), network->name);
        return (-1);
    }

    privnet->active = 1;

    return (0);
}

static int testNetworkDestroy(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    privnet->active = 0;
    if (!privnet->persistent) {
        virNetworkRemoveInactive(&privconn->networks,
                                 privnet);
    }
    return (0);
}

static char *testNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    GET_NETWORK(network, NULL);

    return virNetworkDefFormat(network->conn, privnet->def);
}

static char *testNetworkGetBridgeName(virNetworkPtr network) {
    char *bridge = NULL;
    GET_NETWORK(network, NULL);
    if (privnet->def->bridge &&
        !(bridge = strdup(privnet->def->bridge))) {
        testError(network->conn, VIR_ERR_NO_MEMORY, "network");
        return NULL;
    }
    return bridge;
}

static int testNetworkGetAutostart(virNetworkPtr network,
                                   int *autostart) {
    GET_NETWORK(network, -1);
    *autostart = privnet->autostart;
    return (0);
}

static int testNetworkSetAutostart(virNetworkPtr network,
                                   int autostart) {
    GET_NETWORK(network, -1);
    privnet->autostart = autostart ? 1 : 0;
    return (0);
}


/*
 * Storage Driver routines
 */

static int testStoragePoolObjSetDefaults(virStoragePoolObjPtr pool) {

    pool->def->capacity = defaultPoolCap;
    pool->def->allocation = defaultPoolAlloc;
    pool->def->available = defaultPoolCap - defaultPoolAlloc;

    pool->configFile = strdup("\0");
    if (!pool->configFile) {
        testError(NULL, VIR_ERR_NO_MEMORY, "configFile");
        return -1;
    }

    return 0;
}

static virDrvOpenStatus testStorageOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        int flags ATTRIBUTE_UNUSED) {
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->storagePrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testStorageClose(virConnectPtr conn) {
    conn->storagePrivateData = NULL;
    return 0;
}

static virStoragePoolPtr
testStoragePoolLookupByUUID(virConnectPtr conn,
                            const unsigned char *uuid) {
    virStoragePoolObjPtr pool = NULL;
    GET_CONNECTION(conn);

    if ((pool = virStoragePoolObjFindByUUID(&privconn->pools, uuid)) == NULL) {
        testError (conn, VIR_ERR_NO_STORAGE_POOL, NULL);
        return NULL;
    }

    return virGetStoragePool(conn, pool->def->name, pool->def->uuid);
}

static virStoragePoolPtr
testStoragePoolLookupByName(virConnectPtr conn,
                            const char *name) {
    virStoragePoolObjPtr pool = NULL;
    GET_CONNECTION(conn);

    if ((pool = virStoragePoolObjFindByName(&privconn->pools, name)) == NULL) {
        testError (conn, VIR_ERR_NO_STORAGE_POOL, NULL);
        return NULL;
    }

    return virGetStoragePool(conn, pool->def->name, pool->def->uuid);
}

static virStoragePoolPtr
testStoragePoolLookupByVolume(virStorageVolPtr vol) {
    return testStoragePoolLookupByName(vol->conn, vol->pool);
}

static int
testStorageNumPools(virConnectPtr conn) {

    int numActive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->pools.count ; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numActive++;

    return numActive;
}

static int
testStorageListPools(virConnectPtr conn,
                     char **const names,
                     int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn);

    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->pools.count && n < nnames ; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name)))
            goto no_memory;

    return n;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    return (-1);
}

static int
testStorageNumDefinedPools(virConnectPtr conn) {

    int numInactive = 0, i;
    GET_CONNECTION(conn);

    for (i = 0 ; i < privconn->pools.count ; i++)
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numInactive++;

    return numInactive;
}

static int
testStorageListDefinedPools(virConnectPtr conn,
                            char **const names,
                            int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn);

    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->pools.count && n < nnames ; i++)
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name)))
            goto no_memory;

    return n;

no_memory:
    testError(conn, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    return (-1);
}

static int
testStoragePoolRefresh(virStoragePoolPtr obj,
                       unsigned int flags ATTRIBUTE_UNUSED);

static int
testStoragePoolStart(virStoragePoolPtr obj,
                     unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, -1);
    POOL_IS_NOT_ACTIVE(privpool, -1);

    if (testStoragePoolRefresh(obj, 0) == 0)
        return -1;
    privpool->active = 1;

    return 0;
}

static char *
testStorageFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                           const char *type ATTRIBUTE_UNUSED,
                           const char *srcSpec ATTRIBUTE_UNUSED,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    return NULL;
}


static virStoragePoolPtr
testStoragePoolCreate(virConnectPtr conn,
                      const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;
    GET_CONNECTION(conn);

    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        return NULL;

    if (virStoragePoolObjFindByUUID(&privconn->pools, def->uuid) ||
        virStoragePoolObjFindByName(&privconn->pools, def->name)) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("storage pool already exists"));
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, &privconn->pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (testStoragePoolObjSetDefaults(pool) == -1) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        return NULL;
    }
    pool->active = 1;

    return virGetStoragePool(conn, pool->def->name, pool->def->uuid);
}

static virStoragePoolPtr
testStoragePoolDefine(virConnectPtr conn,
                      const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED) {
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool;
    GET_CONNECTION(conn);

    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        return NULL;

    def->capacity = defaultPoolCap;
    def->allocation = defaultPoolAlloc;
    def->available = defaultPoolCap - defaultPoolAlloc;

    if (!(pool = virStoragePoolObjAssignDef(conn, &privconn->pools, def))) {
        virStoragePoolDefFree(def);
        return NULL;
    }

    if (testStoragePoolObjSetDefaults(pool) == -1) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        return NULL;
    }

    return virGetStoragePool(conn, pool->def->name, pool->def->uuid);
}

static int
testStoragePoolUndefine(virStoragePoolPtr obj) {
    GET_POOL(obj, -1);
    POOL_IS_NOT_ACTIVE(privpool, -1);

    virStoragePoolObjRemove(&privconn->pools, privpool);

    return 0;
}

static int
testStoragePoolBuild(virStoragePoolPtr obj,
                     unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, -1);
    POOL_IS_NOT_ACTIVE(privpool, -1);

    return 0;
}


static int
testStoragePoolDestroy(virStoragePoolPtr obj) {
    GET_POOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);

    privpool->active = 0;

    if (privpool->configFile == NULL)
        virStoragePoolObjRemove(&privconn->pools, privpool);

    return 0;
}


static int
testStoragePoolDelete(virStoragePoolPtr obj,
                      unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, -1);
    POOL_IS_NOT_ACTIVE(privpool, -1);

    return 0;
}


static int
testStoragePoolRefresh(virStoragePoolPtr obj,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);

    return 0;
}


static int
testStoragePoolGetInfo(virStoragePoolPtr obj,
                       virStoragePoolInfoPtr info) {
    GET_POOL(obj, -1);

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (privpool->active)
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = privpool->def->capacity;
    info->allocation = privpool->def->allocation;
    info->available = privpool->def->available;

    return 0;
}

static char *
testStoragePoolDumpXML(virStoragePoolPtr obj,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, NULL);

    return virStoragePoolDefFormat(obj->conn, privpool->def);
}

static int
testStoragePoolGetAutostart(virStoragePoolPtr obj,
                            int *autostart) {
    GET_POOL(obj, -1);

    if (!privpool->configFile) {
        *autostart = 0;
    } else {
        *autostart = privpool->autostart;
    }

    return 0;
}

static int
testStoragePoolSetAutostart(virStoragePoolPtr obj,
                            int autostart) {
    GET_POOL(obj, -1);

    if (!privpool->configFile) {
        testError(obj->conn, VIR_ERR_INVALID_ARG,
                  "%s", _("pool has no config file"));
        return -1;
    }

    autostart = (autostart != 0);

    if (privpool->autostart == autostart)
        return 0;

    privpool->autostart = autostart;
    return 0;
}


static int
testStoragePoolNumVolumes(virStoragePoolPtr obj) {
    GET_POOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);

    return privpool->volumes.count;
}

static int
testStoragePoolListVolumes(virStoragePoolPtr obj,
                           char **const names,
                           int maxnames) {
    GET_POOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);
    int i = 0, n = 0;

    memset(names, 0, maxnames * sizeof(*names));
    for (i = 0 ; i < privpool->volumes.count && n < maxnames ; i++) {
        if ((names[n++] = strdup(privpool->volumes.objs[i]->name)) == NULL) {
            testError(obj->conn, VIR_ERR_NO_MEMORY, "%s", _("name"));
            goto cleanup;
        }
    }

    return n;

 cleanup:
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[i]);

    memset(names, 0, maxnames * sizeof(*names));
    return -1;
}


static virStorageVolPtr
testStorageVolumeLookupByName(virStoragePoolPtr obj,
                              const char *name ATTRIBUTE_UNUSED) {
    GET_POOL(obj, NULL);
    POOL_IS_ACTIVE(privpool, NULL);
    virStorageVolDefPtr vol = virStorageVolDefFindByName(privpool, name);

    if (!vol) {
        testError(obj->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"), name);
        return NULL;
    }

    return virGetStorageVol(obj->conn, privpool->def->name,
                            vol->name, vol->key);
}


static virStorageVolPtr
testStorageVolumeLookupByKey(virConnectPtr conn,
                             const char *key) {
    GET_CONNECTION(conn);
    unsigned int i;

    for (i = 0 ; i < privconn->pools.count ; i++) {
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByKey(privconn->pools.objs[i], key);

            if (vol)
                return virGetStorageVol(conn,
                                        privconn->pools.objs[i]->def->name,
                                        vol->name,
                                        vol->key);
        }
    }

    testError(conn, VIR_ERR_INVALID_STORAGE_VOL,
              _("no storage vol with matching key '%s'"), key);
    return NULL;
}

static virStorageVolPtr
testStorageVolumeLookupByPath(virConnectPtr conn,
                              const char *path) {
    GET_CONNECTION(conn);
    unsigned int i;

    for (i = 0 ; i < privconn->pools.count ; i++) {
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr vol =
                virStorageVolDefFindByPath(privconn->pools.objs[i], path);

            if (vol)
                return virGetStorageVol(conn,
                                        privconn->pools.objs[i]->def->name,
                                        vol->name,
                                        vol->key);
        }
    }

    testError(conn, VIR_ERR_INVALID_STORAGE_VOL,
              _("no storage vol with matching path '%s'"), path);
    return NULL;
}

static virStorageVolPtr
testStorageVolumeCreateXML(virStoragePoolPtr obj,
                           const char *xmldesc,
                           unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL(obj, NULL);
    POOL_IS_ACTIVE(privpool, NULL);
    virStorageVolDefPtr vol;

    vol = virStorageVolDefParse(obj->conn, privpool->def, xmldesc, NULL);
    if (vol == NULL)
        return NULL;

    if (virStorageVolDefFindByName(privpool, vol->name)) {
        testError(obj->conn, VIR_ERR_INVALID_STORAGE_POOL,
                  "%s", _("storage vol already exists"));
        virStorageVolDefFree(vol);
        return NULL;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + vol->allocation) >
         privpool->def->capacity) {
        testError(obj->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Not enough free space in pool for volume '%s'"),
                  vol->name);
        virStorageVolDefFree(vol);
        return NULL;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count+1) < 0) {
        testError(obj->conn, VIR_ERR_NO_MEMORY, NULL);
        virStorageVolDefFree(vol);
        return NULL;
    }

    if (VIR_ALLOC_N(vol->target.path, strlen(privpool->def->target.path) +
                    1 + strlen(vol->name) + 1) < 0) {
        virStorageVolDefFree(vol);
        testError(obj->conn, VIR_ERR_NO_MEMORY, "%s", _("target"));
        return NULL;
    }

    strcpy(vol->target.path, privpool->def->target.path);
    strcat(vol->target.path, "/");
    strcat(vol->target.path, vol->name);
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virStorageVolDefFree(vol);
        testError(obj->conn, VIR_ERR_INTERNAL_ERROR, "%s",
                  _("storage vol key"));
        return NULL;
    }

    privpool->def->allocation += vol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    privpool->volumes.objs[privpool->volumes.count++] = vol;

    return virGetStorageVol(obj->conn, privpool->def->name, vol->name,
                            vol->key);
}

static int
testStorageVolumeDelete(virStorageVolPtr obj,
                        unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL_FROM_VOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);
    GET_VOL(obj, privpool, -1);
    int i;

    privpool->def->allocation -= privvol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    for (i = 0 ; i < privpool->volumes.count ; i++) {
        if (privpool->volumes.objs[i] == privvol) {
            virStorageVolDefFree(privvol);

            if (i < (privpool->volumes.count - 1))
                memmove(privpool->volumes.objs + i,
                        privpool->volumes.objs + i + 1,
                        sizeof(*(privpool->volumes.objs)) *
                                (privpool->volumes.count - (i + 1)));

            if (VIR_REALLOC_N(privpool->volumes.objs,
                              privpool->volumes.count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            privpool->volumes.count--;

            break;
        }
    }

    return 0;
}


static int testStorageVolumeTypeForPool(int pooltype) {

    switch(pooltype) {
        case VIR_STORAGE_POOL_DIR:
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_NETFS:
            return VIR_STORAGE_VOL_FILE;
        default:
            return VIR_STORAGE_VOL_BLOCK;
    }
}

static int
testStorageVolumeGetInfo(virStorageVolPtr obj,
                         virStorageVolInfoPtr info) {
    GET_POOL_FROM_VOL(obj, -1);
    POOL_IS_ACTIVE(privpool, -1);
    GET_VOL(obj, privpool, -1);

    memset(info, 0, sizeof(*info));
    info->type = testStorageVolumeTypeForPool(privpool->def->type);
    info->capacity = privvol->capacity;
    info->allocation = privvol->allocation;

    return 0;
}

static char *
testStorageVolumeGetXMLDesc(virStorageVolPtr obj,
                            unsigned int flags ATTRIBUTE_UNUSED) {
    GET_POOL_FROM_VOL(obj, NULL);
    POOL_IS_ACTIVE(privpool, NULL);
    GET_VOL(obj, privpool, NULL);

    return virStorageVolDefFormat(obj->conn, privpool->def, privvol);
}

static char *
testStorageVolumeGetPath(virStorageVolPtr obj) {
    GET_POOL_FROM_VOL(obj, NULL);
    POOL_IS_ACTIVE(privpool, NULL);
    GET_VOL(obj, privpool, NULL);
    char *ret;

    ret = strdup(privvol->target.path);
    if (ret == NULL) {
        testError(obj->conn, VIR_ERR_NO_MEMORY, "%s", _("path"));
        return NULL;
    }
    return ret;
}


static virDriver testDriver = {
    VIR_DRV_TEST,
    "Test",
    testOpen, /* open */
    testClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    testGetVersion, /* version */
    testGetHostname, /* hostname */
    NULL, /* URI */
    testGetMaxVCPUs, /* getMaxVcpus */
    testNodeGetInfo, /* nodeGetInfo */
    testGetCapabilities, /* getCapabilities */
    testListDomains, /* listDomains */
    testNumOfDomains, /* numOfDomains */
    testDomainCreateXML, /* domainCreateXML */
    testLookupDomainByID, /* domainLookupByID */
    testLookupDomainByUUID, /* domainLookupByUUID */
    testLookupDomainByName, /* domainLookupByName */
    testPauseDomain, /* domainSuspend */
    testResumeDomain, /* domainResume */
    testShutdownDomain, /* domainShutdown */
    testRebootDomain, /* domainReboot */
    testDestroyDomain, /* domainDestroy */
    testGetOSType, /* domainGetOSType */
    testGetMaxMemory, /* domainGetMaxMemory */
    testSetMaxMemory, /* domainSetMaxMemory */
    testSetMemory, /* domainSetMemory */
    testGetDomainInfo, /* domainGetInfo */
    testDomainSave, /* domainSave */
    testDomainRestore, /* domainRestore */
    testDomainCoreDump, /* domainCoreDump */
    testSetVcpus, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    testDomainDumpXML, /* domainDumpXML */
    testListDefinedDomains, /* listDefinedDomains */
    testNumOfDefinedDomains, /* numOfDefinedDomains */
    testDomainCreate, /* domainCreate */
    testDomainDefineXML, /* domainDefineXML */
    testDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    testDomainGetAutostart, /* domainGetAutostart */
    testDomainSetAutostart, /* domainSetAutostart */
    testDomainGetSchedulerType, /* domainGetSchedulerType */
    testDomainGetSchedulerParams, /* domainGetSchedulerParameters */
    testDomainSetSchedulerParams, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    NULL, /* domainBlockStats */
    NULL, /* domainInterfaceStats */
    NULL, /* domainBlockPeek */
    NULL, /* domainMemoryPeek */
    testNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    NULL, /* getFreeMemory */
    NULL, /* domainEventRegister */
    NULL, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
};

static virNetworkDriver testNetworkDriver = {
    "Test",
    testOpenNetwork, /* open */
    testCloseNetwork, /* close */
    testNumNetworks, /* numOfNetworks */
    testListNetworks, /* listNetworks */
    testNumDefinedNetworks, /* numOfDefinedNetworks */
    testListDefinedNetworks, /* listDefinedNetworks */
    testLookupNetworkByUUID, /* networkLookupByUUID */
    testLookupNetworkByName, /* networkLookupByName */
    testNetworkCreate, /* networkCreateXML */
    testNetworkDefine, /* networkDefineXML */
    testNetworkUndefine, /* networkUndefine */
    testNetworkStart, /* networkCreate */
    testNetworkDestroy, /* networkDestroy */
    testNetworkDumpXML, /* networkDumpXML */
    testNetworkGetBridgeName, /* networkGetBridgeName */
    testNetworkGetAutostart, /* networkGetAutostart */
    testNetworkSetAutostart, /* networkSetAutostart */
};

static virStorageDriver testStorageDriver = {
    .name = "Test",
    .open = testStorageOpen,
    .close = testStorageClose,

    .numOfPools = testStorageNumPools,
    .listPools = testStorageListPools,
    .numOfDefinedPools = testStorageNumDefinedPools,
    .listDefinedPools = testStorageListDefinedPools,
    .findPoolSources = testStorageFindPoolSources,
    .poolLookupByName = testStoragePoolLookupByName,
    .poolLookupByUUID = testStoragePoolLookupByUUID,
    .poolLookupByVolume = testStoragePoolLookupByVolume,
    .poolCreateXML = testStoragePoolCreate,
    .poolDefineXML = testStoragePoolDefine,
    .poolBuild = testStoragePoolBuild,
    .poolUndefine = testStoragePoolUndefine,
    .poolCreate = testStoragePoolStart,
    .poolDestroy = testStoragePoolDestroy,
    .poolDelete = testStoragePoolDelete,
    .poolRefresh = testStoragePoolRefresh,
    .poolGetInfo = testStoragePoolGetInfo,
    .poolGetXMLDesc = testStoragePoolDumpXML,
    .poolGetAutostart = testStoragePoolGetAutostart,
    .poolSetAutostart = testStoragePoolSetAutostart,
    .poolNumOfVolumes = testStoragePoolNumVolumes,
    .poolListVolumes = testStoragePoolListVolumes,

    .volLookupByName = testStorageVolumeLookupByName,
    .volLookupByKey = testStorageVolumeLookupByKey,
    .volLookupByPath = testStorageVolumeLookupByPath,
    .volCreateXML = testStorageVolumeCreateXML,
    .volDelete = testStorageVolumeDelete,
    .volGetInfo = testStorageVolumeGetInfo,
    .volGetXMLDesc = testStorageVolumeGetXMLDesc,
    .volGetPath = testStorageVolumeGetPath,
};

/**
 * testRegister:
 *
 * Registers the test driver
 */
int
testRegister(void)
{
    if (virRegisterDriver(&testDriver) < 0)
        return -1;
    if (virRegisterNetworkDriver(&testNetworkDriver) < 0)
        return -1;
    if (virRegisterStorageDriver(&testStorageDriver) < 0)
        return -1;
    return 0;
}
