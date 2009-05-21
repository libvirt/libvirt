/*
 * test.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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
#include "domain_event.h"
#include "event.h"
#include "storage_conf.h"
#include "xml.h"
#include "threads.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_TEST

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
    virMutex lock;

    char path[PATH_MAX];
    int nextDomID;
    virCapsPtr caps;
    virNodeInfo nodeInfo;
    virDomainObjList domains;
    virNetworkObjList networks;
    virStoragePoolObjList pools;
    int numCells;
    testCell cells[MAX_CELLS];


    /* An array of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;
    virDomainEventQueuePtr domainEventQueue;
    int domainEventTimer;
    int domainEventDispatching;
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


#define testError(conn, code, fmt...)                               \
        virReportErrorHelper(conn, VIR_FROM_TEST, code, __FILE__, \
                               __FUNCTION__, __LINE__, fmt)

static int testClose(virConnectPtr conn);
static void testDomainEventFlush(int timer, void *opaque);
static void testDomainEventQueue(testConnPtr driver,
                                 virDomainEventPtr event);


static void testDriverLock(testConnPtr driver)
{
    virMutexLock(&driver->lock);
}

static void testDriverUnlock(testConnPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static virCapsPtr
testBuildCapabilities(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    const char *const guest_types[] = { "hvm", "xen" };
    int i;

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
    virReportOOMError(conn);
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

static const unsigned long long defaultPoolCap = (100 * 1024 * 1024 * 1024ull);
static const unsigned long long defaultPoolAlloc = 0;

static int testStoragePoolObjSetDefaults(virConnectPtr conn, virStoragePoolObjPtr pool);

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
        virReportOOMError(conn);
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("cannot initialize mutex"));
        VIR_FREE(privconn);
        return VIR_DRV_OPEN_ERROR;
    }

    testDriverLock(privconn);
    conn->privateData = privconn;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(conn, errno,
                             "%s", _("getting time of day"));
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

    if (!(domdef = virDomainDefParseString(conn, privconn->caps,
                                           defaultDomainXML,
                                           VIR_DOMAIN_XML_INACTIVE)))
        goto error;
    if (!(domobj = virDomainAssignDef(conn, &privconn->domains, domdef))) {
        virDomainDefFree(domdef);
        goto error;
    }
    domobj->def->id = privconn->nextDomID++;
    domobj->state = VIR_DOMAIN_RUNNING;
    domobj->persistent = 1;
    virDomainObjUnlock(domobj);

    if (!(netdef = virNetworkDefParseString(conn, defaultNetworkXML)))
        goto error;
    if (!(netobj = virNetworkAssignDef(conn, &privconn->networks, netdef))) {
        virNetworkDefFree(netdef);
        goto error;
    }
    netobj->active = 1;
    netobj->persistent = 1;
    virNetworkObjUnlock(netobj);

    if (!(pooldef = virStoragePoolDefParse(conn, defaultPoolXML, NULL)))
        goto error;

    if (!(poolobj = virStoragePoolObjAssignDef(conn, &privconn->pools,
                                               pooldef))) {
        virStoragePoolDefFree(pooldef);
        goto error;
    }

    if (testStoragePoolObjSetDefaults(conn, poolobj) == -1) {
        virStoragePoolObjUnlock(poolobj);
        goto error;
    }
    poolobj->active = 1;
    virStoragePoolObjUnlock(poolobj);

    testDriverUnlock(privconn);

    return VIR_DRV_OPEN_SUCCESS;

error:
    virDomainObjListFree(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virStoragePoolObjListFree(&privconn->pools);
    virCapabilitiesFree(privconn->caps);
    testDriverUnlock(privconn);
    conn->privateData = NULL;
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
        virReportOOMError(conn);
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("cannot initialize mutex"));
        VIR_FREE(privconn);
        return VIR_DRV_OPEN_ERROR;
    }

    testDriverLock(privconn);
    conn->privateData = privconn;

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if ((fd = open(file, O_RDONLY)) < 0) {
        virReportSystemError(NULL, errno,
                             _("loading host definition file '%s'"),
                             file);
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
        virDomainObjUnlock(dom);
    }
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
        virNetworkObjUnlock(net);
    }
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

        if (testStoragePoolObjSetDefaults(conn, pool) == -1) {
            virStoragePoolObjUnlock(pool);
            goto error;
        }
        pool->active = 1;
        virStoragePoolObjUnlock(pool);
    }
    VIR_FREE(pools);

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    testDriverUnlock(privconn);

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
    testDriverUnlock(privconn);
    VIR_FREE(privconn);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}


static virDrvOpenStatus testOpen(virConnectPtr conn,
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

    if (ret == VIR_DRV_OPEN_SUCCESS) {
        testConnPtr privconn = conn->privateData;
        testDriverLock(privconn);
        /* Init callback list */
        if (VIR_ALLOC(privconn->domainEventCallbacks) < 0 ||
            !(privconn->domainEventQueue = virDomainEventQueueNew())) {
            virReportOOMError(NULL);
            testDriverUnlock(privconn);
            testClose(conn);
            return VIR_DRV_OPEN_ERROR;
        }

        if ((privconn->domainEventTimer =
             virEventAddTimeout(-1, testDomainEventFlush, privconn, NULL)) < 0)
            DEBUG0("virEventAddTimeout failed: No addTimeoutImpl defined. "
                   "continuing without events.");
        testDriverUnlock(privconn);
    }

    return (ret);
}

static int testClose(virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    testDriverLock(privconn);
    virCapabilitiesFree(privconn->caps);
    virDomainObjListFree(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virStoragePoolObjListFree(&privconn->pools);

    virDomainEventCallbackListFree(privconn->domainEventCallbacks);
    virDomainEventQueueFree(privconn->domainEventQueue);

    if (privconn->domainEventTimer != -1)
        virEventRemoveTimeout(privconn->domainEventTimer);

    testDriverUnlock(privconn);
    virMutexDestroy(&privconn->lock);

    VIR_FREE (privconn);
    conn->privateData = NULL;
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
    char *result;

    result = virGetHostname();
    if (result == NULL) {
        virReportSystemError(conn, errno,
                             "%s", _("cannot lookup hostname"));
        return NULL;
    }
    /* Caller frees this string. */
    return result;
}

static int testGetMaxVCPUs(virConnectPtr conn ATTRIBUTE_UNUSED,
                           const char *type ATTRIBUTE_UNUSED)
{
    return 32;
}

static int testNodeGetInfo(virConnectPtr conn,
                           virNodeInfoPtr info)
{
    testConnPtr privconn = conn->privateData;
    testDriverLock(privconn);
    memcpy(info, &privconn->nodeInfo, sizeof(virNodeInfo));
    testDriverUnlock(privconn);
    return (0);
}

static char *testGetCapabilities (virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    char *xml;
    testDriverLock(privconn);
    if ((xml = virCapabilitiesFormatXML(privconn->caps)) == NULL)
        virReportOOMError(conn);
    testDriverUnlock(privconn);
    return xml;
}

static int testNumOfDomains(virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    unsigned int numActive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->domains.count ; i++)
        if (virDomainIsActive(privconn->domains.objs[i]))
            numActive++;
    testDriverUnlock(privconn);

    return numActive;
}

static virDomainPtr
testDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    virDomainEventPtr event = NULL;

    testDriverLock(privconn);
    if ((def = virDomainDefParseString(conn, privconn->caps, xml,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL) {
        virDomainDefFree(def);
        goto cleanup;
    }
    dom->state = VIR_DOMAIN_RUNNING;
    dom->def->id = privconn->nextDomID++;

    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);

    ret = virGetDomain(conn, def->name, def->uuid);
    if (ret)
        ret->id = def->id;

cleanup:
    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}


static virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                         int id)
{
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    testDriverLock(privconn);
    dom = virDomainFindByID(&privconn->domains, id);
    testDriverUnlock(privconn);

    if (dom == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

cleanup:
    if (dom)
        virDomainObjUnlock(dom);
    return ret;
}

static virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom ;

    testDriverLock(privconn);
    dom = virDomainFindByUUID(&privconn->domains, uuid);
    testDriverUnlock(privconn);

    if (dom == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

cleanup:
    if (dom)
        virDomainObjUnlock(dom);
    return ret;
}

static virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                           const char *name)
{
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    testDriverLock(privconn);
    dom = virDomainFindByName(&privconn->domains, name);
    testDriverUnlock(privconn);

    if (dom == NULL) {
        testError (conn, VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

cleanup:
    if (dom)
        virDomainObjUnlock(dom);
    return ret;
}

static int testListDomains (virConnectPtr conn,
                            int *ids,
                            int maxids)
{
    testConnPtr privconn = conn->privateData;
    unsigned int n = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->domains.count && n < maxids ; i++) {
        virDomainObjLock(privconn->domains.objs[i]);
        if (virDomainIsActive(privconn->domains.objs[i]))
            ids[n++] = privconn->domains.objs[i]->def->id;
        virDomainObjUnlock(privconn->domains.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;
}

static int testDestroyDomain (virDomainPtr domain)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    privdom->def->id = -1;
    domain->id = -1;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
        privdom = NULL;
    }


    ret = 0;
cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testResumeDomain (virDomainPtr domain)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_PAUSED) {
        testError(domain->conn,
                  VIR_ERR_INTERNAL_ERROR, _("domain '%s' not paused"),
                  domain->name);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_RUNNING;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_RESUMED,
                                     VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event) {
        testDriverLock(privconn);
        testDomainEventQueue(privconn, event);
        testDriverUnlock(privconn);
    }
    return ret;
}

static int testPauseDomain (virDomainPtr domain)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state == VIR_DOMAIN_SHUTOFF ||
        privdom->state == VIR_DOMAIN_PAUSED) {
        testError(domain->conn,
                  VIR_ERR_INTERNAL_ERROR, _("domain '%s' not running"),
                  domain->name);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_PAUSED;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_SUSPENDED,
                                     VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);

    if (event) {
        testDriverLock(privconn);
        testDomainEventQueue(privconn, event);
        testDriverUnlock(privconn);
    }
    return ret;
}

static int testShutdownDomain (virDomainPtr domain)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' not running"), domain->name);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    domain->id = -1;
    privdom->def->id = -1;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
        privdom = NULL;
    }
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

/* Similar behaviour as shutdown */
static int testRebootDomain (virDomainPtr domain,
                             unsigned int action ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

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

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        event = virDomainEventNewFromObj(privdom,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);
        if (!privdom->persistent) {
            virDomainRemoveInactive(&privconn->domains,
                                    privdom);
            privdom = NULL;
        }
    }

    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testGetDomainInfo (virDomainPtr domain,
                              virDomainInfoPtr info)
{
    testConnPtr privconn = domain->conn->privateData;
    struct timeval tv;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("getting time of day"));
        goto cleanup;
    }

    info->state = privdom->state;
    info->memory = privdom->def->memory;
    info->maxMem = privdom->def->maxmem;
    info->nrVirtCpu = privdom->def->vcpus;
    info->cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

#define TEST_SAVE_MAGIC "TestGuestMagic"

static int testDomainSave(virDomainPtr domain,
                          const char *path)
{
    testConnPtr privconn = domain->conn->privateData;
    char *xml = NULL;
    int fd = -1;
    int len;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    xml = virDomainDefFormat(domain->conn,
                             privdom->def,
                             VIR_DOMAIN_XML_SECURE);

    if (xml == NULL) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' failed to allocate space for metadata"),
                             domain->name);
        goto cleanup;
    }

    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' to '%s': open failed"),
                             domain->name, path);
        goto cleanup;
    }
    len = strlen(xml);
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    if (safewrite(fd, (char*)&len, sizeof(len)) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    if (safewrite(fd, xml, len) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    fd = -1;

    privdom->state = VIR_DOMAIN_SHUTOFF;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
        privdom = NULL;
    }
    ret = 0;

cleanup:
    VIR_FREE(xml);

    /* Don't report failure in close or unlink, because
     * in either case we're already in a failure scenario
     * and have reported a earlier error */
    if (ret != 0) {
        if (fd != -1)
            close(fd);
        unlink(path);
    }
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testDomainRestore(virConnectPtr conn,
                             const char *path)
{
    testConnPtr privconn = conn->privateData;
    char *xml = NULL;
    char magic[15];
    int fd = -1;
    int len;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int ret = -1;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(conn, errno,
                             _("cannot read domain image '%s'"),
                             path);
        goto cleanup;
    }
    if (saferead(fd, magic, sizeof(magic)) != sizeof(magic)) {
        virReportSystemError(conn, errno,
                             _("incomplete save header in '%s'"),
                             path);
        goto cleanup;
    }
    if (memcmp(magic, TEST_SAVE_MAGIC, sizeof(magic))) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("mismatched header magic"));
        goto cleanup;
    }
    if (saferead(fd, (char*)&len, sizeof(len)) != sizeof(len)) {
        virReportSystemError(conn, errno,
                             _("failed to read metadata length in '%s'"),
                             path);
        goto cleanup;
    }
    if (len < 1 || len > 8192) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("length of metadata out of range"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(xml, len+1) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    if (saferead(fd, xml, len) != len) {
        virReportSystemError(conn, errno,
                             _("incomplete metdata in '%s'"), path);
        goto cleanup;
    }
    xml[len] = '\0';

    testDriverLock(privconn);
    def = virDomainDefParseString(conn, privconn->caps, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (!def)
        goto cleanup;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL)
        goto cleanup;

    dom->state = VIR_DOMAIN_RUNNING;
    dom->def->id = privconn->nextDomID++;
    def = NULL;
    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    ret = 0;

cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    if (fd != -1)
        close(fd);
    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testDomainCoreDump(virDomainPtr domain,
                              const char *to,
                              int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = domain->conn->privateData;
    int fd = -1;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if ((fd = open(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("domain '%s' coredump: failed to open %s"),
                             domain->name, to);
        goto cleanup;
    }
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("domain '%s' coredump: failed to write header to %s"),
                             domain->name, to);
        goto cleanup;
    }
    if (close(fd) < 0) {
        virReportSystemError(domain->conn, errno,
                             _("domain '%s' coredump: write failed: %s"),
                             domain->name, to);
        goto cleanup;
    }
    privdom->state = VIR_DOMAIN_SHUTOFF;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_CRASHED);
    if (!privdom->persistent) {
        virDomainRemoveInactive(&privconn->domains,
                                privdom);
        privdom = NULL;
    }
    ret = 0;

cleanup:
    if (fd != -1)
        close(fd);
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static char *testGetOSType(virDomainPtr dom) {
    char *ret = strdup("linux");
    if (!ret)
        virReportOOMError(dom->conn);
    return ret;
}

static unsigned long testGetMaxMemory(virDomainPtr domain) {
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    unsigned long ret = 0;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = privdom->def->maxmem;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testSetMaxMemory(virDomainPtr domain,
                            unsigned long memory)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    /* XXX validate not over host memory wrt to other domains */
    privdom->def->maxmem = memory;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testSetMemory(virDomainPtr domain,
                         unsigned long memory)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (memory > privdom->def->maxmem) {
        testError(domain->conn,
                  VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->def->memory = memory;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testSetVcpus(virDomainPtr domain,
                        unsigned int nrCpus) {
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    /* We allow more cpus in guest than host */
    if (nrCpus > 32) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->def->vcpus = nrCpus;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static char *testDomainDumpXML(virDomainPtr domain, int flags)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr privdom;
    char *ret = NULL;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    ret = virDomainDefFormat(domain->conn,
                             def,
                             flags);

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testNumOfDefinedDomains(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    unsigned int numInactive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->domains.count ; i++) {
        virDomainObjLock(privconn->domains.objs[i]);
        if (!virDomainIsActive(privconn->domains.objs[i]))
            numInactive++;
        virDomainObjUnlock(privconn->domains.objs[i]);
    }
    testDriverUnlock(privconn);

    return numInactive;
}

static int testListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames) {
    testConnPtr privconn = conn->privateData;
    unsigned int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*maxnames);
    for (i = 0 ; i < privconn->domains.count && n < maxnames ; i++) {
        virDomainObjLock(privconn->domains.objs[i]);
        if (!virDomainIsActive(privconn->domains.objs[i]) &&
            !(names[n++] = strdup(privconn->domains.objs[i]->def->name))) {
            virDomainObjUnlock(privconn->domains.objs[i]);
            goto no_memory;
        }
        virDomainObjUnlock(privconn->domains.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError(conn);
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                        const char *xml) {
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    virDomainEventPtr event = NULL;

    testDriverLock(privconn);
    if ((def = virDomainDefParseString(conn, privconn->caps, xml,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if ((dom = virDomainAssignDef(conn, &privconn->domains,
                                  def)) == NULL) {
        goto cleanup;
    }
    dom->persistent = 1;
    dom->def->id = -1;
    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED);

    ret = virGetDomain(conn, def->name, def->uuid);
    def = NULL;
    if (ret)
        ret->id = -1;

cleanup:
    virDomainDefFree(def);
    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testNodeGetCellsFreeMemory(virConnectPtr conn,
                                      unsigned long long *freemems,
                                      int startCell, int maxCells) {
    testConnPtr privconn = conn->privateData;
    int i, j;
    int ret = -1;

    testDriverLock(privconn);
    if (startCell > privconn->numCells) {
        testError(conn, VIR_ERR_INVALID_ARG,
                  "%s", _("Range exceeds available cells"));
        goto cleanup;
    }

    for (i = startCell, j = 0;
         (i < privconn->numCells && j < maxCells) ;
         ++i, ++j) {
        freemems[j] = privconn->cells[i].mem;
    }
    ret = j;

cleanup:
    testDriverUnlock(privconn);
    return ret;
}


static int testDomainCreate(virDomainPtr domain) {
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Domain '%s' is already running"), domain->name);
        goto cleanup;
    }

    domain->id = privdom->def->id = privconn->nextDomID++;
    privdom->state = VIR_DOMAIN_RUNNING;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testDomainUndefine(virDomainPtr domain) {
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainEventPtr event = NULL;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Domain '%s' is still running"), domain->name);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    event = virDomainEventNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);
    virDomainRemoveInactive(&privconn->domains,
                            privdom);
    privdom = NULL;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    if (event)
        testDomainEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testDomainGetAutostart(virDomainPtr domain,
                                  int *autostart)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    *autostart = privdom->autostart;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}


static int testDomainSetAutostart(virDomainPtr domain,
                                  int autostart)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->autostart = autostart ? 1 : 0;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static char *testDomainGetSchedulerType(virDomainPtr domain,
                                        int *nparams)
{
    char *type = NULL;

    *nparams = 1;
    type = strdup("fair");
    if (!type)
        virReportOOMError(domain->conn);

    return type;
}

static int testDomainGetSchedulerParams(virDomainPtr domain,
                                        virSchedParameterPtr params,
                                        int *nparams)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (*nparams != 1) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "nparams");
        goto cleanup;
    }
    strcpy(params[0].field, "weight");
    params[0].type = VIR_DOMAIN_SCHED_FIELD_UINT;
    /* XXX */
    /*params[0].value.ui = privdom->weight;*/
    params[0].value.ui = 50;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}


static int testDomainSetSchedulerParams(virDomainPtr domain,
                                        virSchedParameterPtr params,
                                        int nparams)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (nparams != 1) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "nparams");
        goto cleanup;
    }
    if (STRNEQ(params[0].field, "weight")) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "field");
        goto cleanup;
    }
    if (params[0].type != VIR_DOMAIN_SCHED_FIELD_UINT) {
        testError(domain->conn, VIR_ERR_INVALID_ARG, "type");
        goto cleanup;
    }
    /* XXX */
    /*privdom->weight = params[0].value.ui;*/
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
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
    testConnPtr privconn = conn->privateData;
    virNetworkObjPtr net;
    virNetworkPtr ret = NULL;

    testDriverLock(privconn);
    net = virNetworkFindByUUID(&privconn->networks, uuid);
    testDriverUnlock(privconn);

    if (net == NULL) {
        testError (conn, VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

cleanup:
    if (net)
        virNetworkObjUnlock(net);
    return ret;
}

static virNetworkPtr testLookupNetworkByName(virConnectPtr conn,
                                             const char *name)
{
    testConnPtr privconn = conn->privateData;
    virNetworkObjPtr net;
    virNetworkPtr ret = NULL;

    testDriverLock(privconn);
    net = virNetworkFindByName(&privconn->networks, name);
    testDriverUnlock(privconn);

    if (net == NULL) {
        testError (conn, VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

cleanup:
    if (net)
        virNetworkObjUnlock(net);
    return ret;
}


static int testNumNetworks(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    int numActive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (virNetworkIsActive(privconn->networks.objs[i]))
            numActive++;
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return numActive;
}

static int testListNetworks(virConnectPtr conn, char **const names, int nnames) {
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->networks.count && n < nnames ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (virNetworkIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name))) {
            virNetworkObjUnlock(privconn->networks.objs[i]);
            goto no_memory;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError(conn);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int testNumDefinedNetworks(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    int numInactive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (!virNetworkIsActive(privconn->networks.objs[i]))
            numInactive++;
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return numInactive;
}

static int testListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->networks.count && n < nnames ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (!virNetworkIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name))) {
            virNetworkObjUnlock(privconn->networks.objs[i]);
            goto no_memory;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError(conn);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static virNetworkPtr testNetworkCreate(virConnectPtr conn, const char *xml) {
    testConnPtr privconn = conn->privateData;
    virNetworkDefPtr def;
    virNetworkObjPtr net = NULL;
    virNetworkPtr ret = NULL;

    testDriverLock(privconn);
    if ((def = virNetworkDefParseString(conn, xml)) == NULL)
        goto cleanup;

    if ((net = virNetworkAssignDef(conn, &privconn->networks, def)) == NULL)
        goto cleanup;
    def = NULL;
    net->active = 1;

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

cleanup:
    virNetworkDefFree(def);
    if (net)
        virNetworkObjUnlock(net);
    testDriverUnlock(privconn);
    return ret;
}

static virNetworkPtr testNetworkDefine(virConnectPtr conn, const char *xml) {
    testConnPtr privconn = conn->privateData;
    virNetworkDefPtr def;
    virNetworkObjPtr net = NULL;
    virNetworkPtr ret = NULL;

    testDriverLock(privconn);
    if ((def = virNetworkDefParseString(conn, xml)) == NULL)
        goto cleanup;

    if ((net = virNetworkAssignDef(conn, &privconn->networks, def)) == NULL)
        goto cleanup;
    def = NULL;
    net->persistent = 1;

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

cleanup:
    virNetworkDefFree(def);
    if (net)
        virNetworkObjUnlock(net);
    testDriverUnlock(privconn);
    return ret;
}

static int testNetworkUndefine(virNetworkPtr network) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkIsActive(privnet)) {
        testError(network->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Network '%s' is still running"), network->name);
        goto cleanup;
    }

    virNetworkRemoveInactive(&privconn->networks,
                             privnet);
    privnet = NULL;
    ret = 0;

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    testDriverUnlock(privconn);
    return ret;
}

static int testNetworkStart(virNetworkPtr network) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);
    testDriverUnlock(privconn);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkIsActive(privnet)) {
        testError(network->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Network '%s' is already running"), network->name);
        goto cleanup;
    }

    privnet->active = 1;
    ret = 0;

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    return ret;
}

static int testNetworkDestroy(virNetworkPtr network) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privnet->active = 0;
    if (!privnet->persistent) {
        virNetworkRemoveInactive(&privconn->networks,
                                 privnet);
        privnet = NULL;
    }
    ret = 0;

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    testDriverUnlock(privconn);
    return ret;
}

static char *testNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    char *ret = NULL;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);
    testDriverUnlock(privconn);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = virNetworkDefFormat(network->conn, privnet->def);

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    return ret;
}

static char *testNetworkGetBridgeName(virNetworkPtr network) {
    testConnPtr privconn = network->conn->privateData;
    char *bridge = NULL;
    virNetworkObjPtr privnet;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);
    testDriverUnlock(privconn);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privnet->def->bridge &&
        !(bridge = strdup(privnet->def->bridge))) {
        virReportOOMError(network->conn);
        goto cleanup;
    }

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    return bridge;
}

static int testNetworkGetAutostart(virNetworkPtr network,
                                   int *autostart) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);
    testDriverUnlock(privconn);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    *autostart = privnet->autostart;
    ret = 0;

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    return ret;
}

static int testNetworkSetAutostart(virNetworkPtr network,
                                   int autostart) {
    testConnPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    testDriverLock(privconn);
    privnet = virNetworkFindByName(&privconn->networks,
                                   network->name);
    testDriverUnlock(privconn);

    if (privnet == NULL) {
        testError(network->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privnet->autostart = autostart ? 1 : 0;
    ret = 0;

cleanup:
    if (privnet)
        virNetworkObjUnlock(privnet);
    return ret;
}


/*
 * Storage Driver routines
 */

static int testStoragePoolObjSetDefaults(virConnectPtr conn,
                                         virStoragePoolObjPtr pool) {

    pool->def->capacity = defaultPoolCap;
    pool->def->allocation = defaultPoolAlloc;
    pool->def->available = defaultPoolCap - defaultPoolAlloc;

    pool->configFile = strdup("\0");
    if (!pool->configFile) {
        virReportOOMError(conn);
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
    testConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    pool = virStoragePoolObjFindByUUID(&privconn->pools, uuid);
    testDriverUnlock(privconn);

    if (pool == NULL) {
        testError (conn, VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
testStoragePoolLookupByName(virConnectPtr conn,
                            const char *name) {
    testConnPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    pool = virStoragePoolObjFindByName(&privconn->pools, name);
    testDriverUnlock(privconn);

    if (pool == NULL) {
        testError (conn, VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
testStoragePoolLookupByVolume(virStorageVolPtr vol) {
    return testStoragePoolLookupByName(vol->conn, vol->pool);
}

static int
testStorageNumPools(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    int numActive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->pools.count ; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numActive++;
    testDriverUnlock(privconn);

    return numActive;
}

static int
testStorageListPools(virConnectPtr conn,
                     char **const names,
                     int nnames) {
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->pools.count && n < nnames ; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name))) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto no_memory;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError(conn);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int
testStorageNumDefinedPools(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    int numInactive = 0, i;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->pools.count ; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numInactive++;
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return numInactive;
}

static int
testStorageListDefinedPools(virConnectPtr conn,
                            char **const names,
                            int nnames) {
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; i < privconn->pools.count && n < nnames ; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            !(names[n++] = strdup(privconn->pools.objs[i]->def->name))) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto no_memory;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError(conn);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}


static int
testStoragePoolStart(virStoragePoolPtr pool,
                     unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    privpool->active = 1;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
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
    testConnPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        goto cleanup;

    pool = virStoragePoolObjFindByUUID(&privconn->pools, def->uuid);
    if (!pool)
        pool = virStoragePoolObjFindByName(&privconn->pools, def->name);
    if (pool) {
        testError(conn, VIR_ERR_INTERNAL_ERROR,
                  "%s", _("storage pool already exists"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolObjAssignDef(conn, &privconn->pools, def)))
        goto cleanup;
    def = NULL;

    if (testStoragePoolObjSetDefaults(conn, pool) == -1) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        pool = NULL;
        goto cleanup;
    }
    pool->active = 1;

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    testDriverUnlock(privconn);
    return ret;
}

static virStoragePoolPtr
testStoragePoolDefine(virConnectPtr conn,
                      const char *xml,
                      unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    if (!(def = virStoragePoolDefParse(conn, xml, NULL)))
        goto cleanup;

    def->capacity = defaultPoolCap;
    def->allocation = defaultPoolAlloc;
    def->available = defaultPoolCap - defaultPoolAlloc;

    if (!(pool = virStoragePoolObjAssignDef(conn, &privconn->pools, def)))
        goto cleanup;
    def = NULL;

    if (testStoragePoolObjSetDefaults(conn, pool) == -1) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        pool = NULL;
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid);

cleanup:
    virStoragePoolDefFree(def);
    if (pool)
        virStoragePoolObjUnlock(pool);
    testDriverUnlock(privconn);
    return ret;
}

static int
testStoragePoolUndefine(virStoragePoolPtr pool) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    virStoragePoolObjRemove(&privconn->pools, privpool);
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    testDriverUnlock(privconn);
    return ret;
}

static int
testStoragePoolBuild(virStoragePoolPtr pool,
                     unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
testStoragePoolDestroy(virStoragePoolPtr pool) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privpool->active = 0;

    if (privpool->configFile == NULL) {
        virStoragePoolObjRemove(&privconn->pools, privpool);
        privpool = NULL;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    testDriverUnlock(privconn);
    return ret;
}


static int
testStoragePoolDelete(virStoragePoolPtr pool,
                      unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
testStoragePoolRefresh(virStoragePoolPtr pool,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
testStoragePoolGetInfo(virStoragePoolPtr pool,
                       virStoragePoolInfoPtr info) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    memset(info, 0, sizeof(virStoragePoolInfo));
    if (privpool->active)
        info->state = VIR_STORAGE_POOL_RUNNING;
    else
        info->state = VIR_STORAGE_POOL_INACTIVE;
    info->capacity = privpool->def->capacity;
    info->allocation = privpool->def->allocation;
    info->available = privpool->def->available;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
testStoragePoolDumpXML(virStoragePoolPtr pool,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    char *ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = virStoragePoolDefFormat(pool->conn, privpool->def);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
testStoragePoolGetAutostart(virStoragePoolPtr pool,
                            int *autostart) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!privpool->configFile) {
        *autostart = 0;
    } else {
        *autostart = privpool->autostart;
    }
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
testStoragePoolSetAutostart(virStoragePoolPtr pool,
                            int autostart) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!privpool->configFile) {
        testError(pool->conn, VIR_ERR_INVALID_ARG,
                  "%s", _("pool has no config file"));
        goto cleanup;
    }

    autostart = (autostart != 0);
    privpool->autostart = autostart;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
testStoragePoolNumVolumes(virStoragePoolPtr pool) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    ret = privpool->volumes.count;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
testStoragePoolListVolumes(virStoragePoolPtr pool,
                           char **const names,
                           int maxnames) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int i = 0, n = 0;

    memset(names, 0, maxnames * sizeof(*names));

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    for (i = 0 ; i < privpool->volumes.count && n < maxnames ; i++) {
        if ((names[n++] = strdup(privpool->volumes.objs[i]->name)) == NULL) {
            virReportOOMError(pool->conn);
            goto cleanup;
        }
    }

    virStoragePoolObjUnlock(privpool);
    return n;

 cleanup:
    for (n = 0 ; n < maxnames ; n++)
        VIR_FREE(names[i]);

    memset(names, 0, maxnames * sizeof(*names));
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return -1;
}


static virStorageVolPtr
testStorageVolumeLookupByName(virStoragePoolPtr pool,
                              const char *name ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, name);

    if (!privvol) {
        testError(pool->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static virStorageVolPtr
testStorageVolumeLookupByKey(virConnectPtr conn,
                             const char *key) {
    testConnPtr privconn = conn->privateData;
    unsigned int i;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->pools.count ; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByKey(privconn->pools.objs[i], key);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name,
                                       privvol->key);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    if (!ret)
        testError(conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching key '%s'"), key);

    return ret;
}

static virStorageVolPtr
testStorageVolumeLookupByPath(virConnectPtr conn,
                              const char *path) {
    testConnPtr privconn = conn->privateData;
    unsigned int i;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->pools.count ; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByPath(privconn->pools.objs[i], path);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name,
                                       privvol->key);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    if (!ret)
        testError(conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching path '%s'"), path);

    return ret;
}

static virStorageVolPtr
testStorageVolumeCreateXML(virStoragePoolPtr pool,
                           const char *xmldesc,
                           unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParse(pool->conn, privpool->def, xmldesc, NULL);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        testError(pool->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  "%s", _("storage vol already exists"));
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->allocation) >
         privpool->def->capacity) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Not enough free space in pool for volume '%s'"),
                  privvol->name);
        goto cleanup;
    }

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count+1) < 0) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    privpool->def->allocation += privvol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    privpool->volumes.objs[privpool->volumes.count++] = privvol;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);
    privvol = NULL;

cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static virStorageVolPtr
testStorageVolumeCreateXMLFrom(virStoragePoolPtr pool,
                               const char *xmldesc,
                               virStorageVolPtr clonevol,
                               unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL, origvol = NULL;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(pool->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParse(pool->conn, privpool->def, xmldesc, NULL);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        testError(pool->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  "%s", _("storage vol already exists"));
        goto cleanup;
    }

    origvol = virStorageVolDefFindByName(privpool, clonevol->name);
    if (!origvol) {
        testError(pool->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  clonevol->name);
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->allocation) >
         privpool->def->capacity) {
        testError(pool->conn, VIR_ERR_INTERNAL_ERROR,
                  _("Not enough free space in pool for volume '%s'"),
                  privvol->name);
        goto cleanup;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count+1) < 0) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError(pool->conn);
        goto cleanup;
    }

    privpool->def->allocation += privvol->allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    privpool->volumes.objs[privpool->volumes.count++] = privvol;

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key);
    privvol = NULL;

cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
testStorageVolumeDelete(virStorageVolPtr vol,
                        unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int i;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(vol->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }


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
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
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
testStorageVolumeGetInfo(virStorageVolPtr vol,
                         virStorageVolInfoPtr info) {
    testConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(vol->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    memset(info, 0, sizeof(*info));
    info->type = testStorageVolumeTypeForPool(privpool->def->type);
    info->capacity = privvol->capacity;
    info->allocation = privvol->allocation;
    ret = 0;

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
testStorageVolumeGetXMLDesc(virStorageVolPtr vol,
                            unsigned int flags ATTRIBUTE_UNUSED) {
    testConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(vol->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = virStorageVolDefFormat(vol->conn, privpool->def, privvol);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
testStorageVolumeGetPath(virStorageVolPtr vol) {
    testConnPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(vol->conn, VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(vol->conn, VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = strdup(privvol->target.path);
    if (ret == NULL)
        virReportOOMError(vol->conn);

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static virDrvOpenStatus testDevMonOpen(virConnectPtr conn,
                                       virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                       int flags ATTRIBUTE_UNUSED) {
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->devMonPrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testDevMonClose(virConnectPtr conn) {
    conn->devMonPrivateData = NULL;
    return 0;
}


static int
testDomainEventRegister (virConnectPtr conn,
                         virConnectDomainEventCallback callback,
                         void *opaque,
                         virFreeCallback freecb)
{
    testConnPtr driver = conn->privateData;
    int ret;

    testDriverLock(driver);
    ret = virDomainEventCallbackListAdd(conn, driver->domainEventCallbacks,
                                        callback, opaque, freecb);
    testDriverUnlock(driver);

    return ret;
}

static int
testDomainEventDeregister (virConnectPtr conn,
                           virConnectDomainEventCallback callback)
{
    testConnPtr driver = conn->privateData;
    int ret;

    testDriverLock(driver);
    if (driver->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDelete(conn, driver->domainEventCallbacks,
                                                   callback);
    else
        ret = virDomainEventCallbackListRemove(conn, driver->domainEventCallbacks,
                                               callback);
    testDriverUnlock(driver);

    return ret;
}

static void testDomainEventDispatchFunc(virConnectPtr conn,
                                        virDomainEventPtr event,
                                        virConnectDomainEventCallback cb,
                                        void *cbopaque,
                                        void *opaque)
{
    testConnPtr driver = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    testDriverUnlock(driver);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    testDriverLock(driver);
}

static void testDomainEventFlush(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    testConnPtr driver = opaque;
    virDomainEventQueue tempQueue;

    testDriverLock(driver);

    driver->domainEventDispatching = 1;

    /* Copy the queue, so we're reentrant safe */
    tempQueue.count = driver->domainEventQueue->count;
    tempQueue.events = driver->domainEventQueue->events;
    driver->domainEventQueue->count = 0;
    driver->domainEventQueue->events = NULL;

    virEventUpdateTimeout(driver->domainEventTimer, -1);
    virDomainEventQueueDispatch(&tempQueue,
                                driver->domainEventCallbacks,
                                testDomainEventDispatchFunc,
                                driver);

    /* Purge any deleted callbacks */
    virDomainEventCallbackListPurgeMarked(driver->domainEventCallbacks);

    driver->domainEventDispatching = 0;
    testDriverUnlock(driver);
}


/* driver must be locked before calling */
static void testDomainEventQueue(testConnPtr driver,
                                 virDomainEventPtr event)
{
    if (driver->domainEventTimer < 0) {
        virDomainEventFree(event);
        return;
    }

    if (virDomainEventQueuePush(driver->domainEventQueue,
                                event) < 0)
        virDomainEventFree(event);

    if (driver->domainEventQueue->count == 1)
        virEventUpdateTimeout(driver->domainEventTimer, 0);
}


static virDriver testDriver = {
    VIR_DRV_TEST,
    "Test",
    testOpen, /* open */
    testClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    testGetVersion, /* version */
    testGetHostname, /* getHostname */
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
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    testDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXmlFromNative */
    NULL, /* domainXmlToNative */
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
    testDomainEventRegister, /* domainEventRegister */
    testDomainEventDeregister, /* domainEventDeregister */
    NULL, /* domainMigratePrepare2 */
    NULL, /* domainMigrateFinish2 */
    NULL, /* nodeDeviceDettach */
    NULL, /* nodeDeviceReAttach */
    NULL, /* nodeDeviceReset */
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
    .volCreateXMLFrom = testStorageVolumeCreateXMLFrom,
    .volDelete = testStorageVolumeDelete,
    .volGetInfo = testStorageVolumeGetInfo,
    .volGetXMLDesc = testStorageVolumeGetXMLDesc,
    .volGetPath = testStorageVolumeGetPath,
};

static virDeviceMonitor testDevMonitor = {
    .name = "Test",
    .open = testDevMonOpen,
    .close = testDevMonClose,
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
    if (virRegisterDeviceMonitor(&testDevMonitor) < 0)
        return -1;

    return 0;
}
