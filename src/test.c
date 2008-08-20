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

#include "test.h"
#include "buf.h"
#include "util.h"
#include "uuid.h"
#include "capabilities.h"
#include "memory.h"
#include "network_conf.h"
#include "domain_conf.h"
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
    virDomainObjPtr domains;
    virNetworkObjPtr networks;
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
        if ((privdom = virDomainFindByName(privconn->domains,           \
                                            (dom)->name)) == NULL) {    \
            testError((dom)->conn, (dom), NULL, VIR_ERR_INVALID_ARG,    \
                      __FUNCTION__);                                    \
            return (ret);                                               \
        }                                                               \
    } while (0)

#define GET_NETWORK(net, ret)                                           \
    testConnPtr privconn;                                               \
    virNetworkObjPtr privnet;                                           \
                                                                        \
    privconn = (testConnPtr)net->conn->privateData;                     \
    do {                                                                \
        if ((privnet = virNetworkFindByName(privconn->networks,         \
                                            (net)->name)) == NULL) {    \
            testError((net)->conn, NULL, (net), VIR_ERR_INVALID_ARG,    \
                      __FUNCTION__);                                    \
            return (ret);                                               \
        }                                                               \
    } while (0)

#define GET_CONNECTION(conn)                                            \
    testConnPtr privconn;                                               \
                                                                        \
    privconn = (testConnPtr)conn->privateData;


static void
testError(virConnectPtr con,
          virDomainPtr dom,
          virNetworkPtr net,
          virErrorNumber error,
          const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(con, dom, net, VIR_FROM_TEST, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info, 0);
}

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
    testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
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


static int testOpenDefault(virConnectPtr conn) {
    int u;
    struct timeval tv;
    testConnPtr privconn;
    virDomainDefPtr domdef = NULL;
    virDomainObjPtr domobj = NULL;
    virNetworkDefPtr netdef = NULL;
    virNetworkObjPtr netobj = NULL;

    if (VIR_ALLOC(privconn) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = privconn;

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
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

    return VIR_DRV_OPEN_SUCCESS;

error:
    virDomainObjFree(privconn->domains);
    virNetworkObjFree(privconn->networks);
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
    xmlNodePtr *domains = NULL, *networks = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virNodeInfoPtr nodeInfo;
    virNetworkObjPtr net;
    virDomainObjPtr dom;
    testConnPtr privconn;
    if (VIR_ALLOC(privconn) < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }
    conn->privateData = privconn;

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if ((fd = open(file, O_RDONLY)) < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("loading host definition file"));
        goto error;
    }

    if (!(xml = xmlReadFd(fd, file, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("host"));
        goto error;
    }
    close(fd);
    fd = -1;

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "node"))) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("creating xpath context"));
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
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu numa nodes"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu sockets"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu cores"));
        goto error;
    }

    ret = virXPathLong(conn, "string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu threads"));
        goto error;
    }

    nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
    ret = virXPathLong(conn, "string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus) {
            nodeInfo->cpus = l;
        }
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node active cpu"));
        goto error;
    }
    ret = virXPathLong(conn, "string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu mhz"));
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
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node memory"));
        goto error;
    }

    ret = virXPathNodeSet(conn, "/node/domain", ctxt, &domains);
    if (ret < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node domain list"));
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        virDomainDefPtr def;
        char *relFile = virXMLPropString(domains[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving domain filename"));
                goto error;
            }
            def = virDomainDefParseFile(conn, privconn->caps, absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virDomainDefParseNode(conn, privconn->caps, xml, domains[i])) == NULL)
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
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node network list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virNetworkDefPtr def;
        char *relFile = virXMLPropString(networks[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving network filename"));
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

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return (0);

 error:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(domains);
    VIR_FREE(networks);
    if (fd != -1)
        close(fd);
    dom = privconn->domains;
    while (dom) {
        virDomainObjPtr tmp = dom->next;
        virDomainObjFree(dom);
        dom = tmp;
    }
    net = privconn->networks;
    while (net) {
        virNetworkObjPtr tmp = net->next;
        virNetworkObjFree(net);
        net = tmp;
    }
    VIR_FREE(privconn);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}


static int testOpen(virConnectPtr conn,
                    xmlURIPtr uri,
                    virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                    int flags ATTRIBUTE_UNUSED)
{
    int ret;

    if (!uri)
        return VIR_DRV_OPEN_DECLINED;

    if (!uri->scheme || STRNEQ(uri->scheme, "test"))
        return VIR_DRV_OPEN_DECLINED;

    /* Remote driver should handle these. */
    if (uri->server)
        return VIR_DRV_OPEN_DECLINED;

    if (uri->server)
        return VIR_DRV_OPEN_DECLINED;

    /* From this point on, the connection is for us. */
    if (!uri->path
        || uri->path[0] == '\0'
        || (uri->path[0] == '/' && uri->path[1] == '\0')) {
        testError (NULL, NULL, NULL, VIR_ERR_INVALID_ARG,
                   _("testOpen: supply a path or use test:///default"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STREQ(uri->path, "/default"))
        ret = testOpenDefault(conn);
    else
        ret = testOpenFromFile(conn,
                               uri->path);

    return (ret);
}

static int testClose(virConnectPtr conn)
{
    virDomainObjPtr dom;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);
    virCapabilitiesFree(privconn->caps);
    dom = privconn->domains;
    while (dom) {
        virDomainObjPtr tmp = dom->next;
        virDomainObjFree(dom);
        dom = tmp;
    }
    net = privconn->networks;
    while (net) {
        virNetworkObjPtr tmp = net->next;
        virNetworkObjFree(net);
        net = tmp;
    }
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
        testError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    str = strdup (hostname);
    if (str == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    return str;
}

static char * testGetURI (virConnectPtr conn)
{
    char *uri;
    GET_CONNECTION(conn);

    if (asprintf (&uri, "test://%s", privconn->path) == -1) {
        testError (conn, NULL, NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    return uri;
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
        testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return xml;
}

static int testNumOfDomains(virConnectPtr conn)
{
    int numActive = 0;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    dom = privconn->domains;
    while (dom) {
        if (virDomainIsActive(dom))
            numActive++;
        dom = dom->next;
    }
    return numActive;
}

static virDomainPtr
testDomainCreateLinux(virConnectPtr conn, const char *xml,
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

    if ((dom = virDomainFindByID(privconn->domains, id)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
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

    if ((dom = virDomainFindByUUID(privconn->domains, uuid)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
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

    if ((dom = virDomainFindByName(privconn->domains, name)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
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
    int n = 0;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    dom = privconn->domains;
    while (dom && n < maxids) {
        if (virDomainIsActive(dom))
            ids[n++] = dom->def->id;
        dom = dom->next;
    }
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
        testError(domain->conn, domain, NULL,
                  VIR_ERR_INTERNAL_ERROR, _("domain not paused"));
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
        testError(domain->conn, domain, NULL,
                  VIR_ERR_INTERNAL_ERROR, _("domain not running"));
        return -1;
    }

    privdom->state = VIR_DOMAIN_PAUSED;
    return (0);
}

static int testShutdownDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR, "domain not running");
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
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
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
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot allocate space for metadata"));
        return (-1);
    }

    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot save domain"));
        return (-1);
    }
    len = strlen(xml);
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot write header"));
        close(fd);
        return (-1);
    }
    if (safewrite(fd, (char*)&len, sizeof(len)) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot write metadata length"));
        close(fd);
        return (-1);
    }
    if (safewrite(fd, xml, len) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot write metadata"));
        VIR_FREE(xml);
        close(fd);
        return (-1);
    }
    VIR_FREE(xml);
    if (close(fd) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot save domain data"));
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
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot read domain image"));
        return (-1);
    }
    if (read(fd, magic, sizeof(magic)) != sizeof(magic)) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("incomplete save header"));
        close(fd);
        return (-1);
    }
    if (memcmp(magic, TEST_SAVE_MAGIC, sizeof(magic))) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("mismatched header magic"));
        close(fd);
        return (-1);
    }
    if (read(fd, (char*)&len, sizeof(len)) != sizeof(len)) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("failed to read metadata length"));
        close(fd);
        return (-1);
    }
    if (len < 1 || len > 8192) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("length of metadata out of range"));
        close(fd);
        return (-1);
    }
    if (VIR_ALLOC_N(xml, len+1) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "xml");
        close(fd);
        return (-1);
    }
    if (read(fd, xml, len) != len) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("incomplete metdata"));
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
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot save domain core"));
        return (-1);
    }
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot write header"));
        close(fd);
        return (-1);
    }
    if (close(fd) < 0) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("cannot save domain data"));
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
        testError(dom->conn, dom, NULL, VIR_ERR_NO_MEMORY, NULL);
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
        testError(domain->conn, domain, NULL,
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
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
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
    int numInactive = 0;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    dom = privconn->domains;
    while (dom) {
        if (!virDomainIsActive(dom))
            numInactive++;
        dom = dom->next;
    }
    return numInactive;
}

static int testListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames) {
    int n = 0;
    virDomainObjPtr dom;
    GET_CONNECTION(conn);

    dom = privconn->domains;
    memset(names, 0, sizeof(*names)*maxnames);
    while (dom && n < maxnames) {
        if (!virDomainIsActive(dom) &&
            !(names[n++] = strdup(dom->def->name)))
            goto no_memory;
        dom = dom->next;
    }
    return n;

no_memory:
    testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
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
        testError(conn, NULL, NULL, VIR_ERR_INVALID_ARG,
                  _("Range exceeds available cells"));
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
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is already running"));
        return (-1);
    }

    domain->id = privdom->def->id = privconn->nextDomID++;
    privdom->state = VIR_DOMAIN_RUNNING;

    return (0);
}

static int testDomainUndefine(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is still running"));
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
        testError(domain->conn, domain, NULL, VIR_ERR_NO_MEMORY, "schedular");
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
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, "nparams");
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
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, "nparams");
        return (-1);
    }
    if (STRNEQ(params[0].field, "weight")) {
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, "field");
        return (-1);
    }
    if (params[0].type != VIR_DOMAIN_SCHED_FIELD_UINT) {
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, "type");
        return (-1);
    }
    /* XXX */
    /*privdom->weight = params[0].value.ui;*/
    return 0;
}

static virDrvOpenStatus testOpenNetwork(virConnectPtr conn,
                                        xmlURIPtr uri ATTRIBUTE_UNUSED,
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

    if ((net = virNetworkFindByUUID(privconn->networks, uuid)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, net->def->name, net->def->uuid);
}

static virNetworkPtr testLookupNetworkByName(virConnectPtr conn,
                                             const char *name)
{
    virNetworkObjPtr net = NULL;
    GET_CONNECTION(conn);

    if ((net = virNetworkFindByName(privconn->networks, name)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, net->def->name, net->def->uuid);
}


static int testNumNetworks(virConnectPtr conn) {
    int numActive = 0;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    net = privconn->networks;
    while (net) {
        if (virNetworkIsActive(net))
            numActive++;
        net = net->next;
    }
    return numActive;
}

static int testListNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    net = privconn->networks;
    memset(names, 0, sizeof(*names)*nnames);
    while (net && n < nnames) {
        if (virNetworkIsActive(net) &&
            !(names[n++] = strdup(net->def->name)))
            goto no_memory;
        net = net->next;
    }
    return n;

no_memory:
    testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    return (-1);
}

static int testNumDefinedNetworks(virConnectPtr conn) {
    int numInactive = 0;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    net = privconn->networks;
    while (net) {
        if (!virNetworkIsActive(net))
            numInactive++;
        net = net->next;
    }
    return numInactive;
}

static int testListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0;
    virNetworkObjPtr net;
    GET_CONNECTION(conn);

    net = privconn->networks;
    memset(names, 0, sizeof(*names)*nnames);
    while (net && n < nnames) {
        if (!virNetworkIsActive(net) &&
            !(names[n++] = strdup(net->def->name)))
            goto no_memory;
        net = net->next;
    }
    return n;

no_memory:
    testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
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
        testError(network->conn, NULL, network, VIR_ERR_INTERNAL_ERROR,
                  _("Network is still running"));
        return (-1);
    }

    virNetworkRemoveInactive(&privconn->networks,
                             privnet);

    return (0);
}

static int testNetworkStart(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (virNetworkIsActive(privnet)) {
        testError(network->conn, NULL, network, VIR_ERR_INTERNAL_ERROR,
                  _("Network is already running"));
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
        testError(network->conn, NULL, network, VIR_ERR_NO_MEMORY, "network");
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

static virDrvOpenStatus testStorageOpen(virConnectPtr conn,
                                        xmlURIPtr uri ATTRIBUTE_UNUSED,
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


static virDriver testDriver = {
    VIR_DRV_TEST,
    "Test",
    LIBVIR_VERSION_NUMBER,
    NULL, /* probe */
    testOpen, /* open */
    testClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    testGetVersion, /* version */
    testGetHostname, /* hostname */
    testGetURI, /* URI */
    testGetMaxVCPUs, /* getMaxVcpus */
    testNodeGetInfo, /* nodeGetInfo */
    testGetCapabilities, /* getCapabilities */
    testListDomains, /* listDomains */
    testNumOfDomains, /* numOfDomains */
    testDomainCreateLinux, /* domainCreateLinux */
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
