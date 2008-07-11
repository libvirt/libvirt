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

#ifdef WITH_TEST

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "socketcompat.h"

#include "internal.h"
#include "test.h"
#include "xml.h"
#include "buf.h"
#include "util.h"
#include "uuid.h"
#include "capabilities.h"
#include "memory.h"
#include "network_conf.h"

/* Flags that determine the action to take on a shutdown or crash of a domain
 */
typedef enum {
     VIR_DOMAIN_DESTROY	= 1, /* destroy the domain */
     VIR_DOMAIN_RESTART	= 2, /* restart the domain */
     VIR_DOMAIN_PRESERVE= 3, /* keep as is, need manual destroy, for debug */
     VIR_DOMAIN_RENAME_RESTART= 4/* restart under an new unique name */
} virDomainRestart;

struct _testDev {
    char name[20];
    int mode;
};
typedef struct _testDev testDev;
typedef struct _testDev *testDevPtr;

#define MAX_DEVICES 10

struct _testDom {
    int active;
    int config;
    int id;
    char name[20];
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainInfo info;
    unsigned int maxVCPUs;
    virDomainRestart onRestart; /* What to do at end of current shutdown procedure */
    virDomainRestart onReboot;
    virDomainRestart onPoweroff;
    virDomainRestart onCrash;
    int numDevices;
    testDev devices[MAX_DEVICES];
    int autostart;
    unsigned int weight;
};
typedef struct _testDom testDom;
typedef struct _testDom *testDomPtr;

#define MAX_DOMAINS 20
#define MAX_NETWORKS 20
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
    virNodeInfo nodeInfo;
    int numDomains;
    testDom domains[MAX_DOMAINS];
    virNetworkObjPtr networks;
    int numCells;
    testCell cells[MAX_CELLS];
};
typedef struct _testConn testConn;
typedef struct _testConn *testConnPtr;

#define TEST_MODEL "i686"
#define TEST_MODEL_WORDSIZE 32

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
    int domidx;                                                         \
    testConnPtr privconn;                                               \
    testDomPtr privdom;                                                 \
                                                                        \
    privconn = (testConnPtr)dom->conn->privateData;                     \
    if ((domidx = getDomainIndex(dom)) < 0) {                           \
        testError((dom)->conn, (dom), NULL, VIR_ERR_INVALID_ARG,        \
                  __FUNCTION__);                                        \
        return (ret);                                                   \
    }                                                                   \
    privdom = &privconn->domains[domidx];

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

#define GET_CONNECTION(conn, ret)                                       \
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

static int testRestartStringToFlag(const char *str) {
    if (STREQ(str, "restart")) {
        return VIR_DOMAIN_RESTART;
    } else if (STREQ(str, "destroy")) {
        return VIR_DOMAIN_DESTROY;
    } else if (STREQ(str, "preserve")) {
        return VIR_DOMAIN_PRESERVE;
    } else if (STREQ(str, "rename-restart")) {
        return VIR_DOMAIN_RENAME_RESTART;
    } else {
        return (0);
    }
}

static const char *testRestartFlagToString(int flag) {
    switch (flag) {
    case VIR_DOMAIN_RESTART:
        return "restart";
    case VIR_DOMAIN_DESTROY:
        return "destroy";
    case VIR_DOMAIN_PRESERVE:
        return "preserve";
    case VIR_DOMAIN_RENAME_RESTART:
        return "rename-restart";
    }
    return (NULL);
}


static int testLoadDomain(virConnectPtr conn,
                          int domid,
                          xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *name = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    struct timeval tv;
    unsigned long memory = 0;
    unsigned long maxMem = 0;
    int nrVirtCpu;
    char *str;
    int handle = -1, i, ret;
    long l;
    virDomainRestart onReboot = VIR_DOMAIN_RESTART;
    virDomainRestart onPoweroff = VIR_DOMAIN_DESTROY;
    virDomainRestart onCrash = VIR_DOMAIN_RENAME_RESTART;
    GET_CONNECTION(conn, -1);

    if (gettimeofday(&tv, NULL) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return (-1);
    }

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("creating xpath context"));
        goto error;
    }

    name = virXPathString("string(/domain/name[1])", ctxt);
    if (name == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("domain name"));
        goto error;
    }

    str = virXPathString("string(/domain/uuid[1])", ctxt);
    if (str == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
        goto error;
    }
    if (virUUIDParse(str, uuid) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
        goto error;
    }
    VIR_FREE(str);


    ret = virXPathLong("string(/domain/memory[1])", ctxt, &l);
    if (ret != 0) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain memory"));
        goto error;
    }
    maxMem = l;

    ret = virXPathLong("string(/domain/currentMemory[1])", ctxt, &l);
    if (ret == -1) {
        memory = maxMem;
    } else if (ret == -2) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain current memory"));
        goto error;
    } else {
        memory = l;
    }

    ret = virXPathLong("string(/domain/vcpu[1])", ctxt, &l);
    if (ret == -1) {
        nrVirtCpu = 1;
    } else if (ret == -2) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain vcpus"));
        goto error;
    } else {
        nrVirtCpu = l;
    }

    str = virXPathString("string(/domain/on_reboot[1])", ctxt);
    if (str != NULL) {
        if (!(onReboot = testRestartStringToFlag(str))) {
            testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain reboot behaviour"));
            VIR_FREE(str);
            goto error;
        }
        VIR_FREE(str);
    }

    str = virXPathString("string(/domain/on_poweroff[1])", ctxt);
    if (str != NULL) {
        if (!(onPoweroff = testRestartStringToFlag(str))) {
            testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain poweroff behaviour"));
            VIR_FREE(str);
            goto error;
        }
        VIR_FREE(str);
    }

    str = virXPathString("string(/domain/on_crash[1])", ctxt);
    if (str != NULL) {
        if (!(onCrash = testRestartStringToFlag(str))) {
            testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain crash behaviour"));
            VIR_FREE(str);
            goto error;
        }
        VIR_FREE(str);
    }

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!privconn->domains[i].active) {
            handle = i;
            break;
        }
    }
    if (handle < 0)
        goto error;

    privconn->domains[handle].active = 1;
    privconn->domains[handle].id = domid;
    strncpy(privconn->domains[handle].name, name, sizeof(privconn->domains[handle].name)-1);
    privconn->domains[handle].name[sizeof(privconn->domains[handle].name)-1] = '\0';
    VIR_FREE(name);
    name = NULL;

    if (memory > maxMem)
        memory = maxMem;

    memmove(privconn->domains[handle].uuid, uuid, VIR_UUID_BUFLEN);
    privconn->domains[handle].info.maxMem = maxMem;
    privconn->domains[handle].info.memory = memory;
    privconn->domains[handle].info.state = domid < 0 ? VIR_DOMAIN_SHUTOFF : VIR_DOMAIN_RUNNING;
    privconn->domains[handle].info.nrVirtCpu = nrVirtCpu;
    privconn->domains[handle].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    privconn->domains[handle].maxVCPUs = nrVirtCpu;

    privconn->domains[handle].onReboot = onReboot;
    privconn->domains[handle].onPoweroff = onPoweroff;
    privconn->domains[handle].onCrash = onCrash;

    xmlXPathFreeContext(ctxt);
    return (handle);

 error:
    xmlXPathFreeContext(ctxt);
    VIR_FREE(name);
    return (-1);
}

static int testLoadDomainFromDoc(virConnectPtr conn,
                                 int domid,
                                 const char *doc) {
    int ret;
    xmlDocPtr xml;
    if (!(xml = xmlReadDoc(BAD_CAST doc, "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        return (-1);
    }

    ret = testLoadDomain(conn, domid, xml);

    xmlFreeDoc(xml);

    return (ret);
}


static int testLoadDomainFromFile(virConnectPtr conn,
                                  int domid,
                                  const char *filename) {
    int ret, fd;
    xmlDocPtr xml;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("load domain definition file"));
        return (-1);
    }

    if (!(xml = xmlReadFd(fd, filename, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        return (-1);
    }

    ret = testLoadDomain(conn, domid, xml);

    xmlFreeDoc(xml);
    close(fd);

    return (ret);
}


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
    virNetworkDefPtr netdef;
    virNetworkObjPtr netobj;

    if (VIR_ALLOC(privconn) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return VIR_DRV_OPEN_ERROR;
    }

    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    strcpy(privconn->path, "/default");
    privconn->nextDomID = 1;
    privconn->numDomains = 1;
    privconn->domains[0].active = 1;
    privconn->domains[0].config = 1;
    privconn->domains[0].id = privconn->nextDomID++;
    privconn->domains[0].onReboot = VIR_DOMAIN_RESTART;
    privconn->domains[0].onCrash = VIR_DOMAIN_RESTART;
    privconn->domains[0].onPoweroff = VIR_DOMAIN_DESTROY;
    strcpy(privconn->domains[0].name, "test");
    for (u = 0 ; u < VIR_UUID_BUFLEN ; u++) {
        privconn->domains[0].uuid[u] = (u * 75)%255;
    }
    privconn->domains[0].info.maxMem = 8192 * 1024;
    privconn->domains[0].info.memory = 2048 * 1024;
    privconn->domains[0].info.state = VIR_DOMAIN_RUNNING;
    privconn->domains[0].info.nrVirtCpu = 2;
    privconn->domains[0].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));


    if (!(netdef = virNetworkDefParseString(conn, defaultNetworkXML))) {
        return VIR_DRV_OPEN_ERROR;
    }
    if (!(netobj = virNetworkAssignDef(conn, &privconn->networks, netdef))) {
        virNetworkDefFree(netdef);
        return VIR_DRV_OPEN_ERROR;
    }
    netobj->active = 1;
    netobj->persistent = 1;

    // Numa setup
    privconn->numCells = 2;
    for (u = 0; u < 2; ++u) {
        privconn->cells[u].numCpus = 8;
        privconn->cells[u].mem = (u + 1) * 2048 * 1024;
    }
    for (u = 0 ; u < 16 ; u++) {
        privconn->cells[u % 2].cpus[(u / 2)] = u;
    }

    conn->privateData = privconn;
    return (VIR_DRV_OPEN_SUCCESS);
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
    xmlNodePtr *domains, *networks = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virNodeInfoPtr nodeInfo;
    testConnPtr privconn;
    if (VIR_ALLOC(privconn) < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }

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


    conn->privateData = privconn;
    privconn->nextDomID = 1;
    privconn->numDomains = 0;
    privconn->numCells = 0;
    strncpy(privconn->path, file, PATH_MAX-1);
    privconn->path[PATH_MAX-1] = '\0';
    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    nodeInfo = &privconn->nodeInfo;
    ret = virXPathLong("string(/node/cpu/nodes[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->nodes = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu numa nodes"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu sockets"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu cores"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu threads"));
        goto error;
    }

    nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
    ret = virXPathLong("string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus) {
            nodeInfo->cpus = l;
        }
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node active cpu"));
        goto error;
    }
    ret = virXPathLong("string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node cpu mhz"));
        goto error;
    }

    str = virXPathString("string(/node/cpu/model[1])", ctxt);
    if (str != NULL) {
        strncpy(nodeInfo->model, str, sizeof(nodeInfo->model)-1);
        nodeInfo->model[sizeof(nodeInfo->model)-1] = '\0';
        VIR_FREE(str);
    }

    ret = virXPathLong("string(/node/memory[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->memory = l;
    } else if (ret == -2) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node memory"));
        goto error;
    }

    ret = virXPathNodeSet("/node/domain", ctxt, &domains);
    if (ret < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node domain list"));
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        xmlChar *domFile = xmlGetProp(domains[i], BAD_CAST "file");
        char *absFile = testBuildFilename(file, (const char *)domFile);
        int domid = privconn->nextDomID++, handle;
        VIR_FREE(domFile);
        if (!absFile) {
            testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving domain filename"));
            goto error;
        }
        if ((handle = testLoadDomainFromFile(conn, domid, absFile)) < 0) {
            VIR_FREE(absFile);
            goto error;
        }
        privconn->domains[handle].config = 1;
        VIR_FREE(absFile);
        privconn->numDomains++;
    }
    if (domains != NULL) {
        VIR_FREE(domains);
        domains = NULL;
    }


    ret = virXPathNodeSet("/node/network", ctxt, &networks);
    if (ret < 0) {
        testError(NULL, NULL, NULL, VIR_ERR_XML_ERROR, _("node network list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virNetworkDefPtr def;
        virNetworkObjPtr net;
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
    if (networks != NULL) {
        VIR_FREE(networks);
        networks = NULL;
    }

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return (0);

 error:
    xmlXPathFreeContext(ctxt);
    VIR_FREE(domains);
    VIR_FREE(networks);
    if (xml)
        xmlFreeDoc(xml);
    if (fd != -1)
        close(fd);
    VIR_FREE(privconn);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}

static int getDomainIndex(virDomainPtr domain) {
    int i;
    GET_CONNECTION(domain->conn, -1);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (domain->id >= 0) {
            if (domain->id == privconn->domains[i].id)
                return (i);
        } else {
            if (STREQ(domain->name, privconn->domains[i].name))
                return (i);
        }
    }
    return (-1);
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
    GET_CONNECTION(conn, -1);
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
    GET_CONNECTION(conn, NULL);

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
    GET_CONNECTION(conn, -1);
    memcpy(info, &privconn->nodeInfo, sizeof(virNodeInfo));
    return (0);
}

static char *testGetCapabilities (virConnectPtr conn)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;
    char *xml;
    const char *guest_types[] = { "hvm", "xen" };
    int i;

    GET_CONNECTION(conn, -1);

    if ((caps = virCapabilitiesNew(TEST_MODEL, 0, 0)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddHostFeature(caps, "pae") < 0)
        goto no_memory;
    if (virCapabilitiesAddHostFeature(caps ,"nonpae") < 0)
        goto no_memory;

    for (i = 0; i < privconn->numCells; ++i) {
        if (virCapabilitiesAddHostNUMACell(caps, i, privconn->cells[i].numCpus,
                                           privconn->cells[i].cpus) < 0)
            goto no_memory;
    }

    for (i = 0; i < (sizeof(guest_types)/sizeof(guest_types[0])); ++i) {

        if ((guest = virCapabilitiesAddGuest(caps,
                                             guest_types[i],
                                             TEST_MODEL,
                                             TEST_MODEL_WORDSIZE,
                                             NULL,
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

    if ((xml = virCapabilitiesFormatXML(caps)) == NULL)
        goto no_memory;

    virCapabilitiesFree(caps);

    return xml;

 no_memory:
    virCapabilitiesFree(caps);
    testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
    return NULL;
}

static int testNumOfDomains(virConnectPtr conn)
{
    int numActive = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!privconn->domains[i].active ||
            privconn->domains[i].info.state == VIR_DOMAIN_SHUTOFF)
            continue;
        numActive++;
    }
    return (numActive);
}

static virDomainPtr
testDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    int domid, handle = -1;
    virDomainPtr dom;
    GET_CONNECTION(conn, NULL);

    if (xmlDesc == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (privconn->numDomains == MAX_DOMAINS) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many domains"));
        return (NULL);
    }

    domid = privconn->nextDomID++;
    if ((handle = testLoadDomainFromDoc(conn, domid, xmlDesc)) < 0)
        return (NULL);
    privconn->domains[handle].config = 0;

    dom = virGetDomain(conn, privconn->domains[handle].name, privconn->domains[handle].uuid);
    if (dom == NULL) return NULL;
    privconn->numDomains++;
    return (dom);
}


static virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                         int id)
{
    virDomainPtr dom;
    int i, idx = -1;
    GET_CONNECTION(conn, NULL);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (privconn->domains[i].active &&
            privconn->domains[i].id == id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return(NULL);
    }

    dom = virGetDomain(conn, privconn->domains[idx].name, privconn->domains[idx].uuid);
    if (dom == NULL) return NULL;
    dom->id = id;
    return (dom);
}

static virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    virDomainPtr dom;
    int i, idx = -1;
    GET_CONNECTION(conn, NULL);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (privconn->domains[i].active &&
            memcmp(uuid, privconn->domains[i].uuid, VIR_UUID_BUFLEN) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, privconn->domains[idx].name, privconn->domains[idx].uuid);
    if (dom == NULL) return NULL;
    dom->id = privconn->domains[idx].id;

    return dom;
}

static virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                           const char *name)
{
    virDomainPtr dom;
    int i, idx = -1;
    GET_CONNECTION(conn, NULL);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (privconn->domains[i].active &&
            STREQ(name, privconn->domains[i].name)) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        testError (conn, NULL, NULL, VIR_ERR_NO_DOMAIN, NULL);
        return NULL;
    }

    dom = virGetDomain(conn, privconn->domains[idx].name, privconn->domains[idx].uuid);
    if (dom == NULL) return NULL;
    dom->id = privconn->domains[idx].id;

    return dom;
}

static int testListDomains (virConnectPtr conn,
                            int *ids,
                            int maxids)
{
    int n, i;
    GET_CONNECTION(conn, -1);

    for (i = 0, n = 0 ; i < MAX_DOMAINS && n < maxids ; i++) {
        if (privconn->domains[i].active &&
            privconn->domains[i].info.state != VIR_DOMAIN_SHUTOFF) {
            ids[n++] = privconn->domains[i].id;
        }
    }
    return (n);
}

static int testDestroyDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->config) {
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        privdom->id = -1;
        domain->id = -1;
    } else {
        privdom->active = 0;
    }
    return (0);
}

static int testResumeDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->info.state != VIR_DOMAIN_PAUSED) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR, "domain not paused");
        return -1;
    }

    privdom->info.state = VIR_DOMAIN_RUNNING;
    return (0);
}

static int testPauseDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->info.state == VIR_DOMAIN_SHUTOFF ||
        privdom->info.state == VIR_DOMAIN_PAUSED) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR, "domain not running");
        return -1;
    }

    privdom->info.state = VIR_DOMAIN_PAUSED;
    return (0);
}

static int testShutdownDomain (virDomainPtr domain)
{
    GET_DOMAIN(domain, -1);

    if (privdom->info.state == VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR, "domain not running");
        return -1;
    }

    privdom->info.state = VIR_DOMAIN_SHUTOFF;
    domain->id = -1;
    privdom->id = -1;

    return (0);
}

/* Similar behaviour as shutdown */
static int testRebootDomain (virDomainPtr domain, virDomainRestart action)
{
    GET_DOMAIN(domain, -1);

    if (!action)
        action = VIR_DOMAIN_RESTART;

    privdom->info.state = VIR_DOMAIN_SHUTDOWN;
    switch (action) {
    case VIR_DOMAIN_DESTROY:
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->id = -1;
        break;

    case VIR_DOMAIN_RESTART:
        privdom->info.state = VIR_DOMAIN_RUNNING;
        break;

    case VIR_DOMAIN_PRESERVE:
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->id = -1;
        break;

    case VIR_DOMAIN_RENAME_RESTART:
        privdom->info.state = VIR_DOMAIN_RUNNING;
        break;

    default:
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        domain->id = -1;
        privdom->id = -1;
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

    if (privdom->info.state == VIR_DOMAIN_SHUTOFF) {
        privdom->info.cpuTime = 0;
        privdom->info.memory = 0;
    } else {
        privdom->info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    }
    memcpy(info, &privdom->info, sizeof(virDomainInfo));
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
    if (privdom->config) {
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        privdom->id = -1;
        domain->id = -1;
    } else {
        privdom->active = 0;
    }
    return 0;
}

static int testDomainRestore(virConnectPtr conn,
                             const char *path)
{
    char *xml;
    char magic[15];
    int fd, len, ret, domid;
    GET_CONNECTION(conn, -1);

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
    domid = privconn->nextDomID++;
    ret = testLoadDomainFromDoc(conn, domid, xml);
    VIR_FREE(xml);
    return ret < 0 ? -1 : 0;
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
    if (privdom->config) {
        privdom->info.state = VIR_DOMAIN_SHUTOFF;
        privdom->id = -1;
        domain->id = -1;
    } else {
        privdom->active = 0;
    }
    return 0;
}

static char *testGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED) {
    return strdup("linux");
}

static unsigned long testGetMaxMemory(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    return privdom->info.maxMem;
}

static int testSetMaxMemory(virDomainPtr domain,
                            unsigned long memory)
{
    GET_DOMAIN(domain, -1);

    /* XXX validate not over host memory wrt to other domains */
    privdom->info.maxMem = memory;
    return (0);
}

static int testSetMemory(virDomainPtr domain,
                         unsigned long memory)
{
    GET_DOMAIN(domain, -1);

    if (memory > privdom->info.maxMem) {
        testError(domain->conn, domain, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    privdom->info.memory = memory;
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

    privdom->info.nrVirtCpu = nrCpus;
    return (0);
}

static char *testDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    GET_DOMAIN(domain, NULL);

    virBufferVSprintf(&buf, "<domain type='test' id='%d'>\n", domain->id);
    virBufferVSprintf(&buf, "  <name>%s</name>\n", domain->name);
    uuid = domain->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);
    virBufferVSprintf(&buf, "  <memory>%lu</memory>\n", privdom->info.maxMem);
    virBufferVSprintf(&buf, "  <vcpu>%d</vcpu>\n", privdom->info.nrVirtCpu);
    virBufferVSprintf(&buf, "  <on_reboot>%s</on_reboot>\n", testRestartFlagToString(privdom->onReboot));
    virBufferVSprintf(&buf, "  <on_poweroff>%s</on_poweroff>\n", testRestartFlagToString(privdom->onPoweroff));
    virBufferVSprintf(&buf, "  <on_crash>%s</on_crash>\n", testRestartFlagToString(privdom->onCrash));

    virBufferAddLit(&buf, "</domain>\n");

    if (virBufferError(&buf)) {
        testError(domain->conn, domain, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}

static int testNumOfDefinedDomains(virConnectPtr conn) {
    int numInactive = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!privconn->domains[i].active ||
            privconn->domains[i].info.state != VIR_DOMAIN_SHUTOFF)
            continue;
        numInactive++;
    }
    return (numInactive);
}

static int testListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames) {
    int n = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0, n = 0 ; i < MAX_DOMAINS && n < maxnames ; i++) {
        if (privconn->domains[i].active &&
            privconn->domains[i].info.state == VIR_DOMAIN_SHUTOFF) {
            names[n++] = strdup(privconn->domains[i].name);
        }
    }
    return (n);
}

static virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                        const char *doc) {
    int handle;
    xmlDocPtr xml;
    GET_CONNECTION(conn, NULL);

    if (!(xml = xmlReadDoc(BAD_CAST doc, "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        return (NULL);
    }

    handle = testLoadDomain(conn, -1, xml);
    privconn->domains[handle].config = 1;

    xmlFreeDoc(xml);

    if (handle < 0)
        return (NULL);

    return virGetDomain(conn, privconn->domains[handle].name, privconn->domains[handle].uuid);
}

static int testNodeGetCellsFreeMemory(virConnectPtr conn,
                                      unsigned long long *freemems,
                                      int startCell, int maxCells) {
    int i, j;

    GET_CONNECTION(conn, -1);

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

    if (privdom->info.state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is already running"));
        return (-1);
    }

    domain->id = privdom->id = privconn->nextDomID++;
    privdom->info.state = VIR_DOMAIN_RUNNING;

    return (0);
}

static int testDomainUndefine(virDomainPtr domain) {
    GET_DOMAIN(domain, -1);

    if (privdom->info.state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, NULL, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is still running"));
        return (-1);
    }

    privdom->active = 0;

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
    params[0].value.ui = privdom->weight;
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
    privdom->weight = params[0].value.ui;
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
    GET_CONNECTION(conn, NULL);

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
    GET_CONNECTION(conn, NULL);

    if ((net = virNetworkFindByName(privconn->networks, name)) == NULL) {
        testError (conn, NULL, NULL, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, net->def->name, net->def->uuid);
}


static int testNumNetworks(virConnectPtr conn) {
    int numActive = 0;
    virNetworkObjPtr net;
    GET_CONNECTION(conn, -1);

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
    GET_CONNECTION(conn, -1);

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
    GET_CONNECTION(conn, -1);

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
    GET_CONNECTION(conn, -1);

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
    GET_CONNECTION(conn, NULL);

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
    GET_CONNECTION(conn, NULL);

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

#endif /* WITH_TEST */
