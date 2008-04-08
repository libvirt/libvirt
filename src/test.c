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

struct _testNet {
    int active;
    int config;
    int running;
    char name[20];
    char bridge[20];
    unsigned char uuid[VIR_UUID_BUFLEN];
    int forward;
    char forwardDev[IF_NAMESIZE];
    char ipAddress[INET_ADDRSTRLEN];
    char ipNetmask[INET_ADDRSTRLEN];

    char dhcpStart[INET_ADDRSTRLEN];
    char dhcpEnd[INET_ADDRSTRLEN];

    int autostart;
};
typedef struct _testNet testNet;
typedef struct _testNet *testNetPtr;

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
    int numNetworks;
    testNet networks[MAX_NETWORKS];
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
    int netidx;                                                         \
    testConnPtr privconn;                                               \
    testNetPtr privnet;                                                 \
                                                                        \
    privconn = (testConnPtr)net->conn->privateData;                     \
    if ((netidx = getNetworkIndex(net)) < 0) {                          \
        testError((net)->conn, NULL, (net), VIR_ERR_INVALID_ARG,        \
                  __FUNCTION__);                                        \
        return (ret);                                                   \
    }                                                                   \
    privnet = &privconn->networks[netidx];

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
    if (!strcmp(str, "restart")) {
        return VIR_DOMAIN_RESTART;
    } else if (!strcmp(str, "destroy")) {
        return VIR_DOMAIN_DESTROY;
    } else if (!strcmp(str, "preserve")) {
        return VIR_DOMAIN_PRESERVE;
    } else if (!strcmp(str, "rename-restart")) {
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
    free(str);


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
            free(str);
            goto error;
        }
        free(str);
    }

    str = virXPathString("string(/domain/on_poweroff[1])", ctxt);
    if (str != NULL) {
        if (!(onPoweroff = testRestartStringToFlag(str))) {
            testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain poweroff behaviour"));
            free(str);
            goto error;
        }
        free(str);
    }

    str = virXPathString("string(/domain/on_crash[1])", ctxt);
    if (str != NULL) {
        if (!(onCrash = testRestartStringToFlag(str))) {
            testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("domain crash behaviour"));
            free(str);
            goto error;
        }
        free(str);
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
    free(name);
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
    free(name);
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


static int testLoadNetwork(virConnectPtr conn,
                           xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *name = NULL, *bridge = NULL;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *str;
    char *ipaddress = NULL, *ipnetmask = NULL, *dhcpstart = NULL, *dhcpend = NULL;
    int forward;
    char *forwardDev = NULL;
    int handle = -1, i;
    GET_CONNECTION(conn, -1);

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "network"))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("creating xpath context"));
        goto error;
    }

    name = virXPathString("string(/network/name[1])", ctxt);
    if (name == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("network name"));
        goto error;
    }

    bridge = virXPathString("string(/network/bridge[1]/@name)", ctxt);

    str = virXPathString("string(/network/uuid[1])", ctxt);
    if (str == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network uuid"));
        goto error;
    }
    if (virUUIDParse(str, uuid) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network uuid"));
        goto error;
    }
    free(str);


    forward = virXPathBoolean("count(/network/forward) != 0", ctxt);
    if (forward < 0) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network forward"));
        goto error;
    }

    forwardDev = virXPathString("string(/network/forward/@dev)", ctxt);


    ipaddress = virXPathString("string(/network/ip/@address)", ctxt);
    if (ipaddress == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("ip address"));
        goto error;
    }
    ipnetmask = virXPathString("string(/network/ip/@netmask)", ctxt);
    if (ipnetmask == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("ip netmask"));
        goto error;
    }
    dhcpstart = virXPathString("string(/network/ip/dhcp/range[1]/@start)", ctxt);
    if (dhcpstart == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("ip address"));
        goto error;
    }
    dhcpend = virXPathString("string(/network/ip/dhcp/range[1]/@end)", ctxt);
    if (dhcpend == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("ip address"));
        goto error;
    }

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (!privconn->networks[i].active) {
            handle = i;
            break;
        }
    }
    if (handle < 0)
        return (-1);

    privconn->networks[handle].active = 1;
    privconn->networks[handle].running = 1;
    strncpy(privconn->networks[handle].name, name, sizeof(privconn->networks[handle].name)-1);
    privconn->networks[handle].name[sizeof(privconn->networks[handle].name)-1] = '\0';
    strncpy(privconn->networks[handle].bridge, bridge ? bridge : name, sizeof(privconn->networks[handle].bridge)-1);
    privconn->networks[handle].bridge[sizeof(privconn->networks[handle].bridge)-1] = '\0';
    free(name);
    name = NULL;
    if (bridge) {
        free(bridge);
        bridge = NULL;
    }

    memmove(privconn->networks[handle].uuid, uuid, VIR_UUID_BUFLEN);
    privconn->networks[handle].forward = forward;
    if (forwardDev) {
        strncpy(privconn->networks[handle].forwardDev, forwardDev, sizeof(privconn->networks[handle].forwardDev)-1);
        privconn->networks[handle].forwardDev[sizeof(privconn->networks[handle].forwardDev)-1] = '\0';
        free(forwardDev);
    }

    strncpy(privconn->networks[handle].ipAddress, ipaddress, sizeof(privconn->networks[handle].ipAddress)-1);
    privconn->networks[handle].ipAddress[sizeof(privconn->networks[handle].ipAddress)-1] = '\0';
    free(ipaddress);
    strncpy(privconn->networks[handle].ipNetmask, ipnetmask, sizeof(privconn->networks[handle].ipNetmask)-1);
    privconn->networks[handle].ipNetmask[sizeof(privconn->networks[handle].ipNetmask)-1] = '\0';
    free(ipnetmask);
    strncpy(privconn->networks[handle].dhcpStart, dhcpstart, sizeof(privconn->networks[handle].dhcpStart)-1);
    privconn->networks[handle].dhcpStart[sizeof(privconn->networks[handle].dhcpStart)-1] = '\0';
    free(dhcpstart);
    strncpy(privconn->networks[handle].dhcpEnd, dhcpend, sizeof(privconn->networks[handle].dhcpEnd)-1);
    privconn->networks[handle].dhcpEnd[sizeof(privconn->networks[handle].dhcpEnd)-1] = '\0';
    free(dhcpend);
    xmlXPathFreeContext(ctxt);
    return (handle);

 error:
    xmlXPathFreeContext(ctxt);
    free (forwardDev);
    free(ipaddress);
    free(ipnetmask);
    free(dhcpstart);
    free(dhcpend);
    free(name);
    return (-1);
}

static int testLoadNetworkFromDoc(virConnectPtr conn,
                                 const char *doc) {
    int ret;
    xmlDocPtr xml;
    if (!(xml = xmlReadDoc(BAD_CAST doc, "network.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network"));
        return (-1);
    }

    ret = testLoadNetwork(conn, xml);

    xmlFreeDoc(xml);

    return (ret);
}


static int testLoadNetworkFromFile(virConnectPtr conn,
                                  const char *filename) {
    int ret, fd;
    xmlDocPtr xml;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("load network definition file"));
        return (-1);
    }

    if (!(xml = xmlReadFd(fd, filename, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(conn, NULL, NULL, VIR_ERR_XML_ERROR, _("network"));
        return (-1);
    }

    ret = testLoadNetwork(conn, xml);

    xmlFreeDoc(xml);
    close(fd);

    return (ret);
}


static int testOpenDefault(virConnectPtr conn) {
    int u;
    struct timeval tv;
    testConnPtr privconn = malloc(sizeof(*privconn));
    if (!privconn) {
        testError(conn, NULL, NULL, VIR_ERR_NO_MEMORY, "testConn");
        return VIR_DRV_OPEN_ERROR;
    }
    memset(privconn, 0, sizeof(testConn));

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


    privconn->numNetworks = 1;
    privconn->networks[0].active = 1;
    privconn->networks[0].config = 1;
    privconn->networks[0].running = 1;
    strcpy(privconn->networks[0].name, "default");
    strcpy(privconn->networks[0].bridge, "default");
    for (u = 0 ; u < VIR_UUID_BUFLEN ; u++) {
        privconn->networks[0].uuid[u] = (u * 75)%255;
    }
    privconn->networks[0].forward = 1;
    strcpy(privconn->networks[0].forwardDev, "eth0");
    strcpy(privconn->networks[0].ipAddress, "192.168.122.1");
    strcpy(privconn->networks[0].ipNetmask, "255.255.255.0");
    strcpy(privconn->networks[0].dhcpStart, "192.168.122.128");
    strcpy(privconn->networks[0].dhcpEnd, "192.168.122.253");

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
        char *absFile = malloc(baseLen + strlen(filename) + 1);
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
    testConnPtr privconn = calloc(1, sizeof(*privconn));
    if (!privconn) {
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
    privconn->numNetworks = 0;
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
        free(str);
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
        free(domFile);
        if (!absFile) {
            testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving domain filename"));
            goto error;
        }
        if ((handle = testLoadDomainFromFile(conn, domid, absFile)) < 0) {
            free(absFile);
            goto error;
        }
        privconn->domains[handle].config = 1;
        free(absFile);
        privconn->numDomains++;
    }
    if (domains != NULL) {
        free(domains);
        domains = NULL;
    }


    ret = virXPathNodeSet("/node/network", ctxt, &networks);
    if (ret > 0) {
        for (i = 0 ; i < ret ; i++) {
            xmlChar *netFile = xmlGetProp(networks[i], BAD_CAST "file");
            char *absFile = testBuildFilename(file, (const char *)netFile);
            int handle;
            free(netFile);
            if (!absFile) {
                testError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving network filename"));
                goto error;
            }
            if ((handle = testLoadNetworkFromFile(conn, absFile)) < 0) {
                free(absFile);
                goto error;
            }
            privconn->networks[handle].config = 1;
            free(absFile);
            privconn->numNetworks++;
        }
        if (networks != NULL) {
            free(networks);
            networks = NULL;
        }
    }

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);

    return (0);

 error:
    xmlXPathFreeContext(ctxt);
    free(domains);
    free(networks);
    if (xml)
        xmlFreeDoc(xml);
    if (fd != -1)
        close(fd);
    free(privconn);
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

static int getNetworkIndex(virNetworkPtr network) {
    int i;
    GET_CONNECTION(network->conn, -1);

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (STREQ(network->name, privconn->networks[i].name))
            return (i);
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

    if (!uri->scheme || strcmp(uri->scheme, "test") != 0)
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
    free (privconn);
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
            strcmp(name, privconn->domains[i].name) == 0) {
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
        free(xml);
        close(fd);
        return (-1);
    }
    free(xml);
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
    xml = malloc(len+1);
    if (!xml) {
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
    free(xml);
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
    virBufferPtr buf;
    char *xml;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    GET_DOMAIN(domain, NULL);

    if (!(buf = virBufferNew(4000))) {
        testError(domain->conn, domain, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return (NULL);
    }

    virBufferVSprintf(buf, "<domain type='test' id='%d'>\n", domain->id);
    virBufferVSprintf(buf, "  <name>%s</name>\n", domain->name);
    uuid = domain->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(buf, "  <uuid>%s</uuid>\n", uuidstr);
    virBufferVSprintf(buf, "  <memory>%lu</memory>\n", privdom->info.maxMem);
    virBufferVSprintf(buf, "  <vcpu>%d</vcpu>\n", privdom->info.nrVirtCpu);
    virBufferVSprintf(buf, "  <on_reboot>%s</on_reboot>\n", testRestartFlagToString(privdom->onReboot));
    virBufferVSprintf(buf, "  <on_poweroff>%s</on_poweroff>\n", testRestartFlagToString(privdom->onPoweroff));
    virBufferVSprintf(buf, "  <on_crash>%s</on_crash>\n", testRestartFlagToString(privdom->onCrash));

    virBufferAddLit(buf, "</domain>\n");

    xml = buf->content;
    free(buf);

    return (xml);
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
    int i, idx = -1;
    GET_CONNECTION(conn, NULL);

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (privconn->networks[i].active &&
            memcmp(uuid, privconn->networks[i].uuid, VIR_UUID_BUFLEN) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        testError (conn, NULL, NULL, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, privconn->networks[idx].name, privconn->networks[idx].uuid);
}

static virNetworkPtr testLookupNetworkByName(virConnectPtr conn,
                                           const char *name)
{
    int i, idx = -1;
    GET_CONNECTION(conn, NULL);

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (privconn->networks[i].active &&
            strcmp(name, privconn->networks[i].name) == 0) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        testError (conn, NULL, NULL, VIR_ERR_NO_NETWORK, NULL);
        return NULL;
    }

    return virGetNetwork(conn, privconn->networks[idx].name, privconn->networks[idx].uuid);
}


static int testNumNetworks(virConnectPtr conn) {
    int numInactive = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (!privconn->networks[i].active ||
            !privconn->networks[i].running)
            continue;
        numInactive++;
    }
    return (numInactive);
}

static int testListNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0, n = 0 ; i < MAX_NETWORKS && n < nnames ; i++) {
        if (privconn->networks[i].active &&
            privconn->networks[i].running) {
            names[n++] = strdup(privconn->networks[i].name);
        }
    }
    return (n);
}

static int testNumDefinedNetworks(virConnectPtr conn) {
    int numInactive = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0 ; i < MAX_NETWORKS ; i++) {
        if (!privconn->networks[i].active ||
            privconn->networks[i].running)
            continue;
        numInactive++;
    }
    return (numInactive);
}

static int testListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    int n = 0, i;
    GET_CONNECTION(conn, -1);

    for (i = 0, n = 0 ; i < MAX_NETWORKS && n < nnames ; i++) {
        if (privconn->networks[i].active &&
            !privconn->networks[i].running) {
            names[n++] = strdup(privconn->networks[i].name);
        }
    }
    return (n);
}

static virNetworkPtr testNetworkCreate(virConnectPtr conn, const char *xml) {
    int handle = -1;
    virNetworkPtr net;
    GET_CONNECTION(conn, NULL);

    if (xml == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (privconn->numNetworks == MAX_NETWORKS) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many networks"));
        return (NULL);
    }

    if ((handle = testLoadNetworkFromDoc(conn, xml)) < 0)
        return (NULL);
    privconn->networks[handle].config = 0;

    net = virGetNetwork(conn, privconn->networks[handle].name, privconn->networks[handle].uuid);
    if (net == NULL) return NULL;
    privconn->numNetworks++;
    return (net);
}

static virNetworkPtr testNetworkDefine(virConnectPtr conn, const char *xml) {
    int handle = -1;
    virNetworkPtr net;
    GET_CONNECTION(conn, NULL);

    if (xml == NULL) {
        testError(conn, NULL, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }

    if (privconn->numNetworks == MAX_NETWORKS) {
        testError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many networks"));
        return (NULL);
    }

    if ((handle = testLoadNetworkFromDoc(conn, xml)) < 0)
        return (NULL);

    net = virGetNetwork(conn, privconn->networks[handle].name, privconn->networks[handle].uuid);
    privconn->networks[handle].config = 1;
    if (net == NULL) return NULL;
    privconn->numNetworks++;
    return (net);
}

static int testNetworkUndefine(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (privnet->running) {
        testError(network->conn, NULL, network, VIR_ERR_INTERNAL_ERROR,
                  _("Network is still running"));
        return (-1);
    }

    privnet->active = 0;

    return (0);
}

static int testNetworkStart(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (privnet->running) {
        testError(network->conn, NULL, network, VIR_ERR_INTERNAL_ERROR,
                  _("Network is already running"));
        return (-1);
    }

    privnet->running = 1;

    return (0);
}

static int testNetworkDestroy(virNetworkPtr network) {
    GET_NETWORK(network, -1);

    if (privnet->config) {
        privnet->running = 0;
    } else {
        privnet->active = 0;
    }
    return (0);
}

static char *testNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    virBufferPtr buf;
    char *xml;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    GET_NETWORK(network, NULL);

    if (!(buf = virBufferNew(4000))) {
        testError(network->conn, NULL, network, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return (NULL);
    }

    virBufferAddLit(buf, "<network>\n");
    virBufferVSprintf(buf, "  <name>%s</name>\n", network->name);
    uuid = network->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferVSprintf(buf, "  <uuid>%s</uuid>\n", uuidstr);
    virBufferVSprintf(buf, "  <bridge name='%s'/>\n", privnet->bridge);
    if (privnet->forward) {
        if (privnet->forwardDev[0])
            virBufferVSprintf(buf, "  <forward dev='%s'/>\n", privnet->forwardDev);
        else
            virBufferAddLit(buf, "  <forward/>\n");
    }

    virBufferVSprintf(buf, "  <ip address='%s' netmask='%s'>\n",
                      privnet->ipAddress, privnet->ipNetmask);
    virBufferAddLit(buf, "    <dhcp>\n");
    virBufferVSprintf(buf, "      <range start='%s' end='%s'/>\n",
                      privnet->dhcpStart, privnet->dhcpEnd);
    virBufferAddLit(buf, "    </dhcp>\n");
    virBufferAddLit(buf, "  </ip>\n");

    virBufferAddLit(buf, "</network>\n");

    xml = buf->content;
    free(buf);

    return (xml);
}

static char *testNetworkGetBridgeName(virNetworkPtr network) {
    char *bridge;
    GET_NETWORK(network, NULL);
    bridge = strdup(privnet->bridge);
    if (!bridge) {
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
