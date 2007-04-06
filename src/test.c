/*
 * test.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006-2007 Red Hat, Inc.
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

#include "internal.h"
#include "test.h"
#include "xml.h"

int testOpen(virConnectPtr conn,
             const char *name,
             int flags);
int testClose  (virConnectPtr conn);
int testGetVersion(virConnectPtr conn,
                   unsigned long *hvVer);
int testNodeGetInfo(virConnectPtr conn,
                    virNodeInfoPtr info);
char *testGetCapabilities (virConnectPtr conn);
int testNumOfDomains(virConnectPtr conn);
int testListDomains(virConnectPtr conn,
                    int *ids,
                    int maxids);
char *testGetOSType(virDomainPtr dom);
virDomainPtr
testDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                      unsigned int flags ATTRIBUTE_UNUSED);
virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                  int id);
virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                    const unsigned char *uuid);
virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                    const char *name);
int testDestroyDomain(virDomainPtr domain);
int testResumeDomain(virDomainPtr domain);
int testPauseDomain(virDomainPtr domain);
int testShutdownDomain (virDomainPtr domain);
int testRebootDomain (virDomainPtr domain,
                      virDomainRestart action);
int testGetDomainInfo(virDomainPtr domain,
                      virDomainInfoPtr info);
unsigned long testGetMaxMemory(virDomainPtr domain);
int testSetMaxMemory(virDomainPtr domain,
                     unsigned long memory);
int testSetMemory(virDomainPtr domain,
                  unsigned long memory);
int testSetVcpus(virDomainPtr domain,
                 unsigned int nrCpus);
char * testDomainDumpXML(virDomainPtr domain, int flags);

int testNumOfDefinedDomains(virConnectPtr conn);
int testListDefinedDomains(virConnectPtr conn,
                           char **const names,
                           int maxnames);

virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                 const char *xml);

int testDomainCreate(virDomainPtr dom);

int testDomainUndefine(virDomainPtr dom);

static virDriver testDriver = {
    VIR_DRV_TEST,
    "Test",
    LIBVIR_VERSION_NUMBER,
    testOpen, /* open */
    testClose, /* close */
    NULL, /* type */
    testGetVersion, /* version */
    NULL, /* getMaxVcpus */
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
    NULL, /* domainSave */
    NULL, /* domainRestore */
    NULL, /* domainCoreDump */
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
    NULL, /* domainGetAutostart */
    NULL, /* domainSetAutostart */
};

/* Per-connection private data. */
struct _testPrivate {
    int handle;
};
typedef struct _testPrivate *testPrivatePtr;

typedef struct _testDev {
    char name[20];
    virDeviceMode mode;
} testDev;

#define MAX_DEVICES 10

typedef struct _testDom {
    int active;
    int id;
    char name[20];
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainKernel kernel;
    virDomainInfo info;
    unsigned int maxVCPUs;
    virDomainRestart onRestart; /* What to do at end of current shutdown procedure */
    virDomainRestart onReboot;
    virDomainRestart onPoweroff;
    virDomainRestart onCrash;
    int numDevices;
    testDev devices[MAX_DEVICES];
} testDom;

#define MAX_DOMAINS 20

typedef struct _testCon {
    int active;
    virNodeInfo nodeInfo;
    int numDomains;
    testDom domains[MAX_DOMAINS];
} testCon;

#define MAX_CONNECTIONS 5

typedef struct _testNode {
    int numConnections;
    testCon connections[MAX_CONNECTIONS];
} testNode;

/* XXX, how about we stuff this in a SHM
   segment so multiple apps can run tests
   against the mock hypervisor concurrently.
   Would need a pthread process shared mutex
   too probably */
static testNode *node = NULL;
static int nextDomID = 1;

#define TEST_MODEL "i686"
#define TEST_MODEL_WORDSIZE "32"

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

static void
testError(virConnectPtr con,
          virDomainPtr dom,
          virErrorNumber error,
          const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(con, dom, NULL, VIR_FROM_XEN, error, VIR_ERR_ERROR,
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

/**
 * testRegister:
 *
 * Registers the test driver
 */
int
testRegister(void)
{
    return virRegisterDriver(&testDriver);
}

static int testLoadDomain(virConnectPtr conn,
                          int domid,
                          xmlDocPtr xml) {
    xmlNodePtr root = NULL;
    xmlXPathContextPtr ctxt = NULL;
    char *name = NULL;
    unsigned char rawuuid[VIR_UUID_BUFLEN];
    char *dst_uuid;
    testCon *con;
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
    testPrivatePtr priv;

    if (gettimeofday(&tv, NULL) < 0) {
        testError(conn, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return (-1);
    }

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "domain"))) {
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(conn, NULL, VIR_ERR_INTERNAL_ERROR, _("creating xpath context"));
        goto error;
    }

    name = virXPathString("string(/domain/name[1])", ctxt);
    if (name == NULL) {
        testError(conn, NULL, VIR_ERR_INTERNAL_ERROR, _("domain name"));
        goto error;
    }

    str = virXPathString("string(/domain/uuid[1])", ctxt);
    if (str == NULL) {
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
        goto error;
    }
    dst_uuid = (char *) &rawuuid[0];
    if (!(virParseUUID((char **)&dst_uuid, str))) {
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
        goto error;
    }
    free(str);


    ret = virXPathLong("string(/domain/memory[1])", ctxt, &l);
    if (ret != 0) {
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain memory"));
        goto error;
    }
    maxMem = l;

    ret = virXPathLong("string(/domain/currentMemory[1])", ctxt, &l);
    if (ret == -1) {
        memory = maxMem;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain current memory"));
	goto error;
    } else {
        memory = l;
    }

    ret = virXPathLong("string(/domain/vcpu[1])", ctxt, &l);
    if (ret == -1) {
        nrVirtCpu = 1;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain vcpus"));
	goto error;
    } else {
        nrVirtCpu = l;
    }

    str = virXPathString("string(/domain/on_reboot[1])", ctxt);
    if (str != NULL) {
        if (!(onReboot = testRestartStringToFlag(str))) {
            testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain reboot behaviour"));
	    free(str);
            goto error;
        }
	free(str);
    }

    str = virXPathString("string(/domain/on_poweroff[1])", ctxt);
    if (str != NULL) {
        if (!(onReboot = testRestartStringToFlag(str))) {
            testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain poweroff behaviour"));
	    free(str);
            goto error;
        }
	free(str);
    }

    str = virXPathString("string(/domain/on_crash[1])", ctxt);
    if (str != NULL) {
        if (!(onReboot = testRestartStringToFlag(str))) {
            testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain crash behaviour"));
	    free(str);
            goto error;
        }
	free(str);
    }

    priv = (testPrivatePtr) conn->privateData;
    con = &node->connections[priv->handle];

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!con->domains[i].active) {
            handle = i;
            break;
        }
    }
    if (handle < 0)
        return (-1);

    con->domains[handle].active = 1;
    con->domains[handle].id = domid;
    strncpy(con->domains[handle].name, name, sizeof(con->domains[handle].name));
    free(name);
    name = NULL;

    if (memory > maxMem)
        memory = maxMem;

    memmove(con->domains[handle].uuid, rawuuid, VIR_UUID_BUFLEN);
    con->domains[handle].info.maxMem = maxMem;
    con->domains[handle].info.memory = memory;
    con->domains[handle].info.state = domid < 0 ? VIR_DOMAIN_SHUTOFF : VIR_DOMAIN_RUNNING;
    con->domains[handle].info.nrVirtCpu = nrVirtCpu;
    con->domains[handle].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    con->domains[handle].maxVCPUs = nrVirtCpu;

    con->domains[handle].onReboot = onReboot;
    con->domains[handle].onPoweroff = onPoweroff;
    con->domains[handle].onCrash = onCrash;

    return (0);

 error:
    if (name)
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
        testError(NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        return (-1);
    }

    ret = testLoadDomain(conn, domid, xml);

    xmlFreeDoc(xml);

    return (ret);
}

static int testLoadDomainFromFile(virConnectPtr conn,
                                  int domid,
                                  const char *file) {
    int ret, fd;
    xmlDocPtr xml;

    if ((fd = open(file, O_RDONLY)) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("load domain definition file"));
        return (-1);
    }

    if (!(xml = xmlReadFd(fd, file, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        close(fd);
        return (-1);
    }
    close(fd);

    ret = testLoadDomain(conn, domid, xml);

    xmlFreeDoc(xml);

    return (ret);
}


static int testOpenDefault(virConnectPtr conn,
                           int connid) {
    int u;
    struct timeval tv;
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return VIR_DRV_OPEN_ERROR;
    }

    priv->handle = connid;
    node->connections[connid].active = 1;
    memmove(&node->connections[connid].nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    node->connections[connid].numDomains = 1;
    node->connections[connid].domains[0].active = 1;
    node->connections[connid].domains[0].id = nextDomID++;
    node->connections[connid].domains[0].onReboot = VIR_DOMAIN_RESTART;
    node->connections[connid].domains[0].onCrash = VIR_DOMAIN_RESTART;
    node->connections[connid].domains[0].onPoweroff = VIR_DOMAIN_DESTROY;
    strcpy(node->connections[connid].domains[0].name, "test");
    for (u = 0 ; u < VIR_UUID_BUFLEN ; u++) {
        node->connections[connid].domains[0].uuid[u] = (u * 75)%255;
    }
    node->connections[connid].domains[0].info.maxMem = 8192 * 1024;
    node->connections[connid].domains[0].info.memory = 2048 * 1024;
    node->connections[connid].domains[0].info.state = VIR_DOMAIN_RUNNING;
    node->connections[connid].domains[0].info.nrVirtCpu = 2;
    node->connections[connid].domains[0].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    return (0);
}


static char *testBuildFilename(const char *relativeTo,
                               const char *filename) {
    char *offset;
    int baseLen;
    if (!filename || filename[0] == '\0')
        return (NULL);
    if (filename[0] == '/')
        return strdup(filename);

    offset = rindex(relativeTo, '/');
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
                            int connid,
                            const char *file) {
    int fd, i, ret;
    long l;
    char *str;
    xmlDocPtr xml;
    xmlNodePtr root = NULL;
    xmlNodePtr *domains;
    xmlXPathContextPtr ctxt = NULL;
    virNodeInfoPtr nodeInfo;
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;

    if ((fd = open(file, O_RDONLY)) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("loading host definition file"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!(xml = xmlReadFd(fd, file, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("host"));
        goto error;
    }
    close(fd);
    fd = -1;

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "node"))) {
        testError(NULL, NULL, VIR_ERR_XML_ERROR, _("node"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("creating xpath context"));
        goto error;
    }

    priv->handle = connid;
    node->connections[connid].active = 1;
    node->connections[connid].numDomains = 0;
    memmove(&node->connections[connid].nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    nodeInfo = &node->connections[connid].nodeInfo;
    ret = virXPathLong("string(/node/cpu/nodes[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->nodes = l;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu numa nodes"));
	goto error;
    }

    ret = virXPathLong("string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu sockets"));
	goto error;
    }

    ret = virXPathLong("string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu cores"));
	goto error;
    }

    ret = virXPathLong("string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu threads"));
	goto error;
    }

    nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
    ret = virXPathLong("string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus) {
	    nodeInfo->cpus = l;
	}
    } else if (ret == -2) {
	testError(conn, NULL, VIR_ERR_XML_ERROR, _("node active cpu"));
	goto error;
    }
    ret = virXPathLong("string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu mhz"));
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
        testError(conn, NULL, VIR_ERR_XML_ERROR, _("node memory"));
	goto error;
    }

    ret = virXPathNodeSet("/node/domain", ctxt, &domains);
    if (ret < 0) {
        testError(NULL, NULL, VIR_ERR_XML_ERROR, _("node domain list"));
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        xmlChar *domFile = xmlGetProp(domains[i], BAD_CAST "file");
        char *absFile = testBuildFilename(file, (const char *)domFile);
        int domid = nextDomID++;
        free(domFile);
        if (!absFile) {
            testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving domain filename"));
            goto error;
        }
        if (testLoadDomainFromFile(conn, domid, absFile) != 0) {
            free(absFile);
            goto error;
        }
        free(absFile);
        node->connections[connid].numDomains++;
    }
    if (domains != NULL)
        free(domains);

    xmlFreeDoc(xml);

    return (0);

 error:
    if (node->connections[connid].active) {
        for (i = 0 ; i <node->connections[connid].numDomains ; i++) {
            node->connections[connid].domains[i].active = 0;
        }
        node->connections[connid].numDomains = 0;
        node->connections[connid].active = 0;
    }
    if (xml)
        xmlFreeDoc(xml);
    if (fd != -1)
        close(fd);
    return VIR_DRV_OPEN_ERROR;
}

static int getNextConnection(void) {
    int i;
    if (node == NULL) {
        node = calloc(1, sizeof(testNode));
        nextDomID = 1;
        if (!node) {
            testError(NULL, NULL, VIR_ERR_NO_MEMORY, _("allocating node"));
            return (-1);
        }
    }

    for (i = 0 ; i < MAX_CONNECTIONS ; i++) {
        if (!node->connections[i].active) {
            return (i);
        }
    }
    return (-1);
}

static int getDomainIndex(virDomainPtr domain) {
    int i;
    testCon *con;
    testPrivatePtr priv = (testPrivatePtr) domain->conn->privateData;

    con = &node->connections[priv->handle];
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (domain->id >= 0) {
            if (domain->id == con->domains[i].id)
                return (i);
        } else {
            if (!strcmp(domain->name, con->domains[i].name))
                return (i);
        }
    }
    return (-1);
}

int testOpen(virConnectPtr conn,
             const char *name,
             int flags)
{
    xmlURIPtr uri;
    int ret, connid;
    testPrivatePtr priv;

    if (!name)
        return VIR_DRV_OPEN_DECLINED;

    uri = xmlParseURI(name);
    if (uri == NULL) {
        if (!(flags & VIR_DRV_OPEN_QUIET))
            testError(conn, NULL, VIR_ERR_NO_SUPPORT, name);
        return VIR_DRV_OPEN_DECLINED;
    }

    if (!uri->scheme ||
        strcmp(uri->scheme, "test") ||
        !uri->path) {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }


    if ((connid = getNextConnection()) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many connections"));
        return VIR_DRV_OPEN_ERROR;
    }

    /* Allocate per-connection private data. */
    priv = conn->privateData = malloc (sizeof (struct _testPrivate));
    if (!priv) {
        testError(NULL, NULL, VIR_ERR_NO_MEMORY, "allocating private data");
        return VIR_DRV_OPEN_ERROR;
    }
    priv->handle = -1;

    if (!strcmp(uri->path, "/default")) {
        ret = testOpenDefault(conn,
                              connid);
    } else {
        ret = testOpenFromFile(conn,
                               connid,
                               uri->path);
    }

    xmlFreeURI(uri);

    if (ret < 0) free (conn->privateData);

    return (ret);
}

int testClose(virConnectPtr conn)
{
    testPrivatePtr priv;

    if (!conn) {
        testError (NULL, NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    priv = (testPrivatePtr) conn->privateData;
    if (!priv) {
        testError (NULL, NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return -1;
    }

    if (priv->handle >= 0) {
        testCon *con = &node->connections[priv->handle];
        con->active = 0;
        memset (con, 0, sizeof *con); // RWMJ - why?
    }

    free (priv);
    return 0;
}

int testGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED,
                   unsigned long *hvVer)
{
    *hvVer = 2;
    return (0);
}

int testNodeGetInfo(virConnectPtr conn,
                    virNodeInfoPtr info)
{
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    memcpy(info, &con->nodeInfo, sizeof(virNodeInfo));
    return (0);
}

char *
testGetCapabilities (virConnectPtr conn)
{
    static char caps[] = "\
<capabilities>\n\
  <host>\n\
    <cpu>\n\
      <arch>" TEST_MODEL "</arch>\n\
      <features>\n\
        <pae/>\n\
        <nonpae/>\n\
      </features>\n\
    </cpu>\n\
  </host>\n\
\n\
  <guest>\n\
    <os_type>linux</os_type>\n\
    <arch name=\"" TEST_MODEL "\">\n\
      <wordsize>" TEST_MODEL_WORDSIZE "</wordsize>\n\
      <domain type=\"test\"/>\n\
    </arch>\n\
    <features>\n\
      <pae/>\n\
      <nonpae/>\n\
    </features>\n\
  </guest>\n\
</capabilities>\n\
";

    char *caps_copy = strdup (caps);
    if (!caps_copy) {
        testError(conn, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return NULL;
    }
    return caps_copy;
}

int testNumOfDomains(virConnectPtr conn)
{
    int numActive = 0, i;
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!con->domains[i].active ||
            con->domains[i].info.state == VIR_DOMAIN_SHUTOFF)
            continue;
        numActive++;
    }
    return (numActive);
}

virDomainPtr
testDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    testCon *con;
    int domid, handle = -1, i;
    virDomainPtr dom;
    testPrivatePtr priv;

    if (!VIR_IS_CONNECT(conn)) {
        testError(conn, NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        return (NULL);
    }
    if (xmlDesc == NULL) {
        testError(conn, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (NULL);
    }
    if (conn->flags & VIR_CONNECT_RO) {
        testError(conn, NULL, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (NULL);
    }

    priv = (testPrivatePtr) conn->privateData;
  
    con = &node->connections[priv->handle];

    if (con->numDomains == MAX_DOMAINS) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many domains"));
        return (NULL);
    }

    domid = nextDomID++;
    if (testLoadDomainFromDoc(conn, domid, xmlDesc) < 0)
        return (NULL);
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (con->domains[i].id == domid) {
            handle = i;
            break;
        }
    }
    dom = virGetDomain(conn, con->domains[handle].name, con->domains[handle].uuid);
    if (dom == NULL) {
        testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
        return (NULL);
    }
    con->numDomains++;
    return (dom);
}


virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                  int id)
{
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    virDomainPtr dom;
    int i, idx = -1;

    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (con->domains[i].active &&
            con->domains[i].id == id) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        return(NULL);
    }

    dom = virGetDomain(conn, con->domains[idx].name, con->domains[idx].uuid);
    if (dom == NULL) {
        testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
        return(NULL);
    }
    dom->id = id;
    return (dom);
}

virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                    const unsigned char *uuid)
{
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    virDomainPtr dom = NULL;
    int i, idx = -1;
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (con->domains[i].active &&
            memcmp(uuid, con->domains[i].uuid, VIR_UUID_BUFLEN) == 0) {
            idx = i;
            break;
        }
    }
    if (idx >= 0) {
        dom = virGetDomain(conn, con->domains[idx].name, con->domains[idx].uuid);
        if (dom == NULL) {
            testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
            return(NULL);
        }
        dom->id = con->domains[idx].id;
    }
    return (dom);
}

virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                    const char *name)
{
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    virDomainPtr dom = NULL;
    int i, idx = -1;
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (con->domains[i].active &&
            strcmp(name, con->domains[i].name) == 0) {
            idx = i;
            break;
        }
    }
    if (idx >= 0) {
        dom = virGetDomain(conn, con->domains[idx].name, con->domains[idx].uuid);
        if (dom == NULL) {
            testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
            return(NULL);
        }
        dom->id = con->domains[idx].id;
    }
    return (dom);
}

int testListDomains (virConnectPtr conn,
                     int *ids,
                     int maxids)
{
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    int n, i;

    for (i = 0, n = 0 ; i < MAX_DOMAINS && n < maxids ; i++) {
        if (con->domains[i].active &&
            con->domains[i].info.state != VIR_DOMAIN_SHUTOFF) {
            ids[n++] = con->domains[i].id;
        }
    }
    return (n);
}

int testDestroyDomain (virDomainPtr domain)
{
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;

    con = &node->connections[priv->handle];
    con->domains[domidx].active = 0;
    return (0);
}

int testResumeDomain (virDomainPtr domain)
{
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;

    con = &node->connections[priv->handle];
    con->domains[domidx].info.state = VIR_DOMAIN_RUNNING;
    return (0);
}

int testPauseDomain (virDomainPtr domain)
{
    testCon *con;\
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;

    con = &node->connections[priv->handle];
    con->domains[domidx].info.state = VIR_DOMAIN_PAUSED;
    return (0);
}

/* We don't do an immediate shutdown. We basically pretend that
   out shutdown sequence takes 'n' seconds to complete. SO, here
   we just set state to shutdown, and subsquent calls to getDomainInfo
   will check to see if shutdown ought to be marked complete. */
int testShutdownDomain (virDomainPtr domain)
{
    testCon *con;
    int domidx;
    struct timeval tv;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;

    con = &node->connections[priv->handle];

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return (-1);
    }

    con->domains[domidx].info.state = VIR_DOMAIN_SHUTOFF;
    domain->id = -1;
    con->domains[domidx].id = -1;

    return (0);
}

/* Similar behaviour as shutdown */
int testRebootDomain (virDomainPtr domain, virDomainRestart action)
{
    testCon *con;
    int domidx;
    struct timeval tv;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return (-1);
    }

    if (!action)
        action = VIR_DOMAIN_RESTART;

    con->domains[domidx].info.state = VIR_DOMAIN_SHUTDOWN;
    switch (action) {
    case VIR_DOMAIN_DESTROY:
        con->domains[domidx].info.state = VIR_DOMAIN_SHUTOFF;
        break;

    case VIR_DOMAIN_RESTART:
        con->domains[domidx].info.state = VIR_DOMAIN_RUNNING;
        break;

    case VIR_DOMAIN_PRESERVE:
        con->domains[domidx].info.state = VIR_DOMAIN_SHUTOFF;
        break;

    case VIR_DOMAIN_RENAME_RESTART:
        con->domains[domidx].info.state = VIR_DOMAIN_RUNNING;
        break;

    default:
        con->domains[domidx].info.state = VIR_DOMAIN_SHUTOFF;
        break;
    }
    domain->id = -1;
    con->domains[domidx].id = -1;

    return (0);
}

int testGetDomainInfo (virDomainPtr domain,
                       virDomainInfoPtr info)
{
    struct timeval tv;
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (gettimeofday(&tv, NULL) < 0) {
        testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
        return (-1);
    }

    if (con->domains[domidx].info.state == VIR_DOMAIN_SHUTOFF) {
        con->domains[domidx].info.cpuTime = 0;
        con->domains[domidx].info.memory = 0;
    } else {
        con->domains[domidx].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    }
    memcpy(info, &con->domains[domidx].info, sizeof(virDomainInfo));
    return (0);
}

char *testGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED) {
    return strdup("linux");
}

unsigned long testGetMaxMemory(virDomainPtr domain) {
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];
    return con->domains[domidx].info.maxMem;
}

int testSetMaxMemory(virDomainPtr domain,
                     unsigned long memory)
{
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];
    /* XXX validate not over host memory wrt to other domains */
    con->domains[domidx].info.maxMem = memory;
    return (0);
}

int testSetMemory(virDomainPtr domain,
                  unsigned long memory)
{
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (memory > con->domains[domidx].info.maxMem) {
        testError(domain->conn, domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    con->domains[domidx].info.memory = memory;
    return (0);
}

int testSetVcpus(virDomainPtr domain,
                 unsigned int nrCpus) {
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }
    if (domain->conn->flags & VIR_CONNECT_RO) {
        testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    /* We allow more cpus in guest than host */
    if (nrCpus > 32) {
        testError(domain->conn, domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return (-1);
    }

    con->domains[domidx].info.nrVirtCpu = nrCpus;
    return (0);
}

char * testDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
    virBufferPtr buf;
    char *xml;
    unsigned char *uuid;
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (NULL);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (!(buf = virBufferNew(4000))) {
        return (NULL);
    }

    virBufferVSprintf(buf, "<domain type='test' id='%d'>\n", domain->id);
    virBufferVSprintf(buf, "  <name>%s</name>\n", domain->name);
    uuid = domain->uuid;
    virBufferVSprintf(buf,
                      "  <uuid>%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x</uuid>\n",
                      uuid[0], uuid[1], uuid[2], uuid[3],
                      uuid[4], uuid[5], uuid[6], uuid[7],
                      uuid[8], uuid[9], uuid[10], uuid[11],
                      uuid[12], uuid[13], uuid[14], uuid[15]);

    virBufferVSprintf(buf, "  <memory>%lu</memory>\n", con->domains[domidx].info.maxMem);
    virBufferVSprintf(buf, "  <vcpu>%d</vcpu>\n", con->domains[domidx].info.nrVirtCpu);
    virBufferVSprintf(buf, "  <on_reboot>%s</on_reboot>\n", testRestartFlagToString(con->domains[domidx].onReboot));
    virBufferVSprintf(buf, "  <on_poweroff>%s</on_poweroff>\n", testRestartFlagToString(con->domains[domidx].onPoweroff));
    virBufferVSprintf(buf, "  <on_crash>%s</on_crash>\n", testRestartFlagToString(con->domains[domidx].onCrash));

    virBufferAdd(buf, "</domain>\n", -1);

    xml = buf->content;
    free(buf);

    return (xml);
}


int testNumOfDefinedDomains(virConnectPtr conn) {
    int numInactive = 0, i;
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    for (i = 0 ; i < MAX_DOMAINS ; i++) {
        if (!con->domains[i].active ||
            con->domains[i].info.state != VIR_DOMAIN_SHUTOFF)
            continue;
        numInactive++;
    }
    return (numInactive);
}

int testListDefinedDomains(virConnectPtr conn,
                           char **const names,
                           int maxnames) {
    testPrivatePtr priv = (testPrivatePtr) conn->privateData;
    testCon *con = &node->connections[priv->handle];
    int n = 0, i;

    for (i = 0, n = 0 ; i < MAX_DOMAINS && n < maxnames ; i++) {
        if (con->domains[i].active &&
            con->domains[i].info.state == VIR_DOMAIN_SHUTOFF) {
            names[n++] = strdup(con->domains[i].name);
        }
    }
    return (n);
}

virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                 const char *doc) {
    int ret;
    xmlDocPtr xml;
    int domid;

    if (!(xml = xmlReadDoc(BAD_CAST doc, "domain.xml", NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
        return (NULL);
    }

    domid = nextDomID++;
    ret = testLoadDomain(conn, domid, xml);

    xmlFreeDoc(xml);

    if (ret < 0)
        return (NULL);

    return testLookupDomainByID(conn, domid);
}

int testDomainCreate(virDomainPtr domain) {
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (con->domains[domidx].info.state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is already running"));
        return (-1);
    }

    domain->id = con->domains[domidx].id = nextDomID++;
    con->domains[domidx].info.state = VIR_DOMAIN_RUNNING;

    return (0);
}

int testDomainUndefine(virDomainPtr domain) {
    testCon *con;
    int domidx;
    testPrivatePtr priv;

    if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL) ||
        ((domidx = getDomainIndex(domain)) < 0)) {
        testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
                  __FUNCTION__);
        return (-1);
    }

    priv = (testPrivatePtr) domain->conn->privateData;
    con = &node->connections[priv->handle];

    if (con->domains[domidx].info.state != VIR_DOMAIN_SHUTOFF) {
        testError(domain->conn, domain, VIR_ERR_INTERNAL_ERROR,
                  _("Domain is still running"));
        return (-1);
    }

    con->domains[domidx].active = 0;

    return (0);
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
