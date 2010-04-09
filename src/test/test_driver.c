/*
 * test.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
#include "test_driver.h"
#include "buf.h"
#include "util.h"
#include "uuid.h"
#include "capabilities.h"
#include "memory.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "event.h"
#include "storage_conf.h"
#include "node_device_conf.h"
#include "xml.h"
#include "threads.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_TEST

/* Driver specific info to carry with a domain */
struct _testDomainObjPrivate {
    virVcpuInfoPtr vcpu_infos;

    unsigned char *cpumaps;
};
typedef struct _testDomainObjPrivate testDomainObjPrivate;
typedef struct _testDomainObjPrivate *testDomainObjPrivatePtr;

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
    virInterfaceObjList ifaces;
    virStoragePoolObjList pools;
    virNodeDeviceObjList devs;
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


#define testError(code, ...)                                      \
        virReportErrorHelper(NULL, VIR_FROM_TEST, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

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

static void *testDomainObjPrivateAlloc(void)
{
    testDomainObjPrivatePtr priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    return priv;
}

static void testDomainObjPrivateFree(void *data)
{
    testDomainObjPrivatePtr priv = data;

    VIR_FREE(priv->vcpu_infos);
    VIR_FREE(priv->cpumaps);
    VIR_FREE(priv);
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

    caps->privateDataAllocFunc = testDomainObjPrivateAlloc;
    caps->privateDataFreeFunc = testDomainObjPrivateFree;

    caps->host.secModel.model = strdup("testSecurity");
    if (!caps->host.secModel.model)
        goto no_memory;

    caps->host.secModel.doi = strdup("");
    if (!caps->host.secModel.doi)
        goto no_memory;

    return caps;

no_memory:
    virReportOOMError();
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

static const char *defaultInterfaceXML =
"<interface type=\"ethernet\" name=\"eth1\">"
"  <start mode=\"onboot\"/>"
"  <mac address=\"aa:bb:cc:dd:ee:ff\"/>"
"  <mtu size=\"1492\"/>"
"  <protocol family=\"ipv4\">"
"    <ip address=\"192.168.0.5\" prefix=\"24\"/>"
"    <route gateway=\"192.168.0.1\"/>"
"  </protocol>"
"</interface>";

static const char *defaultPoolXML =
"<pool type='dir'>"
"  <name>default-pool</name>"
"  <target>"
"    <path>/default-pool</path>"
"  </target>"
"</pool>";

static const char *defaultPoolSourcesLogicalXML =
"<sources>\n"
"  <source>\n"
"    <device path='/dev/sda20'/>\n"
"    <name>testvg1</name>\n"
"    <format type='lvm2'/>\n"
"  </source>\n"
"  <source>\n"
"    <device path='/dev/sda21'/>\n"
"    <name>testvg2</name>\n"
"    <format type='lvm2'/>\n"
"  </source>\n"
"</sources>\n";

static const char *defaultPoolSourcesNetFSXML =
"<sources>\n"
"  <source>\n"
"    <host name='%s'/>\n"
"    <dir path='/testshare'/>\n"
"    <format type='nfs'/>\n"
"  </source>\n"
"</sources>\n";

static const char *defaultNodeXML =
"<device>"
"  <name>computer</name>"
"  <capability type='system'>"
"    <hardware>"
"      <vendor>Libvirt</vendor>"
"      <version>Test driver</version>"
"      <serial>123456</serial>"
"      <uuid>11111111-2222-3333-4444-555555555555</uuid>"
"    </hardware>"
"    <firmware>"
"      <vendor>Libvirt</vendor>"
"      <version>Test Driver</version>"
"      <release_date>01/22/2007</release_date>"
"    </firmware>"
"  </capability>"
"</device>";

static const unsigned long long defaultPoolCap = (100 * 1024 * 1024 * 1024ull);
static const unsigned long long defaultPoolAlloc = 0;

static int testStoragePoolObjSetDefaults(virStoragePoolObjPtr pool);
static int testNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);

static char *
testDomainGenerateIfname(virDomainDefPtr domdef) {
    int maxif = 1024;
    int ifctr, i;

    for (ifctr = 0; ifctr < maxif; ++ifctr) {
        char *ifname;
        int found = 0;

        if (virAsprintf(&ifname, "testnet%d", ifctr) < 0) {
            virReportOOMError();
            return NULL;
        }

        /* Generate network interface names */
        for (i = 0 ; i < domdef->nnets ; i++) {
            if (domdef->nets[i]->ifname &&
                STREQ (domdef->nets[i]->ifname, ifname)) {
                found = 1;
                break;
            }
        }

        if (!found)
            return ifname;
    }

    testError(VIR_ERR_INTERNAL_ERROR,
              _("Exceeded max iface limit %d"), maxif);
    return NULL;
}

static int
testDomainGenerateIfnames(virDomainDefPtr domdef)
{
    int i = 0;

    for (i = 0; i < domdef->nnets; i++) {
        char *ifname;
        if (domdef->nets[i]->ifname)
            continue;

        ifname = testDomainGenerateIfname(domdef);
        if (!ifname)
            return -1;

        domdef->nets[i]->ifname = ifname;
    }

    return 0;
}

/* Helper to update info for a single VCPU */
static int
testDomainUpdateVCPU(virConnectPtr conn ATTRIBUTE_UNUSED,
                     virDomainObjPtr dom,
                     int vcpu,
                     int maplen,
                     int maxcpu)
{
    testDomainObjPrivatePtr privdata = dom->privateData;
    virVcpuInfoPtr info = &privdata->vcpu_infos[vcpu];
    unsigned char *cpumap = VIR_GET_CPUMAP(privdata->cpumaps, maplen, vcpu);
    int j;

    memset(info, 0, sizeof(virVcpuInfo));
    memset(cpumap, 0, maplen);

    info->number    = vcpu;
    info->state     = VIR_VCPU_RUNNING;
    info->cpuTime   = 5000000;
    info->cpu       = 0;

    if (dom->def->cpumask) {
        for (j = 0; j < maxcpu && j < VIR_DOMAIN_CPUMASK_LEN; ++j) {
            if (dom->def->cpumask[j]) {
                VIR_USE_CPU(cpumap, j);
                info->cpu = j;
            }
        }
    } else {
        for (j = 0; j < maxcpu; ++j) {
            if ((j % 3) == 0) {
                /* Mark of every third CPU as usable */
                VIR_USE_CPU(cpumap, j);
                info->cpu = j;
            }
        }
    }

    return 0;
}

/*
 * Update domain VCPU amount and info
 *
 * @conn: virConnectPtr
 * @dom : domain needing updates
 * @nvcpus: New amount of vcpus for the domain
 * @clear_all: If true, rebuild info for ALL vcpus, not just newly added vcpus
 */
static int
testDomainUpdateVCPUs(virConnectPtr conn,
                      virDomainObjPtr dom,
                      int nvcpus,
                      unsigned int clear_all)
{
    testConnPtr privconn = conn->privateData;
    testDomainObjPrivatePtr privdata = dom->privateData;
    int i, ret = -1;
    int cpumaplen, maxcpu;

    maxcpu  = VIR_NODEINFO_MAXCPUS(privconn->nodeInfo);
    cpumaplen = VIR_CPU_MAPLEN(maxcpu);

    if (VIR_REALLOC_N(privdata->vcpu_infos, nvcpus) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (VIR_REALLOC_N(privdata->cpumaps, nvcpus * cpumaplen) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* Set running VCPU and cpumap state */
    if (clear_all) {
        for (i = 0; i < nvcpus; ++i)
            if (testDomainUpdateVCPU(conn, dom, i, cpumaplen, maxcpu) < 0)
                goto cleanup;

    } else if (nvcpus > dom->def->vcpus) {
        /* VCPU amount has grown, populate info for the new vcpus */
        for (i = dom->def->vcpus; i < nvcpus; ++i)
            if (testDomainUpdateVCPU(conn, dom, i, cpumaplen, maxcpu) < 0)
                goto cleanup;
    }

    ret = 0;
cleanup:
    return ret;
}

/* Set up domain runtime state */
static int
testDomainStartState(virConnectPtr conn,
                     virDomainObjPtr dom)
{
    testConnPtr privconn = conn->privateData;
    int ret = -1;

    if (testDomainUpdateVCPUs(conn, dom, dom->def->vcpus, 1) < 0)
        goto cleanup;

    /* Set typical run state */
    dom->state = VIR_DOMAIN_RUNNING;
    dom->def->id = privconn->nextDomID++;

    ret = 0;
cleanup:
    return ret;
}

static void
testDomainShutdownState(virDomainPtr domain,
                        virDomainObjPtr privdom)
{
    if (privdom->newDef) {
        virDomainDefFree(privdom->def);
        privdom->def = privdom->newDef;
        privdom->newDef = NULL;
    }

    privdom->state = VIR_DOMAIN_SHUTOFF;
    privdom->def->id = -1;
    domain->id = -1;
}

static int testOpenDefault(virConnectPtr conn) {
    int u;
    struct timeval tv;
    testConnPtr privconn;
    virDomainDefPtr domdef = NULL;
    virDomainObjPtr domobj = NULL;
    virNetworkDefPtr netdef = NULL;
    virNetworkObjPtr netobj = NULL;
    virInterfaceDefPtr interfacedef = NULL;
    virInterfaceObjPtr interfaceobj = NULL;
    virStoragePoolDefPtr pooldef = NULL;
    virStoragePoolObjPtr poolobj = NULL;
    virNodeDeviceDefPtr nodedef = NULL;
    virNodeDeviceObjPtr nodeobj = NULL;

    if (VIR_ALLOC(privconn) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  "%s", _("cannot initialize mutex"));
        VIR_FREE(privconn);
        return VIR_DRV_OPEN_ERROR;
    }

    testDriverLock(privconn);
    conn->privateData = privconn;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto error;
    }

    if (virDomainObjListInit(&privconn->domains) < 0)
        goto error;

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

    if (!(domdef = virDomainDefParseString(privconn->caps,
                                           defaultDomainXML,
                                           VIR_DOMAIN_XML_INACTIVE)))
        goto error;
    if (testDomainGenerateIfnames(domdef) < 0)
        goto error;
    if (!(domobj = virDomainAssignDef(privconn->caps,
                                      &privconn->domains, domdef, false)))
        goto error;
    domdef = NULL;

    if (testDomainStartState(conn, domobj) < 0) {
        virDomainObjUnlock(domobj);
        goto error;
    }

    domobj->persistent = 1;
    virDomainObjUnlock(domobj);

    if (!(netdef = virNetworkDefParseString(defaultNetworkXML)))
        goto error;
    if (!(netobj = virNetworkAssignDef(&privconn->networks, netdef))) {
        virNetworkDefFree(netdef);
        goto error;
    }
    netobj->active = 1;
    netobj->persistent = 1;
    virNetworkObjUnlock(netobj);

    if (!(interfacedef = virInterfaceDefParseString(defaultInterfaceXML)))
        goto error;
    if (!(interfaceobj = virInterfaceAssignDef(&privconn->ifaces, interfacedef))) {
        virInterfaceDefFree(interfacedef);
        goto error;
    }
    interfaceobj->active = 1;
    virInterfaceObjUnlock(interfaceobj);

    if (!(pooldef = virStoragePoolDefParseString(defaultPoolXML)))
        goto error;

    if (!(poolobj = virStoragePoolObjAssignDef(&privconn->pools,
                                               pooldef))) {
        virStoragePoolDefFree(pooldef);
        goto error;
    }

    if (testStoragePoolObjSetDefaults(poolobj) == -1) {
        virStoragePoolObjUnlock(poolobj);
        goto error;
    }
    poolobj->active = 1;
    virStoragePoolObjUnlock(poolobj);

    /* Init default node device */
    if (!(nodedef = virNodeDeviceDefParseString(defaultNodeXML, 0)))
        goto error;
    if (!(nodeobj = virNodeDeviceAssignDef(&privconn->devs,
                                           nodedef))) {
        virNodeDeviceDefFree(nodedef);
        goto error;
    }
    virNodeDeviceObjUnlock(nodeobj);

    testDriverUnlock(privconn);

    return VIR_DRV_OPEN_SUCCESS;

error:
    virDomainObjListDeinit(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virInterfaceObjListFree(&privconn->ifaces);
    virStoragePoolObjListFree(&privconn->pools);
    virNodeDeviceObjListFree(&privconn->devs);
    virCapabilitiesFree(privconn->caps);
    testDriverUnlock(privconn);
    conn->privateData = NULL;
    VIR_FREE(privconn);
    virDomainDefFree(domdef);
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
        int totalLen = baseLen + strlen(filename) + 1;
        if (VIR_ALLOC_N(absFile, totalLen) < 0)
            return NULL;
        if (virStrncpy(absFile, relativeTo, baseLen, totalLen) == NULL) {
            VIR_FREE(absFile);
            return NULL;
        }
        strcat(absFile, filename);
        return absFile;
    } else {
        return strdup(filename);
    }
}

static int testOpenVolumesForPool(xmlDocPtr xml,
                                  xmlXPathContextPtr ctxt,
                                  const char *file,
                                  virStoragePoolObjPtr pool,
                                  int poolidx) {
    char *vol_xpath;
    int i, ret, func_ret = -1;
    xmlNodePtr *vols = NULL;
    virStorageVolDefPtr def = NULL;

    /* Find storage volumes */
    if (virAsprintf(&vol_xpath, "/node/pool[%d]/volume", poolidx) < 0) {
        virReportOOMError();
        goto error;
    }

    ret = virXPathNodeSet(vol_xpath, ctxt, &vols);
    VIR_FREE(vol_xpath);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR,
                  _("node vol list for pool '%s'"), pool->def->name);
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        char *relFile = virXMLPropString(vols[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(VIR_ERR_INTERNAL_ERROR, "%s",
                          _("resolving volume filename"));
                goto error;
            }

            def = virStorageVolDefParseFile(pool->def, absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virStorageVolDefParseNode(pool->def, xml,
                                                 vols[i])) == NULL) {
                goto error;
            }
        }

        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virAsprintf(&def->target.path, "%s/%s",
                        pool->def->target.path,
                        def->name) == -1) {
            virReportOOMError();
            goto error;
        }

        def->key = strdup(def->target.path);
        if (def->key == NULL) {
            virReportOOMError();
            goto error;
        }

        pool->def->allocation += def->allocation;
        pool->def->available = (pool->def->capacity -
                                pool->def->allocation);

        pool->volumes.objs[pool->volumes.count++] = def;
        def = NULL;
    }

    func_ret = 0;
error:
    virStorageVolDefFree(def);
    VIR_FREE(vols);
    return func_ret;
}

static int testOpenFromFile(virConnectPtr conn,
                            const char *file) {
    int fd = -1, i, ret;
    long l;
    char *str;
    xmlDocPtr xml = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr *domains = NULL, *networks = NULL, *ifaces = NULL,
               *pools = NULL, *devs = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virNodeInfoPtr nodeInfo;
    virNetworkObjPtr net;
    virInterfaceObjPtr iface;
    virDomainObjPtr dom;
    testConnPtr privconn;
    if (VIR_ALLOC(privconn) < 0) {
        virReportOOMError();
        return VIR_DRV_OPEN_ERROR;
    }
    if (virMutexInit(&privconn->lock) < 0) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  "%s", _("cannot initialize mutex"));
        VIR_FREE(privconn);
        return VIR_DRV_OPEN_ERROR;
    }

    testDriverLock(privconn);
    conn->privateData = privconn;

    if (virDomainObjListInit(&privconn->domains) < 0)
        goto error;

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if ((fd = open(file, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("loading host definition file '%s'"),
                             file);
        goto error;
    }

    if (!(xml = xmlReadFd(fd, file, NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("Invalid XML in file '%s'"), file);
        goto error;
    }
    close(fd);
    fd = -1;

    root = xmlDocGetRootElement(xml);
    if ((root == NULL) || (!xmlStrEqual(root->name, BAD_CAST "node"))) {
        testError(VIR_ERR_XML_ERROR, "%s",
                  _("Root element is not 'node'"));
        goto error;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        testError(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("creating xpath context"));
        goto error;
    }

    privconn->nextDomID = 1;
    privconn->numCells = 0;
    if (virStrcpyStatic(privconn->path, file) == NULL) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("Path %s too big for destination"), file);
        goto error;
    }
    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    nodeInfo = &privconn->nodeInfo;
    ret = virXPathLong("string(/node/cpu/nodes[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->nodes = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node cpu numa nodes"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node cpu sockets"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node cpu cores"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node cpu threads"));
        goto error;
    }

    nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
    ret = virXPathLong("string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus) {
            nodeInfo->cpus = l;
        }
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node active cpu"));
        goto error;
    }
    ret = virXPathLong("string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node cpu mhz"));
        goto error;
    }

    str = virXPathString("string(/node/cpu/model[1])", ctxt);
    if (str != NULL) {
        if (virStrcpyStatic(nodeInfo->model, str) == NULL) {
            testError(VIR_ERR_INTERNAL_ERROR,
                      _("Model %s too big for destination"), str);
            VIR_FREE(str);
            goto error;
        }
        VIR_FREE(str);
    }

    ret = virXPathLong("string(/node/memory[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->memory = l;
    } else if (ret == -2) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node memory"));
        goto error;
    }

    ret = virXPathNodeSet("/node/domain", ctxt, &domains);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node domain list"));
        goto error;
    }

    for (i = 0 ; i < ret ; i++) {
        virDomainDefPtr def;
        char *relFile = virXMLPropString(domains[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(VIR_ERR_INTERNAL_ERROR, "%s", _("resolving domain filename"));
                goto error;
            }
            def = virDomainDefParseFile(privconn->caps, absFile,
                                        VIR_DOMAIN_XML_INACTIVE);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virDomainDefParseNode(privconn->caps, xml, domains[i],
                                             VIR_DOMAIN_XML_INACTIVE)) == NULL)
                goto error;
        }

        if (testDomainGenerateIfnames(def) < 0 ||
            !(dom = virDomainAssignDef(privconn->caps,
                                       &privconn->domains, def, false))) {
            virDomainDefFree(def);
            goto error;
        }

        if (testDomainStartState(conn, dom) < 0) {
            virDomainObjUnlock(dom);
            goto error;
        }

        dom->persistent = 1;
        virDomainObjUnlock(dom);
    }
    VIR_FREE(domains);

    ret = virXPathNodeSet("/node/network", ctxt, &networks);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node network list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virNetworkDefPtr def;
        char *relFile = virXMLPropString(networks[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(VIR_ERR_INTERNAL_ERROR, "%s", _("resolving network filename"));
                goto error;
            }

            def = virNetworkDefParseFile(absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virNetworkDefParseNode(xml, networks[i])) == NULL)
                goto error;
        }
        if (!(net = virNetworkAssignDef(&privconn->networks,
                                        def))) {
            virNetworkDefFree(def);
            goto error;
        }
        net->persistent = 1;
        net->active = 1;
        virNetworkObjUnlock(net);
    }
    VIR_FREE(networks);

    /* Parse interface definitions */
    ret = virXPathNodeSet("/node/interface", ctxt, &ifaces);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node interface list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virInterfaceDefPtr def;
        char *relFile = virXMLPropString(ifaces[i], "file");
        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);
            if (!absFile) {
                testError(VIR_ERR_INTERNAL_ERROR, "%s", _("resolving interface filename"));
                goto error;
            }

            def = virInterfaceDefParseFile(absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virInterfaceDefParseNode(xml, ifaces[i])) == NULL)
                goto error;
        }

        if (!(iface = virInterfaceAssignDef(&privconn->ifaces, def))) {
            virInterfaceDefFree(def);
            goto error;
        }

        iface->active = 1;
        virInterfaceObjUnlock(iface);
    }
    VIR_FREE(ifaces);

    /* Parse Storage Pool list */
    ret = virXPathNodeSet("/node/pool", ctxt, &pools);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node pool list"));
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
                testError(VIR_ERR_INTERNAL_ERROR, "%s",
                          _("resolving pool filename"));
                goto error;
            }

            def = virStoragePoolDefParseFile(absFile);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virStoragePoolDefParseNode(xml,
                                                  pools[i])) == NULL) {
                goto error;
            }
        }

        if (!(pool = virStoragePoolObjAssignDef(&privconn->pools,
                                                def))) {
            virStoragePoolDefFree(def);
            goto error;
        }

        if (testStoragePoolObjSetDefaults(pool) == -1) {
            virStoragePoolObjUnlock(pool);
            goto error;
        }
        pool->active = 1;

        /* Find storage volumes */
        if (testOpenVolumesForPool(xml, ctxt, file, pool, i+1) < 0) {
            virStoragePoolObjUnlock(pool);
            goto error;
        }

        virStoragePoolObjUnlock(pool);
    }
    VIR_FREE(pools);

    ret = virXPathNodeSet("/node/device", ctxt, &devs);
    if (ret < 0) {
        testError(VIR_ERR_XML_ERROR, "%s", _("node device list"));
        goto error;
    }
    for (i = 0 ; i < ret ; i++) {
        virNodeDeviceDefPtr def;
        virNodeDeviceObjPtr dev;
        char *relFile = virXMLPropString(devs[i], "file");

        if (relFile != NULL) {
            char *absFile = testBuildFilename(file, relFile);
            VIR_FREE(relFile);

            if (!absFile) {
                testError(VIR_ERR_INTERNAL_ERROR, "%s",
                          _("resolving device filename"));
                goto error;
            }

            def = virNodeDeviceDefParseFile(absFile, 0);
            VIR_FREE(absFile);
            if (!def)
                goto error;
        } else {
            if ((def = virNodeDeviceDefParseNode(xml, devs[i], 0)) == NULL)
                goto error;
        }
        if (!(dev = virNodeDeviceAssignDef(&privconn->devs, def))) {
            virNodeDeviceDefFree(def);
            goto error;
        }
        virNodeDeviceObjUnlock(dev);
    }
    VIR_FREE(devs);


    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    testDriverUnlock(privconn);

    return (0);

 error:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    VIR_FREE(domains);
    VIR_FREE(networks);
    VIR_FREE(ifaces);
    VIR_FREE(pools);
    if (fd != -1)
        close(fd);
    virDomainObjListDeinit(&privconn->domains);
    virNetworkObjListFree(&privconn->networks);
    virInterfaceObjListFree(&privconn->ifaces);
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

    /* From this point on, the connection is for us. */
    if (!conn->uri->path
        || conn->uri->path[0] == '\0'
        || (conn->uri->path[0] == '/' && conn->uri->path[1] == '\0')) {
        testError(VIR_ERR_INVALID_ARG,
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
            virReportOOMError();
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
    virDomainObjListDeinit(&privconn->domains);
    virNodeDeviceObjListFree(&privconn->devs);
    virNetworkObjListFree(&privconn->networks);
    virInterfaceObjListFree(&privconn->ifaces);
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

static int testIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int testIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
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
        virReportOOMError();
    testDriverUnlock(privconn);
    return xml;
}

static int testNumOfDomains(virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    int count;

    testDriverLock(privconn);
    count = virDomainObjListNumOfDomains(&privconn->domains, 1);
    testDriverUnlock(privconn);

    return count;
}

static int testDomainIsActive(virDomainPtr dom)
{
    testConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virDomainFindByUUID(&privconn->domains, dom->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = virDomainObjIsActive(obj);

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
}

static int testDomainIsPersistent(virDomainPtr dom)
{
    testConnPtr privconn = dom->conn->privateData;
    virDomainObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virDomainFindByUUID(&privconn->domains, dom->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virDomainObjUnlock(obj);
    return ret;
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
    if ((def = virDomainDefParseString(privconn->caps, xml,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (virDomainObjIsDuplicate(&privconn->domains, def, 1) < 0)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainAssignDef(privconn->caps,
                                   &privconn->domains, def, false)))
        goto cleanup;
    def = NULL;

    if (testDomainStartState(conn, dom) < 0)
        goto cleanup;

    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

cleanup:
    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        testDomainEventQueue(privconn, event);
    virDomainDefFree(def);
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
        testError(VIR_ERR_NO_DOMAIN, NULL);
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
        testError(VIR_ERR_NO_DOMAIN, NULL);
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
        testError(VIR_ERR_NO_DOMAIN, NULL);
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
    int n;

    testDriverLock(privconn);
    n = virDomainObjListGetActiveIDs(&privconn->domains, ids, maxids);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    testDomainShutdownState(domain, privdom);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_PAUSED) {
        testError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not paused"),
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state == VIR_DOMAIN_SHUTOFF ||
        privdom->state == VIR_DOMAIN_PAUSED) {
        testError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not running"),
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("domain '%s' not running"), domain->name);
        goto cleanup;
    }

    testDomainShutdownState(domain, privdom);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->state = VIR_DOMAIN_SHUTDOWN;
    switch (privdom->def->onReboot) {
    case VIR_DOMAIN_LIFECYCLE_DESTROY:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART:
        privdom->state = VIR_DOMAIN_RUNNING;
        break;

    case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
        privdom->state = VIR_DOMAIN_RUNNING;
        break;

    default:
        privdom->state = VIR_DOMAIN_SHUTOFF;
        break;
    }

    if (privdom->state == VIR_DOMAIN_SHUTOFF) {
        testDomainShutdownState(domain, privdom);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    xml = virDomainDefFormat(privdom->def,
                             VIR_DOMAIN_XML_SECURE);

    if (xml == NULL) {
        virReportSystemError(errno,
                             _("saving domain '%s' failed to allocate space for metadata"),
                             domain->name);
        goto cleanup;
    }

    if ((fd = open(path, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': open failed"),
                             domain->name, path);
        goto cleanup;
    }
    len = strlen(xml);
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    if (safewrite(fd, (char*)&len, sizeof(len)) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    if (safewrite(fd, xml, len) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }

    if (close(fd) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    fd = -1;

    testDomainShutdownState(domain, privdom);
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
        virReportSystemError(errno,
                             _("cannot read domain image '%s'"),
                             path);
        goto cleanup;
    }
    if (saferead(fd, magic, sizeof(magic)) != sizeof(magic)) {
        virReportSystemError(errno,
                             _("incomplete save header in '%s'"),
                             path);
        goto cleanup;
    }
    if (memcmp(magic, TEST_SAVE_MAGIC, sizeof(magic))) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  "%s", _("mismatched header magic"));
        goto cleanup;
    }
    if (saferead(fd, (char*)&len, sizeof(len)) != sizeof(len)) {
        virReportSystemError(errno,
                             _("failed to read metadata length in '%s'"),
                             path);
        goto cleanup;
    }
    if (len < 1 || len > 8192) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  "%s", _("length of metadata out of range"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(xml, len+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (saferead(fd, xml, len) != len) {
        virReportSystemError(errno,
                             _("incomplete metdata in '%s'"), path);
        goto cleanup;
    }
    xml[len] = '\0';

    testDriverLock(privconn);
    def = virDomainDefParseString(privconn->caps, xml,
                                  VIR_DOMAIN_XML_INACTIVE);
    if (!def)
        goto cleanup;

    if (virDomainObjIsDuplicate(&privconn->domains, def, 1) < 0)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainAssignDef(privconn->caps,
                                   &privconn->domains, def, true)))
        goto cleanup;
    def = NULL;

    if (testDomainStartState(conn, dom) < 0)
        goto cleanup;

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if ((fd = open(to, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: failed to open %s"),
                             domain->name, to);
        goto cleanup;
    }
    if (safewrite(fd, TEST_SAVE_MAGIC, sizeof(TEST_SAVE_MAGIC)) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: failed to write header to %s"),
                             domain->name, to);
        goto cleanup;
    }
    if (close(fd) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: write failed: %s"),
                             domain->name, to);
        goto cleanup;
    }

    if (flags & VIR_DUMP_CRASH) {
        testDomainShutdownState(domain, privdom);
        event = virDomainEventNewFromObj(privdom,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        if (!privdom->persistent) {
            virDomainRemoveInactive(&privconn->domains,
                                    privdom);
            privdom = NULL;
        }
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

static char *testGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED) {
    char *ret = strdup("linux");
    if (!ret)
        virReportOOMError();
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (memory > privdom->def->maxmem) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->def->memory = memory;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testDomainGetMaxVcpus(virDomainPtr domain)
{
    return testGetMaxVCPUs(domain->conn, "test");
}

static int testSetVcpus(virDomainPtr domain,
                        unsigned int nrCpus) {
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom = NULL;
    int ret = -1, maxvcpus;

    /* Do this first before locking */
    maxvcpus = testDomainGetMaxVcpus(domain);
    if (maxvcpus < 0)
        goto cleanup;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virDomainObjIsActive(privdom)) {
        testError(VIR_ERR_OPERATION_INVALID,
                  "%s", _("cannot hotplug vcpus for an inactive domain"));
        goto cleanup;
    }

    /* We allow more cpus in guest than host */
    if (nrCpus > maxvcpus) {
        testError(VIR_ERR_INVALID_ARG,
                  "requested cpu amount exceeds maximum (%d > %d)",
                  nrCpus, maxvcpus);
        goto cleanup;
    }

    /* Update VCPU state for the running domain */
    if (testDomainUpdateVCPUs(domain->conn, privdom, nrCpus, 0) < 0)
        goto cleanup;

    privdom->def->vcpus = nrCpus;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testDomainGetVcpus(virDomainPtr domain,
                              virVcpuInfoPtr info,
                              int maxinfo,
                              unsigned char *cpumaps,
                              int maplen)
{
    testConnPtr privconn = domain->conn->privateData;
    testDomainObjPrivatePtr privdomdata;
    virDomainObjPtr privdom;
    int i, v, maxcpu, hostcpus;
    int ret = -1;
    struct timeval tv;
    unsigned long long statbase;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains, domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virDomainObjIsActive(privdom)) {
        testError(VIR_ERR_OPERATION_INVALID,
                  "%s",_("cannot list vcpus for an inactive domain"));
        goto cleanup;
    }

    privdomdata = privdom->privateData;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto cleanup;
    }

    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;


    hostcpus = VIR_NODEINFO_MAXCPUS(privconn->nodeInfo);
    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    /* Clamp to actual number of vcpus */
    if (maxinfo > privdom->def->vcpus)
        maxinfo = privdom->def->vcpus;

    /* Populate virVcpuInfo structures */
    if (info != NULL) {
        memset(info, 0, sizeof(*info) * maxinfo);

        for (i = 0 ; i < maxinfo ; i++) {
            virVcpuInfo privinfo = privdomdata->vcpu_infos[i];

            info[i].number = privinfo.number;
            info[i].state = privinfo.state;
            info[i].cpu = privinfo.cpu;

            /* Fake an increasing cpu time value */
            info[i].cpuTime = statbase / 10;
        }
    }

    /* Populate cpumaps */
    if (cpumaps != NULL) {
        int privmaplen = VIR_CPU_MAPLEN(hostcpus);
        memset(cpumaps, 0, maplen * maxinfo);

        for (v = 0 ; v < maxinfo ; v++) {
            unsigned char *cpumap = VIR_GET_CPUMAP(cpumaps, maplen, v);

            for (i = 0 ; i < maxcpu ; i++) {
                if (VIR_CPU_USABLE(privdomdata->cpumaps, privmaplen, v, i)) {
                    VIR_USE_CPU(cpumap, i);
                }
            }
        }
    }

    ret = maxinfo;
cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testDomainPinVcpu(virDomainPtr domain,
                             unsigned int vcpu,
                             unsigned char *cpumap,
                             int maplen)
{
    testConnPtr privconn = domain->conn->privateData;
    testDomainObjPrivatePtr privdomdata;
    virDomainObjPtr privdom;
    unsigned char *privcpumap;
    int i, maxcpu, hostcpus, privmaplen;
    int ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains, domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virDomainObjIsActive(privdom)) {
        testError(VIR_ERR_OPERATION_INVALID,
                  "%s",_("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (vcpu > privdom->def->vcpus) {
        testError(VIR_ERR_INVALID_ARG, "%s",
                  _("requested vcpu is higher than allocated vcpus"));
        goto cleanup;
    }

    privdomdata = privdom->privateData;
    hostcpus = VIR_NODEINFO_MAXCPUS(privconn->nodeInfo);
    privmaplen = VIR_CPU_MAPLEN(hostcpus);

    maxcpu = maplen * 8;
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    privcpumap = VIR_GET_CPUMAP(privdomdata->cpumaps, privmaplen, vcpu);
    memset(privcpumap, 0, privmaplen);

    for (i = 0 ; i < maxcpu ; i++) {
        if (VIR_CPU_USABLE(cpumap, maplen, 0, i)) {
            VIR_USE_CPU(privcpumap, i);
        }
    }

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    ret = virDomainDefFormat(def,
                             flags);

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testNumOfDefinedDomains(virConnectPtr conn) {
    testConnPtr privconn = conn->privateData;
    int count;

    testDriverLock(privconn);
    count = virDomainObjListNumOfDomains(&privconn->domains, 0);
    testDriverUnlock(privconn);

    return count;
}

static int testListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames) {

    testConnPtr privconn = conn->privateData;
    int n;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*maxnames);
    n = virDomainObjListGetInactiveNames(&privconn->domains, names, maxnames);
    testDriverUnlock(privconn);

    return n;
}

static virDomainPtr testDomainDefineXML(virConnectPtr conn,
                                        const char *xml) {
    testConnPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    virDomainEventPtr event = NULL;
    int dupVM;

    testDriverLock(privconn);
    if ((def = virDomainDefParseString(privconn->caps, xml,
                                       VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if ((dupVM = virDomainObjIsDuplicate(&privconn->domains, def, 0)) < 0)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainAssignDef(privconn->caps,
                                   &privconn->domains, def, false)))
        goto cleanup;
    def = NULL;
    dom->persistent = 1;

    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !dupVM ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

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
        testError(VIR_ERR_INVALID_ARG,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("Domain '%s' is already running"), domain->name);
        goto cleanup;
    }

    if (testDomainStartState(domain->conn, privdom) < 0)
        goto cleanup;
    domain->id = privdom->def->id;

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (privdom->state != VIR_DOMAIN_SHUTOFF) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->autostart = autostart ? 1 : 0;
    ret = 0;

cleanup:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static char *testDomainGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED,
                                        int *nparams)
{
    char *type = NULL;

    *nparams = 1;
    type = strdup("fair");
    if (!type)
        virReportOOMError();

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (*nparams != 1) {
        testError(VIR_ERR_INVALID_ARG, "nparams");
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (nparams != 1) {
        testError(VIR_ERR_INVALID_ARG, "nparams");
        goto cleanup;
    }
    if (STRNEQ(params[0].field, "weight")) {
        testError(VIR_ERR_INVALID_ARG, "field");
        goto cleanup;
    }
    if (params[0].type != VIR_DOMAIN_SCHED_FIELD_UINT) {
        testError(VIR_ERR_INVALID_ARG, "type");
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

static int testDomainBlockStats(virDomainPtr domain,
                                const char *path,
                                struct _virDomainBlockStats *stats)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    struct timeval tv;
    unsigned long long statbase;
    int i, found = 0, ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    for (i = 0 ; i < privdom->def->ndisks ; i++) {
        if (STREQ(path, privdom->def->disks[i]->dst)) {
            found = 1;
            break;
        }
    }

    if (!found) {
        testError(VIR_ERR_INVALID_ARG,
                  _("invalid path: %s"), path);
        goto error;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto error;
    }

    /* No significance to these numbers, just enough to mix it up*/
    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    stats->rd_req = statbase / 10;
    stats->rd_bytes = statbase / 20;
    stats->wr_req = statbase / 30;
    stats->wr_bytes = statbase / 40;
    stats->errs = tv.tv_sec / 2;

    ret = 0;
error:
    if (privdom)
        virDomainObjUnlock(privdom);
    return ret;
}

static int testDomainInterfaceStats(virDomainPtr domain,
                                    const char *path,
                                    struct _virDomainInterfaceStats *stats)
{
    testConnPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    struct timeval tv;
    unsigned long long statbase;
    int i, found = 0, ret = -1;

    testDriverLock(privconn);
    privdom = virDomainFindByName(&privconn->domains,
                                  domain->name);
    testDriverUnlock(privconn);

    if (privdom == NULL) {
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    for (i = 0 ; i < privdom->def->nnets ; i++) {
        if (privdom->def->nets[i]->ifname &&
            STREQ (privdom->def->nets[i]->ifname, path)) {
            found = 1;
            break;
        }
    }

    if (!found) {
        testError(VIR_ERR_INVALID_ARG,
                  _("invalid path, '%s' is not a known interface"), path);
        goto error;
    }

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(errno,
                             "%s", _("getting time of day"));
        goto error;
    }

    /* No significance to these numbers, just enough to mix it up*/
    statbase = (tv.tv_sec * 1000UL * 1000UL) + tv.tv_usec;
    stats->rx_bytes = statbase / 10;
    stats->rx_packets = statbase / 100;
    stats->rx_errs = tv.tv_sec / 1;
    stats->rx_drop = tv.tv_sec / 2;
    stats->tx_bytes = statbase / 20;
    stats->tx_packets = statbase / 110;
    stats->tx_errs = tv.tv_sec / 3;
    stats->tx_drop = tv.tv_sec / 4;

    ret = 0;
error:
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
        testError(VIR_ERR_NO_NETWORK, NULL);
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
        testError(VIR_ERR_NO_NETWORK, NULL);
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
        if (virNetworkObjIsActive(privconn->networks.objs[i]))
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
        if (virNetworkObjIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name))) {
            virNetworkObjUnlock(privconn->networks.objs[i]);
            goto no_memory;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
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
        if (!virNetworkObjIsActive(privconn->networks.objs[i]))
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
        if (!virNetworkObjIsActive(privconn->networks.objs[i]) &&
            !(names[n++] = strdup(privconn->networks.objs[i]->def->name))) {
            virNetworkObjUnlock(privconn->networks.objs[i]);
            goto no_memory;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}


static int testNetworkIsActive(virNetworkPtr net)
{
    testConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virNetworkFindByUUID(&privconn->networks, net->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = virNetworkObjIsActive(obj);

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}

static int testNetworkIsPersistent(virNetworkPtr net)
{
    testConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virNetworkFindByUUID(&privconn->networks, net->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}


static virNetworkPtr testNetworkCreate(virConnectPtr conn, const char *xml) {
    testConnPtr privconn = conn->privateData;
    virNetworkDefPtr def;
    virNetworkObjPtr net = NULL;
    virNetworkPtr ret = NULL;

    testDriverLock(privconn);
    if ((def = virNetworkDefParseString(xml)) == NULL)
        goto cleanup;

    if ((net = virNetworkAssignDef(&privconn->networks, def)) == NULL)
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
    if ((def = virNetworkDefParseString(xml)) == NULL)
        goto cleanup;

    if ((net = virNetworkAssignDef(&privconn->networks, def)) == NULL)
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkObjIsActive(privnet)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkObjIsActive(privnet)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = virNetworkDefFormat(privnet->def);

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!(privnet->def->bridge)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("network '%s' does not have a bridge name."),
                  privnet->def->name);
        goto cleanup;
    }

    if (!(bridge = strdup(privnet->def->bridge))) {
        virReportOOMError();
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
 * Physical host interface routines
 */

static virDrvOpenStatus testOpenInterface(virConnectPtr conn,
                                          virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                          int flags ATTRIBUTE_UNUSED)
{
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->interfacePrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testCloseInterface(virConnectPtr conn)
{
    conn->interfacePrivateData = NULL;
    return 0;
}


static int testNumOfInterfaces(virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    int i, count = 0;

    testDriverLock(privconn);
    for (i = 0 ; (i < privconn->ifaces.count); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            count++;
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);
    return count;
}

static int testListInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; (i < privconn->ifaces.count) && (n < nnames); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            if (!(names[n++] = strdup(privconn->ifaces.objs[i]->def->name))) {
                virInterfaceObjUnlock(privconn->ifaces.objs[i]);
                goto no_memory;
            }
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int testNumOfDefinedInterfaces(virConnectPtr conn)
{
    testConnPtr privconn = conn->privateData;
    int i, count = 0;

    testDriverLock(privconn);
    for (i = 0 ; i < privconn->ifaces.count; i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (!virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            count++;
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);
    return count;
}

static int testListDefinedInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    testConnPtr privconn = conn->privateData;
    int n = 0, i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0 ; (i < privconn->ifaces.count) && (n < nnames); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (!virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            if (!(names[n++] = strdup(privconn->ifaces.objs[i]->def->name))) {
                virInterfaceObjUnlock(privconn->ifaces.objs[i]);
                goto no_memory;
            }
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

no_memory:
    virReportOOMError();
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static virInterfacePtr testLookupInterfaceByName(virConnectPtr conn,
                                                 const char *name)
{
    testConnPtr privconn = conn->privateData;
    virInterfaceObjPtr iface;
    virInterfacePtr ret = NULL;

    testDriverLock(privconn);
    iface = virInterfaceFindByName(&privconn->ifaces, name);
    testDriverUnlock(privconn);

    if (iface == NULL) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    ret = virGetInterface(conn, iface->def->name, iface->def->mac);

cleanup:
    if (iface)
        virInterfaceObjUnlock(iface);
    return ret;
}

static virInterfacePtr testLookupInterfaceByMACString(virConnectPtr conn,
                                                      const char *mac)
{
    testConnPtr privconn = conn->privateData;
    virInterfaceObjPtr iface;
    int ifacect;
    virInterfacePtr ret = NULL;

    testDriverLock(privconn);
    ifacect = virInterfaceFindByMACString(&privconn->ifaces, mac, &iface, 1);
    testDriverUnlock(privconn);

    if (ifacect == 0) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (ifacect > 1) {
        testError(VIR_ERR_MULTIPLE_INTERFACES, NULL);
        goto cleanup;
    }

    ret = virGetInterface(conn, iface->def->name, iface->def->mac);

cleanup:
    if (iface)
        virInterfaceObjUnlock(iface);
    return ret;
}

static int testInterfaceIsActive(virInterfacePtr iface)
{
    testConnPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virInterfaceFindByName(&privconn->ifaces, iface->name);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }
    ret = virInterfaceObjIsActive(obj);

cleanup:
    if (obj)
        virInterfaceObjUnlock(obj);
    return ret;
}


static char *testInterfaceGetXMLDesc(virInterfacePtr iface,
                                     unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    char *ret = NULL;

    testDriverLock(privconn);
    privinterface = virInterfaceFindByName(&privconn->ifaces,
                                           iface->name);
    testDriverUnlock(privconn);

    if (privinterface == NULL) {
        testError(VIR_ERR_NO_INTERFACE, __FUNCTION__);
        goto cleanup;
    }

    ret = virInterfaceDefFormat(privinterface->def);

cleanup:
    if (privinterface)
        virInterfaceObjUnlock(privinterface);
    return ret;
}


static virInterfacePtr testInterfaceDefineXML(virConnectPtr conn, const char *xmlStr,
                                              unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = conn->privateData;
    virInterfaceDefPtr def;
    virInterfaceObjPtr iface = NULL;
    virInterfacePtr ret = NULL;

    testDriverLock(privconn);
    if ((def = virInterfaceDefParseString(xmlStr)) == NULL)
        goto cleanup;

    if ((iface = virInterfaceAssignDef(&privconn->ifaces, def)) == NULL)
        goto cleanup;
    def = NULL;

    ret = virGetInterface(conn, iface->def->name, iface->def->mac);

cleanup:
    virInterfaceDefFree(def);
    if (iface)
        virInterfaceObjUnlock(iface);
    testDriverUnlock(privconn);
    return ret;
}

static int testInterfaceUndefine(virInterfacePtr iface)
{
    testConnPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    testDriverLock(privconn);
    privinterface = virInterfaceFindByName(&privconn->ifaces,
                                           iface->name);

    if (privinterface == NULL) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    virInterfaceRemove(&privconn->ifaces,
                       privinterface);
    ret = 0;

cleanup:
    testDriverUnlock(privconn);
    return ret;
}

static int testInterfaceCreate(virInterfacePtr iface,
                               unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    testDriverLock(privconn);
    privinterface = virInterfaceFindByName(&privconn->ifaces,
                                           iface->name);

    if (privinterface == NULL) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (privinterface->active != 0) {
        testError(VIR_ERR_OPERATION_INVALID, NULL);
        goto cleanup;
    }

    privinterface->active = 1;
    ret = 0;

cleanup:
    if (privinterface)
        virInterfaceObjUnlock(privinterface);
    testDriverUnlock(privconn);
    return ret;
}

static int testInterfaceDestroy(virInterfacePtr iface,
                                unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    testDriverLock(privconn);
    privinterface = virInterfaceFindByName(&privconn->ifaces,
                                           iface->name);

    if (privinterface == NULL) {
        testError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (privinterface->active == 0) {
        testError(VIR_ERR_OPERATION_INVALID, NULL);
        goto cleanup;
    }

    privinterface->active = 0;
    ret = 0;

cleanup:
    if (privinterface)
        virInterfaceObjUnlock(privinterface);
    testDriverUnlock(privconn);
    return ret;
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
        virReportOOMError();
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
        testError(VIR_ERR_NO_STORAGE_POOL, NULL);
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
        testError(VIR_ERR_NO_STORAGE_POOL, NULL);
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
    virReportOOMError();
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
    virReportOOMError();
    for (n = 0 ; n < nnames ; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}


static int testStoragePoolIsActive(virStoragePoolPtr pool)
{
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = virStoragePoolObjIsActive(obj);

cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}

static int testStoragePoolIsPersistent(virStoragePoolPtr pool)
{
    testConnPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        testError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = obj->configFile ? 1 : 0;

cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
                           const char *type,
                           const char *srcSpec,
                           unsigned int flags ATTRIBUTE_UNUSED)
{
    virStoragePoolSourcePtr source = NULL;
    int pool_type;
    char *ret = NULL;

    pool_type = virStoragePoolTypeFromString(type);
    if (!pool_type) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("unknown storage pool type %s"), type);
        goto cleanup;
    }

    if (srcSpec) {
        source = virStoragePoolDefParseSourceString(srcSpec, pool_type);
        if (!source)
            goto cleanup;
    }

    switch (pool_type) {

    case VIR_STORAGE_POOL_LOGICAL:
        ret = strdup(defaultPoolSourcesLogicalXML);
        if (!ret)
            virReportOOMError();
        break;

    case VIR_STORAGE_POOL_NETFS:
        if (!source || !source->host.name) {
            testError(VIR_ERR_INVALID_ARG,
                      "%s", "hostname must be specified for netfs sources");
            goto cleanup;
        }

        if (virAsprintf(&ret, defaultPoolSourcesNetFSXML,
                        source->host.name) < 0)
            virReportOOMError();
        break;

    default:
        testError(VIR_ERR_NO_SUPPORT,
                  _("pool type '%s' does not support source discovery"), type);
    }

cleanup:
    virStoragePoolSourceFree(source);
    VIR_FREE(source);
    return ret;
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
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    pool = virStoragePoolObjFindByUUID(&privconn->pools, def->uuid);
    if (!pool)
        pool = virStoragePoolObjFindByName(&privconn->pools, def->name);
    if (pool) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  "%s", _("storage pool already exists"));
        goto cleanup;
    }

    if (!(pool = virStoragePoolObjAssignDef(&privconn->pools, def)))
        goto cleanup;
    def = NULL;

    if (testStoragePoolObjSetDefaults(pool) == -1) {
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
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    def->capacity = defaultPoolCap;
    def->allocation = defaultPoolAlloc;
    def->available = defaultPoolCap - defaultPoolAlloc;

    if (!(pool = virStoragePoolObjAssignDef(&privconn->pools, def)))
        goto cleanup;
    def = NULL;

    if (testStoragePoolObjSetDefaults(pool) == -1) {
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = virStoragePoolDefFormat(privpool->def);

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!privpool->configFile) {
        testError(VIR_ERR_INVALID_ARG,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    for (i = 0 ; i < privpool->volumes.count && n < maxnames ; i++) {
        if ((names[n++] = strdup(privpool->volumes.objs[i]->name)) == NULL) {
            virReportOOMError();
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, name);

    if (!privvol) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
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
        testError(VIR_ERR_INVALID_STORAGE_VOL,
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
        testError(VIR_ERR_INVALID_STORAGE_VOL,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  "%s", _("storage vol already exists"));
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->allocation) >
         privpool->def->capacity) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("Not enough free space in pool for volume '%s'"),
                  privvol->name);
        goto cleanup;
    }

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1) {
        virReportOOMError();
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError();
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  "%s", _("storage vol already exists"));
        goto cleanup;
    }

    origvol = virStorageVolDefFindByName(privpool, clonevol->name);
    if (!origvol) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  clonevol->name);
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->allocation) >
         privpool->def->capacity) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("Not enough free space in pool for volume '%s'"),
                  privvol->name);
        goto cleanup;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (VIR_REALLOC_N(privpool->volumes.objs,
                      privpool->volumes.count+1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1) {
        virReportOOMError();
        goto cleanup;
    }

    privvol->key = strdup(privvol->target.path);
    if (privvol->key == NULL) {
        virReportOOMError();
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = virStorageVolDefFormat(privpool->def, privvol);

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
        testError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        testError(VIR_ERR_INVALID_STORAGE_VOL,
                  _("no storage vol with matching name '%s'"),
                  vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        testError(VIR_ERR_INTERNAL_ERROR,
                  _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ret = strdup(privvol->target.path);
    if (ret == NULL)
        virReportOOMError();

cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


/* Node device implementations */
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
testNodeNumOfDevices(virConnectPtr conn,
                     const char *cap,
                     unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr driver = conn->privateData;
    int ndevs = 0;
    unsigned int i;

    testDriverLock(driver);
    for (i = 0; i < driver->devs.count; i++)
        if ((cap == NULL) ||
            virNodeDeviceHasCap(driver->devs.objs[i], cap))
            ++ndevs;
    testDriverUnlock(driver);

    return ndevs;
}

static int
testNodeListDevices(virConnectPtr conn,
                    const char *cap,
                    char **const names,
                    int maxnames,
                    unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr driver = conn->privateData;
    int ndevs = 0;
    unsigned int i;

    testDriverLock(driver);
    for (i = 0; i < driver->devs.count && ndevs < maxnames; i++) {
        virNodeDeviceObjLock(driver->devs.objs[i]);
        if (cap == NULL ||
            virNodeDeviceHasCap(driver->devs.objs[i], cap)) {
            if ((names[ndevs++] = strdup(driver->devs.objs[i]->def->name)) == NULL) {
                virNodeDeviceObjUnlock(driver->devs.objs[i]);
                goto failure;
            }
        }
        virNodeDeviceObjUnlock(driver->devs.objs[i]);
    }
    testDriverUnlock(driver);

    return ndevs;

 failure:
    testDriverUnlock(driver);
    --ndevs;
    while (--ndevs >= 0)
        VIR_FREE(names[ndevs]);
    return -1;
}

static virNodeDevicePtr
testNodeDeviceLookupByName(virConnectPtr conn, const char *name)
{
    testConnPtr driver = conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevicePtr ret = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE, NULL);
        goto cleanup;
    }

    ret = virGetNodeDevice(conn, name);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}

static char *
testNodeDeviceDumpXML(virNodeDevicePtr dev,
                      unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    ret = virNodeDeviceDefFormat(obj->def);

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}

static char *
testNodeDeviceGetParent(virNodeDevicePtr dev)
{
    testConnPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    if (obj->def->parent) {
        ret = strdup(obj->def->parent);
        if (!ret)
            virReportOOMError();
    } else {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("no parent for this device"));
    }

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


static int
testNodeDeviceNumOfCaps(virNodeDevicePtr dev)
{
    testConnPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                 _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    for (caps = obj->def->caps; caps; caps = caps->next)
        ++ncaps;
    ret = ncaps;

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}


static int
testNodeDeviceListCaps(virNodeDevicePtr dev, char **const names, int maxnames)
{
    testConnPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE,
                                _("no node device with matching name '%s'"),
                                 dev->name);
        goto cleanup;
    }

    for (caps = obj->def->caps; caps && ncaps < maxnames; caps = caps->next) {
        names[ncaps] = strdup(virNodeDevCapTypeToString(caps->type));
        if (names[ncaps++] == NULL)
            goto cleanup;
    }
    ret = ncaps;

cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    if (ret == -1) {
        --ncaps;
        while (--ncaps >= 0)
            VIR_FREE(names[ncaps]);
    }
    return ret;
}

static virNodeDevicePtr
testNodeDeviceCreateXML(virConnectPtr conn,
                        const char *xmlDesc,
                        unsigned int flags ATTRIBUTE_UNUSED)
{
    testConnPtr driver = conn->privateData;
    virNodeDeviceDefPtr def = NULL;
    virNodeDeviceObjPtr obj = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;
    virNodeDevicePtr dev = NULL;
    virNodeDevCapsDefPtr caps;

    testDriverLock(driver);

    def = virNodeDeviceDefParseString(xmlDesc, CREATE_DEVICE);
    if (def == NULL) {
        goto cleanup;
    }

    /* We run these next two simply for validation */
    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) == -1) {
        goto cleanup;
    }

    if (virNodeDeviceGetParentHost(&driver->devs,
                                   def->name,
                                   def->parent,
                                   &parent_host) == -1) {
        goto cleanup;
    }

    /* 'name' is supposed to be filled in by the node device backend, which
     * we don't have. Use WWPN instead. */
    VIR_FREE(def->name);
    if (!(def->name = strdup(wwpn))) {
        virReportOOMError();
        goto cleanup;
    }

    /* Fill in a random 'host' value, since this would also come from
     * the backend */
    caps = def->caps;
    while (caps) {
        if (caps->type != VIR_NODE_DEV_CAP_SCSI_HOST)
            continue;

        caps->data.scsi_host.host = virRandom(1024);
        caps = caps->next;
    }


    if (!(obj = virNodeDeviceAssignDef(&driver->devs, def))) {
        goto cleanup;
    }
    virNodeDeviceObjUnlock(obj);

    dev = virGetNodeDevice(conn, def->name);
    def = NULL;
cleanup:
    testDriverUnlock(driver);
    if (def)
        virNodeDeviceDefFree(def);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return dev;
}

static int
testNodeDeviceDestroy(virNodeDevicePtr dev)
{
    int ret = 0;
    testConnPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj = NULL;
    char *parent_name = NULL, *wwnn = NULL, *wwpn = NULL;
    int parent_host = -1;

    testDriverLock(driver);
    obj = virNodeDeviceFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virNodeDeviceReportError(VIR_ERR_NO_NODE_DEVICE, NULL);
        goto out;
    }

    if (virNodeDeviceGetWWNs(obj->def, &wwnn, &wwpn) == -1) {
        goto out;
    }

    parent_name = strdup(obj->def->parent);
    if (parent_name == NULL) {
        virReportOOMError();
        goto out;
    }

    /* virNodeDeviceGetParentHost will cause the device object's lock to be
     * taken, so we have to dup the parent's name and drop the lock
     * before calling it.  We don't need the reference to the object
     * any more once we have the parent's name.  */
    virNodeDeviceObjUnlock(obj);

    /* We do this just for basic validation */
    if (virNodeDeviceGetParentHost(&driver->devs,
                                   dev->name,
                                   parent_name,
                                   &parent_host) == -1) {
        obj = NULL;
        goto out;
    }

    virNodeDeviceObjLock(obj);
    virNodeDeviceObjRemove(&driver->devs, obj);

out:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    VIR_FREE(parent_name);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}


/* Domain event implementations */
static int
testDomainEventRegister(virConnectPtr conn,
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
testDomainEventDeregister(virConnectPtr conn,
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


static int
testDomainEventRegisterAny(virConnectPtr conn,
                           virDomainPtr dom,
                           int eventID,
                           virConnectDomainEventGenericCallback callback,
                           void *opaque,
                           virFreeCallback freecb)
{
    testConnPtr driver = conn->privateData;
    int ret;

    testDriverLock(driver);
    ret = virDomainEventCallbackListAddID(conn, driver->domainEventCallbacks,
                                          dom, eventID,
                                          callback, opaque, freecb);
    testDriverUnlock(driver);

    return ret;
}

static int
testDomainEventDeregisterAny(virConnectPtr conn,
                             int callbackID)
{
    testConnPtr driver = conn->privateData;
    int ret;

    testDriverLock(driver);
    if (driver->domainEventDispatching)
        ret = virDomainEventCallbackListMarkDeleteID(conn, driver->domainEventCallbacks,
                                                     callbackID);
    else
        ret = virDomainEventCallbackListRemoveID(conn, driver->domainEventCallbacks,
                                                 callbackID);
    testDriverUnlock(driver);

    return ret;
}


static void testDomainEventDispatchFunc(virConnectPtr conn,
                                        virDomainEventPtr event,
                                        virConnectDomainEventGenericCallback cb,
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

static virDrvOpenStatus testSecretOpen(virConnectPtr conn,
                                       virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                       int flags ATTRIBUTE_UNUSED) {
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->secretPrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testSecretClose(virConnectPtr conn) {
    conn->secretPrivateData = NULL;
    return 0;
}


static virDrvOpenStatus testNWFilterOpen(virConnectPtr conn,
                                         virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                         int flags ATTRIBUTE_UNUSED) {
    if (STRNEQ(conn->driver->name, "Test"))
        return VIR_DRV_OPEN_DECLINED;

    conn->nwfilterPrivateData = conn->privateData;
    return VIR_DRV_OPEN_SUCCESS;
}

static int testNWFilterClose(virConnectPtr conn) {
    conn->nwfilterPrivateData = NULL;
    return 0;
}

static virDriver testDriver = {
    VIR_DRV_TEST,
    "Test",
    testOpen, /* open */
    testClose, /* close */
    NULL, /* supports_feature */
    NULL, /* type */
    testGetVersion, /* version */
    NULL, /* libvirtVersion (impl. in libvirt.c) */
    virGetHostname, /* getHostname */
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
    testDomainPinVcpu, /* domainPinVcpu */
    testDomainGetVcpus, /* domainGetVcpus */
    testDomainGetMaxVcpus, /* domainGetMaxVcpus */
    NULL, /* domainGetSecurityLabel */
    NULL, /* nodeGetSecurityModel */
    testDomainDumpXML, /* domainDumpXML */
    NULL, /* domainXMLFromNative */
    NULL, /* domainXMLToNative */
    testListDefinedDomains, /* listDefinedDomains */
    testNumOfDefinedDomains, /* numOfDefinedDomains */
    testDomainCreate, /* domainCreate */
    testDomainDefineXML, /* domainDefineXML */
    testDomainUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainAttachDeviceFlags */
    NULL, /* domainDetachDevice */
    NULL, /* domainDetachDeviceFlags */
    NULL, /* domainUpdateDeviceFlags */
    testDomainGetAutostart, /* domainGetAutostart */
    testDomainSetAutostart, /* domainSetAutostart */
    testDomainGetSchedulerType, /* domainGetSchedulerType */
    testDomainGetSchedulerParams, /* domainGetSchedulerParameters */
    testDomainSetSchedulerParams, /* domainSetSchedulerParameters */
    NULL, /* domainMigratePrepare */
    NULL, /* domainMigratePerform */
    NULL, /* domainMigrateFinish */
    testDomainBlockStats, /* domainBlockStats */
    testDomainInterfaceStats, /* domainInterfaceStats */
    NULL, /* domainMemoryStats */
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
    NULL, /* domainMigratePrepareTunnel */
    testIsEncrypted, /* isEncrypted */
    testIsSecure, /* isEncrypted */
    testDomainIsActive, /* domainIsActive */
    testDomainIsPersistent, /* domainIsPersistent */
    NULL, /* cpuCompare */
    NULL, /* cpuBaseline */
    NULL, /* domainGetJobInfo */
    NULL, /* domainAbortJob */
    NULL, /* domainMigrateSetMaxDowntime */
    testDomainEventRegisterAny, /* domainEventRegisterAny */
    testDomainEventDeregisterAny, /* domainEventDeregisterAny */
    NULL, /* domainManagedSave */
    NULL, /* domainHasManagedSaveImage */
    NULL, /* domainManagedSaveRemove */
    NULL, /* domainSnapshotCreateXML */
    NULL, /* domainSnapshotDumpXML */
    NULL, /* domainSnapshotNum */
    NULL, /* domainSnapshotListNames */
    NULL, /* domainSnapshotLookupByName */
    NULL, /* domainHasCurrentSnapshot */
    NULL, /* domainSnapshotCurrent */
    NULL, /* domainRevertToSnapshot */
    NULL, /* domainSnapshotDelete */
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
    testNetworkIsActive, /* networkIsActive */
    testNetworkIsPersistent, /* networkIsPersistent */
};

static virInterfaceDriver testInterfaceDriver = {
    "Test",                     /* name */
    testOpenInterface,          /* open */
    testCloseInterface,         /* close */
    testNumOfInterfaces,        /* numOfInterfaces */
    testListInterfaces,         /* listInterfaces */
    testNumOfDefinedInterfaces, /* numOfDefinedInterfaces */
    testListDefinedInterfaces,  /* listDefinedInterfaces */
    testLookupInterfaceByName,  /* interfaceLookupByName */
    testLookupInterfaceByMACString, /* interfaceLookupByMACString */
    testInterfaceGetXMLDesc,    /* interfaceGetXMLDesc */
    testInterfaceDefineXML,     /* interfaceDefineXML */
    testInterfaceUndefine,      /* interfaceUndefine */
    testInterfaceCreate,        /* interfaceCreate */
    testInterfaceDestroy,       /* interfaceDestroy */
    testInterfaceIsActive,      /* interfaceIsActive */
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
    .poolIsActive = testStoragePoolIsActive,
    .poolIsPersistent = testStoragePoolIsPersistent,
};

static virDeviceMonitor testDevMonitor = {
    .name = "Test",
    .open = testDevMonOpen,
    .close = testDevMonClose,

    .numOfDevices = testNodeNumOfDevices,
    .listDevices = testNodeListDevices,
    .deviceLookupByName = testNodeDeviceLookupByName,
    .deviceDumpXML = testNodeDeviceDumpXML,
    .deviceGetParent = testNodeDeviceGetParent,
    .deviceNumOfCaps = testNodeDeviceNumOfCaps,
    .deviceListCaps = testNodeDeviceListCaps,
    .deviceCreateXML = testNodeDeviceCreateXML,
    .deviceDestroy = testNodeDeviceDestroy,
};

static virSecretDriver testSecretDriver = {
    .name = "Test",
    .open = testSecretOpen,
    .close = testSecretClose,
};


static virNWFilterDriver testNWFilterDriver = {
    .name = "Test",
    .open = testNWFilterOpen,
    .close = testNWFilterClose,
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
    if (virRegisterInterfaceDriver(&testInterfaceDriver) < 0)
        return -1;
    if (virRegisterStorageDriver(&testStorageDriver) < 0)
        return -1;
    if (virRegisterDeviceMonitor(&testDevMonitor) < 0)
        return -1;
    if (virRegisterSecretDriver(&testSecretDriver) < 0)
        return -1;
    if (virRegisterNWFilterDriver(&testNWFilterDriver) < 0)
        return -1;

    return 0;
}
