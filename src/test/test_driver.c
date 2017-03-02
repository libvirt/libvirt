/*
 * test_driver.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include <libxml/xpathInternals.h>


#include "virerror.h"
#include "datatypes.h"
#include "test_driver.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "capabilities.h"
#include "configmake.h"
#include "viralloc.h"
#include "network_conf.h"
#include "interface_conf.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "network_event.h"
#include "snapshot_conf.h"
#include "fdstream.h"
#include "storage_conf.h"
#include "storage_event.h"
#include "node_device_conf.h"
#include "virnodedeviceobj.h"
#include "node_device_event.h"
#include "virxml.h"
#include "virthread.h"
#include "virlog.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virrandom.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "virauth.h"
#include "viratomic.h"
#include "virdomainobjlist.h"
#include "virinterfaceobj.h"
#include "virhostcpu.h"

#define VIR_FROM_THIS VIR_FROM_TEST

VIR_LOG_INIT("test.test_driver");


#define MAX_CPUS 128

struct _testCell {
    unsigned long mem;
    unsigned long freeMem;
    int numCpus;
    virCapsHostNUMACellCPU cpus[MAX_CPUS];
};
typedef struct _testCell testCell;
typedef struct _testCell *testCellPtr;

#define MAX_CELLS 128

struct _testAuth {
    char *username;
    char *password;
};
typedef struct _testAuth testAuth;
typedef struct _testAuth *testAuthPtr;

struct _testDriver {
    virMutex lock;

    virNodeInfo nodeInfo;
    virInterfaceObjList ifaces;
    bool transaction_running;
    virInterfaceObjList backupIfaces;
    virStoragePoolObjList pools;
    virNodeDeviceObjList devs;
    int numCells;
    testCell cells[MAX_CELLS];
    size_t numAuths;
    testAuthPtr auths;

    /* virAtomic access only */
    volatile int nextDomID;

    /* immutable pointer, immutable object after being initialized with
     * testBuildCapabilities */
    virCapsPtr caps;

    /* immutable pointer, immutable object */
    virDomainXMLOptionPtr xmlopt;

    /* immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;
    virNetworkObjListPtr networks;
    virObjectEventStatePtr eventState;
};
typedef struct _testDriver testDriver;
typedef testDriver *testDriverPtr;

static testDriverPtr defaultConn;
static int defaultConnections;
static virMutex defaultLock = VIR_MUTEX_INITIALIZER;

#define TEST_MODEL "i686"
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

static void
testDriverFree(testDriverPtr driver)
{
    if (!driver)
        return;

    virObjectUnref(driver->caps);
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->domains);
    virNodeDeviceObjListFree(&driver->devs);
    virObjectUnref(driver->networks);
    virInterfaceObjListFree(&driver->ifaces);
    virStoragePoolObjListFree(&driver->pools);
    virObjectUnref(driver->eventState);
    virMutexUnlock(&driver->lock);
    virMutexDestroy(&driver->lock);

    VIR_FREE(driver);
}


static void testDriverLock(testDriverPtr driver)
{
    virMutexLock(&driver->lock);
}

static void testDriverUnlock(testDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}

static void testObjectEventQueue(testDriverPtr driver,
                                 virObjectEventPtr event)
{
    if (!event)
        return;

    virObjectEventStateQueue(driver->eventState, event);
}

#define TEST_NAMESPACE_HREF "http://libvirt.org/schemas/domain/test/1.0"

typedef struct _testDomainNamespaceDef testDomainNamespaceDef;
typedef testDomainNamespaceDef *testDomainNamespaceDefPtr;
struct _testDomainNamespaceDef {
    int runstate;
    bool transient;
    bool hasManagedSave;

    unsigned int num_snap_nodes;
    xmlNodePtr *snap_nodes;
};

static void
testDomainDefNamespaceFree(void *data)
{
    testDomainNamespaceDefPtr nsdata = data;
    size_t i;

    if (!nsdata)
        return;

    for (i = 0; i < nsdata->num_snap_nodes; i++)
        xmlFreeNode(nsdata->snap_nodes[i]);

    VIR_FREE(nsdata->snap_nodes);
    VIR_FREE(nsdata);
}

static int
testDomainDefNamespaceParse(xmlDocPtr xml ATTRIBUTE_UNUSED,
                            xmlNodePtr root ATTRIBUTE_UNUSED,
                            xmlXPathContextPtr ctxt,
                            void **data)
{
    testDomainNamespaceDefPtr nsdata = NULL;
    xmlNodePtr *nodes = NULL;
    int tmp, n;
    size_t i;
    unsigned int tmpuint;

    if (xmlXPathRegisterNs(ctxt, BAD_CAST "test",
                           BAD_CAST TEST_NAMESPACE_HREF) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%s'"),
                       TEST_NAMESPACE_HREF);
        return -1;
    }

    if (VIR_ALLOC(nsdata) < 0)
        return -1;

    n = virXPathNodeSet("./test:domainsnapshot", ctxt, &nodes);
    if (n < 0)
        goto error;

    if (n && VIR_ALLOC_N(nsdata->snap_nodes, n) < 0)
        goto error;

    for (i = 0; i < n; i++) {
        xmlNodePtr newnode = xmlCopyNode(nodes[i], 1);
        if (!newnode) {
            virReportOOMError();
            goto error;
        }

        nsdata->snap_nodes[nsdata->num_snap_nodes] = newnode;
        nsdata->num_snap_nodes++;
    }
    VIR_FREE(nodes);

    tmp = virXPathBoolean("boolean(./test:transient)", ctxt);
    if (tmp == -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("invalid transient"));
        goto error;
    }
    nsdata->transient = tmp;

    tmp = virXPathBoolean("boolean(./test:hasmanagedsave)", ctxt);
    if (tmp == -1) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("invalid hasmanagedsave"));
        goto error;
    }
    nsdata->hasManagedSave = tmp;

    tmp = virXPathUInt("string(./test:runstate)", ctxt, &tmpuint);
    if (tmp == 0) {
        if (tmpuint >= VIR_DOMAIN_LAST) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("runstate '%d' out of range'"), tmpuint);
            goto error;
        }
        nsdata->runstate = tmpuint;
    } else if (tmp == -1) {
        nsdata->runstate = VIR_DOMAIN_RUNNING;
    } else if (tmp == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid runstate"));
        goto error;
    }

    if (nsdata->transient && nsdata->runstate == VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
            _("transient domain cannot have runstate 'shutoff'"));
        goto error;
    }
    if (nsdata->hasManagedSave && nsdata->runstate != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
            _("domain with managedsave data can only have runstate 'shutoff'"));
        goto error;
    }

    *data = nsdata;
    return 0;

 error:
    VIR_FREE(nodes);
    testDomainDefNamespaceFree(nsdata);
    return -1;
}

static virCapsPtr
testBuildCapabilities(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    virCapsPtr caps;
    virCapsGuestPtr guest;
    int guest_types[] = { VIR_DOMAIN_OSTYPE_HVM,
                          VIR_DOMAIN_OSTYPE_XEN };
    size_t i, j;

    if ((caps = virCapabilitiesNew(VIR_ARCH_I686, false, false)) == NULL)
        goto error;

    if (virCapabilitiesAddHostFeature(caps, "pae") < 0)
        goto error;
    if (virCapabilitiesAddHostFeature(caps, "nonpae") < 0)
        goto error;

    if (VIR_ALLOC_N(caps->host.pagesSize, 2) < 0)
        goto error;

    caps->host.pagesSize[caps->host.nPagesSize++] = 4;
    caps->host.pagesSize[caps->host.nPagesSize++] = 2048;

    for (i = 0; i < privconn->numCells; i++) {
        virCapsHostNUMACellCPUPtr cpu_cells;
        virCapsHostNUMACellPageInfoPtr pages;
        size_t nPages;

        if (VIR_ALLOC_N(cpu_cells, privconn->cells[i].numCpus) < 0 ||
            VIR_ALLOC_N(pages, caps->host.nPagesSize) < 0) {
                VIR_FREE(cpu_cells);
                goto error;
            }

        nPages = caps->host.nPagesSize;

        memcpy(cpu_cells, privconn->cells[i].cpus,
               sizeof(*cpu_cells) * privconn->cells[i].numCpus);

        for (j = 0; j < nPages; j++)
            pages[j].size = caps->host.pagesSize[j];

        pages[0].avail = privconn->cells[i].mem / pages[0].size;

        if (virCapabilitiesAddHostNUMACell(caps, i, privconn->cells[i].mem,
                                           privconn->cells[i].numCpus,
                                           cpu_cells, 0, NULL, nPages, pages) < 0)
            goto error;
    }

    for (i = 0; i < ARRAY_CARDINALITY(guest_types); i++) {
        if ((guest = virCapabilitiesAddGuest(caps,
                                             guest_types[i],
                                             VIR_ARCH_I686,
                                             TEST_EMULATOR,
                                             NULL,
                                             0,
                                             NULL)) == NULL)
            goto error;

        if (virCapabilitiesAddGuestDomain(guest,
                                          VIR_DOMAIN_VIRT_TEST,
                                          NULL,
                                          NULL,
                                          0,
                                          NULL) == NULL)
            goto error;

        if (virCapabilitiesAddGuestFeature(guest, "pae", true, true) == NULL)
            goto error;
        if (virCapabilitiesAddGuestFeature(guest, "nonpae", true, true) == NULL)
            goto error;
    }

    caps->host.nsecModels = 1;
    if (VIR_ALLOC_N(caps->host.secModels, caps->host.nsecModels) < 0)
        goto error;
    if (VIR_STRDUP(caps->host.secModels[0].model, "testSecurity") < 0)
        goto error;

    if (VIR_STRDUP(caps->host.secModels[0].doi, "") < 0)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}


static testDriverPtr
testDriverNew(void)
{
    virDomainXMLNamespace ns = {
        .parse = testDomainDefNamespaceParse,
        .free = testDomainDefNamespaceFree,
    };
    testDriverPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (virMutexInit(&ret->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        goto error;
    }

    if (!(ret->xmlopt = virDomainXMLOptionNew(NULL, NULL, &ns)) ||
        !(ret->eventState = virObjectEventStateNew()) ||
        !(ret->domains = virDomainObjListNew()) ||
        !(ret->networks = virNetworkObjListNew()))
        goto error;

    virAtomicIntSet(&ret->nextDomID, 1);

    return ret;

 error:
    testDriverFree(ret);
    return NULL;
}


static const char *defaultConnXML =
"<node>"
"<domain type='test'>"
"  <name>test</name>"
"  <uuid>6695eb01-f6a4-8304-79aa-97f2502e193f</uuid>"
"  <memory>8388608</memory>"
"  <currentMemory>2097152</currentMemory>"
"  <vcpu>2</vcpu>"
"  <os>"
"    <type>hvm</type>"
"  </os>"
"</domain>"
""
"<network>"
"  <name>default</name>"
"  <uuid>dd8fe884-6c02-601e-7551-cca97df1c5df</uuid>"
"  <bridge name='virbr0'/>"
"  <forward/>"
"  <ip address='192.168.122.1' netmask='255.255.255.0'>"
"    <dhcp>"
"      <range start='192.168.122.2' end='192.168.122.254'/>"
"    </dhcp>"
"  </ip>"
"</network>"
""
"<interface type=\"ethernet\" name=\"eth1\">"
"  <start mode=\"onboot\"/>"
"  <mac address=\"aa:bb:cc:dd:ee:ff\"/>"
"  <mtu size=\"1492\"/>"
"  <protocol family=\"ipv4\">"
"    <ip address=\"192.168.0.5\" prefix=\"24\"/>"
"    <route gateway=\"192.168.0.1\"/>"
"  </protocol>"
"</interface>"
""
"<pool type='dir'>"
"  <name>default-pool</name>"
"  <uuid>dfe224cb-28fb-8dd0-c4b2-64eb3f0f4566</uuid>"
"  <target>"
"    <path>/default-pool</path>"
"  </target>"
"</pool>"
""
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
"</device>"
"<device>"
"  <name>scsi_host1</name>"
"  <parent>computer</parent>"
"  <capability type='scsi_host'>"
"    <host>1</host>"
"    <unique_id>0</unique_id>"
"    <capability type='fc_host'>"
"      <wwnn>2000000012341234</wwnn>"
"      <wwpn>1000000012341234</wwpn>"
"      <fabric_wwn>2000000043214321</fabric_wwn>"
"    </capability>"
"    <capability type='vport_ops'>"
"      <max_vports>127</max_vports>"
"      <vports>1</vports>"
"    </capability>"
"  </capability>"
"</device>"
"<device>"
"  <name>scsi_host2</name>"
"  <parent>computer</parent>"
"  <capability type='scsi_host'>"
"    <host>2</host>"
"    <unique_id>1</unique_id>"
"    <capability type='fc_host'>"
"      <wwnn>2000000056785678</wwnn>"
"      <wwpn>1000000056785678</wwpn>"
"      <fabric_wwn>2000000087658765</fabric_wwn>"
"    </capability>"
"    <capability type='vport_ops'>"
"      <max_vports>127</max_vports>"
"      <vports>0</vports>"
"    </capability>"
"  </capability>"
"</device>"
"<device>"
"  <name>scsi_host11</name>"
"  <parent>scsi_host1</parent>"
"  <capability type='scsi_host'>"
"    <host>11</host>"
"    <unique_id>10</unique_id>"
"    <capability type='fc_host'>"
"      <wwnn>2000000034563456</wwnn>"
"      <wwpn>1000000034563456</wwpn>"
"      <fabric_wwn>2000000043214321</fabric_wwn>"
"    </capability>"
"  </capability>"
 "</device>"
"</node>";


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

static const unsigned long long defaultPoolCap = (100 * 1024 * 1024 * 1024ull);
static const unsigned long long defaultPoolAlloc;

static int testStoragePoolObjSetDefaults(virStoragePoolObjPtr pool);
static int testNodeGetInfo(virConnectPtr conn, virNodeInfoPtr info);

static virDomainObjPtr
testDomObjFromDomain(virDomainPtr domain)
{
    virDomainObjPtr vm;
    testDriverPtr driver = domain->conn->privateData;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    vm = virDomainObjListFindByUUIDRef(driver->domains, domain->uuid);
    if (!vm) {
        virUUIDFormat(domain->uuid, uuidstr);
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching uuid '%s' (%s)"),
                       uuidstr, domain->name);
    }

    return vm;
}

static char *
testDomainGenerateIfname(virDomainDefPtr domdef)
{
    int maxif = 1024;
    int ifctr;
    size_t i;

    for (ifctr = 0; ifctr < maxif; ++ifctr) {
        char *ifname;
        int found = 0;

        if (virAsprintf(&ifname, "testnet%d", ifctr) < 0)
            return NULL;

        /* Generate network interface names */
        for (i = 0; i < domdef->nnets; i++) {
            if (domdef->nets[i]->ifname &&
                STREQ(domdef->nets[i]->ifname, ifname)) {
                found = 1;
                break;
            }
        }

        if (!found)
            return ifname;
        VIR_FREE(ifname);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Exceeded max iface limit %d"), maxif);
    return NULL;
}

static int
testDomainGenerateIfnames(virDomainDefPtr domdef)
{
    size_t i = 0;

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


static void
testDomainShutdownState(virDomainPtr domain,
                        virDomainObjPtr privdom,
                        virDomainShutoffReason reason)
{
    virDomainObjRemoveTransientDef(privdom);
    virDomainObjSetState(privdom, VIR_DOMAIN_SHUTOFF, reason);

    if (domain)
        domain->id = -1;
}

/* Set up domain runtime state */
static int
testDomainStartState(testDriverPtr privconn,
                     virDomainObjPtr dom,
                     virDomainRunningReason reason)
{
    int ret = -1;

    virDomainObjSetState(dom, VIR_DOMAIN_RUNNING, reason);
    dom->def->id = virAtomicIntAdd(&privconn->nextDomID, 1);

    if (virDomainObjSetDefTransient(privconn->caps,
                                    privconn->xmlopt,
                                    dom) < 0) {
        goto cleanup;
    }

    dom->hasManagedSave = false;
    ret = 0;
 cleanup:
    if (ret < 0)
        testDomainShutdownState(NULL, dom, VIR_DOMAIN_SHUTOFF_FAILED);
    return ret;
}


static char *testBuildFilename(const char *relativeTo,
                               const char *filename)
{
    char *offset;
    int baseLen;
    char *ret;

    if (!filename || filename[0] == '\0')
        return NULL;
    if (filename[0] == '/') {
        ignore_value(VIR_STRDUP(ret, filename));
        return ret;
    }

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
        ignore_value(VIR_STRDUP(ret, filename));
        return ret;
    }
}

static xmlNodePtr
testParseXMLDocFromFile(xmlNodePtr node, const char *file, const char *type)
{
    xmlNodePtr ret = NULL;
    xmlDocPtr doc = NULL;
    char *absFile = NULL;
    char *relFile = virXMLPropString(node, "file");

    if (relFile != NULL) {
        absFile = testBuildFilename(file, relFile);
        VIR_FREE(relFile);
        if (!absFile) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("resolving %s filename"), type);
            return NULL;
        }

        if (!(doc = virXMLParse(absFile, NULL, type)))
            goto error;

        ret = xmlCopyNode(xmlDocGetRootElement(doc), 1);
        if (!ret) {
            virReportOOMError();
            goto error;
        }
        xmlReplaceNode(node, ret);
        xmlFreeNode(node);
    } else {
        ret = node;
    }

 error:
    xmlFreeDoc(doc);
    VIR_FREE(absFile);
    return ret;
}

static int
testParseNodeInfo(virNodeInfoPtr nodeInfo, xmlXPathContextPtr ctxt)
{
    char *str;
    long l;
    int ret;

    ret = virXPathLong("string(/node/cpu/nodes[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->nodes = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu nodes value"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/sockets[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->sockets = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu sockets value"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/cores[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->cores = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu cores value"));
        goto error;
    }

    ret = virXPathLong("string(/node/cpu/threads[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->threads = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu threads value"));
        goto error;
    }

    nodeInfo->cpus = (nodeInfo->cores * nodeInfo->threads *
                      nodeInfo->sockets * nodeInfo->nodes);
    ret = virXPathLong("string(/node/cpu/active[1])", ctxt, &l);
    if (ret == 0) {
        if (l < nodeInfo->cpus)
            nodeInfo->cpus = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu active value"));
        goto error;
    }
    ret = virXPathLong("string(/node/cpu/mhz[1])", ctxt, &l);
    if (ret == 0) {
        nodeInfo->mhz = l;
    } else if (ret == -2) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node cpu mhz value"));
        goto error;
    }

    str = virXPathString("string(/node/cpu/model[1])", ctxt);
    if (str != NULL) {
        if (virStrcpyStatic(nodeInfo->model, str) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("invalid node memory value"));
        goto error;
    }

    return 0;
 error:
    return -1;
}

static int
testParseDomainSnapshots(testDriverPtr privconn,
                         virDomainObjPtr domobj,
                         const char *file,
                         xmlXPathContextPtr ctxt)
{
    size_t i;
    int ret = -1;
    testDomainNamespaceDefPtr nsdata = domobj->def->namespaceData;
    xmlNodePtr *nodes = nsdata->snap_nodes;

    for (i = 0; i < nsdata->num_snap_nodes; i++) {
        virDomainSnapshotObjPtr snap;
        virDomainSnapshotDefPtr def;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file,
                                                  "domainsnapshot");
        if (!node)
            goto error;

        def = virDomainSnapshotDefParseNode(ctxt->doc, node,
                                            privconn->caps,
                                            privconn->xmlopt,
                                            VIR_DOMAIN_SNAPSHOT_PARSE_DISKS |
                                            VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL |
                                            VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE);
        if (!def)
            goto error;

        if (!(snap = virDomainSnapshotAssignDef(domobj->snapshots, def))) {
            virDomainSnapshotDefFree(def);
            goto error;
        }

        if (def->current) {
            if (domobj->current_snapshot) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("more than one snapshot claims to be active"));
                goto error;
            }

            domobj->current_snapshot = snap;
        }
    }

    if (virDomainSnapshotUpdateRelations(domobj->snapshots) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Snapshots have inconsistent relations for "
                         "domain %s"), domobj->def->name);
        goto error;
    }

    ret = 0;
 error:
    return ret;
}

static int
testParseDomains(testDriverPtr privconn,
                 const char *file,
                 xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virDomainObjPtr obj;

    num = virXPathNodeSet("/node/domain", ctxt, &nodes);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        virDomainDefPtr def;
        testDomainNamespaceDefPtr nsdata;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file, "domain");
        if (!node)
            goto error;

        def = virDomainDefParseNode(ctxt->doc, node,
                                    privconn->caps, privconn->xmlopt, NULL,
                                    VIR_DOMAIN_DEF_PARSE_INACTIVE);
        if (!def)
            goto error;

        if (testDomainGenerateIfnames(def) < 0 ||
            !(obj = virDomainObjListAdd(privconn->domains,
                                        def,
                                        privconn->xmlopt,
                                        0, NULL))) {
            virDomainDefFree(def);
            goto error;
        }

        if (testParseDomainSnapshots(privconn, obj, file, ctxt) < 0) {
            virObjectUnlock(obj);
            goto error;
        }

        nsdata = def->namespaceData;
        obj->persistent = !nsdata->transient;
        obj->hasManagedSave = nsdata->hasManagedSave;

        if (nsdata->runstate != VIR_DOMAIN_SHUTOFF) {
            if (testDomainStartState(privconn, obj,
                                     VIR_DOMAIN_RUNNING_BOOTED) < 0) {
                virObjectUnlock(obj);
                goto error;
            }
        } else {
            testDomainShutdownState(NULL, obj, 0);
        }
        virDomainObjSetState(obj, nsdata->runstate, 0);

        virObjectUnlock(obj);
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testParseNetworks(testDriverPtr privconn,
                  const char *file,
                  xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virNetworkObjPtr obj;

    num = virXPathNodeSet("/node/network", ctxt, &nodes);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        virNetworkDefPtr def;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file, "network");
        if (!node)
            goto error;

        def = virNetworkDefParseNode(ctxt->doc, node);
        if (!def)
            goto error;

        if (!(obj = virNetworkAssignDef(privconn->networks, def, 0))) {
            virNetworkDefFree(def);
            goto error;
        }

        obj->active = 1;
        virNetworkObjEndAPI(&obj);
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testParseInterfaces(testDriverPtr privconn,
                    const char *file,
                    xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virInterfaceObjPtr obj;

    num = virXPathNodeSet("/node/interface", ctxt, &nodes);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        virInterfaceDefPtr def;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file,
                                                   "interface");
        if (!node)
            goto error;

        def = virInterfaceDefParseNode(ctxt->doc, node);
        if (!def)
            goto error;

        if (!(obj = virInterfaceObjAssignDef(&privconn->ifaces, def))) {
            virInterfaceDefFree(def);
            goto error;
        }

        obj->active = 1;
        virInterfaceObjUnlock(obj);
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testOpenVolumesForPool(const char *file,
                       xmlXPathContextPtr ctxt,
                       virStoragePoolObjPtr pool,
                       int poolidx)
{
    char *vol_xpath;
    size_t i;
    int num, ret = -1;
    xmlNodePtr *nodes = NULL;
    virStorageVolDefPtr def = NULL;

    /* Find storage volumes */
    if (virAsprintf(&vol_xpath, "/node/pool[%d]/volume", poolidx) < 0)
        goto error;

    num = virXPathNodeSet(vol_xpath, ctxt, &nodes);
    VIR_FREE(vol_xpath);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file,
                                                   "volume");
        if (!node)
            goto error;

        def = virStorageVolDefParseNode(pool->def, ctxt->doc, node, 0);
        if (!def)
            goto error;

        if (def->target.path == NULL) {
            if (virAsprintf(&def->target.path, "%s/%s",
                            pool->def->target.path,
                            def->name) == -1)
                goto error;
        }

        if (!def->key && VIR_STRDUP(def->key, def->target.path) < 0)
            goto error;
        if (VIR_APPEND_ELEMENT_COPY(pool->volumes.objs, pool->volumes.count, def) < 0)
            goto error;

        pool->def->allocation += def->target.allocation;
        pool->def->available = (pool->def->capacity -
                                pool->def->allocation);
        def = NULL;
    }

    ret = 0;
 error:
    virStorageVolDefFree(def);
    VIR_FREE(nodes);
    return ret;
}

static int
testParseStorage(testDriverPtr privconn,
                 const char *file,
                 xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virStoragePoolObjPtr obj;

    num = virXPathNodeSet("/node/pool", ctxt, &nodes);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        virStoragePoolDefPtr def;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file,
                                                   "pool");
        if (!node)
            goto error;

        def = virStoragePoolDefParseNode(ctxt->doc, node);
        if (!def)
            goto error;

        if (!(obj = virStoragePoolObjAssignDef(&privconn->pools,
                                                def))) {
            virStoragePoolDefFree(def);
            goto error;
        }

        if (testStoragePoolObjSetDefaults(obj) == -1) {
            virStoragePoolObjUnlock(obj);
            goto error;
        }
        obj->active = 1;

        /* Find storage volumes */
        if (testOpenVolumesForPool(file, ctxt, obj, i+1) < 0) {
            virStoragePoolObjUnlock(obj);
            goto error;
        }

        virStoragePoolObjUnlock(obj);
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testParseNodedevs(testDriverPtr privconn,
                  const char *file,
                  xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;
    virNodeDeviceObjPtr obj;

    num = virXPathNodeSet("/node/device", ctxt, &nodes);
    if (num < 0)
        goto error;

    for (i = 0; i < num; i++) {
        virNodeDeviceDefPtr def;
        xmlNodePtr node = testParseXMLDocFromFile(nodes[i], file,
                                                  "nodedev");
        if (!node)
            goto error;

        def = virNodeDeviceDefParseNode(ctxt->doc, node, 0, NULL);
        if (!def)
            goto error;

        if (!(obj = virNodeDeviceObjAssignDef(&privconn->devs, def))) {
            virNodeDeviceDefFree(def);
            goto error;
        }

        virNodeDeviceObjUnlock(obj);
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testParseAuthUsers(testDriverPtr privconn,
                   xmlXPathContextPtr ctxt)
{
    int num, ret = -1;
    size_t i;
    xmlNodePtr *nodes = NULL;

    num = virXPathNodeSet("/node/auth/user", ctxt, &nodes);
    if (num < 0)
        goto error;

    privconn->numAuths = num;
    if (num && VIR_ALLOC_N(privconn->auths, num) < 0)
        goto error;

    for (i = 0; i < num; i++) {
        char *username, *password;

        ctxt->node = nodes[i];
        username = virXPathString("string(.)", ctxt);
        if (!username || STREQ(username, "")) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing username in /node/auth/user field"));
            VIR_FREE(username);
            goto error;
        }
        /* This field is optional. */
        password = virXMLPropString(nodes[i], "password");

        privconn->auths[i].username = username;
        privconn->auths[i].password = password;
    }

    ret = 0;
 error:
    VIR_FREE(nodes);
    return ret;
}

static int
testOpenParse(testDriverPtr privconn,
              const char *file,
              xmlXPathContextPtr ctxt)
{
    if (!xmlStrEqual(ctxt->node->name, BAD_CAST "node")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Root element is not 'node'"));
        goto error;
    }

    if (testParseNodeInfo(&privconn->nodeInfo, ctxt) < 0)
        goto error;
    if (testParseDomains(privconn, file, ctxt) < 0)
        goto error;
    if (testParseNetworks(privconn, file, ctxt) < 0)
        goto error;
    if (testParseInterfaces(privconn, file, ctxt) < 0)
        goto error;
    if (testParseStorage(privconn, file, ctxt) < 0)
        goto error;
    if (testParseNodedevs(privconn, file, ctxt) < 0)
        goto error;
    if (testParseAuthUsers(privconn, ctxt) < 0)
        goto error;

    return 0;
 error:
    return -1;
}

/* No shared state between simultaneous test connections initialized
 * from a file.  */
static int
testOpenFromFile(virConnectPtr conn, const char *file)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    testDriverPtr privconn;

    if (!(privconn = testDriverNew()))
        return VIR_DRV_OPEN_ERROR;

    testDriverLock(privconn);
    conn->privateData = privconn;

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if (!(doc = virXMLParseFileCtxt(file, &ctxt)))
        goto error;

    privconn->numCells = 0;
    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    if (testOpenParse(privconn, file, ctxt) < 0)
        goto error;

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    testDriverUnlock(privconn);

    return 0;

 error:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    testDriverFree(privconn);
    conn->privateData = NULL;
    return VIR_DRV_OPEN_ERROR;
}

/* Simultaneous test:///default connections should share the same
 * common state (among other things, this allows testing event
 * detection in one connection for an action caused in another).  */
static int
testOpenDefault(virConnectPtr conn)
{
    testDriverPtr privconn = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    size_t i;

    virMutexLock(&defaultLock);
    if (defaultConnections++) {
        conn->privateData = defaultConn;
        virMutexUnlock(&defaultLock);
        return VIR_DRV_OPEN_SUCCESS;
    }

    if (!(privconn = testDriverNew()))
        goto error;

    conn->privateData = privconn;

    memmove(&privconn->nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

    /* Numa setup */
    privconn->numCells = 2;
    for (i = 0; i < privconn->numCells; i++) {
        privconn->cells[i].numCpus = 8;
        privconn->cells[i].mem = (i + 1) * 2048 * 1024;
        privconn->cells[i].freeMem = (i + 1) * 1024 * 1024;
    }
    for (i = 0; i < 16; i++) {
        virBitmapPtr siblings = virBitmapNew(16);
        if (!siblings)
            goto error;
        ignore_value(virBitmapSetBit(siblings, i));
        privconn->cells[i / 8].cpus[(i % 8)].id = i;
        privconn->cells[i / 8].cpus[(i % 8)].socket_id = i / 8;
        privconn->cells[i / 8].cpus[(i % 8)].core_id = i % 8;
        privconn->cells[i / 8].cpus[(i % 8)].siblings = siblings;
    }

    if (!(privconn->caps = testBuildCapabilities(conn)))
        goto error;

    if (!(doc = virXMLParseStringCtxt(defaultConnXML,
                                      _("(test driver)"), &ctxt)))
        goto error;

    if (testOpenParse(privconn, NULL, ctxt) < 0)
        goto error;

    defaultConn = privconn;

    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    virMutexUnlock(&defaultLock);

    return VIR_DRV_OPEN_SUCCESS;

 error:
    testDriverFree(privconn);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    conn->privateData = NULL;
    defaultConnections--;
    virMutexUnlock(&defaultLock);
    return VIR_DRV_OPEN_ERROR;
}

static int
testConnectAuthenticate(virConnectPtr conn,
                        virConnectAuthPtr auth)
{
    testDriverPtr privconn = conn->privateData;
    int ret = -1;
    ssize_t i;
    char *username = NULL, *password = NULL;

    if (privconn->numAuths == 0)
        return 0;

    /* Authentication is required because the test XML contains a
     * non-empty <auth/> section.  First we must ask for a username.
     */
    username = virAuthGetUsername(conn, auth, "test", NULL, "localhost"/*?*/);
    if (!username) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("authentication failed when asking for username"));
        goto cleanup;
    }

    /* Does the username exist? */
    for (i = 0; i < privconn->numAuths; ++i) {
        if (STREQ(privconn->auths[i].username, username))
            goto found_user;
    }
    i = -1;

 found_user:
    /* Even if we didn't find the user, we still ask for a password. */
    if (i == -1 || privconn->auths[i].password != NULL) {
        password = virAuthGetPassword(conn, auth, "test",
                                      username, "localhost");
        if (password == NULL) {
            virReportError(VIR_ERR_AUTH_FAILED, "%s",
                           _("authentication failed when asking for password"));
            goto cleanup;
        }
    }

    if (i == -1 ||
        (password && STRNEQ(privconn->auths[i].password, password))) {
        virReportError(VIR_ERR_AUTH_FAILED, "%s",
                       _("authentication failed, see test XML for the correct username/password"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(username);
    VIR_FREE(password);
    return ret;
}

static virDrvOpenStatus testConnectOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth,
                                        virConfPtr conf ATTRIBUTE_UNUSED,
                                        unsigned int flags)
{
    int ret;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("testOpen: supply a path or use test:///default"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (STREQ(conn->uri->path, "/default"))
        ret = testOpenDefault(conn);
    else
        ret = testOpenFromFile(conn,
                               conn->uri->path);

    if (ret != VIR_DRV_OPEN_SUCCESS)
        return ret;

    /* Fake authentication. */
    if (testConnectAuthenticate(conn, auth) < 0)
        return VIR_DRV_OPEN_ERROR;

    return VIR_DRV_OPEN_SUCCESS;
}

static int testConnectClose(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    bool dflt = false;

    if (privconn == defaultConn) {
        dflt = true;
        virMutexLock(&defaultLock);
        if (--defaultConnections) {
            virMutexUnlock(&defaultLock);
            return 0;
        }
    }

    testDriverLock(privconn);
    testDriverFree(privconn);

    if (dflt) {
        defaultConn = NULL;
        virMutexUnlock(&defaultLock);
    }

    conn->privateData = NULL;
    return 0;
}

static int testConnectGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 unsigned long *hvVer)
{
    *hvVer = 2;
    return 0;
}

static char *testConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}


static int testConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int testConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 0;
}

static int testConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

static int testConnectGetMaxVcpus(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  const char *type ATTRIBUTE_UNUSED)
{
    return 32;
}

static char *
testConnectBaselineCPU(virConnectPtr conn ATTRIBUTE_UNUSED,
                       const char **xmlCPUs,
                       unsigned int ncpus,
                       unsigned int flags)
{
    char *cpu;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    cpu = cpuBaselineXML(xmlCPUs, ncpus, NULL, 0, flags);

    return cpu;
}

static int testNodeGetInfo(virConnectPtr conn,
                           virNodeInfoPtr info)
{
    testDriverPtr privconn = conn->privateData;
    testDriverLock(privconn);
    memcpy(info, &privconn->nodeInfo, sizeof(virNodeInfo));
    testDriverUnlock(privconn);
    return 0;
}

static char *testConnectGetCapabilities(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    char *xml;
    testDriverLock(privconn);
    xml = virCapabilitiesFormatXML(privconn->caps);
    testDriverUnlock(privconn);
    return xml;
}

static char *
testConnectGetSysinfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                      unsigned int flags)
{
    char *ret;
    const char *sysinfo = "<sysinfo type='smbios'>\n"
           "  <bios>\n"
           "    <entry name='vendor'>LENOVO</entry>\n"
           "    <entry name='version'>G4ETA1WW (2.61 )</entry>\n"
           "    <entry name='date'>05/07/2014</entry>\n"
           "    <entry name='release'>2.61</entry>\n"
           "  </bios>\n"
           "</sysinfo>\n";

    virCheckFlags(0, NULL);

    ignore_value(VIR_STRDUP(ret, sysinfo));
    return ret;
}

static const char *
testConnectGetType(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return "TEST";
}

static int testConnectNumOfDomains(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    int count;

    testDriverLock(privconn);
    count = virDomainObjListNumOfDomains(privconn->domains, true, NULL, NULL);
    testDriverUnlock(privconn);

    return count;
}

static int testDomainIsActive(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret;

    if (!(obj = testDomObjFromDomain(dom)))
        return -1;

    ret = virDomainObjIsActive(obj);
    virDomainObjEndAPI(&obj);
    return ret;
}

static int testDomainIsPersistent(virDomainPtr dom)
{
    virDomainObjPtr obj;
    int ret;

    if (!(obj = testDomObjFromDomain(dom)))
        return -1;

    ret = obj->persistent;

    virDomainObjEndAPI(&obj);
    return ret;
}

static int testDomainIsUpdated(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    return 0;
}

static virDomainPtr
testDomainCreateXML(virConnectPtr conn, const char *xml,
                      unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_START_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_START_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    testDriverLock(privconn);
    if ((def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainObjListAdd(privconn->domains,
                                    def,
                                    privconn->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    NULL)))
        goto cleanup;
    def = NULL;

    if (testDomainStartState(privconn, dom, VIR_DOMAIN_RUNNING_BOOTED) < 0) {
        if (!dom->persistent) {
            virDomainObjListRemove(privconn->domains, dom);
            dom = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    testObjectEventQueue(privconn, event);
    virDomainDefFree(def);
    testDriverUnlock(privconn);
    return ret;
}


static virDomainPtr testDomainLookupByID(virConnectPtr conn,
                                         int id)
{
    testDriverPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByID(privconn->domains, id))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr testDomainLookupByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    testDriverPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByUUID(privconn->domains, uuid))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    if (dom)
        virObjectUnlock(dom);
    return ret;
}

static virDomainPtr testDomainLookupByName(virConnectPtr conn,
                                           const char *name)
{
    testDriverPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainObjPtr dom;

    if (!(dom = virDomainObjListFindByName(privconn->domains, name))) {
        virReportError(VIR_ERR_NO_DOMAIN, NULL);
        goto cleanup;
    }

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    virDomainObjEndAPI(&dom);
    return ret;
}

static int testConnectListDomains(virConnectPtr conn,
                                  int *ids,
                                  int maxids)
{
    testDriverPtr privconn = conn->privateData;

    return virDomainObjListGetActiveIDs(privconn->domains, ids, maxids,
                                        NULL, NULL);
}

static int testDomainDestroy(virDomainPtr domain)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    testDomainShutdownState(domain, privdom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);

    if (!privdom->persistent)
        virDomainObjListRemove(privconn->domains, privdom);

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainResume(virDomainPtr domain)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (virDomainObjGetState(privdom, NULL) != VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not paused"),
                       domain->name);
        goto cleanup;
    }

    virDomainObjSetState(privdom, VIR_DOMAIN_RUNNING,
                         VIR_DOMAIN_RUNNING_UNPAUSED);
    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_RESUMED,
                                     VIR_DOMAIN_EVENT_RESUMED_UNPAUSED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainSuspend(virDomainPtr domain)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;
    int state;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    state = virDomainObjGetState(privdom, NULL);
    if (state == VIR_DOMAIN_SHUTOFF || state == VIR_DOMAIN_PAUSED) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("domain '%s' not running"),
                       domain->name);
        goto cleanup;
    }

    virDomainObjSetState(privdom, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_SUSPENDED,
                                     VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainShutdownFlags(virDomainPtr domain,
                                   unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);


    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainObjGetState(privdom, NULL) == VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("domain '%s' not running"), domain->name);
        goto cleanup;
    }

    testDomainShutdownState(domain, privdom, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);

    if (!privdom->persistent)
        virDomainObjListRemove(privconn->domains, privdom);

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainShutdown(virDomainPtr domain)
{
    return testDomainShutdownFlags(domain, 0);
}

/* Similar behaviour as shutdown */
static int testDomainReboot(virDomainPtr domain,
                            unsigned int action ATTRIBUTE_UNUSED)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;


    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    virDomainObjSetState(privdom, VIR_DOMAIN_SHUTDOWN,
                         VIR_DOMAIN_SHUTDOWN_USER);

    switch (privdom->def->onReboot) {
    case VIR_DOMAIN_LIFECYCLE_DESTROY:
        virDomainObjSetState(privdom, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART:
        virDomainObjSetState(privdom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_BOOTED);
        break;

    case VIR_DOMAIN_LIFECYCLE_PRESERVE:
        virDomainObjSetState(privdom, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        break;

    case VIR_DOMAIN_LIFECYCLE_RESTART_RENAME:
        virDomainObjSetState(privdom, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_BOOTED);
        break;

    default:
        virDomainObjSetState(privdom, VIR_DOMAIN_SHUTOFF,
                             VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        break;
    }

    if (virDomainObjGetState(privdom, NULL) == VIR_DOMAIN_SHUTOFF) {
        testDomainShutdownState(domain, privdom, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        event = virDomainEventLifecycleNewFromObj(privdom,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN);

        if (!privdom->persistent)
            virDomainObjListRemove(privconn->domains, privdom);
    }

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainGetInfo(virDomainPtr domain,
                             virDomainInfoPtr info)
{
    struct timeval tv;
    virDomainObjPtr privdom;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("getting time of day"));
        goto cleanup;
    }

    info->state = virDomainObjGetState(privdom, NULL);
    info->memory = privdom->def->mem.cur_balloon;
    info->maxMem = virDomainDefGetMemoryTotal(privdom->def);
    info->nrVirtCpu = virDomainDefGetVcpus(privdom->def);
    info->cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainGetState(virDomainPtr domain,
                   int *state,
                   int *reason,
                   unsigned int flags)
{
    virDomainObjPtr privdom;

    virCheckFlags(0, -1);

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    *state = virDomainObjGetState(privdom, reason);

    virDomainObjEndAPI(&privdom);

    return 0;
}

#define TEST_SAVE_MAGIC "TestGuestMagic"

static int
testDomainSaveFlags(virDomainPtr domain, const char *path,
                    const char *dxml, unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    char *xml = NULL;
    int fd = -1;
    int len;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }


    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    xml = virDomainDefFormat(privdom->def, privconn->caps,
                             VIR_DOMAIN_DEF_FORMAT_SECURE);

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

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("saving domain '%s' to '%s': write failed"),
                             domain->name, path);
        goto cleanup;
    }
    fd = -1;

    testDomainShutdownState(domain, privdom, VIR_DOMAIN_SHUTOFF_SAVED);
    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);

    if (!privdom->persistent)
        virDomainObjListRemove(privconn->domains, privdom);

    ret = 0;
 cleanup:
    VIR_FREE(xml);

    /* Don't report failure in close or unlink, because
     * in either case we're already in a failure scenario
     * and have reported an earlier error */
    if (ret != 0) {
        VIR_FORCE_CLOSE(fd);
        unlink(path);
    }
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int
testDomainSave(virDomainPtr domain,
               const char *path)
{
    return testDomainSaveFlags(domain, path, NULL, 0);
}

static int
testDomainRestoreFlags(virConnectPtr conn,
                       const char *path,
                       const char *dxml,
                       unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    char *xml = NULL;
    char magic[15];
    int fd = -1;
    int len;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);
    if (dxml) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("xml modification unsupported"));
        return -1;
    }

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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("length of metadata out of range"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(xml, len+1) < 0)
        goto cleanup;
    if (saferead(fd, xml, len) != len) {
        virReportSystemError(errno,
                             _("incomplete metadata in '%s'"), path);
        goto cleanup;
    }
    xml[len] = '\0';

    def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                  NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE);
    if (!def)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainObjListAdd(privconn->domains,
                                    def,
                                    privconn->xmlopt,
                                    VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                    NULL)))
        goto cleanup;
    def = NULL;

    if (testDomainStartState(privconn, dom, VIR_DOMAIN_RUNNING_RESTORED) < 0) {
        if (!dom->persistent) {
            virDomainObjListRemove(privconn->domains, dom);
            dom = NULL;
        }
        goto cleanup;
    }

    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_RESTORED);
    ret = 0;

 cleanup:
    virDomainDefFree(def);
    VIR_FREE(xml);
    VIR_FORCE_CLOSE(fd);
    if (dom)
        virObjectUnlock(dom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int
testDomainRestore(virConnectPtr conn,
                  const char *path)
{
    return testDomainRestoreFlags(conn, path, NULL, 0);
}

static int testDomainCoreDumpWithFormat(virDomainPtr domain,
                                        const char *to,
                                        unsigned int dumpformat,
                                        unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    int fd = -1;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DUMP_CRASH, -1);


    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
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
    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno,
                             _("domain '%s' coredump: write failed: %s"),
                             domain->name, to);
        goto cleanup;
    }

    /* we don't support non-raw formats in test driver */
    if (dumpformat != VIR_DOMAIN_CORE_DUMP_FORMAT_RAW) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("kdump-compressed format is not supported here"));
        goto cleanup;
    }

    if (flags & VIR_DUMP_CRASH) {
        testDomainShutdownState(domain, privdom, VIR_DOMAIN_SHUTOFF_CRASHED);
        event = virDomainEventLifecycleNewFromObj(privdom,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_CRASHED);
        if (!privdom->persistent)
            virDomainObjListRemove(privconn->domains, privdom);
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}


static int
testDomainCoreDump(virDomainPtr domain,
                   const char *to,
                   unsigned int flags)
{
    return testDomainCoreDumpWithFormat(domain, to,
                                        VIR_DOMAIN_CORE_DUMP_FORMAT_RAW, flags);
}


static char *
testDomainGetOSType(virDomainPtr dom ATTRIBUTE_UNUSED)
{
    char *ret;

    ignore_value(VIR_STRDUP(ret, "linux"));
    return ret;
}


static unsigned long long
testDomainGetMaxMemory(virDomainPtr domain)
{
    virDomainObjPtr privdom;
    unsigned long long ret = 0;

    if (!(privdom = testDomObjFromDomain(domain)))
        return 0;

    ret = virDomainDefGetMemoryTotal(privdom->def);

    virDomainObjEndAPI(&privdom);
    return ret;
}

static int testDomainSetMaxMemory(virDomainPtr domain,
                                  unsigned long memory)
{
    virDomainObjPtr privdom;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    /* XXX validate not over host memory wrt to other domains */
    virDomainDefSetMemoryTotal(privdom->def, memory);

    virDomainObjEndAPI(&privdom);
    return 0;
}

static int testDomainSetMemory(virDomainPtr domain,
                               unsigned long memory)
{
    virDomainObjPtr privdom;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (memory > virDomainDefGetMemoryTotal(privdom->def)) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privdom->def->mem.cur_balloon = memory;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainDefPtr def;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if (!(vm = testDomObjFromDomain(domain)))
        return -1;

    if (!(def = virDomainObjGetOneDef(vm, flags)))
        goto cleanup;

    if (flags & VIR_DOMAIN_VCPU_MAXIMUM)
        ret = virDomainDefGetVcpusMax(def);
    else
        ret = virDomainDefGetVcpus(def);

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
testDomainGetMaxVcpus(virDomainPtr domain)
{
    return testDomainGetVcpusFlags(domain, (VIR_DOMAIN_AFFECT_LIVE |
                                            VIR_DOMAIN_VCPU_MAXIMUM));
}

static int
testDomainSetVcpusFlags(virDomainPtr domain, unsigned int nrCpus,
                        unsigned int flags)
{
    testDriverPtr driver = domain->conn->privateData;
    virDomainObjPtr privdom = NULL;
    virDomainDefPtr def;
    virDomainDefPtr persistentDef;
    int ret = -1, maxvcpus;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG |
                  VIR_DOMAIN_VCPU_MAXIMUM, -1);

    if ((maxvcpus = testConnectGetMaxVcpus(domain->conn, NULL)) < 0)
        return -1;

    if (nrCpus > maxvcpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested cpu amount exceeds maximum supported amount "
                         "(%d > %d)"), nrCpus, maxvcpus);
        return -1;
    }

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (virDomainObjGetDefs(privdom, flags, &def, &persistentDef) < 0)
        goto cleanup;

    if (def && virDomainDefGetVcpusMax(def) < nrCpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested cpu amount exceeds maximum (%d > %d)"),
                       nrCpus, virDomainDefGetVcpusMax(def));
        goto cleanup;
    }

    if (persistentDef &&
        !(flags & VIR_DOMAIN_VCPU_MAXIMUM) &&
        virDomainDefGetVcpusMax(persistentDef) < nrCpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested cpu amount exceeds maximum (%d > %d)"),
                       nrCpus, virDomainDefGetVcpusMax(persistentDef));
        goto cleanup;
    }

    if (def &&
        virDomainDefSetVcpus(def, nrCpus) < 0)
        goto cleanup;

    if (persistentDef) {
        if (flags & VIR_DOMAIN_VCPU_MAXIMUM) {
            if (virDomainDefSetVcpusMax(persistentDef, nrCpus,
                                        driver->xmlopt) < 0)
                goto cleanup;
        } else {
            if (virDomainDefSetVcpus(persistentDef, nrCpus) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainSetVcpus(virDomainPtr domain, unsigned int nrCpus)
{
    return testDomainSetVcpusFlags(domain, nrCpus, VIR_DOMAIN_AFFECT_LIVE);
}

static int testDomainGetVcpus(virDomainPtr domain,
                              virVcpuInfoPtr info,
                              int maxinfo,
                              unsigned char *cpumaps,
                              int maplen)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virDomainDefPtr def;
    size_t i;
    int maxcpu, hostcpus;
    int ret = -1;
    struct timeval tv;
    unsigned long long statbase;
    virBitmapPtr allcpumap = NULL;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot list vcpus for an inactive domain"));
        goto cleanup;
    }

    def = privdom->def;

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

    if (!(allcpumap = virBitmapNew(hostcpus)))
        goto cleanup;

    virBitmapSetAll(allcpumap);

    /* Clamp to actual number of vcpus */
    if (maxinfo > virDomainDefGetVcpus(privdom->def))
        maxinfo = virDomainDefGetVcpus(privdom->def);

    memset(info, 0, sizeof(*info) * maxinfo);
    memset(cpumaps, 0, maxinfo * maplen);

    for (i = 0; i < maxinfo; i++) {
        virDomainVcpuDefPtr vcpu = virDomainDefGetVcpu(def, i);
        virBitmapPtr bitmap = NULL;

        if (!vcpu->online)
            continue;

        if (vcpu->cpumask)
            bitmap = vcpu->cpumask;
        else if (def->cpumask)
            bitmap = def->cpumask;
        else
            bitmap = allcpumap;

        if (cpumaps)
            virBitmapToDataBuf(bitmap, VIR_GET_CPUMAP(cpumaps, maplen, i), maplen);

        info[i].number = i;
        info[i].state = VIR_VCPU_RUNNING;
        info[i].cpu = virBitmapLastSetBit(bitmap);

        /* Fake an increasing cpu time value */
        info[i].cpuTime = statbase / 10;
    }

    ret = maxinfo;
 cleanup:
    virBitmapFree(allcpumap);
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int testDomainPinVcpu(virDomainPtr domain,
                             unsigned int vcpu,
                             unsigned char *cpumap,
                             int maplen)
{
    virDomainVcpuDefPtr vcpuinfo;
    virDomainObjPtr privdom;
    virDomainDefPtr def;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    def = privdom->def;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("cannot pin vcpus on an inactive domain"));
        goto cleanup;
    }

    if (!(vcpuinfo = virDomainDefGetVcpu(def, vcpu)) ||
        !vcpuinfo->online) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("requested vcpu '%d' is not present in the domain"),
                       vcpu);
        goto cleanup;
    }

    virBitmapFree(vcpuinfo->cpumask);

    if (!(vcpuinfo->cpumask = virBitmapNewData(cpumap, maplen)))
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainGetVcpuPinInfo(virDomainPtr dom,
                        int ncpumaps,
                        unsigned char *cpumaps,
                        int maplen,
                        unsigned int flags)
{
    testDriverPtr driver = dom->conn->privateData;
    virDomainObjPtr privdom;
    virDomainDefPtr def;
    int ret = -1;

    if (!(privdom = testDomObjFromDomain(dom)))
        return -1;

    if (!(def = virDomainObjGetOneDef(privdom, flags)))
        goto cleanup;

    ret = virDomainDefGetVcpuPinInfoHelper(def, maplen, ncpumaps, cpumaps,
                                           VIR_NODEINFO_MAXCPUS(driver->nodeInfo),
                                           NULL);

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static char *testDomainGetXMLDesc(virDomainPtr domain, unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainDefPtr def;
    virDomainObjPtr privdom;
    char *ret = NULL;

    /* Flags checked by virDomainDefFormat */

    if (!(privdom = testDomObjFromDomain(domain)))
        return NULL;

    def = (flags & VIR_DOMAIN_XML_INACTIVE) &&
        privdom->newDef ? privdom->newDef : privdom->def;

    ret = virDomainDefFormat(def, privconn->caps,
                             virDomainDefFormatConvertXMLFlags(flags));

    virDomainObjEndAPI(&privdom);
    return ret;
}

static int testConnectNumOfDefinedDomains(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;

    return virDomainObjListNumOfDomains(privconn->domains, false, NULL, NULL);
}

static int testConnectListDefinedDomains(virConnectPtr conn,
                                         char **const names,
                                         int maxnames)
{

    testDriverPtr privconn = conn->privateData;

    memset(names, 0, sizeof(*names)*maxnames);
    return virDomainObjListGetInactiveNames(privconn->domains, names, maxnames,
                                            NULL, NULL);
}

static virDomainPtr testDomainDefineXMLFlags(virConnectPtr conn,
                                             const char *xml,
                                             unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    virDomainPtr ret = NULL;
    virDomainDefPtr def;
    virDomainObjPtr dom = NULL;
    virObjectEventPtr event = NULL;
    virDomainDefPtr oldDef = NULL;
    unsigned int parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    virCheckFlags(VIR_DOMAIN_DEFINE_VALIDATE, NULL);

    if (flags & VIR_DOMAIN_DEFINE_VALIDATE)
        parse_flags |= VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA;

    if ((def = virDomainDefParseString(xml, privconn->caps, privconn->xmlopt,
                                       NULL, parse_flags)) == NULL)
        goto cleanup;

    if (virXMLCheckIllegalChars("name", def->name, "\n") < 0)
        goto cleanup;

    if (testDomainGenerateIfnames(def) < 0)
        goto cleanup;
    if (!(dom = virDomainObjListAdd(privconn->domains,
                                    def,
                                    privconn->xmlopt,
                                    0,
                                    &oldDef)))
        goto cleanup;
    def = NULL;
    dom->persistent = 1;

    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_DEFINED,
                                     !oldDef ?
                                     VIR_DOMAIN_EVENT_DEFINED_ADDED :
                                     VIR_DOMAIN_EVENT_DEFINED_UPDATED);

    ret = virGetDomain(conn, dom->def->name, dom->def->uuid);
    if (ret)
        ret->id = dom->def->id;

 cleanup:
    virDomainDefFree(def);
    virDomainDefFree(oldDef);
    if (dom)
        virObjectUnlock(dom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static virDomainPtr
testDomainDefineXML(virConnectPtr conn, const char *xml)
{
    return testDomainDefineXMLFlags(conn, xml, 0);
}

static char *testDomainGetMetadata(virDomainPtr dom,
                                   int type,
                                   const char *uri,
                                   unsigned int flags)
{
    virDomainObjPtr privdom;
    char *ret;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, NULL);

    if (!(privdom = testDomObjFromDomain(dom)))
        return NULL;

    ret = virDomainObjGetMetadata(privdom, type, uri, flags);

    virDomainObjEndAPI(&privdom);
    return ret;
}

static int testDomainSetMetadata(virDomainPtr dom,
                                 int type,
                                 const char *metadata,
                                 const char *key,
                                 const char *uri,
                                 unsigned int flags)
{
    testDriverPtr privconn = dom->conn->privateData;
    virDomainObjPtr privdom;
    int ret;

    virCheckFlags(VIR_DOMAIN_AFFECT_LIVE |
                  VIR_DOMAIN_AFFECT_CONFIG, -1);

    if (!(privdom = testDomObjFromDomain(dom)))
        return -1;

    ret = virDomainObjSetMetadata(privdom, type, metadata, key, uri,
                                  privconn->caps, privconn->xmlopt,
                                  NULL, NULL, flags);

    if (ret == 0) {
        virObjectEventPtr ev = NULL;
        ev = virDomainEventMetadataChangeNewFromObj(privdom, type, uri);
        testObjectEventQueue(privconn, ev);
    }

    virDomainObjEndAPI(&privdom);
    return ret;
}


static int testNodeGetCellsFreeMemory(virConnectPtr conn,
                                      unsigned long long *freemems,
                                      int startCell, int maxCells)
{
    testDriverPtr privconn = conn->privateData;
    int cell;
    size_t i;
    int ret = -1;

    testDriverLock(privconn);
    if (startCell >= privconn->numCells) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("Range exceeds available cells"));
        goto cleanup;
    }

    for (cell = startCell, i = 0;
         (cell < privconn->numCells && i < maxCells);
         ++cell, ++i) {
        freemems[i] = privconn->cells[cell].mem;
    }
    ret = i;

 cleanup:
    testDriverUnlock(privconn);
    return ret;
}

#define TEST_NB_CPU_STATS 4

static int
testNodeGetCPUStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                    int cpuNum ATTRIBUTE_UNUSED,
                    virNodeCPUStatsPtr params,
                    int *nparams,
                    unsigned int flags)
{
    size_t i = 0;

    virCheckFlags(0, -1);

    if (params == NULL) {
        *nparams = TEST_NB_CPU_STATS;
        return 0;
    }

    for (i = 0; i < *nparams && i < 4; i++) {
        switch (i) {
        case 0:
            if (virHostCPUStatsAssign(&params[i],
                                      VIR_NODE_CPU_STATS_USER, 9797400000) < 0)
                return -1;
            break;
        case 1:
            if (virHostCPUStatsAssign(&params[i],
                                      VIR_NODE_CPU_STATS_KERNEL, 34678723400000) < 0)
                return -1;
            break;
        case 2:
            if (virHostCPUStatsAssign(&params[i],
                                      VIR_NODE_CPU_STATS_IDLE, 87264900000) < 0)
                return -1;
            break;
        case 3:
            if (virHostCPUStatsAssign(&params[i],
                                      VIR_NODE_CPU_STATS_IOWAIT, 763600000) < 0)
                return -1;
            break;
        }
    }

    *nparams = i;
    return 0;
}

static unsigned long long
testNodeGetFreeMemory(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    unsigned int freeMem = 0;
    size_t i;

    testDriverLock(privconn);

    for (i = 0; i < privconn->numCells; i++)
        freeMem += privconn->cells[i].freeMem;

    testDriverUnlock(privconn);
    return freeMem;
}

static int
testNodeGetFreePages(virConnectPtr conn ATTRIBUTE_UNUSED,
                     unsigned int npages,
                     unsigned int *pages ATTRIBUTE_UNUSED,
                     int startCell ATTRIBUTE_UNUSED,
                     unsigned int cellCount,
                     unsigned long long *counts,
                     unsigned int flags)
{
    size_t i = 0, j = 0;
    int x = 6;

    virCheckFlags(0, -1);

    for (i = 0; i < cellCount; i++) {
        for (j = 0; j < npages; j++) {
            x = x * 2 + 7;
            counts[(i * npages) +  j] = x;
        }
    }

    return 0;
}

static int testDomainCreateWithFlags(virDomainPtr domain, unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);

    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (virDomainObjGetState(privdom, NULL) != VIR_DOMAIN_SHUTOFF) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Domain '%s' is already running"), domain->name);
        goto cleanup;
    }

    if (testDomainStartState(privconn, privdom,
                             VIR_DOMAIN_RUNNING_BOOTED) < 0)
        goto cleanup;
    domain->id = privdom->def->id;

    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_STARTED,
                                     VIR_DOMAIN_EVENT_STARTED_BOOTED);
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int testDomainCreate(virDomainPtr domain)
{
    return testDomainCreateWithFlags(domain, 0);
}

static int testDomainUndefineFlags(virDomainPtr domain,
                                   unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr privdom;
    virObjectEventPtr event = NULL;
    int nsnapshots;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_UNDEFINE_MANAGED_SAVE |
                  VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA, -1);


    if (!(privdom = testDomObjFromDomain(domain)))
        goto cleanup;

    if (privdom->hasManagedSave &&
        !(flags & VIR_DOMAIN_UNDEFINE_MANAGED_SAVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Refusing to undefine while domain managed "
                         "save image exists"));
        goto cleanup;
    }

    /* Requiring an inactive VM is part of the documented API for
     * UNDEFINE_SNAPSHOTS_METADATA
     */
    if (!virDomainObjIsActive(privdom) &&
        (nsnapshots = virDomainSnapshotObjListNum(privdom->snapshots,
                                                  NULL, 0))) {
        if (!(flags & VIR_DOMAIN_UNDEFINE_SNAPSHOTS_METADATA)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot delete inactive domain with %d "
                             "snapshots"),
                           nsnapshots);
            goto cleanup;
        }

        /* There isn't actually anything to do, we are just emulating qemu
         * behavior here. */
    }

    event = virDomainEventLifecycleNewFromObj(privdom,
                                     VIR_DOMAIN_EVENT_UNDEFINED,
                                     VIR_DOMAIN_EVENT_UNDEFINED_REMOVED);
    privdom->hasManagedSave = false;

    if (virDomainObjIsActive(privdom))
        privdom->persistent = 0;
    else
        virDomainObjListRemove(privconn->domains, privdom);

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    testObjectEventQueue(privconn, event);
    return ret;
}

static int testDomainUndefine(virDomainPtr domain)
{
    return testDomainUndefineFlags(domain, 0);
}

static int testDomainGetAutostart(virDomainPtr domain,
                                  int *autostart)
{
    virDomainObjPtr privdom;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    *autostart = privdom->autostart;

    virDomainObjEndAPI(&privdom);
    return 0;
}


static int testDomainSetAutostart(virDomainPtr domain,
                                  int autostart)
{
    virDomainObjPtr privdom;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    privdom->autostart = autostart ? 1 : 0;

    virDomainObjEndAPI(&privdom);
    return 0;
}

static char *testDomainGetSchedulerType(virDomainPtr domain ATTRIBUTE_UNUSED,
                                        int *nparams)
{
    char *type = NULL;

    if (nparams)
        *nparams = 1;

    ignore_value(VIR_STRDUP(type, "fair"));

    return type;
}

static int
testDomainGetSchedulerParametersFlags(virDomainPtr domain,
                                      virTypedParameterPtr params,
                                      int *nparams,
                                      unsigned int flags)
{
    virDomainObjPtr privdom;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (virTypedParameterAssign(params, VIR_DOMAIN_SCHEDULER_WEIGHT,
                                VIR_TYPED_PARAM_UINT, 50) < 0)
        goto cleanup;
    /* XXX */
    /*params[0].value.ui = privdom->weight;*/

    *nparams = 1;
    ret = 0;

 cleanup:
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainGetSchedulerParameters(virDomainPtr domain,
                                 virTypedParameterPtr params,
                                 int *nparams)
{
    return testDomainGetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int
testDomainSetSchedulerParametersFlags(virDomainPtr domain,
                                      virTypedParameterPtr params,
                                      int nparams,
                                      unsigned int flags)
{
    virDomainObjPtr privdom;
    int ret = -1;
    size_t i;

    virCheckFlags(0, -1);
    if (virTypedParamsValidate(params, nparams,
                               VIR_DOMAIN_SCHEDULER_WEIGHT,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].field, VIR_DOMAIN_SCHEDULER_WEIGHT)) {
            /* XXX */
            /*privdom->weight = params[i].value.ui;*/
        }
    }

    ret = 0;

    virDomainObjEndAPI(&privdom);
    return ret;
}

static int
testDomainSetSchedulerParameters(virDomainPtr domain,
                                 virTypedParameterPtr params,
                                 int nparams)
{
    return testDomainSetSchedulerParametersFlags(domain, params, nparams, 0);
}

static int testDomainBlockStats(virDomainPtr domain,
                                const char *path,
                                virDomainBlockStatsPtr stats)
{
    virDomainObjPtr privdom;
    struct timeval tv;
    unsigned long long statbase;
    int ret = -1;

    if (!*path) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("summary statistics are not supported yet"));
        return ret;
    }

    if (!(privdom = testDomObjFromDomain(domain)))
        return ret;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto error;
    }

    if (virDomainDiskIndexByName(privdom->def, path, false) < 0) {
        virReportError(VIR_ERR_INVALID_ARG,
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
    virDomainObjEndAPI(&privdom);
    return ret;
}

static int testDomainInterfaceStats(virDomainPtr domain,
                                    const char *path,
                                    virDomainInterfaceStatsPtr stats)
{
    virDomainObjPtr privdom;
    struct timeval tv;
    unsigned long long statbase;
    size_t i;
    int found = 0, ret = -1;

    if (!(privdom = testDomObjFromDomain(domain)))
        return -1;

    if (!virDomainObjIsActive(privdom)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto error;
    }

    for (i = 0; i < privdom->def->nnets; i++) {
        if (privdom->def->nets[i]->ifname &&
            STREQ(privdom->def->nets[i]->ifname, path)) {
            found = 1;
            break;
        }
    }

    if (!found) {
        virReportError(VIR_ERR_INVALID_ARG,
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
    virDomainObjEndAPI(&privdom);
    return ret;
}


static virNetworkPtr testNetworkLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid)
{
    testDriverPtr privconn = conn->privateData;
    virNetworkObjPtr net;
    virNetworkPtr ret = NULL;

    net = virNetworkObjFindByUUID(privconn->networks, uuid);
    if (net == NULL) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

 cleanup:
    virNetworkObjEndAPI(&net);
    return ret;
}

static virNetworkPtr testNetworkLookupByName(virConnectPtr conn,
                                             const char *name)
{
    testDriverPtr privconn = conn->privateData;
    virNetworkObjPtr net;
    virNetworkPtr ret = NULL;

    net = virNetworkObjFindByName(privconn->networks, name);
    if (net == NULL) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

 cleanup:
    virNetworkObjEndAPI(&net);
    return ret;
}


static int testConnectNumOfNetworks(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    int numActive;

    numActive = virNetworkObjListNumOfNetworks(privconn->networks,
                                               true, NULL, conn);
    return numActive;
}

static int testConnectListNetworks(virConnectPtr conn, char **const names, int nnames) {
    testDriverPtr privconn = conn->privateData;
    int n;

    n = virNetworkObjListGetNames(privconn->networks,
                                  true, names, nnames, NULL, conn);
    return n;
}

static int testConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    int numInactive;

    numInactive = virNetworkObjListNumOfNetworks(privconn->networks,
                                                 false, NULL, conn);
    return numInactive;
}

static int testConnectListDefinedNetworks(virConnectPtr conn, char **const names, int nnames) {
    testDriverPtr privconn = conn->privateData;
    int n;

    n = virNetworkObjListGetNames(privconn->networks,
                                  false, names, nnames, NULL, conn);
    return n;
}

static int
testConnectListAllNetworks(virConnectPtr conn,
                           virNetworkPtr **nets,
                           unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    return virNetworkObjListExport(conn, privconn->networks, nets, NULL, flags);
}

static int testNetworkIsActive(virNetworkPtr net)
{
    testDriverPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    obj = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = virNetworkObjIsActive(obj);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}

static int testNetworkIsPersistent(virNetworkPtr net)
{
    testDriverPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    obj = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


static virNetworkPtr testNetworkCreateXML(virConnectPtr conn, const char *xml)
{
    testDriverPtr privconn = conn->privateData;
    virNetworkDefPtr def;
    virNetworkObjPtr net = NULL;
    virNetworkPtr ret = NULL;
    virObjectEventPtr event = NULL;

    if ((def = virNetworkDefParseString(xml)) == NULL)
        goto cleanup;

    if (!(net = virNetworkAssignDef(privconn->networks, def,
                                    VIR_NETWORK_OBJ_LIST_ADD_LIVE |
                                    VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE)))
        goto cleanup;
    def = NULL;
    net->active = 1;

    event = virNetworkEventLifecycleNew(net->def->name, net->def->uuid,
                                        VIR_NETWORK_EVENT_STARTED,
                                        0);

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

 cleanup:
    virNetworkDefFree(def);
    testObjectEventQueue(privconn, event);
    virNetworkObjEndAPI(&net);
    return ret;
}

static
virNetworkPtr testNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    testDriverPtr privconn = conn->privateData;
    virNetworkDefPtr def;
    virNetworkObjPtr net = NULL;
    virNetworkPtr ret = NULL;
    virObjectEventPtr event = NULL;

    if ((def = virNetworkDefParseString(xml)) == NULL)
        goto cleanup;

    if (!(net = virNetworkAssignDef(privconn->networks, def, 0)))
        goto cleanup;
    def = NULL;

    event = virNetworkEventLifecycleNew(net->def->name, net->def->uuid,
                                        VIR_NETWORK_EVENT_DEFINED,
                                        0);

    ret = virGetNetwork(conn, net->def->name, net->def->uuid);

 cleanup:
    virNetworkDefFree(def);
    testObjectEventQueue(privconn, event);
    virNetworkObjEndAPI(&net);
    return ret;
}

static int testNetworkUndefine(virNetworkPtr network)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;
    virObjectEventPtr event = NULL;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);

    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkObjIsActive(privnet)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Network '%s' is still running"), network->name);
        goto cleanup;
    }

    event = virNetworkEventLifecycleNew(network->name, network->uuid,
                                        VIR_NETWORK_EVENT_UNDEFINED,
                                        0);

    virNetworkRemoveInactive(privconn->networks, privnet);
    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    virNetworkObjEndAPI(&privnet);
    return ret;
}

static int
testNetworkUpdate(virNetworkPtr net,
                  unsigned int command,
                  unsigned int section,
                  int parentIndex,
                  const char *xml,
                  unsigned int flags)
{
    testDriverPtr privconn = net->conn->privateData;
    virNetworkObjPtr network = NULL;
    int isActive, ret = -1;

    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG,
                  -1);

    network = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    /* VIR_NETWORK_UPDATE_AFFECT_CURRENT means "change LIVE if network
     * is active, else change CONFIG
    */
    isActive = virNetworkObjIsActive(network);
    if ((flags & (VIR_NETWORK_UPDATE_AFFECT_LIVE
                   | VIR_NETWORK_UPDATE_AFFECT_CONFIG)) ==
        VIR_NETWORK_UPDATE_AFFECT_CURRENT) {
        if (isActive)
            flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;
        else
            flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
    }

    /* update the network config in memory/on disk */
    if (virNetworkObjUpdate(network, command, section, parentIndex, xml, flags) < 0)
       goto cleanup;

    ret = 0;
 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}

static int testNetworkCreate(virNetworkPtr network)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;
    virObjectEventPtr event = NULL;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virNetworkObjIsActive(privnet)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Network '%s' is already running"), network->name);
        goto cleanup;
    }

    privnet->active = 1;
    event = virNetworkEventLifecycleNew(privnet->def->name, privnet->def->uuid,
                                        VIR_NETWORK_EVENT_STARTED,
                                        0);
    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    virNetworkObjEndAPI(&privnet);
    return ret;
}

static int testNetworkDestroy(virNetworkPtr network)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;
    virObjectEventPtr event = NULL;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privnet->active = 0;
    event = virNetworkEventLifecycleNew(privnet->def->name, privnet->def->uuid,
                                        VIR_NETWORK_EVENT_STOPPED,
                                        0);
    if (!privnet->persistent)
        virNetworkRemoveInactive(privconn->networks, privnet);

    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    virNetworkObjEndAPI(&privnet);
    return ret;
}

static char *testNetworkGetXMLDesc(virNetworkPtr network,
                                   unsigned int flags)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    ret = virNetworkDefFormat(privnet->def, flags);

 cleanup:
    virNetworkObjEndAPI(&privnet);
    return ret;
}

static char *testNetworkGetBridgeName(virNetworkPtr network) {
    testDriverPtr privconn = network->conn->privateData;
    char *bridge = NULL;
    virNetworkObjPtr privnet;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!(privnet->def->bridge)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("network '%s' does not have a bridge name."),
                       privnet->def->name);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(bridge, privnet->def->bridge));

 cleanup:
    virNetworkObjEndAPI(&privnet);
    return bridge;
}

static int testNetworkGetAutostart(virNetworkPtr network,
                                   int *autostart)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    *autostart = privnet->autostart;
    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&privnet);
    return ret;
}

static int testNetworkSetAutostart(virNetworkPtr network,
                                   int autostart)
{
    testDriverPtr privconn = network->conn->privateData;
    virNetworkObjPtr privnet;
    int ret = -1;

    privnet = virNetworkObjFindByName(privconn->networks, network->name);
    if (privnet == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privnet->autostart = autostart ? 1 : 0;
    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&privnet);
    return ret;
}


/*
 * Physical host interface routines
 */


static int testConnectNumOfInterfaces(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    size_t i;
    int count = 0;

    testDriverLock(privconn);
    for (i = 0; (i < privconn->ifaces.count); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (virInterfaceObjIsActive(privconn->ifaces.objs[i]))
            count++;
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);
    return count;
}

static int testConnectListInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    testDriverPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0; (i < privconn->ifaces.count) && (n < nnames); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            if (VIR_STRDUP(names[n++], privconn->ifaces.objs[i]->def->name) < 0) {
                virInterfaceObjUnlock(privconn->ifaces.objs[i]);
                goto error;
            }
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int testConnectNumOfDefinedInterfaces(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    size_t i;
    int count = 0;

    testDriverLock(privconn);
    for (i = 0; i < privconn->ifaces.count; i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (!virInterfaceObjIsActive(privconn->ifaces.objs[i]))
            count++;
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);
    return count;
}

static int testConnectListDefinedInterfaces(virConnectPtr conn, char **const names, int nnames)
{
    testDriverPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0; (i < privconn->ifaces.count) && (n < nnames); i++) {
        virInterfaceObjLock(privconn->ifaces.objs[i]);
        if (!virInterfaceObjIsActive(privconn->ifaces.objs[i])) {
            if (VIR_STRDUP(names[n++], privconn->ifaces.objs[i]->def->name) < 0) {
                virInterfaceObjUnlock(privconn->ifaces.objs[i]);
                goto error;
            }
        }
        virInterfaceObjUnlock(privconn->ifaces.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static virInterfacePtr testInterfaceLookupByName(virConnectPtr conn,
                                                 const char *name)
{
    testDriverPtr privconn = conn->privateData;
    virInterfaceObjPtr iface;
    virInterfacePtr ret = NULL;

    testDriverLock(privconn);
    iface = virInterfaceObjFindByName(&privconn->ifaces, name);
    testDriverUnlock(privconn);

    if (iface == NULL) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    ret = virGetInterface(conn, iface->def->name, iface->def->mac);

 cleanup:
    if (iface)
        virInterfaceObjUnlock(iface);
    return ret;
}

static virInterfacePtr testInterfaceLookupByMACString(virConnectPtr conn,
                                                      const char *mac)
{
    testDriverPtr privconn = conn->privateData;
    virInterfaceObjPtr iface;
    int ifacect;
    virInterfacePtr ret = NULL;

    testDriverLock(privconn);
    ifacect = virInterfaceObjFindByMACString(&privconn->ifaces, mac, &iface, 1);
    testDriverUnlock(privconn);

    if (ifacect == 0) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (ifacect > 1) {
        virReportError(VIR_ERR_MULTIPLE_INTERFACES, NULL);
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
    testDriverPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virInterfaceObjFindByName(&privconn->ifaces, iface->name);
    testDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }
    ret = virInterfaceObjIsActive(obj);

 cleanup:
    if (obj)
        virInterfaceObjUnlock(obj);
    return ret;
}

static int testInterfaceChangeBegin(virConnectPtr conn,
                                    unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    if (privconn->transaction_running) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("there is another transaction running."));
        goto cleanup;
    }

    privconn->transaction_running = true;

    if (virInterfaceObjListClone(&privconn->ifaces,
                                 &privconn->backupIfaces) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    testDriverUnlock(privconn);
    return ret;
}

static int testInterfaceChangeCommit(virConnectPtr conn,
                                     unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);

    if (!privconn->transaction_running) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("no transaction running, "
                         "nothing to be committed."));
        goto cleanup;
    }

    virInterfaceObjListFree(&privconn->backupIfaces);
    privconn->transaction_running = false;

    ret = 0;

 cleanup:
    testDriverUnlock(privconn);

    return ret;
}

static int testInterfaceChangeRollback(virConnectPtr conn,
                                       unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);

    if (!privconn->transaction_running) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("no transaction running, "
                         "nothing to rollback."));
        goto cleanup;
    }

    virInterfaceObjListFree(&privconn->ifaces);
    privconn->ifaces.count = privconn->backupIfaces.count;
    privconn->ifaces.objs = privconn->backupIfaces.objs;
    privconn->backupIfaces.count = 0;
    privconn->backupIfaces.objs = NULL;

    privconn->transaction_running = false;

    ret = 0;

 cleanup:
    testDriverUnlock(privconn);
    return ret;
}

static char *testInterfaceGetXMLDesc(virInterfacePtr iface,
                                     unsigned int flags)
{
    testDriverPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    privinterface = virInterfaceObjFindByName(&privconn->ifaces, iface->name);
    testDriverUnlock(privconn);

    if (privinterface == NULL) {
        virReportError(VIR_ERR_NO_INTERFACE, __FUNCTION__);
        goto cleanup;
    }

    ret = virInterfaceDefFormat(privinterface->def);

 cleanup:
    if (privinterface)
        virInterfaceObjUnlock(privinterface);
    return ret;
}


static virInterfacePtr testInterfaceDefineXML(virConnectPtr conn, const char *xmlStr,
                                              unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    virInterfaceDefPtr def;
    virInterfaceObjPtr iface = NULL;
    virInterfacePtr ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    if ((def = virInterfaceDefParseString(xmlStr)) == NULL)
        goto cleanup;

    if ((iface = virInterfaceObjAssignDef(&privconn->ifaces, def)) == NULL)
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
    testDriverPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    testDriverLock(privconn);
    privinterface = virInterfaceObjFindByName(&privconn->ifaces, iface->name);

    if (privinterface == NULL) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    virInterfaceObjRemove(&privconn->ifaces, privinterface);
    ret = 0;

 cleanup:
    testDriverUnlock(privconn);
    return ret;
}

static int testInterfaceCreate(virInterfacePtr iface,
                               unsigned int flags)
{
    testDriverPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privinterface = virInterfaceObjFindByName(&privconn->ifaces, iface->name);

    if (privinterface == NULL) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (privinterface->active != 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, NULL);
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
                                unsigned int flags)
{
    testDriverPtr privconn = iface->conn->privateData;
    virInterfaceObjPtr privinterface;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privinterface = virInterfaceObjFindByName(&privconn->ifaces, iface->name);

    if (privinterface == NULL) {
        virReportError(VIR_ERR_NO_INTERFACE, NULL);
        goto cleanup;
    }

    if (privinterface->active == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, NULL);
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


static int testStoragePoolObjSetDefaults(virStoragePoolObjPtr pool)
{

    pool->def->capacity = defaultPoolCap;
    pool->def->allocation = defaultPoolAlloc;
    pool->def->available = defaultPoolCap - defaultPoolAlloc;

    return VIR_STRDUP(pool->configFile, "");
}


static virStoragePoolPtr
testStoragePoolLookupByUUID(virConnectPtr conn,
                            const unsigned char *uuid)
{
    testDriverPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    pool = virStoragePoolObjFindByUUID(&privconn->pools, uuid);
    testDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
testStoragePoolLookupByName(virConnectPtr conn,
                            const char *name)
{
    testDriverPtr privconn = conn->privateData;
    virStoragePoolObjPtr pool;
    virStoragePoolPtr ret = NULL;

    testDriverLock(privconn);
    pool = virStoragePoolObjFindByName(&privconn->pools, name);
    testDriverUnlock(privconn);

    if (pool == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    if (pool)
        virStoragePoolObjUnlock(pool);
    return ret;
}

static virStoragePoolPtr
testStoragePoolLookupByVolume(virStorageVolPtr vol)
{
    return testStoragePoolLookupByName(vol->conn, vol->pool);
}

static int
testConnectNumOfStoragePools(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    int numActive = 0;
    size_t i;

    testDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++)
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numActive++;
    testDriverUnlock(privconn);

    return numActive;
}

static int
testConnectListStoragePools(virConnectPtr conn,
                            char **const names,
                            int nnames)
{
    testDriverPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            VIR_STRDUP(names[n++], privconn->pools.objs[i]->def->name) < 0) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto error;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int
testConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    testDriverPtr privconn = conn->privateData;
    int numInactive = 0;
    size_t i;

    testDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]))
            numInactive++;
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return numInactive;
}

static int
testConnectListDefinedStoragePools(virConnectPtr conn,
                                   char **const names,
                                   int nnames)
{
    testDriverPtr privconn = conn->privateData;
    int n = 0;
    size_t i;

    testDriverLock(privconn);
    memset(names, 0, sizeof(*names)*nnames);
    for (i = 0; i < privconn->pools.count && n < nnames; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (!virStoragePoolObjIsActive(privconn->pools.objs[i]) &&
            VIR_STRDUP(names[n++], privconn->pools.objs[i]->def->name) < 0) {
            virStoragePoolObjUnlock(privconn->pools.objs[i]);
            goto error;
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    return n;

 error:
    for (n = 0; n < nnames; n++)
        VIR_FREE(names[n]);
    testDriverUnlock(privconn);
    return -1;
}

static int
testConnectListAllStoragePools(virConnectPtr conn,
                               virStoragePoolPtr **pools,
                               unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL, -1);

    testDriverLock(privconn);
    ret = virStoragePoolObjListExport(conn, privconn->pools, pools,
                                      NULL, flags);
    testDriverUnlock(privconn);

    return ret;
}

static int testStoragePoolIsActive(virStoragePoolPtr pool)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
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
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr obj;
    int ret = -1;

    testDriverLock(privconn);
    obj = virStoragePoolObjFindByUUID(&privconn->pools, pool->uuid);
    testDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, NULL);
        goto cleanup;
    }
    ret = obj->configFile ? 1 : 0;

 cleanup:
    if (obj)
        virStoragePoolObjUnlock(obj);
    return ret;
}



static int
testStoragePoolCreate(virStoragePoolPtr pool,
                      unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    privpool->active = 1;

    event = virStoragePoolEventLifecycleNew(pool->name, pool->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);
    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
testConnectFindStoragePoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  const char *type,
                                  const char *srcSpec,
                                  unsigned int flags)
{
    virStoragePoolSourcePtr source = NULL;
    int pool_type;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    pool_type = virStoragePoolTypeFromString(type);
    if (!pool_type) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        ignore_value(VIR_STRDUP(ret, defaultPoolSourcesLogicalXML));
        break;

    case VIR_STORAGE_POOL_NETFS:
        if (!source || !source->hosts[0].name) {
            virReportError(VIR_ERR_INVALID_ARG,
                           "%s", _("hostname must be specified for netfs sources"));
            goto cleanup;
        }

        ignore_value(virAsprintf(&ret, defaultPoolSourcesNetFSXML,
                                 source->hosts[0].name));
        break;

    default:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("pool type '%s' does not support source discovery"), type);
    }

 cleanup:
    virStoragePoolSourceFree(source);
    return ret;
}


static virStoragePoolPtr
testStoragePoolCreateXML(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    pool = virStoragePoolObjFindByUUID(&privconn->pools, def->uuid);
    if (!pool)
        pool = virStoragePoolObjFindByName(&privconn->pools, def->name);
    if (pool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

    event = virStoragePoolEventLifecycleNew(pool->def->name, pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STARTED,
                                            0);

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolDefFree(def);
    testObjectEventQueue(privconn, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    testDriverUnlock(privconn);
    return ret;
}

static virStoragePoolPtr
testStoragePoolDefineXML(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;
    virStoragePoolDefPtr def;
    virStoragePoolObjPtr pool = NULL;
    virStoragePoolPtr ret = NULL;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    if (!(def = virStoragePoolDefParseString(xml)))
        goto cleanup;

    def->capacity = defaultPoolCap;
    def->allocation = defaultPoolAlloc;
    def->available = defaultPoolCap - defaultPoolAlloc;

    if (!(pool = virStoragePoolObjAssignDef(&privconn->pools, def)))
        goto cleanup;
    def = NULL;

    event = virStoragePoolEventLifecycleNew(pool->def->name, pool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_DEFINED,
                                            0);

    if (testStoragePoolObjSetDefaults(pool) == -1) {
        virStoragePoolObjRemove(&privconn->pools, pool);
        pool = NULL;
        goto cleanup;
    }

    ret = virGetStoragePool(conn, pool->def->name, pool->def->uuid,
                            NULL, NULL);

 cleanup:
    virStoragePoolDefFree(def);
    testObjectEventQueue(privconn, event);
    if (pool)
        virStoragePoolObjUnlock(pool);
    testDriverUnlock(privconn);
    return ret;
}

static int
testStoragePoolUndefine(virStoragePoolPtr pool)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;
    virObjectEventPtr event = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is already active"), pool->name);
        goto cleanup;
    }

    event = virStoragePoolEventLifecycleNew(pool->name, pool->uuid,
                                            VIR_STORAGE_POOL_EVENT_UNDEFINED,
                                            0);

    virStoragePoolObjRemove(&privconn->pools, privpool);
    privpool = NULL;
    ret = 0;

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    testObjectEventQueue(privconn, event);
    testDriverUnlock(privconn);
    return ret;
}

static int
testStoragePoolBuild(virStoragePoolPtr pool,
                     unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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
testStoragePoolDestroy(virStoragePoolPtr pool)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;
    virObjectEventPtr event = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privpool->active = 0;
    event = virStoragePoolEventLifecycleNew(privpool->def->name, privpool->def->uuid,
                                            VIR_STORAGE_POOL_EVENT_STOPPED,
                                            0);

    if (privpool->configFile == NULL) {
        virStoragePoolObjRemove(&privconn->pools, privpool);
        privpool = NULL;
    }
    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    testDriverUnlock(privconn);
    return ret;
}


static int
testStoragePoolDelete(virStoragePoolPtr pool,
                      unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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
                       unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;
    virObjectEventPtr event = NULL;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    event = virStoragePoolEventRefreshNew(pool->name, pool->uuid);
    ret = 0;

 cleanup:
    testObjectEventQueue(privconn, event);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int
testStoragePoolGetInfo(virStoragePoolPtr pool,
                       virStoragePoolInfoPtr info)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
testStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                          unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
                            int *autostart)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
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
                            int autostart)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!privpool->configFile) {
        virReportError(VIR_ERR_INVALID_ARG,
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
testStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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
                           int maxnames)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    size_t i = 0;
    int n = 0;

    memset(names, 0, maxnames * sizeof(*names));

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    for (i = 0; i < privpool->volumes.count && n < maxnames; i++) {
        if (VIR_STRDUP(names[n++], privpool->volumes.objs[i]->name) < 0)
            goto cleanup;
    }

    virStoragePoolObjUnlock(privpool);
    return n;

 cleanup:
    for (n = 0; n < maxnames; n++)
        VIR_FREE(names[i]);

    memset(names, 0, maxnames * sizeof(*names));
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return -1;
}

static int
testStoragePoolListAllVolumes(virStoragePoolPtr obj,
                              virStorageVolPtr **vols,
                              unsigned int flags)
{
    testDriverPtr privconn = obj->conn->privateData;
    virStoragePoolObjPtr pool;
    size_t i;
    virStorageVolPtr *tmp_vols = NULL;
    virStorageVolPtr vol = NULL;
    int nvols = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    pool = virStoragePoolObjFindByUUID(&privconn->pools, obj->uuid);
    testDriverUnlock(privconn);

    if (!pool) {
        virReportError(VIR_ERR_NO_STORAGE_POOL, "%s",
                       _("no storage pool with matching uuid"));
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(pool)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("storage pool is not active"));
        goto cleanup;
    }

     /* Just returns the volumes count */
    if (!vols) {
        ret = pool->volumes.count;
        goto cleanup;
    }

    if (VIR_ALLOC_N(tmp_vols, pool->volumes.count + 1) < 0)
         goto cleanup;

    for (i = 0; i < pool->volumes.count; i++) {
        if (!(vol = virGetStorageVol(obj->conn, pool->def->name,
                                     pool->volumes.objs[i]->name,
                                     pool->volumes.objs[i]->key,
                                     NULL, NULL)))
            goto cleanup;
        tmp_vols[nvols++] = vol;
    }

    *vols = tmp_vols;
    tmp_vols = NULL;
    ret = nvols;

 cleanup:
    if (tmp_vols) {
        for (i = 0; i < nvols; i++) {
            if (tmp_vols[i])
                virStorageVolFree(tmp_vols[i]);
        }
        VIR_FREE(tmp_vols);
    }

    if (pool)
        virStoragePoolObjUnlock(pool);

    return ret;
}

static virStorageVolPtr
testStorageVolLookupByName(virStoragePoolPtr pool,
                           const char *name ATTRIBUTE_UNUSED)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, name);

    if (!privvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key,
                           NULL, NULL);

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static virStorageVolPtr
testStorageVolLookupByKey(virConnectPtr conn,
                          const char *key)
{
    testDriverPtr privconn = conn->privateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByKey(privconn->pools.objs[i], key);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name,
                                       privvol->key,
                                       NULL, NULL);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching key '%s'"), key);

    return ret;
}

static virStorageVolPtr
testStorageVolLookupByPath(virConnectPtr conn,
                           const char *path)
{
    testDriverPtr privconn = conn->privateData;
    size_t i;
    virStorageVolPtr ret = NULL;

    testDriverLock(privconn);
    for (i = 0; i < privconn->pools.count; i++) {
        virStoragePoolObjLock(privconn->pools.objs[i]);
        if (virStoragePoolObjIsActive(privconn->pools.objs[i])) {
            virStorageVolDefPtr privvol =
                virStorageVolDefFindByPath(privconn->pools.objs[i], path);

            if (privvol) {
                ret = virGetStorageVol(conn,
                                       privconn->pools.objs[i]->def->name,
                                       privvol->name,
                                       privvol->key,
                                       NULL, NULL);
                virStoragePoolObjUnlock(privconn->pools.objs[i]);
                break;
            }
        }
        virStoragePoolObjUnlock(privconn->pools.objs[i]);
    }
    testDriverUnlock(privconn);

    if (!ret)
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching path '%s'"), path);

    return ret;
}

static virStorageVolPtr
testStorageVolCreateXML(virStoragePoolPtr pool,
                        const char *xmldesc,
                        unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL;
    virStorageVolPtr ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc, 0);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("storage vol already exists"));
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->target.allocation) >
         privpool->def->capacity) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not enough free space in pool for volume '%s'"),
                       privvol->name);
        goto cleanup;
    }

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1)
        goto cleanup;

    if (VIR_STRDUP(privvol->key, privvol->target.path) < 0 ||
        VIR_APPEND_ELEMENT_COPY(privpool->volumes.objs,
                                privpool->volumes.count, privvol) < 0)
        goto cleanup;

    privpool->def->allocation += privvol->target.allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key,
                           NULL, NULL);
    privvol = NULL;

 cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static virStorageVolPtr
testStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                            const char *xmldesc,
                            virStorageVolPtr clonevol,
                            unsigned int flags)
{
    testDriverPtr privconn = pool->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol = NULL, origvol = NULL;
    virStorageVolPtr ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           pool->name);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), pool->name);
        goto cleanup;
    }

    privvol = virStorageVolDefParseString(privpool->def, xmldesc, 0);
    if (privvol == NULL)
        goto cleanup;

    if (virStorageVolDefFindByName(privpool, privvol->name)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("storage vol already exists"));
        goto cleanup;
    }

    origvol = virStorageVolDefFindByName(privpool, clonevol->name);
    if (!origvol) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       clonevol->name);
        goto cleanup;
    }

    /* Make sure enough space */
    if ((privpool->def->allocation + privvol->target.allocation) >
         privpool->def->capacity) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not enough free space in pool for volume '%s'"),
                       privvol->name);
        goto cleanup;
    }
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    if (virAsprintf(&privvol->target.path, "%s/%s",
                    privpool->def->target.path,
                    privvol->name) == -1)
        goto cleanup;

    if (VIR_STRDUP(privvol->key, privvol->target.path) < 0 ||
        VIR_APPEND_ELEMENT_COPY(privpool->volumes.objs,
                                privpool->volumes.count, privvol) < 0)
        goto cleanup;

    privpool->def->allocation += privvol->target.allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    ret = virGetStorageVol(pool->conn, privpool->def->name,
                           privvol->name, privvol->key,
                           NULL, NULL);
    privvol = NULL;

 cleanup:
    virStorageVolDefFree(privvol);
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static int
testStorageVolDelete(virStorageVolPtr vol,
                     unsigned int flags)
{
    testDriverPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    size_t i;
    int ret = -1;

    virCheckFlags(0, -1);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }


    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }


    privpool->def->allocation -= privvol->target.allocation;
    privpool->def->available = (privpool->def->capacity -
                                privpool->def->allocation);

    for (i = 0; i < privpool->volumes.count; i++) {
        if (privpool->volumes.objs[i] == privvol) {
            virStorageVolDefFree(privvol);

            VIR_DELETE_ELEMENT(privpool->volumes.objs, i, privpool->volumes.count);
            break;
        }
    }
    ret = 0;

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


static int testStorageVolumeTypeForPool(int pooltype)
{

    switch (pooltype) {
        case VIR_STORAGE_POOL_DIR:
        case VIR_STORAGE_POOL_FS:
        case VIR_STORAGE_POOL_NETFS:
            return VIR_STORAGE_VOL_FILE;
        default:
            return VIR_STORAGE_VOL_BLOCK;
    }
}

static int
testStorageVolGetInfo(virStorageVolPtr vol,
                      virStorageVolInfoPtr info)
{
    testDriverPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    int ret = -1;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    memset(info, 0, sizeof(*info));
    info->type = testStorageVolumeTypeForPool(privpool->def->type);
    info->capacity = privvol->target.capacity;
    info->allocation = privvol->target.allocation;
    ret = 0;

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}

static char *
testStorageVolGetXMLDesc(virStorageVolPtr vol,
                         unsigned int flags)
{
    testDriverPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
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
testStorageVolGetPath(virStorageVolPtr vol)
{
    testDriverPtr privconn = vol->conn->privateData;
    virStoragePoolObjPtr privpool;
    virStorageVolDefPtr privvol;
    char *ret = NULL;

    testDriverLock(privconn);
    privpool = virStoragePoolObjFindByName(&privconn->pools,
                                           vol->pool);
    testDriverUnlock(privconn);

    if (privpool == NULL) {
        virReportError(VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto cleanup;
    }

    privvol = virStorageVolDefFindByName(privpool, vol->name);

    if (privvol == NULL) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("no storage vol with matching name '%s'"),
                       vol->name);
        goto cleanup;
    }

    if (!virStoragePoolObjIsActive(privpool)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("storage pool '%s' is not active"), vol->pool);
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, privvol->target.path));

 cleanup:
    if (privpool)
        virStoragePoolObjUnlock(privpool);
    return ret;
}


/* Node device implementations */

static int
testNodeNumOfDevices(virConnectPtr conn,
                     const char *cap,
                     unsigned int flags)
{
    testDriverPtr driver = conn->privateData;
    int ndevs = 0;
    size_t i;

    virCheckFlags(0, -1);

    testDriverLock(driver);
    for (i = 0; i < driver->devs.count; i++)
        if ((cap == NULL) ||
            virNodeDeviceObjHasCap(driver->devs.objs[i], cap))
            ++ndevs;
    testDriverUnlock(driver);

    return ndevs;
}

static int
testNodeListDevices(virConnectPtr conn,
                    const char *cap,
                    char **const names,
                    int maxnames,
                    unsigned int flags)
{
    testDriverPtr driver = conn->privateData;
    int ndevs = 0;
    size_t i;

    virCheckFlags(0, -1);

    testDriverLock(driver);
    for (i = 0; i < driver->devs.count && ndevs < maxnames; i++) {
        virNodeDeviceObjLock(driver->devs.objs[i]);
        if (cap == NULL ||
            virNodeDeviceObjHasCap(driver->devs.objs[i], cap)) {
            if (VIR_STRDUP(names[ndevs++], driver->devs.objs[i]->def->name) < 0) {
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
    testDriverPtr driver = conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevicePtr ret = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       name);
        goto cleanup;
    }

    if ((ret = virGetNodeDevice(conn, name))) {
        if (VIR_STRDUP(ret->parent, obj->def->parent) < 0)
            virObjectUnref(ret);
    }

 cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    return ret;
}

static char *
testNodeDeviceGetXMLDesc(virNodeDevicePtr dev,
                         unsigned int flags)
{
    testDriverPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
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
    testDriverPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    char *ret = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    if (obj->def->parent) {
        ignore_value(VIR_STRDUP(ret, obj->def->parent));
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    testDriverPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
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
    testDriverPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj;
    virNodeDevCapsDefPtr caps;
    int ncaps = 0;
    int ret = -1;

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto cleanup;
    }

    for (caps = obj->def->caps; caps && ncaps < maxnames; caps = caps->next) {
        if (VIR_STRDUP(names[ncaps++], virNodeDevCapTypeToString(caps->data.type)) < 0)
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


static virNodeDeviceObjPtr
testNodeDeviceMockCreateVport(testDriverPtr driver,
                              const char *wwnn,
                              const char *wwpn)
{
    char *xml = NULL;
    virNodeDeviceDefPtr def = NULL;
    virNodeDevCapsDefPtr caps;
    virNodeDeviceObjPtr obj = NULL, objcopy = NULL;
    virObjectEventPtr event = NULL;

    /* In the real code, we'd call virVHBAManageVport which would take the
     * wwnn/wwpn from the input XML in order to call the "vport_create"
     * function for the parent. That in turn would set off a sequence of
     * events resulting in the creation of a vHBA scsi_hostN in the
     * node device objects list using the "next" host number with the
     * wwnn/wwpn from the input XML. The following will mock this by
     * using the scsi_host11 definition, changing the name and the
     * scsi_host capability fields before calling virNodeDeviceAssignDef
     * to add the def to the node device objects list. */
    if (!(objcopy = virNodeDeviceObjFindByName(&driver->devs, "scsi_host11")))
        goto cleanup;

    xml = virNodeDeviceDefFormat(objcopy->def);
    virNodeDeviceObjUnlock(objcopy);
    if (!xml)
        goto cleanup;

    if (!(def = virNodeDeviceDefParseString(xml, EXISTING_DEVICE, NULL)))
        goto cleanup;

    VIR_FREE(def->name);
    if (VIR_STRDUP(def->name, "scsi_host12") < 0)
        goto cleanup;

    /* Find the 'scsi_host' cap and alter the host # and unique_id and
     * then for the 'fc_host' capability modify the wwnn/wwpn to be that
     * of the input XML. */
    caps = def->caps;
    while (caps) {
        if (caps->data.type != VIR_NODE_DEV_CAP_SCSI_HOST)
            continue;

        /* For the "fc_host" cap - change the wwnn/wwpn to match the input */
        if (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
            VIR_FREE(caps->data.scsi_host.wwnn);
            VIR_FREE(caps->data.scsi_host.wwpn);
            if (VIR_STRDUP(caps->data.scsi_host.wwnn, wwnn) < 0 ||
                VIR_STRDUP(caps->data.scsi_host.wwpn, wwpn) < 0)
                goto cleanup;
        } else {
            /* For the "scsi_host" cap, increment our host and unique_id to
             * give the appearance that something new was created - then add
             * that to the node device driver */
            caps->data.scsi_host.host++;
            caps->data.scsi_host.unique_id++;
        }
        caps = caps->next;
    }

    if (!(obj = virNodeDeviceObjAssignDef(&driver->devs, def)))
        goto cleanup;
    def = NULL;

    event = virNodeDeviceEventLifecycleNew(obj->def->name,
                                           VIR_NODE_DEVICE_EVENT_CREATED,
                                           0);
    testObjectEventQueue(driver, event);

 cleanup:
    VIR_FREE(xml);
    virNodeDeviceDefFree(def);
    return obj;
}


static virNodeDevicePtr
testNodeDeviceCreateXML(virConnectPtr conn,
                        const char *xmlDesc,
                        unsigned int flags)
{
    testDriverPtr driver = conn->privateData;
    virNodeDeviceDefPtr def = NULL;
    char *wwnn = NULL, *wwpn = NULL;
    virNodeDevicePtr dev = NULL, ret = NULL;
    virNodeDeviceObjPtr obj = NULL;

    virCheckFlags(0, NULL);

    testDriverLock(driver);

    if (!(def = virNodeDeviceDefParseString(xmlDesc, CREATE_DEVICE, NULL)))
        goto cleanup;

    /* We run this simply for validation - it essentially validates that
     * the input XML either has a wwnn/wwpn or virNodeDevCapSCSIHostParseXML
     * generated a wwnn/wwpn */
    if (virNodeDeviceGetWWNs(def, &wwnn, &wwpn) < 0)
        goto cleanup;

    /* Unlike the "real" code we don't need the parent_host in order to
     * call virVHBAManageVport, but still let's make sure the code finds
     * something valid and no one messed up the mock environment. */
    if (virNodeDeviceObjGetParentHost(&driver->devs, def, CREATE_DEVICE) < 0)
        goto cleanup;

    /* In the real code, we'd call virVHBAManageVport followed by
     * find_new_device, but we cannot do that here since we're not
     * mocking udev. The mock routine will copy an existing vHBA and
     * rename a few fields to mock that. So in order to allow that to
     * work properly, we need to drop our lock */
    if (!(obj = testNodeDeviceMockCreateVport(driver, wwnn, wwpn)))
        goto cleanup;

    if (!(dev = virGetNodeDevice(conn, obj->def->name)))
        goto cleanup;

    VIR_FREE(dev->parent);
    if (VIR_STRDUP(dev->parent, def->parent) < 0)
        goto cleanup;

    ret = dev;
    dev = NULL;

 cleanup:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    testDriverUnlock(driver);
    virNodeDeviceDefFree(def);
    virObjectUnref(dev);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}

static int
testNodeDeviceDestroy(virNodeDevicePtr dev)
{
    int ret = 0;
    testDriverPtr driver = dev->conn->privateData;
    virNodeDeviceObjPtr obj = NULL;
    char *parent_name = NULL, *wwnn = NULL, *wwpn = NULL;
    virObjectEventPtr event = NULL;

    testDriverLock(driver);
    obj = virNodeDeviceObjFindByName(&driver->devs, dev->name);
    testDriverUnlock(driver);

    if (!obj) {
        virReportError(VIR_ERR_NO_NODE_DEVICE,
                       _("no node device with matching name '%s'"),
                       dev->name);
        goto out;
    }

    if (virNodeDeviceGetWWNs(obj->def, &wwnn, &wwpn) == -1)
        goto out;

    if (VIR_STRDUP(parent_name, obj->def->parent) < 0)
        goto out;

    /* virNodeDeviceGetParentHost will cause the device object's lock to be
     * taken, so we have to dup the parent's name and drop the lock
     * before calling it.  We don't need the reference to the object
     * any more once we have the parent's name.  */
    virNodeDeviceObjUnlock(obj);

    /* We do this just for basic validation, but also avoid finding a
     * vport capable HBA if for some reason our vHBA doesn't exist */
    if (virNodeDeviceObjGetParentHost(&driver->devs, obj->def,
                                      EXISTING_DEVICE) < 0) {
        obj = NULL;
        goto out;
    }

    event = virNodeDeviceEventLifecycleNew(dev->name,
                                           VIR_NODE_DEVICE_EVENT_DELETED,
                                           0);

    virNodeDeviceObjLock(obj);
    virNodeDeviceObjRemove(&driver->devs, &obj);

 out:
    if (obj)
        virNodeDeviceObjUnlock(obj);
    testObjectEventQueue(driver, event);
    VIR_FREE(parent_name);
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    return ret;
}


/* Domain event implementations */
static int
testConnectDomainEventRegister(virConnectPtr conn,
                               virConnectDomainEventCallback callback,
                               void *opaque,
                               virFreeCallback freecb)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virDomainEventStateRegister(conn, driver->eventState,
                                    callback, opaque, freecb) < 0)
        ret = -1;

    return ret;
}


static int
testConnectDomainEventDeregister(virConnectPtr conn,
                                 virConnectDomainEventCallback callback)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virDomainEventStateDeregister(conn, driver->eventState,
                                      callback) < 0)
        ret = -1;

    return ret;
}


static int
testConnectDomainEventRegisterAny(virConnectPtr conn,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback callback,
                                  void *opaque,
                                  virFreeCallback freecb)
{
    testDriverPtr driver = conn->privateData;
    int ret;

    if (virDomainEventStateRegisterID(conn, driver->eventState,
                                      dom, eventID,
                                      callback, opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
testConnectDomainEventDeregisterAny(virConnectPtr conn,
                                    int callbackID)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virObjectEventStateDeregisterID(conn, driver->eventState,
                                        callbackID) < 0)
        ret = -1;

    return ret;
}


static int
testConnectNetworkEventRegisterAny(virConnectPtr conn,
                                   virNetworkPtr net,
                                   int eventID,
                                   virConnectNetworkEventGenericCallback callback,
                                   void *opaque,
                                   virFreeCallback freecb)
{
    testDriverPtr driver = conn->privateData;
    int ret;

    if (virNetworkEventStateRegisterID(conn, driver->eventState,
                                       net, eventID, callback,
                                       opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
testConnectNetworkEventDeregisterAny(virConnectPtr conn,
                                     int callbackID)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virObjectEventStateDeregisterID(conn, driver->eventState,
                                        callbackID) < 0)
        ret = -1;

    return ret;
}

static int
testConnectStoragePoolEventRegisterAny(virConnectPtr conn,
                                       virStoragePoolPtr pool,
                                       int eventID,
                                       virConnectStoragePoolEventGenericCallback callback,
                                       void *opaque,
                                       virFreeCallback freecb)
{
    testDriverPtr driver = conn->privateData;
    int ret;

    if (virStoragePoolEventStateRegisterID(conn, driver->eventState,
                                           pool, eventID, callback,
                                           opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
testConnectStoragePoolEventDeregisterAny(virConnectPtr conn,
                                         int callbackID)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virObjectEventStateDeregisterID(conn, driver->eventState,
                                        callbackID) < 0)
        ret = -1;

    return ret;
}

static int
testConnectNodeDeviceEventRegisterAny(virConnectPtr conn,
                                      virNodeDevicePtr dev,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    testDriverPtr driver = conn->privateData;
    int ret;

    if (virNodeDeviceEventStateRegisterID(conn, driver->eventState,
                                          dev, eventID, callback,
                                          opaque, freecb, &ret) < 0)
        ret = -1;

    return ret;
}

static int
testConnectNodeDeviceEventDeregisterAny(virConnectPtr conn,
                                        int callbackID)
{
    testDriverPtr driver = conn->privateData;
    int ret = 0;

    if (virObjectEventStateDeregisterID(conn, driver->eventState,
                                        callbackID) < 0)
        ret = -1;

    return ret;
}

static int testConnectListAllDomains(virConnectPtr conn,
                                     virDomainPtr **domains,
                                     unsigned int flags)
{
    testDriverPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL, -1);

    return virDomainObjListExport(privconn->domains, conn, domains,
                                  NULL, flags);
}

static int
testNodeGetCPUMap(virConnectPtr conn ATTRIBUTE_UNUSED,
                  unsigned char **cpumap,
                  unsigned int *online,
                  unsigned int flags)
{
    virCheckFlags(0, -1);

    if (cpumap) {
        if (VIR_ALLOC_N(*cpumap, 1) < 0)
            return -1;
        *cpumap[0] = 0x15;
    }

    if (online)
        *online = 3;

    return  8;
}

static char *
testDomainScreenshot(virDomainPtr dom ATTRIBUTE_UNUSED,
                     virStreamPtr st,
                     unsigned int screen ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    char *ret = NULL;

    virCheckFlags(0, NULL);

    if (VIR_STRDUP(ret, "image/png") < 0)
        return NULL;

    if (virFDStreamOpenFile(st, PKGDATADIR "/test-screenshot.png", 0, 0, O_RDONLY) < 0)
        VIR_FREE(ret);

    return ret;
}

static int
testConnectGetCPUModelNames(virConnectPtr conn ATTRIBUTE_UNUSED,
                            const char *archName,
                            char ***models,
                            unsigned int flags)
{
    virArch arch;

    virCheckFlags(0, -1);

    if (!(arch = virArchFromString(archName))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cannot find architecture %s"),
                       archName);
        return -1;
    }

    return virCPUGetModels(arch, models);
}

static int
testDomainManagedSave(virDomainPtr dom, unsigned int flags)
{
    testDriverPtr privconn = dom->conn->privateData;
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SAVE_BYPASS_CACHE |
                  VIR_DOMAIN_SAVE_RUNNING |
                  VIR_DOMAIN_SAVE_PAUSED, -1);

    if (!(vm = testDomObjFromDomain(dom)))
        return -1;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto cleanup;
    }

    if (!vm->persistent) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot do managed save for transient domain"));
        goto cleanup;
    }

    testDomainShutdownState(dom, vm, VIR_DOMAIN_SHUTOFF_SAVED);
    event = virDomainEventLifecycleNewFromObj(vm,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_SAVED);
    vm->hasManagedSave = true;

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&vm);
    testObjectEventQueue(privconn, event);

    return ret;
}


static int
testDomainHasManagedSaveImage(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;
    int ret;

    virCheckFlags(0, -1);

    if (!(vm = testDomObjFromDomain(dom)))
        return -1;

    ret = vm->hasManagedSave;

    virDomainObjEndAPI(&vm);
    return ret;
}

static int
testDomainManagedSaveRemove(virDomainPtr dom, unsigned int flags)
{
    virDomainObjPtr vm;

    virCheckFlags(0, -1);

    if (!(vm = testDomObjFromDomain(dom)))
        return -1;

    vm->hasManagedSave = false;

    virDomainObjEndAPI(&vm);
    return 0;
}


/*
 * Snapshot APIs
 */

static virDomainSnapshotObjPtr
testSnapObjFromName(virDomainObjPtr vm,
                    const char *name)
{
    virDomainSnapshotObjPtr snap = NULL;
    snap = virDomainSnapshotFindByName(vm->snapshots, name);
    if (!snap)
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("no domain snapshot with matching name '%s'"),
                       name);
    return snap;
}

static virDomainSnapshotObjPtr
testSnapObjFromSnapshot(virDomainObjPtr vm,
                        virDomainSnapshotPtr snapshot)
{
    return testSnapObjFromName(vm, snapshot->name);
}

static virDomainObjPtr
testDomObjFromSnapshot(virDomainSnapshotPtr snapshot)
{
    return testDomObjFromDomain(snapshot->domain);
}

static int
testDomainSnapshotNum(virDomainPtr domain, unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromDomain(domain)))
        return -1;

    n = virDomainSnapshotObjListNum(vm->snapshots, NULL, flags);

    virDomainObjEndAPI(&vm);
    return n;
}

static int
testDomainSnapshotListNames(virDomainPtr domain,
                            char **names,
                            int nameslen,
                            unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromDomain(domain)))
        return -1;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, NULL, names, nameslen,
                                         flags);

    virDomainObjEndAPI(&vm);
    return n;
}

static int
testDomainListAllSnapshots(virDomainPtr domain,
                           virDomainSnapshotPtr **snaps,
                           unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int n;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_ROOTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromDomain(domain)))
        return -1;

    n = virDomainListSnapshots(vm->snapshots, NULL, domain, snaps, flags);

    virDomainObjEndAPI(&vm);
    return n;
}

static int
testDomainSnapshotListChildrenNames(virDomainSnapshotPtr snapshot,
                                    char **names,
                                    int nameslen,
                                    unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListGetNames(vm->snapshots, snap, names, nameslen,
                                         flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}

static int
testDomainSnapshotNumChildren(virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainSnapshotObjListNum(vm->snapshots, snap, flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}

static int
testDomainSnapshotListAllChildren(virDomainSnapshotPtr snapshot,
                                  virDomainSnapshotPtr **snaps,
                                  unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    int n = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_LIST_DESCENDANTS |
                  VIR_DOMAIN_SNAPSHOT_FILTERS_ALL, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    n = virDomainListSnapshots(vm->snapshots, snap, snapshot->domain, snaps,
                               flags);

 cleanup:
    virDomainObjEndAPI(&vm);
    return n;
}

static virDomainSnapshotPtr
testDomainSnapshotLookupByName(virDomainPtr domain,
                               const char *name,
                               unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = testDomObjFromDomain(domain)))
        return NULL;

    if (!(snap = testSnapObjFromName(vm, name)))
        goto cleanup;

    snapshot = virGetDomainSnapshot(domain, snap->def->name);

 cleanup:
    virDomainObjEndAPI(&vm);
    return snapshot;
}

static int
testDomainHasCurrentSnapshot(virDomainPtr domain,
                             unsigned int flags)
{
    virDomainObjPtr vm;
    int ret;

    virCheckFlags(0, -1);

    if (!(vm = testDomObjFromDomain(domain)))
        return -1;

    ret = (vm->current_snapshot != NULL);

    virDomainObjEndAPI(&vm);
    return ret;
}

static virDomainSnapshotPtr
testDomainSnapshotGetParent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr parent = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return NULL;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (!snap->def->parent) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT,
                       _("snapshot '%s' does not have a parent"),
                       snap->def->name);
        goto cleanup;
    }

    parent = virGetDomainSnapshot(snapshot->domain, snap->def->parent);

 cleanup:
    virDomainObjEndAPI(&vm);
    return parent;
}

static virDomainSnapshotPtr
testDomainSnapshotCurrent(virDomainPtr domain,
                          unsigned int flags)
{
    virDomainObjPtr vm;
    virDomainSnapshotPtr snapshot = NULL;

    virCheckFlags(0, NULL);

    if (!(vm = testDomObjFromDomain(domain)))
        return NULL;

    if (!vm->current_snapshot) {
        virReportError(VIR_ERR_NO_DOMAIN_SNAPSHOT, "%s",
                       _("the domain does not have a current snapshot"));
        goto cleanup;
    }

    snapshot = virGetDomainSnapshot(domain, vm->current_snapshot->def->name);

 cleanup:
    virDomainObjEndAPI(&vm);
    return snapshot;
}

static char *
testDomainSnapshotGetXMLDesc(virDomainSnapshotPtr snapshot,
                             unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    char *xml = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    testDriverPtr privconn = snapshot->domain->conn->privateData;

    virCheckFlags(VIR_DOMAIN_XML_SECURE, NULL);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return NULL;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    virUUIDFormat(snapshot->domain->uuid, uuidstr);

    xml = virDomainSnapshotDefFormat(uuidstr, snap->def, privconn->caps,
                                     virDomainDefFormatConvertXMLFlags(flags),
                                     0);

 cleanup:
    virDomainObjEndAPI(&vm);
    return xml;
}

static int
testDomainSnapshotIsCurrent(virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret;

    virCheckFlags(0, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    ret = (vm->current_snapshot &&
           STREQ(snapshot->name, vm->current_snapshot->def->name));

    virDomainObjEndAPI(&vm);
    return ret;
}


static int
testDomainSnapshotHasMetadata(virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!testSnapObjFromSnapshot(vm, snapshot))
        goto cleanup;

    ret = 1;

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
testDomainSnapshotAlignDisks(virDomainObjPtr vm,
                             virDomainSnapshotDefPtr def,
                             unsigned int flags)
{
    int align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    bool align_match = true;

    if (flags & VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY) {
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
        align_match = false;
        if (virDomainObjIsActive(vm))
            def->state = VIR_DOMAIN_DISK_SNAPSHOT;
        else
            def->state = VIR_DOMAIN_SHUTOFF;
        def->memory = VIR_DOMAIN_SNAPSHOT_LOCATION_NONE;
    } else if (def->memory == VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL) {
        def->state = virDomainObjGetState(vm, NULL);
        align_location = VIR_DOMAIN_SNAPSHOT_LOCATION_EXTERNAL;
        align_match = false;
    } else {
        def->state = virDomainObjGetState(vm, NULL);
        def->memory = def->state == VIR_DOMAIN_SHUTOFF ?
                      VIR_DOMAIN_SNAPSHOT_LOCATION_NONE :
                      VIR_DOMAIN_SNAPSHOT_LOCATION_INTERNAL;
    }

    return virDomainSnapshotAlignDisks(def, align_location, align_match);
}

static virDomainSnapshotPtr
testDomainSnapshotCreateXML(virDomainPtr domain,
                            const char *xmlDesc,
                            unsigned int flags)
{
    testDriverPtr privconn = domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainSnapshotDefPtr def = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotPtr snapshot = NULL;
    virObjectEventPtr event = NULL;
    char *xml = NULL;
    bool update_current = true;
    bool redefine = flags & VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE;
    unsigned int parse_flags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;

    /*
     * DISK_ONLY: Not implemented yet
     * REUSE_EXT: Not implemented yet
     *
     * NO_METADATA: Explicitly not implemented
     *
     * REDEFINE + CURRENT: Implemented
     * HALT: Implemented
     * QUIESCE: Nothing to do
     * ATOMIC: Nothing to do
     * LIVE: Nothing to do
     */
    virCheckFlags(
        VIR_DOMAIN_SNAPSHOT_CREATE_REDEFINE |
        VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT |
        VIR_DOMAIN_SNAPSHOT_CREATE_HALT |
        VIR_DOMAIN_SNAPSHOT_CREATE_QUIESCE |
        VIR_DOMAIN_SNAPSHOT_CREATE_ATOMIC |
        VIR_DOMAIN_SNAPSHOT_CREATE_LIVE, NULL);

    if ((redefine && !(flags & VIR_DOMAIN_SNAPSHOT_CREATE_CURRENT)))
        update_current = false;
    if (redefine)
        parse_flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (!(vm = testDomObjFromDomain(domain)))
        goto cleanup;

    if (!vm->persistent && (flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot halt after transient domain snapshot"));
        goto cleanup;
    }

    if (!(def = virDomainSnapshotDefParseString(xmlDesc,
                                                privconn->caps,
                                                privconn->xmlopt,
                                                parse_flags)))
        goto cleanup;

    if (redefine) {
        if (virDomainSnapshotRedefinePrep(domain, vm, &def, &snap,
                                          &update_current, flags) < 0)
            goto cleanup;
    } else {
        if (!(def->dom = virDomainDefCopy(vm->def,
                                          privconn->caps,
                                          privconn->xmlopt,
                                          NULL,
                                          true)))
            goto cleanup;

        if (testDomainSnapshotAlignDisks(vm, def, flags) < 0)
            goto cleanup;
    }

    if (!snap) {
        if (!(snap = virDomainSnapshotAssignDef(vm->snapshots, def)))
            goto cleanup;
        def = NULL;
    }

    if (!redefine) {
        if (vm->current_snapshot &&
            (VIR_STRDUP(snap->def->parent,
                        vm->current_snapshot->def->name) < 0))
            goto cleanup;

        if ((flags & VIR_DOMAIN_SNAPSHOT_CREATE_HALT) &&
            virDomainObjIsActive(vm)) {
            testDomainShutdownState(domain, vm,
                                    VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT);
            event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_STOPPED,
                                    VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        }
    }

    snapshot = virGetDomainSnapshot(domain, snap->def->name);
 cleanup:
    VIR_FREE(xml);
    if (vm) {
        if (snapshot) {
            virDomainSnapshotObjPtr other;
            if (update_current)
                vm->current_snapshot = snap;
            other = virDomainSnapshotFindByName(vm->snapshots,
                                                snap->def->parent);
            snap->parent = other;
            other->nchildren++;
            snap->sibling = other->first_child;
            other->first_child = snap;
        }
        virDomainObjEndAPI(&vm);
    }
    testObjectEventQueue(privconn, event);
    virDomainSnapshotDefFree(def);
    return snapshot;
}


typedef struct _testSnapRemoveData testSnapRemoveData;
typedef testSnapRemoveData *testSnapRemoveDataPtr;
struct _testSnapRemoveData {
    virDomainObjPtr vm;
    bool current;
};

static int
testDomainSnapshotDiscardAll(void *payload,
                             const void *name ATTRIBUTE_UNUSED,
                             void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    testSnapRemoveDataPtr curr = data;

    if (snap->def->current)
        curr->current = true;
    virDomainSnapshotObjListRemove(curr->vm->snapshots, snap);
    return 0;
}

typedef struct _testSnapReparentData testSnapReparentData;
typedef testSnapReparentData *testSnapReparentDataPtr;
struct _testSnapReparentData {
    virDomainSnapshotObjPtr parent;
    virDomainObjPtr vm;
    int err;
    virDomainSnapshotObjPtr last;
};

static int
testDomainSnapshotReparentChildren(void *payload,
                                   const void *name ATTRIBUTE_UNUSED,
                                   void *data)
{
    virDomainSnapshotObjPtr snap = payload;
    testSnapReparentDataPtr rep = data;

    if (rep->err < 0)
        return 0;

    VIR_FREE(snap->def->parent);
    snap->parent = rep->parent;

    if (rep->parent->def &&
        VIR_STRDUP(snap->def->parent, rep->parent->def->name) < 0) {
        rep->err = -1;
        return 0;
    }

    if (!snap->sibling)
        rep->last = snap;
    return 0;
}

static int
testDomainSnapshotDelete(virDomainSnapshotPtr snapshot,
                         unsigned int flags)
{
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virDomainSnapshotObjPtr parentsnap = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                  VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY, -1);

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (flags & (VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN |
                 VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)) {
        testSnapRemoveData rem;
        rem.vm = vm;
        rem.current = false;
        virDomainSnapshotForEachDescendant(snap,
                                           testDomainSnapshotDiscardAll,
                                           &rem);
        if (rem.current) {
            if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY)
                snap->def->current = true;
            vm->current_snapshot = snap;
        }
    } else if (snap->nchildren) {
        testSnapReparentData rep;
        rep.parent = snap->parent;
        rep.vm = vm;
        rep.err = 0;
        rep.last = NULL;
        virDomainSnapshotForEachChild(snap,
                                      testDomainSnapshotReparentChildren,
                                      &rep);
        if (rep.err < 0)
            goto cleanup;

        /* Can't modify siblings during ForEachChild, so do it now.  */
        snap->parent->nchildren += snap->nchildren;
        rep.last->sibling = snap->parent->first_child;
        snap->parent->first_child = snap->first_child;
    }

    if (flags & VIR_DOMAIN_SNAPSHOT_DELETE_CHILDREN_ONLY) {
        snap->nchildren = 0;
        snap->first_child = NULL;
    } else {
        virDomainSnapshotDropParent(snap);
        if (snap == vm->current_snapshot) {
            if (snap->def->parent) {
                parentsnap = virDomainSnapshotFindByName(vm->snapshots,
                                                         snap->def->parent);
                if (!parentsnap) {
                    VIR_WARN("missing parent snapshot matching name '%s'",
                             snap->def->parent);
                } else {
                    parentsnap->def->current = true;
                }
            }
            vm->current_snapshot = parentsnap;
        }
        virDomainSnapshotObjListRemove(vm->snapshots, snap);
    }

    ret = 0;
 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}

static int
testDomainRevertToSnapshot(virDomainSnapshotPtr snapshot,
                           unsigned int flags)
{
    testDriverPtr privconn = snapshot->domain->conn->privateData;
    virDomainObjPtr vm = NULL;
    virDomainSnapshotObjPtr snap = NULL;
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    virDomainDefPtr config = NULL;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED |
                  VIR_DOMAIN_SNAPSHOT_REVERT_FORCE, -1);

    /* We have the following transitions, which create the following events:
     * 1. inactive -> inactive: none
     * 2. inactive -> running:  EVENT_STARTED
     * 3. inactive -> paused:   EVENT_STARTED, EVENT_PAUSED
     * 4. running  -> inactive: EVENT_STOPPED
     * 5. running  -> running:  none
     * 6. running  -> paused:   EVENT_PAUSED
     * 7. paused   -> inactive: EVENT_STOPPED
     * 8. paused   -> running:  EVENT_RESUMED
     * 9. paused   -> paused:   none
     * Also, several transitions occur even if we fail partway through,
     * and use of FORCE can cause multiple transitions.
     */

    if (!(vm = testDomObjFromSnapshot(snapshot)))
        return -1;

    if (!(snap = testSnapObjFromSnapshot(vm, snapshot)))
        goto cleanup;

    if (!vm->persistent &&
        snap->def->state != VIR_DOMAIN_RUNNING &&
        snap->def->state != VIR_DOMAIN_PAUSED &&
        (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                  VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) == 0) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("transient domain needs to request run or pause "
                         "to revert to inactive snapshot"));
        goto cleanup;
    }

    if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
        if (!snap->def->dom) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY,
                           _("snapshot '%s' lacks domain '%s' rollback info"),
                           snap->def->name, vm->def->name);
            goto cleanup;
        }
        if (virDomainObjIsActive(vm) &&
            !(snap->def->state == VIR_DOMAIN_RUNNING
              || snap->def->state == VIR_DOMAIN_PAUSED) &&
            (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                      VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                           _("must respawn guest to start inactive snapshot"));
            goto cleanup;
        }
    }


    if (vm->current_snapshot) {
        vm->current_snapshot->def->current = false;
        vm->current_snapshot = NULL;
    }

    snap->def->current = true;
    config = virDomainDefCopy(snap->def->dom, privconn->caps,
                              privconn->xmlopt, NULL, true);
    if (!config)
        goto cleanup;

    if (snap->def->state == VIR_DOMAIN_RUNNING ||
        snap->def->state == VIR_DOMAIN_PAUSED) {
        /* Transitions 2, 3, 5, 6, 8, 9 */
        bool was_running = false;
        bool was_stopped = false;

        if (virDomainObjIsActive(vm)) {
            /* Transitions 5, 6, 8, 9 */
            /* Check for ABI compatibility.  */
            if (!virDomainDefCheckABIStability(vm->def, config)) {
                virErrorPtr err = virGetLastError();

                if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_FORCE)) {
                    /* Re-spawn error using correct category. */
                    if (err->code == VIR_ERR_CONFIG_UNSUPPORTED)
                        virReportError(VIR_ERR_SNAPSHOT_REVERT_RISKY, "%s",
                                       err->str2);
                    goto cleanup;
                }

                virResetError(err);
                testDomainShutdownState(snapshot->domain, vm,
                                        VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT);
                event = virDomainEventLifecycleNewFromObj(vm,
                            VIR_DOMAIN_EVENT_STOPPED,
                            VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
                testObjectEventQueue(privconn, event);
                goto load;
            }

            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
                /* Transitions 5, 6 */
                was_running = true;
                virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                     VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
                /* Create an event now in case the restore fails, so
                 * that user will be alerted that they are now paused.
                 * If restore later succeeds, we might replace this. */
                event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_SUSPENDED,
                                VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
            }
            virDomainObjAssignDef(vm, config, false, NULL);

        } else {
            /* Transitions 2, 3 */
        load:
            was_stopped = true;
            virDomainObjAssignDef(vm, config, false, NULL);
            if (testDomainStartState(privconn, vm,
                                VIR_DOMAIN_RUNNING_FROM_SNAPSHOT) < 0)
                goto cleanup;
            event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_STARTED,
                                VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT);
        }

        /* Touch up domain state.  */
        if (!(flags & VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING) &&
            (snap->def->state == VIR_DOMAIN_PAUSED ||
             (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED))) {
            /* Transitions 3, 6, 9 */
            virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                 VIR_DOMAIN_PAUSED_FROM_SNAPSHOT);
            if (was_stopped) {
                /* Transition 3, use event as-is and add event2 */
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_SUSPENDED,
                                VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
            } /* else transition 6 and 9 use event as-is */
        } else {
            /* Transitions 2, 5, 8 */
            virObjectUnref(event);
            event = NULL;

            if (was_stopped) {
                /* Transition 2 */
                event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_STARTED,
                                VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT);
            } else if (was_running) {
                /* Transition 8 */
                event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_RESUMED,
                                VIR_DOMAIN_EVENT_RESUMED);
            }
        }
    } else {
        /* Transitions 1, 4, 7 */
        virDomainObjAssignDef(vm, config, false, NULL);

        if (virDomainObjIsActive(vm)) {
            /* Transitions 4, 7 */
            testDomainShutdownState(snapshot->domain, vm,
                                    VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT);
            event = virDomainEventLifecycleNewFromObj(vm,
                                    VIR_DOMAIN_EVENT_STOPPED,
                                    VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT);
        }

        if (flags & (VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING |
                     VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED)) {
            /* Flush first event, now do transition 2 or 3 */
            bool paused = (flags & VIR_DOMAIN_SNAPSHOT_REVERT_PAUSED) != 0;

            testObjectEventQueue(privconn, event);
            event = virDomainEventLifecycleNewFromObj(vm,
                            VIR_DOMAIN_EVENT_STARTED,
                            VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT);
            if (paused) {
                event2 = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_SUSPENDED,
                                VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT);
            }
        }
    }

    vm->current_snapshot = snap;
    ret = 0;
 cleanup:
    if (event) {
        testObjectEventQueue(privconn, event);
        testObjectEventQueue(privconn, event2);
    } else {
        virObjectUnref(event2);
    }
    virDomainObjEndAPI(&vm);

    return ret;
}



static virHypervisorDriver testHypervisorDriver = {
    .name = "Test",
    .connectOpen = testConnectOpen, /* 0.1.1 */
    .connectClose = testConnectClose, /* 0.1.1 */
    .connectGetVersion = testConnectGetVersion, /* 0.1.1 */
    .connectGetHostname = testConnectGetHostname, /* 0.6.3 */
    .connectGetMaxVcpus = testConnectGetMaxVcpus, /* 0.3.2 */
    .nodeGetInfo = testNodeGetInfo, /* 0.1.1 */
    .nodeGetCPUStats = testNodeGetCPUStats, /* 2.3.0 */
    .nodeGetFreeMemory = testNodeGetFreeMemory, /* 2.3.0 */
    .nodeGetFreePages = testNodeGetFreePages, /* 2.3.0 */
    .connectGetCapabilities = testConnectGetCapabilities, /* 0.2.1 */
    .connectGetSysinfo = testConnectGetSysinfo, /* 2.3.0 */
    .connectGetType = testConnectGetType, /* 2.3.0 */
    .connectListDomains = testConnectListDomains, /* 0.1.1 */
    .connectNumOfDomains = testConnectNumOfDomains, /* 0.1.1 */
    .connectListAllDomains = testConnectListAllDomains, /* 0.9.13 */
    .domainCreateXML = testDomainCreateXML, /* 0.1.4 */
    .domainLookupByID = testDomainLookupByID, /* 0.1.1 */
    .domainLookupByUUID = testDomainLookupByUUID, /* 0.1.1 */
    .domainLookupByName = testDomainLookupByName, /* 0.1.1 */
    .domainSuspend = testDomainSuspend, /* 0.1.1 */
    .domainResume = testDomainResume, /* 0.1.1 */
    .domainShutdown = testDomainShutdown, /* 0.1.1 */
    .domainShutdownFlags = testDomainShutdownFlags, /* 0.9.10 */
    .domainReboot = testDomainReboot, /* 0.1.1 */
    .domainDestroy = testDomainDestroy, /* 0.1.1 */
    .domainGetOSType = testDomainGetOSType, /* 0.1.9 */
    .domainGetMaxMemory = testDomainGetMaxMemory, /* 0.1.4 */
    .domainSetMaxMemory = testDomainSetMaxMemory, /* 0.1.1 */
    .domainSetMemory = testDomainSetMemory, /* 0.1.4 */
    .domainGetInfo = testDomainGetInfo, /* 0.1.1 */
    .domainGetState = testDomainGetState, /* 0.9.2 */
    .domainSave = testDomainSave, /* 0.3.2 */
    .domainSaveFlags = testDomainSaveFlags, /* 0.9.4 */
    .domainRestore = testDomainRestore, /* 0.3.2 */
    .domainRestoreFlags = testDomainRestoreFlags, /* 0.9.4 */
    .domainCoreDump = testDomainCoreDump, /* 0.3.2 */
    .domainCoreDumpWithFormat = testDomainCoreDumpWithFormat, /* 1.2.3 */
    .domainSetVcpus = testDomainSetVcpus, /* 0.1.4 */
    .domainSetVcpusFlags = testDomainSetVcpusFlags, /* 0.8.5 */
    .domainGetVcpusFlags = testDomainGetVcpusFlags, /* 0.8.5 */
    .domainPinVcpu = testDomainPinVcpu, /* 0.7.3 */
    .domainGetVcpus = testDomainGetVcpus, /* 0.7.3 */
    .domainGetVcpuPinInfo = testDomainGetVcpuPinInfo, /* 1.2.18 */
    .domainGetMaxVcpus = testDomainGetMaxVcpus, /* 0.7.3 */
    .domainGetXMLDesc = testDomainGetXMLDesc, /* 0.1.4 */
    .connectListDefinedDomains = testConnectListDefinedDomains, /* 0.1.11 */
    .connectNumOfDefinedDomains = testConnectNumOfDefinedDomains, /* 0.1.11 */
    .domainCreate = testDomainCreate, /* 0.1.11 */
    .domainCreateWithFlags = testDomainCreateWithFlags, /* 0.8.2 */
    .domainDefineXML = testDomainDefineXML, /* 0.1.11 */
    .domainDefineXMLFlags = testDomainDefineXMLFlags, /* 1.2.12 */
    .domainUndefine = testDomainUndefine, /* 0.1.11 */
    .domainUndefineFlags = testDomainUndefineFlags, /* 0.9.4 */
    .domainGetAutostart = testDomainGetAutostart, /* 0.3.2 */
    .domainSetAutostart = testDomainSetAutostart, /* 0.3.2 */
    .domainGetSchedulerType = testDomainGetSchedulerType, /* 0.3.2 */
    .domainGetSchedulerParameters = testDomainGetSchedulerParameters, /* 0.3.2 */
    .domainGetSchedulerParametersFlags = testDomainGetSchedulerParametersFlags, /* 0.9.2 */
    .domainSetSchedulerParameters = testDomainSetSchedulerParameters, /* 0.3.2 */
    .domainSetSchedulerParametersFlags = testDomainSetSchedulerParametersFlags, /* 0.9.2 */
    .domainBlockStats = testDomainBlockStats, /* 0.7.0 */
    .domainInterfaceStats = testDomainInterfaceStats, /* 0.7.0 */
    .nodeGetCellsFreeMemory = testNodeGetCellsFreeMemory, /* 0.4.2 */
    .connectDomainEventRegister = testConnectDomainEventRegister, /* 0.6.0 */
    .connectDomainEventDeregister = testConnectDomainEventDeregister, /* 0.6.0 */
    .connectIsEncrypted = testConnectIsEncrypted, /* 0.7.3 */
    .connectIsSecure = testConnectIsSecure, /* 0.7.3 */
    .domainIsActive = testDomainIsActive, /* 0.7.3 */
    .domainIsPersistent = testDomainIsPersistent, /* 0.7.3 */
    .domainIsUpdated = testDomainIsUpdated, /* 0.8.6 */
    .connectDomainEventRegisterAny = testConnectDomainEventRegisterAny, /* 0.8.0 */
    .connectDomainEventDeregisterAny = testConnectDomainEventDeregisterAny, /* 0.8.0 */
    .connectIsAlive = testConnectIsAlive, /* 0.9.8 */
    .nodeGetCPUMap = testNodeGetCPUMap, /* 1.0.0 */
    .domainScreenshot = testDomainScreenshot, /* 1.0.5 */
    .domainGetMetadata = testDomainGetMetadata, /* 1.1.3 */
    .domainSetMetadata = testDomainSetMetadata, /* 1.1.3 */
    .connectGetCPUModelNames = testConnectGetCPUModelNames, /* 1.1.3 */
    .domainManagedSave = testDomainManagedSave, /* 1.1.4 */
    .domainHasManagedSaveImage = testDomainHasManagedSaveImage, /* 1.1.4 */
    .domainManagedSaveRemove = testDomainManagedSaveRemove, /* 1.1.4 */

    .domainSnapshotNum = testDomainSnapshotNum, /* 1.1.4 */
    .domainSnapshotListNames = testDomainSnapshotListNames, /* 1.1.4 */
    .domainListAllSnapshots = testDomainListAllSnapshots, /* 1.1.4 */
    .domainSnapshotGetXMLDesc = testDomainSnapshotGetXMLDesc, /* 1.1.4 */
    .domainSnapshotNumChildren = testDomainSnapshotNumChildren, /* 1.1.4 */
    .domainSnapshotListChildrenNames = testDomainSnapshotListChildrenNames, /* 1.1.4 */
    .domainSnapshotListAllChildren = testDomainSnapshotListAllChildren, /* 1.1.4 */
    .domainSnapshotLookupByName = testDomainSnapshotLookupByName, /* 1.1.4 */
    .domainHasCurrentSnapshot = testDomainHasCurrentSnapshot, /* 1.1.4 */
    .domainSnapshotGetParent = testDomainSnapshotGetParent, /* 1.1.4 */
    .domainSnapshotCurrent = testDomainSnapshotCurrent, /* 1.1.4 */
    .domainSnapshotIsCurrent = testDomainSnapshotIsCurrent, /* 1.1.4 */
    .domainSnapshotHasMetadata = testDomainSnapshotHasMetadata, /* 1.1.4 */
    .domainSnapshotCreateXML = testDomainSnapshotCreateXML, /* 1.1.4 */
    .domainRevertToSnapshot = testDomainRevertToSnapshot, /* 1.1.4 */
    .domainSnapshotDelete = testDomainSnapshotDelete, /* 1.1.4 */

    .connectBaselineCPU = testConnectBaselineCPU, /* 1.2.0 */
};

static virNetworkDriver testNetworkDriver = {
    .connectNumOfNetworks = testConnectNumOfNetworks, /* 0.3.2 */
    .connectListNetworks = testConnectListNetworks, /* 0.3.2 */
    .connectNumOfDefinedNetworks = testConnectNumOfDefinedNetworks, /* 0.3.2 */
    .connectListDefinedNetworks = testConnectListDefinedNetworks, /* 0.3.2 */
    .connectListAllNetworks = testConnectListAllNetworks, /* 0.10.2 */
    .connectNetworkEventRegisterAny = testConnectNetworkEventRegisterAny, /* 1.2.1 */
    .connectNetworkEventDeregisterAny = testConnectNetworkEventDeregisterAny, /* 1.2.1 */
    .networkLookupByUUID = testNetworkLookupByUUID, /* 0.3.2 */
    .networkLookupByName = testNetworkLookupByName, /* 0.3.2 */
    .networkCreateXML = testNetworkCreateXML, /* 0.3.2 */
    .networkDefineXML = testNetworkDefineXML, /* 0.3.2 */
    .networkUndefine = testNetworkUndefine, /* 0.3.2 */
    .networkUpdate = testNetworkUpdate, /* 0.10.2 */
    .networkCreate = testNetworkCreate, /* 0.3.2 */
    .networkDestroy = testNetworkDestroy, /* 0.3.2 */
    .networkGetXMLDesc = testNetworkGetXMLDesc, /* 0.3.2 */
    .networkGetBridgeName = testNetworkGetBridgeName, /* 0.3.2 */
    .networkGetAutostart = testNetworkGetAutostart, /* 0.3.2 */
    .networkSetAutostart = testNetworkSetAutostart, /* 0.3.2 */
    .networkIsActive = testNetworkIsActive, /* 0.7.3 */
    .networkIsPersistent = testNetworkIsPersistent, /* 0.7.3 */
};

static virInterfaceDriver testInterfaceDriver = {
    .connectNumOfInterfaces = testConnectNumOfInterfaces, /* 0.7.0 */
    .connectListInterfaces = testConnectListInterfaces, /* 0.7.0 */
    .connectNumOfDefinedInterfaces = testConnectNumOfDefinedInterfaces, /* 0.7.0 */
    .connectListDefinedInterfaces = testConnectListDefinedInterfaces, /* 0.7.0 */
    .interfaceLookupByName = testInterfaceLookupByName, /* 0.7.0 */
    .interfaceLookupByMACString = testInterfaceLookupByMACString, /* 0.7.0 */
    .interfaceGetXMLDesc = testInterfaceGetXMLDesc, /* 0.7.0 */
    .interfaceDefineXML = testInterfaceDefineXML, /* 0.7.0 */
    .interfaceUndefine = testInterfaceUndefine, /* 0.7.0 */
    .interfaceCreate = testInterfaceCreate, /* 0.7.0 */
    .interfaceDestroy = testInterfaceDestroy, /* 0.7.0 */
    .interfaceIsActive = testInterfaceIsActive, /* 0.7.3 */
    .interfaceChangeBegin = testInterfaceChangeBegin,   /* 0.9.2 */
    .interfaceChangeCommit = testInterfaceChangeCommit,  /* 0.9.2 */
    .interfaceChangeRollback = testInterfaceChangeRollback, /* 0.9.2 */
};


static virStorageDriver testStorageDriver = {
    .connectNumOfStoragePools = testConnectNumOfStoragePools, /* 0.5.0 */
    .connectListStoragePools = testConnectListStoragePools, /* 0.5.0 */
    .connectNumOfDefinedStoragePools = testConnectNumOfDefinedStoragePools, /* 0.5.0 */
    .connectListDefinedStoragePools = testConnectListDefinedStoragePools, /* 0.5.0 */
    .connectListAllStoragePools = testConnectListAllStoragePools, /* 0.10.2 */
    .connectFindStoragePoolSources = testConnectFindStoragePoolSources, /* 0.5.0 */
    .connectStoragePoolEventRegisterAny = testConnectStoragePoolEventRegisterAny, /* 2.0.0 */
    .connectStoragePoolEventDeregisterAny = testConnectStoragePoolEventDeregisterAny, /* 2.0.0 */
    .storagePoolLookupByName = testStoragePoolLookupByName, /* 0.5.0 */
    .storagePoolLookupByUUID = testStoragePoolLookupByUUID, /* 0.5.0 */
    .storagePoolLookupByVolume = testStoragePoolLookupByVolume, /* 0.5.0 */
    .storagePoolCreateXML = testStoragePoolCreateXML, /* 0.5.0 */
    .storagePoolDefineXML = testStoragePoolDefineXML, /* 0.5.0 */
    .storagePoolBuild = testStoragePoolBuild, /* 0.5.0 */
    .storagePoolUndefine = testStoragePoolUndefine, /* 0.5.0 */
    .storagePoolCreate = testStoragePoolCreate, /* 0.5.0 */
    .storagePoolDestroy = testStoragePoolDestroy, /* 0.5.0 */
    .storagePoolDelete = testStoragePoolDelete, /* 0.5.0 */
    .storagePoolRefresh = testStoragePoolRefresh, /* 0.5.0 */
    .storagePoolGetInfo = testStoragePoolGetInfo, /* 0.5.0 */
    .storagePoolGetXMLDesc = testStoragePoolGetXMLDesc, /* 0.5.0 */
    .storagePoolGetAutostart = testStoragePoolGetAutostart, /* 0.5.0 */
    .storagePoolSetAutostart = testStoragePoolSetAutostart, /* 0.5.0 */
    .storagePoolNumOfVolumes = testStoragePoolNumOfVolumes, /* 0.5.0 */
    .storagePoolListVolumes = testStoragePoolListVolumes, /* 0.5.0 */
    .storagePoolListAllVolumes = testStoragePoolListAllVolumes, /* 0.10.2 */

    .storageVolLookupByName = testStorageVolLookupByName, /* 0.5.0 */
    .storageVolLookupByKey = testStorageVolLookupByKey, /* 0.5.0 */
    .storageVolLookupByPath = testStorageVolLookupByPath, /* 0.5.0 */
    .storageVolCreateXML = testStorageVolCreateXML, /* 0.5.0 */
    .storageVolCreateXMLFrom = testStorageVolCreateXMLFrom, /* 0.6.4 */
    .storageVolDelete = testStorageVolDelete, /* 0.5.0 */
    .storageVolGetInfo = testStorageVolGetInfo, /* 0.5.0 */
    .storageVolGetXMLDesc = testStorageVolGetXMLDesc, /* 0.5.0 */
    .storageVolGetPath = testStorageVolGetPath, /* 0.5.0 */
    .storagePoolIsActive = testStoragePoolIsActive, /* 0.7.3 */
    .storagePoolIsPersistent = testStoragePoolIsPersistent, /* 0.7.3 */
};

static virNodeDeviceDriver testNodeDeviceDriver = {
    .connectNodeDeviceEventRegisterAny = testConnectNodeDeviceEventRegisterAny, /* 2.2.0 */
    .connectNodeDeviceEventDeregisterAny = testConnectNodeDeviceEventDeregisterAny, /* 2.2.0 */
    .nodeNumOfDevices = testNodeNumOfDevices, /* 0.7.2 */
    .nodeListDevices = testNodeListDevices, /* 0.7.2 */
    .nodeDeviceLookupByName = testNodeDeviceLookupByName, /* 0.7.2 */
    .nodeDeviceGetXMLDesc = testNodeDeviceGetXMLDesc, /* 0.7.2 */
    .nodeDeviceGetParent = testNodeDeviceGetParent, /* 0.7.2 */
    .nodeDeviceNumOfCaps = testNodeDeviceNumOfCaps, /* 0.7.2 */
    .nodeDeviceListCaps = testNodeDeviceListCaps, /* 0.7.2 */
    .nodeDeviceCreateXML = testNodeDeviceCreateXML, /* 0.7.3 */
    .nodeDeviceDestroy = testNodeDeviceDestroy, /* 0.7.3 */
};

static virConnectDriver testConnectDriver = {
    .hypervisorDriver = &testHypervisorDriver,
    .interfaceDriver = &testInterfaceDriver,
    .networkDriver = &testNetworkDriver,
    .nodeDeviceDriver = &testNodeDeviceDriver,
    .nwfilterDriver = NULL,
    .secretDriver = NULL,
    .storageDriver = &testStorageDriver,
};

/**
 * testRegister:
 *
 * Registers the test driver
 */
int
testRegister(void)
{
    return virRegisterConnectDriver(&testConnectDriver,
                                    false);
}
