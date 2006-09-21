/*
 * test.c: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Berrange <berrange@redhat.com>
 */

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

static virDriver testDriver = {
  VIR_DRV_TEST,
  "Test",
  LIBVIR_VERSION_NUMBER,
  NULL, /* init */
  testOpen, /* open */
  testClose, /* close */
  NULL, /* type */
  testGetVersion, /* version */
  testNodeGetInfo, /* nodeGetInfo */
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
  NULL, /* domainFree */
  NULL, /* domainGetName */
  NULL, /* domainGetID */
  NULL, /* domainGetUUID */
  NULL, /* domainGetOSType */
  testGetMaxMemory, /* domainGetMaxMemory */
  testSetMaxMemory, /* domainSetMaxMemory */
  testSetMemory, /* domainSetMemory */
  testGetDomainInfo, /* domainGetInfo */
  NULL, /* domainSave */
  NULL, /* domainRestore */
  testSetVcpus, /* domainSetVcpus */
  NULL, /* domainPinVcpu */
  NULL, /* domainGetVcpus */
  testDomainDumpXML, /* domainDumpXML */
  NULL, /* listDefinedDomains */
  NULL, /* numOfDefinedDomains */
  NULL, /* domainCreate */
  NULL, /* domainDefineXML */
  NULL, /* domainUndefine */
};

/* Amount of time it takes to shutdown */
#define SHUTDOWN_DURATION 15

typedef struct _testDev {
  char name[20];
  virDeviceMode mode;
} testDev;

#define MAX_DEVICES 10

typedef struct _testDom {
  int active;
  char name[20];
  unsigned char uuid[16];
  virDomainKernel kernel;
  virDomainInfo info;
  time_t shutdownStartedAt;
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

static const virNodeInfo defaultNodeInfo = {
  "i686",
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
  __virRaiseError(con, dom, VIR_FROM_XEN, error, VIR_ERR_ERROR,
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
    return 0;
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
  return NULL;
}

/**
 * testRegister:
 *
 * Registers the test driver
 */
void testRegister(void)
{
  virRegisterDriver(&testDriver);
}

static int testLoadDomain(virConnectPtr conn,
			  int domid,
			  xmlDocPtr xml) {
  xmlNodePtr root = NULL;
  xmlXPathContextPtr ctxt = NULL;
  xmlXPathObjectPtr obj = NULL;
  char *name = NULL;
  unsigned char rawuuid[16];
  char *dst_uuid;
  testCon *con;
  struct timeval tv;
  unsigned long memory;
  int nrVirtCpu;
  char *conv;
  virDomainRestart onReboot = VIR_DOMAIN_RESTART;
  virDomainRestart onPoweroff = VIR_DOMAIN_DESTROY;
  virDomainRestart onCrash = VIR_DOMAIN_RENAME_RESTART;

  if (gettimeofday(&tv, NULL) < 0) {
    testError(conn, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
    return -1;
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

  obj = xmlXPathEval(BAD_CAST "string(/domain/name[1])", ctxt);
  if ((obj == NULL) || (obj->type != XPATH_STRING) ||
      (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
    testError(conn, NULL, VIR_ERR_INTERNAL_ERROR, _("domain name"));
    goto error;
  }
  name = strdup((const char *)obj->stringval);
  xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/uuid[1])", ctxt);
  if ((obj == NULL) || (obj->type != XPATH_STRING) ||
      (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
    testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
    goto error;
  }
  dst_uuid = (char *) &rawuuid[0];
  if (!(virParseUUID((char **)&dst_uuid, (const char *)obj->stringval))) {
    testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain uuid"));
    goto error;
  }
  xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/memory[1])", ctxt);
  if ((obj == NULL) || (obj->type != XPATH_STRING) ||
      (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
    testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain memory"));
    goto error;
  }
  memory = strtoll((const char*)obj->stringval, &conv, 10);
  if (conv == (const char*)obj->stringval) {
    testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain memory"));
    goto error;
  }
  xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/vcpu[1])", ctxt);
  if ((obj == NULL) || (obj->type != XPATH_STRING) ||
      (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
    nrVirtCpu = 1;
  } else {
    nrVirtCpu = strtoll((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain vcpus"));
      goto error;
    }
  }
  if (obj)
    xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/on_reboot[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    if (!(onReboot = testRestartStringToFlag((const char *)obj->stringval))) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain reboot behaviour"));
      goto error;
    }
  }
  if (obj)
    xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/on_poweroff[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    if (!(onReboot = testRestartStringToFlag((const char *)obj->stringval))) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain poweroff behaviour"));
      goto error;
    }
  }
  if (obj)
    xmlXPathFreeObject(obj);

  obj = xmlXPathEval(BAD_CAST "string(/domain/on_crash[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    if (!(onReboot = testRestartStringToFlag((const char *)obj->stringval))) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("domain crash behaviour"));
      goto error;
    }
  }
  if (obj)
    xmlXPathFreeObject(obj);

  con = &node->connections[conn->handle];

  con->domains[domid].active = 1;
  strncpy(con->domains[domid].name, name, sizeof(con->domains[domid].name));
  free(name);
  name = NULL;

  memmove(con->domains[domid].uuid, rawuuid, 16);
  con->domains[domid].info.maxMem = memory;
  con->domains[domid].info.memory = memory;
  con->domains[domid].info.state = VIR_DOMAIN_RUNNING;
  con->domains[domid].info.nrVirtCpu = nrVirtCpu;
  con->domains[domid].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));

  con->domains[domid].onReboot = onReboot;
  con->domains[domid].onPoweroff = onPoweroff;
  con->domains[domid].onCrash = onCrash;

  return 0;

 error:
  if (obj)
    xmlXPathFreeObject(obj);
  if (name)
    free(name);
  return -1;
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
    return -1;
  }

  ret = testLoadDomain(conn, domid, xml);

  xmlFreeDoc(xml);

  return ret;
}

static int testLoadDomainFromFile(virConnectPtr conn,
				  int domid,
				  const char *file) {
  int ret, fd;
  xmlDocPtr xml;

  if ((fd = open(file, O_RDONLY)) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("load domain definition file"));
    return -1;
  }

  if (!(xml = xmlReadFd(fd, file, NULL,
			XML_PARSE_NOENT | XML_PARSE_NONET |
			XML_PARSE_NOERROR | XML_PARSE_NOWARNING))) {
    testError(NULL, NULL, VIR_ERR_XML_ERROR, _("domain"));
    close(fd);
    return -1;
  }
  close(fd);

  ret = testLoadDomain(conn, domid, xml);

  xmlFreeDoc(xml);

  return ret;
}


static int testOpenDefault(virConnectPtr conn,
			   int connid) {
  int u;
  struct timeval tv;

  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
    return -1;
  }

  conn->handle = connid;
  node->connections[connid].active = 1;
  memmove(&node->connections[connid].nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

  node->connections[connid].numDomains = 1;
  node->connections[connid].domains[0].active = 1;
  strcpy(node->connections[connid].domains[0].name, "Domain-0");
  for (u = 0 ; u < 16 ; u++) {
    node->connections[connid].domains[0].uuid[u] = (u * 75)%255;
  }
  node->connections[connid].domains[0].info.maxMem = 8192 * 1024;
  node->connections[connid].domains[0].info.memory = 2048 * 1024;
  node->connections[connid].domains[0].info.state = VIR_DOMAIN_RUNNING;
  node->connections[connid].domains[0].info.nrVirtCpu = 2;
  node->connections[connid].domains[0].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
  return 0;
}


static char *testBuildFilename(const char *relativeTo,
			       const char *filename) {
  char *offset;
  int baseLen;
  if (!filename || filename[0] == '\0')
    return NULL;
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
  int fd, i;
  xmlDocPtr xml;
  xmlNodePtr root = NULL;
  xmlXPathContextPtr ctxt = NULL;
  xmlXPathObjectPtr obj = NULL;
  virNodeInfoPtr nodeInfo;

  if ((fd = open(file, O_RDONLY)) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("loading host definition file"));
    return -1;
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

  conn->handle = connid;
  node->connections[connid].active = 1;
  node->connections[connid].numDomains = 0;
  memmove(&node->connections[connid].nodeInfo, &defaultNodeInfo, sizeof(defaultNodeInfo));

  nodeInfo = &node->connections[connid].nodeInfo;
  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/nodes[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->nodes = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu numa nodes"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }

  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/sockets[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->sockets = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu sockets"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }

  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/cores[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->cores = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu cores"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }

  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/threads[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->threads = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu threads"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }
  nodeInfo->cpus = nodeInfo->cores * nodeInfo->threads * nodeInfo->sockets * nodeInfo->nodes;
  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/active[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    unsigned int active = strtol((const char*)obj->stringval, &conv, 10);    
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node active cpu"));
      goto error;
    }
    if (active < nodeInfo->cpus) {
      nodeInfo->cpus = active;
    }
    xmlXPathFreeObject(obj);
  }
  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/mhz[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->mhz = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node cpu mhz"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }
  obj = xmlXPathEval(BAD_CAST "string(/node/cpu/model[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    strncpy(nodeInfo->model, (const char *)obj->stringval, sizeof(nodeInfo->model)-1);
    nodeInfo->model[sizeof(nodeInfo->model)-1] = '\0';
    xmlXPathFreeObject(obj);
  }

  obj = xmlXPathEval(BAD_CAST "string(/node/memory[1])", ctxt);
  if ((obj != NULL) && (obj->type == XPATH_STRING) &&
      (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
    char *conv = NULL;
    nodeInfo->memory = strtol((const char*)obj->stringval, &conv, 10);
    if (conv == (const char*)obj->stringval) {
      testError(conn, NULL, VIR_ERR_XML_ERROR, _("node memory"));
      goto error;
    }
    xmlXPathFreeObject(obj);
  }

  obj = xmlXPathEval(BAD_CAST "/node/domain", ctxt);
  if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
      (obj->nodesetval == NULL)) {
    testError(NULL, NULL, VIR_ERR_XML_ERROR, _("node domain list"));
    goto error;
  }

  for (i = 0 ; i < obj->nodesetval->nodeNr ; i++) {
    xmlChar *domFile = xmlGetProp(obj->nodesetval->nodeTab[i], BAD_CAST "file");
    char *absFile = testBuildFilename(file, (const char *)domFile);
    free(domFile);
    if (!absFile) {
      testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("resolving domain filename"));
      goto error;
    }
    if (testLoadDomainFromFile(conn, i, absFile) != 0) {
      free(absFile);
      goto error;
    }
    free(absFile);
    node->connections[connid].numDomains++;
  }

  xmlXPathFreeObject(obj);
  xmlFreeDoc(xml);

  return 0;

 error:
  if (node->connections[connid].active) {
    for (i = 0 ; i <node->connections[connid].numDomains ; i++) {
      node->connections[connid].domains[i].active = 0;
    }
    node->connections[connid].numDomains = 0;
    node->connections[connid].active = 0;
  }
  if (obj)
    xmlXPathFreeObject(obj);
  if (xml)
    xmlFreeDoc(xml);
  if (fd != -1)
    close(fd);
  return -1;
}

static int getNextConnection(void) {
  int i;
  if (node == NULL) {
    node = calloc(1, sizeof(testNode));
    if (!node) {
      testError(NULL, NULL, VIR_ERR_NO_MEMORY, _("allocating node"));
      return -1;
    }
  }

  for (i = 0 ; i < MAX_CONNECTIONS ; i++) {
    if (!node->connections[i].active) {
      return i;
    }
  }
  return -1;
}

int testOpen(virConnectPtr conn,
             const char *name,
             int flags)
{
  xmlURIPtr uri;
  int ret, connid;

  if (!name) {
    return -1;
  }

  uri = xmlParseURI(name);
  if (uri == NULL) {
    if (!(flags & VIR_DRV_OPEN_QUIET))
      testError(conn, NULL, VIR_ERR_NO_SUPPORT, name);
    return(-1);
  }

  if (!uri->scheme ||
      strcmp(uri->scheme, "test") ||
      !uri->path) {
    xmlFreeURI(uri);
    return -1;
  }


  if ((connid = getNextConnection()) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many connections"));
    return -1;
  }

  if (!strcmp(uri->path, "/default")) {
    ret = testOpenDefault(conn,
			  connid);
  } else {
    ret = testOpenFromFile(conn,
			   connid,
			   uri->path);
  }

  xmlFreeURI(uri);

  return (ret);
}

int testClose(virConnectPtr conn)
{
  testCon *con = &node->connections[conn->handle];
  con->active = 0;
  conn->handle = -1;
  memset(con, 0, sizeof(testCon));
  return 0;
}

int testGetVersion(virConnectPtr conn ATTRIBUTE_UNUSED,
                   unsigned long *hvVer)
{
  *hvVer = 2;
  return 0;
}

int testNodeGetInfo(virConnectPtr conn,
                    virNodeInfoPtr info)
{
  testCon *con = &node->connections[conn->handle];
  memcpy(info, &con->nodeInfo, sizeof(virNodeInfo));
  return 0;
}

int testNumOfDomains(virConnectPtr conn)
{
  testCon *con = &node->connections[conn->handle];
  return con->numDomains;
}

virDomainPtr
testDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
		      unsigned int flags ATTRIBUTE_UNUSED)
{
  testCon *con;
  int i;
  virDomainPtr dom;

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
  
  con = &node->connections[conn->handle];

  for (i = 0 ; i < MAX_DOMAINS ; i++) {
    if (!con->domains[i].active) {
      if (testLoadDomainFromDoc(conn, i, xmlDesc) < 0)
	return NULL;
      dom = virGetDomain(conn, con->domains[i].name, con->domains[i].uuid);
      if (dom == NULL) {
	testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
	return NULL;
      }
      con->numDomains++;
      return dom;
    }
  }
  
  testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("too many domains"));
  return (NULL);
}


virDomainPtr testLookupDomainByID(virConnectPtr conn,
                                  int id)
{
  testCon *con = &node->connections[conn->handle];
  virDomainPtr dom;

  if (!con->domains[id].active) {
    return NULL;
  }

  dom = virGetDomain(conn, con->domains[id].name, con->domains[id].uuid);
  if (dom == NULL) {
    testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
    return(NULL);
  }
  dom->handle = id;
  return dom;
}

virDomainPtr testLookupDomainByUUID(virConnectPtr conn,
                                    const unsigned char *uuid)
{
  testCon *con = &node->connections[conn->handle];
  virDomainPtr dom = NULL;
  int i, id = -1;
  for (i = 0 ; i < MAX_DOMAINS ; i++) {
    if (con->domains[i].active &&
	memcmp(uuid, con->domains[i].uuid, 16) == 0) {
      id = i;
      break;
    }
  }
  if (id >= 0) {
    dom = virGetDomain(conn, con->domains[id].name, con->domains[id].uuid);
    if (dom == NULL) {
      testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
      return(NULL);
    }
    dom->handle = id;
  }
  return dom;
}

virDomainPtr testLookupDomainByName(virConnectPtr conn,
                                    const char *name)
{
  testCon *con = &node->connections[conn->handle];
  virDomainPtr dom = NULL;
  int i, id = -1;
  for (i = 0 ; i < MAX_DOMAINS ; i++) {
    if (con->domains[i].active &&
	strcmp(name, con->domains[i].name) == 0) {
      id = i;
      break;
    }
  }
  if (id >= 0) {
    dom = virGetDomain(conn, con->domains[id].name, con->domains[id].uuid);
    if (dom == NULL) {
      testError(conn, NULL, VIR_ERR_NO_MEMORY, _("allocating domain"));
      return(NULL);
    }
    dom->handle = id;
  }
  return dom;
}

int testListDomains (virConnectPtr conn,
                     int *ids,
                     int maxids)
{
  testCon *con = &node->connections[conn->handle];
  int n, i;

  for (i = 0, n = 0 ; i < MAX_DOMAINS && n < maxids ; i++) {
    if (con->domains[i].active) {
      ids[n++] = i;
    }
  }
  return n;
}

int testDestroyDomain (virDomainPtr domain)
{
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }
  
  con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].active = 0;
  return (0);
}

int testResumeDomain (virDomainPtr domain)
{
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].info.state = VIR_DOMAIN_RUNNING;
  return 0;
}

int testPauseDomain (virDomainPtr domain)
{
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].info.state = VIR_DOMAIN_PAUSED;
  return (0);
}

/* We don't do an immediate shutdown. We basically pretend that
   out shutdown sequence takes 'n' seconds to complete. SO, here
   we just set state to shutdown, and subsquent calls to getDomainInfo
   will check to see if shutdown ought to be marked complete. */
int testShutdownDomain (virDomainPtr domain)
{
  testCon *con;
  struct timeval tv;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return (-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];

  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
    return (-1);
  }

  con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTDOWN;
  con->domains[domain->handle].onRestart = VIR_DOMAIN_DESTROY;
  con->domains[domain->handle].shutdownStartedAt = tv.tv_sec;
  return (0);
}

/* Similar behaviour as shutdown */
int testRebootDomain (virDomainPtr domain, virDomainRestart action)
{
  testCon *con;
  struct timeval tv;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];

  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
    return (-1);
  }

  if (!action)
    action = VIR_DOMAIN_RESTART;

  con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTDOWN;
  con->domains[domain->handle].onRestart = action;
  con->domains[domain->handle].shutdownStartedAt = tv.tv_sec;
  return (0);
}

int testGetDomainInfo (virDomainPtr domain,
                       virDomainInfoPtr info)
{
  struct timeval tv;
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }

  con = &node->connections[domain->conn->handle];

  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, _("getting time of day"));
    return (-1);
  }

  /* Check to see if there is an in-progresss shutdown/reboot that
     needs to be marked completed now */
  if (con->domains[domain->handle].info.state == VIR_DOMAIN_SHUTDOWN &&
      (tv.tv_sec - con->domains[domain->handle].shutdownStartedAt) > SHUTDOWN_DURATION) {

      switch (con->domains[domain->handle].onRestart) {
      case VIR_DOMAIN_DESTROY:
	con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTOFF;
	break;

      case VIR_DOMAIN_RESTART:
	con->domains[domain->handle].info.state = VIR_DOMAIN_RUNNING;
	break;

      case VIR_DOMAIN_PRESERVE:
	con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTOFF;
	break;

      case VIR_DOMAIN_RENAME_RESTART:
	con->domains[domain->handle].info.state = VIR_DOMAIN_RUNNING;
	break;

      default:
	con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTOFF;
	break;
    }
  }

  if (con->domains[domain->handle].info.state == VIR_DOMAIN_SHUTOFF) {
    con->domains[domain->handle].info.cpuTime = 0;
    con->domains[domain->handle].info.memory = 0;
  } else {
    con->domains[domain->handle].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
  }
  memcpy(info, &con->domains[domain->handle].info, sizeof(virDomainInfo));
  return (0);
}

unsigned long testGetMaxMemory(virDomainPtr domain) {
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  
  con = &node->connections[domain->conn->handle];
  return con->domains[domain->handle].info.maxMem;
}

int testSetMaxMemory (virDomainPtr domain,
                      unsigned long memory)
{
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];
  /* XXX validate not over host memory wrt to other domains */
  con->domains[domain->handle].info.maxMem = memory;
  return (0);
}

int testSetMemory (virDomainPtr domain,
		   unsigned long memory)
{
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];

  if (memory > con->domains[domain->handle].info.maxMem) {
    testError(domain->conn, domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
    return (-1);
  }

  con->domains[domain->handle].info.memory = memory;
  return (0);
}

int testSetVcpus(virDomainPtr domain,
		 unsigned int nrCpus) {
  testCon *con;

  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(-1);
  }
  if (domain->conn->flags & VIR_CONNECT_RO) {
    testError(domain->conn, domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
    return (-1);
  }

  con = &node->connections[domain->conn->handle];

  /* We allow more cpus in guest than host */
  if (nrCpus > 32) {
    testError(domain->conn, domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
    return (-1);
  }

  con->domains[domain->handle].info.nrVirtCpu = nrCpus;
  return (0);
}

char * testDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED)
{
  virBufferPtr buf;
  char *xml;
  unsigned char *uuid;
  testCon *con;
  if ((domain == NULL) || (domain->conn == NULL) || (domain->name == NULL)) {
    testError((domain ? domain->conn : NULL), domain, VIR_ERR_INVALID_ARG,
	      __FUNCTION__);
    return(NULL);
  }
  
  con = &node->connections[domain->conn->handle];
  
  if (!(buf = virBufferNew(4000))) {
    return (NULL);
  }
  
  virBufferVSprintf(buf, "<domain type='test' id='%d'>\n", domain->handle);
  virBufferVSprintf(buf, "  <name>%s</name>\n", domain->name);
  uuid = domain->uuid;
  virBufferVSprintf(buf,
		    "  <uuid>%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x</uuid>\n",
		    uuid[0], uuid[1], uuid[2], uuid[3],
		    uuid[4], uuid[5], uuid[6], uuid[7],
		    uuid[8], uuid[9], uuid[10], uuid[11],
		    uuid[12], uuid[13], uuid[14], uuid[15]);
  
  virBufferVSprintf(buf, "  <memory>%d</memory>\n", con->domains[domain->handle].info.maxMem);
  virBufferVSprintf(buf, "  <vcpu>%d</vcpu>\n", con->domains[domain->handle].info.nrVirtCpu);
  virBufferVSprintf(buf, "  <on_reboot>%s</on_reboot>\n", testRestartFlagToString(con->domains[domain->handle].onReboot));
  virBufferVSprintf(buf, "  <on_poweroff>%s</on_poweroff>\n", testRestartFlagToString(con->domains[domain->handle].onPoweroff));
  virBufferVSprintf(buf, "  <on_crash>%s</on_crash>\n", testRestartFlagToString(con->domains[domain->handle].onCrash));
  
  virBufferAdd(buf, "</domain>\n", -1);
  
  xml = buf->content;
  free(buf);
  return xml;
}
