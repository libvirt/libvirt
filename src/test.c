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
#include <libxml/uri.h>

#include "internal.h"
#include "test.h"

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
  NULL, /* domainCreateLinux */
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
  NULL, /* domainGetMaxMemory */
  testSetMaxMemory, /* domainSetMaxMemory */
  NULL, /* domainSetMemory */
  testGetDomainInfo, /* domainGetInfo */
  NULL, /* domainSave */
  NULL, /* domainRestore */
  NULL, /* domainSetVcpus */
  NULL, /* domainPinVcpu */
  NULL /* domainGetVcpus */
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
  virDomainRestart onRestart;
  int numDevices;
  testDev devices[MAX_DEVICES];
} testDom;

#define MAX_DOMAINS 20

typedef struct _testCon {
  int active;
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

static virNodeInfo nodeInfo = {
  "i86",
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


/**
 * testRegister:
 *
 * Registers the test driver
 */
void testRegister(void)
{
  virRegisterDriver(&testDriver);
}


int testOpen(virConnectPtr conn,
             const char *name,
             int flags)
{
  xmlURIPtr uri;
  int i, j;

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
      !uri->path ||
      strcmp(uri->path, "/default")) {
    xmlFreeURI(uri);
    return -1;
  }


  xmlFreeURI(uri);

  if (node == NULL) {
    node = calloc(1, sizeof(testNode));
    if (!node) {
      testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot allocate memory");
      return -1;
    }
  }

  for (i = 0 ; i < MAX_CONNECTIONS ; i++) {
    if (!node->connections[i].active) {
      struct timeval tv;

      if (gettimeofday(&tv, NULL) < 0) {
	testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot get timeofday");
	return -1;
      }

      conn->handle = i;
      node->connections[i].active = 1;

      node->connections[i].numDomains = 1;
      node->connections[i].domains[0].active = 1;
      strcpy(node->connections[i].domains[0].name, "Domain-0");
      for (j = 0 ; j < 16 ; j++) {
	node->connections[i].domains[0].uuid[j] = (j * 75)%255;
      }
      node->connections[i].domains[0].info.maxMem = 8192 * 1024;
      node->connections[i].domains[0].info.memory = 2048 * 1024;
      node->connections[i].domains[0].info.state = VIR_DOMAIN_RUNNING;
      node->connections[i].domains[0].info.nrVirtCpu = 2;
      node->connections[i].domains[0].info.cpuTime = ((tv.tv_sec * 1000ll * 1000ll  * 1000ll) + (tv.tv_usec * 1000ll));
      return 0;
    }
  }


  testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "too make connections");
  return -1;
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
  *hvVer = 1;
  return 0;
}

int testNodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED,
                    virNodeInfoPtr info)
{
  memcpy(info, &nodeInfo, sizeof(nodeInfo));
  return 0;
}

int testNumOfDomains(virConnectPtr conn)
{
  testCon *con = &node->connections[conn->handle];
  return con->numDomains;
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
    testError(conn, NULL, VIR_ERR_NO_MEMORY, "Allocating domain");
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
      testError(conn, NULL, VIR_ERR_NO_MEMORY, "Allocating domain");
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
      testError(conn, NULL, VIR_ERR_NO_MEMORY, "Allocating domain");
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
  testCon *con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].active = 0;
  return 0;
}

int testResumeDomain (virDomainPtr domain)
{
  testCon *con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].info.state = VIR_DOMAIN_RUNNING;
  return 0;
}

int testPauseDomain (virDomainPtr domain)
{
  testCon *con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].info.state = VIR_DOMAIN_PAUSED;
  return 0;
}

/* We don't do an immediate shutdown. We basically pretend that
   out shutdown sequence takes 'n' seconds to complete. SO, here
   we just set state to shutdown, and subsquent calls to getDomainInfo
   will check to see if shutdown ought to be marked complete. */
int testShutdownDomain (virDomainPtr domain)
{
  testCon *con = &node->connections[domain->conn->handle];
  struct timeval tv;
  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot get timeofday");
    return -1;
  }

  con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTDOWN;
  con->domains[domain->handle].onRestart = VIR_DOMAIN_DESTROY;
  con->domains[domain->handle].shutdownStartedAt = tv.tv_sec;
  return 0;
}

/* Similar behaviour as shutdown */
int testRebootDomain (virDomainPtr domain, virDomainRestart action)
{
  testCon *con = &node->connections[domain->conn->handle];
  struct timeval tv;
  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot get timeofday");
    return -1;
  }

  if (!action)
    action = VIR_DOMAIN_RESTART;

  con->domains[domain->handle].info.state = VIR_DOMAIN_SHUTDOWN;
  con->domains[domain->handle].onRestart = action;
  con->domains[domain->handle].shutdownStartedAt = tv.tv_sec;
  return 0;
}

int testGetDomainInfo (virDomainPtr domain,
                       virDomainInfoPtr info)
{
  testCon *con = &node->connections[domain->conn->handle];
  struct timeval tv;
  if (gettimeofday(&tv, NULL) < 0) {
    testError(NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot get timeofday");
    return -1;
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
  return 0;
}

int testSetMaxMemory (virDomainPtr domain,
                      unsigned long memory)
{
  testCon *con = &node->connections[domain->conn->handle];
  con->domains[domain->handle].info.maxMem = memory;
  return 0;
}
