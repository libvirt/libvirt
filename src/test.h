/*
 * test.h: A "mock" hypervisor for use by application unit tests
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Berrange <berrange@redhat.com>
 */

#ifndef __VIR_TEST_SIMPLE_INTERNAL_H__
#define __VIR_TEST_SIMPLE_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <virterror.h>

  void testRegister(void);
  int testOpen(virConnectPtr conn,
		     const char *name,
		     int flags);
  int testClose  (virConnectPtr conn);
  int testGetVersion(virConnectPtr conn,
			   unsigned long *hvVer);
  int testNodeGetInfo(virConnectPtr conn,
			    virNodeInfoPtr info);
  int testNumOfDomains(virConnectPtr conn);
  int testListDomains(virConnectPtr conn,
			    int *ids,
			    int maxids);
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
  int testRebootDomain (virDomainPtr domain, virDomainRestart action);
  int testGetDomainInfo(virDomainPtr domain,
			      virDomainInfoPtr info);
  int testGetDomainID(virDomainPtr domain);
  const char*testGetDomainName(virDomainPtr domain);
  int testSetMaxMemory(virDomainPtr domain,
			     unsigned long memory);

#ifdef __cplusplus
}
#endif
#endif                          /* __VIR_TEST_INTERNAL_H__ */
