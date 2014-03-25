/*
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Cedric Bosdonnat <cbosdonnat@suse.com>
 */

#include <config.h>

#include "testutils.h"

#include "virerror.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NONE


static const char domainDef[] =
"<domain type='test'>"
"  <name>test-domain</name>"
"  <uuid>77a6fc12-07b5-9415-8abb-a803613f2a40</uuid>"
"  <memory>8388608</memory>"
"  <currentMemory>2097152</currentMemory>"
"  <vcpu>2</vcpu>"
"  <os>"
"    <type>hvm</type>"
"  </os>"
"</domain>";

static const char networkDef[] =
"<network>\n"
"  <name>test</name>\n"
"  <bridge name=\"virbr0\"/>\n"
"  <forward/>\n"
"  <ip address=\"192.168.122.1\" netmask=\"255.255.255.0\">\n"
"    <dhcp>\n"
"      <range start=\"192.168.122.2\" end=\"192.168.122.254\"/>\n"
"    </dhcp>\n"
"  </ip>\n"
"</network>\n";

typedef struct {
    int startEvents;
    int stopEvents;
    int defineEvents;
    int undefineEvents;
    int unexpectedEvents;
} lifecycleEventCounter;

static void
lifecycleEventCounter_reset(lifecycleEventCounter *counter)
{
    counter->startEvents = 0;
    counter->stopEvents = 0;
    counter->defineEvents = 0;
    counter->undefineEvents = 0;
    counter->unexpectedEvents = 0;
}

typedef struct {
    virConnectPtr conn;
    virNetworkPtr net;
} objecteventTest;


static int
domainLifecycleCb(virConnectPtr conn ATTRIBUTE_UNUSED,
                  virDomainPtr dom ATTRIBUTE_UNUSED,
                  int event,
                  int detail ATTRIBUTE_UNUSED,
                  void *opaque)
{
    lifecycleEventCounter *counter = opaque;

    switch (event) {
        case VIR_DOMAIN_EVENT_STARTED:
            counter->startEvents++;
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            counter->stopEvents++;
            break;
        case VIR_DOMAIN_EVENT_DEFINED:
            counter->defineEvents++;
            break;
        case VIR_DOMAIN_EVENT_UNDEFINED:
            counter->undefineEvents++;
            break;
        default:
            /* Ignore other events */
            break;
    }
    return 0;
}

static void
networkLifecycleCb(virConnectPtr conn ATTRIBUTE_UNUSED,
                   virNetworkPtr net ATTRIBUTE_UNUSED,
                   int event,
                   int detail ATTRIBUTE_UNUSED,
                   void* opaque)
{
    lifecycleEventCounter *counter = opaque;

    if (event == VIR_NETWORK_EVENT_STARTED)
        counter->startEvents++;
    else if (event == VIR_NETWORK_EVENT_STOPPED)
        counter->stopEvents++;
    else if (event == VIR_NETWORK_EVENT_DEFINED)
        counter->defineEvents++;
    else if (event == VIR_NETWORK_EVENT_UNDEFINED)
        counter->undefineEvents++;
}


static int
testDomainCreateXMLOld(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    virDomainPtr dom = NULL;
    int ret = -1;
    bool registered = false;

    lifecycleEventCounter_reset(&counter);

    if (virConnectDomainEventRegister(test->conn,
                                      domainLifecycleCb,
                                      &counter, NULL) != 0)
        goto cleanup;
    registered = true;
    dom = virDomainCreateXML(test->conn, domainDef, 0);

    if (dom == NULL || virEventRunDefaultImpl() < 0)
        goto cleanup;

    if (counter.startEvents != 1 || counter.unexpectedEvents > 0)
        goto cleanup;

    if (virConnectDomainEventDeregister(test->conn, domainLifecycleCb) != 0)
        goto cleanup;
    registered = false;
    ret = 0;

 cleanup:
    if (registered)
        virConnectDomainEventDeregister(test->conn, domainLifecycleCb);
    if (dom) {
        virDomainDestroy(dom);
        virDomainFree(dom);
    }

    return ret;
}

static int
testDomainCreateXMLNew(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    int eventId = VIR_DOMAIN_EVENT_ID_LIFECYCLE;
    virDomainPtr dom = NULL;
    int id;
    int ret = -1;

    lifecycleEventCounter_reset(&counter);

    id = virConnectDomainEventRegisterAny(test->conn, NULL, eventId,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                           &counter, NULL);
    if (id < 0)
        goto cleanup;
    dom = virDomainCreateXML(test->conn, domainDef, 0);

    if (dom == NULL || virEventRunDefaultImpl() < 0)
        goto cleanup;

    if (counter.startEvents != 1 || counter.unexpectedEvents > 0)
        goto cleanup;

    if (virConnectDomainEventDeregisterAny(test->conn, id) != 0)
        goto cleanup;
    id = -1;
    ret = 0;

 cleanup:
    if (id >= 0)
        virConnectDomainEventDeregisterAny(test->conn, id);
    if (dom) {
        virDomainDestroy(dom);
        virDomainFree(dom);
    }

    return ret;
}

static int
testDomainCreateXMLMixed(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    virDomainPtr dom;
    int ret = -1;
    int id1 = -1;
    int id2 = -1;
    bool registered = false;

    lifecycleEventCounter_reset(&counter);

    /* Fun with mixing old and new API, also with global and
     * per-domain.  Handler should be fired three times, once for each
     * registration.  */
    dom = virDomainDefineXML(test->conn, domainDef);
    if (dom == NULL)
        goto cleanup;

    id1 = virConnectDomainEventRegisterAny(test->conn, dom,
                                           VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                                           &counter, NULL);
    if (id1 < 0)
        goto cleanup;
    if (virConnectDomainEventRegister(test->conn,
                                      domainLifecycleCb,
                                      &counter, NULL) != 0)
        goto cleanup;
    registered = true;
    id2 = virConnectDomainEventRegisterAny(test->conn, NULL,
                                           VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                                           &counter, NULL);
    if (id2 < 0)
        goto cleanup;

    virDomainUndefine(dom);
    virDomainDestroy(dom);
    virDomainFree(dom);

    dom = virDomainCreateXML(test->conn, domainDef, 0);
    if (dom == NULL || virEventRunDefaultImpl() < 0)
        goto cleanup;

    if (counter.startEvents != 3 || counter.unexpectedEvents > 0)
        goto cleanup;

    if (virConnectDomainEventDeregister(test->conn, domainLifecycleCb) != 0)
        goto cleanup;
    registered = false;
    if (virConnectDomainEventDeregisterAny(test->conn, id1) != 0)
        goto cleanup;
    id1 = -1;
    if (virConnectDomainEventDeregisterAny(test->conn, id2) != 0)
        goto cleanup;
    id2 = -1;
    ret = 0;

 cleanup:
    if (id1 >= 0)
        virConnectDomainEventDeregisterAny(test->conn, id1);
    if (id2 >= 0)
        virConnectDomainEventDeregisterAny(test->conn, id2);
    if (registered)
        virConnectDomainEventDeregister(test->conn, domainLifecycleCb);
    if (dom != NULL) {
        virDomainUndefine(dom);
        virDomainDestroy(dom);
        virDomainFree(dom);
    }

    return ret;
}


static int
testDomainDefine(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    int eventId = VIR_DOMAIN_EVENT_ID_LIFECYCLE;
    virDomainPtr dom = NULL;
    int id;
    int ret = 0;

    lifecycleEventCounter_reset(&counter);

    id = virConnectDomainEventRegisterAny(test->conn, NULL, eventId,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                           &counter, NULL);

    /* Make sure the define event is triggered */
    dom = virDomainDefineXML(test->conn, domainDef);

    if (dom == NULL || virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.defineEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }

    /* Make sure the undefine event is triggered */
    virDomainUndefine(dom);

    if (virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.undefineEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }


 cleanup:
    virConnectDomainEventDeregisterAny(test->conn, id);
    if (dom != NULL)
        virDomainFree(dom);

    return ret;
}

static int
testDomainStartStopEvent(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    int eventId = VIR_DOMAIN_EVENT_ID_LIFECYCLE;
    int id;
    int ret = -1;
    virDomainPtr dom;
    virConnectPtr conn2 = NULL;
    virDomainPtr dom2 = NULL;

    lifecycleEventCounter_reset(&counter);

    dom = virDomainLookupByName(test->conn, "test");
    if (dom == NULL)
        return -1;

    id = virConnectDomainEventRegisterAny(test->conn, dom, eventId,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                           &counter, NULL);

    /* Test domain is started */
    virDomainDestroy(dom);
    virDomainCreate(dom);

    if (virEventRunDefaultImpl() < 0)
        goto cleanup;

    if (counter.startEvents != 1 || counter.stopEvents != 1 ||
            counter.unexpectedEvents > 0)
        goto cleanup;

    /* Repeat the test, but this time, trigger the events via an
     * alternate connection.  */
    if (!(conn2 = virConnectOpen("test:///default")))
        goto cleanup;
    if (!(dom2 = virDomainLookupByName(conn2, "test")))
        goto cleanup;

    if (virDomainDestroy(dom2) < 0)
        goto cleanup;
    if (virDomainCreate(dom2) < 0)
        goto cleanup;

    if (virEventRunDefaultImpl() < 0)
        goto cleanup;

    if (counter.startEvents != 2 || counter.stopEvents != 2 ||
            counter.unexpectedEvents > 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virConnectDomainEventDeregisterAny(test->conn, id);
    virDomainFree(dom);
    if (dom2)
        virDomainFree(dom2);
    if (conn2)
        virConnectClose(conn2);

    return ret;
}

static int
testNetworkCreateXML(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    virNetworkPtr net;
    int id;
    int ret = 0;

    lifecycleEventCounter_reset(&counter);

    id = virConnectNetworkEventRegisterAny(test->conn, NULL,
                           VIR_NETWORK_EVENT_ID_LIFECYCLE,
                           VIR_NETWORK_EVENT_CALLBACK(&networkLifecycleCb),
                           &counter, NULL);
    net = virNetworkCreateXML(test->conn, networkDef);

    if (virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.startEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    virConnectNetworkEventDeregisterAny(test->conn, id);
    virNetworkDestroy(net);

    virNetworkFree(net);

    return ret;
}

static int
testNetworkDefine(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    virNetworkPtr net;
    int id;
    int ret = 0;

    lifecycleEventCounter_reset(&counter);

    id = virConnectNetworkEventRegisterAny(test->conn, NULL,
                           VIR_NETWORK_EVENT_ID_LIFECYCLE,
                           VIR_NETWORK_EVENT_CALLBACK(&networkLifecycleCb),
                           &counter, NULL);

    /* Make sure the define event is triggered */
    net = virNetworkDefineXML(test->conn, networkDef);

    if (virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.defineEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }

    /* Make sure the undefine event is triggered */
    virNetworkUndefine(net);

    if (virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.undefineEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }


 cleanup:
    virConnectNetworkEventDeregisterAny(test->conn, id);
    virNetworkFree(net);

    return ret;
}

static int
testNetworkStartStopEvent(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    int id;
    int ret = 0;

    lifecycleEventCounter_reset(&counter);

    id = virConnectNetworkEventRegisterAny(test->conn, test->net,
                           VIR_NETWORK_EVENT_ID_LIFECYCLE,
                           VIR_NETWORK_EVENT_CALLBACK(&networkLifecycleCb),
                           &counter, NULL);
    virNetworkCreate(test->net);
    virNetworkDestroy(test->net);

    if (virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.startEvents != 1 || counter.stopEvents != 1 ||
            counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }
 cleanup:
    virConnectNetworkEventDeregisterAny(test->conn, id);

    return ret;
}

static void
timeout(int id ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    fputs("test taking too long; giving up", stderr);
    _exit(EXIT_FAILURE);
}

static int
mymain(void)
{
    objecteventTest test;
    int ret = EXIT_SUCCESS;
    int timer;

    virEventRegisterDefaultImpl();

    /* Set up a timer to abort this test if it takes 10 seconds.  */
    if ((timer = virEventAddTimeout(10 * 1000, timeout, NULL, NULL)) < 0)
        return EXIT_FAILURE;

    if (!(test.conn = virConnectOpen("test:///default")))
        return EXIT_FAILURE;

    virtTestQuiesceLibvirtErrors(false);

    /* Domain event tests */
    if (virtTestRun("Domain createXML start event (old API)",
                    testDomainCreateXMLOld, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain createXML start event (new API)",
                    testDomainCreateXMLNew, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain createXML start event (both API)",
                    testDomainCreateXMLMixed, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain (un)define events", testDomainDefine, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain start stop events", testDomainStartStopEvent, &test) < 0)
        ret = EXIT_FAILURE;

    /* Network event tests */
    /* Tests requiring the test network not to be set up*/
    if (virtTestRun("Network createXML start event ", testNetworkCreateXML, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Network (un)define events", testNetworkDefine, &test) < 0)
        ret = EXIT_FAILURE;

    /* Define a test network */
    test.net = virNetworkDefineXML(test.conn, networkDef);
    if (virtTestRun("Network start stop events ", testNetworkStartStopEvent, &test) < 0)
        ret = EXIT_FAILURE;

    /* Cleanup */
    virNetworkUndefine(test.net);
    virNetworkFree(test.net);
    virConnectClose(test.conn);
    virEventRemoveTimeout(timer);

    return ret;
}

VIRT_TEST_MAIN(mymain)
