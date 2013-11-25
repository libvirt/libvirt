/*
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

static int
testDomainCreateXML(const void *data)
{
    const objecteventTest *test = data;
    lifecycleEventCounter counter;
    int eventId = VIR_DOMAIN_EVENT_ID_LIFECYCLE;
    virDomainPtr dom;
    int id;
    int ret = 0;

    lifecycleEventCounter_reset(&counter);

    id = virConnectDomainEventRegisterAny(test->conn, NULL, eventId,
                           VIR_DOMAIN_EVENT_CALLBACK(&domainLifecycleCb),
                           &counter, NULL);
    dom = virDomainCreateXML(test->conn, domainDef, 0);

    if (dom == NULL || virEventRunDefaultImpl() < 0) {
        ret = -1;
        goto cleanup;
    }

    if (counter.startEvents != 1 || counter.unexpectedEvents > 0) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    virConnectDomainEventDeregisterAny(test->conn, id);
    if (dom != NULL) {
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
    virDomainPtr dom;
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
    int ret = 0;
    virDomainPtr dom;

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
    virConnectDomainEventDeregisterAny(test->conn, id);
    virDomainFree(dom);

    return ret;
}

static int
mymain(void)
{
    objecteventTest test;
    int ret = EXIT_SUCCESS;

    virEventRegisterDefaultImpl();

    if (!(test.conn = virConnectOpen("test:///default")))
        return EXIT_FAILURE;

    virtTestQuiesceLibvirtErrors(false);

    /* Domain event tests */
    if (virtTestRun("Domain createXML start event ", testDomainCreateXML, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain (un)define events", testDomainDefine, &test) < 0)
        ret = EXIT_FAILURE;
    if (virtTestRun("Domain start stop events", testDomainStartStopEvent, &test) < 0)
        ret = EXIT_FAILURE;

    virConnectClose(test.conn);

    return ret;
}

VIRT_TEST_MAIN(mymain)
