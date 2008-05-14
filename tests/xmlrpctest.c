/*
 * xmlrpctest.c: simple client for XML-RPC tests
 *
 * Copyright (C) 2005, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Karel Zak <kzak@redhat.com>
 *
 * $Id$
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "libvirt/libvirt.h"
#include "buf.h"
#include "xmlrpc.h"

#include "testutils.h"


#define NLOOPS  100     /* default number of loops per test */

static char *progname;


static int
testMethodPlusINT(const void *data)
{
    int retval = 0;
    xmlRpcContextPtr cxt = (xmlRpcContextPtr) data;

    if (xmlRpcCall(cxt, "plus", "i", "ii",
            (const char *) &retval, 10, 10) < 0)
        return -1;

    return retval==(10+10) ? 0 : -1;
}

static int
testMethodPlusDOUBLE(const void *data)
{
    double retval = 0;
    xmlRpcContextPtr cxt = (xmlRpcContextPtr) data;

    if (xmlRpcCall(cxt, "plus", "f", "ff",
            (const char *) &retval, 10.1234, 10.1234) < 0)
        return -1;

    return retval==(10.1234+10.1234) ? 0 : -1;
}

static void
marshalRequest(virBufferPtr buf, const char *fmt, ...)
{
    int argc;
    xmlRpcValuePtr *argv;
    va_list ap;

    va_start(ap, fmt);
    argv = xmlRpcArgvNew(fmt, ap, &argc);
    va_end(ap);

    xmlRpcMarshalRequest("test", buf, argc, argv);

    xmlRpcArgvFree(argc, argv);
}

static int
checkRequestValue(const char *xmlstr, const char *xpath, int type, void *expected)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlXPathObjectPtr obj = NULL;
    int ret = -1;

    xml = xmlReadDoc((const xmlChar *) xmlstr, "xmlrpctest.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (!xml)
        goto error;

    if (!(ctxt = xmlXPathNewContext(xml)))
        goto error;

    if (!(obj = xmlXPathEval(BAD_CAST xpath, ctxt)))
        goto error;

    switch(type) {
        case XML_RPC_INTEGER:
            if ((obj->type != XPATH_NUMBER) ||
                    ((int) obj->floatval != *((int *)expected)))
                goto error;
            break;
         case XML_RPC_DOUBLE:
            if ((obj->type != XPATH_NUMBER) ||
                    ((double) obj->floatval != *((double *)expected)))
                goto error;
            break;
         case XML_RPC_STRING:
            if ((obj->type != XPATH_STRING) ||
                    (STRNEQ((const char *)obj->stringval, (const char *)expected)))
                goto error;
            break;
        default:
            goto error;
    }
    ret = 0;

error:
    xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctxt);
    if (xml)
        xmlFreeDoc(xml);
    return ret;
}

static int
testMarshalRequestINT(const void *data)
{
    int num = INT_MAX;
    int ret = 0;
    int check = data ? *((int *)data) : 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    marshalRequest(&buf, "i", num);
    char *content;

    if (virBufferError(&buf))
        return -1;

    content = virBufferContentAndReset(&buf);

    if (check)
        ret = checkRequestValue(content,
                "number(/methodCall/params/param[1]/value/int)",
                XML_RPC_INTEGER, (void *) &num);

    free(content);
    return ret;
}

static int
testMarshalRequestSTRING(const void *data ATTRIBUTE_UNUSED)
{
    const char *str = "This library will be really sexy.";
    int ret = 0;
    int check = data ? *((int *)data) : 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *content;

    marshalRequest(&buf, "s", str);

    if (virBufferError(&buf))
        return -1;

    content = virBufferContentAndReset(&buf);
    if (check)
        ret = checkRequestValue(content,
                "string(/methodCall/params/param[1]/value/string)",
                XML_RPC_STRING, (void *) str);

    free(content);
    return ret;
}

static int
testMarshalRequestDOUBLE(const void *data)
{
    double num = 123456789.123;
    int ret = 0;
    int check = data ? *((int *)data) : 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *content;

    marshalRequest(&buf, "f", num);

    if (virBufferError(&buf))
        return -1;

    content = virBufferContentAndReset(&buf);
    if (check)
        ret = checkRequestValue(content,
                "number(/methodCall/params/param[1]/value/double)",
                XML_RPC_DOUBLE, (void *) &num);

    free(content);
    return ret;
}


int
main(int argc, char **argv)
{
        xmlRpcContextPtr cxt = NULL;
    int check = 1;
        int ret = 0;
    const char *url = "http://localhost:8000";

        progname = argv[0];

        if (argc > 2)
        {
                fprintf(stderr, "Usage: %s [url]\n", progname);
                exit(EXIT_FAILURE);
        }
    if (argc == 2)
        url = argv[1];

     /*
      * client-server tests
      */
        if (!(cxt = xmlRpcContextNew(url)))
        {
                fprintf(stderr, "%s: failed create new RPC context\n", progname);
                exit(EXIT_FAILURE);
        }

       if (virtTestRun("XML-RPC methodCall INT+INT",
                NLOOPS, testMethodPlusINT, (const void *) cxt) != 0)
        ret = -1;

    if (virtTestRun("XML-RPC methodCall DOUBLE+DOUBLE",
                NLOOPS, testMethodPlusDOUBLE, (const void *) cxt) != 0)
        ret = -1;

        xmlRpcContextFree(cxt);

    /*
     * regression / performance tests
     */
    if (virtTestRun("XML-RPC request marshalling: INT (check)",
                1, testMarshalRequestINT, (const void *) &check) != 0)
        ret = -1;
    if (virtTestRun("XML-RPC request marshalling: INT",
                NLOOPS, testMarshalRequestINT, NULL) != 0)
        ret = -1;

    if (virtTestRun("XML-RPC request marshalling: DOUBLE (check)",
                1, testMarshalRequestDOUBLE, (const void *) &check) != 0)
        ret = -1;
    if (virtTestRun("XML-RPC request marshalling: DOUBLE",
                NLOOPS, testMarshalRequestDOUBLE, NULL) != 0)
        ret = -1;

    if (virtTestRun("XML-RPC request marshalling: STRING (check)",
                1, testMarshalRequestSTRING, (void *) &check) != 0)
        ret = -1;
    if (virtTestRun("XML-RPC request marshalling: STRING",
                NLOOPS, testMarshalRequestSTRING, NULL) != 0)
        ret = -1;

    exit(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}


/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
