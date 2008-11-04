/*
 * xml.c: XML based interfaces for the libvir library
 *
 * Copyright (C) 2005, 2007, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>               /* for isnan() */

#include "virterror_internal.h"
#include "xml.h"
#include "buf.h"
#include "util.h"
#include "memory.h"

#define virXMLError(conn, code, fmt...)                                      \
        virReportErrorHelper(conn, VIR_FROM_XML, code, __FILE__,           \
                               __FUNCTION__, __LINE__, fmt)


/************************************************************************
 *									*
 * Wrappers around libxml2 XPath specific functions			*
 *									*
 ************************************************************************/

/**
 * virXPathString:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath string
 *
 * Returns a new string which must be deallocated by the caller or NULL
 *         if the evaluation failed.
 */
char *
virXPathString(virConnectPtr conn,
               const char *xpath,
               xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    char *ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathString()"));
        return (NULL);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        xmlXPathFreeObject(obj);
        return (NULL);
    }
    ret = strdup((char *) obj->stringval);
    xmlXPathFreeObject(obj);
    if (ret == NULL) {
        virXMLError(conn, VIR_ERR_NO_MEMORY, "%s", _("strdup failed"));
    }
    ctxt->node = relnode;
    return (ret);
}

/**
 * virXPathNumber:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned double value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the evaluation failed.
 */
int
virXPathNumber(virConnectPtr conn,
               const char *xpath,
               xmlXPathContextPtr ctxt,
               double *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathNumber()"));
        return (-1);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval))) {
        xmlXPathFreeObject(obj);
        ctxt->node = relnode;
        return (-1);
    }

    *value = obj->floatval;
    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (0);
}

/**
 * virXPathLong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathLong(virConnectPtr conn,
             const char *xpath,
             xmlXPathContextPtr ctxt,
             long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathNumber()"));
        return (-1);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        char *conv = NULL;
        long val;

        val = strtol((const char *) obj->stringval, &conv, 10);
        if (conv == (const char *) obj->stringval) {
            ret = -2;
        } else {
            *value = val;
        }
    } else if ((obj != NULL) && (obj->type == XPATH_NUMBER) &&
               (!(isnan(obj->floatval)))) {
        *value = (long) obj->floatval;
        if (*value != obj->floatval) {
            ret = -2;
        }
    } else {
        ret = -1;
    }

    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (ret);
}

/**
 * virXPathULong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathULong(virConnectPtr conn,
              const char *xpath,
              xmlXPathContextPtr ctxt,
              unsigned long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathNumber()"));
        return (-1);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        char *conv = NULL;
        long val;

        val = strtoul((const char *) obj->stringval, &conv, 10);
        if (conv == (const char *) obj->stringval) {
            ret = -2;
        } else {
            *value = val;
        }
    } else if ((obj != NULL) && (obj->type == XPATH_NUMBER) &&
               (!(isnan(obj->floatval)))) {
        *value = (unsigned long) obj->floatval;
        if (*value != obj->floatval) {
            ret = -2;
        }
    } else {
        ret = -1;
    }

    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (ret);
}

char *
virXMLPropString(xmlNodePtr node,
                 const char *name)
{
    return (char *)xmlGetProp(node, BAD_CAST name);
}

/**
 * virXPathBoolean:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath boolean
 *
 * Returns 0 if false, 1 if true, or -1 if the evaluation failed.
 */
int
virXPathBoolean(virConnectPtr conn,
                const char *xpath,
                xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathBoolean()"));
        return (-1);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN) ||
        (obj->boolval < 0) || (obj->boolval > 1)) {
        xmlXPathFreeObject(obj);
        return (-1);
    }
    ret = obj->boolval;

    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (ret);
}

/**
 * virXPathNode:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 *
 * Convenience function to evaluate an XPath node set and returning
 * only one node, the first one in the set if any
 *
 * Returns a pointer to the node or NULL if the evaluation failed.
 */
xmlNodePtr
virXPathNode(virConnectPtr conn,
             const char *xpath,
             xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    xmlNodePtr ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathNode()"));
        return (NULL);
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
        (obj->nodesetval->nodeTab == NULL)) {
        xmlXPathFreeObject(obj);
        ctxt->node = relnode;
        return (NULL);
    }

    ret = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (ret);
}

/**
 * virXPathNodeSet:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @list: the returned list of nodes (or NULL if only count matters)
 *
 * Convenience function to evaluate an XPath node set
 *
 * Returns the number of nodes found in which case @list is set (and
 *         must be freed) or -1 if the evaluation failed.
 */
int
virXPathNodeSet(virConnectPtr conn,
                const char *xpath,
                xmlXPathContextPtr ctxt,
                xmlNodePtr **list)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                    "%s", _("Invalid parameter to virXPathNodeSet()"));
        return (-1);
    }

    if (list != NULL)
        *list = NULL;

    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr < 0)) {
        xmlXPathFreeObject(obj);
        ctxt->node = relnode;
        return (-1);
    }

    ret = obj->nodesetval->nodeNr;
    if (list != NULL && ret) {
        if (VIR_ALLOC_N(*list, ret) < 0) {
            virXMLError(conn, VIR_ERR_NO_MEMORY,
                        _("allocate string array size %lu"),
                        (unsigned long)ret * sizeof(**list));
            ret = -1;
        } else {
            memcpy(*list, obj->nodesetval->nodeTab,
                   ret * sizeof(xmlNodePtr));
        }
    }
    xmlXPathFreeObject(obj);
    ctxt->node = relnode;
    return (ret);
}

