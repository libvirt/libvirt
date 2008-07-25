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
#include "c-ctype.h"
#include "internal.h"
#include "xml.h"
#include "buf.h"
#include "util.h"
#include "memory.h"
#include "xend_internal.h"      /* for is_sound_* functions */


/**
 * virXMLError:
 * @conn: a connection if any
 * @error: the error number
 * @info: information/format string
 * @value: extra integer parameter for the error string
 *
 * Report an error coming from the XML module.
 */
static void
virXMLError(virConnectPtr conn, virErrorNumber error, const char *info,
            int value)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(conn, NULL, NULL, VIR_FROM_XML, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}


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
virXPathString(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    char *ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathString()"), 0);
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
        virXMLError(NULL, VIR_ERR_NO_MEMORY, _("strdup failed"), 0);
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
virXPathNumber(const char *xpath, xmlXPathContextPtr ctxt, double *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNumber()"), 0);
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
virXPathLong(const char *xpath, xmlXPathContextPtr ctxt, long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNumber()"), 0);
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
virXPathULong(const char *xpath, xmlXPathContextPtr ctxt, unsigned long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNumber()"), 0);
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
virXPathBoolean(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathBoolean()"), 0);
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
virXPathNode(const char *xpath, xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    xmlNodePtr ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNode()"), 0);
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
virXPathNodeSet(const char *xpath, xmlXPathContextPtr ctxt,
                xmlNodePtr ** list)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virXMLError(NULL, VIR_ERR_INTERNAL_ERROR,
                    _("Invalid parameter to virXPathNodeSet()"), 0);
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
            virXMLError(NULL, VIR_ERR_NO_MEMORY,
                        _("allocate string array"),
                        ret * sizeof(**list));
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

#if WITH_XEN
#ifndef PROXY
/**
 * virConvertCpuSet:
 * @conn: connection
 * @str: pointer to a Xen or user provided CPU set string pointer
 * @maxcpu: number of CPUs on the node, if 0 4096 will be used
 *
 * Parse the given CPU set string and convert it to a range based
 * string.
 *
 * Returns a new string which must be freed by the caller or NULL in
 *         case of error.
 */
char *
virConvertCpuSet(virConnectPtr conn, const char *str, int maxcpu) {
    int ret;
    char *res, *cpuset;
    const char *cur = str;

    if (str == NULL)
        return(NULL);

    if (maxcpu <= 0)
        maxcpu = 4096;

    if (VIR_ALLOC_N(cpuset, maxcpu) < 0) {
        virXMLError(conn, VIR_ERR_NO_MEMORY, _("allocate buffer"), 0);
        return(NULL);
    }

    ret = virDomainCpuSetParse(conn, &cur, 0, cpuset, maxcpu);
    if (ret < 0) {
        VIR_FREE(cpuset);
        return(NULL);
    }
    res = virDomainCpuSetFormat(conn, cpuset, maxcpu);
    VIR_FREE(cpuset);
    return (res);
}


/**
 * virBuildSoundStringFromXML
 * @sound buffer to populate
 * @len size of preallocated buffer 'sound'
 * @ctxt xml context to pull sound info from
 *
 * Builds a string of the form m1,m2,m3 from the different sound models
 * in the xml. String must be free'd by caller.
 *
 * Returns string on success, NULL on error
 */
char * virBuildSoundStringFromXML(virConnectPtr conn,
                                  xmlXPathContextPtr ctxt) {

    int nb_nodes, size = 256;
    char *sound;
    xmlNodePtr *nodes = NULL;

    if (VIR_ALLOC_N(sound, size + 1) < 0) {
        virXMLError(conn, VIR_ERR_NO_MEMORY,
                    _("failed to allocate sound string"), 0);
        return NULL;
    }

    nb_nodes = virXPathNodeSet("/domain/devices/sound", ctxt, &nodes);
    if (nb_nodes > 0) {
        int i;
        for (i = 0; i < nb_nodes && size > 0; i++) {
            char *model = NULL;
            int collision = 0;

            model = (char *) xmlGetProp(nodes[i], (xmlChar *) "model");
            if (!model) {
                virXMLError(conn, VIR_ERR_XML_ERROR,
                            _("no model for sound device"), 0);
                goto error;
            }

            if (!is_sound_model_valid(model)) {
                virXMLError(conn, VIR_ERR_XML_ERROR,
                            _("unknown sound model type"), 0);
                VIR_FREE(model);
                goto error;
            }

            // Check for duplicates in currently built string
            if (*sound)
                collision = is_sound_model_conflict(model, sound);

            // If no collision, add to string
            if (!collision) {
                if (*sound && (size >= (strlen(model) + 1))) {
                    strncat(sound, ",", size--);
                } else if (*sound || size < strlen(model)) {
                    VIR_FREE(model);
                    continue;
                }
                strncat(sound, model, size);
                size -= strlen(model);
            }

            VIR_FREE(model);
        }
    }
    VIR_FREE(nodes);
    return sound;
  error:
    VIR_FREE(nodes);
    return NULL;
}

int
virDomainParseXMLOSDescHVMChar(virConnectPtr conn,
                               char *buf,
                               size_t buflen,
                               xmlNodePtr node)
{
    xmlChar *type = NULL;
    xmlChar *path = NULL;
    xmlChar *bindHost = NULL;
    xmlChar *bindService = NULL;
    xmlChar *connectHost = NULL;
    xmlChar *connectService = NULL;
    xmlChar *mode = NULL;
    xmlChar *protocol = NULL;
    xmlNodePtr cur;

    type = xmlGetProp(node, BAD_CAST "type");

    if (type != NULL) {
        cur = node->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE) {
                if (xmlStrEqual(cur->name, BAD_CAST "source")) {
                    if (mode == NULL)
                        mode = xmlGetProp(cur, BAD_CAST "mode");

                    if (STREQ((const char *)type, "dev") ||
                        STREQ((const char *)type, "file") ||
                        STREQ((const char *)type, "pipe") ||
                        STREQ((const char *)type, "unix")) {
                        if (path == NULL)
                            path = xmlGetProp(cur, BAD_CAST "path");

                    } else if (STREQ((const char *)type, "udp") ||
                               STREQ((const char *)type, "tcp")) {
                        if (mode == NULL ||
                            STREQ((const char *)mode, "connect")) {

                            if (connectHost == NULL)
                                connectHost = xmlGetProp(cur, BAD_CAST "host");
                            if (connectService == NULL)
                                connectService = xmlGetProp(cur, BAD_CAST "service");
                        } else {
                            if (bindHost == NULL)
                                bindHost = xmlGetProp(cur, BAD_CAST "host");
                            if (bindService == NULL)
                                bindService = xmlGetProp(cur, BAD_CAST "service");
                        }

                        if (STREQ((const char*)type, "udp")) {
                            xmlFree(mode);
                            mode = NULL;
                        }
                    }
                } else if (xmlStrEqual(cur->name, BAD_CAST "protocol")) {
                    if (protocol == NULL)
                        protocol = xmlGetProp(cur, BAD_CAST "type");
                }
            }
            cur = cur->next;
        }
    }

    if (type == NULL ||
        STREQ((const char *)type, "pty")) {
        strncpy(buf, "pty", buflen);
    } else if (STREQ((const char *)type, "null") ||
               STREQ((const char *)type, "stdio") ||
               STREQ((const char *)type, "vc")) {
        snprintf(buf, buflen, "%s", type);
    } else if (STREQ((const char *)type, "file") ||
               STREQ((const char *)type, "dev") ||
               STREQ((const char *)type, "pipe")) {
        if (path == NULL) {
            virXMLError(conn, VIR_ERR_XML_ERROR,
                        _("Missing source path attribute for char device"), 0);
            goto cleanup;
        }

        if (STREQ((const char *)type, "dev"))
            strncpy(buf, (const char *)path, buflen);
        else
            snprintf(buf, buflen, "%s:%s", type, path);
    } else if (STREQ((const char *)type, "tcp")) {
        int telnet = 0;
        if (protocol != NULL &&
            STREQ((const char *)protocol, "telnet"))
            telnet = 1;

        if (mode == NULL ||
            STREQ((const char *)mode, "connect")) {
            if (connectHost == NULL) {
                virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                            _("Missing source host attribute for char device"), 0);
                goto cleanup;
            }
            if (connectService == NULL) {
                virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                            _("Missing source service attribute for char device"), 0);
                goto cleanup;
            }

            snprintf(buf, buflen, "%s:%s:%s",
                     (telnet ? "telnet" : "tcp"),
                     connectHost, connectService);
        } else {
            if (bindHost == NULL) {
                virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                            _("Missing source host attribute for char device"), 0);
                goto cleanup;
            }
            if (bindService == NULL) {
                virXMLError(conn, VIR_ERR_INTERNAL_ERROR,
                            _("Missing source service attribute for char device"), 0);
                goto cleanup;
            }

            snprintf(buf, buflen, "%s:%s:%s,listen",
                     (telnet ? "telnet" : "tcp"),
                     bindHost, bindService);
        }
    } else if (STREQ((const char *)type, "udp")) {
        if (connectService == NULL) {
            virXMLError(conn, VIR_ERR_XML_ERROR,
                        _("Missing source service attribute for char device"), 0);
            goto cleanup;
        }

        snprintf(buf, buflen, "udp:%s:%s@%s:%s",
                 connectHost ? (const char *)connectHost : "",
                 connectService,
                 bindHost ? (const char *)bindHost : "",
                 bindService ? (const char *)bindService : "");
    } else if (STREQ((const char *)type, "unix")) {
        if (path == NULL) {
            virXMLError(conn, VIR_ERR_XML_ERROR,
                        _("Missing source path attribute for char device"), 0);
            goto cleanup;
        }

        if (mode == NULL ||
            STREQ((const char *)mode, "connect")) {
            snprintf(buf, buflen, "%s:%s", type, path);
        } else {
            snprintf(buf, buflen, "%s:%s,listen", type, path);
        }
    }
    buf[buflen-1] = '\0';

    xmlFree(mode);
    xmlFree(protocol);
    xmlFree(type);
    xmlFree(bindHost);
    xmlFree(bindService);
    xmlFree(connectHost);
    xmlFree(connectService);
    xmlFree(path);

    return 0;

cleanup:
    xmlFree(mode);
    xmlFree(protocol);
    xmlFree(type);
    xmlFree(bindHost);
    xmlFree(bindService);
    xmlFree(connectHost);
    xmlFree(connectService);
    xmlFree(path);
    return -1;
}

#endif /* !PROXY */

#endif /* WITH_XEN */
