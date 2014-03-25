/*
 * virxml.c: helper APIs for dealing with XML documents
 *
 * Copyright (C) 2005, 2007-2012 Red Hat, Inc.
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
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>               /* for isnan() */
#include <sys/stat.h>

#include "virerror.h"
#include "virxml.h"
#include "virbuffer.h"
#include "virutil.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_XML

#define virGenericReportError(from, code, ...)                          \
        virReportErrorHelper(from, code, __FILE__,                      \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

/* Internal data to be passed to SAX parser and used by error handler. */
struct virParserData {
    int domcode;
};


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
virXPathString(const char *xpath,
               xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    char *ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathString()"));
        return NULL;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj == NULL) || (obj->type != XPATH_STRING) ||
        (obj->stringval == NULL) || (obj->stringval[0] == 0)) {
        xmlXPathFreeObject(obj);
        return NULL;
    }
    ignore_value(VIR_STRDUP(ret, (char *) obj->stringval));
    xmlXPathFreeObject(obj);
    return ret;
}

/**
 * virXPathStringLimit:
 * @xpath: the XPath string to evaluate
 * @maxlen: maximum length permittred string
 * @ctxt: an XPath context
 *
 * Wrapper for virXPathString, which validates the length of the returned
 * string.
 *
 * Returns a new string which must be deallocated by the caller or NULL if
 * the evaluation failed.
 */
char *
virXPathStringLimit(const char *xpath,
                    size_t maxlen,
                    xmlXPathContextPtr ctxt)
{
    char *tmp = virXPathString(xpath, ctxt);

    if (tmp != NULL && strlen(tmp) >= maxlen) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("\'%s\' value longer than %zu bytes"),
                       xpath, maxlen);
        VIR_FREE(tmp);
        return NULL;
    }

    return tmp;
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
virXPathNumber(const char *xpath,
               xmlXPathContextPtr ctxt,
               double *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathNumber()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj == NULL) || (obj->type != XPATH_NUMBER) ||
        (isnan(obj->floatval))) {
        xmlXPathFreeObject(obj);
        return -1;
    }

    *value = obj->floatval;
    xmlXPathFreeObject(obj);
    return 0;
}

static int
virXPathLongBase(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 int base,
                 long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathLong()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (virStrToLong_l((char *) obj->stringval, NULL, base, value) < 0)
            ret = -2;
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
    return ret;
}

/**
 * virXPathInt:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned int value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have an int format.
 */
int
virXPathInt(const char *xpath,
            xmlXPathContextPtr ctxt,
            int *value)
{
    long tmp;
    int ret;

    ret = virXPathLongBase(xpath, ctxt, 10, &tmp);
    if (ret < 0)
        return ret;
    if ((int) tmp != tmp)
        return -2;
    *value = tmp;
    return 0;
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
virXPathLong(const char *xpath,
             xmlXPathContextPtr ctxt,
             long *value)
{
    return virXPathLongBase(xpath, ctxt, 10, value);
}

/**
 * virXPathLongHex:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long value
 *
 * Convenience function to evaluate an XPath number
 * according to a base of 16
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathLongHex(const char *xpath,
                xmlXPathContextPtr ctxt,
                long *value)
{
    return virXPathLongBase(xpath, ctxt, 16, value);
}

static int
virXPathULongBase(const char *xpath,
                  xmlXPathContextPtr ctxt,
                  int base,
                  unsigned long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathULong()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (virStrToLong_ul((char *) obj->stringval, NULL, base, value) < 0)
            ret = -2;
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
    return ret;
}

/**
 * virXPathUInt:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned int value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have an int format.
 */
int
virXPathUInt(const char *xpath,
             xmlXPathContextPtr ctxt,
             unsigned int *value)
{
    unsigned long tmp;
    int ret;

    ret = virXPathULongBase(xpath, ctxt, 10, &tmp);
    if (ret < 0)
        return ret;
    if ((unsigned int) tmp != tmp)
        return -2;
    *value = tmp;
    return 0;
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
virXPathULong(const char *xpath,
              xmlXPathContextPtr ctxt,
              unsigned long *value)
{
    return virXPathULongBase(xpath, ctxt, 10, value);
}

/**
 * virXPathUHex:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long value
 *
 * Convenience function to evaluate an XPath number
 * according to base of 16
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathULongHex(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 unsigned long *value)
{
    return virXPathULongBase(xpath, ctxt, 16, value);
}

/**
 * virXPathULongLong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long long value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathULongLong(const char *xpath,
                  xmlXPathContextPtr ctxt,
                  unsigned long long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathULong()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (virStrToLong_ull((char *) obj->stringval, NULL, 10, value) < 0)
            ret = -2;
    } else if ((obj != NULL) && (obj->type == XPATH_NUMBER) &&
               (!(isnan(obj->floatval)))) {
        *value = (unsigned long long) obj->floatval;
        if (*value != obj->floatval) {
            ret = -2;
        }
    } else {
        ret = -1;
    }

    xmlXPathFreeObject(obj);
    return ret;
}

/**
 * virXPathULongLong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long long value
 *
 * Convenience function to evaluate an XPath number
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a long format.
 */
int
virXPathLongLong(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 long long *value)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret = 0;

    if ((ctxt == NULL) || (xpath == NULL) || (value == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathLongLong()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj != NULL) && (obj->type == XPATH_STRING) &&
        (obj->stringval != NULL) && (obj->stringval[0] != 0)) {
        if (virStrToLong_ll((char *) obj->stringval, NULL, 10, value) < 0)
            ret = -2;
    } else if ((obj != NULL) && (obj->type == XPATH_NUMBER) &&
               (!(isnan(obj->floatval)))) {
        *value = (long long) obj->floatval;
        if (*value != obj->floatval) {
            ret = -2;
        }
    } else {
        ret = -1;
    }

    xmlXPathFreeObject(obj);
    return ret;
}

/**
 * virXMLPropString:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 *
 * Convenience function to return copy of an attribute value of a XML node.
 *
 * Returns the property (attribute) value as string or NULL in case of failure.
 * The caller is responsible for freeing the returned buffer.
 */
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
virXPathBoolean(const char *xpath,
                xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathBoolean()"));
        return -1;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN) ||
        (obj->boolval < 0) || (obj->boolval > 1)) {
        xmlXPathFreeObject(obj);
        return -1;
    }
    ret = obj->boolval;

    xmlXPathFreeObject(obj);
    return ret;
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
virXPathNode(const char *xpath,
             xmlXPathContextPtr ctxt)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    xmlNodePtr ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathNode()"));
        return NULL;
    }
    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
        (obj->nodesetval->nodeTab == NULL)) {
        xmlXPathFreeObject(obj);
        return NULL;
    }

    ret = obj->nodesetval->nodeTab[0];
    xmlXPathFreeObject(obj);
    return ret;
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
virXPathNodeSet(const char *xpath,
                xmlXPathContextPtr ctxt,
                xmlNodePtr **list)
{
    xmlXPathObjectPtr obj;
    xmlNodePtr relnode;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter to virXPathNodeSet()"));
        return -1;
    }

    if (list != NULL)
        *list = NULL;

    relnode = ctxt->node;
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    ctxt->node = relnode;
    if (obj == NULL)
        return 0;

    if (obj->type != XPATH_NODESET) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Incorrect xpath '%s'"), xpath);
        xmlXPathFreeObject(obj);
        return -1;
    }

    if ((obj->nodesetval == NULL)  || (obj->nodesetval->nodeNr < 0)) {
        xmlXPathFreeObject(obj);
        return 0;
    }

    ret = obj->nodesetval->nodeNr;
    if (list != NULL && ret) {
        if (VIR_ALLOC_N(*list, ret) < 0) {
            ret = -1;
        } else {
            memcpy(*list, obj->nodesetval->nodeTab,
                   ret * sizeof(xmlNodePtr));
        }
    }
    xmlXPathFreeObject(obj);
    return ret;
}


/**
 * catchXMLError:
 *
 * Called from SAX on parsing errors in the XML.
 *
 * This version is heavily based on xmlParserPrintFileContextInternal from libxml2.
 */
static void
catchXMLError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    const xmlChar *cur, *base;
    unsigned int n, col;	/* GCC warns if signed, because compared with sizeof() */
    int domcode = VIR_FROM_XML;

    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *contextstr = NULL;
    char *pointerstr = NULL;


    /* conditions for error printing */
    if (!ctxt ||
        (virGetLastError() != NULL) ||
        ctxt->input == NULL ||
        ctxt->lastError.level != XML_ERR_FATAL ||
        ctxt->lastError.message == NULL)
        return;

    if (ctxt->_private)
            domcode = ((struct virParserData *) ctxt->_private)->domcode;


    cur = ctxt->input->cur;
    base = ctxt->input->base;

    /* skip backwards over any end-of-lines */
    while ((cur > base) && ((*(cur) == '\n') || (*(cur) == '\r'))) {
        cur--;
    }

    /* search backwards for beginning-of-line (to max buff size) */
    while ((cur > base) && (*(cur) != '\n') && (*(cur) != '\r'))
        cur--;
    if ((*(cur) == '\n') || (*(cur) == '\r')) cur++;

    /* calculate the error position in terms of the current position */
    col = ctxt->input->cur - cur;

    /* search forward for end-of-line (to max buff size) */
    /* copy selected text to our buffer */
    while ((*cur != 0) && (*(cur) != '\n') && (*(cur) != '\r')) {
        virBufferAddChar(&buf, *cur++);
    }

    /* create blank line with problem pointer */
    contextstr = virBufferContentAndReset(&buf);

    /* (leave buffer space for pointer + line terminator) */
    for  (n = 0; (n<col) && (contextstr[n] != 0); n++) {
        if (contextstr[n] == '\t')
            virBufferAddChar(&buf, '\t');
        else
            virBufferAddChar(&buf, '-');
    }

    virBufferAddChar(&buf, '^');

    pointerstr = virBufferContentAndReset(&buf);

    if (ctxt->lastError.file) {
        virGenericReportError(domcode, VIR_ERR_XML_DETAIL,
                              _("%s:%d: %s%s\n%s"),
                              ctxt->lastError.file,
                              ctxt->lastError.line,
                              ctxt->lastError.message,
                              contextstr,
                              pointerstr);
    } else {
         virGenericReportError(domcode, VIR_ERR_XML_DETAIL,
                              _("at line %d: %s%s\n%s"),
                              ctxt->lastError.line,
                              ctxt->lastError.message,
                              contextstr,
                              pointerstr);
    }

    VIR_FREE(contextstr);
    VIR_FREE(pointerstr);
}

/**
 * virXMLParseHelper:
 * @domcode: error domain of the caller, usually VIR_FROM_THIS
 * @filename: file to be parsed or NULL if string parsing is requested
 * @xmlStr: XML string to be parsed in case filename is NULL
 * @url: URL of XML document for string parser
 * @ctxt: optional pointer to populate with new context pointer
 *
 * Parse XML document provided either as a file or a string. The function
 * guarantees that the XML document contains a root element.
 *
 * Returns parsed XML document.
 */
xmlDocPtr
virXMLParseHelper(int domcode,
                  const char *filename,
                  const char *xmlStr,
                  const char *url,
                  xmlXPathContextPtr *ctxt)
{
    struct virParserData private;
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt();
    if (!pctxt || !pctxt->sax) {
        virReportOOMError();
        goto error;
    }

    private.domcode = domcode;
    pctxt->_private = &private;
    pctxt->sax->error = catchXMLError;

    if (filename) {
        xml = xmlCtxtReadFile(pctxt, filename, NULL,
                              XML_PARSE_NOENT | XML_PARSE_NONET |
                              XML_PARSE_NOWARNING);
    } else {
        xml = xmlCtxtReadDoc(pctxt, BAD_CAST xmlStr, url, NULL,
                             XML_PARSE_NOENT | XML_PARSE_NONET |
                             XML_PARSE_NOWARNING);
    }
    if (!xml)
        goto error;

    if (xmlDocGetRootElement(xml) == NULL) {
        virGenericReportError(domcode, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto error;
    }

    if (ctxt) {
        *ctxt = xmlXPathNewContext(xml);
        if (!*ctxt) {
            virReportOOMError();
            goto error;
        }
        (*ctxt)->node = xmlDocGetRootElement(xml);
    }

 cleanup:
    xmlFreeParserCtxt(pctxt);

    return xml;

 error:
    xmlFreeDoc(xml);
    xml = NULL;

    if (virGetLastError() == NULL) {
        virGenericReportError(domcode, VIR_ERR_XML_ERROR,
                              "%s", _("failed to parse xml document"));
    }
    goto cleanup;
}

const char *virXMLPickShellSafeComment(const char *str1, const char *str2)
{
    if (str1 && !strpbrk(str1, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~") &&
        !strstr(str1, "--"))
        return str1;
    if (str2 && !strpbrk(str2, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~") &&
        !strstr(str2, "--"))
        return str2;
    return NULL;
}

static int virXMLEmitWarning(int fd,
                             const char *name,
                             const char *cmd)
{
    size_t len;
    const char *prologue =
        "<!--\n"
        "WARNING: THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE\n"
        "OVERWRITTEN AND LOST. Changes to this xml configuration should be made using:\n"
        "  virsh ";
    const char *epilogue =
        "\n"
        "or other application using the libvirt API.\n"
        "-->\n\n";

    if (fd < 0 || !cmd) {
        errno = EINVAL;
        return -1;
    }

    len = strlen(prologue);
    if (safewrite(fd, prologue, len) != len)
        return -1;

    len = strlen(cmd);
    if (safewrite(fd, cmd, len) != len)
        return -1;

    if (name) {
        if (safewrite(fd, " ", 1) != 1)
            return -1;

        len = strlen(name);
        if (safewrite(fd, name, len) != len)
            return -1;
    }

    len = strlen(epilogue);
    if (safewrite(fd, epilogue, len) != len)
        return -1;

    return 0;
}


struct virXMLRewriteFileData {
    const char *warnName;
    const char *warnCommand;
    const char *xml;
};

static int
virXMLRewriteFile(int fd, void *opaque)
{
    struct virXMLRewriteFileData *data = opaque;

    if (data->warnCommand) {
        if (virXMLEmitWarning(fd, data->warnName, data->warnCommand) < 0)
            return -1;
    }

    if (safewrite(fd, data->xml, strlen(data->xml)) < 0)
        return -1;

    return 0;
}

int
virXMLSaveFile(const char *path,
               const char *warnName,
               const char *warnCommand,
               const char *xml)
{
    struct virXMLRewriteFileData data = { warnName, warnCommand, xml };

    return virFileRewrite(path, S_IRUSR | S_IWUSR, virXMLRewriteFile, &data);
}

/* Returns the number of children of node, or -1 on error.  */
long
virXMLChildElementCount(xmlNodePtr node)
{
    long ret = 0;
    xmlNodePtr cur = NULL;

    /* xmlChildElementCount returns 0 on error, which isn't helpful;
     * besides, it is not available in libxml2 2.6.  */
    if (!node || node->type != XML_ELEMENT_NODE)
        return -1;
    cur = node->children;
    while (cur) {
        if (cur->type == XML_ELEMENT_NODE)
            ret++;
        cur = cur->next;
    }
    return ret;
}


/**
 * virXMLNodeToString: convert an XML node ptr to an XML string
 *
 * Returns the XML string of the document or NULL on error.
 * The caller has to free the string.
 */
char *
virXMLNodeToString(xmlDocPtr doc,
                   xmlNodePtr node)
{
     xmlBufferPtr xmlbuf = NULL;
     char *ret = NULL;

     if (!(xmlbuf = xmlBufferCreate())) {
         virReportOOMError();
         return NULL;
     }

     if (xmlNodeDump(xmlbuf, doc, node, 0, 1) == 0) {
         virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to convert the XML node tree"));
         goto cleanup;
     }

     ignore_value(VIR_STRDUP(ret, (const char *)xmlBufferContent(xmlbuf)));

 cleanup:
     xmlBufferFree(xmlbuf);

     return ret;
}

typedef int (*virXMLForeachCallback)(xmlNodePtr node,
                                     void *opaque);

static int
virXMLForeachNode(xmlNodePtr root,
                  virXMLForeachCallback cb,
                  void *opaque);

static int
virXMLForeachNode(xmlNodePtr root,
                  virXMLForeachCallback cb,
                  void *opaque)
{
    xmlNodePtr next;
    int ret;

    for (next = root; next; next = next->next) {
        if ((ret = cb(next, opaque)) != 0)
            return ret;

        /* recurse into children */
        if (next->children) {
            if ((ret = virXMLForeachNode(next->children, cb, opaque)) != 0)
                return ret;
        }
    }

    return 0;
}


static int
virXMLRemoveElementNamespace(xmlNodePtr node,
                             void *opaque)
{
    const char *uri = opaque;

    if (node->ns &&
        STREQ_NULLABLE((const char *)node->ns->href, uri))
        xmlSetNs(node, NULL);
    return 0;
}


xmlNodePtr
virXMLFindChildNodeByNs(xmlNodePtr root,
                        const char *uri)
{
    xmlNodePtr next;

    for (next = root->children; next; next = next->next) {
        if (next->ns &&
            STREQ_NULLABLE((const char *) next->ns->href, uri))
            return next;
    }

    return NULL;
}


/**
 * virXMLExtractNamespaceXML: extract a sub-namespace of XML as string
 */
int
virXMLExtractNamespaceXML(xmlNodePtr root,
                          const char *uri,
                          char **doc)
{
    xmlNodePtr node;
    xmlNodePtr nodeCopy = NULL;
    xmlNsPtr actualNs;
    xmlNsPtr prevNs = NULL;
    char *xmlstr = NULL;
    int ret = -1;

    if (!(node = virXMLFindChildNodeByNs(root, uri))) {
        /* node not found */
        ret = 1;
        goto cleanup;
    }

    /* copy the node so that we can modify the namespace */
    if (!(nodeCopy = xmlCopyNode(node, 1))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to copy XML node"));
        goto cleanup;
    }

    virXMLForeachNode(nodeCopy, virXMLRemoveElementNamespace,
                      (void *)uri);

    /* remove the namespace declaration
     *  - it's only a single linked list ... doh */
    for (actualNs = nodeCopy->nsDef; actualNs; actualNs = actualNs->next) {
        if (STREQ_NULLABLE((const char *)actualNs->href, uri)) {

            /* unlink */
            if (prevNs)
                prevNs->next = actualNs->next;
            else
                nodeCopy->nsDef = actualNs->next;

            /* discard */
            xmlFreeNs(actualNs);
            break;
        }

        prevNs = actualNs;
    }

    if (!(xmlstr = virXMLNodeToString(nodeCopy->doc, nodeCopy)))
        goto cleanup;

    ret = 0;

 cleanup:
    if (doc)
        *doc = xmlstr;
    else
        VIR_FREE(xmlstr);
    xmlFreeNode(nodeCopy);
    return ret;
}


static int
virXMLAddElementNamespace(xmlNodePtr node,
                          void *opaque)
{
    xmlNsPtr ns = opaque;

    if (!node->ns)
        xmlSetNs(node, ns);

    return 0;
}


int
virXMLInjectNamespace(xmlNodePtr node,
                      const char *uri,
                      const char *key)
{
    xmlNsPtr ns;

    if (!(ns = xmlNewNs(node, (const unsigned char *)uri, (const unsigned char *)key))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create a new XML namespace"));
        return -1;
    }

    virXMLForeachNode(node, virXMLAddElementNamespace, ns);

    return 0;
}
