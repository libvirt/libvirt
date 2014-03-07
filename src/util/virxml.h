/*
 * virxml.h: helper APIs for dealing with XML documents
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

#ifndef __VIR_XML_H__
# define __VIR_XML_H__

# include "internal.h"

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

int              virXPathBoolean(const char *xpath,
                                 xmlXPathContextPtr ctxt);
char *            virXPathString(const char *xpath,
                                 xmlXPathContextPtr ctxt);
char *       virXPathStringLimit(const char *xpath,
                                 size_t maxlen,
                                 xmlXPathContextPtr ctxt);
int               virXPathNumber(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 double *value);
int                  virXPathInt(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 int *value);
int                 virXPathUInt(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned int *value);
int                 virXPathLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int                virXPathULong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
int            virXPathULongLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long long *value);
int             virXPathLongLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long long *value);
int              virXPathLongHex(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int             virXPathULongHex(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
xmlNodePtr          virXPathNode(const char *xpath,
                                 xmlXPathContextPtr ctxt);
int              virXPathNodeSet(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 xmlNodePtr **list);
char *          virXMLPropString(xmlNodePtr node,
                                 const char *name);
long     virXMLChildElementCount(xmlNodePtr node);

/* Internal function; prefer the macros below.  */
xmlDocPtr      virXMLParseHelper(int domcode,
                                 const char *filename,
                                 const char *xmlStr,
                                 const char *url,
                                 xmlXPathContextPtr *pctxt);

const char *virXMLPickShellSafeComment(const char *str1, const char *str2);
/**
 * virXMLParse:
 * @filename: file to parse, or NULL for string parsing
 * @xmlStr: if @filename is NULL, a string to parse
 * @url: if @filename is NULL, an optional filename to attribute the parse to
 *
 * Parse xml from either a file or a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParse(filename, xmlStr, url)                     \
    virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url, NULL)

/**
 * virXMLParseString:
 * @xmlStr: a string to parse
 * @url: an optional filename to attribute the parse to
 *
 * Parse xml from a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParseString(xmlStr, url)                         \
    virXMLParseHelper(VIR_FROM_THIS, NULL, xmlStr, url, NULL)

/**
 * virXMLParseFile:
 * @filename: file to parse
 *
 * Parse xml from a file.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParseFile(filename)                              \
    virXMLParseHelper(VIR_FROM_THIS, filename, NULL, NULL, NULL)

/**
 * virXMLParseCtxt:
 * @filename: file to parse, or NULL for string parsing
 * @xmlStr: if @filename is NULL, a string to parse
 * @url: if @filename is NULL, an optional filename to attribute the parse to
 * @pctxt: if non-NULL, populate with a new context object on success,
 * with (*pctxt)->node pre-set to the root node
 *
 * Parse xml from either a file or a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParseCtxt(filename, xmlStr, url, pctxt)                  \
    virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url, pctxt)

/**
 * virXMLParseStringCtxt:
 * @xmlStr: a string to parse
 * @url: an optional filename to attribute the parse to
 * @pctxt: if non-NULL, populate with a new context object on success,
 * with (*pctxt)->node pre-set to the root node
 *
 * Parse xml from a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParseStringCtxt(xmlStr, url, pctxt)              \
    virXMLParseHelper(VIR_FROM_THIS, NULL, xmlStr, url, pctxt)

/**
 * virXMLParseFileCtxt:
 * @filename: file to parse
 * @pctxt: if non-NULL, populate with a new context object on success,
 * with (*pctxt)->node pre-set to the root node
 *
 * Parse xml from a file.
 *
 * Return the parsed document object, or NULL on failure.
 */
# define virXMLParseFileCtxt(filename, pctxt)                           \
    virXMLParseHelper(VIR_FROM_THIS, filename, NULL, NULL, pctxt)

int virXMLSaveFile(const char *path,
                   const char *warnName,
                   const char *warnCommand,
                   const char *xml);

char *virXMLNodeToString(xmlDocPtr doc, xmlNodePtr node);

xmlNodePtr virXMLFindChildNodeByNs(xmlNodePtr root,
                                   const char *uri);

int virXMLExtractNamespaceXML(xmlNodePtr root,
                              const char *uri,
                              char **doc);

int virXMLInjectNamespace(xmlNodePtr node,
                          const char *uri,
                          const char *key);

#endif                          /* __VIR_XML_H__ */
