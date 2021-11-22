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
 */

#pragma once

#include "internal.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/relaxng.h>

#include "virbuffer.h"
#include "virenum.h"

xmlXPathContextPtr virXMLXPathContextNew(xmlDocPtr xml)
    G_GNUC_WARN_UNUSED_RESULT;


typedef enum {
    VIR_XML_PROP_NONE = 0,
    VIR_XML_PROP_REQUIRED = 1 << 0, /* Attribute may not be absent */
    VIR_XML_PROP_NONZERO = 1 << 1, /* Attribute may not be zero */
} virXMLPropFlags;


int
virXPathBoolean(const char *xpath,
                xmlXPathContextPtr ctxt);
char *
virXPathString(const char *xpath,
               xmlXPathContextPtr ctxt);
int
virXPathNumber(const char *xpath,
               xmlXPathContextPtr ctxt,
               double *value);
int
virXPathInt(const char *xpath,
            xmlXPathContextPtr ctxt,
            int *value);
int
virXPathUInt(const char *xpath,
             xmlXPathContextPtr ctxt,
             unsigned int *value);
int
virXPathLong(const char *xpath,
             xmlXPathContextPtr ctxt,
             long *value);
int
virXPathULong(const char *xpath,
              xmlXPathContextPtr ctxt,
              unsigned long *value);
int
virXPathULongLong(const char *xpath,
                  xmlXPathContextPtr ctxt,
                  unsigned long long *value);
int
virXPathLongLong(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 long long *value);
int
virXPathLongHex(const char *xpath,
                xmlXPathContextPtr ctxt,
                long *value);
int
virXPathULongHex(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 unsigned long *value);
xmlNodePtr
virXPathNode(const char *xpath,
             xmlXPathContextPtr ctxt);
int
virXPathNodeSet(const char *xpath,
                xmlXPathContextPtr ctxt,
                xmlNodePtr **list);
char *
virXMLPropString(xmlNodePtr node,
                 const char *name);
char *
virXMLNodeContentString(xmlNodePtr node);

int
virXMLPropTristateBool(xmlNodePtr node,
                       const char *name,
                       virXMLPropFlags flags,
                       virTristateBool *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
virXMLPropTristateSwitch(xmlNodePtr node,
                         const char *name,
                         virXMLPropFlags flags,
                         virTristateSwitch *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
virXMLPropInt(xmlNodePtr node,
              const char *name,
              int base,
              virXMLPropFlags flags,
              int *result,
              int defaultResult)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropUInt(xmlNodePtr node,
               const char* name,
               int base,
               virXMLPropFlags flags,
               unsigned int *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropULongLong(xmlNodePtr node,
                    const char* name,
                    int base,
                    virXMLPropFlags flags,
                    unsigned long long *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropEnum(xmlNodePtr node,
               const char* name,
               int (*strToInt)(const char*),
               virXMLPropFlags flags,
               unsigned int *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5);

int
virXMLPropEnumDefault(xmlNodePtr node,
                      const char* name,
                      int (*strToInt)(const char*),
                      virXMLPropFlags flags,
                      unsigned int *result,
                      unsigned int defaultResult)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5);


/* Internal function; prefer the macros below.  */
xmlDocPtr
virXMLParseHelper(int domcode,
                  const char *filename,
                  const char *xmlStr,
                  const char *url,
                  const char *rootelement,
                  xmlXPathContextPtr *ctxt,
                  const char *schemafile,
                  bool validate);

const char *
virXMLPickShellSafeComment(const char *str1,
                           const char *str2);
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
#define virXMLParse(filename, xmlStr, url, schemafile, validate) \
    virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url, NULL, NULL, schemafile, validate)

/**
 * virXMLParseString:
 * @xmlStr: a string to parse
 * @url: an optional filename to attribute the parse to
 *
 * Parse xml from a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
#define virXMLParseString(xmlStr, url) \
    virXMLParseHelper(VIR_FROM_THIS, NULL, xmlStr, url, NULL, NULL, NULL, false)

/**
 * virXMLParseFile:
 * @filename: file to parse
 *
 * Parse xml from a file.
 *
 * Return the parsed document object, or NULL on failure.
 */
#define virXMLParseFile(filename) \
    virXMLParseHelper(VIR_FROM_THIS, filename, NULL, NULL, NULL, NULL, NULL, false)

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
#define virXMLParseCtxt(filename, xmlStr, url, pctxt) \
    virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url, NULL, pctxt, NULL, false)

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
#define virXMLParseStringCtxt(xmlStr, url, pctxt) \
    virXMLParseHelper(VIR_FROM_THIS, NULL, xmlStr, url, NULL, pctxt, NULL, false)

/* virXMLParseStringCtxtRoot is same as above, except it also validates root node name */
#define virXMLParseStringCtxtRoot(xmlStr, url, rootnode, pctxt) \
    virXMLParseHelper(VIR_FROM_THIS, NULL, xmlStr, url, rootnode, pctxt, NULL, false)

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
#define virXMLParseFileCtxt(filename, pctxt) \
    virXMLParseHelper(VIR_FROM_THIS, filename, NULL, NULL, NULL, pctxt, NULL, false)

int
virXMLSaveFile(const char *path,
               const char *warnName,
               const char *warnCommand,
               const char *xml);

char *
virXMLNodeToString(xmlDocPtr doc,
                   xmlNodePtr node);

bool
virXMLNodeNameEqual(xmlNodePtr node,
                    const char *name);

xmlNodePtr
virXMLFindChildNodeByNs(xmlNodePtr root,
                        const char *uri);

int
virXMLExtractNamespaceXML(xmlNodePtr root,
                          const char *uri,
                          char **doc);

int
virXMLInjectNamespace(xmlNodePtr node,
                      const char *uri,
                      const char *key);

void
virXMLNodeSanitizeNamespaces(xmlNodePtr node);

int
virXMLCheckIllegalChars(const char *nodeName,
                        const char *str,
                        const char *illegal);

struct _virXMLValidator {
    xmlRelaxNGParserCtxtPtr rngParser;
    xmlRelaxNGPtr rng;
    xmlRelaxNGValidCtxtPtr rngValid;
    virBuffer buf;
    char *schemafile;
};
typedef struct _virXMLValidator virXMLValidator;

virXMLValidator *
virXMLValidatorInit(const char *schemafile);

int
virXMLValidatorValidate(virXMLValidator *validator,
                        xmlDocPtr doc);

int
virXMLValidateAgainstSchema(const char *schemafile,
                            xmlDocPtr xml);

int
virXMLValidateNodeAgainstSchema(const char *schemafile,
                                xmlNodePtr node);

void
virXMLValidatorFree(virXMLValidator *validator);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virXMLValidator, virXMLValidatorFree);

void
virXMLFormatElement(virBuffer *buf,
                    const char *name,
                    virBuffer *attrBuf,
                    virBuffer *childBuf);

void
virXMLFormatElementEmpty(virBuffer *buf,
                         const char *name,
                         virBuffer *attrBuf,
                         virBuffer *childBuf);

int
virXMLFormatMetadata(virBuffer *buf,
                     xmlNodePtr metadata);

struct _virXPathContextNodeSave {
    xmlXPathContextPtr ctxt;
    xmlNodePtr node;
};
typedef struct _virXPathContextNodeSave virXPathContextNodeSave;

void
virXPathContextNodeRestore(virXPathContextNodeSave *save);

G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(virXPathContextNodeSave, virXPathContextNodeRestore);

/**
 * VIR_XPATH_NODE_AUTORESTORE:
 * @ctxt: XML XPath context pointer
 *
 * This macro ensures that when the scope where it's used ends, @ctxt's current
 * node pointer is reset to the original value when this macro was used.
 */
#define VIR_XPATH_NODE_AUTORESTORE(_ctxt) \
    VIR_WARNINGS_NO_UNUSED_VARIABLE \
    g_auto(virXPathContextNodeSave) _ctxt ## CtxtSave = { .ctxt = _ctxt,\
                                                          .node = _ctxt->node}; \
    VIR_WARNINGS_RESET

G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlDoc, xmlFreeDoc);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlXPathContext, xmlXPathFreeContext);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlXPathObject, xmlXPathFreeObject);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlBuffer, xmlBufferFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlNode, xmlFreeNode);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(xmlParserCtxt, xmlFreeParserCtxt);

typedef int (*virXMLNamespaceParse)(xmlXPathContextPtr ctxt,
                                    void **nsdata);
typedef void (*virXMLNamespaceFree)(void *nsdata);
typedef int (*virXMLNamespaceFormat)(virBuffer *buf,
                                     void *nsdata);
typedef const char *(*virXMLNamespaceHref)(void);

struct _virXMLNamespace {
    virXMLNamespaceParse parse;
    virXMLNamespaceFree free;
    virXMLNamespaceFormat format;
    const char *prefix;
    const char *uri;
};
typedef struct _virXMLNamespace virXMLNamespace;

void
virXMLNamespaceFormatNS(virBuffer *buf,
                        virXMLNamespace const *ns);
int
virXMLNamespaceRegister(xmlXPathContextPtr ctxt,
                        virXMLNamespace const *ns);

int
virParseScaledValue(const char *xpath,
                    const char *units_xpath,
                    xmlXPathContextPtr ctxt,
                    unsigned long long *val,
                    unsigned long long scale,
                    unsigned long long max,
                    bool required);

xmlBufferPtr
virXMLBufferCreate(void);

xmlNodePtr
virXMLNewNode(xmlNsPtr ns,
              const char *name);
