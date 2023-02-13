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

typedef enum {
    VIR_XML_PROP_NONE = 0,
    VIR_XML_PROP_REQUIRED = 1 << 0, /* Attribute may not be absent */
    VIR_XML_PROP_NONZERO = 1 << 1, /* Attribute may not be zero */
    VIR_XML_PROP_NONNEGATIVE = 1 << 2, /* Attribute may not be negative, makes
                                          sense only for some virXMLProp*()
                                          functions. */
} virXMLPropFlags;


int
virXPathBoolean(const char *xpath,
                xmlXPathContextPtr ctxt);
char *
virXPathString(const char *xpath,
               xmlXPathContextPtr ctxt);
int
virXPathInt(const char *xpath,
            xmlXPathContextPtr ctxt,
            int *value);
int
virXPathUIntBase(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 unsigned int base,
                 unsigned int *value);
int
virXPathUInt(const char *xpath,
             xmlXPathContextPtr ctxt,
             unsigned int *value);
int
virXPathULongLongBase(const char *xpath,
                      xmlXPathContextPtr ctxt,
                      unsigned int base,
                      unsigned long long *value);
int
virXPathULongLong(const char *xpath,
                  xmlXPathContextPtr ctxt,
                  unsigned long long *value);
int
virXPathLongLong(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 long long *value);

xmlNodePtr
virXMLNodeGetSubelement(xmlNodePtr node,
                        const char *name);

size_t
virXMLNodeGetSubelementList(xmlNodePtr node,
                            const char *name,
                            xmlNodePtr **list);

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
virXMLPropStringRequired(xmlNodePtr node,
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
virXMLPropTristateBoolAllowDefault(xmlNodePtr node,
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
               const char *name,
               int base,
               virXMLPropFlags flags,
               unsigned int *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropUIntDefault(xmlNodePtr node,
                      const char *name,
                      int base,
                      virXMLPropFlags flags,
                      unsigned int *result,
                      unsigned int defaultResult)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropLongLong(xmlNodePtr node,
                   const char *name,
                   int base,
                   virXMLPropFlags flags,
                   long long *result,
                   long long defaultResult)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropULongLong(xmlNodePtr node,
                    const char *name,
                    int base,
                    virXMLPropFlags flags,
                    unsigned long long *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

int
virXMLPropEnum(xmlNodePtr node,
               const char *name,
               int (*strToInt)(const char *),
               virXMLPropFlags flags,
               unsigned int *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5);

int
virXMLPropUUID(xmlNodePtr node,
               const char *name,
               virXMLPropFlags flags,
               unsigned char *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
virXMLPropEnumDefault(xmlNodePtr node,
                      const char *name,
                      int (*strToInt)(const char *),
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
 * @rootelement: if non-NULL, validate that the root element name equals to this parameter
 * @ctxt: if non-NULL, filled with a new XPath context including populating the root node
 * @schemafile: name of the appropriate schema file for the parsed XML for validation (may be NULL)
 * @validate: if true and @schemafile is non-NULL, validate the XML against @schemafile
 *
 * Parse xml from either a file or a string.
 *
 * Return the parsed document object, or NULL on failure.
 */
#define virXMLParse(filename, xmlStr, url, rootelement, ctxt, schemafile, validate) \
    virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url, rootelement, ctxt, schemafile, validate)

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
virXMLFormatElementInternal(virBuffer *buf,
                            const char *name,
                            virBuffer *attrBuf,
                            virBuffer *childBuf,
                            bool allowEmpty,
                            bool childNewline);
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
 * VIR_XPATH_NODE_AUTORESTORE_NAME:
 * @name: name of the temporary variable used to save @ctxt
 * @ctxt: XML XPath context pointer
 *
 * This macro ensures that when the scope where it's used ends, @ctxt's current
 * node pointer is reset to the original value when this macro was used. The
 * context is saved into a variable named @name;
 */
#define VIR_XPATH_NODE_AUTORESTORE_NAME(_name, _ctxt) \
    VIR_WARNINGS_NO_UNUSED_VARIABLE \
    g_auto(virXPathContextNodeSave) _name = { .ctxt = _ctxt,\
                                              .node = _ctxt->node}; \
    VIR_WARNINGS_RESET
/**
 * VIR_XPATH_NODE_AUTORESTORE:
 * @ctxt: XML XPath context pointer
 *
 * This macro ensures that when the scope where it's used ends, @ctxt's current
 * node pointer is reset to the original value when this macro was used.
 */
#define VIR_XPATH_NODE_AUTORESTORE(_ctxt) \
    VIR_XPATH_NODE_AUTORESTORE_NAME(_ctxt ## CtxtSave, _ctxt)

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
