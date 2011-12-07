/*
 * xml.h: internal definitions used for XML parsing routines.
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

#endif                          /* __VIR_XML_H__ */
