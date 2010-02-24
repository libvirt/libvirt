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
int                 virXPathLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int                 virXPathULong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
int            virXPathULongLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long long *value);
int	        virXPathLongLong(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long long *value);
int		virXPathLongHex	(const char *xpath,
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

xmlDocPtr      virXMLParseHelper(int domcode,
                                 const char *filename,
                                 const char *xmlStr,
                                 const char *url);
xmlDocPtr   virXMLParseStrHelper(int domcode,
                                 const char *xmlStr,
                                 const char *url);
xmlDocPtr  virXMLParseFileHelper(int domcode,
                                 const char *filename);

# define virXMLParse(filename, xmlStr, url)                     \
        virXMLParseHelper(VIR_FROM_THIS, filename, xmlStr, url)

# define virXMLParseString(xmlStr, url)                         \
        virXMLParseStrHelper(VIR_FROM_THIS, xmlStr, url)

# define virXMLParseFile(filename)                              \
        virXMLParseFileHelper(VIR_FROM_THIS, filename)

#endif                          /* __VIR_XML_H__ */
