/*
 * xml.h: internal definitions used for XML parsing routines.
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "internal.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

int		virXPathBoolean	(const char *xpath,
                                 xmlXPathContextPtr ctxt);
char *		virXPathString	(const char *xpath,
                                 xmlXPathContextPtr ctxt);
int		virXPathNumber	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 double *value);
int		virXPathInt	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 int *value);
int		virXPathUInt	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned int *value);
int		virXPathLong	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int		virXPathULong	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
xmlNodePtr	virXPathNode	(const char *xpath,
                                 xmlXPathContextPtr ctxt);
int		virXPathNodeSet	(const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 xmlNodePtr **list);

char *          virXMLPropString(xmlNodePtr node,
                                 const char *name);

#endif                          /* __VIR_XML_H__ */
