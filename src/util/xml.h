/*
 * xml.h: internal definitions used for XML parsing routines.
 */

#ifndef __VIR_XML_H__
#define __VIR_XML_H__

#include "internal.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

int		virXPathBoolean	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt);
char *		virXPathString	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt);
char *          virXPathStringLimit(virConnectPtr conn,
                                    const char *xpath,
                                    size_t maxlen,
                                    xmlXPathContextPtr ctxt);
int		virXPathNumber	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 double *value);
int		virXPathLong	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int		virXPathULong	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
int	        virXPathULongLong(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long long *value);
int		virXPathLongHex	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 long *value);
int		virXPathULongHex(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 unsigned long *value);
xmlNodePtr	virXPathNode	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt);
int		virXPathNodeSet	(virConnectPtr conn,
                                 const char *xpath,
                                 xmlXPathContextPtr ctxt,
                                 xmlNodePtr **list);

char *          virXMLPropString(xmlNodePtr node,
                                 const char *name);

#endif                          /* __VIR_XML_H__ */
