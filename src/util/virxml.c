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
 */

#include <config.h>

#include <stdarg.h>
#include <math.h>               /* for isnan() */
#include <sys/stat.h>

#include <libxml/xpathInternals.h>

#include "virerror.h"
#include "virxml.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virutil.h"
#include "viruuid.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_XML

#define virGenericReportError(from, code, ...) \
        virReportErrorHelper(from, code, __FILE__, \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

/* Internal data to be passed to SAX parser and used by error handler. */
struct virParserData {
    int domcode;
};


static xmlXPathContextPtr
virXMLXPathContextNew(xmlDocPtr xml)
{
    xmlXPathContextPtr ctxt;

    if (!(ctxt = xmlXPathNewContext(xml)))
        abort();

    return ctxt;
}


static xmlXPathObject *
virXPathEvalString(const char *xpath,
                   xmlXPathContextPtr ctxt)
{
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!xpath) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing XPath expression"));
        return NULL;
    }

    if (!ctxt) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing XPath context"));
        return NULL;
    }

    if (!(obj = xmlXPathEval(BAD_CAST xpath, ctxt)))
        return NULL;

    if (obj->type != XPATH_STRING ||
        !obj->stringval ||
        obj->stringval[0] == '\0')
        return NULL;

    return g_steal_pointer(&obj);
}


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
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!(obj = virXPathEvalString(xpath, ctxt)))
        return NULL;

    return g_strdup((char *)obj->stringval);
}


/**
 * virXPathInt:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned int value
 *
 * Convenience function to evaluate an XPath number. The @xpath expression
 * must ensure that the evaluated value is returned as a string (use the
 * 'string()' conversion in the expression).
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
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!(obj = virXPathEvalString(xpath, ctxt)))
        return -1;

    if (virStrToLong_i((char *) obj->stringval, NULL, 10, value) < 0)
        return -2;

    return 0;
}


/**
 * virXPathUIntBase:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @base: base of the number to fetch @value as
 * @value: the returned unsigned int value
 *
 * Convenience function to evaluate an XPath number. The @xpath expression
 * must ensure that the evaluated value is returned as a string (use the
 * 'string()' conversion in the expression).
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have an unsigned int format.
 */
int
virXPathUIntBase(const char *xpath,
                 xmlXPathContextPtr ctxt,
                 unsigned int base,
                 unsigned int *value)
{
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!(obj = virXPathEvalString(xpath, ctxt)))
        return -1;

    if (virStrToLong_uip((char *) obj->stringval, NULL, base, value) < 0)
        return -2;

    return 0;
}


int
virXPathUInt(const char *xpath,
             xmlXPathContextPtr ctxt,
             unsigned int *value)
{
    return virXPathUIntBase(xpath, ctxt, 10, value);
}


/**
 * virXPathULongLongBase:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @base: base of the number to fetch @value as
 * @value: the returned unsigned long long value
 *
 * Convenience function to evaluate an XPath number. The @xpath expression
 * must ensure that the evaluated value is returned as a string (use the
 * 'string()' conversion in the expression).
 *
 * Returns 0 in case of success in which case @value is set,
 *         or -1 if the XPath evaluation failed or -2 if the
 *         value doesn't have a unsigned long long format.
 */
int
virXPathULongLongBase(const char *xpath,
                      xmlXPathContextPtr ctxt,
                      unsigned int base,
                      unsigned long long *value)
{
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!(obj = virXPathEvalString(xpath, ctxt)))
        return -1;

    if (virStrToLong_ullp((char *) obj->stringval, NULL, base, value) < 0)
        return -2;

    return 0;
}


int
virXPathULongLong(const char *xpath,
                  xmlXPathContextPtr ctxt,
                  unsigned long long *value)
{
    return virXPathULongLongBase(xpath, ctxt, 10, value);
}


/**
 * virXPathLongLong:
 * @xpath: the XPath string to evaluate
 * @ctxt: an XPath context
 * @value: the returned long long value
 *
 * Convenience function to evaluate an XPath number. The @xpath expression
 * must ensure that the evaluated value is returned as a string (use the
 * 'string()' conversion in the expression).
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
    g_autoptr(xmlXPathObject) obj = NULL;

    if (!(obj = virXPathEvalString(xpath, ctxt)))
        return -1;

    if (virStrToLong_ll((char *) obj->stringval, NULL, 10, value) < 0)
        return -2;

    return 0;
}


/**
 * virXMLCheckIllegalChars:
 * @nodeName: Name of checked node
 * @str: string to check
 * @illegal: illegal chars to check
 *
 * If string contains any of illegal chars VIR_ERR_XML_DETAIL error will be
 * reported.
 *
 * Returns: 0 if string don't contains any of given characters, -1 otherwise
 */
int
virXMLCheckIllegalChars(const char *nodeName,
                        const char *str,
                        const char *illegal)
{
    char *c;
    if ((c = strpbrk(str, illegal))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid char in %1$s: %2$c"), nodeName, *c);
        return -1;
    }
    return 0;
}


/**
 * virXMLPropString:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 *
 * Convenience function to return copy of an attribute value of a XML node.
 *
 * Returns the property (attribute) value as string or NULL if the attribute
 * is not present (no error is reported).
 * The caller is responsible for freeing the returned buffer.
 */
char *
virXMLPropString(xmlNodePtr node,
                 const char *name)
{
    return (char *)xmlGetProp(node, BAD_CAST name);
}


/**
 * virXMLPropStringRequired:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 *
 * Convenience function to return copy of an mandatoryu attribute value of an
 * XML node.
 *
 * Returns the property (attribute) value as string or NULL and if the attribute
 * is not present (libvirt error reported).
 * The caller is responsible for freeing the returned buffer.
 */
char *
virXMLPropStringRequired(xmlNodePtr node,
                         const char *name)
{
    char *ret = virXMLPropString(node, name);

     if (!ret)
         virReportError(VIR_ERR_XML_ERROR,
                        _("Missing required attribute '%1$s' in element '%2$s'"),
                        name, node->name);

     return ret;
}


/**
 * virXMLNodeContentString:
 * @node: XML dom node pointer
 *
 * Convenience function to return copy of content of an XML node.
 *
 * Returns the content value as string or NULL in case of failure.
 * The caller is responsible for freeing the returned buffer.
 */
char *
virXMLNodeContentString(xmlNodePtr node)
{
    char *ret = NULL;

    if (node->type !=  XML_ELEMENT_NODE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("node '%1$s' has unexpected type %2$d"),
                       node->name, node->type);
        return NULL;
    }

    ret = (char *)xmlNodeGetContent(node);

    if (!ret) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("node '%1$s' has unexpected NULL content. This could be caused by malformed input, or a memory allocation failure"),
                       node->name);
        return NULL;
    }

    return ret;
}


static int
virXMLPropEnumInternal(xmlNodePtr node,
                       const char *name,
                       int (*strToInt)(const char *),
                       virXMLPropFlags flags,
                       unsigned int *result,
                       unsigned int defaultResult)

{
    g_autofree char *tmp = NULL;
    int ret;

    *result = defaultResult;

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    ret = strToInt(tmp);
    if (ret < 0 ||
        ((flags & VIR_XML_PROP_NONZERO) && (ret == 0))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'."),
                       name, node->name, NULLSTR(tmp));
        return -1;
    }

    *result = ret;
    return 1;
}


/**
 * virXMLPropTristateBool:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 *
 * Convenience function to return value of a yes / no attribute.
 * In case when the property is missing @result is initialized to
 * VIR_TRISTATE_BOOL_ABSENT.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropTristateBool(xmlNodePtr node,
                       const char *name,
                       virXMLPropFlags flags,
                       virTristateBool *result)
{
    flags |= VIR_XML_PROP_NONZERO;

    return virXMLPropEnumInternal(node, name, virTristateBoolTypeFromString,
                                  flags, result, VIR_TRISTATE_BOOL_ABSENT);
}


/* Same as virXMLPropTristateBoolAllowDefault, but will accept the
 * value 'default' and convert it to VIR_TRISTATE_BOOL_ABSENT instead
 * of rejecting it with an error. Should only be used for backwards
 * compatibility reasons, and specifically to parse XML files where a
 * property having value VIR_TRISTATE_BOOL_ABSENT has historically
 * resulted in it being formatted with value 'default' instead of
 * being omitted entirely */
int
virXMLPropTristateBoolAllowDefault(xmlNodePtr node,
                                   const char *name,
                                   virXMLPropFlags flags,
                                   virTristateBool *result)
{
    return virXMLPropEnumInternal(node, name, virTristateBoolTypeFromString,
                                  flags, result, VIR_TRISTATE_BOOL_ABSENT);
}


/**
 * virXMLPropTristateSwitch:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 *
 * Convenience function to return value of an on / off attribute.
 * In case when the property is missing @result is initialized to
 * VIR_TRISTATE_SWITCH_ABSENT.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropTristateSwitch(xmlNodePtr node,
                         const char *name,
                         virXMLPropFlags flags,
                         virTristateSwitch *result)
{
    flags |= VIR_XML_PROP_NONZERO;

    return virXMLPropEnumInternal(node, name, virTristateSwitchTypeFromString,
                                  flags, result, VIR_TRISTATE_SWITCH_ABSENT);
}


/**
 * virXMLPropInt:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @base: Number base, see strtol
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 * @defaultResult: default value of @result in case the property is not found
 *
 * Convenience function to return value of an integer attribute.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropInt(xmlNodePtr node,
              const char *name,
              int base,
              virXMLPropFlags flags,
              int *result,
              int defaultResult)
{
    g_autofree char *tmp = NULL;
    int val;

    *result = defaultResult;

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    if (virStrToLong_i(tmp, NULL, base, &val) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected integer value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONNEGATIVE) && (val < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected non-negative value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONZERO) && (val == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': Zero is not permitted"),
                       name, node->name);
        return -1;
    }

    *result = val;
    return 1;
}


/**
 * virXMLPropUInt:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @base: Number base, see strtol
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 *
 * Convenience function to return value of an unsigned integer attribute.
 * @result is initialized to 0 on error or if the element is not found.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropUInt(xmlNodePtr node,
               const char *name,
               int base,
               virXMLPropFlags flags,
               unsigned int *result)
{
    return virXMLPropUIntDefault(node, name, base, flags, result, 0);
}


/**
 * virXMLPropUIntDefault:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @base: Number base, see strtol
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 * @defaultResult: Default value of @result in case the property is not found
 *
 * Convenience function to return value of an unsigned integer attribute.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropUIntDefault(xmlNodePtr node,
                      const char *name,
                      int base,
                      virXMLPropFlags flags,
                      unsigned int *result,
                      unsigned int defaultResult)
{
    g_autofree char *tmp = NULL;
    int ret;
    unsigned int val;

    *result = defaultResult;

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    ret = virStrToLong_uip(tmp, NULL, base, &val);

    if (ret < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected non-negative integer value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONZERO) && (val == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': Zero is not permitted"),
                       name, node->name);
        return -1;
    }

    *result = val;
    return 1;
}


/**
 * virXMLPropLongLong:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @base: Number base, see strtol
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 * @defaultResult: Default value of @result in case the property is not found
 *
 * Convenience function to return value of a long long attribute.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropLongLong(xmlNodePtr node,
                   const char *name,
                   int base,
                   virXMLPropFlags flags,
                   long long *result,
                   long long defaultResult)
{
    g_autofree char *tmp = NULL;
    long long val;

    *result = defaultResult;

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    if (virStrToLong_ll(tmp, NULL, base, &val) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected long long integer value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONNEGATIVE) && (val < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected non-negative value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONZERO) && (val == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': Zero is not permitted"),
                       name, node->name);
        return -1;
    }

    *result = val;
    return 1;
}


/**
 * virXMLPropULongLong:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @base: Number base, see strtol
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 *
 * Convenience function to return value of an unsigned long long attribute.
 * @result is initialized to 0 on error or if the element is not found.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropULongLong(xmlNodePtr node,
                    const char *name,
                    int base,
                    virXMLPropFlags flags,
                    unsigned long long *result)
{
    g_autofree char *tmp = NULL;
    int ret;
    unsigned long long val;

    *result = 0;

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    ret = virStrToLong_ullp(tmp, NULL, base, &val);

    if (ret < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected non-negative integer value"),
                       name, node->name, tmp);
        return -1;
    }

    if ((flags & VIR_XML_PROP_NONZERO) && (val == 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': Zero is not permitted"),
                       name, node->name);
        return -1;
    }

    *result = val;
    return 1;
}


/**
 * virXMLPropEnumDefault:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @strToInt: Conversion function to turn enum name to value. Expected to
 *            return negative value on failure.
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 * @defaultResult: default value set to @result in case the property is missing
 *
 * Convenience function to return value of an enum attribute.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropEnumDefault(xmlNodePtr node,
                      const char *name,
                      int (*strToInt)(const char*),
                      virXMLPropFlags flags,
                      unsigned int *result,
                      unsigned int defaultResult)
{
    return virXMLPropEnumInternal(node, name, strToInt, flags, result, defaultResult);
}


/**
 * virXMLPropUUID:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: Array of VIR_UUID_BUFLEN bytes to store the raw UUID
 *
 * Convenience function to fetch an XML property as a UUID.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropUUID(xmlNodePtr node,
               const char *name,
               virXMLPropFlags flags,
               unsigned char *result)
{
    g_autofree char *tmp = NULL;
    unsigned char val[VIR_UUID_BUFLEN];

    if (!(tmp = virXMLPropString(node, name))) {
        if (!(flags & VIR_XML_PROP_REQUIRED))
            return 0;

        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required attribute '%1$s' in element '%2$s'"),
                       name, node->name);
        return -1;
    }

    if (virUUIDParse(tmp, val) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value for attribute '%1$s' in element '%2$s': '%3$s'. Expected UUID"),
                       name, node->name, tmp);
        return -1;
    }

    memcpy(result, val, VIR_UUID_BUFLEN);
    return 1;
}


/**
 * virXMLPropEnum:
 * @node: XML dom node pointer
 * @name: Name of the property (attribute) to get
 * @strToInt: Conversion function to turn enum name to value. Expected to
 *            return negative value on failure.
 * @flags: Bitwise-OR of virXMLPropFlags
 * @result: The returned value
 *
 * Convenience function to return value of an enum attribute.
 * @result is initialized to 0 on error or if the element is not found.
 *
 * Returns 1 in case of success in which case @result is set,
 *         or 0 if the attribute is not present,
 *         or -1 and reports an error on failure.
 */
int
virXMLPropEnum(xmlNodePtr node,
               const char *name,
               int (*strToInt)(const char*),
               virXMLPropFlags flags,
               unsigned int *result)
{
    return virXMLPropEnumInternal(node, name, strToInt, flags, result, 0);
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
    g_autoptr(xmlXPathObject) obj = NULL;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter"));
        return -1;
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_BOOLEAN) ||
        (obj->boolval < 0) || (obj->boolval > 1)) {
        return -1;
    }
    return obj->boolval;
}


/**
 * virXMLNodeGetSubelement:
 * @node: node to get subelement of
 * @name: name of subelement to fetch
 *
 * Find and return a sub-element node of @node named @name.
 */
xmlNodePtr
virXMLNodeGetSubelement(xmlNodePtr node,
                        const char *name)
{
    xmlNodePtr n;

    for (n = node->children; n; n = n->next) {
        if (n->type == XML_ELEMENT_NODE &&
            virXMLNodeNameEqual(n, name))
            return n;
    }

    return NULL;
}


/**
 * virXMLNodeGetSubelementList:
 * @node: node to get subelement of
 * @name: name of subelement to fetch (NULL to fetch all sub-elements)
 * @list: If non-NULL, filled with a list of pointers to the nodes. Caller is
 *        responsible for freeing the list but not the members.
 *
 * Find and return a sub-elements node of @node named @name in a list.
 * Returns the number of subelements with @name
 */
size_t
virXMLNodeGetSubelementList(xmlNodePtr node,
                            const char *name,
                            xmlNodePtr **list)
{
    xmlNodePtr n;
    size_t nelems = 0;

    for (n = node->children; n; n = n->next) {
        if (n->type == XML_ELEMENT_NODE) {
            if (name && !virXMLNodeNameEqual(n, name))
                continue;

            if (list)
                VIR_APPEND_ELEMENT_COPY(*list, nelems, n);
            else
                nelems++;
        }
    }

    return nelems;
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
    g_autoptr(xmlXPathObject) obj = NULL;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter"));
        return NULL;
    }
    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if ((obj == NULL) || (obj->type != XPATH_NODESET) ||
        (obj->nodesetval == NULL) || (obj->nodesetval->nodeNr <= 0) ||
        (obj->nodesetval->nodeTab == NULL)) {
        return NULL;
    }

    return obj->nodesetval->nodeTab[0];
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
    g_autoptr(xmlXPathObject) obj = NULL;
    int ret;

    if ((ctxt == NULL) || (xpath == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Invalid parameter"));
        return -1;
    }

    if (list != NULL)
        *list = NULL;

    obj = xmlXPathEval(BAD_CAST xpath, ctxt);
    if (obj == NULL)
        return 0;

    if (obj->type != XPATH_NODESET) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Incorrect xpath '%1$s'"), xpath);
        return -1;
    }

    if ((obj->nodesetval == NULL)  || (obj->nodesetval->nodeNr < 0))
        return 0;

    ret = obj->nodesetval->nodeNr;
    if (list != NULL && ret) {
        *list = g_new0(xmlNodePtr, ret);
        memcpy(*list, obj->nodesetval->nodeTab, ret * sizeof(xmlNodePtr));
    }
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
catchXMLError(void *ctx, const char *msg G_GNUC_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    const xmlChar *cur, *base;
    unsigned int n, col;        /* GCC warns if signed, because compared with sizeof() */
    int domcode = VIR_FROM_XML;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *contextstr = NULL;
    g_autofree char *pointerstr = NULL;


    /* conditions for error printing */
    if (!ctxt ||
        (virGetLastErrorCode()) ||
        ctxt->input == NULL ||
        ctxt->lastError.level != XML_ERR_FATAL ||
        ctxt->lastError.message == NULL)
        return;

    if (ctxt->_private)
        domcode = ((struct virParserData *) ctxt->_private)->domcode;


    cur = ctxt->input->cur;
    base = ctxt->input->base;

    /* skip backwards over any end-of-lines */
    while ((cur > base) && ((*(cur) == '\n') || (*(cur) == '\r')))
        cur--;

    /* search backwards for beginning-of-line (to max buff size) */
    while ((cur > base) && (*(cur) != '\n') && (*(cur) != '\r'))
        cur--;
    if ((*(cur) == '\n') || (*(cur) == '\r')) cur++;

    /* calculate the error position in terms of the current position */
    col = ctxt->input->cur - cur;

    /* search forward for end-of-line (to max buff size) */
    /* copy selected text to our buffer */
    while ((*cur != 0) && (*(cur) != '\n') && (*(cur) != '\r'))
        virBufferAddChar(&buf, *cur++);

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
                              _("%1$s:%2$d: %3$s%4$s\n%5$s"),
                              ctxt->lastError.file,
                              ctxt->lastError.line,
                              ctxt->lastError.message,
                              contextstr,
                              pointerstr);
    } else {
        virGenericReportError(domcode, VIR_ERR_XML_DETAIL,
                              _("at line %1$d: %2$s%3$s\n%4$s"),
                              ctxt->lastError.line,
                              ctxt->lastError.message,
                              contextstr,
                              pointerstr);
    }
}


/**
 * virXMLParseHelper:
 * @domcode: error domain of the caller, usually VIR_FROM_THIS
 * @filename: file to be parsed or NULL if string parsing is requested
 * @xmlStr: XML string to be parsed in case filename is NULL
 * @url: URL of XML document for string parser
 * @rootelement: Optional name of the expected root element
 * @ctxt: optional pointer to populate with new context pointer
 * @schemafile: optional name of the file the parsed XML will be validated against
 * @validate: if true, the XML will be validated against schema in @schemafile
 *
 * Parse XML document provided either as a file or a string. The function
 * guarantees that the XML document contains a root element.
 *
 * If @rootelement is not NULL, the name of the root element of the parsed XML
 * is vaidated against
 *
 * Returns parsed XML document.
 */
xmlDocPtr
virXMLParseHelper(int domcode,
                  const char *filename,
                  const char *xmlStr,
                  const char *url,
                  const char *rootelement,
                  xmlXPathContextPtr *ctxt,
                  const char *schemafile,
                  bool validate)
{
    struct virParserData private;
    g_autoptr(xmlParserCtxt) pctxt = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    xmlNodePtr rootnode;
    const char *docname;

    if (filename)
        docname = filename;
    else if (url)
        docname = url;
    else
        docname = "[inline data]";

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt();
    if (!pctxt || !pctxt->sax)
        abort();

    private.domcode = domcode;
    pctxt->_private = &private;
    pctxt->sax->error = catchXMLError;

    if (filename) {
        xml = xmlCtxtReadFile(pctxt, filename, NULL,
                              XML_PARSE_NONET |
                              XML_PARSE_NOWARNING);
    } else {
        xml = xmlCtxtReadDoc(pctxt, BAD_CAST xmlStr, url, NULL,
                             XML_PARSE_NONET |
                             XML_PARSE_NOWARNING);
    }

    if (!xml) {
        if (virGetLastErrorCode() == VIR_ERR_OK) {
            virGenericReportError(domcode, VIR_ERR_XML_ERROR,
                                  _("failed to parse xml document '%1$s'"),
                                  docname);
        }

        return NULL;
    }

    if (!(rootnode = xmlDocGetRootElement(xml))) {
        virGenericReportError(domcode, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));

        return NULL;
    }

    if (rootelement &&
        !virXMLNodeNameEqual(rootnode, rootelement)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("expecting root element of '%1$s', not '%2$s'"),
                       rootelement, rootnode->name);
        return NULL;
    }

    if (ctxt) {
        if (!(*ctxt = virXMLXPathContextNew(xml)))
            return NULL;

        (*ctxt)->node = rootnode;
    }

    if (validate && schemafile != NULL) {
        g_autofree char *schema = virFileFindResource(schemafile,
                                                      abs_top_srcdir "/src/conf/schemas",
                                                      PKGDATADIR "/schemas");
        if (!schema ||
            (virXMLValidateAgainstSchema(schema, xml) < 0))
            return NULL;
    }

    return g_steal_pointer(&xml);
}


const char *
virXMLPickShellSafeComment(const char *str1,
                           const char *str2)
{
    if (str1 && !strpbrk(str1, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~") &&
        !strstr(str1, "--"))
        return str1;
    if (str2 && !strpbrk(str2, "\r\t\n !\"#$&'()*;<>?[\\]^`{|}~") &&
        !strstr(str2, "--"))
        return str2;
    return NULL;
}


static int
virXMLEmitWarning(int fd,
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
virXMLRewriteFile(int fd,
                  const char *path,
                  const void *opaque)
{
    const struct virXMLRewriteFileData *data = opaque;

    if (data->warnCommand &&
        virXMLEmitWarning(fd, data->warnName, data->warnCommand) < 0) {
        virReportSystemError(errno,
                             _("cannot write data to file '%1$s'"),
                             path);
        return -1;
    }

    if (safewrite(fd, data->xml, strlen(data->xml)) < 0) {
        virReportSystemError(errno,
                             _("cannot write data to file '%1$s'"),
                             path);
        return -1;
    }

    return 0;
}


int
virXMLSaveFile(const char *path,
               const char *warnName,
               const char *warnCommand,
               const char *xml)
{
    struct virXMLRewriteFileData data = { warnName, warnCommand, xml };

    return virFileRewrite(path, S_IRUSR | S_IWUSR, -1, -1,
                          virXMLRewriteFile, &data);
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
    g_autoptr(xmlBuffer) xmlbuf = virXMLBufferCreate();

    if (xmlNodeDump(xmlbuf, doc, node, 0, 1) == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to convert the XML node tree"));
        return NULL;
    }

    return g_strdup((const char *)xmlBufferContent(xmlbuf));
}


/**
 * virXMLNodeNameEqual:
 * @node: xml Node pointer to check
 * @name: name of the @node
 *
 * Compares the @node name with @name.
 */
bool
virXMLNodeNameEqual(xmlNodePtr node,
                    const char *name)
{
    return xmlStrEqual(node->name, BAD_CAST name);
}


typedef int (*virXMLForeachCallback)(xmlNodePtr node,
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

    if (!root)
        return NULL;

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

    if (xmlValidateNCName((const unsigned char *)key, 1) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to validate prefix for a new XML namespace"));
        return -1;
    }

    if (!(ns = xmlNewNs(node, (const unsigned char *)uri, (const unsigned char *)key))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create a new XML namespace"));
        return -1;
    }

    virXMLForeachNode(node, virXMLAddElementNamespace, ns);

    return 0;
}

/**
 * virXMLNodeSanitizeNamespaces()
 * @node: Sanitize the namespaces for this node
 *
 * This function removes subnodes in node that share the namespace.
 * The first instance of every duplicate namespace is kept.
 * Additionally nodes with no namespace are deleted.
 */
void
virXMLNodeSanitizeNamespaces(xmlNodePtr node)
{
    xmlNodePtr child;
    xmlNodePtr next;
    xmlNodePtr dupl;

    if (!node)
        return;

    child = node->children;
    while (child) {
        /* remove subelements that don't have any namespace at all */
        if (!child->ns || !child->ns->href) {
            dupl = child;
            child = child->next;

            xmlUnlinkNode(dupl);
            xmlFreeNode(dupl);
            continue;
        }

        /* check that every other child of @root doesn't share the namespace of
         * the current one and delete them possibly */
        next = child->next;
        while (next) {
            dupl = NULL;

            if (child->ns && next->ns &&
                STREQ_NULLABLE((const char *) child->ns->href,
                               (const char *) next->ns->href))
                dupl = next;

            next = next->next;
            if (dupl) {
                xmlUnlinkNode(dupl);
                xmlFreeNode(dupl);
            }
        }
        child = child->next;
    }
}


static void
virXMLValidatorRNGErrorCatch(void *ctx,
                             const char *msg,
                             ...)
{
    virBuffer *buf = ctx;
    va_list args;

    va_start(args, msg);
    VIR_WARNINGS_NO_PRINTF;
    virBufferVasprintf(buf, msg, args);
    VIR_WARNINGS_RESET;
    va_end(args);
}


static void
virXMLValidatorRNGErrorIgnore(void *ctx G_GNUC_UNUSED,
                              const char *msg G_GNUC_UNUSED,
                              ...)
{}


virXMLValidator *
virXMLValidatorInit(const char *schemafile)
{
    g_autoptr(virXMLValidator) validator = NULL;

    validator = g_new0(virXMLValidator, 1);

    validator->schemafile = g_strdup(schemafile);

    if (!(validator->rngParser =
          xmlRelaxNGNewParserCtxt(validator->schemafile))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to create RelaxNG parser for schema '%1$s'"),
                       validator->schemafile);
        return NULL;
    }

    xmlRelaxNGSetParserErrors(validator->rngParser,
                              virXMLValidatorRNGErrorCatch,
                              virXMLValidatorRNGErrorIgnore,
                              &validator->buf);

    if (!(validator->rng = xmlRelaxNGParse(validator->rngParser))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse RelaxNG schema '%1$s': %2$s"),
                       validator->schemafile,
                       virBufferCurrentContent(&validator->buf));
        return NULL;
    }

    if (!(validator->rngValid = xmlRelaxNGNewValidCtxt(validator->rng))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to create RelaxNG validation context for schema '%1$s'"),
                       validator->schemafile);
        return NULL;
    }

    xmlRelaxNGSetValidErrors(validator->rngValid,
                             virXMLValidatorRNGErrorCatch,
                             virXMLValidatorRNGErrorIgnore,
                             &validator->buf);

    return g_steal_pointer(&validator);
}


int
virXMLValidatorValidate(virXMLValidator *validator,
                        xmlDocPtr doc)
{
    if (xmlRelaxNGValidateDoc(validator->rngValid, doc) != 0) {
        virReportError(VIR_ERR_XML_INVALID_SCHEMA,
                       _("Unable to validate doc against %1$s\n%2$s"),
                       validator->schemafile,
                       virBufferCurrentContent(&validator->buf));
        return -1;
    }

    return 0;
}


int
virXMLValidateAgainstSchema(const char *schemafile,
                            xmlDocPtr doc)
{
    g_autoptr(virXMLValidator) validator = NULL;

    if (!(validator = virXMLValidatorInit(schemafile)))
        return -1;

    if (virXMLValidatorValidate(validator, doc) < 0)
        return -1;

    return 0;
}


int
virXMLValidateNodeAgainstSchema(const char *schemafile, xmlNodePtr node)
{
    int ret;
    g_autoptr(xmlDoc) copy = xmlNewDoc(NULL);

    xmlDocSetRootElement(copy, xmlCopyNode(node, true));
    ret = virXMLValidateAgainstSchema(schemafile, copy);

    return ret;
}


void
virXMLValidatorFree(virXMLValidator *validator)
{
    if (!validator)
        return;

    g_free(validator->schemafile);
    virBufferFreeAndReset(&validator->buf);
    xmlRelaxNGFreeParserCtxt(validator->rngParser);
    xmlRelaxNGFreeValidCtxt(validator->rngValid);
    xmlRelaxNGFree(validator->rng);
    g_free(validator);
}


/**
 * virXMLFormatElementInternal
 * @buf: the parent buffer where the element will be placed
 * @name: the name of the element
 * @attrBuf: buffer with attributes for element, may be NULL
 * @childBuf: buffer with child elements, may be NULL
 * @allowEmpty: Format empty element if @attrBuf and @childBuf are empty
 * @childNewline: Add a newline after the opening element before formatting @childBuf
 *
 * Helper to format element where attributes or child elements
 * are optional and may not be formatted.  If both @attrBuf and
 * @childBuf are NULL or are empty buffers the element is not
 * formatted.
 *
 * Passing false for @childNewline allows to format elements where we directly
 * output a value without subelements.
 *
 * Both passed buffers are always consumed and freed.
 */
void
virXMLFormatElementInternal(virBuffer *buf,
                            const char *name,
                            virBuffer *attrBuf,
                            virBuffer *childBuf,
                            bool allowEmpty,
                            bool childNewline)
{
    if (!allowEmpty) {
        if ((!attrBuf || virBufferUse(attrBuf) == 0) &&
            (!childBuf || virBufferUse(childBuf) == 0))
            return;
    }

    virBufferAsprintf(buf, "<%s", name);

    if (attrBuf && virBufferUse(attrBuf) > 0)
        virBufferAddBuffer(buf, attrBuf);

    if (childBuf && virBufferUse(childBuf) > 0) {
        virBufferAddLit(buf, ">");
        if (childNewline)
            virBufferAddLit(buf, "\n");
        virBufferAddBuffer(buf, childBuf);
        virBufferAsprintf(buf, "</%s>\n", name);
    } else {
        virBufferAddLit(buf, "/>\n");
    }

    virBufferFreeAndReset(attrBuf);
    virBufferFreeAndReset(childBuf);
}


/* same as virXMLFormatElement but outputs an empty element if @attrBuf and
 * @childBuf are both empty */
void
virXMLFormatElementEmpty(virBuffer *buf,
                         const char *name,
                         virBuffer *attrBuf,
                         virBuffer *childBuf)
{
    virXMLFormatElementInternal(buf, name, attrBuf, childBuf, true, true);
}


/**
 * virXMLFormatElement
 * @buf: the parent buffer where the element will be placed
 * @name: the name of the element
 * @attrBuf: buffer with attributes for element, may be NULL
 * @childBuf: buffer with child elements, may be NULL
 *
 * Helper to format element where attributes or child elements
 * are optional and may not be formatted.  If both @attrBuf and
 * @childBuf are NULL or are empty buffers the element is not
 * formatted.
 *
 * Both passed buffers are always consumed and freed.
 */
void
virXMLFormatElement(virBuffer *buf,
                    const char *name,
                    virBuffer *attrBuf,
                    virBuffer *childBuf)
{
    virXMLFormatElementInternal(buf, name, attrBuf, childBuf, false, true);
}


/**
 * virXMLFormatMetadata:
 * @buf: the parent buffer where the element will be placed
 * @metadata: pointer to metadata node
 *
 * Helper to format metadata element. If @metadata is NULL then
 * this function is a NOP.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
virXMLFormatMetadata(virBuffer *buf,
                     xmlNodePtr metadata)
{
    g_autoptr(xmlBuffer) xmlbuf = NULL;
    const char *xmlbufContent = NULL;
    int oldIndentTreeOutput = xmlIndentTreeOutput;

    if (!metadata)
        return 0;

    /* Indentation on output requires that we previously set
     * xmlKeepBlanksDefault to 0 when parsing; also, libxml does 2
     * spaces per level of indentation of intermediate elements,
     * but no leading indentation before the starting element.
     * Thankfully, libxml maps what looks like globals into
     * thread-local uses, so we are thread-safe.  */
    xmlIndentTreeOutput = 1;
    xmlbuf = virXMLBufferCreate();

    if (xmlNodeDump(xmlbuf, metadata->doc, metadata,
                    virBufferGetIndent(buf) / 2, 1) < 0) {
        xmlIndentTreeOutput = oldIndentTreeOutput;
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to format metadata element"));
        return -1;
    }

    /* After libxml2-v2.9.12-2-g85b1792e even the first line is indented.
     * But virBufferAsprintf() also adds indentation. Skip one of them. */
    xmlbufContent = (const char *) xmlBufferContent(xmlbuf);
    virSkipSpaces(&xmlbufContent);

    virBufferAsprintf(buf, "%s\n", xmlbufContent);
    xmlIndentTreeOutput = oldIndentTreeOutput;

    return 0;
}


void
virXPathContextNodeRestore(virXPathContextNodeSave *save)
{
    if (!save->ctxt)
        return;

    save->ctxt->node = save->node;
}


void
virXMLNamespaceFormatNS(virBuffer *buf,
                        virXMLNamespace const *ns)
{
    virBufferAsprintf(buf, " xmlns:%s='%s'", ns->prefix, ns->uri);
}


int
virXMLNamespaceRegister(xmlXPathContextPtr ctxt,
                        virXMLNamespace const *ns)
{
    if (xmlXPathRegisterNs(ctxt,
                           BAD_CAST ns->prefix,
                           BAD_CAST ns->uri) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to register xml namespace '%1$s'"),
                       ns->uri);
        return -1;
    }

    return 0;
}


/**
 * virParseScaledValue:
 * @xpath: XPath to memory amount
 * @units_xpath: XPath to units attribute
 * @ctxt: XPath context
 * @val: scaled value is stored here
 * @scale: default scale for @val
 * @max: maximal @val allowed
 * @required: is the value required?
 *
 * Parse a value located at @xpath within @ctxt, and store the
 * result into @val. The value is scaled by units located at
 * @units_xpath (or the 'unit' attribute under @xpath if
 * @units_xpath is NULL). If units are not present, the default
 * @scale is used. If @required is set, then the value must
 * exist; otherwise, the value is optional. The resulting value
 * is in bytes.
 *
 * Returns 1 on success,
 *         0 if the value was not present and !@required,
 *         -1 on failure after issuing error.
 */
int
virParseScaledValue(const char *xpath,
                    const char *units_xpath,
                    xmlXPathContextPtr ctxt,
                    unsigned long long *val,
                    unsigned long long scale,
                    unsigned long long max,
                    bool required)
{
    unsigned long long bytes;
    g_autofree char *xpath_full = NULL;
    g_autofree char *unit = NULL;
    g_autofree char *bytes_str = NULL;

    *val = 0;
    xpath_full = g_strdup_printf("string(%s)", xpath);

    bytes_str = virXPathString(xpath_full, ctxt);
    if (!bytes_str) {
        if (!required)
            return 0;
        virReportError(VIR_ERR_XML_ERROR,
                       _("missing element or attribute '%1$s'"),
                       xpath);
        return -1;
    }
    VIR_FREE(xpath_full);

    if (virStrToLong_ullp(bytes_str, NULL, 10, &bytes) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid value '%1$s' for element or attribute '%2$s'"),
                       bytes_str, xpath);
        return -1;
    }

    if (units_xpath)
         xpath_full = g_strdup_printf("string(%s)", units_xpath);
    else
         xpath_full = g_strdup_printf("string(%s/@unit)", xpath);
    unit = virXPathString(xpath_full, ctxt);

    if (virScaleInteger(&bytes, unit, scale, max) < 0)
        return -1;

    *val = bytes;
    return 1;
}


xmlBufferPtr
virXMLBufferCreate(void)
{
    xmlBufferPtr ret;

    if (!(ret = xmlBufferCreate()))
        abort();

    return ret;
}


xmlNodePtr
virXMLNewNode(xmlNsPtr ns,
              const char *name)
{
    xmlNodePtr ret;

    if (!(ret = xmlNewNode(ns, BAD_CAST name)))
        abort();

    return ret;
}
