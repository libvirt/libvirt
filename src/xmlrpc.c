/*
 * xmlrpc.c: XML-RPC protocol handler for libvir library
 *
 * Copyright (C) 2006  IBM, Corp.
 *
 * See COPYING.LIB for the License of this software
 *
 * Anthony Liguori <aliguori@us.ibm.com>
 */

#include "xmlrpc.h"
#include "internal.h"

#include <libxml/nanohttp.h>

#include <string.h>
#include <errno.h>

/* TODO
   1) Lots of error checking
   2) xmlRpcValueToSexpr
*/

static xmlNodePtr xmlFirstElement(xmlNodePtr node);
static xmlNodePtr xmlNextElement(xmlNodePtr node);

struct _xmlRpcContext
{
    char *uri;
    int faultCode;
    char *faultMessage;
};

static void xmlRpcError(virErrorNumber error, const char *info, int value)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(NULL, NULL, VIR_FROM_RPC, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, value, 0, errmsg, info, value);
}

static xmlRpcValuePtr xmlRpcValueNew(xmlRpcValueType type)
{
    xmlRpcValuePtr ret = malloc(sizeof(*ret));
    
    if (!ret)
        xmlRpcError(VIR_ERR_NO_MEMORY, "allocate value", sizeof(*ret));
    else
        ret->kind = type;
    return ret;
}

static char *xmlGetText(xmlNodePtr node)
{
    for (node = node->children; node; node = node->next)
	if (node->type == XML_TEXT_NODE) {
	    char *x = strdup((const char *)node->content);
	    if (!x)
                xmlRpcError(VIR_ERR_NO_MEMORY, _("copying node content"),
                            strlen((const char *)node->content));
	    return x;
	}
    return NULL;
}

static xmlNodePtr xmlFirstElement(xmlNodePtr node)
{
    for (node = node->children; node; node = node->next)
	if (node->type == XML_ELEMENT_NODE)
	    break;
    return node;
}

static xmlNodePtr xmlNextElement(xmlNodePtr node)
{
    for (node = node->next; node; node = node->next)
	if (node->type == XML_ELEMENT_NODE)
	    break;
    return node;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalDateTime(xmlNodePtr node ATTRIBUTE_UNUSED)
{
    /* we don't need this */
    TODO
    return NULL;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalString(xmlNodePtr node)
{
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_STRING);
    
    if (ret)
        ret->value.string = xmlGetText(node);
    return ret;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalBase64(xmlNodePtr node ATTRIBUTE_UNUSED)
{
    /* we don't need this */
    TODO
    return NULL;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalInteger(xmlNodePtr node)
{
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_INTEGER);
    char *value = xmlGetText(node);
    
    if (ret && value)
        ret->value.integer = atoi(value);
    if (value)
        free(value);
    return ret;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalBoolean(xmlNodePtr node)
{
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_BOOLEAN);
    char *value = xmlGetText(node);

    if (!ret)
        return NULL;
    if (value && atoi(value))
	ret->value.boolean = true;
    else
	ret->value.boolean = false;
    if (value)
        free(value);
    return ret;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalDouble(xmlNodePtr node)
{
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_DOUBLE);
    char *value = xmlGetText(node);

    if (ret && value)
        ret->value.real = atof(value);
    if (value)
        free(value);
    return ret;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalArray(xmlNodePtr node)
{
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_ARRAY);
    xmlNodePtr cur;
    int n_elements = 0;

    if (!ret)
        return NULL;

    for (cur = xmlFirstElement(node); cur; cur = xmlNextElement(cur))
	n_elements += 1;

    ret->value.array.elements = malloc(n_elements * sizeof(xmlRpcValue));
    if (!ret->value.array.elements) {
        xmlRpcError(VIR_ERR_NO_MEMORY, _("allocate value array"),
                    n_elements * sizeof(xmlRpcValue));
	free(ret);
	return NULL;
    }
    n_elements = 0;
    for (cur = xmlFirstElement(node); cur; cur = xmlNextElement(cur)) {
	ret->value.array.elements[n_elements] = xmlRpcValueUnmarshal(cur);
	n_elements += 1;
    }

    ret->value.array.n_elements = n_elements;

    return ret;
}

static xmlRpcValueDictElementPtr xmlRpcValueUnmarshalDictElement(xmlNodePtr node)
{
    xmlRpcValueDictElementPtr ret = malloc(sizeof(*ret));
    xmlNodePtr cur;

    if (!ret) {
        xmlRpcError(VIR_ERR_NO_MEMORY, "allocate dict", sizeof(*ret));
	return NULL;
    }
    memset(ret, 0, sizeof(*ret));

    for (cur = xmlFirstElement(node); cur; cur = xmlNextElement(cur)) {
	if (xmlStrEqual(cur->name, BAD_CAST "name")) {
	    ret->name = xmlGetText(cur);
	} else if (xmlStrEqual(cur->name, BAD_CAST "value")) {
	    ret->value = xmlRpcValueUnmarshal(cur);
	} else {
            xmlRpcError(VIR_ERR_XML_ERROR, _("unexpected dict node"), 0);
	    if (ret->name)
		free(ret->name);
	    if (ret->value)
		xmlRpcValueFree(ret->value);
	    free(ret);
	    return NULL;
	}
    }

    ret->next = NULL;

    return ret;
}

static xmlRpcValuePtr xmlRpcValueUnmarshalDict(xmlNodePtr node)
{
    xmlRpcValueDictElementPtr root = NULL, *elem = &root;
    xmlRpcValuePtr ret = xmlRpcValueNew(XML_RPC_STRUCT);
    xmlNodePtr cur;

    if (!ret)
	return NULL;
    
    ret->value.dict.root = root;
    
    for (cur = xmlFirstElement(node); cur; cur = xmlNextElement(cur)) {
	*elem = xmlRpcValueUnmarshalDictElement(cur);
	if (*elem==NULL) {
	    xmlRpcValueFree(ret);
	    return NULL;
	} 
	elem = &(*elem)->next;
    }

    return ret;
}

xmlRpcValuePtr xmlRpcValueUnmarshal(xmlNodePtr node)
{
    xmlNodePtr n;
    xmlRpcValuePtr ret = NULL;

    if (xmlStrEqual(node->name, BAD_CAST "value")) {
	n = xmlFirstElement(node);
	if (n == NULL) {
	    ret = xmlRpcValueUnmarshalString(node);
	} else {
	    ret = xmlRpcValueUnmarshal(n);
	}
    } else if (xmlStrEqual(node->name, BAD_CAST "dateTime.iso8601")) {
	ret = xmlRpcValueUnmarshalDateTime(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "string")) {
	ret = xmlRpcValueUnmarshalString(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "base64")) {
	ret = xmlRpcValueUnmarshalBase64(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "i4") ||
	       xmlStrEqual(node->name, BAD_CAST "int")) {
	ret = xmlRpcValueUnmarshalInteger(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "boolean")) {
	ret = xmlRpcValueUnmarshalBoolean(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "double")) {
	ret = xmlRpcValueUnmarshalDouble(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "array")) {
	ret = xmlRpcValueUnmarshal(xmlFirstElement(node));
    } else if (xmlStrEqual(node->name, BAD_CAST "data")) {
	ret = xmlRpcValueUnmarshalArray(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "struct")) {
	ret = xmlRpcValueUnmarshalDict(node);
    } else if (xmlStrEqual(node->name, BAD_CAST "nil")) {
	ret = xmlRpcValueNew(XML_RPC_NIL);
    } else {
        xmlRpcError(VIR_ERR_XML_ERROR, _("unexpected value node"), 0);
    }

    return ret;
}

void xmlRpcValueFree(xmlRpcValuePtr value)
{
    int i;
    xmlRpcValueDictElementPtr cur, next;

    if (value == NULL)
	return;

    switch (value->kind) {
    case XML_RPC_ARRAY:
	for (i = 0; i < value->value.array.n_elements; i++)
	    xmlRpcValueFree(value->value.array.elements[i]);
	free(value->value.array.elements);
	break;
    case XML_RPC_STRUCT:
	next = value->value.dict.root;
	while (next) {
	    cur = next;
	    next = next->next;
	    free(cur->name);
	    xmlRpcValueFree(cur->value);
	    free(cur);
	}
	break;
    case XML_RPC_STRING:
	free(value->value.string);
	break;
    default:
	break;
    }

    free(value);
}

void xmlRpcValueMarshal(xmlRpcValuePtr value, virBufferPtr buf, int indent)
{
    int i;
    xmlRpcValueDictElement *elem;

    virBufferVSprintf(buf, "%*s<value>", indent, "");
    switch (value->kind) {
    case XML_RPC_ARRAY:
	virBufferStrcat(buf, "<array><data>\n", NULL);
	for (i = 0; i < value->value.array.n_elements; i++)
	    xmlRpcValueMarshal(value->value.array.elements[i], buf, indent+2);
	virBufferVSprintf(buf, "%*s</data></array>", indent, "");
	break;
    case XML_RPC_STRUCT:
	virBufferStrcat(buf, "<struct>\n", NULL);
	indent += 2;
	for (elem = value->value.dict.root; elem; elem = elem->next) {
	    virBufferVSprintf(buf, "%*s<member>\n", indent, "");
	    virBufferVSprintf(buf, "%*s<name>%s</name>\n",
			      indent + 2, "", elem->name);
	    xmlRpcValueMarshal(elem->value, buf, indent + 2);
	    virBufferVSprintf(buf, "%*s</member>\n", indent, "");
	}
	indent -= 2;
	virBufferVSprintf(buf, "%*s</struct>", indent, "");
	break;
    case XML_RPC_INTEGER:
	virBufferVSprintf(buf, "<int>%d</int>", value->value.integer);
	break;
    case XML_RPC_DOUBLE:
	virBufferVSprintf(buf, "<double>%f</double>", value->value.real);
	break;
    case XML_RPC_BOOLEAN:
	if (value->value.boolean)
	    i = 1;
	else
	    i = 0;
	virBufferVSprintf(buf, "<boolean>%d</boolean>", i);
	break;
    case XML_RPC_DATE_TIME:
	/* FIXME */
	TODO
	break;
    case XML_RPC_BASE64:
	/* FIXME */
	TODO
	break;
    case XML_RPC_STRING:
	virBufferStrcat(buf, 
		"<string>", value->value.string, "</string>", NULL);
	break;
    case XML_RPC_NIL:
	virBufferStrcat(buf, "<nil> </nil>", NULL);
	break;
    }
    virBufferStrcat(buf, "</value>\n", NULL);
}

virBufferPtr xmlRpcMarshalRequest(const char *request,
				  int argc, xmlRpcValuePtr *argv)
{
    virBufferPtr buf;
    int i;

    buf = virBufferNew(1024);

    virBufferStrcat(buf,
		    "<?xml version=\"1.0\"?>\n"
		    "<methodCall>\n"
		    "  <methodName>", request, "</methodName>\n"
		    "  <params>\n", NULL);
    for (i = 0; i < argc; i++) {
	virBufferStrcat(buf,  
                    "    <param>\n", NULL);
	xmlRpcValueMarshal(argv[i], buf, 6);
	virBufferStrcat(buf,  
                    "    </param>\n", NULL);
    }
    virBufferStrcat(buf,
                    "  </params>\n"
		    "</methodCall>\n", NULL);
    return buf;
}

xmlRpcValuePtr xmlRpcUnmarshalResponse(xmlNodePtr node, bool *is_fault)
{
    if (!node)
	return NULL;

    if (!xmlStrEqual(node->name, BAD_CAST "methodResponse"))
	return NULL;

    node = xmlFirstElement(node);
    if (xmlStrEqual(node->name, BAD_CAST "params")) {
	node = xmlFirstElement(node);

	if (!xmlStrEqual(node->name, BAD_CAST "param"))
	    return NULL;

	*is_fault = false;
	return xmlRpcValueUnmarshal(xmlFirstElement(node));
    } else if (xmlStrEqual(node->name, BAD_CAST "fault")) {
	*is_fault = true;
	return xmlRpcValueUnmarshal(xmlFirstElement(node));
    } else
	return NULL;
}

static char *xmlRpcCallRaw(const char *url, const char *request)
{
	void *cxt;
	char *contentType = (char *) "text/xml";
	int len, ret, serrno;
	char *response = NULL;

	cxt = xmlNanoHTTPMethod(url,
				"POST",
				request,
				&contentType,
				NULL,
				strlen(request));

	if (cxt == NULL) {
                xmlRpcError(VIR_ERR_POST_FAILED, _("send request"), 0);
		goto error;
	}

	if (contentType && strcmp(contentType, "text/xml") != 0) {
		errno = EINVAL;
		xmlRpcError(VIR_ERR_POST_FAILED, _("unexpected mime type"), 0);
		goto error;
	}

	len = xmlNanoHTTPContentLength(cxt);
	response = malloc(len + 1);
	if (response == NULL) {
		xmlRpcError(VIR_ERR_NO_MEMORY, _("allocate response"), len);
		goto error;
	}
	ret = xmlNanoHTTPRead(cxt, response, len);
	if (ret != len) {
		errno = EINVAL;
		free(response);
		response = NULL;
		xmlRpcError(VIR_ERR_POST_FAILED, _("read response"), 0);
	}

	response[len] = 0;

 error:
	serrno = errno;
	if (cxt) {
		xmlNanoHTTPClose(cxt);
		free(contentType);
	}
	errno = serrno;

	return response;
}

static char **xmlRpcStringArray(xmlRpcValuePtr value)
{
    char **ret, *ptr;
    int i;
    size_t size = 0;

    if (value->kind != XML_RPC_ARRAY)
	return NULL;

    size = sizeof(char *) * (value->value.array.n_elements + 1);

    for (i = 0; i < value->value.array.n_elements; i++)
	if (value->value.array.elements[i]->kind == XML_RPC_STRING)
	    size += strlen(value->value.array.elements[i]->value.string) + 1;

    if (!(ptr = malloc(size))) {
	xmlRpcError(VIR_ERR_NO_MEMORY, _("allocate string array"), size);
	return NULL;
    }
    ret = (char **)ptr;
    ptr += sizeof(char *) * (value->value.array.n_elements + 1);

    for (i = 0; i < value->value.array.n_elements; i++) {
	if (value->value.array.elements[i]->kind == XML_RPC_STRING) {
	    char *s = value->value.array.elements[i]->value.string;
	    strcpy(ptr, s);
	    ret[i] = ptr;
	    ptr += strlen(s) + 1;
	} else
	    ret[i] = (char *) "";
    }

    ret[i] = NULL;

    return ret;
}

xmlRpcValuePtr *
xmlRpcArgvNew(const char *fmt, va_list ap, int *argc)
{
    xmlRpcValuePtr *argv;
    const char *ptr;
    int i;
    
    *argc = strlen(fmt);
    if (!(argv = malloc(sizeof(*argv) * *argc))) {
        xmlRpcError(VIR_ERR_NO_MEMORY, _("read response"), sizeof(*argv) * *argc);
        return NULL;
    }
    i = 0;
    for (ptr = fmt; *ptr; ptr++) {
	switch (*ptr) {
	case 'i':
	    if ((argv[i] = xmlRpcValueNew(XML_RPC_INTEGER)))
		argv[i]->value.integer = va_arg(ap, int32_t);
	    break;
	case 'f':
	    if ((argv[i] = xmlRpcValueNew(XML_RPC_DOUBLE)))
		argv[i]->value.real = va_arg(ap, double);
	    break;
	case 'b':
	    if ((argv[i] = xmlRpcValueNew(XML_RPC_BOOLEAN)))
	        argv[i]->value.boolean = va_arg(ap, int);
	    break;
	case 's':
	    if ((argv[i] = xmlRpcValueNew(XML_RPC_STRING)))
  	        argv[i]->value.string = strdup(va_arg(ap, const char *));
	    break;
	default:
	    argv[i] = NULL;
	    break;
	}
	if (argv[i]==NULL) {
	    xmlRpcArgvFree(i, argv);
	    return NULL;
	}
	i++;
    }
    return argv;
}

void
xmlRpcArgvFree(int argc, xmlRpcValuePtr *argv)
{
    int i;
    if (!argv)
	return;
    for (i = 0; i < argc; i++)
	xmlRpcValueFree(argv[i]);

    free(argv);
}

int xmlRpcCall(xmlRpcContextPtr context, const char *method,
	       const char *retfmt, const char *fmt, ...)
{
    va_list ap;
    int argc;
    xmlRpcValuePtr *argv;
    virBufferPtr buf;
    char *ret;
    xmlDocPtr xml;
    xmlNodePtr node;
    bool fault;
    xmlRpcValuePtr value;
    void *retval = NULL;

    va_start(ap, fmt);
    
    if (retfmt && *retfmt)
	retval = va_arg(ap, void *);
 
    if (!(argv = xmlRpcArgvNew(fmt, ap, &argc)))
	return -1;
    
    va_end(ap);

    buf = xmlRpcMarshalRequest(method, argc, argv);

    xmlRpcArgvFree(argc, argv);
	
    if (!buf)
	return -1;
    
    ret = xmlRpcCallRaw(context->uri, buf->content);

    virBufferFree(buf);

    if (!ret)
	return -1;

    xml = xmlReadDoc((const xmlChar *)ret, "response.xml", NULL,
		     XML_PARSE_NOENT | XML_PARSE_NONET |
		     XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    free(ret);

    if (xml == NULL) {
	errno = EINVAL;
	xmlRpcError(VIR_ERR_XML_ERROR, _("parse server response failed"), 0);
	return -1;
    }

    node = xmlDocGetRootElement(xml);

    value = xmlRpcUnmarshalResponse(node, &fault);

    if (!fault) {
	switch (*retfmt) {
	case 'i':
	    if (value->kind == XML_RPC_INTEGER)
		*(int32_t *)retval = value->value.integer;
	    break;
	case 'b':
	    if (value->kind == XML_RPC_BOOLEAN)
		*(bool *)retval = value->value.boolean;
	    break;
	case 'f':
	    if (value->kind == XML_RPC_DOUBLE)
		*(double *)retval = value->value.real;
	    break;
	case 's':
	    if (value->kind == XML_RPC_STRING)
		*(char **)retval = strdup(value->value.string);
	    break;
	case 'S':
	    *(char ***)retval = xmlRpcStringArray(value);
	    break;
	case 'V':
	    *(xmlRpcValuePtr *)retval = value;
	    value = NULL;
	    break;
	default:
	    printf("not supported yet\n");
	    break;
	}
    }

    xmlFreeDoc(xml);

    if (fault) { 
	/* FIXME we need generic dict routines */
	/* FIXME we need faultMessage propagate to libvirt error API */
	context->faultCode = value->value.dict.root->value->value.integer;
	context->faultMessage = strdup(value->value.dict.root->next->value->value.string);
	xmlRpcValueFree(value);
	errno = EFAULT;
	return -1;
    }

    xmlRpcValueFree(value);

    return 0;
}

xmlRpcContextPtr xmlRpcContextNew(const char *uri)
{
    xmlRpcContextPtr ret = malloc(sizeof(*ret));

    if (ret) {
	ret->uri = strdup(uri);
	ret->faultMessage = NULL;
    } else
        xmlRpcError(VIR_ERR_NO_MEMORY, _("allocate new context"), sizeof(*ret));

    return ret;
}

void xmlRpcContextFree(xmlRpcContextPtr context)
{
    if (context) {
	if (context->uri)
	    free(context->uri);

	if (context->faultMessage)
	    free(context->faultMessage);

	free(context);
    }
}

int xmlRpcContextFaultCode(xmlRpcContextPtr context)
{
    return context->faultCode;
}

const char *xmlRpcContextFaultMessage(xmlRpcContextPtr context)
{
    return context->faultMessage;
}
