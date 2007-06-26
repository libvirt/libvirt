/*
 * xmlrpc.c: XML-RPC protocol handler for libvir library
 *
 * Copyright (C) 2006  IBM, Corp.
 *
 * See COPYING.LIB for the License of this software
 *
 * Anthony Liguori <aliguori@us.ibm.com>
 */

#ifndef _VIR_XML_RPC_H_
#define _VIR_XML_RPC_H_

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

#include "buf.h"

typedef enum _xmlRpcValueType xmlRpcValueType;

typedef struct _xmlRpcValueArray xmlRpcValueArray;
typedef struct _xmlRpcValueDictElement xmlRpcValueDictElement;
typedef struct _xmlRpcValueDict xmlRpcValueDict;
typedef struct _xmlRpcValueBase64 xmlRpcValueBase64;
typedef struct _xmlRpcValue xmlRpcValue;
typedef struct _xmlRpcContext xmlRpcContext;

typedef xmlRpcValueArray *xmlRpcValueArrayPtr;
typedef xmlRpcValueDictElement *xmlRpcValueDictElementPtr;
typedef xmlRpcValueDict *xmlRpcValueDictPtr;
typedef xmlRpcValueBase64 *xmlRpcValueBase64Ptr;
typedef xmlRpcValue *xmlRpcValuePtr;
typedef xmlRpcContext *xmlRpcContextPtr;

enum _xmlRpcValueType {
    XML_RPC_ARRAY,
    XML_RPC_STRUCT,
    XML_RPC_INTEGER,
    XML_RPC_DOUBLE,
    XML_RPC_BOOLEAN,
    XML_RPC_DATE_TIME,
    XML_RPC_BASE64,
    XML_RPC_STRING,
    XML_RPC_NIL,
};

struct _xmlRpcValueArray {
    int n_elements;
    xmlRpcValuePtr *elements;
};

struct _xmlRpcValueDictElement {
    char *name;
    xmlRpcValuePtr value;
    xmlRpcValueDictElementPtr next;
};

struct _xmlRpcValueDict {
    xmlRpcValueDictElementPtr root;
};

struct _xmlRpcValueBase64 {
    void *data;
    size_t n_data;
};

struct _xmlRpcValue {
    xmlRpcValueType kind;

    union {
	char *string;
	xmlRpcValueArray array;
	xmlRpcValueDict dict;
	int32_t integer;
	double real;
	bool boolean;
	time_t dateTime;
	xmlRpcValueBase64 base64;
    } value;
};

struct _xmlRpcContext;

xmlRpcValuePtr *xmlRpcArgvNew(const char *fmt, va_list ap, int *argc);
void xmlRpcArgvFree(int argc, xmlRpcValuePtr *argv);

virBufferPtr xmlRpcMarshalRequest(const char *request,
				  int argc, xmlRpcValuePtr *argv);

xmlRpcValuePtr xmlRpcUnmarshalResponse(xmlNodePtr node, bool *is_fault);

void xmlRpcValueMarshal(xmlRpcValuePtr value, virBufferPtr buf, int indent);

xmlRpcValuePtr xmlRpcValueUnmarshal(xmlNodePtr node);

void xmlRpcValueFree(xmlRpcValuePtr value);

int xmlRpcCall(xmlRpcContextPtr context, const char *method,
	       const char *retval, const char *fmt, ...);

xmlRpcContextPtr xmlRpcContextNew(const char *uri);

void xmlRpcContextFree(xmlRpcContextPtr context);

int xmlRpcContextFaultCode(xmlRpcContextPtr context);

const char *xmlRpcContextFaultMessage(xmlRpcContextPtr context);

#endif
