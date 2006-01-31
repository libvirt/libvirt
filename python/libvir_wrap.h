/*
 * libvir_wrap.h: type wrappers for libvir python bindings
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <Python.h>
#include <libvir.h>

#ifdef __GNUC__
#ifdef ATTRIBUTE_UNUSED
#undef ATTRIBUTE_UNUSED
#endif
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#endif /* ATTRIBUTE_UNUSED */
#else
#define ATTRIBUTE_UNUSED
#endif

#define PyvirConnect_Get(v) (((v) == Py_None) ? NULL : \
	(((PyvirConnect_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virConnectPtr obj;
} PyvirConnect_Object;


#define PyvirDomain_Get(v) (((v) == Py_None) ? NULL : \
	(((PyvirDomain_Object *)(v))->obj))

typedef struct {
    PyObject_HEAD
    virDomainPtr obj;
} PyvirDomain_Object;


PyObject * libvir_intWrap(int val);
PyObject * libvir_longWrap(long val);
PyObject * libvir_longlongWrap(long long val);
PyObject * libvir_charPtrWrap(char *str);
PyObject * libvir_constcharPtrWrap(const char *str);
PyObject * libvir_charPtrConstWrap(const char *str);
PyObject * libvir_virConnectPtrWrap(virConnectPtr node);
PyObject * libvir_virDomainPtrWrap(virDomainPtr node);

