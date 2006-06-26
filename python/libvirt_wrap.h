/*
 * libvirt_wrap.h: type wrappers for libvir python bindings
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <Python.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

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


PyObject * libvirt_intWrap(int val);
PyObject * libvirt_longWrap(long val);
PyObject * libvirt_longlongWrap(long long val);
PyObject * libvirt_charPtrWrap(char *str);
PyObject * libvirt_constcharPtrWrap(const char *str);
PyObject * libvirt_charPtrConstWrap(const char *str);
PyObject * libvirt_virConnectPtrWrap(virConnectPtr node);
PyObject * libvirt_virDomainPtrWrap(virDomainPtr node);

