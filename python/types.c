/*
 * types.c: converter functions between the internal representation
 *          and the Python objects
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvir_wrap.h"

PyObject *
libvir_intWrap(int val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_intWrap: val = %d\n", val);
#endif
    ret = PyInt_FromLong((long) val);
    return (ret);
}

PyObject *
libvir_longWrap(long val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_longWrap: val = %ld\n", val);
#endif
    ret = PyInt_FromLong(val);
    return (ret);
}

PyObject *
libvir_charPtrWrap(char *str)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_xmlcharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret = PyString_FromString(str);
    free(str);
    return (ret);
}

PyObject *
libvir_constcharPtrWrap(const char *str)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_xmlcharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret = PyString_FromString(str);
    return (ret);
}

PyObject *
libvir_charPtrConstWrap(const char *str)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_xmlcharPtrWrap: str = %s\n", str);
#endif
    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret = PyString_FromString(str);
    return (ret);
}

PyObject *
libvir_virDomainPtrWrap(virDomainPtr node)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_virDomainPtrWrap: node = %p\n", node);
#endif
    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virDomainPtr",
                                     NULL);
    return (ret);
}

PyObject *
libvir_virConnectPtrWrap(virConnectPtr node)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvir_virConnectPtrWrap: node = %p\n", node);
#endif
    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virConnectPtr",
                                     NULL);
    return (ret);
}
