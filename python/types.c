/*
 * types.c: converter functions between the internal representation
 *          and the Python objects
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include "libvirt_wrap.h"

PyObject *
libvirt_intWrap(int val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_intWrap: val = %d\n", val);
#endif
    ret = PyInt_FromLong((long) val);
    return (ret);
}

PyObject *
libvirt_longWrap(long val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_longWrap: val = %ld\n", val);
#endif
    ret = PyInt_FromLong(val);
    return (ret);
}

PyObject *
libvirt_ulongWrap(unsigned long val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_ulongWrap: val = %lu\n", val);
#endif
    ret = PyLong_FromLong(val);
    return (ret);
}   

PyObject *
libvirt_longlongWrap(long long val)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_longWrap: val = %ld\n", val);
#endif
    ret = PyLong_FromUnsignedLongLong((unsigned long long) val);
    return (ret);
}

PyObject *
libvirt_charPtrWrap(char *str)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
#ifdef DEBUG
    printf("libvirt_xmlcharPtrWrap: str = %s\n", str);
#endif
    ret = PyString_FromString(str);
    free(str);
    return (ret);
}

PyObject *
libvirt_constcharPtrWrap(const char *str)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
#ifdef DEBUG
    printf("libvirt_xmlcharPtrWrap: str = %s\n", str);
#endif
    ret = PyString_FromString(str);
    return (ret);
}

PyObject *
libvirt_charPtrConstWrap(const char *str)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
#ifdef DEBUG
    printf("libvirt_xmlcharPtrWrap: str = %s\n", str);
#endif
    ret = PyString_FromString(str);
    return (ret);
}

PyObject *
libvirt_virDomainPtrWrap(virDomainPtr node)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_virDomainPtrWrap: node = %p\n", node);
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
libvirt_virNetworkPtrWrap(virNetworkPtr node)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_virNetworkPtrWrap: node = %p\n", node);
#endif
    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virNetworkPtr",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virConnectPtrWrap(virConnectPtr node)
{
    PyObject *ret;

#ifdef DEBUG
    printf("libvirt_virConnectPtrWrap: node = %p\n", node);
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
