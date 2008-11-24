/*
 * types.c: converter functions between the internal representation
 *          and the Python objects
 *
 * Copyright (C) 2005, 2007 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

/* Horrible kludge to work around even more horrible name-space pollution
 *    via Python.h.  That file includes /usr/include/python2.5/pyconfig*.h,
 *       which has over 180 autoconf-style HAVE_* definitions.  Shame on them.  */
#undef HAVE_PTHREAD_H

#include "libvirt_wrap.h"

PyObject *
libvirt_intWrap(int val)
{
    PyObject *ret;
    ret = PyInt_FromLong((long) val);
    return (ret);
}

PyObject *
libvirt_longWrap(long val)
{
    PyObject *ret;
    ret = PyInt_FromLong(val);
    return (ret);
}

PyObject *
libvirt_ulongWrap(unsigned long val)
{
    PyObject *ret;
    ret = PyLong_FromLong(val);
    return (ret);
}

PyObject *
libvirt_longlongWrap(long long val)
{
    PyObject *ret;
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
    ret = PyString_FromString(str);
    return (ret);
}

PyObject *
libvirt_virDomainPtrWrap(virDomainPtr node)
{
    PyObject *ret;

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
libvirt_virStoragePoolPtrWrap(virStoragePoolPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virStoragePoolPtr",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virStorageVolPtrWrap(virStorageVolPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virStorageVolPtr",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virConnectPtrWrap(virConnectPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virConnectPtr",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virNodeDevicePtrWrap(virNodeDevicePtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virNodeDevicePtr",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virEventHandleCallbackWrap(virEventHandleCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        printf("%s: WARNING - Wrapping None\n", __FUNCTION__);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virEventHandleCallback",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virEventTimeoutCallbackWrap(virEventTimeoutCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        printf("%s: WARNING - Wrapping None\n", __FUNCTION__);
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virEventTimeoutCallback",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virFreeCallbackWrap(virFreeCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "virFreeCallback",
                                     NULL);
    return (ret);
}

PyObject *
libvirt_virVoidPtrWrap(void* node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }
    ret =
        PyCObject_FromVoidPtrAndDesc((void *) node, (char *) "void*",
                                     NULL);
    return (ret);
}
