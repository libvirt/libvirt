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

#include "typewrappers.h"

#ifndef Py_CAPSULE_H
typedef void(*PyCapsule_Destructor)(void *, void *);
#endif

static PyObject *
libvirt_buildPyObject(void *cobj,
                      const char *name,
                      PyCapsule_Destructor destr)
{
    PyObject *ret;

#ifdef Py_CAPSULE_H
    ret = PyCapsule_New(cobj, name, destr);
#else
    ret = PyCObject_FromVoidPtrAndDesc(cobj, (void *) name, destr);
#endif /* _TEST_CAPSULE */

    return ret;
}

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
libvirt_ulonglongWrap(unsigned long long val)
{
    PyObject *ret;
    ret = PyLong_FromUnsignedLongLong(val);
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

    ret = libvirt_buildPyObject(node, "virDomainPtr", NULL);
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

    ret = libvirt_buildPyObject(node, "virNetworkPtr", NULL);
    return (ret);
}

PyObject *
libvirt_virInterfacePtrWrap(virInterfacePtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }

    ret = libvirt_buildPyObject(node, "virInterfacePtr", NULL);
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

    ret = libvirt_buildPyObject(node, "virStoragePoolPtr", NULL);
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

    ret = libvirt_buildPyObject(node, "virStorageVolPtr", NULL);
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

    ret = libvirt_buildPyObject(node, "virConnectPtr", NULL);
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

    ret = libvirt_buildPyObject(node, "virNodeDevicePtr", NULL);
    return (ret);
}

PyObject *
libvirt_virSecretPtrWrap(virSecretPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virSecretPtr", NULL);
    return (ret);
}

PyObject *
libvirt_virNWFilterPtrWrap(virNWFilterPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virNWFilterPtr", NULL);
    return (ret);
}

PyObject *
libvirt_virStreamPtrWrap(virStreamPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virStreamPtr", NULL);
    return (ret);
}

PyObject *
libvirt_virDomainSnapshotPtrWrap(virDomainSnapshotPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return (Py_None);
    }

    ret = libvirt_buildPyObject(node, "virDomainSnapshotPtr", NULL);
    return (ret);
}

PyObject *
libvirt_virEventHandleCallbackWrap(virEventHandleCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        printf("%s: WARNING - Wrapping None\n", __func__);
        return (Py_None);
    }

    ret = libvirt_buildPyObject(node, "virEventHandleCallback", NULL);
    return (ret);
}

PyObject *
libvirt_virEventTimeoutCallbackWrap(virEventTimeoutCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        printf("%s: WARNING - Wrapping None\n", __func__);
        Py_INCREF(Py_None);
        return (Py_None);
    }

    ret = libvirt_buildPyObject(node, "virEventTimeoutCallback", NULL);
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

    ret = libvirt_buildPyObject(node, "virFreeCallback", NULL);
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

    ret = libvirt_buildPyObject(node, "void*", NULL);
    return (ret);
}
