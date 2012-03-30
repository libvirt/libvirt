/*
 * types.c: converter functions between the internal representation
 *          and the Python objects
 *
 * Copyright (C) 2005, 2007, 2012 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

/* Horrible kludge to work around even more horrible name-space pollution
 *    via Python.h.  That file includes /usr/include/python2.5/pyconfig*.h,
 *       which has over 180 autoconf-style HAVE_* definitions.  Shame on them.  */
#undef HAVE_PTHREAD_H

#include "typewrappers.h"

#include "memory.h"

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
    return ret;
}

PyObject *
libvirt_longWrap(long val)
{
    PyObject *ret;
    ret = PyInt_FromLong(val);
    return ret;
}

PyObject *
libvirt_ulongWrap(unsigned long val)
{
    PyObject *ret;
    ret = PyLong_FromLong(val);
    return ret;
}

PyObject *
libvirt_longlongWrap(long long val)
{
    PyObject *ret;
    ret = PyLong_FromUnsignedLongLong((unsigned long long) val);
    return ret;
}

PyObject *
libvirt_ulonglongWrap(unsigned long long val)
{
    PyObject *ret;
    ret = PyLong_FromUnsignedLongLong(val);
    return ret;
}

PyObject *
libvirt_charPtrSizeWrap(char *str, Py_ssize_t size)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    ret = PyString_FromStringAndSize(str, size);
    VIR_FREE(str);
    return ret;
}

PyObject *
libvirt_charPtrWrap(char *str)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    ret = PyString_FromString(str);
    VIR_FREE(str);
    return ret;
}

PyObject *
libvirt_constcharPtrWrap(const char *str)
{
    PyObject *ret;

    if (str == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }
    ret = PyString_FromString(str);
    return ret;
}

int
libvirt_intUnwrap(PyObject *obj, int *val)
{
    long long_val;

    /* If obj is type of PyInt_Type, PyInt_AsLong converts it
     * to C long type directly. If it is of PyLong_Type, PyInt_AsLong
     * will call PyLong_AsLong() to deal with it automatically.
     */
    long_val = PyInt_AsLong(obj);
    if ((long_val == -1) && PyErr_Occurred())
        return -1;

    if (long_val >= INT_MIN && long_val <= INT_MAX) {
        *val = long_val;
    } else {
        PyErr_SetString(PyExc_OverflowError,
                        "Python int too large to convert to C int");
        return -1;
    }
    return 0;
}

int
libvirt_uintUnwrap(PyObject *obj, unsigned int *val)
{
    long long_val;

    long_val = PyInt_AsLong(obj);
    if ((long_val == -1) && PyErr_Occurred())
        return -1;

    if (long_val >= 0 && long_val <= UINT_MAX) {
        *val = long_val;
    } else {
        PyErr_SetString(PyExc_OverflowError,
                        "Python int too large to convert to C unsigned int");
        return -1;
    }
    return 0;
}

int
libvirt_longUnwrap(PyObject *obj, long *val)
{
    long long_val;

    long_val = PyInt_AsLong(obj);
    if ((long_val == -1) && PyErr_Occurred())
        return -1;

    *val = long_val;
    return 0;
}

int
libvirt_ulongUnwrap(PyObject *obj, unsigned long *val)
{
    long long_val;

    long_val = PyInt_AsLong(obj);
    if ((long_val == -1) && PyErr_Occurred())
        return -1;

    if (long_val >= 0) {
        *val = long_val;
    } else {
        PyErr_SetString(PyExc_OverflowError,
                        "negative Python int cannot be converted to C unsigned long");
        return -1;
    }
    return 0;
}

int
libvirt_longlongUnwrap(PyObject *obj, long long *val)
{
    long long llong_val;

    /* If obj is of PyInt_Type, PyLong_AsLongLong
     * will call PyInt_AsLong() to handle it automatically.
     */
    llong_val = PyLong_AsLongLong(obj);
    if ((llong_val == -1) && PyErr_Occurred())
        return -1;

    *val = llong_val;
    return 0;
}

int
libvirt_ulonglongUnwrap(PyObject *obj, unsigned long long *val)
{
    unsigned long long ullong_val = -1;
    long long llong_val;

    /* The PyLong_AsUnsignedLongLong doesn't check the type of
     * obj, only accept argument of PyLong_Type, so we check it instead.
     */
    if (PyInt_Check(obj)) {
        llong_val = PyInt_AsLong(obj);
        if (llong_val < 0)
            PyErr_SetString(PyExc_OverflowError,
                            "negative Python int cannot be converted to C unsigned long long");
        else
            ullong_val = llong_val;
    } else if (PyLong_Check(obj)) {
        ullong_val = PyLong_AsUnsignedLongLong(obj);
    } else {
        PyErr_SetString(PyExc_TypeError, "an integer is required");
    }

    if ((ullong_val == -1) && PyErr_Occurred())
        return -1;

    *val = ullong_val;
    return 0;
}

int
libvirt_doubleUnwrap(PyObject *obj, double *val)
{
    double double_val;

    double_val = PyFloat_AsDouble(obj);
    if ((double_val == -1) && PyErr_Occurred())
        return -1;

    *val = double_val;
    return 0;
}

int
libvirt_boolUnwrap(PyObject *obj, bool *val)
{
    int ret;

    ret = PyObject_IsTrue(obj);
    if (ret < 0)
        return ret;

    *val = ret > 0;
    return 0;
}

PyObject *
libvirt_virDomainPtrWrap(virDomainPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virDomainPtr", NULL);
    return ret;
}

PyObject *
libvirt_virNetworkPtrWrap(virNetworkPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virNetworkPtr", NULL);
    return ret;
}

PyObject *
libvirt_virInterfacePtrWrap(virInterfacePtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virInterfacePtr", NULL);
    return ret;
}

PyObject *
libvirt_virStoragePoolPtrWrap(virStoragePoolPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virStoragePoolPtr", NULL);
    return ret;
}

PyObject *
libvirt_virStorageVolPtrWrap(virStorageVolPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virStorageVolPtr", NULL);
    return ret;
}

PyObject *
libvirt_virConnectPtrWrap(virConnectPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virConnectPtr", NULL);
    return ret;
}

PyObject *
libvirt_virNodeDevicePtrWrap(virNodeDevicePtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virNodeDevicePtr", NULL);
    return ret;
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
    return ret;
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
    return ret;
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
    return ret;
}

PyObject *
libvirt_virDomainSnapshotPtrWrap(virDomainSnapshotPtr node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virDomainSnapshotPtr", NULL);
    return ret;
}

PyObject *
libvirt_virEventHandleCallbackWrap(virEventHandleCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        printf("%s: WARNING - Wrapping None\n", __func__);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virEventHandleCallback", NULL);
    return ret;
}

PyObject *
libvirt_virEventTimeoutCallbackWrap(virEventTimeoutCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        printf("%s: WARNING - Wrapping None\n", __func__);
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virEventTimeoutCallback", NULL);
    return ret;
}

PyObject *
libvirt_virFreeCallbackWrap(virFreeCallback node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "virFreeCallback", NULL);
    return ret;
}

PyObject *
libvirt_virVoidPtrWrap(void* node)
{
    PyObject *ret;

    if (node == NULL) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    ret = libvirt_buildPyObject(node, "void*", NULL);
    return ret;
}
