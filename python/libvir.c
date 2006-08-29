/*
 * libvir.c: this modules implements the main part of the glue of the
 *           libvir library and the Python interpreter. It provides the
 *           entry points where an automatically generated stub is
 *           unpractical
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#include <Python.h>
#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include "libvirt_wrap.h"
#include "libvirt-py.h"

void initlibvirmod(void);

PyObject *libvirt_virDomainGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args);
/************************************************************************
 *									*
 *		Global error handler at the Python level		*
 *									*
 ************************************************************************/

static PyObject *libvirt_virPythonErrorFuncHandler = NULL;
static PyObject *libvirt_virPythonErrorFuncCtxt = NULL;

static void
libvirt_virErrorFuncHandler(ATTRIBUTE_UNUSED void *ctx, virErrorPtr err)
{
    PyObject *list, *info;
    PyObject *result;

#ifdef DEBUG_ERROR
    printf("libvirt_virErrorFuncHandler(%p, %s, ...) called\n", ctx, msg);
#endif

    if ((err == NULL) || (err->code == VIR_ERR_OK))
        return;

    if ((libvirt_virPythonErrorFuncHandler == NULL) ||
        (libvirt_virPythonErrorFuncHandler == Py_None)) {
        virDefaultErrorFunc(err);
    } else {
        list = PyTuple_New(2);
        info = PyTuple_New(9);
        PyTuple_SetItem(list, 0, libvirt_virPythonErrorFuncCtxt);
        PyTuple_SetItem(list, 1, info);
        Py_XINCREF(libvirt_virPythonErrorFuncCtxt);
        PyTuple_SetItem(info, 0, PyInt_FromLong((long) err->code));
        PyTuple_SetItem(info, 1, PyInt_FromLong((long) err->domain));
	PyTuple_SetItem(info, 2, libvirt_constcharPtrWrap(err->message));
        PyTuple_SetItem(info, 3, PyInt_FromLong((long) err->level));
	PyTuple_SetItem(info, 4, libvirt_constcharPtrWrap(err->str1));
	PyTuple_SetItem(info, 5, libvirt_constcharPtrWrap(err->str2));
	PyTuple_SetItem(info, 6, libvirt_constcharPtrWrap(err->str3));
        PyTuple_SetItem(info, 7, PyInt_FromLong((long) err->int1));
        PyTuple_SetItem(info, 8, PyInt_FromLong((long) err->int2));
	/* TODO pass conn and dom if available */
        result = PyEval_CallObject(libvirt_virPythonErrorFuncHandler, list);
        Py_XDECREF(list);
        Py_XDECREF(result);
    }
}

static PyObject *
libvirt_virRegisterErrorHandler(ATTRIBUTE_UNUSED PyObject * self,
                               PyObject * args)
{
    PyObject *py_retval;
    PyObject *pyobj_f;
    PyObject *pyobj_ctx;

    if (!PyArg_ParseTuple
        (args, (char *) "OO:xmlRegisterErrorHandler", &pyobj_f,
         &pyobj_ctx))
        return (NULL);

#ifdef DEBUG_ERROR
    printf("libvirt_virRegisterErrorHandler(%p, %p) called\n", pyobj_ctx,
           pyobj_f);
#endif

    virSetErrorFunc(NULL, libvirt_virErrorFuncHandler);
    if (libvirt_virPythonErrorFuncHandler != NULL) {
        Py_XDECREF(libvirt_virPythonErrorFuncHandler);
    }
    if (libvirt_virPythonErrorFuncCtxt != NULL) {
        Py_XDECREF(libvirt_virPythonErrorFuncCtxt);
    }

    if ((pyobj_f == Py_None) && (pyobj_ctx == Py_None)) {
        libvirt_virPythonErrorFuncHandler = NULL;
	libvirt_virPythonErrorFuncCtxt = NULL;
    } else {
	Py_XINCREF(pyobj_ctx);
	Py_XINCREF(pyobj_f);

	/* TODO: check f is a function ! */
	libvirt_virPythonErrorFuncHandler = pyobj_f;
	libvirt_virPythonErrorFuncCtxt = pyobj_ctx;
    }

    py_retval = libvirt_intWrap(1);
    return (py_retval);
}

/************************************************************************
 *									*
 *		Wrappers for functions where generator fails		*
 *									*
 ************************************************************************/

static PyObject *
libvirt_virDomainFree(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virDomainPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainFree", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainFree(domain);
    py_retval = libvirt_intWrap((int) c_retval);
    return(py_retval);
}

static PyObject *
libvirt_virConnectClose(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;

    if (!PyArg_ParseTuple(args, (char *)"O:virConnectClose", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectClose(conn);
    py_retval = libvirt_intWrap((int) c_retval);
    return(py_retval);
}

static PyObject *
libvirt_virConnectListDomainsID(PyObject *self ATTRIBUTE_UNUSED,
                               PyObject *args) {
    PyObject *py_retval;
    int ids[500], c_retval, i;
    virConnectPtr conn;
    PyObject *pyobj_conn;


    if (!PyArg_ParseTuple(args, (char *)"O:virConnectListDomains", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectListDomains(conn, &ids[0], 500);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyList_New(c_retval);
    for (i = 0;i < c_retval;i++) {
        PyList_SetItem(py_retval, i, libvirt_intWrap(ids[i]));
    }
    return(py_retval);
}

static PyObject *
libvirt_virDomainGetInfo(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virDomainPtr domain;
    PyObject *pyobj_domain;
    virDomainInfo info;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetInfo", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainGetInfo(domain, &info);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyList_New(5);
    PyList_SetItem(py_retval, 0, libvirt_intWrap((int) info.state));
    PyList_SetItem(py_retval, 1, libvirt_longWrap((long) info.maxMem));
    PyList_SetItem(py_retval, 2, libvirt_longWrap((long) info.memory));
    PyList_SetItem(py_retval, 3, libvirt_intWrap((int) info.nrVirtCpu));
    PyList_SetItem(py_retval, 4,
                   libvirt_longlongWrap((unsigned long long) info.cpuTime));
    return(py_retval);
}

static PyObject *
libvirt_virNodeGetInfo(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    virNodeInfo info;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetInfo", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virNodeGetInfo(conn, &info);
    if (c_retval < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyList_New(8);
    PyList_SetItem(py_retval, 0, libvirt_constcharPtrWrap(&info.model[0]));
    PyList_SetItem(py_retval, 1, libvirt_longWrap((long) info.memory >> 10));
    PyList_SetItem(py_retval, 2, libvirt_intWrap((int) info.cpus));
    PyList_SetItem(py_retval, 3, libvirt_intWrap((int) info.mhz));
    PyList_SetItem(py_retval, 4, libvirt_intWrap((int) info.nodes));
    PyList_SetItem(py_retval, 5, libvirt_intWrap((int) info.sockets));
    PyList_SetItem(py_retval, 6, libvirt_intWrap((int) info.cores));
    PyList_SetItem(py_retval, 7, libvirt_intWrap((int) info.threads));
    return(py_retval);
}

PyObject *
libvirt_virDomainGetUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    unsigned char uuid[16];
    virDomainPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainGetUUID", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    if (domain == NULL) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    if (virDomainGetUUID(domain, &uuid[0]) < 0) {
        Py_INCREF(Py_None);
	return(Py_None);
    }
    py_retval = PyString_FromStringAndSize((char *) &uuid[0], 16);

    return(py_retval);
}

PyObject *
libvirt_virDomainLookupByUUID(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    virDomainPtr c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;
    unsigned char * uuid;
    int len;

    if (!PyArg_ParseTuple(args, (char *)"Oz#:virDomainLookupByUUID", &pyobj_conn, &uuid, &len))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    if ((uuid == NULL) || (len != 16)) {
        Py_INCREF(Py_None);
	return(Py_None);
    }

    c_retval = virDomainLookupByUUID(conn, uuid);
    py_retval = libvirt_virDomainPtrWrap((virDomainPtr) c_retval);
    return(py_retval);
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirtMethods[] = {
#include "libvirt-export.c"
    {(char *) "virDomainFree", libvirt_virDomainFree, METH_VARARGS, NULL},
    {(char *) "virConnectClose", libvirt_virConnectClose, METH_VARARGS, NULL},
    {(char *) "virConnectListDomainsID", libvirt_virConnectListDomainsID, METH_VARARGS, NULL},
    {(char *) "virDomainGetInfo", libvirt_virDomainGetInfo, METH_VARARGS, NULL},
    {(char *) "virNodeGetInfo", libvirt_virNodeGetInfo, METH_VARARGS, NULL},
    {(char *) "virDomainGetUUID", libvirt_virDomainGetUUID, METH_VARARGS, NULL},
    {(char *) "virDomainLookupByUUID", libvirt_virDomainLookupByUUID, METH_VARARGS, NULL},
    {(char *) "virRegisterErrorHandler", libvirt_virRegisterErrorHandler, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

void
initlibvirtmod(void)
{
    static int initialized = 0;

    if (initialized != 0)
        return;

    virInitialize();

    /* intialize the python extension module */
    Py_InitModule((char *) "libvirtmod", libvirtMethods);

    initialized = 1;
}
