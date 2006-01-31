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
#include <libvir.h>
#include "libvir_wrap.h"
#include "libvir-py.h"

void initlibvirmod(void);

static PyObject *
libvir_virDomainFree(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virDomainPtr domain;
    PyObject *pyobj_domain;

    if (!PyArg_ParseTuple(args, (char *)"O:virDomainFree", &pyobj_domain))
        return(NULL);
    domain = (virDomainPtr) PyvirDomain_Get(pyobj_domain);

    c_retval = virDomainFree(domain);
    py_retval = libvir_intWrap((int) c_retval);
    return(py_retval);
}

static PyObject *
libvir_virConnectClose(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
    PyObject *py_retval;
    int c_retval;
    virConnectPtr conn;
    PyObject *pyobj_conn;

    if (!PyArg_ParseTuple(args, (char *)"O:virConnectClose", &pyobj_conn))
        return(NULL);
    conn = (virConnectPtr) PyvirConnect_Get(pyobj_conn);

    c_retval = virConnectClose(conn);
    py_retval = libvir_intWrap((int) c_retval);
    return(py_retval);
}

static PyObject *
libvir_virConnectListDomainsID(PyObject *self ATTRIBUTE_UNUSED,
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
        PyList_SetItem(py_retval, i, libvir_intWrap(ids[i]));
    }
    return(py_retval);
}

static PyObject *
libvir_virDomainGetInfo(PyObject *self ATTRIBUTE_UNUSED, PyObject *args) {
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
    PyList_SetItem(py_retval, 0, libvir_intWrap((int) info.state));
    PyList_SetItem(py_retval, 1, libvir_longWrap((long) info.maxMem));
    PyList_SetItem(py_retval, 2, libvir_longWrap((long) info.memory));
    PyList_SetItem(py_retval, 3, libvir_intWrap((int) info.nrVirtCpu));
    PyList_SetItem(py_retval, 4,
                   libvir_longlongWrap((unsigned long long) info.cpuTime));
    return(py_retval);
}

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirMethods[] = {
#include "libvir-export.c"
    {(char *) "virDomainFree", libvir_virDomainFree, METH_VARARGS, NULL},
    {(char *) "virConnectClose", libvir_virConnectClose, METH_VARARGS, NULL},
    {(char *) "virConnectListDomainsID", libvir_virConnectListDomainsID, METH_VARARGS, NULL},
    {(char *) "virDomainGetInfo", libvir_virDomainGetInfo, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

void
initlibvirmod(void)
{
    static int initialized = 0;

    if (initialized != 0)
        return;

    /* intialize the python extension module */
    Py_InitModule((char *) "libvirmod", libvirMethods);

    initialized = 1;
}
