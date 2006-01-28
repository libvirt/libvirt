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

/************************************************************************
 *									*
 *			The registration stuff				*
 *									*
 ************************************************************************/
static PyMethodDef libvirMethods[] = {
#include "libvir-export.c"
    {(char *) "virDomainFree", libvir_virDomainFree, METH_VARARGS, NULL},
    {(char *) "virConnectClose", libvir_virConnectClose, METH_VARARGS, NULL},
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
